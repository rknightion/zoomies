package backend

// Job-user slots: the local accounts macOS jobs run as, one per concurrent job
// and one more, so that a slot being cleaned never keeps a new job waiting.
// See docs/macos-job-users.md for what this does and does not isolate.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// jobUserUIDBase plus a slot's number is its UID. The range is above the 501
	// and up that macOS gives to people, and outside the 450 to 499 that role
	// accounts take. It is fixed in the code and not configurable, because the
	// checks below are written against it.
	jobUserUIDBase = 650
	// jobUserGID is the primary group every slot shares and no person is in.
	// A job user must not be in staff: every local account is, and macOS homes
	// are readable by that group, so any other local user's files would be too.
	jobUserGID   = 650
	jobUserGroup = "_zjobs"
	// jobUserMaxSlots is how many accounts there can be, so a capacity of 47 is
	// the most one host takes, and the highest UID is 698.
	jobUserMaxSlots    = 48
	jobUserMaxCapacity = jobUserMaxSlots - 1
	// jobUserUIDLimit is the top of the range nothing else may hold.
	jobUserUIDLimit = 699
	// jobUserShell is what a job's SHELL says. It is not the account's login
	// shell, which is jobUserLoginShell: nobody can log in as a slot.
	jobUserShell      = "/bin/zsh"
	jobUserLoginShell = "/usr/bin/false"
	// jobUserRunDirName is where the runner is laid out inside a slot's home.
	jobUserRunDirName = "actions-runner"
	// jobUserTrashName is where a wiped home waits to be deleted.
	jobUserTrashName = ".zoomies-trash"
)

var jobUserNamePattern = regexp.MustCompile(`^zj([0-9]{2})$`)

func jobUserName(n int) string { return fmt.Sprintf("zj%02d", n) }
func jobUserUID(n int) int     { return jobUserUIDBase + n }

// jobUserSlot is one account.
type jobUserSlot struct {
	n    int
	name string
	uid  int
	// offered is whether new jobs may use it. An account above a reduced capacity
	// is drained: never offered again, but still reset at start-up and after the
	// job it holds ends.
	offered bool
	// exists is whether the Mac has the account, whether or not it is offered. It
	// is set by ensureSlots before anything else runs, and read after that.
	exists bool

	// The fields below are guarded by jobUsers.mu.

	// holder is the runner directory using the slot, or empty when it is free.
	holder  string
	healthy bool
	// failures counts resets that failed in a row; nextRetry is when the watcher
	// tries again; lastErr is what the last one said.
	failures  int
	nextRetry time.Time
	lastErr   string
}

// jobUsers is the whole of the machinery. It is built by NewProcess when the
// backend is given JobUserOptions, and nothing in it runs until StartJobUsers.
type jobUsers struct {
	sys      jobUserSystem
	log      *slog.Logger
	now      func() time.Time
	pause    func(ctx context.Context, d time.Duration)
	usersDir string
	trashDir string
	stateDir string
	capacity int

	mu    sync.Mutex
	slots []*jobUserSlot
	// reprobe is whether a slot changed health since the last probe, so that the
	// next one is not served from the cache.
	reprobe atomic.Bool

	// started is set once StartJobUsers has made the accounts; nothing is
	// admitted before it.
	started atomic.Bool

	cancel  context.CancelFunc
	watchWG sync.WaitGroup
	// every and the retry schedule are fields so a test can drive the watcher.
	watchEvery time.Duration
}

// JobUserOptions turns on the job-user launcher of the process backend.
type JobUserOptions struct {
	// Capacity is how many jobs may run at once. The host has one more account
	// than that.
	Capacity int
	// StateDir holds what must outlive the agent: each slot's manifest. It must
	// be readable by root alone. Empty means job-users under the work directory.
	StateDir string
	// UsersDir is where homes live. Empty means /Users.
	UsersDir string
	// Now is the clock. Nil means the real one.
	Now func() time.Time

	// system and pause stand in for the host and for waiting, in tests.
	system jobUserSystem
	pause  func(ctx context.Context, d time.Duration)
}

// newJobUsers builds the machinery without touching the host.
func newJobUsers(o JobUserOptions, workDir string, log *slog.Logger) (*jobUsers, error) {
	if o.Capacity < 1 || o.Capacity > jobUserMaxCapacity {
		return nil, fmt.Errorf("%w: agent.capacity is %d, and job users run 1 to %d jobs at once", ErrBackendConfig, o.Capacity, jobUserMaxCapacity)
	}
	return buildJobUsers(o, workDir, log)
}

// buildJobUsers is newJobUsers without the capacity check, which removing the
// accounts has no use for.
func buildJobUsers(o JobUserOptions, workDir string, log *slog.Logger) (*jobUsers, error) {
	sys := o.system
	if sys == nil {
		var err error
		if sys, err = newJobUserSystem(); err != nil {
			return nil, err
		}
	}
	u := &jobUsers{
		sys:        sys,
		log:        log.With("component", "job-users"),
		now:        o.Now,
		pause:      o.pause,
		usersDir:   o.UsersDir,
		stateDir:   o.StateDir,
		capacity:   o.Capacity,
		watchEvery: jobUserWatchEvery,
	}
	if u.now == nil {
		u.now = time.Now
	}
	if u.pause == nil {
		u.pause = func(ctx context.Context, d time.Duration) {
			select {
			case <-ctx.Done():
			case <-time.After(d):
			}
		}
	}
	if u.usersDir == "" {
		u.usersDir = "/Users"
	}
	u.trashDir = filepath.Join(u.usersDir, jobUserTrashName)
	if u.stateDir == "" {
		u.stateDir = filepath.Join(workDir, "job-users")
	}
	u.slots = make([]*jobUserSlot, jobUserMaxSlots)
	for i := range u.slots {
		n := i + 1
		u.slots[i] = &jobUserSlot{n: n, name: jobUserName(n), uid: jobUserUID(n), offered: n <= o.Capacity+1, healthy: true}
	}
	return u, nil
}

// covered returns every account the start-up reset must reach: the offered ones
// and any other that exists.
func (u *jobUsers) covered() []*jobUserSlot {
	var out []*jobUserSlot
	for _, s := range u.slots {
		if s.offered || s.exists {
			out = append(out, s)
		}
	}
	return out
}

// offered returns the accounts new jobs may use, in order.
func (u *jobUsers) offered() []*jobUserSlot {
	var out []*jobUserSlot
	for _, s := range u.slots {
		if s.offered {
			out = append(out, s)
		}
	}
	return out
}

func (u *jobUsers) slotNamed(name string) *jobUserSlot {
	for _, s := range u.slots {
		if s.name == name {
			return s
		}
	}
	return nil
}

func (u *jobUsers) home(s *jobUserSlot) string { return filepath.Join(u.usersDir, s.name) }

func (u *jobUsers) runDir(s *jobUserSlot) string { return filepath.Join(u.home(s), jobUserRunDirName) }

func (u *jobUsers) manifestPath(s *jobUserSlot) string {
	return filepath.Join(u.stateDir, s.name+".manifest")
}

// run runs a command as root, and turns a non-zero exit into an error naming
// the command and what it said.
func (u *jobUsers) run(ctx context.Context, argv ...string) (string, error) {
	return u.runCmd(ctx, jobUserCommand{Argv: argv})
}

func (u *jobUsers) runCmd(ctx context.Context, c jobUserCommand) (string, error) {
	res, err := u.sys.Run(ctx, c)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return res.Output, fmt.Errorf("%s exited %d: %s", strings.Join(c.Argv[:min(len(c.Argv), 3)], " "), res.ExitCode, strings.TrimSpace(res.Output))
	}
	return res.Output, nil
}

// reserve takes the lowest-numbered slot that is free and healthy. The
// reservation is recorded before the lock is released, so two creates cannot
// take the same one.
func (u *jobUsers) reserve(holder string) (*jobUserSlot, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	unhealthy := []string{}
	for _, s := range u.slots {
		if !s.offered {
			continue
		}
		switch {
		case !s.healthy:
			unhealthy = append(unhealthy, s.name)
		case s.holder != "":
		default:
			s.holder = holder
			return s, nil
		}
	}
	detail := "every job user is running a job"
	if len(unhealthy) > 0 {
		detail = fmt.Sprintf("%s could not be cleaned and are being retried", strings.Join(unhealthy, ", "))
	}
	return nil, busyErr(fmt.Errorf("no job user is free: %s", detail))
}

// release frees a reservation.
func (u *jobUsers) release(s *jobUserSlot) {
	u.mu.Lock()
	s.holder = ""
	u.mu.Unlock()
}

// markUnhealthy frees a slot that could not be cleaned and schedules its
// retry: after a minute, after five more, then every fifteen.
func (u *jobUsers) markUnhealthy(s *jobUserSlot, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	s.holder = ""
	s.healthy = false
	s.failures++
	s.lastErr = err.Error()
	s.nextRetry = u.now().Add(jobUserRetryDelay(s.failures))
	u.reprobe.Store(true)
	u.log.Error("a job user could not be cleaned, so it is out of service until it can be", "slot", s.name, "failures", s.failures, "error", err)
}

func (u *jobUsers) markHealthy(s *jobUserSlot) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !s.healthy {
		u.log.Info("a job user was cleaned and is back in service", "slot", s.name)
		u.reprobe.Store(true)
	}
	s.healthy, s.failures, s.lastErr = true, 0, ""
}

// jobUserRetryDelay is when a slot that failed for the n'th time in a row is
// tried again.
func jobUserRetryDelay(n int) time.Duration {
	switch {
	case n <= 1:
		return time.Minute
	case n == 2:
		return 5 * time.Minute
	}
	return 15 * time.Minute
}

// unhealthy lists the offered slots out of service with why.
func (u *jobUsers) unhealthy() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	var out []string
	for _, s := range u.slots {
		if s.offered && !s.healthy {
			out = append(out, fmt.Sprintf("%s (%s)", s.name, s.lastErr))
		}
	}
	return out
}

// healthyCount is how many offered slots could take a job if none were busy.
func (u *jobUsers) healthyCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, s := range u.slots {
		if s.offered && s.healthy {
			n++
		}
	}
	return n
}

// ---- accounts ----

// parseJobUserIDs reads the two-column output of dscl -list: a name and a
// number. A line it cannot read is left out.
func parseJobUserIDs(out string) map[string]int {
	ids := make(map[string]int)
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		if n, err := strconv.Atoi(f[1]); err == nil {
			ids[f[0]] = n
		}
	}
	return ids
}

// checkJobUserAccounts refuses a host where the accounts or the group Zoomies
// would make already exist as something else. It never adopts a person's
// account: a name of ours with another UID, or a UID of ours under another name,
// is somebody else's, and wiping its home at the end of a job would destroy it.
func checkJobUserAccounts(users, groups map[string]int) error {
	names := make([]string, 0, len(users))
	for name := range users {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		uid := users[name]
		m := jobUserNamePattern.FindStringSubmatch(name)
		n := 0
		if m != nil {
			n, _ = strconv.Atoi(m[1])
		}
		ours := m != nil && n >= 1 && n <= jobUserMaxSlots
		switch {
		case ours && uid != jobUserUID(n):
			return fmt.Errorf("%w: an account named %s already exists with UID %d, and Zoomies would make it UID %d; rename or remove that account, because Zoomies wipes its job users' homes and will not adopt one it did not make", ErrBackendConfig, name, uid, jobUserUID(n))
		case uid >= jobUserUIDBase && uid <= jobUserUIDLimit && !ours:
			return fmt.Errorf("%w: UID %d belongs to the account %s, which Zoomies did not make; job users use UIDs %d to %d, so move that account to another UID", ErrBackendConfig, uid, name, jobUserUIDBase+1, jobUserUIDBase+jobUserMaxSlots)
		}
	}
	gnames := make([]string, 0, len(groups))
	for name := range groups {
		gnames = append(gnames, name)
	}
	sort.Strings(gnames)
	for _, name := range gnames {
		switch gid := groups[name]; {
		case name == jobUserGroup && gid != jobUserGID:
			return fmt.Errorf("%w: the group %s exists with GID %d, and job users need it to be GID %d; remove that group or change its GID", ErrBackendConfig, jobUserGroup, gid, jobUserGID)
		case name != jobUserGroup && gid == jobUserGID:
			return fmt.Errorf("%w: the group %s has GID %d, which job users need for %s; move that group to another GID", ErrBackendConfig, name, gid, jobUserGroup)
		}
	}
	return nil
}

// ensureSlots makes the group and any missing account, and refuses to go on if
// an existing one is not as Zoomies would have made it. It runs at start, before
// any job is admitted, so no job user is running while it works. Every account in
// the range that exists is checked, offered or not, because a job that survived
// a restart can be running in one, and Zoomies wipes its home when that job ends.
// Nothing is changed until all of them have been looked at.
func (u *jobUsers) ensureSlots(ctx context.Context) error {
	out, err := u.run(ctx, "/usr/bin/dscl", ".", "-list", "/Users", "UniqueID")
	if err != nil {
		return fmt.Errorf("listing the local accounts: %w", err)
	}
	users := parseJobUserIDs(out)
	out, err = u.run(ctx, "/usr/bin/dscl", ".", "-list", "/Groups", "PrimaryGroupID")
	if err != nil {
		return fmt.Errorf("listing the local groups: %w", err)
	}
	groups := parseJobUserIDs(out)
	if err := checkJobUserAccounts(users, groups); err != nil {
		return err
	}

	var existing, wrongShell []*jobUserSlot
	for _, s := range u.slots {
		if _, ok := users[s.name]; !ok {
			continue
		}
		shell, err := u.checkAccount(ctx, s)
		if err != nil {
			return err
		}
		existing = append(existing, s)
		if shell != jobUserLoginShell {
			wrongShell = append(wrongShell, s)
		}
	}

	// The group comes first: an account made without it would be in staff for as
	// long as it took to put that right, and the home it is given then would be
	// readable by every other local user.
	if _, ok := groups[jobUserGroup]; !ok {
		g := "/Groups/" + jobUserGroup
		for _, argv := range [][]string{
			{"/usr/bin/dscl", ".", "-create", g},
			{"/usr/bin/dscl", ".", "-create", g, "PrimaryGroupID", strconv.Itoa(jobUserGID)},
			{"/usr/bin/dscl", ".", "-create", g, "RealName", "Zoomies job users"},
		} {
			if _, err := u.run(ctx, argv...); err != nil {
				return fmt.Errorf("creating the group %s: %w", jobUserGroup, err)
			}
		}
	}
	for _, s := range wrongShell {
		// An account somebody made by hand, or an older Zoomies. Nobody may log in as
		// a slot: with Remote Login open to every user, a job could write an
		// authorized_keys file and be followed in by whoever holds the key.
		if err := u.setLoginShell(ctx, s); err != nil {
			return err
		}
		u.log.Info("changed a job user's login shell to one that cannot log in", "slot", s.name)
	}
	for _, s := range existing {
		s.exists = true
	}
	for _, s := range u.offered() {
		if s.exists {
			continue
		}
		if err := u.createAccount(ctx, s); err != nil {
			return err
		}
		s.exists = true
	}
	return nil
}

// readUserAttr reads one attribute of a local account with dscl, whose answer is
// "Name: value", or the value on the next line when it has spaces in it.
func (u *jobUsers) readUserAttr(ctx context.Context, s *jobUserSlot, attr string) (string, error) {
	out, err := u.run(ctx, "/usr/bin/dscl", ".", "-read", "/Users/"+s.name, attr)
	if err != nil {
		return "", err
	}
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), attr+":")
		if !ok {
			continue
		}
		if v := strings.TrimSpace(rest); v != "" {
			return v, nil
		}
		if i+1 < len(lines) {
			return strings.TrimSpace(lines[i+1]), nil
		}
	}
	return "", fmt.Errorf("dscl did not print %s for %s", attr, s.name)
}

// isAdmin asks whether an account is in the admin group. dseditgroup answers
// "yes NAME is a member of admin" or "no NAME is NOT a member of admin", and its
// exit code for the second is 67, which is also what an error gives, so the answer
// is read from the text and anything else is "cannot tell".
func (u *jobUsers) isAdmin(ctx context.Context, name string) (bool, error) {
	res, err := u.sys.Run(ctx, jobUserCommand{Argv: []string{"/usr/sbin/dseditgroup", "-o", "checkmember", "-m", name, "admin"}})
	if err != nil {
		return false, err
	}
	switch out := strings.TrimSpace(res.Output); {
	case strings.HasPrefix(out, "yes "):
		return true, nil
	case strings.HasPrefix(out, "no "):
		return false, nil
	default:
		return false, fmt.Errorf("dseditgroup said %q and exited %d", jobUserFirstLine(out), res.ExitCode)
	}
}

// checkAccount refuses an existing account that is not what Zoomies would have
// made, before anything is changed: its primary group, its home and its standing
// all decide what wiping its home does. It returns the account's login shell,
// which is "" when dscl cannot say, and which ensureSlots corrects afterwards.
func (u *jobUsers) checkAccount(ctx context.Context, s *jobUserSlot) (shell string, err error) {
	gid, err := u.readUserAttr(ctx, s, "PrimaryGroupID")
	if err != nil {
		return "", fmt.Errorf("reading the group of %s: %w", s.name, err)
	}
	if gid != strconv.Itoa(jobUserGID) {
		return "", fmt.Errorf("%w: the account %s exists but its primary group is not %s (GID %d), so a job in it could read other users' homes; set it with dscl or delete the account and let Zoomies make it", ErrBackendConfig, s.name, jobUserGroup, jobUserGID)
	}
	home, err := u.readUserAttr(ctx, s, "NFSHomeDirectory")
	if err != nil {
		return "", fmt.Errorf("reading the home of %s: %w", s.name, err)
	}
	if home != u.home(s) {
		return "", fmt.Errorf("%w: the account %s has its home at %s, and a job user's is %s; Zoomies wipes that folder after every job and will not adopt an account whose home is anywhere else, so delete the account and let Zoomies make it", ErrBackendConfig, s.name, home, u.home(s))
	}
	admin, err := u.isAdmin(ctx, s.name)
	if err != nil {
		return "", fmt.Errorf("%w: could not tell whether the account %s is a member of admin (%v), and Zoomies will not wipe the home of one that may be a person's", ErrBackendConfig, s.name, err)
	}
	if admin {
		return "", fmt.Errorf("%w: the account %s is a member of admin, so it is somebody's own account and not one Zoomies made; remove it from the group or delete the account and let Zoomies make it", ErrBackendConfig, s.name)
	}
	shell, err = u.readUserAttr(ctx, s, "UserShell")
	if err != nil {
		// An account with no shell set reads as an error; it is corrected the same.
		return "", nil
	}
	return shell, nil
}

func (u *jobUsers) setLoginShell(ctx context.Context, s *jobUserSlot) error {
	if _, err := u.run(ctx, "/usr/bin/dscl", ".", "-create", "/Users/"+s.name, "UserShell", jobUserLoginShell); err != nil {
		return fmt.Errorf("setting the login shell of %s to %s: %w", s.name, jobUserLoginShell, err)
	}
	return nil
}

// createAccount makes one account. The password is 32 random bytes, passed once
// and never stored or used: sysadminctl wants one, and the account is never
// logged in to. It is on the command line for a moment, when no job is running
// anywhere on this host. The login shell is set straight afterwards, with the
// group, and the account is not kept if either fails.
func (u *jobUsers) createAccount(ctx context.Context, s *jobUserSlot) error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("making a password for %s: %w", s.name, err)
	}
	if _, err := u.run(ctx, "/usr/sbin/sysadminctl", "-addUser", s.name, "-UID", strconv.Itoa(s.uid),
		"-home", u.home(s), "-password", base64.StdEncoding.EncodeToString(raw)); err != nil {
		return fmt.Errorf("creating the account %s: %w", s.name, err)
	}
	// sysadminctl on macOS 27.3 was seen to ignore -UID and hand out the next
	// free one, which would leave the account outside the range everything else
	// is keyed to. The UID is set again here and read back below.
	for _, argv := range [][]string{
		{"/usr/bin/dscl", ".", "-create", "/Users/" + s.name, "UniqueID", strconv.Itoa(s.uid)},
		{"/usr/bin/dscl", ".", "-create", "/Users/" + s.name, "UserShell", jobUserLoginShell},
		{"/usr/bin/dscl", ".", "-create", "/Users/" + s.name, "PrimaryGroupID", strconv.Itoa(jobUserGID)},
		{"/usr/bin/dscl", ".", "-create", "/Users/" + s.name, "IsHidden", "1"},
	} {
		if _, err := u.run(ctx, argv...); err != nil {
			// An account left in staff is the leak this design exists to close, and
			// one with a login shell is a way in, so it is not kept half made.
			_, _ = u.run(ctx, "/usr/sbin/sysadminctl", "-deleteUser", s.name)
			return fmt.Errorf("setting up the account %s: %w", s.name, err)
		}
	}
	got, err := u.run(ctx, "/usr/bin/dscl", ".", "-read", "/Users/"+s.name, "UniqueID")
	if err != nil || strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(got), "UniqueID:")) != strconv.Itoa(s.uid) {
		_, _ = u.run(ctx, "/usr/sbin/sysadminctl", "-deleteUser", s.name)
		return fmt.Errorf("the account %s did not take UID %d (Directory Services says %q), so it was not kept", s.name, s.uid, strings.TrimSpace(got))
	}
	u.log.Info("made a job user", "slot", s.name, "uid", s.uid)
	return nil
}

// parseJobUserProcesses reads ps -ax -o pid=,ruid=,uid=.
func parseJobUserProcesses(out string) ([]jobUserProc, error) {
	var procs []jobUserProc
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 3 {
			return nil, fmt.Errorf("ps printed a line this version of Zoomies cannot read: %q", line)
		}
		var v [3]int
		for i := range v {
			n, err := strconv.Atoi(f[i])
			if err != nil {
				return nil, fmt.Errorf("ps printed a line this version of Zoomies cannot read: %q", line)
			}
			v[i] = n
		}
		procs = append(procs, jobUserProc{PID: v[0], RUID: v[1], EUID: v[2]})
	}
	return procs, nil
}

// processesOf lists what runs under a UID, real or effective.
func (u *jobUsers) processesOf(ctx context.Context, uid int) ([]jobUserProc, error) {
	all, err := u.sys.Processes(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing processes: %w", err)
	}
	var out []jobUserProc
	for _, p := range all {
		if p.RUID == uid || p.EUID == uid {
			out = append(out, p)
		}
	}
	return out, nil
}

// jobUserFirstLine is the first line of what a command printed, for a message
// that has room for one.
func jobUserFirstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return line
}
