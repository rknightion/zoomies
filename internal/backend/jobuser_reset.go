package backend

// Cleaning a slot after a job. The order is the design: stop everything first,
// so nothing is writing while the rest is removed, and verify last, so a step
// that quietly did nothing is found before the slot is offered again.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// jobUserKillWithin is how long step one keeps trying to leave nothing
	// running, and jobUserKillEvery how often it tries again. Each try stops
	// every process before it kills any, so a fork loop cannot outrun it.
	jobUserKillWithin = 10 * time.Second
	jobUserKillEvery  = 200 * time.Millisecond
)

// The steps of a reset, as the error names them.
const (
	stepStop      = "stop every process"
	stepBootout   = "boot out the launchd domains"
	stepScheduled = "remove cron and at jobs"
	stepMounts    = "unmount what the job mounted"
	stepHome      = "replace the home"
	stepTemp      = "remove the per-user temporary folder"
	stepShared    = "remove files in the shared folders"
	stepIPC       = "remove shared memory and semaphores"
	stepVerify    = "verify the slot is clean"
)

// resetError is a reset that stopped, and where.
type resetError struct {
	Slot string
	Step string
	Err  error
}

func (e *resetError) Error() string {
	return fmt.Sprintf("cleaning %s failed at the step %q: %v", e.Slot, e.Step, e.Err)
}

func (e *resetError) Unwrap() error { return e.Err }

// resetSlot runs the whole reset. It returns a *resetError naming the step that
// failed; the steps after it are not run, because several of them are only
// safe once the ones before them have worked.
func (u *jobUsers) resetSlot(ctx context.Context, s *jobUserSlot) error {
	steps := []struct {
		name string
		run  func(context.Context, *jobUserSlot) error
	}{
		{stepStop, u.stopProcesses},
		{stepBootout, u.bootoutDomains},
		{stepScheduled, u.removeScheduled},
		{stepMounts, u.unmountJobMounts},
		{stepHome, u.replaceHome},
		{stepTemp, u.removeUserTemp},
		{stepShared, u.removeSharedFiles},
		{stepIPC, u.removeIPC},
		{stepVerify, u.verifyReset},
	}
	for _, step := range steps {
		if err := step.run(ctx, s); err != nil {
			return &resetError{Slot: s.name, Step: step.name, Err: err}
		}
	}
	return nil
}

// resetAndFree resets a slot a job is finished with and then offers it again,
// or marks it unhealthy so that the watcher keeps trying.
func (u *jobUsers) resetAndFree(ctx context.Context, s *jobUserSlot) error {
	return u.free(s, u.resetSlot(ctx, s))
}

// free gives a slot back after its reset: in service if the reset worked, and
// out of it, to be tried again, if not. The caller has to have finished with
// everything that names the slot, because the next create can take it from here.
func (u *jobUsers) free(s *jobUserSlot, resetErr error) error {
	if resetErr != nil {
		u.markUnhealthy(s, resetErr)
		return resetErr
	}
	u.markHealthy(s)
	u.release(s)
	return nil
}

// runAllowing runs a command as root and accepts any of the exit codes given, such
// as the 1 pkill uses for "nothing matched", which is the goal and not a failure.
func (u *jobUsers) runAllowing(ctx context.Context, allowed []int, argv ...string) (string, error) {
	res, err := u.sys.Run(ctx, jobUserCommand{Argv: argv})
	if err != nil {
		return "", err
	}
	for _, code := range allowed {
		if res.ExitCode == code {
			return res.Output, nil
		}
	}
	return res.Output, fmt.Errorf("%s exited %d: %s", strings.Join(argv[:min(len(argv), 3)], " "), res.ExitCode, strings.TrimSpace(res.Output))
}

// stopProcesses leaves nothing running as the slot's UID. pkill -u matches the
// effective UID and -U the real one, and both are used because a set-user-ID
// program can have one without the other.
func (u *jobUsers) stopProcesses(ctx context.Context, s *jobUserSlot) error {
	uid := strconv.Itoa(s.uid)
	deadline := u.now().Add(jobUserKillWithin)
	for {
		for _, a := range [][]string{{"-STOP", "-U"}, {"-STOP", "-u"}, {"-KILL", "-U"}, {"-KILL", "-u"}} {
			// Exit 1 is "no process matched", which is the goal.
			if _, err := u.runAllowing(ctx, []int{0, 1}, "/usr/bin/pkill", a[0], a[1], uid); err != nil {
				return err
			}
		}
		left, err := u.processesOf(ctx, s.uid)
		if err != nil {
			return err
		}
		if len(left) == 0 {
			return nil
		}
		if !u.now().Before(deadline) || ctx.Err() != nil {
			return fmt.Errorf("%d processes of %s were still there %s after SIGKILL (the first is %d)", len(left), s.name, jobUserKillWithin, left[0].PID)
		}
		u.pause(ctx, jobUserKillEvery)
	}
}

// bootoutNoDomain is what launchctl says when the user has no such domain, which
// is the usual case and not a failure. The exit codes are launchd's for "no
// such process" and "input/output error", which it uses for a domain that is not
// loaded, and an account that has never logged in has no gui domain at all, which
// launchd answers with "Domain does not support specified action" (exit 125).
var bootoutNoDomain = regexp.MustCompile(`(?i)no such process|could not find|not found|input/output error|no such domain|does not support specified action`)

func (u *jobUsers) bootoutDomains(ctx context.Context, s *jobUserSlot) error {
	for _, domain := range []string{"user", "gui"} {
		res, err := u.sys.Run(ctx, jobUserCommand{Argv: []string{"/bin/launchctl", "bootout", domain + "/" + strconv.Itoa(s.uid)}})
		if err != nil {
			return err
		}
		if res.ExitCode != 0 && !bootoutNoDomain.MatchString(res.Output) {
			return fmt.Errorf("launchctl bootout %s/%d exited %d: %s", domain, s.uid, res.ExitCode, strings.TrimSpace(res.Output))
		}
	}
	return nil
}

// removeScheduled removes the slot's crontab and at jobs. A job that left either
// would run in a later job's time, as the same account.
func (u *jobUsers) removeScheduled(ctx context.Context, s *jobUserSlot) error {
	// crontab -r exits non-zero for "no crontab for", which is the usual answer.
	res, err := u.sys.Run(ctx, jobUserCommand{Argv: []string{"/usr/bin/crontab", "-r", "-u", s.name}})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 && !strings.Contains(strings.ToLower(res.Output), "no crontab") {
		return fmt.Errorf("crontab -r -u %s exited %d: %s", s.name, res.ExitCode, strings.TrimSpace(res.Output))
	}
	// An at job is a file in the spool owned by whoever queued it. atq on macOS
	// prints no owner at all, even to root, so the spool is read instead: the
	// owner there is the kernel's record, which a job cannot change. Neither
	// follows a link nor leaves the spool's own volume.
	if _, err := u.run(ctx, "/usr/bin/find", "-x", "-P", jobUserAtSpool, "-maxdepth", "1", "-type", "f", "-user", strconv.Itoa(s.uid), "-delete"); err != nil {
		return err
	}
	return nil
}

// jobUserAtSpool is where macOS's at keeps queued jobs, one file per job.
const jobUserAtSpool = "/private/var/at/jobs"

// pathWithin says whether p is base or something under it, by whole names, so
// that /Users/zj01 does not claim /Users/zj010.
func pathWithin(base, p string) bool {
	base, p = filepath.Clean(base), filepath.Clean(p)
	return p == base || strings.HasPrefix(p, base+"/")
}

// unmountJobMounts takes off every filesystem the job left mounted, before the
// home is moved. A disk image attached with its mount point in the home goes
// with the folder that holds it, and would then be deleted through; and one
// attached elsewhere, such as under /Volumes or /private/tmp, outlives the job
// and every cleaned tree. What is taken is whatever is mounted at or under the
// slot's home, whoever mounted it, and whatever the slot's UID mounted anywhere,
// which the kernel records and a job cannot change. The table is read from the
// kernel, never parsed from the output of mount, because a mount point's name is
// the job's to choose.
func (u *jobUsers) unmountJobMounts(ctx context.Context, s *jobUserSlot) error {
	home := u.home(s)
	return u.unmountWhere(ctx, func(m jobUserMount) bool {
		return pathWithin(home, m.Path) || m.Owner == s.uid
	})
}

// unmountWhere unmounts the mounts that match, the deepest first, each with
// umount -f and then, if that fails, diskutil, and says if any is still there.
func (u *jobUsers) unmountWhere(ctx context.Context, match func(jobUserMount) bool) error {
	matching := func() ([]string, error) {
		mounts, err := u.sys.Mounts()
		if err != nil {
			return nil, fmt.Errorf("reading the mount table: %w", err)
		}
		var paths []string
		for _, m := range mounts {
			if match(m) {
				paths = append(paths, m.Path)
			}
		}
		// A mount under another has a longer path, and the outer one is busy until
		// the inner one has gone.
		sort.Slice(paths, func(i, j int) bool { return len(paths[i]) > len(paths[j]) })
		return paths, nil
	}
	paths, err := matching()
	if err != nil || len(paths) == 0 {
		return err
	}
	for _, p := range paths {
		if _, err := u.run(ctx, "/sbin/umount", "-f", p); err != nil {
			if _, err2 := u.run(ctx, "/usr/sbin/diskutil", "unmount", "force", p); err2 != nil {
				return fmt.Errorf("could not unmount %s (umount: %v; diskutil: %v)", p, err, err2)
			}
		}
	}
	left, err := matching()
	if err != nil {
		return err
	}
	if len(left) > 0 {
		return fmt.Errorf("%s is still mounted after it was unmounted", left[0])
	}
	return nil
}

// replaceHome moves the home aside and makes a new one. The rename is instant,
// because the trash is on the same volume, so a huge build folder does not hold
// the slot; the watcher deletes the trash later.
func (u *jobUsers) replaceHome(ctx context.Context, s *jobUserSlot) error {
	home := u.home(s)
	if _, err := u.sys.Lstat(home); err == nil {
		// A job can set flags that stop root removing or renaming its files, any of
		// them (uchg, schg, uappnd, sappnd), and a flag on a file inside the home
		// would stop the trash being emptied. They are all cleared, by value, and
		// not as a list of the ones somebody thought of.
		if _, err := u.run(ctx, "/usr/bin/chflags", "-R", "0", home); err != nil {
			return err
		}
		if err := u.sys.MkdirAll(u.trashDir, 0o700); err != nil {
			return fmt.Errorf("making the trash folder %s: %w", u.trashDir, err)
		}
		if err := u.sys.Chown(u.trashDir, 0, 0); err != nil {
			return fmt.Errorf("giving the trash folder %s to root: %w", u.trashDir, err)
		}
		dest := filepath.Join(u.trashDir, fmt.Sprintf("%s-%d", s.name, time.Now().UnixNano()))
		if err := u.sys.Rename(home, dest); err != nil {
			return fmt.Errorf("moving %s aside: %w", home, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("looking at %s: %w", home, err)
	}
	if _, err := u.run(ctx, "/usr/sbin/createhomedir", "-c", "-u", s.name); err != nil {
		return err
	}
	if _, err := u.run(ctx, "/bin/chmod", "700", home); err != nil {
		return err
	}
	return u.ensureManifest(s)
}

// userTempDir is what getconf prints for a user's temporary folder: three
// folders below /var/folders, the last of them T.
var userTempDir = regexp.MustCompile(`^((?:/private)?/var/folders/[A-Za-z0-9_]{2}/[A-Za-z0-9_]+)/T/?$`)

// removeUserTemp removes the folder macOS keeps the user's temporary and cache
// files in. Its place is asked of the system, as the slot user, because it is
// derived from the UID and not a name; what comes back is held to the exact
// shape before anything is removed as root.
func (u *jobUsers) removeUserTemp(ctx context.Context, s *jobUserSlot) error {
	dir, err := u.userTempDir(ctx, s)
	if err != nil {
		return err
	}
	m := userTempDir.FindStringSubmatch(dir)
	if m == nil {
		return fmt.Errorf("getconf printed %q for %s's temporary folder, which is not a per-user folder below /var/folders, so nothing was removed", dir, s.name)
	}
	parent := m[1]
	info, err := u.sys.Lstat(parent)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if uid, _, ok := u.sys.Owner(parent, info); !ok || uid != s.uid {
		return fmt.Errorf("%s is not owned by %s (UID %d), so it is not removed", parent, s.name, s.uid)
	}
	return u.sys.RemoveAll(parent)
}

// userTempDir asks the system, as the slot user, for its temporary folder.
func (u *jobUsers) userTempDir(ctx context.Context, s *jobUserSlot) (string, error) {
	out, err := u.runCmd(ctx, jobUserCommand{Argv: []string{"/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"}, AsUser: true, UID: s.uid, GID: jobUserGID})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// jobUserCleanedTrees are the places outside a home that a job can write to and
// the reset cleans: what the slot's UID owns in them is removed, and checked to be
// gone. /Library/Caches is there because a job can write to it when it is
// world-writable, which is how it is on the Macs this was written for; where it
// is not, the job owns nothing in it and cleaning it does nothing. The list is
// one variable, so that the cleaning, the check and the documentation cannot
// disagree about it. The users' shared folder, whose place depends on the
// configuration, is added by sharedTrees.
var jobUserCleanedTrees = []string{"/private/tmp", "/private/var/tmp", "/Library/Caches"}

// sharedTrees are the places on a standard install where any account can leave
// files, beside its own home.
func (u *jobUsers) sharedTrees() []string {
	return append(append([]string(nil), jobUserCleanedTrees...), filepath.Join(u.usersDir, "Shared"))
}

// removeSharedFiles removes what the UID owns in the shared trees. find does
// not cross volumes (-x) or follow links (-P), so a link planted in /tmp cannot
// point root's deletion anywhere else.
func (u *jobUsers) removeSharedFiles(ctx context.Context, s *jobUserSlot) error {
	for _, tree := range u.sharedTrees() {
		if _, err := u.sys.Lstat(tree); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return err
		}
		if _, err := u.run(ctx, "/usr/bin/find", "-x", "-P", tree, "-user", strconv.Itoa(s.uid), "-delete"); err != nil {
			return err
		}
	}
	return nil
}

// ipcObject is one System V object ipcs listed.
type ipcObject struct {
	flag string // "-m", "-s" or "-q", as ipcrm takes it
	id   string
}

// parseJobUserIPC reads ipcs -a for the objects an account owns or created.
// Its columns are T, ID, KEY, MODE, OWNER, GROUP, CREATOR, CGROUP, under a
// heading for each kind.
func parseJobUserIPC(out, name string, uid int) []ipcObject {
	var found []ipcObject
	uidText := strconv.Itoa(uid)
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 7 {
			continue
		}
		var flag string
		switch f[0] {
		case "q":
			flag = "-q"
		case "m":
			flag = "-m"
		case "s":
			flag = "-s"
		default:
			continue
		}
		if _, err := strconv.Atoi(f[1]); err != nil {
			continue
		}
		if f[4] == name || f[4] == uidText || f[6] == name || f[6] == uidText {
			found = append(found, ipcObject{flag: flag, id: f[1]})
		}
	}
	return found
}

func (u *jobUsers) removeIPC(ctx context.Context, s *jobUserSlot) error {
	out, err := u.run(ctx, "/usr/bin/ipcs", "-a")
	if err != nil {
		return err
	}
	for _, o := range parseJobUserIPC(out, s.name, s.uid) {
		if _, err := u.run(ctx, "/usr/bin/ipcrm", o.flag, o.id); err != nil {
			return err
		}
	}
	return nil
}

// verifyReset is the last step: nothing of the UID runs, the home is what
// createhomedir makes, and nothing the UID owns is left in the shared trees.
func (u *jobUsers) verifyReset(ctx context.Context, s *jobUserSlot) error {
	if err := u.verifySlot(ctx, s); err != nil {
		return err
	}
	for _, tree := range u.sharedTrees() {
		if _, err := u.sys.Lstat(tree); err != nil {
			continue
		}
		out, err := u.run(ctx, "/usr/bin/find", "-x", "-P", tree, "-user", strconv.Itoa(s.uid), "-print")
		if err != nil {
			return err
		}
		if strings.TrimSpace(out) != "" {
			first, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
			return fmt.Errorf("%s still owns files in %s, the first being %s", s.name, tree, first)
		}
	}
	return nil
}

// ---- the manifest ----

// homeListing is the home as one line per entry: its path from the home, its
// type and permission bits, and its owner. It is what a clean home is compared
// against, so a job's leftover shows up whatever it is called.
func (u *jobUsers) homeListing(s *jobUserSlot) (string, error) {
	home := u.home(s)
	var b bytes.Buffer
	var walk func(dir, rel string) error
	walk = func(dir, rel string) error {
		entries, err := u.sys.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				return err
			}
			uid, gid, _ := u.sys.Owner(filepath.Join(dir, e.Name()), info)
			name := path.Join(rel, e.Name())
			fmt.Fprintf(&b, "%s\t%s\t%d:%d\n", name, info.Mode().String(), uid, gid)
			if info.IsDir() {
				if err := walk(filepath.Join(dir, e.Name()), name); err != nil {
					return err
				}
			}
		}
		return nil
	}
	info, err := u.sys.Lstat(home)
	if err != nil {
		return "", err
	}
	uid, gid, _ := u.sys.Owner(home, info)
	fmt.Fprintf(&b, ".\t%s\t%d:%d\n", info.Mode().String(), uid, gid)
	if err := walk(home, ""); err != nil {
		return "", err
	}
	return b.String(), nil
}

// ensureManifest saves the listing of a fresh home the first time, after
// checking that the home really is what a job user's must be: its own, in the
// shared group, and closed to everybody else.
func (u *jobUsers) ensureManifest(s *jobUserSlot) error {
	listing, err := u.homeListing(s)
	if err != nil {
		return fmt.Errorf("listing the new home: %w", err)
	}
	first, _, _ := strings.Cut(listing, "\n")
	want := fmt.Sprintf(".\tdrwx------\t%d:%d", s.uid, jobUserGID)
	if first != want {
		return fmt.Errorf("the new home of %s is %q, and a job user's must be %q; createhomedir did not make what was expected", s.name, first, want)
	}
	if _, err := u.sys.ReadFile(u.manifestPath(s), 1<<20); err == nil {
		return nil
	}
	if err := u.sys.MkdirAll(u.stateDir, 0o700); err != nil {
		return fmt.Errorf("making %s: %w", u.stateDir, err)
	}
	if err := writeFileAtomic(u.manifestPath(s), []byte(listing), 0o600); err != nil {
		return fmt.Errorf("saving the manifest of %s: %w", s.name, err)
	}
	return nil
}

// verifySlot is the cheap check before a job, and the end of a reset: no
// process has the slot's UID, and the home holds exactly what the manifest says
// a fresh one does.
func (u *jobUsers) verifySlot(ctx context.Context, s *jobUserSlot) error {
	procs, err := u.processesOf(ctx, s.uid)
	if err != nil {
		return err
	}
	if len(procs) > 0 {
		return fmt.Errorf("%d processes of %s are still running, the first being %d", len(procs), s.name, procs[0].PID)
	}
	want, err := u.sys.ReadFile(u.manifestPath(s), 1<<20)
	if err != nil {
		return fmt.Errorf("there is no manifest of a clean home for %s: %w", s.name, err)
	}
	got, err := u.homeListing(s)
	if err != nil {
		return fmt.Errorf("listing the home of %s: %w", s.name, err)
	}
	if got != string(want) {
		return fmt.Errorf("the home of %s is not what a fresh one is: %s", s.name, firstListingDifference(string(want), got))
	}
	return nil
}

// firstListingDifference says what differs first, so the operator is told which
// file a job left rather than that something did.
func firstListingDifference(want, got string) string {
	have := map[string]bool{}
	for _, l := range strings.Split(want, "\n") {
		have[l] = true
	}
	for _, l := range strings.Split(got, "\n") {
		if l != "" && !have[l] {
			return fmt.Sprintf("%q is there and the manifest does not have it", l)
		}
	}
	in := map[string]bool{}
	for _, l := range strings.Split(got, "\n") {
		in[l] = true
	}
	for _, l := range strings.Split(want, "\n") {
		if l != "" && !in[l] {
			return fmt.Sprintf("%q is missing", l)
		}
	}
	return "its entries are in another order"
}

// ensureClean is what a slot goes through before a job: the cheap check, and the
// full reset when that fails.
func (u *jobUsers) ensureClean(ctx context.Context, s *jobUserSlot) error {
	err := u.verifySlot(ctx, s)
	if err == nil {
		return nil
	}
	u.log.Info("a job user was not clean, so it is being reset before the job", "slot", s.name, "reason", err)
	return u.resetSlot(ctx, s)
}
