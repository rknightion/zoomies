package backend

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeJobUsers is the host as the job-user machinery sees it: it records every
// command and file operation in order, answers the commands the machinery
// runs the way macOS does, and runs the file operations against a temporary
// folder standing in for /Users. A test scripts a failure with fail and reads
// what happened from log.
type fakeJobUsers struct {
	t        *testing.T
	usersDir string

	mu      sync.Mutex
	cmds    []jobUserCommand
	log     []string
	users   map[string]int
	groups  map[string]int
	groupOf map[string]int
	// shellOf, homeOf and admins are what dscl and dseditgroup say of an account;
	// an account not named here has the shell, home and standing Zoomies gives.
	shellOf map[string]string
	homeOf  map[string]string
	admins  map[string]bool
	procs   []jobUserProc
	// procsErr makes the process listing fail, as ps does when it cannot be run.
	procsErr error
	// stubborn keeps every process alive through pkill, so a reset has to give up.
	stubborn bool
	// ignoreUID makes sysadminctl hand out the next free UID from 503 whatever
	// -UID said, as it was seen to on a real Mac.
	ignoreUID bool
	rules     []fakeRule
	owners    map[string][2]int
	// lstat answers for paths that cannot exist on the machine the test runs on.
	lstat map[string]fs.FileInfo
	// readDir answers for folders that cannot exist on the machine the test runs on.
	readDir map[string][]fs.DirEntry
	ipcs    string
	findOut string
	// tempDir is what getconf prints.
	tempDir string
	started []fakeStart
	umasks  []int
	clock   time.Time
	// mounts is the mount table, and devs says which filesystem a path is on: a
	// path not in it is on filesystem 1. Unmounting removes a mount and what it
	// held from both.
	mounts []jobUserMount
	devs   map[string]uint64
	// onRun is called after every command, outside the fake's lock, so a test
	// can have the host change under the code that is running a command.
	onRun func(c jobUserCommand)
}

type fakeRule struct {
	prefix []string
	res    jobUserResult
	err    error
	once   bool
}

type fakeStart struct {
	uid, gid int
	dir      string
	env      []string
	path     string
}

func newFakeJobUsers(t *testing.T) *fakeJobUsers {
	t.Helper()
	return &fakeJobUsers{
		t:        t,
		usersDir: t.TempDir(),
		users:    map[string]int{"root": 0, "alice": 501},
		groups:   map[string]int{"staff": 20, "wheel": 0},
		groupOf:  map[string]int{},
		shellOf:  map[string]string{},
		homeOf:   map[string]string{},
		admins:   map[string]bool{},
		devs:     map[string]uint64{},
		owners:   map[string][2]int{},
		lstat:    map[string]fs.FileInfo{},
		readDir:  map[string][]fs.DirEntry{},
		tempDir:  "/var/folders/ab/cdef12/T/",
		clock:    time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC),
	}
}

// fail makes the next commands that start with prefix exit 2 and say boom.
func (f *fakeJobUsers) fail(prefix ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = append(f.rules, fakeRule{prefix: prefix, res: jobUserResult{ExitCode: 2, Output: "boom"}})
}

// failOnce is fail for one command.
func (f *fakeJobUsers) failOnce(prefix ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = append(f.rules, fakeRule{prefix: prefix, res: jobUserResult{ExitCode: 2, Output: "boom"}, once: true})
}

// answer scripts what the next commands starting with prefix print.
func (f *fakeJobUsers) answer(output string, prefix ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = append(f.rules, fakeRule{prefix: prefix, res: jobUserResult{Output: output}})
}

// answerCode is answer with an exit code, for a command that fails in a way the
// code has to read.
func (f *fakeJobUsers) answerCode(code int, output string, prefix ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = append(f.rules, fakeRule{prefix: prefix, res: jobUserResult{ExitCode: code, Output: output}})
}

func (f *fakeJobUsers) clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = nil
}

func (f *fakeJobUsers) logged() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

func (f *fakeJobUsers) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log, f.cmds = nil, nil
}

// indexOf is where the first logged entry containing every part is, or -1.
func (f *fakeJobUsers) indexOf(parts ...string) int { return f.indexAfter(0, parts...) }

func (f *fakeJobUsers) indexAfter(from int, parts ...string) int {
	log := f.logged()
	for i := from; i < len(log); i++ {
		ok := true
		for _, p := range parts {
			if !strings.Contains(log[i], p) {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

func (f *fakeJobUsers) count(parts ...string) int {
	n := 0
	for _, l := range f.logged() {
		ok := true
		for _, p := range parts {
			if !strings.Contains(l, p) {
				ok = false
			}
		}
		if ok {
			n++
		}
	}
	return n
}

func (f *fakeJobUsers) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clock
}

func (f *fakeJobUsers) advance(d time.Duration) {
	f.mu.Lock()
	f.clock = f.clock.Add(d)
	f.mu.Unlock()
}

func (f *fakeJobUsers) pause(_ context.Context, d time.Duration) { f.advance(d) }

func hasPrefix(argv, prefix []string) bool {
	if len(argv) < len(prefix) {
		return false
	}
	for i, p := range prefix {
		if filepath.Base(argv[i]) != filepath.Base(p) && argv[i] != p {
			return false
		}
	}
	return true
}

func (f *fakeJobUsers) Run(_ context.Context, c jobUserCommand) (jobUserResult, error) {
	res, err := f.run(c)
	f.mu.Lock()
	hook := f.onRun
	f.mu.Unlock()
	if hook != nil {
		hook(c)
	}
	return res, err
}

func (f *fakeJobUsers) run(c jobUserCommand) (jobUserResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, c)
	entry := "run " + strings.Join(c.Argv, " ")
	if c.AsUser {
		entry += fmt.Sprintf(" (as %d:%d)", c.UID, c.GID)
	}
	f.log = append(f.log, entry)
	for i, r := range f.rules {
		if hasPrefix(c.Argv, r.prefix) {
			if r.once {
				f.rules = append(f.rules[:i], f.rules[i+1:]...)
			}
			return r.res, r.err
		}
	}
	return f.defaultRun(c), nil
}

var fakeSlotName = regexp.MustCompile(`zj[0-9]{2}`)

func (f *fakeJobUsers) defaultRun(c jobUserCommand) jobUserResult {
	argv := c.Argv
	arg := func(i int) string {
		if i < len(argv) {
			return argv[i]
		}
		return ""
	}
	ok := jobUserResult{}
	switch filepath.Base(argv[0]) {
	case "dscl":
		switch {
		case arg(2) == "-list" && arg(3) == "/Users":
			return jobUserResult{Output: listIDs(f.users)}
		case arg(2) == "-list" && arg(3) == "/Groups":
			return jobUserResult{Output: listIDs(f.groups)}
		case arg(2) == "-read":
			name := strings.TrimPrefix(arg(3), "/Users/")
			switch arg(4) {
			case "UserShell":
				sh, set := f.shellOf[name]
				if !set {
					sh = jobUserLoginShell
				}
				return jobUserResult{Output: "UserShell: " + sh + "\n"}
			case "UniqueID":
				uid, set := f.users[name]
				if !set {
					return jobUserResult{ExitCode: 56, Output: "eDSRecordNotFound"}
				}
				return jobUserResult{Output: fmt.Sprintf("UniqueID: %d\n", uid)}
			case "NFSHomeDirectory":
				home, set := f.homeOf[name]
				if !set {
					home = filepath.Join(f.usersDir, name)
				}
				return jobUserResult{Output: "NFSHomeDirectory: " + home + "\n"}
			}
			g, set := f.groupOf[name]
			if !set {
				g = 20
			}
			return jobUserResult{Output: fmt.Sprintf("PrimaryGroupID: %d\n", g)}
		case arg(2) == "-create" && strings.HasPrefix(arg(3), "/Groups/") && arg(4) == "PrimaryGroupID":
			n, _ := strconv.Atoi(arg(5))
			f.groups[strings.TrimPrefix(arg(3), "/Groups/")] = n
		case arg(2) == "-create" && strings.HasPrefix(arg(3), "/Users/") && arg(4) == "PrimaryGroupID":
			n, _ := strconv.Atoi(arg(5))
			f.groupOf[strings.TrimPrefix(arg(3), "/Users/")] = n
		case arg(2) == "-create" && strings.HasPrefix(arg(3), "/Users/") && arg(4) == "UniqueID":
			n, _ := strconv.Atoi(arg(5))
			f.users[strings.TrimPrefix(arg(3), "/Users/")] = n
		case arg(2) == "-create" && strings.HasPrefix(arg(3), "/Users/") && arg(4) == "UserShell":
			f.shellOf[strings.TrimPrefix(arg(3), "/Users/")] = arg(5)
		case arg(2) == "-delete" && strings.HasPrefix(arg(3), "/Groups/"):
			delete(f.groups, strings.TrimPrefix(arg(3), "/Groups/"))
		}
	case "dseditgroup":
		// dseditgroup -o checkmember -m NAME admin
		if f.admins[arg(4)] {
			return jobUserResult{Output: "yes " + arg(4) + " is a member of " + arg(5) + "\n"}
		}
		return jobUserResult{ExitCode: 67, Output: "no " + arg(4) + " is NOT a member of " + arg(5) + "\n"}
	case "umount", "diskutil":
		path := argv[len(argv)-1]
		kept := f.mounts[:0:0]
		for _, m := range f.mounts {
			if m.Path != path {
				kept = append(kept, m)
			}
		}
		f.mounts = kept
		for p := range f.devs {
			if p == path || strings.HasPrefix(p, path+"/") {
				delete(f.devs, p)
			}
		}
	case "sysadminctl":
		switch arg(1) {
		case "-addUser":
			uid, _ := strconv.Atoi(arg(4))
			if f.ignoreUID {
				uid = 503 + len(f.users)
			}
			f.users[arg(2)] = uid
			f.groupOf[arg(2)] = 20
			// sysadminctl's own default, unless it is told otherwise.
			f.shellOf[arg(2)] = "/bin/zsh"
			for i, a := range argv {
				switch {
				case a == "-shell" && i+1 < len(argv):
					f.shellOf[arg(2)] = argv[i+1]
				case a == "-home" && i+1 < len(argv):
					f.homeOf[arg(2)] = argv[i+1]
				}
			}
		case "-deleteUser":
			delete(f.users, arg(2))
		}
	case "pkill":
		if arg(1) != "-KILL" {
			return jobUserResult{ExitCode: 1}
		}
		uid, _ := strconv.Atoi(arg(3))
		matched := false
		var left []jobUserProc
		for _, p := range f.procs {
			mine := p.RUID == uid || p.EUID == uid
			matched = matched || mine
			if !mine || f.stubborn {
				left = append(left, p)
			}
		}
		f.procs = left
		if !matched {
			return jobUserResult{ExitCode: 1}
		}
	case "createhomedir":
		home := filepath.Join(f.usersDir, arg(3))
		for _, d := range []string{"", "Library", "Documents"} {
			if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
				f.t.Fatal(err)
			}
		}
	case "getconf":
		return jobUserResult{Output: f.tempDir + "\n"}
	case "find":
		if arg(len(argv)-1) == "-print" {
			return jobUserResult{Output: f.findOut}
		}
	case "ipcs":
		return jobUserResult{Output: f.ipcs}
	case "cp":
		if err := cloneTree(argv[len(argv)-2], argv[len(argv)-1]); err != nil {
			return jobUserResult{ExitCode: 1, Output: err.Error()}
		}
	}
	return ok
}

func listIDs(m map[string]int) string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, "%-30s %d\n", n, m[n])
	}
	return b.String()
}

func (f *fakeJobUsers) record(s string) {
	f.mu.Lock()
	f.log = append(f.log, s)
	f.mu.Unlock()
}

func (f *fakeJobUsers) Lstat(path string) (fs.FileInfo, error) {
	f.mu.Lock()
	info, ok := f.lstat[path]
	f.mu.Unlock()
	if ok {
		return info, nil
	}
	// The shared trees are real folders on a Mac and not on the machine the test
	// runs on, so they stand for the temporary folder.
	if path == "/private/tmp" || path == "/private/var/tmp" {
		path = os.TempDir()
	}
	return os.Lstat(path)
}
func (f *fakeJobUsers) ReadDir(path string) ([]fs.DirEntry, error) {
	f.mu.Lock()
	entries, ok := f.readDir[path]
	f.mu.Unlock()
	if ok {
		return entries, nil
	}
	return os.ReadDir(path)
}
func (f *fakeJobUsers) Rename(oldPath, newPath string) error {
	f.record("rename " + oldPath + " " + newPath)
	return os.Rename(oldPath, newPath)
}
func (f *fakeJobUsers) RemoveAll(path string) error {
	f.record("removeall " + path)
	return os.RemoveAll(path)
}
func (f *fakeJobUsers) MkdirAll(path string, perm fs.FileMode) error { return os.MkdirAll(path, perm) }
func (f *fakeJobUsers) Chown(path string, uid, gid int) error {
	f.record(fmt.Sprintf("chown %s %d:%d", path, uid, gid))
	return nil
}

func (f *fakeJobUsers) Owner(path string, _ fs.FileInfo) (int, int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if o, ok := f.owners[path]; ok {
		return o[0], o[1], true
	}
	rel, err := filepath.Rel(f.usersDir, path)
	if err == nil {
		if m := fakeSlotName.FindString(strings.SplitN(rel, string(filepath.Separator), 2)[0]); m != "" {
			n, _ := strconv.Atoi(m[2:])
			return jobUserUID(n), jobUserGID, true
		}
	}
	return 0, 0, true
}

func (f *fakeJobUsers) ReadFile(path string, max int64) ([]byte, error) {
	f.record("readfile " + path)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return os.ReadFile(path)
}

func (f *fakeJobUsers) Dev(path string, _ fs.FileInfo) (uint64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if d, ok := f.devs[path]; ok {
		return d, true
	}
	return 1, true
}

func (f *fakeJobUsers) Mounts() ([]jobUserMount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]jobUserMount(nil), f.mounts...), nil
}

func (f *fakeJobUsers) Processes(context.Context) ([]jobUserProc, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.procsErr != nil {
		return nil, f.procsErr
	}
	return append([]jobUserProc(nil), f.procs...), nil
}

// Start runs the command as the test's own user, which is the most a test can
// do without root, and records who it would have run as.
func (f *fakeJobUsers) Start(cmd *exec.Cmd, uid, gid int) error {
	f.mu.Lock()
	f.started = append(f.started, fakeStart{uid: uid, gid: gid, dir: cmd.Dir, env: append([]string(nil), cmd.Env...), path: cmd.Path})
	f.log = append(f.log, fmt.Sprintf("start %s (as %d:%d)", cmd.Path, uid, gid))
	f.mu.Unlock()
	return cmd.Start()
}

func (f *fakeJobUsers) SetUmask(mask int) {
	f.mu.Lock()
	f.umasks = append(f.umasks, mask)
	f.mu.Unlock()
}

var _ jobUserSystem = (*fakeJobUsers)(nil)

// jobUserFixture is a process backend in job-user mode over the fake host.
type jobUserFixture struct {
	b     *ProcessBackend
	u     *jobUsers
	f     *fakeJobUsers
	root  string
	state string
}

// newJobUserFixture builds the backend with capacity jobs at once and has not
// started it. The runner release is a stub that waits for SIGINT.
func newJobUserFixture(t *testing.T, capacity int, tweak ...func(*JobUserOptions)) *jobUserFixture {
	t.Helper()
	requireUnix(t)
	f := newFakeJobUsers(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(f.usersDir, "Shared"), 0o755); err != nil {
		t.Fatal(err)
	}
	installStubRunner(t, root, stubVersion, stubListener, "")
	return buildJobUserFixture(t, f, root, filepath.Join(t.TempDir(), "job-users"), capacity, tweak...)
}

// restart is a second agent process on the same host, work folder and state:
// what is left of the first is what the second adopts.
func (x *jobUserFixture) restart(t *testing.T, capacity int, tweak ...func(*JobUserOptions)) *jobUserFixture {
	t.Helper()
	return buildJobUserFixture(t, x.f, x.root, x.state, capacity, tweak...)
}

func buildJobUserFixture(t *testing.T, f *fakeJobUsers, root, state string, capacity int, tweak ...func(*JobUserOptions)) *jobUserFixture {
	t.Helper()
	o := JobUserOptions{
		Capacity: capacity,
		StateDir: state,
		UsersDir: f.usersDir,
		Now:      f.now,
		system:   f,
		pause:    f.pause,
	}
	for _, tw := range tweak {
		tw(&o)
	}
	b, err := NewProcess(ProcessOptions{WorkDir: root, RunnerVersion: stubVersion, Logger: quietLogger(), JobUsers: &o})
	if err != nil {
		t.Fatalf("NewProcess: %v", err)
	}
	t.Cleanup(b.Close)
	return &jobUserFixture{b: b, u: b.jobUsers, f: f, root: root, state: state}
}

// startedJobUserFixtureWithAccounts is startedJobUserFixture on a Mac where the
// first existing accounts were made already, in the group, as an earlier agent
// with a bigger capacity would have left them.
func startedJobUserFixtureWithAccounts(t *testing.T, capacity, existing int) *jobUserFixture {
	t.Helper()
	x := newJobUserFixture(t, capacity)
	x.f.groups[jobUserGroup] = jobUserGID
	for n := 1; n <= existing; n++ {
		x.f.users[jobUserName(n)] = jobUserUID(n)
		x.f.groupOf[jobUserName(n)] = jobUserGID
	}
	if err := x.b.StartJobUsers(context.Background()); err != nil {
		t.Fatalf("StartJobUsers: %v", err)
	}
	x.f.reset()
	return x
}

// startedFixture is newJobUserFixture after StartJobUsers.
func startedJobUserFixture(t *testing.T, capacity int, tweak ...func(*JobUserOptions)) *jobUserFixture {
	t.Helper()
	x := newJobUserFixture(t, capacity, tweak...)
	if err := x.b.StartJobUsers(context.Background()); err != nil {
		t.Fatalf("StartJobUsers: %v", err)
	}
	x.f.reset()
	return x
}

func jobUserSpec(name string) Spec {
	s := processSpec()
	s.Name = name
	return s
}

// stopAll interrupts and removes every runner the fixture started, so no stub
// listener outlives its test.
func (x *jobUserFixture) cleanup(t *testing.T, handles ...Handle) {
	t.Helper()
	t.Cleanup(func() {
		for _, h := range handles {
			_ = x.b.Remove(context.Background(), h)
		}
	})
}
