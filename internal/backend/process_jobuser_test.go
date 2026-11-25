package backend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// jobUserCreate starts a runner and registers its removal.
func jobUserCreate(t *testing.T, x *jobUserFixture, name string) Handle {
	t.Helper()
	r, err := x.b.CreateWithResult(context.Background(), jobUserSpec(name))
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	x.cleanup(t, r.Handle)
	return r.Handle
}

func slotOf(t *testing.T, h Handle) string {
	t.Helper()
	meta, err := readMeta(string(h))
	if err != nil {
		t.Fatal(err)
	}
	return meta.Slot
}

func TestJobUserCreateRefusesANonEphemeralPool(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	spec := jobUserSpec("runner-a")
	spec.Ephemeral = false
	_, err := x.b.CreateWithResult(context.Background(), spec)
	if !errors.Is(err, ErrBackendConfig) || !strings.Contains(err.Error(), "ephemeral") {
		t.Fatalf("create = %v; want ErrBackendConfig saying the pool must be ephemeral", err)
	}
	// Nothing was reserved, laid out or started.
	if len(x.f.logged()) != 0 || x.u.slotNamed("zj01").holder != "" {
		t.Errorf("a refused pool still touched the host: %v", x.f.logged())
	}

	// A registration token is how a runner joins a pool that is not ephemeral,
	// and the job-user launcher has no use for one.
	spec = jobUserSpec("runner-a")
	spec.Credentials.JITConfig = ""
	spec.Credentials.RegistrationToken = "a-token"
	spec.Credentials.URL = "https://github.com/example"
	if _, err := x.b.CreateWithResult(context.Background(), spec); !errors.Is(err, ErrBackendConfig) {
		t.Errorf("a create with a registration token and no just-in-time configuration = %v", err)
	}
}

func TestJobUserCreateTakesTheLowestFreeHealthySlot(t *testing.T) {
	x := startedJobUserFixture(t, 3)
	a := jobUserCreate(t, x, "runner-a")
	b := jobUserCreate(t, x, "runner-b")
	if slotOf(t, a) != "zj01" || slotOf(t, b) != "zj02" {
		t.Fatalf("first two runners are in %s and %s", slotOf(t, a), slotOf(t, b))
	}
	if err := x.b.Remove(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	c := jobUserCreate(t, x, "runner-c")
	if slotOf(t, c) != "zj01" {
		t.Errorf("a freed zj01 was passed over for %s", slotOf(t, c))
	}

	// An unhealthy slot is skipped, and comes back to the front when it is well.
	x.u.markUnhealthy(x.u.slotNamed("zj03"), errors.New("boom"))
	d := jobUserCreate(t, x, "runner-d")
	if slotOf(t, d) != "zj04" {
		t.Errorf("runner-d is in %s; zj03 is unhealthy and zj01 and zj02 are held", slotOf(t, d))
	}
}

func TestJobUserCreateReportsBusyWhenEverySlotIsHeldOrUnhealthy(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	jobUserCreate(t, x, "runner-a")
	jobUserCreate(t, x, "runner-b")
	_, err := x.b.CreateWithResult(context.Background(), jobUserSpec("runner-c"))
	if !errors.Is(err, ErrDaemonBusy) || !strings.Contains(err.Error(), "running a job") {
		t.Fatalf("create with every slot held = %v; want the busy error the agent retries", err)
	}
	if err := x.b.Remove(context.Background(), Handle(x.u.slotNamed("zj02").holder)); err != nil {
		t.Fatal(err)
	}
	x.u.markUnhealthy(x.u.slotNamed("zj02"), errors.New("boom"))
	_, err = x.b.CreateWithResult(context.Background(), jobUserSpec("runner-c"))
	if !errors.Is(err, ErrDaemonBusy) || !strings.Contains(err.Error(), "zj02") {
		t.Fatalf("create with one held and one unhealthy = %v; want busy naming zj02", err)
	}
}

func TestJobUserCreateReleasesTheReservationWhenAStepFails(t *testing.T) {
	steps := map[string][]string{
		"the egress check":        {"zoomies", "agent", "egress-probe"},
		"asking for the temp dir": {"getconf"},
		"laying out the runner":   {"cp"},
		"giving it to the user":   {"chown"},
	}
	for name, prefix := range steps {
		x := startedJobUserFixture(t, 1)
		x.f.fail(prefix...)
		if _, err := x.b.CreateWithResult(context.Background(), jobUserSpec("runner-a")); err == nil {
			t.Errorf("%s: the create went ahead", name)
			continue
		}
		if holder := x.u.slotNamed("zj01").holder; holder != "" {
			t.Errorf("%s: zj01 is still held by %q", name, holder)
		}
		// A refused create leaves no record behind for the agent to find.
		if entries, _ := os.ReadDir(filepath.Join(x.root, runnersDirName)); len(entries) != 0 {
			t.Errorf("%s: %d records left", name, len(entries))
		}
		x.f.clear()
		x.u.state.file.HoldUntil = time.Time{}
		jobUserCreate(t, x, "runner-a")
	}
}

func TestJobUserCreateStartsTheListenerAsTheSlotUserInTheSlotsHome(t *testing.T) {
	x := startedJobUserFixture(t, 2)
	h := jobUserCreate(t, x, "runner-a")
	waitForLog(t, string(h), "listener started with run", 10*time.Second)

	home := filepath.Join(x.f.usersDir, "zj01")
	runDir := filepath.Join(home, jobUserRunDirName)
	if len(x.f.started) != 1 {
		t.Fatalf("%d runners started", len(x.f.started))
	}
	st := x.f.started[0]
	if st.uid != 651 || st.gid != jobUserGID {
		t.Errorf("started as %d:%d, want 651:650", st.uid, st.gid)
	}
	if st.dir != runDir || st.path != filepath.Join(runDir, listenerPath) {
		t.Errorf("started %s in %s; want the listener in %s", st.path, st.dir, runDir)
	}
	env := envMap(st.env)
	if env["HOME"] != home || env["USER"] != "zj01" || env[EnvUpstreamJITConfig] != "eyJhbGciOi" {
		t.Errorf("environment = %v", env)
	}
	if _, ok := env["RUNNER_ALLOW_RUNASROOT"]; ok {
		t.Error("the runner was told it may run as root")
	}

	// The stub wrote where it ran: the slot's home, not the agent's record.
	if _, err := os.Stat(filepath.Join(runDir, "listener-args.txt")); err != nil {
		t.Errorf("the listener did not run in the slot's home: %v", err)
	}
	if _, err := os.Stat(filepath.Join(string(h), "listener-args.txt")); err == nil {
		t.Error("the listener ran in the record folder")
	}
	// The record is the agent's and holds no runner.
	meta, err := readMeta(string(h))
	if err != nil || meta.Slot != "zj01" || meta.RunDir != runDir || meta.PID == 0 || meta.ProcessIdentity == "" {
		t.Fatalf("meta = %+v, %v", meta, err)
	}
	if _, err := os.Stat(filepath.Join(string(h), jobUserRunDirName)); err == nil {
		t.Error("the runner was laid out in the record folder")
	}

	// Cloned, then given to the user, and both before the start.
	clone := x.f.indexOf("cp -c -R -P", runDir)
	chown := x.f.indexOf("chown -R -h 651:650", runDir)
	start := x.f.indexOf("start " + filepath.Join(runDir, listenerPath))
	probe := x.f.indexOf("egress-probe")
	if probe < 0 || clone < 0 || chown < 0 || start < 0 || !(probe < clone && clone < chown && chown < start) {
		t.Errorf("probe %d, clone %d, chown %d, start %d; want that order: %v", probe, clone, chown, start, x.f.logged())
	}
	if st := x.f.umasks; len(st) == 0 || st[0] != 0o022 {
		t.Errorf("umask calls = %v; the agent sets 022 at start", st)
	}
}

func TestJobUserRemoveCopiesDiagWithoutFollowingLinksThenResets(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	h := jobUserCreate(t, x, "runner-a")
	waitForLog(t, string(h), "listener started with run", 10*time.Second)
	runDir := filepath.Join(x.f.usersDir, "zj01", jobUserRunDirName)

	secret := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(secret, []byte("the agent's credentials"), 0o600); err != nil {
		t.Fatal(err)
	}
	diag := filepath.Join(runDir, "_diag")
	if err := os.MkdirAll(filepath.Join(diag, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(diag, "Runner_20261125.log"), []byte("runner log"), 0o644))
	must(os.WriteFile(filepath.Join(diag, "Worker_20261125.log"), []byte("worker log"), 0o644))
	must(os.WriteFile(filepath.Join(diag, "nested", "inner.log"), []byte("not copied"), 0o644))
	// What a hostile job leaves: a link to something of the agent's, and a file
	// too big to keep.
	must(os.Symlink(secret, filepath.Join(diag, "evil.log")))
	big, err := os.Create(filepath.Join(diag, "huge.log"))
	must(err)
	must(big.Truncate(jobUserDiagLimit + 1))
	must(big.Close())
	x.f.reset()

	if err := x.b.Remove(context.Background(), h); err != nil {
		t.Fatal(err)
	}

	kept := filepath.Join(x.root, jobUserDiagDir, filepath.Base(string(h)))
	entries, err := os.ReadDir(kept)
	if err != nil {
		t.Fatalf("no diagnostics were kept: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "Runner_20261125.log,Worker_20261125.log" {
		t.Errorf("kept %v; want the two regular files and neither the link, the folder nor the big file", names)
	}
	if b, _ := os.ReadFile(filepath.Join(kept, "Runner_20261125.log")); string(b) != "runner log" {
		t.Errorf("the copy holds %q", b)
	}
	// Everything of the job was stopped before its folder was read as root, and
	// the reset came after the copy: the old home is gone and the new one is bare.
	stop := x.f.indexOf("pkill -KILL -U 651")
	read := x.f.indexOf("readfile", "_diag")
	reset := x.f.indexOf("createhomedir -c -u zj01")
	if stop < 0 || read < 0 || reset < 0 || !(stop < read && read < reset) {
		t.Errorf("stop at %d, read of _diag at %d, reset at %d; want them in that order: %v", stop, read, reset, x.f.logged())
	}
	if _, err := os.Stat(filepath.Join(runDir, "_diag")); err == nil {
		t.Error("the job's folder survived the reset")
	}
	if holder := x.u.slotNamed("zj01").holder; holder != "" {
		t.Errorf("the slot is still held by %q after the record went", holder)
	}
	if _, err := os.Stat(string(h)); err == nil {
		t.Error("the record is still there")
	}
}

func TestJobUserRemoveStillResetsWhenTheDiagCopyFails(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	h := jobUserCreate(t, x, "runner-a")
	runDir := filepath.Join(x.f.usersDir, "zj01", jobUserRunDirName)
	if err := os.MkdirAll(filepath.Join(runDir, "_diag"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "_diag", "a.log"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The keep folder cannot be made: a file stands where it should be.
	if err := os.WriteFile(filepath.Join(x.root, jobUserDiagDir), []byte("in the way"), 0o644); err != nil {
		t.Fatal(err)
	}
	x.f.reset()
	if err := x.b.Remove(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if x.f.indexOf("createhomedir -c -u zj01") < 0 {
		t.Error("a failed copy stopped the reset")
	}
}

func TestOldDiagnosticsArePrunedToTheNewest(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour)
	for i := range 5 {
		d := filepath.Join(dir, string(rune('a'+i)))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(d, base.Add(time.Duration(i)*time.Minute), base.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	pruneJobUserDiag(dir, 3, quietLogger())
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, "") != "cde" {
		t.Errorf("kept %v; want the three newest", names)
	}
}

func TestJobUserRemoveOfAnAdoptedRunnerResetsItsSlot(t *testing.T) {
	first := startedJobUserFixture(t, 2)
	h := jobUserCreate(t, first, "runner-a")
	waitForLog(t, string(h), "listener started with run", 10*time.Second)

	// The agent restarts. Its successor finds the runner by its record.
	second := first.restart(t, 2)
	if err := second.b.StartJobUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := second.u.slotNamed("zj01").holder; got != string(h) {
		t.Fatalf("zj01 is held by %q; want the adopted runner %q", got, h)
	}
	workloads, err := second.b.List(context.Background())
	if err != nil || len(workloads) != 1 || workloads[0].Status.Phase != PhaseRunning {
		t.Fatalf("List = %+v, %v; want the adopted runner running", workloads, err)
	}
	second.f.reset()

	if err := second.b.Remove(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if second.f.indexOf("createhomedir -c -u zj01") < 0 || second.f.indexOf("pkill -KILL -U 651") < 0 {
		t.Errorf("the adopted runner's slot was not cleaned: %v", second.f.logged())
	}
	if second.u.slotNamed("zj01").holder != "" {
		t.Error("the slot was not given back")
	}
}

func TestJobUserStatusIsReadUntilRemove(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	h := jobUserCreate(t, x, "runner-a")
	waitForLog(t, string(h), "listener started with run", 10*time.Second)
	if err := x.b.Stop(context.Background(), h, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	waitForPhase(t, x.b, h, PhaseExited, 10*time.Second)

	// The record, and the slot, stay until the agent has read the exit.
	time.Sleep(100 * time.Millisecond)
	st, err := x.b.Status(context.Background(), h)
	if err != nil || st.Phase != PhaseExited {
		t.Fatalf("Status = %+v, %v", st, err)
	}
	if x.u.slotNamed("zj01").holder == "" {
		t.Error("the slot was given back before the runner was removed")
	}
	if x.f.indexOf("createhomedir") >= 0 {
		t.Error("the home was wiped before the runner was removed")
	}
	workloads, err := x.b.List(context.Background())
	if err != nil || len(workloads) != 1 {
		t.Fatalf("List = %v, %v", workloads, err)
	}

	if err := x.b.Remove(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if _, err := x.b.Status(context.Background(), h); !errors.Is(err, ErrNotFound) {
		t.Errorf("Status after Remove = %v; want not found", err)
	}
	if x.f.indexOf("createhomedir -c -u zj01") < 0 {
		t.Error("Remove did not clean the slot")
	}
}

func TestJobUserRestartRebuildsSlotsAndResetsTheFreeOnes(t *testing.T) {
	first := startedJobUserFixture(t, 2)
	h := jobUserCreate(t, first, "runner-a")
	waitForLog(t, string(h), "listener started with run", 10*time.Second)

	second := first.restart(t, 2)
	if err := second.b.StartJobUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	// zj01 holds a running job and is not touched; zj02 and zj03 are free and
	// cleaned in full before they are offered, even though they look clean.
	if second.f.indexOf("createhomedir -c -u zj01") >= 0 || second.f.indexOf("pkill", "651") >= 0 {
		t.Errorf("the slot of a running job was reset: %v", second.f.logged())
	}
	for _, name := range []string{"zj02", "zj03"} {
		if second.f.indexOf("createhomedir -c -u "+name) < 0 {
			t.Errorf("%s was offered without a reset", name)
		}
	}
	// The next job gets the first free one, not the busy one.
	h2 := jobUserCreate(t, second, "runner-b")
	if slotOf(t, h2) != "zj02" {
		t.Errorf("the next job is in %s", slotOf(t, h2))
	}
	// The accounts already existed, so none was made again.
	if second.f.count("sysadminctl") != 0 {
		t.Error("an account was made twice")
	}
}

func TestJobUserProbeSaysWhatTheHostCanDo(t *testing.T) {
	x := newJobUserFixture(t, 2)
	if info := x.b.Probe(context.Background()); info.Available || !strings.Contains(info.Detail, "not been set up") {
		t.Errorf("before start: %+v", info)
	}
	if err := x.b.StartJobUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	info := x.b.Probe(context.Background())
	if !info.Available || !info.Rootless || !strings.Contains(info.Detail, "each job runs as its own job user (zj01 to zj03), never as root or as the agent") {
		t.Errorf("a ready host: %+v", info)
	}

	x.u.markUnhealthy(x.u.slotNamed("zj02"), errors.New("boom"))
	info = x.b.Probe(context.Background())
	if !info.Available || !strings.Contains(info.Detail, "zj02") {
		t.Errorf("one slot out: %+v; want it still available and saying which", info)
	}
	for _, n := range []string{"zj01", "zj03"} {
		x.u.markUnhealthy(x.u.slotNamed(n), errors.New("boom"))
	}
	if info = x.b.Probe(context.Background()); info.Available || !strings.Contains(info.Detail, "no job user can take a job") {
		t.Errorf("every slot out: %+v", info)
	}
}

func TestJobUserBackendIsSlotSizedAndThePlainOneIsNot(t *testing.T) {
	x := newJobUserFixture(t, 1)
	if !x.b.SlotSized() {
		t.Error("a job-user host reports itself sized by cores and memory")
	}
	plain, _ := newStubProcessBackend(t)
	if plain.SlotSized() || plain.ProbeStale() {
		t.Error("the plain process backend changed")
	}
	plain.Close()
}

func TestJobUserBackendRefusesTheAccountsWhenNothingFitsBeforeStart(t *testing.T) {
	x := newJobUserFixture(t, 1)
	_, err := x.b.CreateWithResult(context.Background(), jobUserSpec("runner-a"))
	if err == nil || !strings.Contains(err.Error(), "not been set up") {
		t.Fatalf("create before StartJobUsers = %v", err)
	}
}

func TestNewProcessRefusesJobUsersWithNoEgressListsOrTooManyJobs(t *testing.T) {
	f := newFakeJobUsers(t)
	for name, tweak := range map[string]func(*JobUserOptions){
		"no allow list": func(o *JobUserOptions) { o.EgressMustAllow = nil },
		"no block list": func(o *JobUserOptions) { o.EgressMustBlock = nil },
		"a block name":  func(o *JobUserOptions) { o.EgressMustBlock = []string{"example.com:443"} },
		"no jobs":       func(o *JobUserOptions) { o.Capacity = 0 },
		"too many jobs": func(o *JobUserOptions) { o.Capacity = jobUserMaxCapacity + 1 },
		"an IPv6 block": func(o *JobUserOptions) { o.EgressMustBlock = []string{"[2001:db8::1]:443"} },
	} {
		o := JobUserOptions{Capacity: 2, EgressMustAllow: []string{"github.com:443"}, EgressMustBlock: []string{"198.51.100.10:443"}, StateDir: t.TempDir(), system: f}
		tweak(&o)
		if _, err := NewProcess(ProcessOptions{WorkDir: t.TempDir(), JobUsers: &o, Logger: quietLogger()}); !errors.Is(err, ErrBackendConfig) {
			t.Errorf("%s: NewProcess = %v", name, err)
		}
	}
}

func TestJobUserHostIsNotHeldByRunnersThatExitWithoutTakingAJob(t *testing.T) {
	// The VM backend holds a host whose runners keep leaving without a job. Here
	// there is no evidence a runner outside the job's own home could rely on: a
	// job can delete the worker's logs, and a burst of short jobs on a healthy host
	// looks the same. The design leaves the breaker out of this mode.
	x := startedJobUserFixture(t, 1)
	for i := range vmpalBreakerThreshold + 1 {
		h := jobUserCreate(t, x, "runner-"+string(rune('a'+i)))
		meta, _ := readMeta(string(h))
		if err := syscall.Kill(meta.PID, syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		waitForPhase(t, x.b, h, PhaseFailed, 10*time.Second)
		if err := x.b.Remove(context.Background(), h); err != nil {
			t.Fatal(err)
		}
		if held := x.u.state.held(); held != nil {
			t.Fatalf("held after %d runners left without a job: %v", i+1, held)
		}
	}
}

func TestJobUserCreateHoldsTheHostWhenTheFirewallIsGone(t *testing.T) {
	x := startedJobUserFixture(t, 2)
	x.f.pfRules = ""
	x.f.procs = []jobUserProc{{PID: 9, RUID: 652, EUID: 652}}
	_, err := x.b.CreateWithResult(context.Background(), jobUserSpec("runner-a"))
	if !errors.Is(err, errJobUsersHeld) {
		t.Fatalf("create with no firewall = %v", err)
	}
	if len(x.f.started) != 0 {
		t.Error("a runner started with no firewall")
	}
	if len(x.f.procs) != 0 {
		t.Error("a running job was left with no firewall")
	}
	if x.u.slotNamed("zj01").holder != "" {
		t.Error("the slot stayed reserved")
	}
}
