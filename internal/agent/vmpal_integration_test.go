//go:build !windows

package agent

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eyupio/zoomies/internal/backend"
	"github.com/eyupio/zoomies/internal/store"
	"github.com/eyupio/zoomies/test/fakevmpal"
)

// These tests put the real agent, the real macOS VM backend and a fake vmpal
// command together, which is the one arrangement no unit test on either side
// sees. The backend's own tests prove the clone lifecycle with a stand-in for
// the agent, and the agent's tests prove the task lifecycle with a stand-in
// for the backend; what neither can show is that the sentences and codes one
// produces are the ones the other acts on.
//
// The only parts that are not real are the controller (a fake transport) and
// the Mac (the fake command, which runs nothing and answers from a script).

func TestMain(m *testing.M) {
	code := m.Run()
	fakevmpal.CleanUp()
	os.Exit(code)
}

const (
	vmpalE2ETemplate = "ci-template"
	vmpalE2EJIT      = "jit-config-that-must-stay-secret"
	// vmpalE2EWatch is how long a test allows for the backend's watcher to see an
	// exit. The watcher reads every fifteen seconds and that is not adjustable
	// from outside the backend package, so a test that waits for a runner's end
	// waits for a tick.
	vmpalE2EWatch = 45 * time.Second
)

var vmpalE2ECloneName = regexp.MustCompile("^zoomies-vm-[0-9a-f]{8}-run_[A-Za-z0-9]+$")

// recordingTransport is the fake controller plus a memory of every runner
// report, because what the agent says about an ending is the whole subject.
type recordingTransport struct {
	*fakeTransport

	mu      sync.Mutex
	reports []RunnerReport
}

func (r *recordingTransport) ReportRunners(ctx context.Context, reports []RunnerReport) error {
	if err := r.fakeTransport.ReportRunners(ctx, reports); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reports = append(r.reports, reports...)
	return nil
}

// ended is the first report of a runner reaching the end of its life, which is
// the one the controller acts on.
func (r *recordingTransport) ended(runnerID string) (RunnerReport, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rep := range r.reports {
		if rep.RunnerID == runnerID && rep.State.Terminal() && !rep.HostRemoved {
			return rep, true
		}
	}
	return RunnerReport{}, false
}

func (r *recordingTransport) hostRemoved(runnerID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rep := range r.reports {
		if rep.RunnerID == runnerID && rep.HostRemoved {
			return true
		}
	}
	return false
}

// vmpalE2E is one Mac: a fake vmpal with a template, a work directory that
// survives an agent restart, and the options every backend of it is built from.
type vmpalE2E struct {
	t    *testing.T
	fake *fakevmpal.Fake
	work string
	opts backend.VMPalOptions
}

func newVMPalE2E(t *testing.T) *vmpalE2E {
	t.Helper()
	fake := fakevmpal.New(t)
	fake.AddTemplate(vmpalE2ETemplate)
	for match, reply := range map[string]string{
		"helper.sh session": "zoomies-session v1 uid=501 gui=1\n",
		"helper.sh arm":     "zoomies-arm v1 ok source=cache\n",
		"helper.sh deliver": "zoomies-deliver v1 ok\n",
		"helper.sh start":   "zoomies-start v1 ok\n",
		"helper.sh exit":    "zoomies-exit v1 running\n",
		"helper.sh stop":    "zoomies-stop v1 ok\n",
	} {
		fake.OnExec(match, fakevmpal.ExecReply{Stdout: reply})
	}
	const allow, block = "allowed.example:443", "203.0.113.10:22"
	fake.OnEgress(map[string]string{allow: "connected", block: "timeout"})

	// The real gate, not the test one the backend's own tests inject: the policy
	// check is a real executable, and the Mac "reaches" the must-block target so
	// that the guest's timeout means something.
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy-check")
	if err := os.WriteFile(policy, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	return &vmpalE2E{t: t, fake: fake, work: work, opts: backend.VMPalOptions{
		GOOS: "darwin", Binary: fake.Path(), Template: vmpalE2ETemplate, MaxVMs: 2,
		GuestCIDR: "192.0.2.0/24", PolicyCheck: policy,
		EgressMustAllow: []string{allow}, EgressMustBlock: []string{block},
		EgressDial: func(context.Context, string) error { return nil },
		WorkDir:    work, RunnerSHA256: strings.Repeat("ab", 32),
		Logger: testLogger(),
	}}
}

// exits scripts what the guest's exit record says from now on.
func (m *vmpalE2E) exits(record string) {
	m.t.Helper()
	m.fake.OnExec("helper.sh exit", fakevmpal.ExecReply{Stdout: record + "\n"})
}

func (m *vmpalE2E) clones() []string {
	m.t.Helper()
	var out []string
	for _, vm := range m.fake.VMs() {
		if strings.HasPrefix(vm.Name, "zoomies-vm-") {
			out = append(out, vm.Name)
		}
	}
	return out
}

func (m *vmpalE2E) ledgerFiles() []string {
	m.t.Helper()
	files, err := filepath.Glob(filepath.Join(m.work, "vmpal", "clones", "*"))
	if err != nil {
		m.t.Fatal(err)
	}
	return files
}

func (m *vmpalE2E) execs(match string) []fakevmpal.ExecCall {
	m.t.Helper()
	var out []fakevmpal.ExecCall
	for _, c := range m.fake.Execs() {
		if strings.Contains(strings.Join(c.Argv, " "), match) {
			out = append(out, c)
		}
	}
	return out
}

// assertCredentialOnlyDelivered checks the one place the JIT config may be: the
// environment of the single deliver step, and nowhere in any argument.
func (m *vmpalE2E) assertCredentialOnlyDelivered() {
	m.t.Helper()
	var carriers []string
	for _, c := range m.fake.Execs() {
		if strings.Contains(strings.Join(c.Argv, " "), vmpalE2EJIT) {
			m.t.Errorf("the credential is in an exec's arguments: %v", c.Argv)
		}
		for k, v := range c.Env {
			if strings.Contains(v, vmpalE2EJIT) {
				carriers = append(carriers, strings.Join(c.Argv, " ")+" via "+k)
			}
		}
	}
	if len(carriers) != 1 || !strings.Contains(carriers[0], "helper.sh deliver via ACTIONS_RUNNER_INPUT_JITCONFIG") {
		m.t.Errorf("the credential travelled in %v, want exactly one deliver step", carriers)
	}
	for _, f := range m.ledgerFiles() {
		data, err := os.ReadFile(f)
		if err != nil {
			m.t.Fatal(err)
		}
		if strings.Contains(string(data), vmpalE2EJIT) {
			m.t.Errorf("the credential is in the ledger: %s", f)
		}
	}
}

// vmpalAgent is one running agent over a Mac. Starting a second over the same
// Mac is what an agent restart is.
type vmpalAgent struct {
	m      *vmpalE2E
	t      *testing.T
	agent  *Agent
	tr     *recordingTransport
	reg    *backend.Registry
	cancel context.CancelFunc
	done   chan error

	stopOnce sync.Once
}

// start builds the backend through the same constructor the real agent uses,
// then the agent over it. join is false for a restart, which finds its
// credentials in the work directory as a restarted service does.
func (m *vmpalE2E) start(join bool) *vmpalAgent {
	m.t.Helper()
	return m.startWith(join, nil)
}

// startWith is start for a controller that answers every heartbeat with beat,
// when it is not nil.
func (m *vmpalE2E) startWith(join bool, beat *HeartbeatResponse) *vmpalAgent {
	m.t.Helper()
	reg, err := backend.NewVMPalRegistry(m.opts)
	if err != nil {
		m.t.Fatalf("NewVMPalRegistry: %v", err)
	}
	tr := &recordingTransport{fakeTransport: newFakeTransport()}
	if beat != nil {
		tr.beatResp = beat
	}
	a, err := New(Options{
		Name: "mac-test", WorkDir: m.work, Capacity: 1,
		Backends: reg, DefaultBackend: store.BackendProcess,
		Transport: tr, HeartbeatInterval: time.Second, Logger: testLogger(),
	})
	if err != nil {
		m.t.Fatalf("New: %v", err)
	}
	if join {
		if err := a.Join(context.Background(), "join-token"); err != nil {
			m.t.Fatalf("Join: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &vmpalAgent{m: m, t: m.t, agent: a, tr: tr, reg: reg, cancel: cancel, done: make(chan error, 1)}
	go func() { h.done <- a.Run(ctx) }()
	m.t.Cleanup(h.stop)
	return h
}

func (h *vmpalAgent) stop() {
	h.stopOnce.Do(func() {
		h.cancel()
		select {
		case <-h.done:
		case <-time.After(20 * time.Second):
			h.t.Error("the agent did not shut down within 20s")
		}
	})
}

// reconcile is one pass of the agent's own reconciler and the delivery of what
// it saw. The loop does the same every thirty seconds; a test that waited that
// long for each step would be the slowest in the package.
func (h *vmpalAgent) reconcile() {
	h.t.Helper()
	ctx := context.Background()
	reports, err := h.agent.ReconcileOnce(ctx)
	if err != nil {
		h.t.Logf("reconcile: %v", err)
	}
	if len(reports) > 0 {
		h.agent.sendReports(ctx, reports)
	}
}

// waitFor reconciles until the condition holds, which is how a test lets the
// agent do what it does on its own timers without a sleep it has to guess.
func (h *vmpalAgent) waitFor(what string, limit time.Duration, cond func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(limit)
	for !cond() {
		if time.Now().After(deadline) {
			h.t.Fatalf("gave up after %s waiting for %s", limit, what)
		}
		h.reconcile()
		time.Sleep(100 * time.Millisecond)
	}
}

func vmpalE2ECreate(taskID, runnerID string) Task {
	return Task{
		ID: taskID, Kind: TaskCreateRunner, RunnerID: runnerID,
		Spec: &backend.Spec{
			Name: "macos-" + runnerID, RunnerID: runnerID, PoolID: "pool-macos", PoolName: "macos",
			Credentials: backend.Credentials{JITConfig: vmpalE2EJIT}, Ephemeral: true, DockerMode: store.DockerNone,
		},
	}
}

func (h *vmpalAgent) result() TaskResult {
	h.t.Helper()
	select {
	case res := <-h.tr.results:
		return res
	case <-time.After(60 * time.Second):
		h.t.Fatal("no task result within 60s")
		return TaskResult{}
	}
}

// create sends one create task and returns its handle once the agent says it
// worked.
func (h *vmpalAgent) create(runnerID string) string {
	h.t.Helper()
	h.tr.tasks <- []Task{vmpalE2ECreate("create-"+runnerID, runnerID)}
	res := h.result()
	if !res.OK {
		h.t.Fatalf("create failed: %s", res.Error)
	}
	if !vmpalE2ECloneName.MatchString(string(res.Handle)) {
		h.t.Fatalf("the handle is %q, which is not a clone's name", res.Handle)
	}
	return string(res.Handle)
}

// One job, from the controller's create task to the clone being gone. Each step
// is read from where it would be observed in production: the Mac for the clone
// and what it was told, the controller's side for what the agent reported.
func TestAJobRunsInAHardenedCloneAndLeavesNothingOnTheMac(t *testing.T) {
	t.Parallel()
	m := newVMPalE2E(t)
	h := m.start(true)
	if kinds := h.reg.Kinds(); len(kinds) != 1 || kinds[0] != store.BackendProcess {
		t.Fatalf("the registry holds %v, want only the VM backend as process: anything else is a way for a job onto the Mac", kinds)
	}

	handle := h.create("run_lifecycle")
	vm, ok := m.fake.VM(handle)
	if !ok || vm.State != "running" {
		t.Fatalf("the clone is %+v, want it running", vm)
	}
	if vm.Settings["networkMode"] != "shared" || vm.Settings["localNetwork"] != "off" || vm.Settings["clipboard"] != false {
		t.Errorf("the clone was not hardened: %v", vm.Settings)
	}
	if tmpl, _ := m.fake.VM(vmpalE2ETemplate); tmpl.State != "stopped" {
		t.Errorf("the template is %s, but a clone must never be made by running it", tmpl.State)
	}
	// Order is the safeguard: the egress check comes before anything that carries a credential.
	order := map[string]int{}
	for i, c := range m.fake.Execs() {
		for _, step := range []string{"egress", "arm", "deliver", "start"} {
			if strings.Contains(strings.Join(c.Argv, " "), "helper.sh "+step) {
				if _, seen := order[step]; !seen {
					order[step] = i
				}
			}
		}
	}
	if !(order["egress"] < order["arm"] && order["arm"] < order["deliver"] && order["deliver"] < order["start"]) || len(order) != 4 {
		t.Errorf("the guest steps ran in the order %v, want egress, arm, deliver, start", order)
	}
	m.assertCredentialOnlyDelivered()

	h.waitFor("the runner to be reported live", 10*time.Second, func() bool {
		r, ok := h.agent.snapshot("run_lifecycle")
		return ok && r.phase == backend.PhaseRunning
	})

	m.exits("zoomies-exit v1 code=0 job=1")
	h.waitFor("the runner's end to be reported", vmpalE2EWatch, func() bool { _, ok := h.tr.ended("run_lifecycle"); return ok })
	rep, _ := h.tr.ended("run_lifecycle")
	if rep.State != store.RunnerRemoved || rep.Fault != "" || rep.ExitCode != 0 {
		t.Errorf("a job that ran cleanly was reported as %+v", rep)
	}

	h.waitFor("the clone to be deleted and reported", 30*time.Second, func() bool { return h.tr.hostRemoved("run_lifecycle") })
	if left := m.clones(); len(left) != 0 {
		t.Errorf("clones left on the Mac: %v", left)
	}
	if left := m.ledgerFiles(); len(left) != 0 {
		t.Errorf("ledger entries left behind: %v", left)
	}
	if tmpl, ok := m.fake.VM(vmpalE2ETemplate); !ok || tmpl.State != "stopped" {
		t.Errorf("the template is %+v after the job, want it untouched", tmpl)
	}
	if _, ok := h.agent.snapshot("run_lifecycle"); ok {
		t.Error("the agent still tracks a runner whose workload is gone")
	}
	m.assertCredentialOnlyDelivered()
}

// The backend decides how a guest's record is mapped, and the agent decides what
// the mapping means to the controller. A code the job picked must not claim one
// of the reserved meanings, and a runner that never took a job must be told
// apart from one whose job failed, because only the first is counted against
// the host.
func TestEveryWayAGuestEndsIsWhatTheAgentReportsToTheController(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		record   string
		state    store.RunnerState
		fault    store.FaultKind
		exitCode int
		message  string
	}{
		{"a clean job", "zoomies-exit v1 code=0 job=1", store.RunnerRemoved, "", 0, "cleanly"},
		{"a job that failed", "zoomies-exit v1 code=3 job=1", store.RunnerFailed, store.FaultRunnerExited, 3, "the job's runner exited with code 3"},
		// 137 from a job is the job's own, and exitFault would call it an
		// out-of-memory kill if the backend let it through.
		{"a job that used a reserved code", "zoomies-exit v1 code=137 job=1", store.RunnerFailed, store.FaultRunnerExited, 1, "the job's runner exited with code 137"},
		{"no job taken", "zoomies-exit v1 code=1 job=0", store.RunnerFailed, store.FaultRunnerExited, 1, "without taking a job"},
		{"a runner version that is out of date", "zoomies-exit v1 code=7 job=0", store.RunnerFailed, store.FaultConfig, 7, "outdated"},
		{"an unreadable record", "this is not a record", store.RunnerFailed, store.FaultRunnerExited, 1, "unreadable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := newVMPalE2E(t)
			h := m.start(true)
			h.create("run_mapping")
			m.exits(tc.record)
			h.waitFor("the end to be reported", vmpalE2EWatch, func() bool { _, ok := h.tr.ended("run_mapping"); return ok })
			rep, _ := h.tr.ended("run_mapping")
			if rep.State != tc.state || rep.Fault != tc.fault || rep.ExitCode != tc.exitCode || !strings.Contains(rep.Message, tc.message) {
				t.Errorf("reported %+v\nwant state %s, fault %q, exit code %d and a message containing %q", rep, tc.state, tc.fault, tc.exitCode, tc.message)
			}
			// Whatever the ending, the clone does not outlive its report.
			h.waitFor("the clone to be deleted", 30*time.Second, func() bool { return h.tr.hostRemoved("run_mapping") })
			if left := m.clones(); len(left) != 0 {
				t.Errorf("clones left on the Mac: %v", left)
			}
		})
	}
}

// A drain is a stop task: let the runner finish and exit. The backend signals
// the guest and waits for its own record, and an exit it asked for must come
// out clean, not as a runner that died without taking a job.
func TestDrainingARunnerSignalsTheGuestAndEndsCleanly(t *testing.T) {
	t.Parallel()
	m := newVMPalE2E(t)
	h := m.start(true)
	handle := h.create("run_drain")

	// The guest answers a stop signal by writing its record, as the real
	// helper's LaunchAgent does when the runner gets SIGINT.
	go func() {
		for deadline := time.Now().Add(vmpalE2EWatch); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if len(m.execs("helper.sh stop")) > 0 {
				m.exits("zoomies-exit v1 code=130 job=0")
				return
			}
		}
	}()
	h.tr.tasks <- []Task{{ID: "stop-1", Kind: TaskStopRunner, RunnerID: "run_drain", StopTimeout: 30 * time.Second}}
	res := h.result()
	if !res.OK || string(res.Handle) != handle {
		t.Fatalf("the stop task answered %+v", res)
	}
	if len(m.execs("helper.sh stop")) != 1 {
		t.Errorf("the guest was signalled %d times, want once", len(m.execs("helper.sh stop")))
	}

	h.waitFor("the end to be reported", 30*time.Second, func() bool { _, ok := h.tr.ended("run_drain"); return ok })
	rep, _ := h.tr.ended("run_drain")
	if rep.State != store.RunnerRemoved || rep.Fault != "" || rep.ExitCode != 0 {
		t.Errorf("a drained runner was reported as %+v, want a clean removal with no fault", rep)
	}
	h.waitFor("the clone to be deleted", 30*time.Second, func() bool { return h.tr.hostRemoved("run_drain") })
	if left := m.clones(); len(left) != 0 {
		t.Errorf("clones left on the Mac: %v", left)
	}
	// Three runners that exit without a job start a hold, and a drain is the
	// operator's doing: it must leave the host able to take the next one.
	if infos := h.reg.Probe(context.Background()); len(infos) != 1 || !infos[0].Available {
		t.Errorf("the host reports %+v after a drain, want it available", infos)
	}
}

// A job is running when the agent restarts. The new agent finds the clone from
// its ledger, adopts it, and a create task the controller sends again is
// answered with the clone that is already there: the JIT config was consumed by
// the first delivery and a second would register nothing.
func TestARestartedAgentAdoptsTheRunningCloneAndNeverDeliversTheCredentialAgain(t *testing.T) {
	t.Parallel()
	m := newVMPalE2E(t)
	first := m.start(true)
	handle := first.create("run_restart")
	first.waitFor("the runner to be live", 10*time.Second, func() bool {
		r, ok := first.agent.snapshot("run_restart")
		return ok && r.phase == backend.PhaseRunning
	})
	first.stop()

	if got := m.clones(); !slices.Equal(got, []string{handle}) {
		t.Fatalf("after the agent stopped the Mac has %v, want its one clone left running: a restart must never kill a job", got)
	}
	if vm, _ := m.fake.VM(handle); vm.State != "running" {
		t.Fatalf("the clone is %s after the agent stopped", vm.State)
	}

	second := m.start(false)
	second.waitFor("the new agent to adopt the clone", 10*time.Second, func() bool {
		r, ok := second.agent.snapshot("run_restart")
		return ok && r.handle == backend.Handle(handle)
	})
	second.tr.tasks <- []Task{vmpalE2ECreate("create-again", "run_restart")}
	res := second.result()
	if !res.OK || string(res.Handle) != handle {
		t.Fatalf("the repeated create answered %+v, want the existing clone %s", res, handle)
	}
	if got := m.clones(); !slices.Equal(got, []string{handle}) {
		t.Errorf("the Mac has %v after a repeated create, want the one clone", got)
	}
	if n := len(m.execs("helper.sh deliver")); n != 1 {
		t.Errorf("the credential was delivered %d times across the restart, want once", n)
	}
	m.assertCredentialOnlyDelivered()

	// And the job still ends properly under the new agent, which is the part a
	// lost ledger would break: nobody would be left to say how it went.
	m.exits("zoomies-exit v1 code=0 job=1")
	second.waitFor("the adopted runner's end to be reported", vmpalE2EWatch, func() bool { _, ok := second.tr.ended("run_restart"); return ok })
	rep, _ := second.tr.ended("run_restart")
	if rep.State != store.RunnerRemoved || rep.Fault != "" {
		t.Errorf("the adopted runner was reported as %+v", rep)
	}
	second.waitFor("the clone to be deleted", 30*time.Second, func() bool { return second.tr.hostRemoved("run_restart") })
	if left := m.clones(); len(left) != 0 {
		t.Errorf("clones left on the Mac: %v", left)
	}
}

// A cordoned host takes no new work. For a VM host that matters more than for
// most, because a create that gets through costs a clone and a credential.
func TestACordonedHostMakesNoCloneAndTakesWorkAgainOnceItIsLifted(t *testing.T) {
	t.Parallel()
	m := newVMPalE2E(t)
	a := m.startWith(true, &HeartbeatResponse{OK: true, Cordoned: true})
	tr := a.tr
	a.waitForCordon(true)

	tr.tasks <- []Task{vmpalE2ECreate("refused", "run_cordon")}
	select {
	case res := <-tr.results:
		if res.OK || !strings.Contains(res.Error, "cordoned") {
			t.Fatalf("the create answered %+v, want a refusal that names the cordon", res)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("no answer to a create on a cordoned host")
	}
	if got := m.clones(); len(got) != 0 {
		t.Errorf("a cordoned host made %v", got)
	}
	if got := m.execs(""); len(got) != 0 {
		t.Errorf("a cordoned host ran %d guest commands", len(got))
	}
	if got := m.ledgerFiles(); len(got) != 0 {
		t.Errorf("a cordoned host wrote ledger entries: %v", got)
	}

	// The same task is accepted once the flag is gone, so the refusal above was
	// the cordon and nothing else about this host.
	tr.mu.Lock()
	tr.beatResp = &HeartbeatResponse{OK: true}
	tr.mu.Unlock()
	a.waitForCordon(false)
	tr.tasks <- []Task{vmpalE2ECreate("accepted", "run_cordon")}
	select {
	case res := <-tr.results:
		if !res.OK {
			t.Fatalf("the create after the cordon was lifted failed: %s", res.Error)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("no answer to a create on an uncordoned host")
	}
	if got := m.clones(); len(got) != 1 {
		t.Errorf("the Mac has %v, want one clone", got)
	}
}

// waitForCordon waits until the agent's own copy of the flag says want, because
// a create that arrives before the first heartbeat has been read would pass the
// agent's cheap check and make the test about timing.
func (h *vmpalAgent) waitForCordon(want bool) {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for (h.agent.refuseNewWork() != "") != want {
		if time.Now().After(deadline) {
			h.t.Fatalf("the agent never came to believe cordoned=%v", want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
