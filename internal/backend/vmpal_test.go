//go:build !windows

package backend

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/eyupio/zoomies/internal/store"
	"github.com/eyupio/zoomies/test/fakevmpal"
)

const (
	vmpalTestJIT      = "jit-config-that-must-stay-secret"
	vmpalTestTemplate = "ci-template"
	vmpalTestRunner   = "run_testrunner1"
)

func TestMain(m *testing.M) {
	code := m.Run()
	fakevmpal.CleanUp()
	os.Exit(code)
}

// vmpalTestGate is the permissive gate only a test may inject.
type vmpalTestGate struct {
	mu        sync.Mutex
	admitErr  error
	verifyErr error
	onVerify  func()
	exits     [][2]bool
}

func (g *vmpalTestGate) Held() error { return nil }

func (g *vmpalTestGate) Admit(context.Context, vmpalSlotUse) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.admitErr
}

func (g *vmpalTestGate) Verify(context.Context, vmpalInfo) error {
	g.mu.Lock()
	hook, err := g.onVerify, g.verifyErr
	g.mu.Unlock()
	if hook != nil {
		hook()
	}
	return err
}

func (g *vmpalTestGate) RunnerExited(tookJob, stopRequested bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.exits = append(g.exits, [2]bool{tookJob, stopRequested})
}

func (g *vmpalTestGate) exitCalls() [][2]bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([][2]bool(nil), g.exits...)
}

type vmpalTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *vmpalTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *vmpalTestClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type vmpalRig struct {
	t     *testing.T
	fake  *fakevmpal.Fake
	gate  *vmpalTestGate
	clock *vmpalTestClock
	opts  VMPalOptions
	b     *VMPalBackend
}

func newVMPalRig(t *testing.T) *vmpalRig {
	t.Helper()
	fake := fakevmpal.New(t)
	fake.AddTemplate(vmpalTestTemplate)
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
	r := &vmpalRig{
		t: t, fake: fake, gate: &vmpalTestGate{},
		clock: &vmpalTestClock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)},
	}
	r.opts = VMPalOptions{
		GOOS: "darwin", Now: r.clock.Now, Binary: fake.Path(), Template: vmpalTestTemplate,
		MaxVMs: 2, GuestCIDR: "192.0.2.0/24", PolicyCheck: "/usr/local/bin/policy-check",
		WorkDir: t.TempDir(), Gate: r.gate,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	r.open()
	return r
}

// open builds a backend over the same work directory, which is what an agent
// restart is from the backend's side.
func (r *vmpalRig) open() {
	r.t.Helper()
	b, err := NewVMPal(r.opts)
	if err != nil {
		r.t.Fatal(err)
	}
	b.watchEvery = time.Hour
	b.stopPoll = 5 * time.Millisecond
	b.removeWait = 200 * time.Millisecond
	b.removeEvery = 5 * time.Millisecond
	b.logPoll = 5 * time.Millisecond
	b.addressWait = 0
	b.cli.stopGrace = 200 * time.Millisecond
	r.b = b
	r.t.Cleanup(b.Close)
}

func (r *vmpalRig) restart() {
	r.t.Helper()
	r.b.Close()
	r.open()
}

func vmpalTestSpec(runnerID string) Spec {
	return Spec{
		Name: "macos-" + runnerID, RunnerID: runnerID, PoolID: "pool_test", PoolName: "macos",
		Credentials: Credentials{JITConfig: vmpalTestJIT}, Ephemeral: true, DockerMode: store.DockerNone,
		Env: map[string]string{"POOL_SETTING": "value"},
	}
}

func (r *vmpalRig) create() string {
	r.t.Helper()
	h, err := r.b.Create(context.Background(), vmpalTestSpec(vmpalTestRunner))
	if err != nil {
		r.t.Fatalf("create: %v", err)
	}
	return string(h)
}

// seed puts a running clone on the fake and a ledger entry for it at a stage,
// as a crashed agent would have left them.
func (r *vmpalRig) seed(stage vmpalStage, change func(*vmpalEntry)) string {
	r.t.Helper()
	name := r.b.vmName(vmpalTestRunner)
	r.fake.AddVM(fakevmpal.VM{
		Name: name, State: "running", Installed: true, AgentControl: true,
		InternetAddress: "192.0.2.20", Tools: fakevmpal.Tools{Connected: true, Version: "0.42"},
	})
	vm, _ := r.fake.VM(name)
	e := vmpalEntry{
		RunnerID: vmpalTestRunner, RunnerName: "macos-runner", PoolID: "pool_test", VMName: name,
		VMPalID: vm.ID, Stage: stage, CreatedAt: r.clock.Now(), UpdatedAt: r.clock.Now(),
	}
	if change != nil {
		change(&e)
	}
	if err := r.b.ledger.write(e); err != nil {
		r.t.Fatal(err)
	}
	return name
}

func (r *vmpalRig) workload(name string) Workload {
	r.t.Helper()
	ws, err := r.b.List(context.Background())
	if err != nil {
		r.t.Fatal(err)
	}
	for _, w := range ws {
		if string(w.Handle) == name {
			return w
		}
	}
	r.t.Fatalf("%s is not listed: %+v", name, ws)
	return Workload{}
}

func (r *vmpalRig) execs(match string) []fakevmpal.ExecCall {
	r.t.Helper()
	var out []fakevmpal.ExecCall
	for _, c := range r.fake.Execs() {
		if strings.Contains(strings.Join(c.Argv, " "), match) {
			out = append(out, c)
		}
	}
	return out
}

// credentialReachedGuest looks at everything vmpal was asked to run, in both
// its arguments and the environment it was handed.
func (r *vmpalRig) credentialReachedGuest() bool {
	r.t.Helper()
	for _, c := range r.fake.Execs() {
		if strings.Contains(strings.Join(c.Argv, " "), vmpalTestJIT) {
			return true
		}
		for _, v := range c.Env {
			if strings.Contains(v, vmpalTestJIT) {
				return true
			}
		}
	}
	return false
}

func (r *vmpalRig) ledgerFiles() []string {
	r.t.Helper()
	files, err := filepath.Glob(filepath.Join(r.b.ledger.dir, "*"))
	if err != nil {
		r.t.Fatal(err)
	}
	return files
}

func (r *vmpalRig) assertNoCloneLeft() {
	r.t.Helper()
	for _, vm := range r.fake.VMs() {
		if strings.HasPrefix(vm.Name, "zoomies-vm-") {
			r.t.Errorf("clone %s was left on the Mac", vm.Name)
		}
	}
	if files := r.ledgerFiles(); len(files) != 0 {
		r.t.Errorf("ledger entries were left behind: %v", files)
	}
}

// A clone must be hardened and proven before the one thing that makes it worth
// attacking arrives, and that thing must travel only in the deliver step's
// environment: anywhere else it is readable on the Mac or kept on its disk.
func TestARunnerStartsInAHardenedCloneAndOnlyTheDeliverStepSeesItsCredential(t *testing.T) {
	r := newVMPalRig(t)
	name := r.create()
	if !regexp.MustCompile(`^zoomies-vm-[0-9a-f]{8}-run_testrunner1$`).MatchString(name) {
		t.Fatalf("the handle is %q", name)
	}
	vm, ok := r.fake.VM(name)
	if !ok {
		t.Fatal("the clone does not exist")
	}
	if vm.Settings["networkMode"] != "shared" || vm.Settings["localNetwork"] != "off" || vm.Settings["speakers"] != false {
		t.Errorf("the clone was not hardened: %v", vm.Settings)
	}

	var carriers []string
	for _, c := range r.fake.Execs() {
		if strings.Contains(strings.Join(c.Argv, " "), vmpalTestJIT) {
			t.Errorf("the credential is in an exec's arguments: %v", c.Argv)
		}
		for k, v := range c.Env {
			if strings.Contains(v, vmpalTestJIT) {
				carriers = append(carriers, strings.Join(c.Argv, " ")+" via "+k)
			}
		}
	}
	if len(carriers) != 1 || !strings.Contains(carriers[0], "helper.sh deliver via ACTIONS_RUNNER_INPUT_JITCONFIG") {
		t.Errorf("the credential travelled in %v", carriers)
	}
	for _, f := range r.ledgerFiles() {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), vmpalTestJIT) {
			t.Errorf("the credential is in the ledger: %s", f)
		}
	}
	if w := r.workload(name); w.Status.Phase != PhaseRunning || w.RunnerID != vmpalTestRunner {
		t.Errorf("listed as %+v", w)
	}
}

// The order is the safeguard: a gate that says no after the credential has gone
// has not protected anything.
func TestNoCredentialIsDeliveredWhenTheGateRefusesAClone(t *testing.T) {
	r := newVMPalRig(t)
	r.gate.verifyErr = errors.New("the network policy is not in force")
	_, err := r.b.Create(context.Background(), vmpalTestSpec(vmpalTestRunner))
	if err == nil {
		t.Fatal("create succeeded with the gate refusing")
	}
	if r.credentialReachedGuest() {
		t.Error("the credential reached the guest")
	}
	if got := r.execs("helper.sh deliver"); len(got) != 0 {
		t.Errorf("deliver ran: %v", got)
	}
	if got := r.execs("helper.sh arm"); len(got) != 0 {
		t.Errorf("arm ran before the gate agreed: %v", got)
	}
	r.assertNoCloneLeft()
}

// Without a complete policy, nothing configured by accident may reach a
// credential delivery, and the refusal must not read as a broken container
// runtime or as a host worth retrying at once.
func TestABackendGivenNoGateMakesNoClone(t *testing.T) {
	r := newVMPalRig(t)
	r.opts.Gate = nil
	r.restart()
	_, err := r.b.Create(context.Background(), vmpalTestSpec(vmpalTestRunner))
	if !errors.Is(err, errVMPalHeld) {
		t.Fatalf("create returned %v", err)
	}
	if errors.Is(err, ErrUnavailable) || errors.Is(err, ErrDaemonBusy) {
		t.Errorf("the refusal wraps a sentinel that sends the agent the wrong way: %v", err)
	}
	if got := Fault(err); got != store.FaultBackend {
		t.Errorf("fault %q", got)
	}
	r.assertNoCloneLeft()
	// Refused at admission: a clone made and then discarded would still have
	// booted, and taken a slot from a host that could never use it.
	if got := r.fake.Execs(); len(got) != 0 {
		t.Errorf("a clone got as far as running commands: %v", got)
	}
	if r.b.Probe(context.Background()).Available {
		t.Error("Probe called a backend that refuses every clone available")
	}
	if err := (vmpalRefusingGate{}).Verify(context.Background(), vmpalInfo{}); !errors.Is(err, errVMPalHeld) {
		t.Errorf("the default gate let a clone through verification: %v", err)
	}
}

// A registration token is reusable, so one inside a guest could be carried out
// by the job and used to register anything.
func TestASpecThatIsNotASingleUseRegistrationIsRefused(t *testing.T) {
	r := newVMPalRig(t)
	for name, change := range map[string]func(*Spec){
		"a registration token": func(s *Spec) {
			s.Credentials = Credentials{RegistrationToken: "reusable", URL: "https://github.invalid/example"}
		},
		"a pool that is not ephemeral": func(s *Spec) { s.Ephemeral = false },
		"docker-in-docker":             func(s *Spec) { s.DockerMode = store.DockerDinD },
		"the host's Docker socket":     func(s *Spec) { s.DockerMode = store.DockerHostSocket },
		"a variable naming the JIT":    func(s *Spec) { s.Env = map[string]string{EnvUpstreamJITConfig: "x"} },
		"a variable with a line break": func(s *Spec) { s.Env = map[string]string{"A": "1\nB=2"} },
	} {
		t.Run(name, func(t *testing.T) {
			spec := vmpalTestSpec(vmpalTestRunner)
			change(&spec)
			_, err := r.b.Create(context.Background(), spec)
			if err == nil {
				t.Fatal("the spec was accepted")
			}
			if got := Fault(err); got != store.FaultConfig {
				t.Errorf("fault %q, want config: %v", got, err)
			}
			r.assertNoCloneLeft()
		})
	}
}

// Every way a create can fail must leave no VM holding one of the Mac's two
// slots, and must report a fault that sends the operator to the right place.
func TestACreateThatFailsDeletesItsCloneAndNamesTheFault(t *testing.T) {
	failExec := func(match string) func(*vmpalRig) {
		return func(r *vmpalRig) { r.fake.OnExec(match, fakevmpal.ExecReply{Stderr: "failed", ExitCode: 1}) }
	}
	for _, tc := range []struct {
		name      string
		arrange   func(*vmpalRig)
		fault     store.FaultKind
		delivered bool
	}{
		{"the clone fails", func(r *vmpalRig) { r.fake.Fail("clone", fakevmpal.Fault{Stderr: "no"}) }, store.FaultBackend, false},
		{"a setting does not stick", func(r *vmpalRig) { r.fake.SettingsDoNotStick("networkMode") }, store.FaultConfig, false},
		{"VMPal grows a setting nobody has reviewed", func(r *vmpalRig) { r.fake.AddUnknownSetting("aNewWayToShare") }, store.FaultConfig, false},
		{"the session comes up bridged", func(r *vmpalRig) { r.fake.BridgeAtBoot(true) }, store.FaultConfig, false},
		{"Tools never connect", func(r *vmpalRig) { r.fake.ToolsNeverConnect(true) }, store.FaultBackend, false},
		{"nobody is signed in", failExec("helper.sh session"), store.FaultBackend, false},
		{"the runner cannot be armed", failExec("helper.sh arm"), store.FaultBackend, false},
		{"delivery fails", failExec("helper.sh deliver"), store.FaultBackend, true},
		{"the runner does not start", failExec("helper.sh start"), store.FaultBackend, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newVMPalRig(t)
			tc.arrange(r)
			_, err := r.b.Create(context.Background(), vmpalTestSpec(vmpalTestRunner))
			if err == nil {
				t.Fatal("the create succeeded")
			}
			if got := Fault(err); got != tc.fault {
				t.Errorf("fault %q, want %q: %v", got, tc.fault, err)
			}
			if strings.Contains(err.Error(), vmpalTestJIT) {
				t.Errorf("the credential is in the error: %v", err)
			}
			if got := r.credentialReachedGuest(); got != tc.delivered {
				t.Errorf("credential reached the guest: %v, want %v", got, tc.delivered)
			}
			r.assertNoCloneLeft()
			if len(r.fake.Trashed()) != 0 {
				t.Errorf("a clone went to the Trash, where it still holds its disk: %v", r.fake.Trashed())
			}
		})
	}
}

// Apple's limit counts other apps' VMs too, so it can be reached however
// carefully this agent counts its own, and it is a reason to wait.
func TestAppleLimitAtStartIsTheHostBeingBusy(t *testing.T) {
	r := newVMPalRig(t)
	for _, name := range []string{"someone-elses-1", "someone-elses-2"} {
		r.fake.AddVM(fakevmpal.VM{Name: name, State: "running", Installed: true})
	}
	_, err := r.b.Create(context.Background(), vmpalTestSpec(vmpalTestRunner))
	if got := Fault(err); got != store.FaultBackendBusy {
		t.Fatalf("fault %q: %v", got, err)
	}
	r.assertNoCloneLeft()
	for _, name := range []string{"someone-elses-1", "someone-elses-2"} {
		if vm, ok := r.fake.VM(name); !ok || vm.State != "running" {
			t.Errorf("%s was disturbed: %+v", name, vm)
		}
	}
}

// The template, the host's other VMs and another install's clones are not this
// agent's, whatever they are called and whatever it is asked to do to them.
func TestAVMThisAgentDidNotCreateIsNeverTouched(t *testing.T) {
	r := newVMPalRig(t)
	other := "00000000"
	if r.b.installID == other {
		other = "11111111"
	}
	foreign := []string{
		vmpalTestTemplate,
		"ci-linux-builder",
		"zoomies-vm-" + other + "-" + vmpalTestRunner,
		"copy-of-" + r.b.vmName(vmpalTestRunner),
		r.b.vmName(vmpalTestRunner) + "-copy",
		"zoomies-vm-" + r.b.installID + "-notarunner",
	}
	for _, name := range foreign[1:] {
		r.fake.AddVM(fakevmpal.VM{Name: name, State: "running", Installed: true, Tools: fakevmpal.Tools{Connected: true, Version: "0.42"}})
	}
	ws, err := r.b.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 0 {
		t.Fatalf("listed VMs that are not ours: %+v", ws)
	}
	for _, name := range foreign {
		if err := r.b.Remove(context.Background(), Handle(name)); err == nil {
			t.Errorf("Remove accepted %s", name)
		}
		if err := r.b.Stop(context.Background(), Handle(name), time.Millisecond); err == nil {
			t.Errorf("Stop accepted %s", name)
		}
		vm, ok := r.fake.VM(name)
		if !ok {
			t.Fatalf("%s was deleted", name)
		}
		if name != vmpalTestTemplate && vm.State != "running" {
			t.Errorf("%s was stopped", name)
		}
	}
	if got := r.fake.Execs(); len(got) != 0 {
		t.Errorf("something ran inside a VM that is not ours: %v", got)
	}
}

// A template renamed to look like a clone is still the template.
func TestTheTemplateIsRefusedEvenWithACloneName(t *testing.T) {
	r := newVMPalRig(t)
	name := r.b.vmName("run_impostor")
	r.fake.AddTemplate(name)
	r.opts.Template = name
	r.restart()
	if err := r.b.Remove(context.Background(), Handle(name)); err == nil {
		t.Fatal("Remove accepted the template")
	}
	if _, ok := r.fake.VM(name); !ok {
		t.Fatal("the template was deleted")
	}
}

// The name says whose a VM is, and the ID says it is the same machine. A VM
// that took a dead clone's name is somebody's work.
func TestAVMThatTookAClonesNameIsNotDeleted(t *testing.T) {
	r := newVMPalRig(t)
	name := r.seed(vmpalStageRunning, func(e *vmpalEntry) { e.VMPalID = "a-different-id" })
	err := r.b.Remove(context.Background(), Handle(name))
	if err == nil {
		t.Fatal("Remove deleted a VM whose ID is not the recorded one")
	}
	if _, ok := r.fake.VM(name); !ok {
		t.Fatal("the VM is gone")
	}
}

// Each row of the exit table, as the Status the agent's terminal-outcome mapping
// is handed. A guest must not be able to claim a reserved code's meaning: code
// 78 from a job would otherwise blame the pool's configuration.
func TestTheExitRecordMapsToWhatTheAgentIsTold(t *testing.T) {
	for _, tc := range []struct {
		name    string
		record  string
		stop    bool
		phase   Phase
		code    int
		message string
		counted bool
		tookJob bool
	}{
		{"a job that passed", "zoomies-exit v1 code=0 job=1\n", false, PhaseExited, 0, "", true, true},
		{"a job's own failure", "zoomies-exit v1 code=2 job=1\n", false, PhaseFailed, 2, "the job's runner exited with code 2", true, true},
		{"a job claiming outdated", "zoomies-exit v1 code=7 job=1\n", false, PhaseFailed, 1, "the job's runner exited with code 7", true, true},
		{"a job claiming no credentials", "zoomies-exit v1 code=64 job=1\n", false, PhaseFailed, 1, "the job's runner exited with code 64", true, true},
		{"a job claiming no daemon", "zoomies-exit v1 code=69 job=1\n", false, PhaseFailed, 1, "the job's runner exited with code 69", true, true},
		{"a job claiming bad config", "zoomies-exit v1 code=78 job=1\n", false, PhaseFailed, 1, "the job's runner exited with code 78", true, true},
		{"a job claiming a memory kill", "zoomies-exit v1 code=137 job=1\n", false, PhaseFailed, 1, "the job's runner exited with code 137", true, true},
		{"no job, stopped by the agent", "zoomies-exit v1 code=130 job=0\n", true, PhaseExited, 0, "", true, false},
		{"no job, outdated runner", "zoomies-exit v1 code=7 job=0\n", false, PhaseFailed, 7, "the runner version is outdated", true, false},
		{"no job, any other code", "zoomies-exit v1 code=3 job=0\n", false, PhaseFailed, 1, "the runner exited without taking a job", true, false},
		{"a malformed record", "zoomies-exit v1 code=999 job=1\n", false, PhaseFailed, 1, vmpalMsgUnreadable, true, false},
		{"a record with a second line", "zoomies-exit v1 code=0 job=1\nmore\n", false, PhaseFailed, 1, vmpalMsgUnreadable, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newVMPalRig(t)
			name := r.seed(vmpalStageRunning, func(e *vmpalEntry) {
				if tc.stop {
					e.StopRequestedAt = r.clock.Now()
				}
			})
			r.fake.OnExec("helper.sh exit", fakevmpal.ExecReply{Stdout: tc.record})
			if !r.b.watchOnce(context.Background(), name, &vmpalWatchState{}) {
				t.Fatal("the watcher did not finish on an exit record")
			}
			st := r.workload(name).Status
			if st.Phase != tc.phase || st.ExitCode != tc.code || st.Message != tc.message {
				t.Errorf("got %s/%d/%q, want %s/%d/%q", st.Phase, st.ExitCode, st.Message, tc.phase, tc.code, tc.message)
			}
			calls := r.gate.exitCalls()
			if !tc.counted {
				if len(calls) != 0 {
					t.Errorf("the breaker was told %v about a record that cannot be believed", calls)
				}
				return
			}
			if len(calls) != 1 || calls[0] != [2]bool{tc.tookJob, tc.stop} {
				t.Errorf("the breaker was told %v", calls)
			}
		})
	}
}

// What a restarted agent makes of each stage it can find. Before Delivering the
// registration was never sent and died with the old process; from Delivering
// on it may have been used, so it is never sent again.
func TestARestartedAgentRecoversEachLedgerStage(t *testing.T) {
	exit := &vmpalExitResult{Phase: PhaseFailed, Code: 3, Message: "stored", At: time.Unix(100, 0).UTC()}
	for _, tc := range []struct {
		stage vmpalStage
		exit  *vmpalExitResult
		phase Phase
		code  int
	}{
		{vmpalStageIntent, nil, PhaseFailed, 1},
		{vmpalStageCloned, nil, PhaseFailed, 1},
		{vmpalStageHardened, nil, PhaseFailed, 1},
		{vmpalStageBooting, nil, PhaseFailed, 1},
		{vmpalStageVerifying, nil, PhaseFailed, 1},
		{vmpalStageArming, nil, PhaseFailed, 1},
		{vmpalStageDelivering, nil, PhaseRunning, 0},
		{vmpalStageRunning, nil, PhaseRunning, 0},
		{vmpalStageExited, exit, PhaseFailed, 3},
		{vmpalStageDeleting, nil, PhaseFailed, 1},
		{vmpalStageDeleting, exit, PhaseFailed, 3},
	} {
		t.Run(string(tc.stage), func(t *testing.T) {
			r := newVMPalRig(t)
			name := r.seed(tc.stage, func(e *vmpalEntry) { e.Exit = tc.exit })
			r.restart()
			w := r.workload(name)
			if w.RunnerID != vmpalTestRunner || w.Status.Phase != tc.phase || w.Status.ExitCode != tc.code {
				t.Errorf("listed as %s/%d for runner %s, want %s/%d", w.Status.Phase, w.Status.ExitCode, w.RunnerID, tc.phase, tc.code)
			}
			if tc.stage.preparing() && !strings.Contains(w.Status.Message, "never delivered") {
				t.Errorf("the message does not say the registration was unused: %q", w.Status.Message)
			}
			if r.credentialReachedGuest() || len(r.execs("helper.sh deliver")) != 0 || len(r.execs("helper.sh start")) != 0 {
				t.Error("recovery delivered or started something")
			}
			if _, ok := r.fake.VM(name); !ok {
				t.Error("List deleted a VM; only the agent's Remove does, once the controller has heard")
			}
			if err := r.b.Remove(context.Background(), Handle(name)); err != nil {
				t.Fatalf("remove: %v", err)
			}
			r.assertNoCloneLeft()
		})
	}
}

// A ledger entry whose VM has gone is reported once as gone rather than as a
// clean exit, and it does not hold a slot.
func TestAClonesDisappearanceIsReportedAsGone(t *testing.T) {
	for _, tc := range []struct {
		name string
		stop bool
		code int
	}{
		{"unprompted", false, 1},
		{"after the agent stopped it", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newVMPalRig(t)
			name := r.seed(vmpalStageRunning, func(e *vmpalEntry) {
				if tc.stop {
					e.StopRequestedAt = r.clock.Now()
				}
			})
			if _, err := r.b.cli.run(context.Background(), time.Second, nil, "delete", name, "--force", "--permanently"); err != nil {
				t.Fatal(err)
			}
			st := r.workload(name).Status
			if st.Phase != PhaseGone || st.ExitCode != tc.code {
				t.Errorf("got %s/%d, want gone/%d", st.Phase, st.ExitCode, tc.code)
			}
			if err := r.b.Remove(context.Background(), Handle(name)); err != nil {
				t.Fatal(err)
			}
			r.assertNoCloneLeft()
		})
	}
}

// A create in progress must read as starting at every stage, or the reconciler
// would report a runner that is coming up perfectly well as dead.
func TestListCallsACloneBeingCreatedStartingAtEveryStage(t *testing.T) {
	for _, stage := range vmpalStageOrder[:vmpalStageRunning.rank()] {
		t.Run(string(stage), func(t *testing.T) {
			r := newVMPalRig(t)
			name := r.seed(stage, nil)
			r.b.mu.Lock()
			r.b.creating[name] = true
			r.b.mu.Unlock()
			if w := r.workload(name); w.Status.Phase != PhaseStarting {
				t.Errorf("listed as %s", w.Status.Phase)
			}
		})
	}
	t.Run("through a real create", func(t *testing.T) {
		r := newVMPalRig(t)
		var seen Phase
		r.gate.onVerify = func() {
			ws, err := r.b.List(context.Background())
			if err != nil || len(ws) != 1 {
				t.Errorf("listed %v, %v", ws, err)
				return
			}
			seen = ws[0].Status.Phase
		}
		r.create()
		if seen != PhaseStarting {
			t.Errorf("listed as %q during verification", seen)
		}
	})
}

// Recovery trusts this record to say whether the registration may have been
// used, so it has to be on disk before the registration leaves the agent. An
// agent killed during delivery must find Delivering and never send it again.
func TestTheLedgerSaysDeliveringBeforeTheCredentialMoves(t *testing.T) {
	r := newVMPalRig(t)
	r.fake.OnExec("helper.sh deliver", fakevmpal.ExecReply{Hang: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := r.b.Create(ctx, vmpalTestSpec(vmpalTestRunner))
		done <- err
	}()
	deadline := time.Now().Add(10 * time.Second)
	for len(r.execs("helper.sh deliver")) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("delivery never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	e, ok, err := r.b.readEntry(r.b.vmName(vmpalTestRunner))
	if err != nil || !ok || e.Stage != vmpalStageDelivering {
		t.Errorf("during delivery the ledger says %q (found=%v, %v)", e.Stage, ok, err)
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("the create succeeded")
	}
}

// A JIT config is single-use. A create that comes round again after a restart
// must find the runner and never send that config to a second machine.
func TestARestartNeverReplaysARegistration(t *testing.T) {
	r := newVMPalRig(t)
	name := r.create()
	r.restart()
	if w := r.workload(name); w.Status.Phase != PhaseRunning {
		t.Fatalf("not adopted: %+v", w)
	}
	_, err := r.b.Create(context.Background(), vmpalTestSpec(vmpalTestRunner))
	if !errors.Is(err, ErrContainerConflict) {
		t.Fatalf("a repeated create returned %v", err)
	}
	if got := r.execs("helper.sh deliver"); len(got) != 1 {
		t.Errorf("deliver ran %d times", len(got))
	}
	if _, ok := r.fake.VM(name); !ok {
		t.Error("the running clone was disturbed")
	}
}

// The same when the record is what was lost: the VM may be running a job that
// has already used the registration, and the delete a replace would need is
// the one thing that cannot be taken back.
func TestACreateNeverReplacesAVMWhoseRecordIsLost(t *testing.T) {
	r := newVMPalRig(t)
	name := r.seed(vmpalStageRunning, nil)
	if err := os.Remove(r.b.ledger.path(name)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.b.Create(context.Background(), vmpalTestSpec(vmpalTestRunner)); !errors.Is(err, ErrContainerConflict) {
		t.Fatalf("create returned %v", err)
	}
	if vm, ok := r.fake.VM(name); !ok || vm.State != "running" {
		t.Errorf("the VM was disturbed: %+v", vm)
	}
	if r.credentialReachedGuest() {
		t.Error("the registration was sent")
	}
}

// The same protection when the VM has gone but its record has not.
func TestARecordWithNoVMStillBlocksASecondDelivery(t *testing.T) {
	r := newVMPalRig(t)
	name := r.create()
	if _, err := r.b.cli.run(context.Background(), time.Second, nil, "delete", name, "--force", "--permanently"); err != nil {
		t.Fatal(err)
	}
	r.restart()
	if _, err := r.b.Create(context.Background(), vmpalTestSpec(vmpalTestRunner)); !errors.Is(err, ErrContainerConflict) {
		t.Fatalf("create returned %v", err)
	}
	if got := r.execs("helper.sh deliver"); len(got) != 1 {
		t.Errorf("deliver ran %d times", len(got))
	}
}

// A lost or damaged file must not cost a live job: the name still says which
// runner it is, and the controller decides what happens to it.
func TestACloneWhoseLedgerFileIsLostIsStillReported(t *testing.T) {
	for name, damage := range map[string]func(path string) error{
		"missing": os.Remove,
		"corrupt": func(p string) error { return os.WriteFile(p, []byte("{half a rec"), 0o600) },
		"about another VM": func(p string) error {
			return os.WriteFile(p, []byte(`{"vm_name":"elsewhere","runner_id":"run_other","stage":"running"}`), 0o600)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newVMPalRig(t)
			vm := r.seed(vmpalStageRunning, nil)
			if err := damage(r.b.ledger.path(vm)); err != nil {
				t.Fatal(err)
			}
			r.restart()
			w := r.workload(vm)
			if w.RunnerID != vmpalTestRunner || w.Status.Phase != PhaseRunning {
				t.Errorf("listed as %+v", w)
			}
			if got, ok := r.fake.VM(vm); !ok || got.State != "running" {
				t.Errorf("the live clone was disturbed: %+v", got)
			}
			e, ok, err := r.b.readEntry(vm)
			if err != nil || !ok || !e.Recovered {
				t.Errorf("no record to follow it with: %+v, %v, %v", e, ok, err)
			}
		})
	}
}

func TestAStoppedCloneWithNoRecordHasAnUnknownEnd(t *testing.T) {
	r := newVMPalRig(t)
	vm := r.seed(vmpalStageRunning, nil)
	if err := os.Remove(r.b.ledger.path(vm)); err != nil {
		t.Fatal(err)
	}
	r.fake.Reboot()
	if st := r.workload(vm).Status; st.Phase != PhaseExitUnknown {
		t.Errorf("listed as %s", st.Phase)
	}
}

func TestAMacRestartFailsTheRunnerAndNamesTheCause(t *testing.T) {
	r := newVMPalRig(t)
	name := r.create()
	r.fake.Reboot()
	r.restart()
	st := r.workload(name).Status
	if st.Phase != PhaseFailed || st.ExitCode != 1 || !strings.Contains(st.Message, "restarts") {
		t.Errorf("listed as %+v", st)
	}
}

// A clone is not resumed after the Mac has slept, because nothing says its
// network policy held while the host was away.
func TestAWallClockGapEndsTheRunner(t *testing.T) {
	r := newVMPalRig(t)
	name := r.seed(vmpalStageRunning, func(e *vmpalEntry) { e.StartedAt = r.clock.Now() })
	var st vmpalWatchState
	if r.b.watchOnce(context.Background(), name, &st) {
		t.Fatal("the first look ended the watch")
	}
	r.clock.advance(vmpalWakeGap)
	if r.b.watchOnce(context.Background(), name, &st) {
		t.Fatal("a gap of exactly the limit ended the watch")
	}
	r.clock.advance(vmpalWakeGap + time.Second)
	if !r.b.watchOnce(context.Background(), name, &st) {
		t.Fatal("the watcher slept through a gap")
	}
	got := r.workload(name).Status
	if got.Phase != PhaseFailed || got.ExitCode != 1 || !strings.Contains(got.Message, "asleep") {
		t.Errorf("listed as %+v", got)
	}
	if calls := r.gate.exitCalls(); len(calls) != 0 {
		t.Errorf("a sleep was counted as a runner that took no job: %v", calls)
	}
}

// A restart is not a sleep: running jobs are meant to survive an agent upgrade,
// however long the gap between the last agent and this one.
func TestAnAgentRestartIsNotMistakenForASleep(t *testing.T) {
	r := newVMPalRig(t)
	name := r.seed(vmpalStageRunning, func(e *vmpalEntry) { e.StartedAt = r.clock.Now() })
	r.clock.advance(time.Hour)
	r.restart()
	if r.b.watchOnce(context.Background(), name, &vmpalWatchState{}) {
		t.Fatal("the first look after a restart ended the watch")
	}
	if st := r.workload(name).Status; st.Phase != PhaseRunning {
		t.Errorf("listed as %+v", st)
	}
}

// The lifetime limit is the only thing that ends a guest that has wedged.
func TestARunnerIsEndedAtTheLifetimeLimit(t *testing.T) {
	r := newVMPalRig(t)
	name := r.seed(vmpalStageRunning, func(e *vmpalEntry) { e.StartedAt = r.clock.Now() })
	r.clock.advance(vmpalLifetime)
	if !r.b.watchOnce(context.Background(), name, &vmpalWatchState{}) {
		t.Fatal("the limit passed unnoticed")
	}
	if st := r.workload(name).Status; st.Phase != PhaseFailed || !strings.Contains(st.Message, "limit") {
		t.Errorf("listed as %+v", st)
	}
}

// A job can break Tools in its own guest. That must end the runner in bounded
// time, and a brief failure must not.
func TestAGuestThatStopsAnsweringIsEndedAfterTenMinutes(t *testing.T) {
	r := newVMPalRig(t)
	name := r.seed(vmpalStageRunning, func(e *vmpalEntry) { e.StartedAt = r.clock.Now() })
	r.fake.OnExec("helper.sh exit", fakevmpal.ExecReply{Stderr: "no Tools", ExitCode: 125})
	var st vmpalWatchState
	for elapsed := time.Duration(0); elapsed < vmpalReadGiveUp; elapsed += 2 * time.Minute {
		if r.b.watchOnce(context.Background(), name, &st) {
			t.Fatalf("gave up after %s", elapsed)
		}
		r.clock.advance(2 * time.Minute)
	}
	if !r.b.watchOnce(context.Background(), name, &st) {
		t.Fatal("did not give up at the limit")
	}
	if got := r.workload(name).Status; got.Phase != PhaseFailed || !strings.Contains(got.Message, "did not answer") {
		t.Errorf("listed as %+v", got)
	}
}

func TestAGuestThatAnswersAgainStartsTheTenMinutesOver(t *testing.T) {
	r := newVMPalRig(t)
	name := r.seed(vmpalStageRunning, func(e *vmpalEntry) { e.StartedAt = r.clock.Now() })
	var st vmpalWatchState
	r.fake.OnExec("helper.sh exit", fakevmpal.ExecReply{ExitCode: 125})
	r.b.watchOnce(context.Background(), name, &st)
	r.fake.OnExec("helper.sh exit", fakevmpal.ExecReply{Stdout: "zoomies-exit v1 running\n"})
	r.clock.advance(2 * time.Minute)
	r.b.watchOnce(context.Background(), name, &st)
	if !st.failingSince.IsZero() {
		t.Fatal("a good read did not clear the failure")
	}
}

// List must answer from vmpal list and the ledger alone, or one job's broken
// Tools would stall the reconcile of every runner on the host.
func TestListRunsNothingInTheGuest(t *testing.T) {
	r := newVMPalRig(t)
	name := r.seed(vmpalStageRunning, nil)
	r.fake.OnExec("helper.sh exit", fakevmpal.ExecReply{Hang: true})
	before := len(r.fake.Execs())
	start := time.Now()
	if st, err := r.b.Status(context.Background(), Handle(name)); err != nil || st.Phase != PhaseRunning {
		t.Fatalf("status %+v, %v", st, err)
	}
	r.b.mu.Lock()
	r.b.closed = true // so List starts no watcher, whose read is a legitimate exec
	r.b.mu.Unlock()
	if w := r.workload(name); w.Status.Phase != PhaseRunning {
		t.Fatalf("listed as %+v", w)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("took %s", took)
	}
	if after := len(r.fake.Execs()); after != before {
		t.Errorf("%d commands ran in the guest", after-before)
	}
}

func TestStopSignalsTheRunnerAndLeavesAFinishedVMRunning(t *testing.T) {
	r := newVMPalRig(t)
	name := r.create()
	r.fake.OnExec("helper.sh exit", fakevmpal.ExecReply{Stdout: "zoomies-exit v1 code=130 job=0\n"})
	if err := r.b.Stop(context.Background(), Handle(name), 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if len(r.execs("helper.sh stop")) != 1 {
		t.Error("the runner was not signalled")
	}
	if vm, _ := r.fake.VM(name); vm.State != "running" {
		t.Errorf("a runner that stopped by itself had its VM forced off: %s", vm.State)
	}
	if st := r.workload(name).Status; st.Phase != PhaseExited || st.ExitCode != 0 {
		t.Errorf("listed as %+v", st)
	}
	if calls := r.gate.exitCalls(); len(calls) != 1 || calls[0] != [2]bool{false, true} {
		t.Errorf("the breaker was told %v", calls)
	}
}

func TestStopForcesOffARunnerThatIgnoresIt(t *testing.T) {
	r := newVMPalRig(t)
	name := r.create()
	if err := r.b.Stop(context.Background(), Handle(name), 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if vm, _ := r.fake.VM(name); vm.State != "stopped" {
		t.Errorf("the VM is %s", vm.State)
	}
	if st := r.workload(name).Status; st.Phase != PhaseExited || st.ExitCode != 0 {
		t.Errorf("a runner the agent stopped is listed as %+v", st)
	}
}

// A guest that has broken its helper must not be able to keep its VM on by
// failing to answer the request to stop.
func TestStopForcesOffAGuestThatCannotBeSignalled(t *testing.T) {
	r := newVMPalRig(t)
	name := r.create()
	r.fake.OnExec("helper.sh stop", fakevmpal.ExecReply{ExitCode: 1})
	if err := r.b.Stop(context.Background(), Handle(name), time.Second); err != nil {
		t.Fatal(err)
	}
	if vm, _ := r.fake.VM(name); vm.State != "stopped" {
		t.Errorf("the VM is %s", vm.State)
	}
}

// The exit that follows a stop was asked for. An agent restarted between the
// two must not report it as a runner that died without taking a job.
func TestARestartDuringStopStillReadsTheExitAsRequested(t *testing.T) {
	r := newVMPalRig(t)
	name := r.create()
	if err := r.b.markStopRequested(name); err != nil {
		t.Fatal(err)
	}
	r.restart()
	r.fake.OnExec("helper.sh exit", fakevmpal.ExecReply{Stdout: "zoomies-exit v1 code=130 job=0\n"})
	if !r.b.watchOnce(context.Background(), name, &vmpalWatchState{}) {
		t.Fatal("the exit was not read")
	}
	if st := r.workload(name).Status; st.Phase != PhaseExited || st.ExitCode != 0 {
		t.Errorf("listed as %+v", st)
	}
	if calls := r.gate.exitCalls(); len(calls) != 1 || calls[0] != [2]bool{false, true} {
		t.Errorf("the breaker was told %v", calls)
	}
}

// vmpal delete returns a few seconds before the VM leaves the list. Dropping
// the record on its return would free a slot the Mac still counts.
func TestRemoveWaitsForTheVMToLeaveTheList(t *testing.T) {
	r := newVMPalRig(t)
	name := r.create()
	r.fake.DeleteLingers(2)
	r.b.removeWait = 0
	err := r.b.Remove(context.Background(), Handle(name))
	if !errors.Is(err, ErrRemovalInProgress) {
		t.Fatalf("remove returned %v", err)
	}
	if got := Fault(err); got != store.FaultBackendBusy {
		t.Errorf("fault %q", got)
	}
	if _, ok, _ := r.b.readEntry(name); !ok {
		t.Fatal("the entry went before the VM did")
	}
	r.b.removeWait = 200 * time.Millisecond
	if err := r.b.Remove(context.Background(), Handle(name)); err != nil {
		t.Fatalf("the second remove returned %v", err)
	}
	r.assertNoCloneLeft()
}

func TestADeleteThatFailsKeepsTheEntryAndIsRetried(t *testing.T) {
	r := newVMPalRig(t)
	name := r.create()
	r.fake.Fail("delete", fakevmpal.Fault{Stderr: "busy", Times: 1})
	if err := r.b.Remove(context.Background(), Handle(name)); err == nil {
		t.Fatal("remove reported success")
	}
	e, ok, _ := r.b.readEntry(name)
	if !ok || e.Stage != vmpalStageDeleting {
		t.Fatalf("entry %+v, %v", e, ok)
	}
	if _, there := r.fake.VM(name); !there {
		t.Fatal("the fake lost the VM")
	}
	r.clock.advance(vmpalDeleteAgain)
	if err := r.b.Remove(context.Background(), Handle(name)); err != nil {
		t.Fatal(err)
	}
	r.assertNoCloneLeft()
}

func TestRemovingAVMThatIsAlreadyGoneIsNotAnError(t *testing.T) {
	r := newVMPalRig(t)
	if err := r.b.Remove(context.Background(), Handle(r.b.vmName("run_neverexisted"))); err != nil {
		t.Fatal(err)
	}
}

// VMPal runs two commands at a time in one VM. Log followers take one between
// them, or two people watching a job would leave nothing to notice it ending.
func TestLogFollowersNeverStarveTheWatcher(t *testing.T) {
	r := newVMPalRig(t)
	name := r.create()
	r.fake.OnExec("helper.sh log", fakevmpal.ExecReply{Hang: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for range 2 {
		rc, err := r.b.Logs(ctx, Handle(name), LogOptions{Follow: true})
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		go io.Copy(io.Discard, rc)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(r.execs("helper.sh log")) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no log read started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)

	r.fake.OnExec("helper.sh exit", fakevmpal.ExecReply{Stdout: "zoomies-exit v1 code=0 job=1\n"})
	readCtx, cancelRead := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelRead()
	finished, err := r.b.readGuestExit(readCtx, name, time.Second)
	if err != nil || !finished {
		t.Fatalf("the watcher could not read the exit past two followers: finished=%v, %v", finished, err)
	}
}

func vmpalLogReply(next, size int, data string) fakevmpal.ExecReply {
	return fakevmpal.ExecReply{Stdout: fmt.Sprintf("zoomies-log v1 next=%d size=%d\n%s\n", next, size, base64.StdEncoding.EncodeToString([]byte(data)))}
}

func TestLogsDecodeWhatTheGuestWrote(t *testing.T) {
	r := newVMPalRig(t)
	name := r.create()
	// Not valid UTF-8, which is why the guest sends base64.
	text := "first\n\xff\xfe second\n"
	r.fake.OnExec("helper.sh log 0 ", vmpalLogReply(len(text), len(text), text))
	rc, err := r.b.Logs(context.Background(), Handle(name), LogOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != text {
		t.Errorf("read %q", got)
	}
}

func TestLogTailIsCountedInLines(t *testing.T) {
	r := newVMPalRig(t)
	name := r.create()
	text := "one\ntwo\nthree\nfour\n"
	r.fake.OnExec("helper.sh log 576460752303423488 0", fakevmpal.ExecReply{Stdout: fmt.Sprintf("zoomies-log v1 next=%d size=0\n", len(text))})
	r.fake.OnExec("helper.sh log 0 ", vmpalLogReply(len(text), len(text), text))
	rc, err := r.b.Logs(context.Background(), Handle(name), LogOptions{Tail: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "three\nfour\n" {
		t.Errorf("read %q", got)
	}
}

func TestAFollowedLogEndsOnceTheExitIsKnown(t *testing.T) {
	r := newVMPalRig(t)
	name := r.create()
	r.fake.OnExec("helper.sh log", vmpalLogReply(0, 0, ""))
	rc, err := r.b.Logs(context.Background(), Handle(name), LogOptions{Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if err := r.b.recordExit(name, PhaseExited, 0, ""); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := io.ReadAll(rc); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the follower did not end")
	}
}

func TestVMPalLastLines(t *testing.T) {
	for _, tc := range []struct {
		in      string
		n       int
		partial bool
		want    string
	}{
		{"a\nb\nc\n", 2, false, "b\nc\n"},
		{"a\nb\nc", 2, false, "b\nc"},
		{"a\nb\n", 5, false, "a\nb\n"},
		{"half\nb\nc\n", 5, true, "b\nc\n"},
		{"", 3, false, ""},
	} {
		if got := string(vmpalLastLines([]byte(tc.in), tc.n, tc.partial)); got != tc.want {
			t.Errorf("vmpalLastLines(%q, %d, %v) = %q, want %q", tc.in, tc.n, tc.partial, got, tc.want)
		}
	}
}

// After a job has run, the guest writes these answers.
func TestTheGuestParsersAcceptOnlyTheirGrammar(t *testing.T) {
	for _, bad := range []string{
		"", "zoomies-exit v1", "zoomies-exit v1 code=256 job=0", "zoomies-exit v1 code=01 job=0",
		"zoomies-exit v1 code=-1 job=0", "zoomies-exit v1 code=1 job=2", "zoomies-exit v2 code=1 job=0",
		" zoomies-exit v1 code=1 job=0", "zoomies-exit v1 code=1 job=0 extra",
		"zoomies-exit v1 code=1 job=0\nzoomies-exit v1 code=0 job=1", "zoomies-exit v1 running\nmore",
	} {
		if _, _, err := parseVMPalExit(bad); err == nil {
			t.Errorf("parseVMPalExit accepted %q", bad)
		}
	}
	if g, running, err := parseVMPalExit("zoomies-exit v1 code=255 job=1\n"); err != nil || running || g.Code != 255 || !g.TookJob {
		t.Errorf("parseVMPalExit = %+v, %v, %v", g, running, err)
	}
	if _, running, err := parseVMPalExit("zoomies-exit v1 running\n"); err != nil || !running {
		t.Errorf("running = %v, %v", running, err)
	}
	for _, bad := range []string{"", "zoomies-session v1 uid=501 gui=0", "zoomies-session v1 uid=x gui=1", "zoomies-session v1 uid=501 gui=1 more"} {
		if parseVMPalSession(bad) == nil {
			t.Errorf("parseVMPalSession accepted %q", bad)
		}
	}
	for _, bad := range []string{"", "zoomies-arm v1 ok", "zoomies-arm v1 ok source=elsewhere", "zoomies-arm v1 failed source=cache"} {
		if _, err := parseVMPalArm(bad); err == nil {
			t.Errorf("parseVMPalArm accepted %q", bad)
		}
	}
	data := base64.StdEncoding.EncodeToString([]byte("abcd"))
	for name, bad := range map[string]string{
		"no header":        data,
		"size disagrees":   "zoomies-log v1 next=4 size=3\n" + data,
		"over the limit":   "zoomies-log v1 next=99 size=99\n" + data,
		"next before size": "zoomies-log v1 next=1 size=4\n" + data,
		"not base64":       "zoomies-log v1 next=4 size=4\n!!!!",
		"negative":         "zoomies-log v1 next=-4 size=4\n" + data,
	} {
		if _, _, err := parseVMPalLog(bad, 16); err == nil {
			t.Errorf("parseVMPalLog accepted %s", name)
		}
	}
	got, next, err := parseVMPalLog("zoomies-log v1 next=10 size=4\n"+data+"\n", 16)
	if err != nil || string(got) != "abcd" || next != 10 {
		t.Errorf("parseVMPalLog = %q, %d, %v", got, next, err)
	}
}

// The settings check is a closed list, in both directions.
func TestTheHardeningCheckReadsTheWholeSettingsObject(t *testing.T) {
	good := func() map[string]json.RawMessage {
		out := map[string]json.RawMessage{"cpuCount": json.RawMessage("4"), "name": json.RawMessage(`"x"`)}
		for k, v := range vmpalRequiredSettings {
			out[k] = json.RawMessage(v)
		}
		for k, v := range vmpalBootSettings {
			out[k] = json.RawMessage(v)
		}
		return out
	}
	if got := vmpalSettingProblems(good(), true); len(got) != 0 {
		t.Fatalf("a good object has problems: %v", got)
	}
	for key := range vmpalRequiredSettings {
		missing := good()
		delete(missing, key)
		if len(vmpalSettingProblems(missing, false)) == 0 {
			t.Errorf("no problem with %s missing", key)
		}
		wrong := good()
		wrong[key] = json.RawMessage(`"wrong"`)
		if len(vmpalSettingProblems(wrong, false)) == 0 {
			t.Errorf("no problem with %s wrong", key)
		}
	}
	unknown := good()
	unknown["aNewWayToShare"] = json.RawMessage("true")
	if len(vmpalSettingProblems(unknown, false)) == 0 {
		t.Error("an unknown setting passed")
	}
	// Before boot the in-effect values are only what the VM would probably get.
	resolved := good()
	resolved["networkModeInEffect"] = json.RawMessage(`"bridged"`)
	if got := vmpalSettingProblems(resolved, false); len(got) != 0 {
		t.Errorf("a stopped VM's resolved value was held against it: %v", got)
	}
	if len(vmpalSettingProblems(resolved, true)) == 0 {
		t.Error("a running VM's in-effect value was not checked")
	}
}

// A template's existing shares must be removed by name: a blanket flag does not
// exist, so an entry skipped here is a shared folder in every clone.
func TestHardeningRemovesEachEntryTheTemplateHas(t *testing.T) {
	r := newVMPalRig(t)
	r.fake.AddVM(fakevmpal.VM{
		Name: "shared-template", Installed: true, AgentControl: true,
		Tools: fakevmpal.Tools{Version: "0.42"},
		Settings: func() map[string]any {
			tpl, _ := r.fake.VM(vmpalTestTemplate)
			s := map[string]any{}
			for k, v := range tpl.Settings {
				s[k] = v
			}
			s["sharedFolders"] = []any{"/Users/shared/one", map[string]any{"path": "/Users/shared/two"}}
			s["forwardedPorts"] = []any{map[string]any{"hostPort": 8022}}
			s["vsockForwards"] = []any{5000}
			return s
		}(),
	})
	r.opts.Template = "shared-template"
	r.restart()
	name := r.create()
	vm, _ := r.fake.VM(name)
	for _, key := range []string{"sharedFolders", "forwardedPorts", "vsockForwards"} {
		if list, _ := vm.Settings[key].([]any); len(list) != 0 {
			t.Errorf("%s still holds %v", key, list)
		}
	}
}

func TestProbeNamesWhyAHostCannotTakeAClone(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arrange func(*vmpalRig)
		detail  string
	}{
		{"not a Mac", func(r *vmpalRig) { r.opts.GOOS = "linux"; r.restart() }, "only runs on a Mac"},
		{"no policy check", func(r *vmpalRig) { r.opts.PolicyCheck = ""; r.restart() }, "policy"},
		{"vmpal is failing", func(r *vmpalRig) { r.fake.Fail("list", fakevmpal.Fault{Stderr: "no"}) }, "could not list"},
		{"the template is missing", func(r *vmpalRig) { r.opts.Template = "absent"; r.restart() }, "could not read the template"},
		{"every slot is someone else's", func(r *vmpalRig) {
			for _, n := range []string{"a", "b"} {
				r.fake.AddVM(fakevmpal.VM{Name: n, State: "running", Installed: true})
			}
		}, "does not manage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newVMPalRig(t)
			tc.arrange(r)
			info := r.b.Probe(context.Background())
			if info.Available || !strings.Contains(info.Detail, tc.detail) {
				t.Errorf("available=%v, detail %q", info.Available, info.Detail)
			}
			if info.Kind != store.BackendProcess {
				t.Errorf("kind %q", info.Kind)
			}
		})
	}
}

// Its own clones holding both slots is a busy host and not a broken one, or the
// controller would stop scheduling to it the moment it was doing its job.
func TestProbeStaysAvailableWhileTheHostRunsItsOwnClones(t *testing.T) {
	r := newVMPalRig(t)
	for _, id := range []string{"run_one", "run_two"} {
		r.fake.AddVM(fakevmpal.VM{Name: r.b.vmName(id), State: "running", Installed: true})
	}
	if info := r.b.Probe(context.Background()); !info.Available {
		t.Errorf("unavailable: %s", info.Detail)
	}
}

// The template's size is not always the size jobs need, so a configured one is
// applied to the stopped clone and the template itself is left as it was.
func TestAConfiguredSizeIsAppliedToTheCloneAndHeldThroughBoot(t *testing.T) {
	r := newVMPalRig(t)
	r.opts.CPUs, r.opts.MemoryGB = 6, 10
	r.restart()
	vm, ok := r.fake.VM(r.create())
	if !ok {
		t.Fatal("the clone does not exist")
	}
	if vm.Settings["cpuCount"] != float64(6) || vm.Settings["memoryGB"] != float64(10) {
		t.Errorf("settings are %v CPUs and %v GB", vm.Settings["cpuCount"], vm.Settings["memoryGB"])
	}
	if vm.SessionHardware == nil || vm.SessionHardware.CPUCount != 6 || vm.SessionHardware.MemoryGB != 10 {
		t.Errorf("the session has %+v", vm.SessionHardware)
	}
	template, _ := r.fake.VM(vmpalTestTemplate)
	if template.Settings["cpuCount"] != float64(4) || template.Settings["memoryGB"] != float64(8) {
		t.Errorf("the template was resized: %v CPUs, %v GB", template.Settings["cpuCount"], template.Settings["memoryGB"])
	}
}

func TestACloneWithNoConfiguredSizeInheritsTheTemplates(t *testing.T) {
	r := newVMPalRig(t)
	vm, ok := r.fake.VM(r.create())
	if !ok {
		t.Fatal("the clone does not exist")
	}
	if vm.SessionHardware == nil || vm.SessionHardware.CPUCount != 4 || vm.SessionHardware.MemoryGB != 8 {
		t.Errorf("the session has %+v", vm.SessionHardware)
	}
}

// A job on a smaller VM than configured fails in ways that look like the job's
// fault, so a size that did not take is a failed clone like any other setting.
func TestACloneThatDoesNotGetItsSizeIsDeleted(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arrange func(*vmpalRig)
		// booted is false when the read-back on the stopped clone must catch it.
		booted bool
	}{
		{"the CPU count does not stick", func(r *vmpalRig) { r.fake.SettingsDoNotStick("cpuCount") }, false},
		{"the memory does not stick", func(r *vmpalRig) { r.fake.SettingsDoNotStick("memoryGB") }, false},
		{"it boots with other CPUs", func(r *vmpalRig) { r.fake.BootWithSize(2, 0) }, true},
		{"it boots with other memory", func(r *vmpalRig) { r.fake.BootWithSize(0, 8) }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newVMPalRig(t)
			r.opts.CPUs, r.opts.MemoryGB = 6, 10
			r.restart()
			tc.arrange(r)
			if !tc.booted {
				// A start would now report a backend fault, so the config fault
				// below can only come from the read-back on the stopped clone.
				r.fake.Fail("start", fakevmpal.Fault{Stderr: "this clone should not have been started"})
			}
			_, err := r.b.Create(context.Background(), vmpalTestSpec(vmpalTestRunner))
			if got := Fault(err); got != store.FaultConfig {
				t.Fatalf("fault %q: %v", got, err)
			}
			if r.credentialReachedGuest() {
				t.Error("the credential reached the guest")
			}
			r.assertNoCloneLeft()
		})
	}
}

// A release that stops reporting a size has not shown the clone has it.
func TestASizeThatIsNotReportedFailsTheCheck(t *testing.T) {
	r := newVMPalRig(t)
	r.opts.CPUs, r.opts.MemoryGB = 6, 10
	r.restart()
	if got := r.b.sizeSettingProblems(map[string]json.RawMessage{"cpuCount": json.RawMessage(`"6"`)}); len(got) != 2 {
		t.Errorf("settings problems: %v", got)
	}
	if got := r.b.sessionSizeProblems(&vmpalSessionHardware{}); len(got) != 2 {
		t.Errorf("session problems: %v", got)
	}
}

func TestANegativeSizeIsRefused(t *testing.T) {
	r := newVMPalRig(t)
	for _, change := range []func(*VMPalOptions){
		func(o *VMPalOptions) { o.CPUs = -1 },
		func(o *VMPalOptions) { o.MemoryGB = -1 },
	} {
		opts := r.opts
		change(&opts)
		if _, err := NewVMPal(opts); !errors.Is(err, ErrBackendConfig) {
			t.Errorf("NewVMPal returned %v", err)
		}
	}
}

func TestCheckVMPalTemplate(t *testing.T) {
	good := vmpalInfo{vmpalVM: vmpalVM{Name: "t", Guest: "macOS", Installed: true, State: "stopped", AgentControl: true}, Tools: vmpalTools{Version: "0.34"}}
	if err := checkVMPalTemplate(good); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*vmpalInfo){
		"not macOS":        func(i *vmpalInfo) { i.Guest = "Linux" },
		"not installed":    func(i *vmpalInfo) { i.Installed = false },
		"running":          func(i *vmpalInfo) { i.State = "running" },
		"no agent control": func(i *vmpalInfo) { i.AgentControl = false },
		"old Tools":        func(i *vmpalInfo) { i.Tools.Version = "0.33" },
		"unreadable Tools": func(i *vmpalInfo) { i.Tools.Version = "new" },
	} {
		bad := good
		change(&bad)
		if checkVMPalTemplate(bad) == nil {
			t.Errorf("%s passed", name)
		}
	}
	// Compared as numbers: as text, 0.100 sorts before 0.34.
	later := good
	later.Tools.Version = "0.100"
	if err := checkVMPalTemplate(later); err != nil {
		t.Errorf("0.100 was refused: %v", err)
	}
}

// The ID is what says which clones are this agent's, so a new one would disown
// every clone on the Mac.
func TestTheInstallIDSurvivesARestartAndIsNeverQuietlyReplaced(t *testing.T) {
	dir := t.TempDir()
	first, err := loadVMPalInstallID(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !vmpalInstallIDPattern.MatchString(first) {
		t.Fatalf("the ID is %q", first)
	}
	again, err := loadVMPalInstallID(dir)
	if err != nil || again != first {
		t.Fatalf("got %q, %v", again, err)
	}
	path := filepath.Join(dir, "install-id")
	if err := os.WriteFile(path, []byte("not-an-id"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVMPalInstallID(dir); err == nil {
		t.Fatal("a damaged ID was accepted")
	}
	if data, _ := os.ReadFile(path); string(data) != "not-an-id" {
		t.Errorf("the damaged file was replaced with %q", data)
	}
}

func TestARunnerVersionWithNoKnownDigestIsRefused(t *testing.T) {
	r := newVMPalRig(t)
	spec := vmpalTestSpec(vmpalTestRunner)
	spec.RunnerVersion = "9.9.9"
	_, err := r.b.Create(context.Background(), spec)
	if got := Fault(err); got != store.FaultConfig {
		t.Fatalf("fault %q: %v", got, err)
	}
	r.assertNoCloneLeft()
}

// The configured digest describes one release. Applied to another it would
// either refuse a good archive or vouch for one nobody checked.
func TestAConfiguredDigestAnswersForItsOwnVersionOnly(t *testing.T) {
	configured := strings.Repeat("a", 64)
	got, asset, err := resolveRunnerDigest("darwin", "arm64", "9.9.9", configured, "9.9.9")
	if err != nil || got != configured || asset != "actions-runner-osx-arm64-9.9.9.tar.gz" {
		t.Errorf("own version: %q, %q, %v", got, asset, err)
	}
	if got, _, _ := resolveRunnerDigest("darwin", "arm64", "9.9.8", configured, "9.9.9"); got != "" {
		t.Errorf("another version took the configured digest: %q", got)
	}
	want := knownRunnerSHA256[DefaultRunnerVersion+"/actions-runner-osx-arm64-"+DefaultRunnerVersion+".tar.gz"]
	if got, _, _ := resolveRunnerDigest("darwin", "arm64", DefaultRunnerVersion, configured, "9.9.9"); got != want || want == "" {
		t.Errorf("the shipped table gave %q, want %q", got, want)
	}
}

func TestWriteFileAtomicSetsTheModeAndLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "record.json")
	for _, content := range []string{"first", "second"} {
		if err := writeFileAtomic(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != content {
			t.Fatalf("read %q, %v", got, err)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode %o", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Errorf("the directory holds %v, %v", entries, err)
	}
}

// ---- the helper itself ----

// guestRig runs the real helper script under this machine's sh, in a home of
// its own, with the macOS-only tools replaced by small stand-ins.
type guestRig struct {
	t      *testing.T
	home   string
	script string
	stubs  string
}

func newGuestRig(t *testing.T) *guestRig {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh to run the helper with")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	g := &guestRig{t: t, home: filepath.Join(root, "home"), stubs: filepath.Join(root, "stubs")}
	for _, d := range []string{filepath.Join(g.home, ".zoomies", "runner"), g.stubs, filepath.Join(root, "cache")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	realBase64, err := exec.LookPath("base64")
	if err != nil {
		t.Skip("no base64")
	}
	g.stub("launchctl", "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \""+root+"/launchctl.log\"\nexit 0\n")
	g.stub("base64", "#!/bin/sh\nif [ \"$1\" = -D ]; then exec "+realBase64+" -d; fi\nexec "+realBase64+" \"$@\"\n")
	if path, err := exec.LookPath("sha256sum"); err == nil {
		g.stub("shasum", "#!/bin/sh\nexec "+path+" \"$3\"\n")
	} else if path, err := exec.LookPath("shasum"); err == nil {
		g.stub("shasum", "#!/bin/sh\nexec "+path+" -a 256 \"$3\"\n")
	} else {
		t.Skip("no SHA-256 tool")
	}
	g.stub("curl", "#!/bin/sh\nwhile [ $# -gt 1 ]; do\n  if [ \"$1\" = -o ]; then out=$2; fi\n  shift\ndone\nexec cp \""+root+"/download\" \"$out\"\n")
	perl, err := exec.LookPath("perl")
	if err != nil {
		t.Skip("no perl, which the helper starts the runner through")
	}
	g.stub("perl", "#!/bin/sh\nexec "+perl+" \"$@\"\n")
	script := vmpalHelperScript
	for tool, line := range map[string]string{
		"perl":      "PERL=/usr/bin/perl",
		"launchctl": "LAUNCHCTL=/bin/launchctl",
		"base64":    "BASE64=/usr/bin/base64",
		"shasum":    "SHASUM=/usr/bin/shasum",
		"curl":      "CURL=/usr/bin/curl",
	} {
		if !strings.Contains(script, line) {
			t.Fatalf("the helper no longer has the line %q", line)
		}
		script = strings.Replace(script, line, strings.SplitN(line, "=", 2)[0]+"="+filepath.Join(g.stubs, tool), 1)
	}
	script = strings.Replace(script, "CACHE_DIR=/Library/Caches/zoomies", "CACHE_DIR="+filepath.Join(root, "cache"), 1)
	g.script = filepath.Join(g.home, ".zoomies", "helper.sh")
	if err := os.WriteFile(g.script, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return g
}

func (g *guestRig) stub(name, body string) {
	g.t.Helper()
	if err := os.WriteFile(filepath.Join(g.stubs, name), []byte(body), 0o755); err != nil {
		g.t.Fatal(err)
	}
}

func (g *guestRig) path(parts ...string) string {
	return filepath.Join(append([]string{g.home, ".zoomies"}, parts...)...)
}

func (g *guestRig) command(env []string, args ...string) *exec.Cmd {
	cmd := exec.Command("sh", append([]string{g.script}, args...)...)
	cmd.Dir = g.home
	cmd.Env = append([]string{"HOME=" + g.home, "PATH=/usr/bin:/bin"}, env...)
	return cmd
}

func (g *guestRig) run(env []string, args ...string) (string, error) {
	g.t.Helper()
	out, err := g.command(env, args...).Output()
	return string(out), err
}

func (g *guestRig) runner(body string) {
	g.t.Helper()
	if err := os.WriteFile(g.path("runner", "run.sh"), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		g.t.Fatal(err)
	}
}

// The registration must be on disk only between delivery and the wrapper's
// first act, and readable by nobody else while it is.
func TestTheHelperHoldsTheRegistrationPrivatelyAndDeletesItOnRead(t *testing.T) {
	g := newGuestRig(t)
	payload := base64.StdEncoding.EncodeToString([]byte("POOL_SETTING=a value with spaces\nnot a line\n"))
	out, err := g.run([]string{"ACTIONS_RUNNER_INPUT_JITCONFIG=" + vmpalTestJIT, "ZOOMIES_ENV_B64=" + payload}, "deliver")
	if err != nil || checkVMPalLine(out, vmpalDeliverOK) != nil {
		t.Fatalf("deliver: %q, %v", out, err)
	}
	info, err := os.Stat(g.path("jit"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("the registration file has mode %o", info.Mode().Perm())
	}
	g.runner(`printf '%s' "$ACTIONS_RUNNER_INPUT_JITCONFIG" > "$HOME/seen-jit"
printf '%s' "$POOL_SETTING" > "$HOME/seen-env"
if [ -e "$HOME/.zoomies/jit" ] || [ -e "$HOME/.zoomies/env" ]; then touch "$HOME/still-there"; fi
exit 0`)
	if out, err := g.run(nil, "run"); err != nil {
		t.Fatalf("run: %q, %v", out, err)
	}
	for file, want := range map[string]string{"seen-jit": vmpalTestJIT, "seen-env": "a value with spaces"} {
		got, err := os.ReadFile(filepath.Join(g.home, file))
		if err != nil || string(got) != want {
			t.Errorf("%s = %q, %v", file, got, err)
		}
	}
	if _, err := os.Stat(filepath.Join(g.home, "still-there")); err == nil {
		t.Error("the registration or environment file was still there when the runner started")
	}
	for _, f := range []string{"jit", "env"} {
		if _, err := os.Stat(g.path(f)); err == nil {
			t.Errorf("%s was left on disk", f)
		}
	}
}

func TestTheHelperRecordsWhetherARunnerTookAJob(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		code int
		took bool
	}{
		{"a job that passed", `mkdir -p _diag; : > _diag/Worker_20260101.log; exit 0`, 0, true},
		{"a job that failed", `mkdir -p _diag; : > _diag/Worker_20260101.log; exit 3`, 3, true},
		{"no job ran", `mkdir -p _diag; : > _diag/Runner_20260101.log; exit 1`, 1, false},
		{"an outdated runner", `exit 7`, 7, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newGuestRig(t)
			if _, err := g.run([]string{"ACTIONS_RUNNER_INPUT_JITCONFIG=x"}, "deliver"); err != nil {
				t.Fatal(err)
			}
			g.runner(tc.body)
			g.run(nil, "run")
			out, err := g.run(nil, "exit")
			if err != nil {
				t.Fatal(err)
			}
			exit, running, err := parseVMPalExit(out)
			if err != nil || running || exit.Code != tc.code || exit.TookJob != tc.took {
				t.Errorf("exit record %q parsed as %+v, running=%v, %v", out, exit, running, err)
			}
		})
	}
}

// Stop works by SIGINT to the service, and the wrapper is what launchd signals.
// If it died of the signal the runner would never be told and no record written.
func TestTheHelperPassesAStopToTheRunnerAndRecordsItsExit(t *testing.T) {
	g := newGuestRig(t)
	if _, err := g.run([]string{"ACTIONS_RUNNER_INPUT_JITCONFIG=x"}, "deliver"); err != nil {
		t.Fatal(err)
	}
	g.runner(`trap 'touch "$HOME/got-int"; exit 42' INT
touch "$HOME/runner-up"
while :; do sleep 0.02; done`)
	cmd := g.command(nil, "run")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(g.home, "runner-up")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the runner never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the wrapper did not end after SIGINT")
	}
	if _, err := os.Stat(filepath.Join(g.home, "got-int")); err != nil {
		t.Error("the runner was not told")
	}
	out, err := g.run(nil, "exit")
	if err != nil {
		t.Fatal(err)
	}
	if exit, running, err := parseVMPalExit(out); err != nil || running || exit.Code != 42 {
		t.Errorf("exit record %q parsed as %+v, %v, %v", out, exit, running, err)
	}
}

func TestTheHelperServesTheLogInPieces(t *testing.T) {
	g := newGuestRig(t)
	text := "first line\n\xff\xfe not text\nlast line\n"
	if err := os.WriteFile(g.path("runner.log"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	var got []byte
	var offset int64
	for range 100 {
		out, err := g.run(nil, "log", strconv.FormatInt(offset, 10), "7")
		if err != nil {
			t.Fatal(err)
		}
		chunk, next, err := parseVMPalLog(out, 7)
		if err != nil {
			t.Fatalf("%q: %v", out, err)
		}
		got = append(got, chunk...)
		offset = next
		if len(chunk) == 0 {
			break
		}
	}
	if string(got) != text {
		t.Errorf("read %q", got)
	}
	out, err := g.run(nil, "log", "576460752303423488", "0")
	if err != nil {
		t.Fatal(err)
	}
	if _, next, err := parseVMPalLog(out, 0); err != nil || next != int64(len(text)) {
		t.Errorf("the end of the log came back as %d, %v from %q", next, err, out)
	}
}

// A corrupted download must never become the program given a registration.
func TestTheHelperOnlyUnpacksAnArchiveThatMatchesItsDigest(t *testing.T) {
	g := newGuestRig(t)
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "run.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(filepath.Dir(g.stubs), "download")
	if out, err := exec.Command("tar", "-czf", archive, "-C", src, "run.sh").CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	good := hex.EncodeToString(sum[:])

	if out, err := g.run(nil, "arm", "2.338.2", strings.Repeat("0", 64), "https://releases.invalid/runner.tar.gz"); err == nil {
		t.Fatalf("a wrong digest was accepted: %q", out)
	}
	if _, err := os.Stat(g.path("runner", "run.sh")); err == nil {
		t.Fatal("the archive was unpacked despite its digest")
	}
	out, err := g.run(nil, "arm", "2.338.2", good, "https://releases.invalid/runner.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if source, err := parseVMPalArm(out); err != nil || source != "download" {
		t.Fatalf("%q: %q, %v", out, source, err)
	}
	cache := filepath.Join(filepath.Dir(g.stubs), "cache", "actions-runner-osx-arm64-2.338.2.tar.gz")
	if err := os.WriteFile(cache, data, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err = g.run(nil, "arm", "2.338.2", good, "https://releases.invalid/runner.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if source, err := parseVMPalArm(out); err != nil || source != "cache" {
		t.Fatalf("%q: %q, %v", out, source, err)
	}
}

func TestTheHelperStartsTheRunnerAsALaunchAgent(t *testing.T) {
	g := newGuestRig(t)
	g.runner("exit 0")
	if _, err := g.run([]string{"ACTIONS_RUNNER_INPUT_JITCONFIG=x"}, "deliver"); err != nil {
		t.Fatal(err)
	}
	out, err := g.run(nil, "start")
	if err != nil || checkVMPalLine(out, vmpalStartOK) != nil {
		t.Fatalf("start: %q, %v", out, err)
	}
	plist, err := os.ReadFile(filepath.Join(g.home, "Library", "LaunchAgents", "dev.zoomies.runner.plist"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plist), "x</string>") || !strings.Contains(string(plist), "<string>run</string>") {
		t.Errorf("the plist is wrong:\n%s", plist)
	}
	log, err := os.ReadFile(filepath.Join(filepath.Dir(g.stubs), "launchctl.log"))
	if err != nil || !strings.Contains(string(log), "bootstrap gui/") {
		t.Errorf("launchctl saw %q, %v", log, err)
	}
	if out, err := g.run(nil, "stop"); err != nil || checkVMPalLine(out, vmpalStopOK) != nil {
		t.Errorf("stop: %q, %v", out, err)
	}
}

func TestTheHelperFitsTheInstallCommand(t *testing.T) {
	if n := len(vmpalHelperScript); n >= 16<<10 {
		t.Errorf("the helper is %d bytes; it travels in one environment variable and must stay under 16 KiB", n)
	}
	if strings.Contains(vmpalHelperScript, "ACTIONS_RUNNER_INPUT_JITCONFIG=x") {
		t.Error("the helper holds a registration")
	}
}

// The host's parser accepts only this grammar, so the script has to speak it
// exactly. Loopback only: one port with a listener and one without.
func TestTheHelperReportsEgressInItsGrammar(t *testing.T) {
	if _, err := os.Stat("/usr/bin/perl"); err != nil {
		t.Skip("no /usr/bin/perl")
	}
	if err := exec.Command("/usr/bin/perl", "-MIO::Socket::IP", "-e", "1").Run(); err != nil {
		t.Skip("perl has no IO::Socket::IP")
	}
	g := newGuestRig(t)
	open := vmpalTestListener(t)
	closed := vmpalTestClosedPort(t)
	out, err := g.run([]string{"ZOOMIES_EGRESS_TARGETS=" + open + " " + closed + " not-a-target"}, "egress")
	if err != nil {
		t.Fatalf("egress: %q, %v", out, err)
	}
	want := "zoomies-egress v1 target 0 connected\nzoomies-egress v1 target 1 refused\nzoomies-egress v1 target 2 error\nzoomies-egress v1 end 3\n"
	if out != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
}

func vmpalTestListener(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l.Addr().String()
}

func vmpalTestClosedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}
