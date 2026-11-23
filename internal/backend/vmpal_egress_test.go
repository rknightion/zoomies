//go:build !windows

package backend

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eyupio/zoomies/internal/store"
	"github.com/eyupio/zoomies/test/fakevmpal"
)

const (
	egressAllowName = "allowed.example:443"
	egressAllowIP   = "198.51.100.10:443"
	egressBlockLAN  = "203.0.113.10:22"
	egressBlockVPN  = "203.0.113.20:443"
)

// egressRig is a backend with the real gate over the fake vmpal, a scripted Mac
// dialer and a real policy-check executable.
type egressRig struct {
	*vmpalRig
	mu       sync.Mutex
	answers  map[string]string
	dialErr  map[string]error
	dialHook func(string)
	dialed   []string
	policyAt string
	marker   string
}

func newEgressRig(t *testing.T, maxVMs int) *egressRig {
	t.Helper()
	r := &egressRig{
		vmpalRig: newVMPalRig(t),
		answers: map[string]string{
			egressAllowName: vmpalEgressConnected, egressAllowIP: vmpalEgressConnected,
			egressBlockLAN: vmpalEgressTimeout, egressBlockVPN: vmpalEgressTimeout,
		},
		dialErr: map[string]error{},
	}
	dir := t.TempDir()
	r.policyAt, r.marker = filepath.Join(dir, "policy-check"), filepath.Join(dir, "policy-ran")
	r.writePolicy("exit 0")
	r.fake.OnEgress(r.answers)
	r.opts.Gate = nil
	r.opts.MaxVMs = maxVMs
	r.opts.PolicyCheck = r.policyAt
	r.opts.EgressMustAllow = []string{egressAllowName, egressAllowIP}
	r.opts.EgressMustBlock = []string{egressBlockLAN, egressBlockVPN}
	r.opts.EgressDial = r.dial
	r.restart()
	return r
}

func (r *egressRig) writePolicy(body string) {
	r.t.Helper()
	script := fmt.Sprintf("#!/bin/sh\n: > %q\n%s\n", r.marker, body)
	if err := os.WriteFile(r.policyAt, []byte(script), 0o755); err != nil {
		r.t.Fatal(err)
	}
}

func (r *egressRig) policyRan() bool {
	_, err := os.Stat(r.marker)
	return err == nil
}

func (r *egressRig) dial(_ context.Context, address string) error {
	r.mu.Lock()
	r.dialed = append(r.dialed, address)
	hook, err := r.dialHook, r.dialErr[address]
	r.mu.Unlock()
	if hook != nil {
		hook(address)
	}
	return err
}

func (r *egressRig) answer(target, word string) {
	r.t.Helper()
	r.answers[target] = word
	r.fake.OnEgress(r.answers)
}

func (r *egressRig) policyGate() *vmpalPolicyGate {
	r.t.Helper()
	g, ok := r.b.gate.(*vmpalPolicyGate)
	if !ok {
		r.t.Fatalf("the backend's gate is %T", r.b.gate)
	}
	return g
}

// assertNothingDelivered is the property the whole check exists for.
func (r *egressRig) assertNothingDelivered() {
	r.t.Helper()
	if r.credentialReachedGuest() {
		r.t.Error("the credential reached the guest")
	}
	for _, step := range []string{"helper.sh arm", "helper.sh deliver", "helper.sh start"} {
		if got := r.execs(step); len(got) != 0 {
			r.t.Errorf("%s ran on a clone that had not passed: %v", step, got)
		}
	}
}

// The order is the design: a must-block result only means something once the
// Mac has just reached the same target, and the attestation comes last.
func TestAPassingCheckRunsItsStepsInOrderAndThenDelivers(t *testing.T) {
	r := newEgressRig(t, 1)
	var seen []int
	r.dialHook = func(string) { seen = append(seen, len(r.execs("helper.sh egress"))) }
	r.create()

	if want := []string{egressBlockLAN, egressBlockVPN}; !slices.Equal(r.dialed, want) {
		t.Errorf("the Mac dialled %v, want %v", r.dialed, want)
	}
	// One guest run for the must-allow targets, then one for each must-block
	// target, each after the Mac's own attempt on it.
	if want := []int{1, 2}; !slices.Equal(seen, want) {
		t.Errorf("guest runs before each dial: %v, want %v", seen, want)
	}
	var sent []string
	for _, c := range r.execs("helper.sh egress") {
		sent = append(sent, c.Env[vmpalEgressTargetsVar])
	}
	want := []string{egressAllowName + " " + egressAllowIP, egressBlockLAN, egressBlockVPN}
	if !slices.Equal(sent, want) {
		t.Errorf("the guest was given %q, want %q", sent, want)
	}
	if !r.policyRan() {
		t.Error("the host policy check did not run")
	}
	if got := r.execs("helper.sh deliver"); len(got) != 1 {
		t.Errorf("%d deliveries", len(got))
	}
}

// Every way the check can fail, each held to the same promise: the registration
// stays on the Mac, this clone goes, and the host stops taking new work.
func TestEveryFailedCheckKeepsTheRegistrationOutOfTheGuest(t *testing.T) {
	malformed := func(stdout string) func(*egressRig) {
		return func(r *egressRig) { r.fake.OnExec("helper.sh egress", fakevmpal.ExecReply{Stdout: stdout}) }
	}
	answer := func(target, word string) func(*egressRig) {
		return func(r *egressRig) { r.answer(target, word) }
	}
	dead := func(target string) func(*egressRig) {
		return func(r *egressRig) { r.dialErr[target] = errors.New("connection timed out") }
	}
	both := func(fs ...func(*egressRig)) func(*egressRig) {
		return func(r *egressRig) {
			for _, f := range fs {
				f(r)
			}
		}
	}
	policy := func(body string) func(*egressRig) {
		return func(r *egressRig) { r.writePolicy(body) }
	}
	for _, tc := range []struct {
		name   string
		make   func(*egressRig)
		breach bool
	}{
		{"a must-block target connects", answer(egressBlockLAN, vmpalEgressConnected), true},
		{"a must-block target refuses", answer(egressBlockVPN, vmpalEgressRefused), true},
		{"a guest reaches a target the Mac cannot", both(dead(egressBlockLAN), answer(egressBlockLAN, vmpalEgressConnected)), true},
		{"a breach after a target that could not be judged", both(dead(egressBlockLAN), answer(egressBlockVPN, vmpalEgressConnected)), true},
		{"a breach with must-allow failing too", both(answer(egressAllowIP, vmpalEgressTimeout), answer(egressBlockVPN, vmpalEgressRefused)), true},

		{"a dead must-block target", dead(egressBlockLAN), false},
		{"every must-block target dead", both(dead(egressBlockLAN), dead(egressBlockVPN)), false},
		{"a must-block attempt unreachable", answer(egressBlockLAN, vmpalEgressUnreachable), false},
		{"a must-block attempt errors", answer(egressBlockVPN, vmpalEgressError), false},
		{"a must-allow target refuses", answer(egressAllowName, vmpalEgressRefused), false},
		{"a must-allow target times out", answer(egressAllowIP, vmpalEgressTimeout), false},
		{"a must-allow target is unreachable", answer(egressAllowName, vmpalEgressUnreachable), false},
		{"a must-allow target errors", answer(egressAllowIP, vmpalEgressError), false},

		{"no output", malformed(""), false},
		{"prose", malformed("everything is fine\n"), false},
		{"no end line", malformed("zoomies-egress v1 target 0 connected\nzoomies-egress v1 target 1 connected\n"), false},
		{"an end line that disagrees", malformed("zoomies-egress v1 target 0 connected\nzoomies-egress v1 target 1 connected\nzoomies-egress v1 end 3\n"), false},
		{"an index out of order", malformed("zoomies-egress v1 target 1 connected\nzoomies-egress v1 target 0 connected\nzoomies-egress v1 end 2\n"), false},
		{"an unknown result", malformed("zoomies-egress v1 target 0 fine\nzoomies-egress v1 target 1 fine\nzoomies-egress v1 end 2\n"), false},
		{"the helper fails", func(r *egressRig) {
			r.fake.OnExec("helper.sh egress", fakevmpal.ExecReply{Stderr: "no perl", ExitCode: 1})
		}, false},

		{"the policy check fails", policy("exit 3"), false},
		{"the policy check is missing", func(r *egressRig) {
			if err := os.Remove(r.policyAt); err != nil {
				r.t.Fatal(err)
			}
		}, false},
		{"the policy check hangs", func(r *egressRig) {
			r.writePolicy("trap '' TERM\nsleep 3")
			g := r.policyGate()
			g.policyLimit, g.policyGrace = 100*time.Millisecond, 100*time.Millisecond
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newEgressRig(t, 1)
			tc.make(r)
			_, err := r.b.Create(context.Background(), vmpalTestSpec(vmpalTestRunner))

			var failed *vmpalEgressFailure
			if !errors.As(err, &failed) {
				t.Fatalf("create returned %v", err)
			}
			if failed.Breach != tc.breach {
				t.Errorf("breach=%v, want %v: %v", failed.Breach, tc.breach, err)
			}
			if errors.Is(err, ErrUnavailable) || errors.Is(err, ErrDaemonBusy) {
				t.Errorf("the failure wraps a sentinel that sends the agent the wrong way: %v", err)
			}
			if got := Fault(err); got != store.FaultBackend {
				t.Errorf("fault %q", got)
			}
			if strings.Contains(err.Error(), vmpalTestJIT) {
				t.Errorf("the credential is in the error: %v", err)
			}
			r.assertNothingDelivered()
			r.assertNoCloneLeft()
			if err := r.b.gate.Held(); !errors.Is(err, errVMPalHeld) {
				t.Errorf("the host is not on hold: %v", err)
			}
			if info := r.b.Probe(context.Background()); info.Available {
				t.Error("Probe calls a host on hold available")
			}
		})
	}
}

// The attestation must not be consulted to rescue a guest that has already
// failed, and must be what stops one that has otherwise passed.
func TestThePolicyCheckRunsOnlyAfterTheGuestChecksPass(t *testing.T) {
	for _, word := range []string{vmpalEgressConnected, vmpalEgressUnreachable} {
		r := newEgressRig(t, 1)
		r.answer(egressBlockLAN, word)
		if _, err := r.b.Create(context.Background(), vmpalTestSpec(vmpalTestRunner)); err == nil {
			t.Fatal("create succeeded")
		}
		if r.policyRan() {
			t.Errorf("the policy check ran after the guest had already failed with %s", word)
		}
	}

	r := newEgressRig(t, 1)
	r.writePolicy("exit 1")
	if _, err := r.b.Create(context.Background(), vmpalTestSpec(vmpalTestRunner)); err == nil {
		t.Fatal("create succeeded with the policy check failing")
	}
	if got := r.execs("helper.sh egress"); len(got) != 3 {
		t.Errorf("%d guest runs before the policy check, want all 3", len(got))
	}
	if !r.policyRan() {
		t.Error("the policy check did not run")
	}
}

// It runs as the agent on the Mac, so nothing in the agent's environment may
// change what it loads or be readable by it.
func TestThePolicyCheckGetsAMinimalEnvironmentAndNoArguments(t *testing.T) {
	t.Setenv("ZOOMIES_CANARY", "must-not-arrive")
	t.Setenv("DYLD_INSERT_LIBRARIES", "/tmp/not-a-library")
	r := newEgressRig(t, 1)
	seen := filepath.Join(t.TempDir(), "seen")
	r.writePolicy(fmt.Sprintf("{ echo args=$#; /usr/bin/env; } > %q", seen))
	r.create()
	data, err := os.ReadFile(seen)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.Contains(got, "args=0") {
		t.Errorf("the check was given arguments: %s", got)
	}
	for _, leak := range []string{"ZOOMIES_CANARY", "DYLD_INSERT_LIBRARIES", vmpalTestJIT} {
		if strings.Contains(got, leak) {
			t.Errorf("%s reached the policy check", leak)
		}
	}
}

// A check that ignores its signal must still not hold the create for longer than
// its own limit, because the create's whole budget is shared.
func TestAHungPolicyCheckIsAbandonedAtItsLimit(t *testing.T) {
	r := newEgressRig(t, 1)
	r.writePolicy("trap '' TERM\nsleep 3")
	g := r.policyGate()
	g.policyLimit, g.policyGrace = 100*time.Millisecond, 100*time.Millisecond
	started := time.Now()
	err := g.runPolicyCheck(context.Background())
	if err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("got %v", err)
	}
	if took := time.Since(started); took > 2*time.Second {
		t.Errorf("a hung check held the create for %s", took)
	}
}

// A breach is about the host, so a clone that passed earlier was checked against
// a policy now known not to hold. Everything that is not this agent's is left.
func TestABreachDeletesEveryCloneThisAgentManagesAndNothingElse(t *testing.T) {
	r := newEgressRig(t, 2)
	other := "00000000"
	if r.b.installID == other {
		other = "11111111"
	}
	running := r.seed(vmpalStageRunning, func(e *vmpalEntry) { e.StartedAt = r.clock.Now() })
	foreign := []string{"ci-linux-builder", "zoomies-vm-" + other + "-run_notours"}
	r.fake.AddVM(fakevmpal.VM{Name: foreign[0], Guest: "Linux", State: "running", Installed: true})
	r.fake.AddVM(fakevmpal.VM{Name: foreign[1], State: "stopped", Installed: true})

	r.answer(egressBlockLAN, vmpalEgressConnected)
	_, err := r.b.Create(context.Background(), vmpalTestSpec("run_breacher"))
	var failed *vmpalEgressFailure
	if !errors.As(err, &failed) || !failed.Breach {
		t.Fatalf("create returned %v", err)
	}
	if _, ok := r.fake.VM(running); ok {
		t.Error("the clone already running survived a breach")
	}
	if _, ok := r.fake.VM(r.b.vmName("run_breacher")); ok {
		t.Error("the clone that found the breach survived it")
	}
	for _, name := range append(foreign, vmpalTestTemplate) {
		if _, ok := r.fake.VM(name); !ok {
			t.Errorf("%s was deleted, and it is not this agent's", name)
		}
	}
	if vm, _ := r.fake.VM(foreign[0]); vm.State != "running" {
		t.Errorf("%s was disturbed: %s", foreign[0], vm.State)
	}

	// The controller is told why, rather than finding the runner gone.
	w := r.workload(running)
	if w.Status.Phase != PhaseFailed || !strings.Contains(w.Status.Message, "network policy") {
		t.Errorf("the purged runner reports %+v", w.Status)
	}
	if err := r.b.Remove(context.Background(), Handle(running)); err != nil {
		t.Fatalf("remove: %v", err)
	}
	r.assertOnlyTheseClonesLeft(foreign)
	if err := r.b.gate.Held(); !errors.Is(err, errVMPalHeld) {
		t.Errorf("no hold after a breach: %v", err)
	}
}

func (r *egressRig) assertOnlyTheseClonesLeft(except []string) {
	r.t.Helper()
	for _, vm := range r.fake.VMs() {
		if strings.HasPrefix(vm.Name, "zoomies-vm-") && !slices.Contains(except, vm.Name) {
			r.t.Errorf("clone %s was left on the Mac", vm.Name)
		}
	}
	if files := r.ledgerFiles(); len(files) != 0 {
		r.t.Errorf("ledger entries were left behind: %v", files)
	}
}

// A create that was part way through when another clone found the breach must
// not go on to deliver: its own check started before the news.
func TestABreachStopsACreateAlreadyInFlight(t *testing.T) {
	r := newEgressRig(t, 2)
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	r.dialHook = func(string) {
		first := false
		once.Do(func() { first = true })
		if first {
			close(reached)
			<-release
		}
	}
	inFlight := make(chan error, 1)
	go func() {
		_, err := r.b.Create(context.Background(), vmpalTestSpec("run_inflight"))
		inFlight <- err
	}()
	<-reached

	r.answer(egressBlockLAN, vmpalEgressRefused)
	_, err := r.b.Create(context.Background(), vmpalTestSpec("run_breacher"))
	var failed *vmpalEgressFailure
	if !errors.As(err, &failed) || !failed.Breach {
		close(release)
		t.Fatalf("create returned %v", err)
	}
	if _, ok := r.fake.VM(r.b.vmName("run_inflight")); ok {
		t.Error("the in-flight clone survived the breach")
	}
	// Its own answer would now pass, so only the purge can stop it.
	r.answer(egressBlockLAN, vmpalEgressTimeout)
	close(release)
	if err := <-inFlight; err == nil {
		t.Fatal("the in-flight create succeeded after the breach")
	}
	r.assertNothingDelivered()
	r.assertNoCloneLeft()
}

// An admission that has counted its slot but not yet written its entry is
// invisible in the ledger, so a purge that did not wait for it would miss a clone
// that goes on to be made.
func TestABreachWaitsForAnAdmissionInProgress(t *testing.T) {
	r := newEgressRig(t, 2)
	r.b.admitMu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.b.purgeClones(context.Background())
	}()
	select {
	case <-done:
		r.b.admitMu.Unlock()
		t.Fatal("the purge read the ledger with an admission still in progress")
	case <-time.After(150 * time.Millisecond):
	}
	name := r.seed(vmpalStageIntent, nil)
	r.b.admitMu.Unlock()
	<-done
	if _, ok := r.fake.VM(name); ok {
		t.Error("the clone admitted during the purge survived it")
	}
}

// The recorded ID is what shows a VM is still the clone that was made. With no
// record to read, a VM with this name may be somebody else's, so it is left for
// the agent's Remove to retry rather than deleted on the name alone.
func TestAPurgeLeavesAVMWhoseRecordCannotBeRead(t *testing.T) {
	r := newEgressRig(t, 1)
	name := r.seed(vmpalStageRunning, nil)
	path := r.b.ledger.path(name)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	r.b.purgeClone(context.Background(), name)
	if _, ok := r.fake.VM(name); !ok {
		t.Error("a VM was deleted with no record to check it against")
	}
}

// Inconclusive may be nothing more than a target that was down for a moment, so
// it must not take a running job with it.
func TestAnInconclusiveCheckLeavesOtherClonesRunning(t *testing.T) {
	r := newEgressRig(t, 2)
	running := r.seed(vmpalStageRunning, func(e *vmpalEntry) { e.StartedAt = r.clock.Now() })
	r.dialErr[egressBlockLAN] = errors.New("no route to host")
	_, err := r.b.Create(context.Background(), vmpalTestSpec("run_doubtful"))
	var failed *vmpalEgressFailure
	if !errors.As(err, &failed) || failed.Breach {
		t.Fatalf("create returned %v", err)
	}
	vm, ok := r.fake.VM(running)
	if !ok || vm.State != "running" {
		t.Fatalf("the running clone was disturbed: %+v, %v", vm, ok)
	}
	if w := r.workload(running); w.Status.Phase != PhaseRunning {
		t.Errorf("the running clone reports %+v", w.Status)
	}
	if _, ok := r.fake.VM(r.b.vmName("run_doubtful")); ok {
		t.Error("the clone that failed its check survived")
	}
	if err := r.b.gate.Held(); !errors.Is(err, errVMPalHeld) {
		t.Errorf("no hold after an inconclusive check: %v", err)
	}
}

// Cancelling a create says nothing about the network, so it must not take the
// host out of service for ten minutes.
func TestACancelledCheckStartsNoHold(t *testing.T) {
	r := newEgressRig(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.dialHook = func(string) { cancel() }
	_, err := r.b.Create(ctx, vmpalTestSpec(vmpalTestRunner))
	if err == nil {
		t.Fatal("the create succeeded")
	}
	if err := r.b.gate.Held(); err != nil {
		t.Errorf("a cancelled create held the host: %v", err)
	}
	r.assertNothingDelivered()
	r.assertNoCloneLeft()
}

// With any part missing the check would test less than the operator meant it
// to, and nothing about a passing check would say so.
func TestAnIncompletePolicyLeavesTheBackendRefusing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*VMPalOptions)
		detail string
	}{
		{"no policy check", func(o *VMPalOptions) { o.PolicyCheck = "" }, "policy_check"},
		{"a relative policy check", func(o *VMPalOptions) { o.PolicyCheck = "bin/check" }, "absolute"},
		{"no must-allow", func(o *VMPalOptions) { o.EgressMustAllow = nil }, "egress_must_allow"},
		{"no must-block", func(o *VMPalOptions) { o.EgressMustBlock = nil }, "egress_must_block"},
		{"a must-allow with no port", func(o *VMPalOptions) { o.EgressMustAllow = []string{"allowed.example"} }, "host:port"},
		{"a must-allow with a space", func(o *VMPalOptions) { o.EgressMustAllow = []string{"a b:443"} }, "does not name"},
		{"a must-allow in IPv6", func(o *VMPalOptions) { o.EgressMustAllow = []string{"[2001:db8::1]:443"} }, "IPv6"},
		{"a must-block by name", func(o *VMPalOptions) { o.EgressMustBlock = []string{"blocked.example:22"} }, "IP address"},
		{"a must-block in IPv6", func(o *VMPalOptions) { o.EgressMustBlock = []string{"[2001:db8::1]:22"} }, "IPv6"},
		{"a must-block on loopback", func(o *VMPalOptions) { o.EgressMustBlock = []string{"127.0.0.1:22"} }, "guest itself"},
		{"a port out of range", func(o *VMPalOptions) { o.EgressMustBlock = []string{"203.0.113.10:70000"} }, "port"},
		{"a target on both lists", func(o *VMPalOptions) { o.EgressMustAllow = []string{egressBlockLAN} }, "also in"},
		{"more targets than fit the time limit", func(o *VMPalOptions) {
			o.EgressMustBlock = nil
			for i := range vmpalEgressMaxTargets {
				o.EgressMustBlock = append(o.EgressMustBlock, fmt.Sprintf("203.0.113.%d:22", i+1))
			}
		}, "more than"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newEgressRig(t, 1)
			tc.change(&r.opts)
			r.restart()
			_, err := r.b.Create(context.Background(), vmpalTestSpec(vmpalTestRunner))
			if !errors.Is(err, errVMPalHeld) {
				t.Fatalf("create returned %v", err)
			}
			if got := r.fake.Execs(); len(got) != 0 {
				t.Errorf("a clone got as far as running commands: %v", got)
			}
			r.assertNoCloneLeft()
			info := r.b.Probe(context.Background())
			if info.Available || !strings.Contains(info.Detail, tc.detail) {
				t.Errorf("available=%v, detail %q, want it to mention %q", info.Available, info.Detail, tc.detail)
			}
		})
	}
}

func TestTheEgressParserAcceptsOnlyItsGrammar(t *testing.T) {
	good := "zoomies-egress v1 target 0 connected\nzoomies-egress v1 target 1 timeout\nzoomies-egress v1 end 2\n"
	got, err := parseVMPalEgress(good, 2)
	if err != nil || !slices.Equal(got, []string{"connected", "timeout"}) {
		t.Fatalf("got %v, %v", got, err)
	}
	for name, stdout := range map[string]string{
		"empty":            "",
		"no end":           "zoomies-egress v1 target 0 connected\nzoomies-egress v1 target 1 timeout\n",
		"too few":          "zoomies-egress v1 target 0 connected\nzoomies-egress v1 end 1\n",
		"a repeated index": "zoomies-egress v1 target 0 connected\nzoomies-egress v1 target 0 timeout\nzoomies-egress v1 end 2\n",
		"a skipped index":  "zoomies-egress v1 target 0 connected\nzoomies-egress v1 target 2 timeout\nzoomies-egress v1 end 2\n",
		"out of order":     "zoomies-egress v1 target 1 timeout\nzoomies-egress v1 target 0 connected\nzoomies-egress v1 end 2\n",
		"a wrong end":      "zoomies-egress v1 target 0 connected\nzoomies-egress v1 target 1 timeout\nzoomies-egress v1 end 3\n",
		"an unknown word":  "zoomies-egress v1 target 0 connected\nzoomies-egress v1 target 1 blocked\nzoomies-egress v1 end 2\n",
		"another version":  "zoomies-egress v2 target 0 connected\nzoomies-egress v1 target 1 timeout\nzoomies-egress v1 end 2\n",
		"trailing text":    good + "and one more thing\n",
		"a leading line":   "hello\n" + good,
		"carriage returns": strings.ReplaceAll(good, "\n", "\r\n"),
		"a padded index":   "zoomies-egress v1 target 00 connected\nzoomies-egress v1 target 1 timeout\nzoomies-egress v1 end 2\n",
		"a trailing space": "zoomies-egress v1 target 0 connected \nzoomies-egress v1 target 1 timeout\nzoomies-egress v1 end 2\n",
	} {
		if got, err := parseVMPalEgress(stdout, 2); err == nil {
			t.Errorf("%s was accepted as %v", name, got)
		}
	}
}
