//go:build !windows

package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eyupio/zoomies/internal/store"
	"github.com/eyupio/zoomies/test/fakevmpal"
)

func newHostStateForTest(t *testing.T) (*vmpalHostState, *vmpalTestClock, string) {
	t.Helper()
	clock := &vmpalTestClock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	path := filepath.Join(t.TempDir(), "state.json")
	return openVMPalHostState(path, clock.Now, slog.New(slog.NewTextHandler(io.Discard, nil))), clock, path
}

func failThree(s *vmpalHostState) {
	for range vmpalBreakerThreshold {
		s.runnerExited(false, false)
	}
}

func TestTheBreakerHoldDoublesFromTenMinutesToAnHour(t *testing.T) {
	s, clock, _ := newHostStateForTest(t)
	for round, want := range []time.Duration{10, 20, 40, 60, 60, 60} {
		s.runnerExited(false, false)
		s.runnerExited(false, false)
		if err := s.held(); err != nil {
			t.Fatalf("round %d: held after two failures: %v", round, err)
		}
		s.runnerExited(false, false)
		if got := s.file.HoldUntil.Sub(clock.Now()); got != want*time.Minute {
			t.Fatalf("round %d: hold of %s, want %d minutes", round, got, want)
		}
		if s.file.Count != 0 {
			t.Errorf("round %d: starting a hold left the count at %d", round, s.file.Count)
		}
		clock.advance(want*time.Minute - time.Second)
		if err := s.held(); !errors.Is(err, errVMPalHeld) {
			t.Errorf("round %d: the hold ended early: %v", round, err)
		}
		clock.advance(time.Second)
		if err := s.held(); err != nil {
			t.Errorf("round %d: the hold did not end: %v", round, err)
		}
	}
}

// A job is the one proof that the host works, so it wipes the slate.
func TestARunnerThatTookAJobClearsTheCountAndTheLevel(t *testing.T) {
	s, clock, _ := newHostStateForTest(t)
	failThree(s)
	failThree(s)
	if s.file.Level != 2 {
		t.Fatalf("level %d", s.file.Level)
	}
	clock.advance(time.Hour)
	s.runnerExited(false, false)
	s.runnerExited(true, false)
	if s.file.Count != 0 || s.file.Level != 0 {
		t.Fatalf("count %d, level %d after a job", s.file.Count, s.file.Level)
	}
	failThree(s)
	if got := s.file.HoldUntil.Sub(clock.Now()); got != 10*time.Minute {
		t.Errorf("the next hold is %s, want the first step again", got)
	}
}

// Even a runner the agent stopped has shown the host works if it took a job.
func TestAJobThatWasThenStoppedStillClearsTheBreaker(t *testing.T) {
	s, _, _ := newHostStateForTest(t)
	s.runnerExited(false, false)
	s.runnerExited(true, true)
	if s.file.Count != 0 {
		t.Errorf("count %d", s.file.Count)
	}
}

// Scaling down stops idle runners on purpose, and that is no evidence of
// anything, so it must neither trip the breaker nor reset it.
func TestAStoppedRunnerNeitherCountsNorClears(t *testing.T) {
	s, _, _ := newHostStateForTest(t)
	for range 20 {
		s.runnerExited(false, true)
	}
	if err := s.held(); err != nil || s.file.Count != 0 {
		t.Fatalf("stopped runners moved the breaker: count %d, %v", s.file.Count, err)
	}
	s.runnerExited(false, false)
	s.runnerExited(false, true)
	if s.file.Count != 1 {
		t.Errorf("a stopped runner changed the count to %d", s.file.Count)
	}
}

// With two slots, one runner is still up when the other trips the breaker.
func TestAnExitDuringAHoldCountsTowardTheNextRound(t *testing.T) {
	s, clock, _ := newHostStateForTest(t)
	failThree(s)
	first := s.file.HoldUntil
	s.runnerExited(false, false)
	if s.file.Count != 1 {
		t.Errorf("count %d after an exit during the hold", s.file.Count)
	}
	if !s.file.HoldUntil.Equal(first) {
		t.Errorf("an exit during the hold moved it to %s", s.file.HoldUntil)
	}
	clock.advance(10 * time.Minute)
	s.runnerExited(false, false)
	s.runnerExited(false, false)
	if got := s.file.HoldUntil.Sub(clock.Now()); got != 20*time.Minute {
		t.Errorf("the next hold is %s, want 20 minutes after two more failures", got)
	}
}

// The failure this guards against is a breaker that reads a busy, healthy fleet
// as a broken one and takes it out of service.
func TestShortRealJobsNeverTripTheBreaker(t *testing.T) {
	r := newEgressRig(t, 1)
	r.fake.OnExec("helper.sh exit", fakevmpal.ExecReply{Stdout: "zoomies-exit v1 code=0 job=1\n"})
	for i := range 6 {
		h, err := r.b.Create(context.Background(), vmpalTestSpec(fmt.Sprintf("run_real%d", i)))
		if err != nil {
			t.Fatalf("job %d: %v", i, err)
		}
		if finished, err := r.b.readGuestExit(context.Background(), string(h), time.Second); err != nil || !finished {
			t.Fatalf("job %d: finished=%v, %v", i, finished, err)
		}
		if err := r.b.Remove(context.Background(), h); err != nil {
			t.Fatal(err)
		}
		r.clock.advance(time.Second)
	}
	if err := r.b.gate.Held(); err != nil {
		t.Errorf("real jobs tripped the breaker: %v", err)
	}
}

// A short hold arriving during a long one must not let work back in early, and
// the reason shown has to be the one that is actually in force.
func TestTheLaterHoldWinsAndKeepsItsReason(t *testing.T) {
	s, clock, _ := newHostStateForTest(t)
	s.startHold(40*time.Minute, "the long one")
	s.startHold(10*time.Minute, "the short one")
	if got := s.file.HoldUntil.Sub(clock.Now()); got != 40*time.Minute || s.file.HoldReason != "the long one" {
		t.Errorf("hold of %s for %q", got, s.file.HoldReason)
	}
	s.startHold(50*time.Minute, "the later one")
	if got := s.file.HoldUntil.Sub(clock.Now()); got != 50*time.Minute || s.file.HoldReason != "the later one" {
		t.Errorf("hold of %s for %q", got, s.file.HoldReason)
	}
}

// A restart that forgot a hold would be the easiest way past it, and the refusal
// must be the one sentinel the agent does not retry or read as a dead runtime.
func TestAHoldSurvivesARestartAndRefusesBeforeCloning(t *testing.T) {
	r := newEgressRig(t, 1)
	r.dialErr[egressBlockLAN] = errors.New("no route to host")
	if _, err := r.b.Create(context.Background(), vmpalTestSpec(vmpalTestRunner)); err == nil {
		t.Fatal("create succeeded")
	}
	delete(r.dialErr, egressBlockLAN)
	r.restart()
	execs := len(r.fake.Execs())

	r.clock.advance(vmpalEgressHold - time.Second)
	_, err := r.b.Create(context.Background(), vmpalTestSpec("run_during"))
	if !errors.Is(err, errVMPalHeld) {
		t.Fatalf("create during the hold returned %v", err)
	}
	if errors.Is(err, ErrUnavailable) || errors.Is(err, ErrDaemonBusy) {
		t.Errorf("the refusal wraps a sentinel that sends the agent the wrong way: %v", err)
	}
	if got := Fault(err); got != store.FaultBackend {
		t.Errorf("fault %q", got)
	}
	if _, ok := r.fake.VM(r.b.vmName("run_during")); ok {
		t.Error("a clone was made during a hold")
	}
	if got := len(r.fake.Execs()); got != execs {
		t.Errorf("%d commands ran in a guest during a hold", got-execs)
	}
	info := r.b.Probe(context.Background())
	if info.Available || !strings.Contains(info.Detail, "held until") || !strings.Contains(info.Detail, egressBlockLAN) {
		t.Errorf("available=%v, detail %q", info.Available, info.Detail)
	}

	r.clock.advance(time.Second)
	if info := r.b.Probe(context.Background()); !info.Available {
		t.Errorf("still unavailable after the hold: %s", info.Detail)
	}
	if _, err := r.b.Create(context.Background(), vmpalTestSpec("run_after")); err != nil {
		t.Errorf("create after the hold: %v", err)
	}
}

func TestTheBreakerCountSurvivesARestart(t *testing.T) {
	r := newEgressRig(t, 1)
	r.policyGate().RunnerExited(false, false)
	r.policyGate().RunnerExited(false, false)
	r.restart()
	if err := r.b.gate.Held(); err != nil {
		t.Fatalf("held after two failures: %v", err)
	}
	r.policyGate().RunnerExited(false, false)
	if err := r.b.gate.Held(); !errors.Is(err, errVMPalHeld) {
		t.Errorf("the third failure after a restart did not trip the breaker: %v", err)
	}
}

// A damaged file may be the record of a hold, so it is treated as one.
func TestACorruptStateFileStartsATenMinuteHoldAndIsRewritten(t *testing.T) {
	for name, content := range map[string]string{
		"not JSON":            "{ this is not json",
		"empty":               "",
		"the wrong type":      "[1, 2, 3]",
		"a negative count":    `{"breaker_count": -1, "breaker_level": 0}`,
		"a count past a trip": `{"breaker_count": 3, "breaker_level": 0}`,
		"an impossible level": `{"breaker_count": 0, "breaker_level": 9}`,
		"a hold years away":   `{"hold_until": "2099-01-01T00:00:00Z", "hold_reason": "x", "breaker_count": 0, "breaker_level": 0}`,
	} {
		t.Run(name, func(t *testing.T) {
			r := newEgressRig(t, 1)
			path := filepath.Join(r.opts.WorkDir, "vmpal", "state.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			r.restart()
			if got := r.policyGate().state.file.HoldUntil.Sub(r.clock.Now()); got != vmpalEgressHold {
				t.Errorf("hold of %s", got)
			}
			if _, err := r.b.Create(context.Background(), vmpalTestSpec(vmpalTestRunner)); !errors.Is(err, errVMPalHeld) {
				t.Errorf("create returned %v", err)
			}
			if info := r.b.Probe(context.Background()); info.Available {
				t.Error("Probe calls the host available")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var file vmpalHostFile
			if err := json.Unmarshal(data, &file); err != nil || !file.believable(r.clock.Now()) {
				t.Errorf("the file was not rewritten: %q, %v", data, err)
			}
			// A rewritten file is a good one: the next start does not extend it.
			r.clock.advance(time.Minute)
			r.restart()
			if got := r.policyGate().state.file.HoldUntil.Sub(r.clock.Now()); got != vmpalEgressHold-time.Minute {
				t.Errorf("a restart moved the hold: %s left", got)
			}
		})
	}
}

// A state path nobody can read is as unknown as a corrupt one.
func TestAStateFileThatCannotBeReadStartsAHold(t *testing.T) {
	_, clock, path := newHostStateForTest(t)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	got := openVMPalHostState(path, clock.Now, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := got.held(); !errors.Is(err, errVMPalHeld) {
		t.Errorf("no hold: %v", err)
	}
}

// registrationsInTheFirstHour drives the real backend through the worst schedule
// there is: every slot refilled the moment it frees, and every runner exiting
// having taken no job.
func registrationsInTheFirstHour(t *testing.T, slots int) int {
	t.Helper()
	return registrationsWithExitRecord(t, slots, "zoomies-exit v1 code=1 job=0\n")
}

func registrationsWithExitRecord(t *testing.T, slots int, record string) int {
	t.Helper()
	r := newEgressRig(t, slots)
	r.fake.OnExec("helper.sh exit", fakevmpal.ExecReply{Stdout: record})
	end := r.clock.Now().Add(time.Hour)
	var alive []Handle
	registered, id := 0, 0
	for r.clock.Now().Before(end) {
		for {
			id++
			h, err := r.b.Create(context.Background(), vmpalTestSpec(fmt.Sprintf("run_bound%d", id)))
			if err != nil {
				if !errors.Is(err, errVMPalHeld) && !errors.Is(err, ErrDaemonBusy) {
					t.Fatalf("create: %v", err)
				}
				break
			}
			registered++
			alive = append(alive, h)
			// With no breaker the clock never moves, so stop well past any bound
			// and let the caller report the count instead of hanging.
			if registered > 100 {
				return registered
			}
		}
		if len(alive) == 0 {
			r.clock.advance(time.Minute)
			continue
		}
		h := alive[0]
		alive = alive[1:]
		if finished, err := r.b.readGuestExit(context.Background(), string(h), time.Second); err != nil || !finished {
			t.Fatalf("exit: finished=%v, %v", finished, err)
		}
		if err := r.b.Remove(context.Background(), h); err != nil {
			t.Fatalf("remove: %v", err)
		}
	}
	return registered
}

// The bound is what the breaker is for: the controller's backoff cannot see a
// runner that registered and then died, so nothing else limits them.
func TestARepeatingFailureMakesABoundedNumberOfRegistrations(t *testing.T) {
	for _, tc := range []struct{ slots, want, ceiling int }{
		{1, 9, 9},
		// Three rounds of three plus the one runner still up when the last hold
		// starts. Each round's straggler is counted in the next, so the four a
		// round could reach on its own happen only in the first.
		{2, 10, 12},
	} {
		t.Run(fmt.Sprintf("%d slots", tc.slots), func(t *testing.T) {
			got := registrationsInTheFirstHour(t, tc.slots)
			if got != tc.want {
				t.Errorf("%d registrations in the first hour, want %d", got, tc.want)
			}
			if got > tc.ceiling {
				t.Errorf("%d registrations is over the ceiling of %d", got, tc.ceiling)
			}
		})
	}
}

// One schedule shows the bound is reached. This tries all of them, so it also
// shows nothing goes past it: any order of registering, exiting and waiting.
func TestNoScheduleRegistersMoreThanTheBound(t *testing.T) {
	type node struct {
		file     vmpalHostFile
		at       time.Duration
		inFlight int
	}
	epoch := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
	for slots, want := range map[int]int{1: 9, 2: 10} {
		memo := map[node]int{}
		var worst func(n node) int
		worst = func(n node) int {
			if n.at >= time.Hour {
				return 0
			}
			if v, ok := memo[n]; ok {
				return v
			}
			now := epoch.Add(n.at)
			best := 0
			held := now.Before(n.file.HoldUntil)
			if !held && n.inFlight < slots {
				next := n
				next.inFlight++
				best = max(best, 1+worst(next))
			}
			if n.inFlight > 0 {
				next := n
				next.inFlight--
				next.file = n.file.afterExit(false, false, now)
				best = max(best, worst(next))
			}
			if held {
				next := n
				next.at = n.file.HoldUntil.Sub(epoch)
				best = max(best, worst(next))
			}
			memo[n] = best
			return best
		}
		if got := worst(node{}); got != want {
			t.Errorf("%d slots: the worst schedule makes %d registrations, want %d", slots, got, want)
		}
	}
}

// A helper that breaks leaves no readable record, and if that told the breaker
// nothing, a guest broken the same way each time would register without limit.
func TestARunnerWhoseExitCannotBeReadIsBoundedToo(t *testing.T) {
	if got := registrationsWithExitRecord(t, 1, "not an exit record\n"); got != 9 {
		t.Fatalf("%d registrations in the first hour, want 9", got)
	}
}

func TestRunnersWhoseToolsStopAnsweringTripTheBreaker(t *testing.T) {
	r := newEgressRig(t, 1)
	ctx := context.Background()
	for i := range 3 {
		h, err := r.b.Create(ctx, vmpalTestSpec(fmt.Sprintf("run_silent%d", i)))
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		if !r.b.endUnfollowable(string(h), "the guest stopped answering") {
			t.Fatalf("runner %d was not ended", i)
		}
		if err := r.b.Remove(ctx, h); err != nil {
			t.Fatalf("remove %d: %v", i, err)
		}
	}
	if _, err := r.b.Create(ctx, vmpalTestSpec("run_silent9")); !errors.Is(err, errVMPalHeld) {
		t.Fatalf("the fourth create returned %v, want a hold", err)
	}
}

// Without this the controller keeps minting registrations for up to five
// minutes for a host that is refusing them, and waits as long to use it again.
func TestAHoldAndItsEndEachAskForOneFreshProbe(t *testing.T) {
	r := newEgressRig(t, 1)
	ctx := context.Background()
	r.b.Probe(ctx)
	if r.b.ProbeStale() {
		t.Fatal("a fresh probe was called stale")
	}
	for i := range 3 {
		h, err := r.b.Create(ctx, vmpalTestSpec(fmt.Sprintf("run_stale%d", i)))
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		if !r.b.endUnfollowable(string(h), "the guest stopped answering") {
			t.Fatalf("runner %d was not ended", i)
		}
		if err := r.b.Remove(ctx, h); err != nil {
			t.Fatalf("remove %d: %v", i, err)
		}
	}
	if !r.b.ProbeStale() {
		t.Fatal("a hold starting did not ask for a probe")
	}
	if r.b.ProbeStale() {
		t.Fatal("one hold asked for a second probe")
	}
	r.clock.advance(11 * time.Minute)
	if !r.b.ProbeStale() {
		t.Fatal("a hold ending did not ask for a probe")
	}
	if r.b.ProbeStale() {
		t.Fatal("one hold ending asked for a second probe")
	}
}

func TestACloneThatFailsAsksForAFreshProbe(t *testing.T) {
	r := newEgressRig(t, 1)
	ctx := context.Background()
	r.b.Probe(ctx)
	r.b.ProbeStale()
	r.fake.Fail("clone", fakevmpal.Fault{Stderr: "the template is running", ExitCode: 1, Times: 1})
	if _, err := r.b.Create(ctx, vmpalTestSpec("run_clonefail")); err == nil {
		t.Fatal("the create succeeded with a failing clone")
	}
	if !r.b.ProbeStale() {
		t.Fatal("a failed clone did not ask for a probe")
	}
}
