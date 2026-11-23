//go:build !windows

package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/eyupio/zoomies/test/fakevmpal"
)

// diskFull makes every ledger write fail the way a full disk does.
func (r *vmpalRig) diskFull(full bool) {
	r.t.Helper()
	r.b.mu.Lock()
	defer r.b.mu.Unlock()
	r.b.ledger.writeFile = nil
	if full {
		r.b.ledger.writeFile = func(string, []byte, os.FileMode) error { return syscall.ENOSPC }
	}
}

func (r *vmpalRig) assertExits(want ...[2]bool) {
	r.t.Helper()
	got := r.gate.exitCalls()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		r.t.Errorf("the breaker was told %v, want %v", got, want)
	}
}

// Losing a record costs one repeated delete. Keeping a clone because its record
// could not be written would leave an untrusted guest running on a full disk,
// which is exactly when nothing else is going to clear it.
func TestAFullDiskDoesNotStopACloneBeingDeleted(t *testing.T) {
	r := newVMPalRig(t)
	name := r.seed(vmpalStageRunning, func(e *vmpalEntry) { e.StartedAt = r.clock.Now() })
	r.diskFull(true)
	if err := r.b.Remove(context.Background(), Handle(name)); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, there := r.fake.VM(name); there {
		t.Error("the clone is still on the Mac")
	}
}

func TestAFullDiskDoesNotStopTheBreachPurge(t *testing.T) {
	r := newVMPalRig(t)
	name := r.seed(vmpalStageRunning, func(e *vmpalEntry) { e.StartedAt = r.clock.Now() })
	r.diskFull(true)
	r.b.purgeClones(context.Background())
	if _, there := r.fake.VM(name); there {
		t.Error("a breach left a clone running because its record could not be written")
	}
}

// GitHub's completed webhook usually beats the watcher's next tick. If only the
// watcher read the record, real jobs would rarely clear the count, and "three in
// a row" would become "three in total" on a perfectly healthy host.
func TestARealJobEndedByRemoveClearsTheBreakerCount(t *testing.T) {
	r := newEgressRig(t, 1)
	ctx := context.Background()
	run := func(id, record string, watcherSawIt bool) {
		t.Helper()
		r.fake.OnExec("helper.sh exit", fakevmpal.ExecReply{Stdout: record})
		h, err := r.b.Create(ctx, vmpalTestSpec(id))
		if err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
		if watcherSawIt {
			if _, err := r.b.readGuestExit(ctx, string(h), time.Second); err != nil {
				t.Fatal(err)
			}
		}
		if err := r.b.Remove(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	const noJob, realJob = "zoomies-exit v1 code=1 job=0\n", "zoomies-exit v1 code=0 job=1\n"
	run("run_a1", noJob, true)
	run("run_a2", noJob, true)
	run("run_b1", realJob, false)
	run("run_c1", noJob, true)
	run("run_c2", noJob, true)
	if err := r.b.gate.Held(); err != nil {
		t.Errorf("a real job did not clear the count: %v", err)
	}
}

func TestARemovalRetriedWhileVMPalDeletesCountsTheRunnerOnce(t *testing.T) {
	r := newVMPalRig(t)
	r.fake.OnExec("helper.sh exit", fakevmpal.ExecReply{Stdout: "zoomies-exit v1 code=0 job=1\n"})
	name := r.create()
	r.fake.DeleteLingers(5)
	r.b.removeWait = 0
	if err := r.b.Remove(context.Background(), Handle(name)); !errors.Is(err, ErrRemovalInProgress) {
		t.Fatalf("remove returned %v", err)
	}
	r.b.removeWait = 200 * time.Millisecond
	if err := r.b.Remove(context.Background(), Handle(name)); err != nil {
		t.Fatal(err)
	}
	r.assertExits([2]bool{true, false})
}

// A guest that cannot answer says nothing about whether a job ran, and it is
// the guest most in need of deleting.
func TestAFinalReadThatGetsNoAnswerNeitherDelaysNorCounts(t *testing.T) {
	for label, reply := range map[string]fakevmpal.ExecReply{
		"hangs":         {Hang: true},
		"fails":         {Stderr: "no Tools", ExitCode: 125},
		"has no record": {Stdout: "zoomies-exit v1 running\n"},
	} {
		t.Run(label, func(t *testing.T) {
			r := newVMPalRig(t)
			name := r.create()
			r.fake.OnExec("helper.sh exit", reply)
			r.b.finalRead = 100 * time.Millisecond
			started := time.Now()
			if err := r.b.Remove(context.Background(), Handle(name)); err != nil {
				t.Fatal(err)
			}
			if took := time.Since(started); took > 5*time.Second {
				t.Errorf("the removal took %s", took)
			}
			r.assertNoCloneLeft()
			r.assertExits()
		})
	}
}

// These clones are not resumed, so they must not go on running a job for as
// long as it takes the controller to hear about them.
func TestACloneEndedByTheWatcherIsForcedOffAndKeepsItsResult(t *testing.T) {
	for label, end := range map[string]func(r *vmpalRig, name string) bool{
		"sleep": func(r *vmpalRig, name string) bool {
			st := vmpalWatchState{lastTick: r.clock.Now()}
			r.clock.advance(vmpalWakeGap + time.Second)
			return r.b.watchOnce(context.Background(), name, &st)
		},
		"lifetime": func(r *vmpalRig, name string) bool {
			r.clock.advance(vmpalLifetime)
			return r.b.watchOnce(context.Background(), name, &vmpalWatchState{})
		},
		"lost Tools": func(r *vmpalRig, name string) bool {
			r.fake.OnExec("helper.sh exit", fakevmpal.ExecReply{ExitCode: 125})
			st := vmpalWatchState{failingSince: r.clock.Now().Add(-vmpalReadGiveUp)}
			return r.b.watchOnce(context.Background(), name, &st)
		},
	} {
		t.Run(label, func(t *testing.T) {
			r := newVMPalRig(t)
			name := r.seed(vmpalStageRunning, func(e *vmpalEntry) { e.StartedAt = r.clock.Now() })
			if !end(r, name) {
				t.Fatal("the watch did not end")
			}
			vm, there := r.fake.VM(name)
			if !there || vm.State != "stopped" {
				t.Fatalf("the clone is %q (present %v), want it forced off and kept for the report", vm.State, there)
			}
			if e, ok, _ := r.b.readEntry(name); !ok || e.Exit == nil || e.Exit.Phase != PhaseFailed {
				t.Errorf("the result to report was not kept: %+v", e)
			}
		})
	}
}

// A full disk must not turn "this clone slept" into "carry on": the gap is only
// seen once, so it has to survive the write that failed.
func TestASleepIsStillActedOnWhenItsRecordCannotBeWritten(t *testing.T) {
	r := newVMPalRig(t)
	name := r.seed(vmpalStageRunning, func(e *vmpalEntry) { e.StartedAt = r.clock.Now() })
	st := vmpalWatchState{lastTick: r.clock.Now()}
	r.clock.advance(vmpalWakeGap + time.Second)
	r.diskFull(true)
	if r.b.watchOnce(context.Background(), name, &st) {
		t.Fatal("the watch ended with nothing recorded")
	}
	if vm, _ := r.fake.VM(name); vm.State != "stopped" {
		t.Fatalf("the clone is %q, want it forced off", vm.State)
	}
	r.workload(name)
	r.diskFull(false)
	r.workload(name)
	r.assertExits()
	r.clock.advance(time.Second)
	if !r.b.watchOnce(context.Background(), name, &st) {
		t.Fatal("the retry did not finish the watch")
	}
	if got := r.workload(name).Status; !strings.Contains(got.Message, "asleep") {
		t.Errorf("listed as %+v", got)
	}
	r.assertExits()
}

// A JIT configuration is single-use, and the ledger entry that guards it goes
// with the clone. A create redelivered after that must not send it again.
func TestASpentRunnerIsRefusedAfterItsCloneHasGone(t *testing.T) {
	r := newVMPalRig(t)
	ctx := context.Background()
	name := r.create()
	if err := r.b.Remove(ctx, Handle(name)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.b.Create(ctx, vmpalTestSpec(vmpalTestRunner)); !errors.Is(err, ErrContainerConflict) {
		t.Fatalf("a redelivered create returned %v, want a conflict", err)
	}
	if got := len(r.execs("helper.sh deliver")); got != 1 {
		t.Fatalf("the registration was delivered %d times", got)
	}
	r.clock.advance(24*time.Hour + time.Minute)
	if _, err := r.b.Create(ctx, vmpalTestSpec(vmpalTestRunner)); err != nil {
		t.Fatalf("a marker older than a day was not pruned: %v", err)
	}
	if files, _ := os.ReadDir(r.b.spentDir); len(files) != 1 {
		t.Errorf("%d markers on disk, want the new one alone", len(files))
	}
}

func TestADeliveryThatFailedStillSpendsTheRegistration(t *testing.T) {
	r := newVMPalRig(t)
	ctx := context.Background()
	r.fake.OnExec("helper.sh deliver", fakevmpal.ExecReply{ExitCode: 1})
	if _, err := r.b.Create(ctx, vmpalTestSpec(vmpalTestRunner)); err == nil {
		t.Fatal("the create succeeded")
	}
	r.fake.OnExec("helper.sh deliver", fakevmpal.ExecReply{Stdout: "zoomies-deliver v1 ok\n"})
	if _, err := r.b.Create(ctx, vmpalTestSpec(vmpalTestRunner)); !errors.Is(err, ErrContainerConflict) {
		t.Fatalf("the retry returned %v, want a conflict", err)
	}
	if got := len(r.execs("helper.sh deliver")); got != 1 {
		t.Fatalf("the registration was sent %d times", got)
	}
}

func TestARegistrationIsNotSentIfItCannotBeMarkedSpent(t *testing.T) {
	r := newVMPalRig(t)
	r.gate.onVerify = func() {
		// A file where the directory should be fails for root as well.
		if err := os.RemoveAll(r.b.spentDir); err != nil {
			t.Error(err)
		}
		if err := os.WriteFile(r.b.spentDir, nil, 0o600); err != nil {
			t.Error(err)
		}
	}
	if _, err := r.b.Create(context.Background(), vmpalTestSpec(vmpalTestRunner)); err == nil {
		t.Fatal("the create succeeded with no durable marker")
	}
	if r.credentialReachedGuest() {
		t.Error("the registration was sent with nothing to stop it being sent again")
	}
}

// A field that is absent has not been shown to be safe, and a plain bool or a
// nil pointer would read the same as the safe value.
func TestTheSessionCheckFailsOnAMissingField(t *testing.T) {
	document := func() map[string]any {
		settings := map[string]json.RawMessage{}
		for _, table := range []map[string]string{vmpalRequiredSettings, vmpalBootSettings} {
			for key, value := range table {
				settings[key] = json.RawMessage(value)
			}
		}
		return map[string]any{
			"id": "vm-1", "name": "clone", "guest": "macOS", "state": "running",
			"internetAddress": "192.0.2.10", "pendingSettings": []any{}, "settings": settings,
			"sessionHardware": map[string]any{"networkMode": "shared", "localNetworkCard": false, "bridgedInterface": nil},
		}
	}
	r := newVMPalRig(t)
	problems := func(doc map[string]any) []string {
		t.Helper()
		data, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		var info vmpalInfo
		if err := json.Unmarshal(data, &info); err != nil {
			t.Fatal(err)
		}
		return r.b.sessionProblems(info)
	}
	if got := problems(document()); len(got) != 0 {
		t.Fatalf("a complete session was refused: %v", got)
	}
	hardware := func(doc map[string]any) map[string]any { return doc["sessionHardware"].(map[string]any) }
	for label, change := range map[string]func(map[string]any){
		"no localNetworkCard":  func(d map[string]any) { delete(hardware(d), "localNetworkCard") },
		"no bridgedInterface":  func(d map[string]any) { delete(hardware(d), "bridgedInterface") },
		"no pendingSettings":   func(d map[string]any) { delete(d, "pendingSettings") },
		"null pendingSettings": func(d map[string]any) { d["pendingSettings"] = nil },
		"bridged":              func(d map[string]any) { hardware(d)["bridgedInterface"] = "en0" },
		"local network card":   func(d map[string]any) { hardware(d)["localNetworkCard"] = true },
		"settings waiting":     func(d map[string]any) { d["pendingSettings"] = []any{map[string]any{"key": "camera"}} },
	} {
		t.Run(label, func(t *testing.T) {
			doc := document()
			change(doc)
			if got := problems(doc); len(got) == 0 {
				t.Error("the check passed")
			}
		})
	}
}

// jumpWhileArming moves the clock as the clone is recorded as arming, which is
// after the egress check has passed and before anything is delivered.
func (r *vmpalRig) jumpWhileArming(d time.Duration) {
	r.b.ledger.writeFile = func(path string, data []byte, mode os.FileMode) error {
		if bytes.Contains(data, []byte(fmt.Sprintf("%q: %q", "stage", vmpalStageArming))) {
			r.clock.advance(d)
		}
		return writeFileAtomic(path, data, mode)
	}
}

// The egress result describes the network before the sleep. The watcher starts
// only after provisioning, so nothing else would notice.
func TestASleepBetweenTheEgressCheckAndDeliveryFailsTheCreate(t *testing.T) {
	r := newVMPalRig(t)
	r.jumpWhileArming(vmpalWakeGap + time.Second)
	_, err := r.b.Create(context.Background(), vmpalTestSpec(vmpalTestRunner))
	if err == nil || !strings.Contains(err.Error(), "asleep") {
		t.Fatalf("create returned %v, want it to name the sleep", err)
	}
	if r.credentialReachedGuest() {
		t.Error("the registration went to a clone whose network check is out of date")
	}
	r.assertNoCloneLeft()
}

func TestAnArmThatTakesUpToTheGapStillDelivers(t *testing.T) {
	r := newVMPalRig(t)
	r.jumpWhileArming(vmpalWakeGap)
	if _, err := r.b.Create(context.Background(), vmpalTestSpec(vmpalTestRunner)); err != nil {
		t.Fatalf("create: %v", err)
	}
}

// The controller may record a lost job from a failed report, and this runner
// is being deleted because the controller asked for that.
func TestAReconcileDuringARemovalSeesNoFailure(t *testing.T) {
	r := newVMPalRig(t)
	name := r.create()
	r.fake.DeleteLingers(5)
	r.b.removeWait = 0
	if err := r.b.Remove(context.Background(), Handle(name)); !errors.Is(err, ErrRemovalInProgress) {
		t.Fatalf("remove returned %v", err)
	}
	if st := r.workload(name).Status; st.Phase != PhaseExited || st.ExitCode != 0 {
		t.Errorf("List reported %s/%d during the removal", st.Phase, st.ExitCode)
	}
	st, err := r.b.Status(context.Background(), Handle(name))
	if err != nil {
		t.Fatal(err)
	}
	if st.Phase != PhaseExited || st.ExitCode != 0 {
		t.Errorf("Status reported %s/%d during the removal", st.Phase, st.ExitCode)
	}
}

// List reads the ledger before vmpal list. A removal that finishes between the
// two leaves a record whose VM is gone, which must not read as a lost clone.
func TestARemovalFinishedDuringAListIsNotReportedAsLost(t *testing.T) {
	r := newVMPalRig(t)
	ctx := context.Background()
	name := r.create()
	entries, err := r.b.ledger.all()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.b.Remove(ctx, Handle(name)); err != nil {
		t.Fatal(err)
	}
	vms, err := r.b.cli.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r.b.dropRemoved(entries, vms)
	if _, still := entries[name]; still {
		t.Error("a clone this agent just removed would be reported as lost")
	}
}

// A template that dies after registering would otherwise never be bounded: its
// runners power off, are reported failed and never reach the breaker.
func TestAGuestThatPowersItselfOffCountsOnce(t *testing.T) {
	r := newVMPalRig(t)
	ctx := context.Background()
	name := r.create()
	if err := r.b.cli.Stop(ctx, name, time.Second); err != nil {
		t.Fatal(err)
	}
	if st := r.workload(name).Status; st.Phase != PhaseFailed || !strings.Contains(st.Message, "stopped") {
		t.Errorf("listed as %+v", st)
	}
	r.workload(name)
	if _, err := r.b.Status(ctx, Handle(name)); err != nil {
		t.Fatal(err)
	}
	if err := r.b.Remove(ctx, Handle(name)); err != nil {
		t.Fatal(err)
	}
	r.assertExits([2]bool{false, false})
}

func TestAGuestPoweredOffAfterAStopRequestIsNotCounted(t *testing.T) {
	r := newVMPalRig(t)
	ctx := context.Background()
	name := r.create()
	if err := r.b.markStopRequested(name); err != nil {
		t.Fatal(err)
	}
	if err := r.b.cli.Stop(ctx, name, time.Second); err != nil {
		t.Fatal(err)
	}
	r.workload(name)
	if _, err := r.b.Status(ctx, Handle(name)); err != nil {
		t.Fatal(err)
	}
	r.assertExits()
}

// An answer with no list in it says nothing about what is on the Mac. Read as
// an empty list, it would make every clone look gone and get live jobs reaped.
func TestAListWithNoVMsKeyIsAnError(t *testing.T) {
	for label, tc := range map[string]struct {
		body string
		ok   bool
	}{
		"no key":     {"echo '{}'", false},
		"null":       {"echo '{\"vms\":null}'", false},
		"empty list": {"echo '{\"vms\":[]}'", true},
	} {
		t.Run(label, func(t *testing.T) {
			c, _ := scriptedVMPal(t, tc.body)
			_, err := c.List(context.Background())
			if (err == nil) != tc.ok {
				t.Fatalf("list returned %v", err)
			}
		})
	}
}
