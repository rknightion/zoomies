//go:build !windows

package backend

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eyupio/zoomies/internal/store"
	"github.com/eyupio/zoomies/test/fakevmpal"
)

// Each row is a way a VM can hold a slot, or look as if it does. Undercounting
// sends a boot into Apple's limit, and overcounting parks a free host.
func TestVMSlotsCountEverythingThatHoldsOne(t *testing.T) {
	owned := func(name string) (string, bool) { return name, strings.HasPrefix(name, "mine-") }
	entry := map[string]vmpalEntry{"mine-1": {VMName: "mine-1"}}
	for _, tc := range []struct {
		name    string
		vms     []vmpalVM
		entries map[string]vmpalEntry
		own     int
		foreign []string
	}{
		{"a create whose VM does not exist yet", nil, entry, 1, nil},
		{"a clone in both the list and the ledger is one", []vmpalVM{{Name: "mine-1", Guest: "macOS", State: "running"}}, entry, 1, nil},
		{"a clone still being deleted", []vmpalVM{{Name: "mine-1", Guest: "macOS", State: "stopping"}}, entry, 1, nil},
		{"a clone whose ledger file was lost", []vmpalVM{{Name: "mine-2", Guest: "macOS", State: "running"}}, nil, 1, nil},
		{"a foreign running VM", []vmpalVM{{Name: "other", Guest: "macOS", State: "running"}}, nil, 0, []string{"other"}},
		{"a foreign VM starting", []vmpalVM{{Name: "other", Guest: "macOS", State: "starting"}}, nil, 0, []string{"other"}},
		{"a foreign VM stopping", []vmpalVM{{Name: "other", Guest: "macOS", State: "stopping"}}, nil, 0, []string{"other"}},
		{"a foreign VM in a state this version has not heard of", []vmpalVM{{Name: "other", Guest: "macOS", State: "migrating"}}, nil, 0, []string{"other"}},
		{"a foreign stopped VM", []vmpalVM{{Name: "other", Guest: "macOS", State: "stopped"}}, nil, 0, nil},
		{"a foreign suspended VM", []vmpalVM{{Name: "other", Guest: "macOS", State: "suspended"}}, nil, 0, nil},
		{"a running Linux VM, which Apple's limit does not cover", []vmpalVM{{Name: "other", Guest: "Linux", State: "running"}}, nil, 0, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := countVMPalSlots(tc.vms, tc.entries, owned)
			if got.Own != tc.own || !slices.Equal(got.Foreign, tc.foreign) {
				t.Errorf("got %+v, want own %d, foreign %v", got, tc.own, tc.foreign)
			}
		})
	}
}

// A configured limit above Apple's would only turn a clean refusal into a boot
// that fails after the clone has been made.
func TestTheSlotLimitIsTheLowerOfMaxVMsAndApplesLimit(t *testing.T) {
	for maxVMs, want := range map[int]int{1: 1, 2: 2, 3: 2, 8: 2} {
		if got := vmpalSlotLimit(maxVMs); got != want {
			t.Errorf("limit for %d is %d, want %d", maxVMs, got, want)
		}
	}
}

// Refused before the clone: a VM made only to be thrown away still costs a boot
// and briefly holds the very slot that was not free.
func TestACreateWithNoFreeSlotIsBusyAndMakesNoClone(t *testing.T) {
	for _, tc := range []struct {
		name    string
		maxVMs  int
		own     bool
		foreign int
	}{
		{"one slot held by a foreign VM", 1, false, 1},
		{"one slot held by this agent", 1, true, 0},
		{"two slots held by foreign VMs", 2, false, 2},
		{"two slots shared with a foreign VM", 2, true, 1},
		{"a limit above Apple's is capped", 5, false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newEgressRig(t, tc.maxVMs)
			if tc.own {
				r.seed(vmpalStageRunning, nil)
			}
			for i := range tc.foreign {
				r.fake.AddVM(fakevmpal.VM{Name: fmt.Sprintf("foreign-%d", i), State: "running", Installed: true})
			}
			_, err := r.b.Create(context.Background(), vmpalTestSpec("run_second"))
			if !errors.Is(err, ErrDaemonBusy) || Fault(err) != store.FaultBackendBusy {
				t.Fatalf("create returned %v", err)
			}
			if errors.Is(err, errVMPalHeld) {
				t.Errorf("a full host was reported as a hold: %v", err)
			}
			if _, ok := r.fake.VM(r.b.vmName("run_second")); ok {
				t.Error("a clone was made with no slot free")
			}
			if r.credentialReachedGuest() {
				t.Error("the credential reached a guest")
			}
		})
	}
}

func TestStoppedAndSuspendedVMsLeaveTheirSlotsFree(t *testing.T) {
	r := newEgressRig(t, 1)
	r.fake.AddVM(fakevmpal.VM{Name: "stopped-one", State: "stopped", Installed: true})
	r.fake.AddVM(fakevmpal.VM{Name: "suspended-one", State: "suspended", Installed: true})
	if _, err := r.b.Create(context.Background(), vmpalTestSpec(vmpalTestRunner)); err != nil {
		t.Fatalf("create: %v", err)
	}
}

// vmpal returns from a delete seconds before the VM has gone, and until it has
// the VM still occupies one of Apple's slots.
func TestAVMStillBeingDeletedHoldsItsSlot(t *testing.T) {
	r := newEgressRig(t, 1)
	name := r.create()
	r.fake.DeleteLingers(1000)
	if err := r.b.Remove(context.Background(), Handle(name)); !errors.Is(err, ErrRemovalInProgress) {
		t.Fatalf("remove returned %v", err)
	}
	_, err := r.b.Create(context.Background(), vmpalTestSpec("run_next"))
	if !errors.Is(err, ErrDaemonBusy) {
		t.Fatalf("a create took the slot of a VM still being deleted: %v", err)
	}
	if _, ok := r.fake.VM(r.b.vmName("run_next")); ok {
		t.Error("a clone was made while the slot was taken")
	}
}

// The window this closes is the list: two creates that both read "one free"
// before either has written its entry would both clone.
func TestConcurrentCreatesCannotShareTheLastSlot(t *testing.T) {
	r := newEgressRig(t, 1)
	r.b.gate = &vmpalSlowAdmitGate{vmpalGate: r.b.gate}
	const racers = 8
	errs := make([]error, racers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range racers {
		wg.Go(func() {
			<-start
			_, errs[i] = r.b.Create(context.Background(), vmpalTestSpec(fmt.Sprintf("run_racer%d", i)))
		})
	}
	close(start)
	wg.Wait()

	won := 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, ErrDaemonBusy):
			t.Errorf("a loser got %v, not the busy error", err)
		}
	}
	if won != 1 {
		t.Errorf("%d creates won the one slot", won)
	}
	clones := 0
	for _, vm := range r.fake.VMs() {
		if strings.HasPrefix(vm.Name, "zoomies-vm-") {
			clones++
		}
	}
	if clones != 1 {
		t.Errorf("%d clones exist", clones)
	}
	if got := r.execs("helper.sh deliver"); len(got) != 1 {
		t.Errorf("%d registrations were delivered", len(got))
	}
}

// vmpalSlowAdmitGate holds the gap between counting the slots and writing the
// entry open, so that a missing lock loses this race every time rather than now
// and then.
type vmpalSlowAdmitGate struct{ vmpalGate }

func (g *vmpalSlowAdmitGate) Admit(ctx context.Context, slots vmpalSlotUse) error {
	time.Sleep(50 * time.Millisecond)
	return g.vmpalGate.Admit(ctx, slots)
}

// The controller stops scheduling to a host Probe calls unavailable, so its own
// jobs filling it must not count, and only other people's VMs may.
func TestProbeIsUnavailableOnlyWhenForeignVMsHoldEverySlot(t *testing.T) {
	for _, tc := range []struct {
		name         string
		maxVMs       int
		own, foreign int
		available    bool
	}{
		{"its own job in the only slot", 1, 1, 0, true},
		{"its own jobs in both slots", 2, 2, 0, true},
		{"one of each", 2, 1, 1, true},
		{"one foreign VM of two slots", 2, 0, 1, true},
		{"foreign VMs in both slots", 2, 0, 2, false},
		{"a foreign VM in the only slot", 1, 0, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newEgressRig(t, tc.maxVMs)
			for i := range tc.own {
				r.fake.AddVM(fakevmpal.VM{Name: r.b.vmName(fmt.Sprintf("run_own%d", i)), State: "running", Installed: true})
			}
			for i := range tc.foreign {
				r.fake.AddVM(fakevmpal.VM{Name: fmt.Sprintf("foreign-%d", i), State: "running", Installed: true})
			}
			info := r.b.Probe(context.Background())
			if info.Available != tc.available {
				t.Fatalf("available=%v: %s", info.Available, info.Detail)
			}
			if !tc.available && !strings.Contains(info.Detail, VMPalSlotsOccupiedDetail) {
				t.Fatalf("a join would not recognise this as occupied slots: %s", info.Detail)
			}
			if !tc.available && !strings.Contains(info.Detail, "foreign-0") {
				t.Errorf("the detail does not name the VMs in the way: %s", info.Detail)
			}
		})
	}
}
