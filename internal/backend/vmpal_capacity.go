package backend

import (
	"fmt"
	"slices"
)

// vmpalSlotUse is who holds this Mac's VM slots at one moment.
type vmpalSlotUse struct {
	// Own counts this agent's clones: every ledger entry, which covers a create
	// in flight and a VM still being deleted, and any VM with one of this
	// agent's names whose entry was lost.
	Own int
	// Foreign names the macOS VMs this agent does not manage that hold a slot.
	Foreign []string
}

func (u vmpalSlotUse) total() int { return u.Own + len(u.Foreign) }

// vmpalSlotLimit is how many VMs this agent may count up to. Apple's limit
// applies whatever the configuration says.
func vmpalSlotLimit(maxVMs int) int { return min(maxVMs, vmpalMacOSLimit) }

// vmpalForeignHoldsSlot reports whether a VM this agent does not manage takes
// one of Apple's slots. It names the two states that do not, rather than the one
// that does, so a VM starting, stopping or in a state a later VMPal adds is
// counted: overcounting delays a job, and undercounting fails a boot.
func vmpalForeignHoldsSlot(vm vmpalVM) bool {
	return vm.Guest == "macOS" && vm.State != "stopped" && vm.State != "suspended"
}

// countVMPalSlots works out who holds the slots from vmpal's list and the
// ledger. A clone in both is counted once.
func countVMPalSlots(vms []vmpalVM, entries map[string]vmpalEntry, owned func(string) (string, bool)) vmpalSlotUse {
	use := vmpalSlotUse{Own: len(entries)}
	for _, vm := range vms {
		if _, ours := owned(vm.Name); ours {
			if _, known := entries[vm.Name]; !known {
				use.Own++
			}
			continue
		}
		if vmpalForeignHoldsSlot(vm) {
			use.Foreign = append(use.Foreign, vm.Name)
		}
	}
	slices.Sort(use.Foreign)
	return use
}

// admit returns the busy error when no slot is free. Busy is the right answer
// even when other people's VMs are the cause: it is a reason to wait, and the
// agent retries it with a backoff.
func (u vmpalSlotUse) admit(limit int) error {
	if u.total() < limit {
		return nil
	}
	return busyErr(fmt.Errorf("this Mac has no free VM slot: %d of %d are in use, %d by this agent and %d by VMs Zoomies does not manage", u.total(), limit, u.Own, len(u.Foreign)))
}
