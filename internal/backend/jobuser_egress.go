package backend

// The egress check before every job. It is the VM backend's, with the slot user
// standing where the guest does: each must-allow target must connect as the
// slot user, and each must-block target must first be reachable from the agent
// itself and then time out as the slot user. A refusal or a connection is a
// breach, because it means packets got there.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// checkJobUserTargets holds the two lists to the rules the VM backend's are held
// to, and names the job-user settings in what it says.
func checkJobUserTargets(allow, block []string) error {
	return checkVMPalEgressTargets("agent.job_users", allow, block)
}

// newJobUserGate is the VM backend's gate with the guest replaced by a question
// to the slot, and the host policy check left out: in this mode the agent writes
// and compares the firewall itself.
func newJobUserGate(u *jobUsers, dial func(ctx context.Context, address string) error) *vmpalPolicyGate {
	return &vmpalPolicyGate{
		policy: vmpalPolicy{mustAllow: u.mustAllow, mustBlock: u.mustBlock},
		limit:  u.capacity,
		state:  u.state,
		dial:   dial,
		asker:  u.runEgressProbe,
		the:    "the job user",
		a:      "a job user",
		log:    u.log,
	}
}

// runEgressProbe asks the slot's own account to try the targets. It is
// a short-lived child of this binary started with the slot's credentials. The
// slot is reserved and idle, and the probe exits before the runner starts.
func (u *jobUsers) runEgressProbe(ctx context.Context, name string, targets []string) ([]string, error) {
	s := u.slotNamed(name)
	if s == nil {
		return nil, fmt.Errorf("%q is not a job user", name)
	}
	if u.exe == "" {
		return nil, errors.New("this agent does not know its own path, so it cannot run the egress probe as a job user")
	}
	ctx, cancel := context.WithTimeout(ctx, vmpalEgressAttempt*time.Duration(len(targets)+1))
	defer cancel()
	argv := append([]string{u.exe, "agent", "egress-probe", "--timeout", vmpalDuration(vmpalEgressAttempt)}, targets...)
	res, err := u.sys.Run(ctx, jobUserCommand{Argv: argv, AsUser: true, UID: s.uid, GID: jobUserGID})
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("the egress probe exited %d: %s", res.ExitCode, jobUserFirstLine(res.Output))
	}
	return parseVMPalEgress(res.Output, len(targets))
}

// jobUserEgressError is a check that did not pass.
type jobUserEgressError struct{ failure *vmpalEgressFailure }

func (e *jobUserEgressError) Error() string {
	if e.failure.Breach {
		return "backend: the job users' network policy is not in force: " + e.failure.Reason + "; every running job on this Mac is being stopped and new runners are held, so check the firewall anchor " + jobUserAnchor
	}
	return "backend: the egress check could not show that the job users' network policy is in force: " + e.failure.Reason + "; new runners are held"
}

func (e *jobUserEgressError) Unwrap() error { return e.failure }

// checkEgress runs the check as the slot and starts the hold if it does not pass.
// A create cancelled part way through has learned nothing about the network, so
// that alone is not a reason to hold the host.
func (u *jobUsers) checkEgress(ctx context.Context, s *jobUserSlot) error {
	failure := u.gate.check(ctx, s.name)
	if failure == nil {
		return nil
	}
	if !failure.Breach && errors.Is(ctx.Err(), context.Canceled) {
		return fmt.Errorf("backend: the egress check as %s was cancelled: %w", s.name, ctx.Err())
	}
	u.state.startHold(vmpalEgressHold, failure.Reason)
	u.reprobe.Store(true)
	u.log.Error("the egress check failed", "slot", s.name, "breach", failure.Breach, "reason", failure.Reason)
	if failure.Breach {
		u.stopRunning(ctx)
	}
	return &jobUserEgressError{failure: failure}
}

// stopRunning kills every process of every job user, so that each runner exits
// through the normal path and its slot is cleaned. It is the counterpart of the
// VM backend deleting its clones after a breach: a job that was admitted under a
// policy since shown not to hold is not trusted to finish.
func (u *jobUsers) stopRunning(ctx context.Context) {
	ctx = context.WithoutCancel(ctx)
	for _, s := range u.offered() {
		if err := u.stopProcesses(ctx, s); err != nil {
			u.log.Warn("could not stop a job user's processes after the firewall failed", "slot", s.name, "error", err)
		}
	}
}

// jobUserFirstLine is the first line of what a command printed, for a message
// that has room for one.
func jobUserFirstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return line
}
