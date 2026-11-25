package backend

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	vmpalEgressTargetsVar = "ZOOMIES_EGRESS_TARGETS"
	// vmpalEgressAttempt is the limit the helper puts on one connection.
	vmpalEgressAttempt = 5 * time.Second
	// vmpalMacDialLimit is how long the Mac gets to reach a must-block target.
	vmpalMacDialLimit = 3 * time.Second
	vmpalPolicyLimit  = 20 * time.Second
	vmpalPolicyGrace  = 2 * time.Second
	// vmpalEgressMaxTargets keeps a passing check inside the verify budget,
	// since every must-block target costs a full attempt when it is working.
	vmpalEgressMaxTargets = 8
)

// What the helper can say about one connection.
const (
	vmpalEgressConnected   = "connected"
	vmpalEgressRefused     = "refused"
	vmpalEgressTimeout     = "timeout"
	vmpalEgressUnreachable = "unreachable"
	vmpalEgressError       = "error"
)

var (
	vmpalEgressTargetLine = regexp.MustCompile(`^zoomies-egress v1 target (0|[1-9][0-9]{0,2}) (connected|refused|timeout|unreachable|error)$`)
	vmpalEgressEndLine    = regexp.MustCompile(`^zoomies-egress v1 end (0|[1-9][0-9]{0,2})$`)
	vmpalEgressHostName   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)
)

// parseVMPalEgress reads the helper's answer about count targets. Every index
// must appear once, in order, and the end line must agree: an answer cut short
// could otherwise leave out the one target that connected.
func parseVMPalEgress(stdout string, count int) ([]string, error) {
	lines := strings.Split(vmpalAnswer(stdout), "\n")
	if len(lines) != count+1 {
		return nil, errVMPalGuestAnswer
	}
	results := make([]string, count)
	for i := range count {
		m := vmpalEgressTargetLine.FindStringSubmatch(lines[i])
		if m == nil || m[1] != strconv.Itoa(i) {
			return nil, errVMPalGuestAnswer
		}
		results[i] = m[2]
	}
	m := vmpalEgressEndLine.FindStringSubmatch(lines[count])
	if m == nil || m[1] != strconv.Itoa(count) {
		return nil, errVMPalGuestAnswer
	}
	return results, nil
}

// vmpalEgressFailure is a check that did not pass. Breach means the guest
// reached something the policy must stop. Otherwise the check could not tell,
// which fails it just the same but says nothing against the clones already up.
type vmpalEgressFailure struct {
	Breach bool
	Reason string
}

func (e *vmpalEgressFailure) Error() string {
	if e.Breach {
		return "backend: the Mac's network policy is not in force: " + e.Reason + "; every clone on this Mac is being deleted and new runners are held, so fix the host firewall"
	}
	return "backend: the egress check could not show that the Mac's network policy is in force: " + e.Reason + "; this clone is being deleted and new runners are held"
}

// vmpalPolicy is a complete egress policy. There is no default for any part of
// it: a check with nothing to test would pass.
type vmpalPolicy struct {
	mustAllow []string
	mustBlock []string
	check     string
}

func newVMPalPolicy(mustAllow, mustBlock []string, check string) (vmpalPolicy, error) {
	check = strings.TrimSpace(check)
	switch {
	case check == "":
		return vmpalPolicy{}, errors.New("agent.vmpal.policy_check is not set")
	case !filepath.IsAbs(check):
		return vmpalPolicy{}, errors.New("agent.vmpal.policy_check must be an absolute path")
	}
	if err := checkVMPalEgressTargets("agent.vmpal", mustAllow, mustBlock); err != nil {
		return vmpalPolicy{}, err
	}
	return vmpalPolicy{mustAllow: slices.Clone(mustAllow), mustBlock: slices.Clone(mustBlock), check: check}, nil
}

// checkVMPalEgressTargets holds the two target lists to the rules both modes
// share. prefix names the settings in what it says: agent.vmpal for VM isolation
// and agent.job_users for job users.
func checkVMPalEgressTargets(prefix string, mustAllow, mustBlock []string) error {
	switch {
	case len(mustAllow) == 0:
		return errors.New(prefix + ".egress_must_allow is empty")
	case len(mustBlock) == 0:
		return errors.New(prefix + ".egress_must_block is empty")
	case len(mustAllow)+len(mustBlock) > vmpalEgressMaxTargets:
		return fmt.Errorf("%s.egress_must_allow and egress_must_block name more than %d targets, which will not fit the check's time limit", prefix, vmpalEgressMaxTargets)
	}
	for _, target := range mustAllow {
		if err := checkVMPalAllowTarget(target); err != nil {
			return fmt.Errorf("%s.egress_must_allow: %w", prefix, err)
		}
	}
	for _, target := range mustBlock {
		if err := checkVMPalBlockTarget(target); err != nil {
			return fmt.Errorf("%s.egress_must_block: %w", prefix, err)
		}
		if slices.Contains(mustAllow, target) {
			return fmt.Errorf("%s.egress_must_block: %s is also in egress_must_allow, so no result could pass", prefix, target)
		}
	}
	return nil
}

func splitVMPalTarget(target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", fmt.Errorf("%q is not host:port", target)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("%q does not have a port from 1 to 65535", target)
	}
	return host, nil
}

// checkVMPalAllowTarget accepts a name or an IPv4 address. An IPv6 literal is
// refused because IPv6 is not judged from the guest at all: a guest's view of it
// has given a false pass, so the host policy check is what attests it.
func checkVMPalAllowTarget(target string) error {
	host, err := splitVMPalTarget(target)
	if err != nil {
		return err
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if !addr.Is4() {
			return fmt.Errorf("%q is IPv6, which the host policy check attests rather than the guest", target)
		}
		return nil
	}
	if !vmpalEgressHostName.MatchString(host) {
		return fmt.Errorf("%q does not name a host", target)
	}
	return nil
}

// checkVMPalBlockTarget accepts only an IPv4 literal. A name could resolve
// differently on the Mac and in the guest, and then the two would not be testing
// the same destination. Loopback is the guest itself, which always answers.
func checkVMPalBlockTarget(target string) error {
	host, err := splitVMPalTarget(target)
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(host)
	switch {
	case err != nil:
		return fmt.Errorf("%q must be an IP address, because a name could resolve differently in the guest", target)
	case !addr.Is4():
		return fmt.Errorf("%q is IPv6, which the host policy check attests rather than the guest", target)
	case addr.IsLoopback() || addr.IsUnspecified():
		return fmt.Errorf("%q is the guest itself, so it would always answer", target)
	}
	return nil
}

// vmpalPolicyGate is the real gate: holds, slots and the egress check.
type vmpalPolicyGate struct {
	policy      vmpalPolicy
	limit       int
	state       *vmpalHostState
	dial        func(ctx context.Context, address string) error
	guest       func(ctx context.Context, name string, limit time.Duration, env map[string]string, sub string, args ...string) (vmpalOutput, error)
	policyLimit time.Duration
	policyGrace time.Duration
	log         *slog.Logger

	// asker, when set, answers the check's questions in place of guest: job
	// users ask a slot's own account, and there is no VM to run a helper in. the
	// and a are what the check calls the thing it asks, in its reasons.
	asker func(ctx context.Context, name string, targets []string) ([]string, error)
	the   string
	a     string
	// unreachableBlocks reads "unreachable" from a must-block target the Mac itself
	// reached as a block, like a timeout. It is for job users: the probe runs on
	// the same host over the same routes as the Mac's own dial, so the firewall is
	// the only difference, and pf can refuse a packet it drops from a local socket
	// with an error from the kernel as well as by dropping it silently. A VM guest
	// has routes of its own, so there it is still a doubt.
	unreachableBlocks bool
}

// subject is what the check calls whatever it is testing from, for the reasons
// an operator reads.
func (g *vmpalPolicyGate) subject() (the, a string) {
	if g.the == "" {
		return "the guest", "a guest"
	}
	return g.the, g.a
}

// policyGate builds the gate for these options. An incomplete policy gets the
// refusing gate, whose reason Probe shows, rather than a check that tests less
// than the operator meant it to.
func (b *VMPalBackend) policyGate(opts VMPalOptions, statePath string) vmpalGate {
	policy, err := newVMPalPolicy(opts.EgressMustAllow, opts.EgressMustBlock, opts.PolicyCheck)
	if err != nil {
		return vmpalRefusingGate{reason: err.Error()}
	}
	dial := opts.EgressDial
	if dial == nil {
		dial = vmpalDialTCP
	}
	return &vmpalPolicyGate{
		policy:      policy,
		limit:       vmpalSlotLimit(b.maxVMs),
		state:       openVMPalHostState(statePath, b.now, b.log),
		dial:        dial,
		guest:       b.helper,
		policyLimit: vmpalPolicyLimit,
		policyGrace: vmpalPolicyGrace,
		log:         b.log,
	}
}

func vmpalDialTCP(ctx context.Context, address string) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	return conn.Close()
}

func (g *vmpalPolicyGate) Held() error { return g.state.held() }

func (g *vmpalPolicyGate) Admit(_ context.Context, slots vmpalSlotUse) error {
	if err := g.state.held(); err != nil {
		return err
	}
	return slots.admit(g.limit)
}

func (g *vmpalPolicyGate) RunnerExited(tookJob, stopRequested bool) {
	g.state.runnerExited(tookJob, stopRequested)
}

// Verify runs the egress check and starts a hold if it does not pass. A create
// cancelled part way through has learned nothing about the network, so that
// alone is not a reason to hold the host.
func (g *vmpalPolicyGate) Verify(ctx context.Context, clone vmpalInfo) error {
	failure := g.check(ctx, clone.Name)
	if failure == nil {
		return nil
	}
	if !failure.Breach && errors.Is(ctx.Err(), context.Canceled) {
		return fmt.Errorf("backend: the egress check on %s was cancelled: %w", clone.Name, ctx.Err())
	}
	g.state.startHold(vmpalEgressHold, failure.Reason)
	g.log.Error("the egress check failed", "vm", clone.Name, "breach", failure.Breach, "reason", failure.Reason)
	return failure
}

// check runs the three conditions in order. It carries on past a target it
// cannot judge, because a later must-block target that answers is a breach, and
// that changes what happens to every other clone on the host.
func (g *vmpalPolicyGate) check(ctx context.Context, name string) *vmpalEgressFailure {
	var doubts []string
	the, a := g.subject()

	answers, err := g.ask(ctx, name, g.policy.mustAllow)
	if err != nil {
		return &vmpalEgressFailure{Reason: fmt.Sprintf("%s could not run the check: %v", the, err)}
	}
	for i, answer := range answers {
		if answer != vmpalEgressConnected {
			doubts = append(doubts, fmt.Sprintf("%s could not reach %s, which it must (%s)", the, g.policy.mustAllow[i], answer))
		}
	}

	for _, target := range g.policy.mustBlock {
		// The Mac goes first and immediately before the guest. A target that is
		// down looks exactly like a firewall to the guest, so without this a
		// dead address would pass the check for ever.
		dialCtx, cancel := context.WithTimeout(ctx, vmpalMacDialLimit)
		macErr := g.dial(dialCtx, target)
		cancel()

		answers, err := g.ask(ctx, name, []string{target})
		if err != nil {
			return &vmpalEgressFailure{Reason: fmt.Sprintf("%s could not run the check: %v", the, err)}
		}
		// Judged before the Mac's result: a connection or a refusal means the
		// guest's packets got there, whether or not the Mac's did.
		switch answer := answers[0]; {
		case answer == vmpalEgressConnected || answer == vmpalEgressRefused:
			return &vmpalEgressFailure{Breach: true, Reason: fmt.Sprintf("%s got an answer from %s (%s), which the firewall must block", a, target, answer)}
		case macErr != nil:
			doubts = append(doubts, fmt.Sprintf("the Mac could not reach must-block target %s, so %s failing to reach it proves nothing; check that it is up (%v)", target, the, macErr))
		case answer == vmpalEgressUnreachable && g.unreachableBlocks:
			// Blocked, as a timeout is.
		case answer != vmpalEgressTimeout:
			doubts = append(doubts, fmt.Sprintf("%s's attempt on %s ended in %s rather than timing out", the, target, answer))
		}
	}
	if len(doubts) > 0 {
		return &vmpalEgressFailure{Reason: strings.Join(doubts, "; ")}
	}

	// Job users have no operator-supplied attestation: the agent writes and
	// compares the firewall itself, so there is nothing for one to say.
	if g.policy.check == "" {
		return nil
	}
	if err := g.runPolicyCheck(ctx); err != nil {
		return &vmpalEgressFailure{Reason: err.Error()}
	}
	return nil
}

// ask has the guest try these targets, one attempt each.
func (g *vmpalPolicyGate) ask(ctx context.Context, name string, targets []string) ([]string, error) {
	if g.asker != nil {
		return g.asker(ctx, name, targets)
	}
	limit := vmpalEgressAttempt * time.Duration(len(targets)+1)
	out, err := g.guest(ctx, name, limit, map[string]string{vmpalEgressTargetsVar: strings.Join(targets, " ")}, "egress")
	if err != nil {
		return nil, err
	}
	return parseVMPalEgress(out.Stdout, len(targets))
}

// runPolicyCheck runs the operator's attestation that the firewall covers IPv4
// and IPv6 on every candidate bridge. It gets no arguments and an environment
// built from nothing, and only exit 0 inside the limit counts.
func (g *vmpalPolicyGate) runPolicyCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, g.policyLimit)
	defer cancel()

	output := &cappedBuffer{limit: vmpalDetailLimit}
	cmd := exec.CommandContext(ctx, g.policy.check)
	cmd.Env = vmpalChildEnv(nil)
	cmd.Dir = "/"
	cmd.Stdout, cmd.Stderr = output, output
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	// Past this the check is killed and its pipes closed, so one that ignores
	// the signal, or left a child holding them, cannot hold up the create.
	cmd.WaitDelay = g.policyGrace

	err := cmd.Run()
	detail := strings.Join(strings.Fields(output.String()), " ")
	switch {
	case ctx.Err() != nil:
		return fmt.Errorf("the host policy check %s did not finish in time", g.policy.check)
	case err == nil:
		return nil
	case detail != "":
		return fmt.Errorf("the host policy check %s failed (%v): %s", g.policy.check, err, detail)
	}
	return fmt.Errorf("the host policy check %s failed: %v", g.policy.check, err)
}

// vmpalPurgeMessage is what a clone deleted because of another clone's breach
// reports as its end.
const vmpalPurgeMessage = "another clone on this Mac found the network policy not in force, so this clone was deleted; fix the host firewall"

// purgeClones deletes every clone this agent manages, after a breach has put
// the host on hold. A guest that was checked earlier was checked against a
// policy that has since been shown not to hold, so none of them is kept.
func (b *VMPalBackend) purgeClones(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), vmpalCleanupLimit)
	defer cancel()

	// Passing through the admission lock is what makes this complete. An
	// admission that got in first has written its entry and is read here, and
	// one that comes after will see the hold.
	b.admitMu.Lock()
	b.mu.Lock()
	entries, err := b.ledger.all()
	b.mu.Unlock()
	b.admitMu.Unlock()
	if err != nil {
		b.log.Warn("could not read the VM ledger while deleting clones after a breach", "error", err)
	}
	names := make(map[string]bool, len(entries))
	for name := range entries {
		names[name] = true
	}
	vms, err := b.cli.List(ctx)
	if err != nil {
		b.log.Warn("could not list VMs while deleting clones after a breach", "error", err)
	}
	for _, vm := range vms {
		if _, ours := b.ownedRunner(vm.Name); ours && !names[vm.Name] {
			if _, ok := b.recoverEntry(vm); ok {
				names[vm.Name] = true
			}
		}
	}

	var wg sync.WaitGroup
	for name := range names {
		wg.Go(func() { b.purgeClone(ctx, name) })
	}
	wg.Wait()
}

// purgeClone deletes one clone and leaves its entry for the agent's Remove, so
// the controller is told why the runner ended rather than finding it gone. A
// clone still being created has nobody to report to: its own create fails on
// the next stage change and clears the entry.
func (b *VMPalBackend) purgeClone(ctx context.Context, name string) {
	// In memory and first, because every write below can fail on a full disk,
	// and this is what stops a create in flight from delivering regardless.
	b.mu.Lock()
	b.abandonLocked(name)
	creating := b.creating[name]
	b.mu.Unlock()
	b.stopWatcher(name)
	if !creating {
		if err := b.recordExit(name, PhaseFailed, 1, vmpalPurgeMessage); err != nil {
			b.log.Warn("could not record why a clone is being deleted", "vm", name, "error", err)
		}
	}
	e, known, err := b.markDeleting(name)
	if err != nil {
		b.log.Warn("could not mark a clone for deletion after a breach", "vm", name, "error", err)
		// With no record read there is no ID to check the VM against, and a
		// name alone is not enough to delete on. The agent's Remove retries.
		if !known {
			return
		}
	}
	if err := b.deleteVM(ctx, name, e, known); err != nil {
		b.log.Warn("could not delete a clone after a breach; it will be retried", "vm", name, "error", err)
	}
}
