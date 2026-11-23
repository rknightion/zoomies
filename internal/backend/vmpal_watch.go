package backend

import (
	"context"
	"fmt"
	"time"
)

const (
	vmpalWatchEvery = 15 * time.Second
	vmpalWatchRead  = 10 * time.Second
	// vmpalWakeGap is how long a watcher can go unscheduled before the Mac is
	// taken to have slept. A clone that has been through that is not resumed,
	// because the network policy it was checked against may not have held.
	vmpalWakeGap = 3 * time.Minute
	// vmpalReadGiveUp is how long the guest may go without answering. A job can
	// break VMPal Tools in its own guest, and nothing else would end it.
	vmpalReadGiveUp = 10 * time.Minute
	vmpalLifetime   = 6 * time.Hour
)

// vmpalWatchState is one watcher's memory. It is deliberately not persisted: a
// gap that spans an agent restart is the agent having been away, and running
// jobs are meant to survive that.
type vmpalWatchState struct {
	lastTick     time.Time
	failingSince time.Time
}

type vmpalWatcher struct{ cancel context.CancelFunc }

// ensureWatcher starts the one background reader a running clone has. It runs
// outside List so that a job that wedges Tools in its own guest can never stall
// or fail the listing for every other runner on the host.
func (b *VMPalBackend) ensureWatcher(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.watchers[name] != nil || b.abandoned[name] {
		return
	}
	ctx, cancel := context.WithCancel(b.baseCtx)
	w := &vmpalWatcher{cancel: cancel}
	b.watchers[name] = w
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		defer cancel()
		b.watchLoop(ctx, name)
		b.mu.Lock()
		if b.watchers[name] == w {
			delete(b.watchers, name)
		}
		b.mu.Unlock()
	}()
}

func (b *VMPalBackend) stopWatcher(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if w := b.watchers[name]; w != nil {
		w.cancel()
		delete(b.watchers, name)
	}
}

func (b *VMPalBackend) watchLoop(ctx context.Context, name string) {
	ticker := time.NewTicker(b.watchEvery)
	defer ticker.Stop()
	// Starting from now, so a Mac that sleeps before the first tick is noticed.
	st := vmpalWatchState{lastTick: b.now().Round(0)}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if b.watchOnce(ctx, name, &st) {
			return
		}
	}
}

// watchOnce is one look at a clone, and reports whether there is nothing left
// to watch.
func (b *VMPalBackend) watchOnce(ctx context.Context, name string, st *vmpalWatchState) bool {
	// Stripped of its monotonic reading, because on a Mac that clock stops
	// while the machine sleeps and a sleep is the very gap being looked for.
	now := b.now().Round(0)
	e, ok, err := b.readEntry(name)
	if err != nil {
		b.log.Warn("could not read a VM's ledger entry; trying again", "vm", name, "error", err)
		return false
	}
	if !ok || e.Exit != nil || e.Stage == vmpalStageDeleting {
		return true
	}

	gap := time.Duration(0)
	if !st.lastTick.IsZero() {
		gap = now.Sub(st.lastTick)
	}
	if gap > vmpalWakeGap {
		// lastTick stays where it was, so that if the result cannot be written
		// the next look still sees this gap.
		return b.endWatch(name, fmt.Sprintf("the Mac was asleep or stalled for %s while this runner was up, so whether its network policy held is unknown; the clone is being deleted, and the Mac should be kept from sleeping", gap.Round(time.Second)))
	}
	st.lastTick = now
	started := e.StartedAt
	if started.IsZero() {
		started = e.CreatedAt
	}
	if now.Sub(started) >= vmpalLifetime {
		return b.endWatch(name, fmt.Sprintf("the runner reached the %s limit on one clone, and the clone is being deleted", vmpalLifetime))
	}

	finished, err := b.readGuestExit(ctx, name, vmpalWatchRead)
	if err != nil {
		if ctx.Err() != nil {
			return true
		}
		if st.failingSince.IsZero() {
			st.failingSince = now
		}
		if now.Sub(st.failingSince) >= vmpalReadGiveUp {
			return b.endUnfollowable(name, fmt.Sprintf("VMPal Tools in the guest did not answer for %s, so the runner cannot be followed; the clone is being deleted", vmpalReadGiveUp))
		}
		return false
	}
	st.failingSince = time.Time{}
	return finished
}

// endWatch records a runner's end when nothing in the guest said how it ended
// and turns the VM off. The delete stays with the agent, which removes a
// workload once the controller has heard about it, but a clone that is not being
// resumed must not go on running a job until then.
func (b *VMPalBackend) endWatch(name, message string) bool {
	err := b.recordExit(name, PhaseFailed, 1, message)
	return b.finishEnding(name, message, err)
}

// finishEnding forces the VM off whether or not the result could be written,
// because a full disk is no reason to leave it running.
func (b *VMPalBackend) finishEnding(name, message string, recordErr error) bool {
	b.forceOff(name)
	if recordErr != nil {
		b.log.Warn("could not record a runner's end; trying again", "vm", name, "error", recordErr)
		return false
	}
	b.log.Warn("ending a macOS VM runner", "vm", name, "reason", message)
	return true
}

// forceOff runs on a context of its own: the watcher's is cancelled when the
// agent shuts down, and this clone is not one to leave running through that.
// Once a stop has worked it is not issued again, and only the call that set the
// flag clears it, so a failed retry cannot erase the record that Zoomies turned
// this VM off and have the guest blamed for it.
func (b *VMPalBackend) forceOff(name string) {
	b.mu.Lock()
	if b.forcedOff[name] {
		b.mu.Unlock()
		return
	}
	b.forcedOff[name] = true
	b.mu.Unlock()
	if err := b.cli.Stop(context.Background(), name, vmpalForceOffLimit); err != nil {
		b.mu.Lock()
		delete(b.forcedOff, name)
		b.mu.Unlock()
		b.log.Warn("could not force off a clone that is being ended; it keeps running until it is deleted", "vm", name, "error", err)
	}
}

// endUnfollowable is endWatch for a runner the guest stopped reporting on. No
// job is known to have run, so it counts toward the breaker: a guest broken the
// same way each time would otherwise register without limit.
func (b *VMPalBackend) endUnfollowable(name, message string) bool {
	err := b.recordUnreadableExit(name, message)
	return b.finishEnding(name, message, err)
}

// recordUnreadableExit stores a failed end for a runner whose guest gave no
// usable account of it, and tells the breaker that no job is known to have run.
func (b *VMPalBackend) recordUnreadableExit(name, message string) error {
	b.mu.Lock()
	e, ok, err := b.ledger.read(name)
	if err != nil || !ok || e.Exit != nil {
		b.mu.Unlock()
		return err
	}
	stopRequested := !e.StopRequestedAt.IsZero()
	err = b.writeExitLocked(e, PhaseFailed, 1, message)
	b.mu.Unlock()
	if err != nil {
		return err
	}
	b.gate.RunnerExited(false, stopRequested)
	return nil
}

// readGuestExit asks the guest for its exit record and records what it says.
// finished is true once the runner's end is in the ledger.
func (b *VMPalBackend) readGuestExit(ctx context.Context, name string, limit time.Duration) (finished bool, err error) {
	out, err := b.helper(ctx, name, limit, nil, "exit")
	if err != nil {
		return false, err
	}
	exit, running, parseErr := parseVMPalExit(out.Stdout)
	if running {
		return false, nil
	}
	if parseErr != nil {
		if err := b.recordUnreadableExit(name, vmpalMsgUnreadable); err != nil {
			return false, err
		}
		return true, nil
	}

	b.mu.Lock()
	e, ok, err := b.ledger.read(name)
	if err != nil || !ok || e.Exit != nil {
		b.mu.Unlock()
		return ok, err
	}
	stopRequested := !e.StopRequestedAt.IsZero()
	phase, code, message := vmpalExitOutcome(exit, stopRequested)
	err = b.writeExitLocked(e, phase, code, message)
	b.mu.Unlock()
	if err != nil {
		return false, err
	}
	// After the write, so a crash between the two loses one count rather than
	// counting the same runner twice on the next start.
	b.gate.RunnerExited(exit.TookJob, stopRequested)
	return true, nil
}

// recordExit stores a runner's end unless one is already stored: the first
// account of how a runner ended is the one that gets reported.
func (b *VMPalBackend) recordExit(name string, phase Phase, code int, message string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok, err := b.ledger.read(name)
	if err != nil || !ok || e.Exit != nil {
		return err
	}
	return b.writeExitLocked(e, phase, code, message)
}

func (b *VMPalBackend) writeExitLocked(e vmpalEntry, phase Phase, code int, message string) error {
	now := b.now()
	e.Exit = &vmpalExitResult{Phase: phase, Code: code, Message: message, At: now}
	if e.Stage.rank() < vmpalStageExited.rank() {
		e.Stage = vmpalStageExited
	}
	e.UpdatedAt = now
	return b.ledger.write(e)
}
