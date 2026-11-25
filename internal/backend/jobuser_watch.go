package backend

import (
	"context"
	"fmt"
	"path/filepath"
	"time"
)

// jobUserWatchEvery is how often the watcher looks at the firewall.
const jobUserWatchEvery = 60 * time.Second

// startWatch starts the one background goroutine job users have. It runs outside
// every create, so a firewall that is lost is noticed while no job is starting.
func (u *jobUsers) startWatch(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	u.cancel = cancel
	u.watchWG.Add(1)
	go func() {
		defer u.watchWG.Done()
		ticker := time.NewTicker(u.watchEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				u.watchOnce(ctx)
			}
		}
	}()
}

// close stops the watcher. It leaves every job running: a runner outlives an
// agent restart, and the next agent adopts it from its record.
func (u *jobUsers) close() {
	if u.cancel != nil {
		u.cancel()
	}
	u.watchWG.Wait()
}

// watchOnce is one pass: the firewall, the slots that need another try, and the
// trash.
func (u *jobUsers) watchOnce(ctx context.Context) {
	if err := u.pf.verify(ctx); err != nil {
		u.firewallLost(ctx, err)
	}
	u.retryUnhealthy(ctx)
	u.sweepTrash(ctx)
}

// firewallLost is the incident the watcher exists for: the anchor is missing, or
// pf is off, or the rules are not the ones loaded. It reloads the anchor, stops
// every job's processes so that their runners exit through the normal path, and
// holds the host, so a lost firewall is a visible incident and not a silent gap.
func (u *jobUsers) firewallLost(ctx context.Context, cause error) {
	reason := fmt.Sprintf("the firewall for job users was lost or changed, so every running job was stopped: %v", cause)
	if err := u.pf.load(ctx); err != nil {
		reason += fmt.Sprintf("; reloading it failed too: %v", err)
	} else {
		reason += "; it has been loaded again"
	}
	u.log.Error("the job users' firewall was lost", "reason", reason)
	u.state.startHold(vmpalEgressHold, reason)
	u.reprobe.Store(true)
	u.stopRunning(ctx)
}

// retryUnhealthy tries again every slot whose time has come. The schedule is the
// slot's own: a minute after the first failure, five after the second, then
// every fifteen, so a cause that passes clears itself and an operator needs no
// command.
func (u *jobUsers) retryUnhealthy(ctx context.Context) {
	for _, s := range u.slots {
		u.mu.Lock()
		due := !s.healthy && s.holder == "" && !u.now().Before(s.nextRetry)
		if due {
			// Taken while it is retried, so that a create cannot reserve it.
			s.holder = "retry"
		}
		u.mu.Unlock()
		if !due {
			continue
		}
		err := u.resetSlot(ctx, s)
		if err != nil {
			u.markUnhealthy(s, err)
			continue
		}
		u.markHealthy(s)
		u.release(s)
	}
}

// sweepTrash deletes the homes waiting in the trash. It is off every job's path:
// moving a home there is instant, and deleting it is as slow as it is big.
func (u *jobUsers) sweepTrash(ctx context.Context) {
	entries, err := u.sys.ReadDir(u.trashDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if ctx.Err() != nil {
			return
		}
		if err := u.sys.RemoveAll(filepath.Join(u.trashDir, e.Name())); err != nil {
			u.log.Warn("could not delete a home from the trash", "entry", e.Name(), "error", err)
		}
	}
}
