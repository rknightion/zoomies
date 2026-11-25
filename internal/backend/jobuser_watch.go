package backend

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"
)

// jobUserWatchEvery is how often the watcher looks at the slots and the trash.
const jobUserWatchEvery = 60 * time.Second

// startWatch starts the one background goroutine job users have. It runs outside
// every create, so a slot that could not be cleaned is tried again, and the trash
// emptied, while no job is starting.
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

// watchOnce is one pass: the slots that need another try, and the trash.
func (u *jobUsers) watchOnce(ctx context.Context) {
	u.retryUnhealthy(ctx)
	u.sweepTrash(ctx)
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
		_ = u.resetAndFree(ctx, s)
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
		if err := u.removeTrashEntry(ctx, filepath.Join(u.trashDir, e.Name())); err != nil {
			u.log.Warn("could not delete a home from the trash", "entry", e.Name(), "error", err)
		}
	}
}

// removeTrashEntry deletes one wiped home. A filesystem a job mounted inside it
// is not deleted through, which would delete what is on that disk and not the
// job's leavings: the entry is looked over first, and if another filesystem is
// found in it, it is unmounted once, and if it is still there the entry is left
// as it is, and said so. Every flag is cleared before the delete, as when the home
// was moved, because a job can set one on a file at any depth.
func (u *jobUsers) removeTrashEntry(ctx context.Context, entry string) error {
	err := u.sameFilesystemThroughout(entry)
	if err != nil {
		if uerr := u.unmountWhere(ctx, func(m jobUserMount) bool { return pathWithin(entry, m.Path) }); uerr != nil {
			return fmt.Errorf("%w; it could not be unmounted either: %v", err, uerr)
		}
		if err = u.sameFilesystemThroughout(entry); err != nil {
			return err
		}
	}
	if _, err := u.run(ctx, "/usr/bin/chflags", "-R", "0", entry); err != nil {
		return err
	}
	return u.sys.RemoveAll(entry)
}

// sameFilesystemThroughout refuses an entry with a folder on a different
// filesystem from the trash itself, found by device number before anything is
// descended into. Only folders are looked at, so a large home costs one read of
// each of its folders and no more. A link is not followed.
func (u *jobUsers) sameFilesystemThroughout(entry string) error {
	info, err := u.sys.Lstat(u.trashDir)
	if err != nil {
		return err
	}
	want, ok := u.sys.Dev(u.trashDir, info)
	if !ok {
		return fmt.Errorf("cannot tell which filesystem %s is on, so nothing in it is deleted", u.trashDir)
	}
	check := func(path string, fi fs.FileInfo) error {
		if dev, ok := u.sys.Dev(path, fi); !ok || dev != want {
			return fmt.Errorf("%s is on another filesystem than the trash, so it is not deleted through", path)
		}
		return nil
	}
	var walk func(dir string) error
	walk = func(dir string) error {
		entries, err := u.sys.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			fi, err := e.Info()
			if err != nil {
				return err
			}
			path := filepath.Join(dir, e.Name())
			if err := check(path, fi); err != nil {
				return err
			}
			if err := walk(path); err != nil {
				return err
			}
		}
		return nil
	}
	top, err := u.sys.Lstat(entry)
	if err != nil {
		return err
	}
	if err := check(entry, top); err != nil {
		return err
	}
	if !top.IsDir() {
		return nil
	}
	return walk(entry)
}
