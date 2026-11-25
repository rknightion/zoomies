package backend

// A persistent cache for job users. The reset wipes a slot's home after every
// job, which is the point of the mode and also why a Swift build starts cold each
// time: the packages are fetched and resolved again and everything is compiled
// again. A pool that turns its cache on (pool.cache.enabled) gets one folder for
// each slot, outside the home so the reset never reaches it, and the job is told
// where it is. What goes in it is the workflow's business: nothing here reads it.
//
// It is one folder for each slot and not one for the host, so that a folder has
// one owner. The slot's account owns it and nobody else can open it, which keeps
// what the reset exists for: one job user can never write another's files.
//
// Like every cache in Zoomies it is disposable, so a failure to make or prune it
// costs the job its cache and never the job.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"time"

	"github.com/eyupio/zoomies/internal/store"
)

const (
	// EnvCacheDir is the variable a job reads to find its slot's cache folder. It
	// is set only when the pool's cache is on, so a workflow opts in by using it.
	// XDG_CACHE_HOME is deliberately not pointed at the folder as well: a tool
	// that moved its cache without the workflow asking would share it across jobs
	// of every trust level without the workflow having said so.
	EnvCacheDir = "ZOOMIES_CACHE_DIR"

	// jobUserCacheDirName is the folder below the users' folder that holds one
	// folder for each slot, beside the trash and for the same reason: it is on
	// the volume the homes are on, and outside every tree the reset sweeps.
	jobUserCacheDirName = ".zoomies-cache"
	// jobUserCacheDefaultLimit is what one slot's folder is kept under when the
	// pool sets no size limit, which is what the cache service keeps as well. A
	// folder with no bound would fill the Mac's disk with builds nobody wants.
	jobUserCacheDefaultLimit int64 = 10 << 30
	// jobUserCacheMaxDepth is how many folders down the pruning will look for
	// something smaller to evict than the one entry that is left.
	jobUserCacheMaxDepth = 4
)

// errCacheCrossesFilesystem is what measuring a cache says when something is
// mounted in it. Deleting the entry that holds it would delete through the mount.
var errCacheCrossesFilesystem = errors.New("another filesystem is mounted inside it")

// cacheRoot is the folder that holds every slot's cache folder.
func (u *jobUsers) cacheRoot() string { return filepath.Join(u.usersDir, jobUserCacheDirName) }

// cacheDir is a slot's cache folder.
func (u *jobUsers) cacheDir(s *jobUserSlot) string { return filepath.Join(u.cacheRoot(), s.name) }

// jobUserCacheLimit is what a slot's cache folder is kept under: the pool's size
// limit where it has one. It applies to each slot's folder, so the most this uses
// on a host is the limit times the number of accounts.
func jobUserCacheLimit(c store.CacheConfig) int64 {
	if c.SizeLimit > 0 {
		return c.SizeLimit
	}
	return jobUserCacheDefaultLimit
}

// prepareCache makes a slot's cache folder ready for the job that is about to
// start in it, and returns where it is, or "" when the pool keeps no cache or the
// folder could not be made. It runs with the slot reserved and nothing of the job
// started, which is the only time the folder can be pruned: a job holding a file
// open under a folder that is being deleted is the failure that timing designs out.
func (u *jobUsers) prepareCache(ctx context.Context, s *jobUserSlot, spec Spec) string {
	if !spec.Cache.Enabled {
		return ""
	}
	dir, err := u.ensureCacheDir(ctx, s)
	if err != nil {
		u.log.Warn("could not make the cache folder of a job user, so this job runs without one; the pool's cache is only an accelerator", "slot", s.name, "dir", u.cacheDir(s), "error", err)
		return ""
	}
	if err := u.pruneCache(ctx, s, dir, jobUserCacheLimit(spec.Cache)); err != nil {
		u.log.Warn("could not keep a job user's cache folder under its size limit, so it was left as it is this time", "slot", s.name, "dir", dir, "error", err)
	}
	return dir
}

// ensureCacheDir makes the slot's folder if it is not there and, every time, gives
// it to the slot and closes it to everybody else. A job may have opened its own
// folder to every user. The folder above is root's and no slot can write to it, so
// a slot can neither replace its folder nor reach another's, and what this puts
// back is the one thing a job could change: who may open its own.
func (u *jobUsers) ensureCacheDir(ctx context.Context, s *jobUserSlot) (string, error) {
	root := u.cacheRoot()
	if err := u.sys.MkdirAll(root, 0o755); err != nil {
		return "", fmt.Errorf("making %s: %w", root, err)
	}
	if err := u.sys.Chown(root, 0, 0); err != nil {
		return "", fmt.Errorf("giving %s to root: %w", root, err)
	}
	// Every slot has to be able to walk down to its own folder, and no further.
	if _, err := u.run(ctx, "/bin/chmod", "755", root); err != nil {
		return "", err
	}
	dir := u.cacheDir(s)
	switch info, err := u.sys.Lstat(dir); {
	case err == nil && !info.IsDir():
		// A link or a file where the folder belongs is not something a slot can have
		// made, because the folder above is not theirs. Chowning through a link would
		// give away whatever it points at, so it is removed and made again.
		if err := u.sys.RemoveAll(dir); err != nil {
			return "", fmt.Errorf("removing what is at %s where the cache folder belongs: %w", dir, err)
		}
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return "", fmt.Errorf("looking at %s: %w", dir, err)
	}
	if err := u.sys.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("making %s: %w", dir, err)
	}
	if err := u.sys.Chown(dir, s.uid, jobUserGID); err != nil {
		return "", fmt.Errorf("giving %s to %s: %w", dir, s.name, err)
	}
	if _, err := u.run(ctx, "/bin/chmod", "700", dir); err != nil {
		return "", err
	}
	return dir, nil
}

// cacheEntry is one thing directly inside a folder being pruned: a file, or a
// folder with everything in it.
type cacheEntry struct {
	name string
	dir  bool
	size int64
	// newest is the latest modification time of anything in the entry. A folder's
	// own time only changes when something is added to it or removed from it, so it
	// says nothing about whether the files below it were written to.
	newest time.Time
}

// pruneCache brings a slot's folder under limit bytes by deleting whole entries,
// the one written to longest ago first, so what the next job is most likely to
// want survives longest. The entries are what is directly in the folder, which
// the workflow chooses by how it lays the folder out. When what is left is one
// folder and it is still over, the entries inside it are weighed the same way, so
// a workflow that keeps everything under one name is not emptied for being big.
//
// It is a ceiling on how far over a folder is when a job starts, not a quota: a
// job can fill the disk between two prunes.
func (u *jobUsers) pruneCache(ctx context.Context, s *jobUserSlot, dir string, limit int64) error {
	info, err := u.sys.Lstat(dir)
	if err != nil {
		return err
	}
	dev, ok := u.sys.Dev(dir, info)
	if !ok {
		return fmt.Errorf("cannot tell which filesystem %s is on", dir)
	}
	st := &cachePrune{u: u, slot: s.name, limit: limit, dev: dev}
	if err := st.level(ctx, dir, 0); err != nil {
		return err
	}
	if st.removed > 0 {
		u.log.Info("evicted entries from a job user's cache folder to stay under the pool's cache size limit",
			"slot", s.name, "dir", dir, "limit_bytes", limit, "freed_bytes", st.freed, "entries", st.removed)
	}
	return nil
}

type cachePrune struct {
	u       *jobUsers
	slot    string
	limit   int64
	dev     uint64
	freed   int64
	removed int
}

func (p *cachePrune) level(ctx context.Context, dir string, depth int) error {
	entries, err := p.entries(ctx, dir)
	if err != nil {
		return err
	}
	var total int64
	for _, e := range entries {
		total += e.size
	}
	if total <= p.limit {
		return nil
	}
	// Ties break by name, to keep the order the same from one run to the next.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].newest.Equal(entries[j].newest) {
			return entries[i].name < entries[j].name
		}
		return entries[i].newest.Before(entries[j].newest)
	})
	for i, e := range entries {
		if ctx.Err() != nil || total <= p.limit {
			return ctx.Err()
		}
		path := filepath.Join(dir, e.name)
		if i == len(entries)-1 && e.dir && depth < jobUserCacheMaxDepth {
			return p.level(ctx, path, depth+1)
		}
		if err := p.evict(ctx, path); err != nil {
			p.u.log.Warn("could not evict an entry of a job user's cache folder", "slot", p.slot, "entry", path, "error", err)
			continue
		}
		total -= e.size
		p.freed += e.size
		p.removed++
	}
	return nil
}

// evict deletes one entry as root. File flags a job set (uchg and the like) would
// stop that, so they are cleared first, by value, as the reset does for a home.
func (p *cachePrune) evict(ctx context.Context, path string) error {
	if _, err := p.u.run(ctx, "/usr/bin/chflags", "-R", "0", path); err != nil {
		return err
	}
	return p.u.sys.RemoveAll(path)
}

func (p *cachePrune) entries(ctx context.Context, dir string) ([]cacheEntry, error) {
	children, err := p.u.sys.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]cacheEntry, 0, len(children))
	for _, c := range children {
		e := cacheEntry{name: c.Name()}
		if err := p.weigh(ctx, filepath.Join(dir, c.Name()), c, &e); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("measuring %s: %w", filepath.Join(dir, c.Name()), err)
		}
		e.dir = c.IsDir()
		out = append(out, e)
	}
	return out, nil
}

// weigh adds what is at path, and below it, to e. It looks at links and never
// follows them, because the folder belongs to a job and is read here as root, and
// it stops at a filesystem boundary because deleting an entry deletes through it.
func (p *cachePrune) weigh(ctx context.Context, path string, d fs.DirEntry, e *cacheEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := d.Info()
	if err != nil {
		return err
	}
	if dev, ok := p.u.sys.Dev(path, info); !ok || dev != p.dev {
		return fmt.Errorf("%s: %w", path, errCacheCrossesFilesystem)
	}
	if info.ModTime().After(e.newest) {
		e.newest = info.ModTime()
	}
	if !info.IsDir() {
		e.size += info.Size()
		return nil
	}
	children, err := p.u.sys.ReadDir(path)
	if err != nil {
		return err
	}
	for _, c := range children {
		if err := p.weigh(ctx, filepath.Join(path, c.Name()), c, e); err != nil {
			return err
		}
	}
	return nil
}

// removeCacheFolders deletes every slot's cache folder, for the removal command.
func (u *jobUsers) removeCacheFolders(ctx context.Context) error {
	root := u.cacheRoot()
	if _, err := u.sys.Lstat(root); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if _, err := u.run(ctx, "/usr/bin/chflags", "-R", "0", root); err != nil {
		return err
	}
	return u.sys.RemoveAll(root)
}
