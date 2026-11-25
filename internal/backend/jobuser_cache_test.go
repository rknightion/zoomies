package backend

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eyupio/zoomies/internal/store"
)

// A persistent cache for a job user. The home is wiped after every job, which is
// the point of the mode and also why a Swift build starts cold each time, so a
// pool that turns its cache on gets one folder for each slot, owned by that slot's
// account and kept outside its home. These tests drive it through a create and a
// remove, as the agent does, over the fake host.

// cacheFolderOf is where the fake host keeps a slot's cache.
func cacheFolderOf(x *jobUserFixture, slot string) string {
	return filepath.Join(x.f.usersDir, ".zoomies-cache", slot)
}

func cacheSpec(name string) Spec {
	s := jobUserSpec(name)
	s.Cache.Enabled = true
	return s
}

func jobUserCreateWith(t *testing.T, x *jobUserFixture, spec Spec) Handle {
	t.Helper()
	r, err := x.b.CreateWithResult(context.Background(), spec)
	if err != nil {
		t.Fatalf("create %s: %v", spec.Name, err)
	}
	x.cleanup(t, r.Handle)
	return r.Handle
}

// putCacheFile writes n bytes at path and dates the file age ago.
func putCacheFile(t *testing.T, path string, n int, age time.Duration) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, n), 0o600); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

func ageDir(t *testing.T, path string, age time.Duration) {
	t.Helper()
	when := time.Now().Add(-age)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func TestJobUserCacheIsOffWhenThePoolCacheIsOff(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	h := jobUserCreate(t, x, "runner-a")
	waitForLog(t, string(h), "listener started with run", 10*time.Second)

	if _, ok := envMap(x.f.started[0].env)["ZOOMIES_CACHE_DIR"]; ok {
		t.Error("a pool with no cache was told where a cache is")
	}
	if exists(filepath.Join(x.f.usersDir, ".zoomies-cache")) || x.f.count(".zoomies-cache") != 0 {
		t.Errorf("a pool with no cache still made one: %v", x.f.logged())
	}
}

func TestJobUserCacheGivesTheSlotAFolderOutsideItsHomeAndNamesIt(t *testing.T) {
	x := startedJobUserFixture(t, 2)
	h := jobUserCreateWith(t, x, cacheSpec("runner-a"))
	waitForLog(t, string(h), "listener started with run", 10*time.Second)

	dir := cacheFolderOf(x, "zj01")
	env := envMap(x.f.started[0].env)
	if env["ZOOMIES_CACHE_DIR"] != dir {
		t.Errorf("ZOOMIES_CACHE_DIR = %q, want %q", env["ZOOMIES_CACHE_DIR"], dir)
	}
	// Other tools' caches are the workflow's to point at the folder, not ours: a
	// tool that moved house without being asked would share across trust levels
	// without the workflow having said so.
	if v, ok := env["XDG_CACHE_HOME"]; ok {
		t.Errorf("XDG_CACHE_HOME = %q; the workflow opts in, the agent does not", v)
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Fatalf("the slot's cache folder was not made: %v", err)
	}
	if pathWithin(filepath.Join(x.f.usersDir, "zj01"), dir) {
		t.Errorf("%s is inside the home, which the reset replaces", dir)
	}
	// The slot's folder is the slot's and nobody else's; the folder above it is
	// root's and can be walked, so the slot reaches its own and no more.
	root := filepath.Dir(dir)
	for _, want := range []string{
		"chown " + root + " 0:0",
		"run /bin/chmod 755 " + root,
		"chown " + dir + " 651:650",
		"run /bin/chmod 700 " + dir,
	} {
		if x.f.indexOf(want) < 0 {
			t.Errorf("never saw %q: %v", want, x.f.logged())
		}
	}
	if own, start := x.f.indexOf("chmod 700 "+dir), x.f.indexOf("start "); own < 0 || own > start {
		t.Errorf("the folder was given to the slot at %d, after the runner started at %d", own, start)
	}

	// The next slot has a folder of its own, not a share of this one.
	h2 := jobUserCreateWith(t, x, cacheSpec("runner-b"))
	waitForLog(t, string(h2), "listener started with run", 10*time.Second)
	if got := envMap(x.f.started[1].env)["ZOOMIES_CACHE_DIR"]; got != cacheFolderOf(x, "zj02") {
		t.Errorf("the second slot's cache is %q; each slot keeps its own", got)
	}
}

func TestJobUserResetLeavesTheCacheAloneAndTheNextJobFindsIt(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	h := jobUserCreateWith(t, x, cacheSpec("runner-a"))
	waitForLog(t, string(h), "listener started with run", 10*time.Second)

	dir := cacheFolderOf(x, "zj01")
	kept := filepath.Join(dir, "main", "build", "objects.o")
	putCacheFile(t, kept, 100, time.Hour)
	inHome := filepath.Join(x.f.usersDir, "zj01", "Documents", "left-behind")
	putCacheFile(t, inHome, 10, 0)
	x.f.reset()

	if err := x.b.Remove(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if !exists(kept) {
		t.Fatal("the reset took the slot's cache with the home")
	}
	if exists(inHome) {
		t.Error("the reset did not run, so the cache surviving proves nothing")
	}
	// Not a command of the reset touched it: the trees it sweeps are the shared
	// ones, and the cache is in none of them.
	for _, l := range x.f.logged() {
		if strings.Contains(l, ".zoomies-cache") {
			t.Errorf("the reset did something to the cache: %q", l)
		}
	}

	// The same slot comes back with what the last job saved.
	h2 := jobUserCreateWith(t, x, cacheSpec("runner-b"))
	waitForLog(t, string(h2), "listener started with run", 10*time.Second)
	if got := envMap(x.f.started[len(x.f.started)-1].env)["ZOOMIES_CACHE_DIR"]; got != dir || !exists(kept) {
		t.Errorf("the next job on the slot got %q and the file is there: %v", got, exists(kept))
	}
}

func TestJobUserCacheFolderIsOutsideEveryTreeTheResetSweeps(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	dir := cacheFolderOf(x, "zj01")
	for _, tree := range x.u.sharedTrees() {
		if pathWithin(tree, dir) {
			t.Errorf("the cache folder %s is inside %s, which the reset empties of what the slot owns", dir, tree)
		}
	}
	if pathWithin(x.u.home(x.u.slotNamed("zj01")), dir) || pathWithin(x.u.trashDir, dir) {
		t.Errorf("the cache folder %s is in the home or the trash, both of which are deleted", dir)
	}
}

func TestJobUserCacheStillFailsTheResetOnWhatElseTheSlotLeft(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	h := jobUserCreateWith(t, x, cacheSpec("runner-a"))
	waitForLog(t, string(h), "listener started with run", 10*time.Second)
	putCacheFile(t, filepath.Join(cacheFolderOf(x, "zj01"), "kept"), 10, 0)

	// What find reports for the shared trees is still a reason to take the slot
	// out of service, cache or no cache.
	x.f.findOut = "/private/tmp/left-by-the-job\n"
	if err := x.b.Remove(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if healthy := x.u.slotNamed("zj01").healthy; healthy {
		t.Error("the slot went back into service with a file of the job's in /private/tmp")
	}
}

func TestJobUserCacheReplacesAnythingButAFolderAtTheSlotsPlace(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	dir := cacheFolderOf(x, "zj01")
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, dir); err != nil {
		t.Fatal(err)
	}
	h := jobUserCreateWith(t, x, cacheSpec("runner-a"))
	waitForLog(t, string(h), "listener started with run", 10*time.Second)

	if st, err := os.Lstat(dir); err != nil || !st.IsDir() {
		t.Fatalf("the link was not replaced by a folder: %v", err)
	}
	if x.f.indexOf("removeall "+dir) < 0 {
		t.Errorf("the link was not removed: %v", x.f.logged())
	}
	// Chowning through it would have given the folder it points at to the slot.
	if x.f.count("chown "+elsewhere) != 0 {
		t.Error("something was given to the slot through the link")
	}
}

func TestJobUserCacheIsClosedAgainBeforeEveryJob(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	dir := cacheFolderOf(x, "zj01")
	h := jobUserCreateWith(t, x, cacheSpec("runner-a"))
	waitForLog(t, string(h), "listener started with run", 10*time.Second)
	if err := x.b.Remove(context.Background(), h); err != nil {
		t.Fatal(err)
	}

	// A job may have opened its folder to everybody. The next one starts with
	// it owned and closed again, so another slot's job cannot read or fill it.
	x.f.reset()
	h2 := jobUserCreateWith(t, x, cacheSpec("runner-b"))
	waitForLog(t, string(h2), "listener started with run", 10*time.Second)
	if x.f.indexOf("chown "+dir+" 651:650") < 0 || x.f.indexOf("run /bin/chmod 700 "+dir) < 0 {
		t.Errorf("the folder was not owned and closed again: %v", x.f.logged())
	}
}

func TestJobUserCacheEvictsTheOldestEntriesOverTheLimitBeforeTheJobStarts(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	dir := cacheFolderOf(x, "zj01")
	putCacheFile(t, filepath.Join(dir, "stale"), 600, 5*time.Hour)
	// A folder whose own date is old but which holds a recent file is recent:
	// what matters is when anything in it was last written.
	putCacheFile(t, filepath.Join(dir, "busy", "old.o"), 400, 6*time.Hour)
	putCacheFile(t, filepath.Join(dir, "busy", "new.o"), 400, time.Minute)
	ageDir(t, filepath.Join(dir, "busy"), 7*time.Hour)
	putCacheFile(t, filepath.Join(dir, "other"), 300, 2*time.Hour)

	spec := cacheSpec("runner-a")
	spec.Cache.SizeLimit = 900
	h := jobUserCreateWith(t, x, spec)
	waitForLog(t, string(h), "listener started with run", 10*time.Second)

	if exists(filepath.Join(dir, "stale")) || exists(filepath.Join(dir, "other")) {
		t.Errorf("the oldest entries were kept over the limit: %v", x.f.logged())
	}
	if !exists(filepath.Join(dir, "busy", "new.o")) || !exists(filepath.Join(dir, "busy", "old.o")) {
		t.Error("an entry that was written to recently was evicted, or cut in half")
	}
	// Before the runner starts, and not while it runs: a job holding a file open
	// under a deleted folder is the failure that timing designs out.
	evict, start := x.f.indexOf("removeall "+filepath.Join(dir, "other")), x.f.indexOf("start ")
	if evict < 0 || start < 0 || evict > start {
		t.Errorf("evicted at %d, started at %d", evict, start)
	}
	// File flags a job set would stop root deleting, so they are cleared first.
	flags := x.f.indexOf("run /usr/bin/chflags -R 0 " + filepath.Join(dir, "stale"))
	if rm := x.f.indexOf("removeall " + filepath.Join(dir, "stale")); flags < 0 || flags > rm {
		t.Errorf("flags cleared at %d, removed at %d", flags, rm)
	}
}

func TestJobUserCacheLooksInsideTheOnlyEntryLeftWhenItIsStillOverTheLimit(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	dir := cacheFolderOf(x, "zj01")
	// One namespace holding every scratch folder is how a workflow is likely to
	// lay it out; emptying all of it for being over would be a cold build.
	putCacheFile(t, filepath.Join(dir, "main", "scratch-a", "a.o"), 600, 5*time.Hour)
	putCacheFile(t, filepath.Join(dir, "main", "scratch-b", "b.o"), 400, time.Minute)
	ageDir(t, filepath.Join(dir, "main"), time.Minute)

	spec := cacheSpec("runner-a")
	spec.Cache.SizeLimit = 500
	h := jobUserCreateWith(t, x, spec)
	waitForLog(t, string(h), "listener started with run", 10*time.Second)

	if exists(filepath.Join(dir, "main", "scratch-a")) {
		t.Error("the oldest scratch folder was kept over the limit")
	}
	if !exists(filepath.Join(dir, "main", "scratch-b", "b.o")) {
		t.Error("the recent scratch folder was evicted with it")
	}
}

func TestJobUserCacheLeavesAnotherSlotsCacheAloneWhileItsJobRuns(t *testing.T) {
	x := startedJobUserFixture(t, 2)
	a := cacheSpec("runner-a")
	a.Cache.SizeLimit = 100
	ha := jobUserCreateWith(t, x, a)
	waitForLog(t, string(ha), "listener started with run", 10*time.Second)
	// The first job is running and has grown its folder past the limit.
	busy := filepath.Join(cacheFolderOf(x, "zj01"), "in-use")
	putCacheFile(t, busy, 1000, time.Hour)
	x.f.reset()

	b := cacheSpec("runner-b")
	b.Cache.SizeLimit = 100
	hb := jobUserCreateWith(t, x, b)
	waitForLog(t, string(hb), "listener started with run", 10*time.Second)

	if !exists(busy) || x.f.count("removeall", cacheFolderOf(x, "zj01")) != 0 {
		t.Errorf("a slot's cache was pruned while its job was running: %v", x.f.logged())
	}
}

func TestJobUserCacheWithoutALimitIsLeftAlone(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	dir := cacheFolderOf(x, "zj01")
	putCacheFile(t, filepath.Join(dir, "big"), 5000, time.Hour)
	h := jobUserCreateWith(t, x, cacheSpec("runner-a"))
	waitForLog(t, string(h), "listener started with run", 10*time.Second)
	if !exists(filepath.Join(dir, "big")) {
		t.Error("a cache well under the default limit was pruned")
	}
}

func TestJobUserCacheNeverCrossesOntoAnotherFilesystemWhilePruning(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	dir := cacheFolderOf(x, "zj01")
	putCacheFile(t, filepath.Join(dir, "stale", "inner", "x.o"), 600, 5*time.Hour)
	putCacheFile(t, filepath.Join(dir, "fresh"), 600, time.Minute)
	// Something mounted under an entry, as a job can arrange. Deleting the entry
	// would delete through it.
	x.f.devs[filepath.Join(dir, "stale", "inner")] = 2

	spec := cacheSpec("runner-a")
	spec.Cache.SizeLimit = 700
	h := jobUserCreateWith(t, x, spec)
	waitForLog(t, string(h), "listener started with run", 10*time.Second)

	if !exists(filepath.Join(dir, "stale", "inner", "x.o")) || x.f.count("removeall", ".zoomies-cache") != 0 {
		t.Errorf("an entry with another filesystem in it was deleted: %v", x.f.logged())
	}
	if got := envMap(x.f.started[0].env)["ZOOMIES_CACHE_DIR"]; got != dir {
		t.Errorf("a cache that could not be pruned cost the job its cache folder: %q", got)
	}
}

func TestJobUserCacheThatCannotBeMadeCostsTheJobItsCacheNotTheJob(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	dir := cacheFolderOf(x, "zj01")
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("not a folder"), 0o600); err != nil {
		t.Fatal(err)
	}
	// macOS will not let even root remove it.
	x.f.removeErr[dir] = os.ErrPermission

	h := jobUserCreateWith(t, x, cacheSpec("runner-a"))
	waitForLog(t, string(h), "listener started with run", 10*time.Second)
	if v, ok := envMap(x.f.started[0].env)["ZOOMIES_CACHE_DIR"]; ok {
		t.Errorf("the job was told its cache is at %q, which is not a folder", v)
	}
}

func TestRemovingJobUsersDeletesTheCacheFoldersToo(t *testing.T) {
	x := removeFixture(t)
	dir := cacheFolderOf(x, "zj01")
	putCacheFile(t, filepath.Join(dir, "main", "x.o"), 10, time.Hour)
	x.f.reset()

	err := RemoveJobUsers(context.Background(), RemoveJobUsersOptions{StateDir: x.state, UsersDir: x.f.usersDir, Logger: quietLogger(), system: x.f})
	if err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(x.f.usersDir, ".zoomies-cache")) {
		t.Error("the cache folders were left behind by the removal")
	}
}

func TestJobUserEnvNamesTheCacheFolderOnlyWhenThereIsOne(t *testing.T) {
	s := &jobUserSlot{n: 1, name: "zj01", uid: 651}
	with := envMap(jobUserEnv(s, "/Users/zj01", "", "/Users/.zoomies-cache/zj01", Spec{}))
	if with["ZOOMIES_CACHE_DIR"] != "/Users/.zoomies-cache/zj01" {
		t.Errorf("ZOOMIES_CACHE_DIR = %q", with["ZOOMIES_CACHE_DIR"])
	}
	without := envMap(jobUserEnv(s, "/Users/zj01", "", "", Spec{}))
	if v, ok := without["ZOOMIES_CACHE_DIR"]; ok {
		t.Errorf("ZOOMIES_CACHE_DIR = %q with no cache", v)
	}
	// The pool's own settings come last and win, as for every other variable.
	last := ""
	for _, e := range jobUserEnv(s, "/Users/zj01", "", "/a", Spec{Env: map[string]string{"ZOOMIES_CACHE_DIR": "/b"}}) {
		if strings.HasPrefix(e, "ZOOMIES_CACHE_DIR=") {
			last = e
		}
	}
	if last != "ZOOMIES_CACHE_DIR=/b" {
		t.Errorf("the last ZOOMIES_CACHE_DIR is %q; the pool's must win", last)
	}
	if EnvCacheDir != "ZOOMIES_CACHE_DIR" {
		t.Errorf("EnvCacheDir = %q; workflows read this name", EnvCacheDir)
	}
}

func TestJobUserCacheLimitIsThePoolsOrTenGiB(t *testing.T) {
	if got := jobUserCacheLimit(store.CacheConfig{SizeLimit: 3 << 30}); got != 3<<30 {
		t.Errorf("limit = %d, want the pool's 3 GiB", got)
	}
	for _, zero := range []int64{0, -1} {
		if got := jobUserCacheLimit(store.CacheConfig{SizeLimit: zero}); got != 10<<30 {
			t.Errorf("limit with %d = %d, want the 10 GiB default", zero, got)
		}
	}
}
