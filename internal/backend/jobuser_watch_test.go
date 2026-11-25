package backend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWatchReloadsAMissingAnchorAndHoldsTheHost(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	x.f.procs = []jobUserProc{{PID: 500, RUID: 651, EUID: 651}, {PID: 501, RUID: 652, EUID: 652}}
	// Something flushed the anchor while jobs were running.
	x.f.pfRules = ""

	x.u.watchOnce(context.Background())

	if x.f.indexOf("pfctl -a "+jobUserAnchor+" -f -") < 0 || x.f.pfRules == "" {
		t.Errorf("the anchor was not loaded again: %v", x.f.logged())
	}
	if len(x.f.procs) != 0 {
		t.Errorf("%d job processes were left running with no firewall", len(x.f.procs))
	}
	held := x.u.state.held()
	if !errors.Is(held, errJobUsersHeld) || !strings.Contains(held.Error(), "firewall") {
		t.Fatalf("held = %v; want a hold that says the firewall was lost", held)
	}
	if !x.b.ProbeStale() {
		t.Error("the Hosts page is not told to look again")
	}
	if info := x.b.Probe(context.Background()); info.Available || !strings.Contains(info.Detail, "firewall") {
		t.Errorf("Probe = %+v; want the host unavailable and saying why", info)
	}
	// Nobody is started while it is held.
	_, err := x.b.CreateWithResult(context.Background(), jobUserSpec("runner-held"))
	if !errors.Is(err, errJobUsersHeld) {
		t.Errorf("create while held = %v", err)
	}

	// The incident is one incident: with the anchor back, the next pass is quiet.
	x.f.reset()
	x.u.watchOnce(context.Background())
	if x.f.count("pkill") != 0 {
		t.Error("jobs were stopped a second time for the same loss")
	}
}

func TestWatchLeavesAHealthyHostAlone(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	x.f.procs = []jobUserProc{{PID: 500, RUID: 651, EUID: 651}}
	x.u.watchOnce(context.Background())
	if len(x.f.procs) != 1 || x.u.state.held() != nil {
		t.Errorf("a host with its firewall in place was disturbed: held=%v procs=%v", x.u.state.held(), x.f.procs)
	}
}

func TestWatchRetriesAnUnhealthySlotOnItsSchedule(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	ctx := context.Background()
	s := x.u.slotNamed("zj01")
	x.f.fail("createhomedir")

	if err := x.u.resetAndFree(ctx, s); err == nil {
		t.Fatal("the reset was meant to fail")
	}
	if s.healthy || x.u.healthyCount() != 1 {
		t.Fatalf("healthy=%v healthyCount=%d; want zj01 out and zj02 in", s.healthy, x.u.healthyCount())
	}
	if len(x.u.unhealthy()) != 1 || !strings.Contains(x.u.unhealthy()[0], "zj01") {
		t.Errorf("unhealthy = %v; want zj01 named", x.u.unhealthy())
	}

	steps := []struct {
		advance time.Duration
		retried bool
		what    string
	}{
		{59 * time.Second, false, "59 seconds after the first failure"},
		{2 * time.Second, true, "a minute after the first failure"},
		{4 * time.Minute, false, "4 minutes after the second"},
		{61 * time.Second, true, "5 minutes after the second"},
		{14 * time.Minute, false, "14 minutes after the third"},
		{61 * time.Second, true, "15 minutes after the third"},
		{15*time.Minute + time.Second, true, "15 minutes after the fourth, which is the schedule from here on"},
	}
	for _, st := range steps {
		x.f.advance(st.advance)
		x.f.reset()
		x.u.watchOnce(ctx)
		if got := x.f.count("createhomedir") > 0; got != st.retried {
			t.Fatalf("%s: retried=%v, want %v", st.what, got, st.retried)
		}
	}

	// The cause passes and no operator command is needed.
	x.f.clear()
	x.f.advance(15*time.Minute + time.Second)
	x.u.watchOnce(ctx)
	if !s.healthy || x.u.healthyCount() != 2 || len(x.u.unhealthy()) != 0 {
		t.Errorf("the slot did not come back: healthy=%v", s.healthy)
	}
	if !x.b.ProbeStale() {
		t.Error("coming back did not ask for a fresh probe")
	}
}

func TestWatchDoesNotRetryASlotAJobIsUsing(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	s := x.u.slotNamed("zj01")
	x.u.markUnhealthy(s, errors.New("boom"))
	x.u.mu.Lock()
	s.holder = "somebody"
	x.u.mu.Unlock()
	x.f.advance(time.Hour)
	x.u.watchOnce(context.Background())
	if x.f.count("createhomedir") != 0 {
		t.Error("a slot that is held was reset under its holder")
	}
}

func TestWatchEmptiesTheTrashOffTheJobPath(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	trash := filepath.Join(x.f.usersDir, jobUserTrashName)
	for _, n := range []string{"zj01-1", "zj02-2"} {
		if err := os.MkdirAll(filepath.Join(trash, n, "Library"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	x.u.watchOnce(context.Background())
	left, err := os.ReadDir(trash)
	if err != nil || len(left) != 0 {
		t.Fatalf("trash = %v, %v; want it empty", left, err)
	}
}

func TestWatchClearsEveryFlagOnATrashEntryBeforeDeletingIt(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	trash := filepath.Join(x.f.usersDir, jobUserTrashName)
	entry := filepath.Join(trash, "zj01-1")
	if err := os.MkdirAll(filepath.Join(entry, "Library"), 0o700); err != nil {
		t.Fatal(err)
	}
	x.f.reset()
	x.u.watchOnce(context.Background())
	// A job can set a flag after the home was moved aside only if something of it
	// still ran, but one set before is still there, and one append-only file
	// would fail the sweep every minute for ever.
	flags, del := x.f.indexOf("chflags -R 0 "+entry), x.f.indexOf("removeall "+entry)
	if flags < 0 || del < 0 || flags > del {
		t.Errorf("flags cleared at %d, entry deleted at %d; want the flags first: %v", flags, del, x.f.logged())
	}
}

func TestWatchWillNotDeleteThroughAMountInsideATrashEntry(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	trash := filepath.Join(x.f.usersDir, jobUserTrashName)
	entry := filepath.Join(trash, "zj01-1")
	mount := filepath.Join(entry, "Documents", "dmg")
	if err := os.MkdirAll(filepath.Join(mount, "precious"), 0o700); err != nil {
		t.Fatal(err)
	}
	// What is under the mount point is another filesystem: deleting through it
	// would delete that, wherever it comes from.
	x.f.devs[mount] = 7
	x.f.mounts = []jobUserMount{{Path: mount, Owner: 0}}
	x.f.fail("umount")
	x.f.fail("diskutil")
	x.f.reset()

	x.u.watchOnce(context.Background())

	if x.f.indexOf("removeall") >= 0 {
		t.Errorf("a trash entry with a mounted filesystem inside was deleted: %v", x.f.logged())
	}
	if _, err := os.Stat(filepath.Join(mount, "precious")); err != nil {
		t.Errorf("what was under the mount point is gone: %v", err)
	}
}

func TestWatchUnmountsAMountInsideATrashEntryAndThenDeletesIt(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	trash := filepath.Join(x.f.usersDir, jobUserTrashName)
	entry := filepath.Join(trash, "zj01-1")
	mount := filepath.Join(entry, "Documents", "dmg")
	if err := os.MkdirAll(mount, 0o700); err != nil {
		t.Fatal(err)
	}
	x.f.devs[mount] = 7
	x.f.mounts = []jobUserMount{{Path: mount, Owner: 0}}
	x.f.reset()

	x.u.watchOnce(context.Background())

	un, del := x.f.indexOf("umount -f "+mount), x.f.indexOf("removeall "+entry)
	if un < 0 || del < 0 || un > del {
		t.Errorf("unmounted at %d, deleted at %d; want the mount taken off first: %v", un, del, x.f.logged())
	}
}

func TestTheWatcherRunsUntilTheBackendIsClosed(t *testing.T) {
	x := newJobUserFixture(t, 1)
	x.u.watchEvery = 5 * time.Millisecond
	if err := x.b.StartJobUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Flushed behind its back, it is found by the ticker and not by a test.
	x.f.mu.Lock()
	x.f.pfRules = ""
	x.f.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for x.u.state.held() == nil {
		if time.Now().After(deadline) {
			t.Fatal("the watcher never noticed the lost anchor")
		}
		time.Sleep(5 * time.Millisecond)
	}
	x.b.Close()
}
