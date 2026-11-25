package backend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeStaleRecord leaves a runner record that names a slot, as a crashed agent
// or a failed deletion would: no process behind it, and nothing to say it is
// not the slot's holder.
func writeStaleRecord(t *testing.T, x *jobUserFixture, dirName, slot string) string {
	t.Helper()
	dir := filepath.Join(x.root, runnersDirName, dirName)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	s := x.u.slotNamed(slot)
	if err := writeMeta(dir, processMeta{Name: dirName, RunnerID: "r-" + dirName, Slot: slot, RunDir: x.u.runDir(s), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestJobUserDiagIsNotCopiedThroughALinkAtAnyStep(t *testing.T) {
	plant := map[string]func(t *testing.T, runDir, elsewhere string){
		"the _diag folder is a link": func(t *testing.T, runDir, elsewhere string) {
			if err := os.Symlink(filepath.Join(elsewhere, "_diag"), filepath.Join(runDir, "_diag")); err != nil {
				t.Fatal(err)
			}
		},
		"the runner folder is a link": func(t *testing.T, runDir, elsewhere string) {
			// The running listener keeps its working folder, which has moved.
			if err := os.Rename(runDir, runDir+"-real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(elsewhere, runDir); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, do := range plant {
		x := startedJobUserFixture(t, 1)
		h := jobUserCreate(t, x, "runner-a")
		waitForLog(t, string(h), "listener started with run", 10*time.Second)
		runDir := filepath.Join(x.f.usersDir, "zj01", jobUserRunDirName)

		// Something root can read and the job cannot, which a link must not get the
		// agent to copy to where the agent's own files are kept.
		elsewhere := t.TempDir()
		if err := os.MkdirAll(filepath.Join(elsewhere, "_diag"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(elsewhere, "_diag", "secret.log"), []byte("not the job's to have copied"), 0o600); err != nil {
			t.Fatal(err)
		}
		do(t, runDir, elsewhere)
		x.f.reset()

		if err := x.b.Remove(context.Background(), h); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		kept := filepath.Join(x.root, jobUserDiagDir, filepath.Base(string(h)))
		if _, err := os.Stat(kept); err == nil {
			t.Errorf("%s: diagnostics were copied through the link", name)
		}
		if x.f.indexOf("readfile", "secret.log") >= 0 {
			t.Errorf("%s: a file behind the link was read as root", name)
		}
		// The skipped copy does not stop the reset.
		if x.f.indexOf("createhomedir -c -u zj01") < 0 {
			t.Errorf("%s: the slot was not reset", name)
		}
	}
}

func TestJobUserRemoveOfARecordThatDoesNotHoldItsSlotLeavesTheSlotAlone(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	live := jobUserCreate(t, x, "runner-a")
	waitForLog(t, string(live), "listener started with run", 10*time.Second)
	// A record of an earlier job in the same account, left behind when the agent
	// died between giving the slot back and deleting the record.
	stale := writeStaleRecord(t, x, "runner-stale", "zj01")
	x.f.reset()

	if err := x.b.Remove(context.Background(), Handle(stale)); err != nil {
		t.Fatal(err)
	}
	// The live job is the slot's, and it is neither killed nor wiped.
	for _, cmd := range []string{"pkill", "createhomedir", "launchctl", "chflags"} {
		if x.f.count(cmd) != 0 {
			t.Errorf("removing a stale record ran %s on a slot that another job holds: %v", cmd, x.f.logged())
		}
	}
	if x.f.indexOf("rename") >= 0 {
		t.Error("the live job's home was moved aside")
	}
	if got := x.u.slotNamed("zj01").holder; got != string(live) {
		t.Errorf("zj01 is held by %q; want the live runner %q", got, live)
	}
	if pid := readPID(string(live)); pid <= 0 || !processAlive(pid) {
		t.Error("the live runner's process was killed")
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("the stale record is still there")
	}
}

func TestJobUserAdoptionGivesASlotToTheRecordWhoseRunnerIsAlive(t *testing.T) {
	first := startedJobUserFixture(t, 1)
	live := jobUserCreate(t, first, "runner-b")
	waitForLog(t, string(live), "listener started with run", 10*time.Second)
	// Sorts before the live one, so a rule of "the first keeps it" gives the slot
	// to a record with nothing running behind it.
	stale := writeStaleRecord(t, first, "000-stale", "zj01")

	second := first.restart(t, 1)
	if err := second.b.StartJobUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := second.u.slotNamed("zj01").holder; got != string(live) {
		t.Fatalf("zj01 is held by %q; want the record whose runner is alive, %q", got, live)
	}
	// The loser's claim is gone, so nothing that later reads it can touch the slot.
	if meta, err := readMeta(stale); err != nil || meta.Slot != "" {
		t.Errorf("the stale record still claims %q (%v)", meta.Slot, err)
	}
	second.f.reset()
	if err := second.b.Remove(context.Background(), Handle(stale)); err != nil {
		t.Fatal(err)
	}
	if second.f.count("pkill") != 0 || second.f.count("createhomedir") != 0 {
		t.Errorf("cleaning the dead record touched the live job's slot: %v", second.f.logged())
	}
}

func TestJobUserAdoptionOfTwoDeadRecordsKeepsOneClaim(t *testing.T) {
	first := startedJobUserFixture(t, 1)
	a := writeStaleRecord(t, first, "000-a", "zj01")
	b := writeStaleRecord(t, first, "000-b", "zj01")
	second := first.restart(t, 1)
	if err := second.b.StartJobUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := second.u.slotNamed("zj01").holder; got != a {
		t.Errorf("zj01 is held by %q; want the first of two dead records, %q", got, a)
	}
	if meta, _ := readMeta(b); meta.Slot != "" {
		t.Errorf("the second record still claims %q", meta.Slot)
	}
}

func TestJobUserTheClaimIsClearedFromTheRecordBeforeTheSlotIsGivenBack(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	h := jobUserCreate(t, x, "runner-a")
	waitForLog(t, string(h), "listener started with run", 10*time.Second)
	// The reset fails, so the slot goes out of service, which is the other way a
	// slot is given up. The record must not still name it when it is.
	x.f.fail("createhomedir")
	var seen []string
	x.u.now = func() time.Time {
		if meta, err := readMeta(string(h)); err == nil {
			seen = append(seen, meta.Slot)
		}
		return x.f.now()
	}
	if err := x.b.Remove(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if len(seen) == 0 || seen[len(seen)-1] != "" {
		t.Errorf("the record named %q when the slot was given up; want no slot, or a record that survives would claim it again", seen)
	}
	if x.u.slotNamed("zj01").healthy {
		t.Error("zj01 was not taken out of service")
	}
}

func TestJobUserSlotsAboveAReducedCapacityAreCoveredAndDrained(t *testing.T) {
	ctx := context.Background()
	// Capacity 4 means five accounts, four running jobs and zj05 free.
	first := startedJobUserFixture(t, 4)
	var hs []Handle
	for _, n := range []string{"a", "b", "c", "d"} {
		h := jobUserCreate(t, first, "runner-"+n)
		waitForLog(t, string(h), "listener started with run", 10*time.Second)
		hs = append(hs, h)
	}

	// The operator lowers the capacity to 1, which offers zj01 and zj02, and
	// restarts the agent while the four jobs run.
	first.f.reset()
	second := first.restart(t, 1)
	if err := second.b.StartJobUsers(ctx); err != nil {
		t.Fatal(err)
	}
	for i, h := range hs {
		if got := second.u.slotNamed(jobUserName(i + 1)).holder; got != string(h) {
			t.Errorf("%s is held by %q after the restart; want %q", jobUserName(i+1), got, h)
		}
	}
	// zj05 is free but above the capacity: cleaned in full all the same, because
	// nothing says what a job left there before the restart.
	if second.f.indexOf("pkill -KILL -U 655") < 0 || second.f.indexOf("createhomedir -c -u zj05") < 0 {
		t.Errorf("the free account above capacity was not cleaned: %v", second.f.logged())
	}

	// The jobs in the drained slots end: each slot is cleaned, and never offered.
	second.f.reset()
	for _, h := range hs[2:] {
		if err := second.b.Remove(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"zj03", "zj04"} {
		if second.f.indexOf("createhomedir -c -u "+name) < 0 {
			t.Errorf("%s was not cleaned when its job ended", name)
		}
		if got := second.u.slotNamed(name).holder; got != "" {
			t.Errorf("%s is still held by %q", name, got)
		}
	}
	_, err := second.b.CreateWithResult(ctx, jobUserSpec("runner-e"))
	if !errors.Is(err, ErrDaemonBusy) {
		t.Errorf("create = %v; want busy, because zj01 and zj02 hold jobs and the drained accounts are not offered again", err)
	}
}
