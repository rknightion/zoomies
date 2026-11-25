package backend

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// firstStepCommands is a marker in the log for each step of a reset, in the
// order the design gives them.
var resetMarkers = []struct {
	step  string
	parts []string
}{
	{stepStop, []string{"pkill -STOP -U 651"}},
	{stepBootout, []string{"launchctl bootout user/651"}},
	{stepScheduled, []string{"crontab -r -u zj01"}},
	{stepHome, []string{"createhomedir -c -u zj01"}},
	{stepTemp, []string{"getconf DARWIN_USER_TEMP_DIR"}},
	{stepShared, []string{"find -x -P /private/tmp -user 651 -delete"}},
	{stepIPC, []string{"ipcs -a"}},
	{stepVerify, []string{"find -x -P /private/tmp -user 651 -print"}},
}

func TestResetRunsItsStepsInOrderAndNamesTheOneThatFailed(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	s := x.u.slotNamed("zj01")
	if err := x.u.resetSlot(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	prev := -1
	for _, m := range resetMarkers {
		i := x.f.indexOf(m.parts...)
		if i < 0 {
			t.Fatalf("step %q never ran %v; log:\n%s", m.step, m.parts, strings.Join(x.f.logged(), "\n"))
		}
		if i <= prev {
			t.Errorf("step %q ran at %d, before the step ahead of it at %d", m.step, i, prev)
		}
		prev = i
	}

	// Each step that can fail stops the reset there and is the one named.
	failures := []struct {
		step   string
		prefix []string
	}{
		{stepBootout, []string{"launchctl", "bootout", "user/651"}},
		{stepScheduled, []string{"crontab"}},
		{stepHome, []string{"createhomedir"}},
		{stepTemp, []string{"getconf"}},
		{stepShared, []string{"find", "-x", "-P", "/private/tmp", "-user", "651", "-delete"}},
		{stepIPC, []string{"ipcs"}},
		{stepVerify, []string{"find", "-x", "-P", "/private/tmp", "-user", "651", "-print"}},
	}
	for _, tc := range failures {
		x.f.reset()
		x.f.clear()
		x.f.fail(tc.prefix...)
		err := x.u.resetSlot(context.Background(), s)
		var re *resetError
		if !errors.As(err, &re) || re.Step != tc.step || re.Slot != "zj01" {
			t.Errorf("a failing %v gave %v; want a resetError at step %q for zj01", tc.prefix, err, tc.step)
			continue
		}
		// Nothing after the step that failed ran.
		after := false
		for _, m := range resetMarkers {
			if m.step == tc.step {
				after = true
				continue
			}
			if after && x.f.indexOf(m.parts...) >= 0 && m.step != stepVerify {
				t.Errorf("after %q failed, step %q still ran", tc.step, m.step)
			}
		}
	}
	x.f.clear()
}

func TestResetStopsEveryProcessBeforeKillingAnyOfThem(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	x.f.procs = []jobUserProc{{PID: 900, RUID: 651, EUID: 651}, {PID: 901, RUID: 0, EUID: 651}}

	if err := x.u.stopProcesses(context.Background(), x.u.slotNamed("zj01")); err != nil {
		t.Fatal(err)
	}
	// STOP by real and by effective UID, then KILL by both: a fork loop that is
	// stopped cannot outrun the kill.
	order := []string{"pkill -STOP -U 651", "pkill -STOP -u 651", "pkill -KILL -U 651", "pkill -KILL -u 651"}
	prev := -1
	for _, o := range order {
		i := x.f.indexOf(o)
		if i <= prev {
			t.Fatalf("%q at %d, not after %d; log: %v", o, i, prev, x.f.logged())
		}
		prev = i
	}
	if len(x.f.procs) != 0 {
		t.Errorf("%d processes are left", len(x.f.procs))
	}
}

func TestResetGivesUpOnAProcessThatSurvivesSigkillAfterTenSeconds(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	x.f.procs = []jobUserProc{{PID: 900, RUID: 651, EUID: 651}}
	x.f.stubborn = true
	start := x.f.now()

	err := x.u.resetSlot(context.Background(), x.u.slotNamed("zj01"))
	var re *resetError
	if !errors.As(err, &re) || re.Step != stepStop {
		t.Fatalf("got %v; want the stop step to fail", err)
	}
	if waited := x.f.now().Sub(start); waited < jobUserKillWithin || waited > jobUserKillWithin+time.Second {
		t.Errorf("it tried for %s; want about %s, trying every %s", waited, jobUserKillWithin, jobUserKillEvery)
	}
	// The home was left alone, because something may still be writing to it.
	if x.f.indexOf("rename") >= 0 || x.f.indexOf("createhomedir") >= 0 {
		t.Error("the home was replaced while a process of the user was still running")
	}
}

func TestResetClearsImmutableFlagsBeforeMovingTheHome(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	home := filepath.Join(x.f.usersDir, "zj01")
	if err := os.WriteFile(filepath.Join(home, "leftover"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := x.u.resetSlot(context.Background(), x.u.slotNamed("zj01")); err != nil {
		t.Fatal(err)
	}
	flags := x.f.indexOf("chflags -R 0 " + home)
	move := x.f.indexOf("rename " + home)
	create := x.f.indexOf("createhomedir -c -u zj01")
	if flags < 0 || move < 0 || create < 0 || !(flags < move && move < create) {
		t.Fatalf("flags at %d, move at %d, create at %d; want that order. log: %v", flags, move, create, x.f.logged())
	}
	// The old home is in the trash, not deleted on the job's path, and the new
	// one holds nothing of it.
	trash, err := os.ReadDir(filepath.Join(x.f.usersDir, jobUserTrashName))
	if err != nil || len(trash) != 1 || !strings.HasPrefix(trash[0].Name(), "zj01-") {
		t.Fatalf("trash = %v, %v; want one entry for zj01", trash, err)
	}
	if _, err := os.Stat(filepath.Join(home, "leftover")); err == nil {
		t.Error("the new home holds the old one's file")
	}
	if x.f.indexOf("removeall "+home) >= 0 {
		t.Error("the home was deleted on the job's path instead of moved")
	}
}

func TestVerifyFailsWhenTheHomeDiffersFromItsManifest(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	s := x.u.slotNamed("zj01")
	if err := x.u.verifySlot(context.Background(), s); err != nil {
		t.Fatalf("a fresh home does not verify: %v", err)
	}
	home := filepath.Join(x.f.usersDir, "zj01")

	cases := map[string]func() error{
		"a file left in the home": func() error { return os.WriteFile(filepath.Join(home, ".bash_profile"), nil, 0o600) },
		"a file deeper down":      func() error { return os.WriteFile(filepath.Join(home, "Library", "LaunchAgents.plist"), nil, 0o600) },
		"a link":                  func() error { return os.Symlink("/etc", filepath.Join(home, "etc")) },
		"a file that was removed": func() error { return os.Remove(filepath.Join(home, "Documents")) },
	}
	for name, change := range cases {
		if err := x.u.resetSlot(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		if err := change(); err != nil {
			t.Fatal(err)
		}
		if err := x.u.verifySlot(context.Background(), s); err == nil || !strings.Contains(err.Error(), "not what a fresh one is") {
			t.Errorf("%s: verify = %v; want it to refuse the home", name, err)
		}
	}
}

func TestVerifyFailsWhenTheHomeIsOwnedByAnotherUser(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	s := x.u.slotNamed("zj01")
	home := filepath.Join(x.f.usersDir, "zj01")
	x.f.owners[filepath.Join(home, "Library")] = [2]int{0, 0}
	if err := x.u.verifySlot(context.Background(), s); err == nil {
		t.Error("a folder in the home that root owns was accepted")
	}
}

func TestVerifyFailsWhileAProcessOfTheUserIsLeft(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	x.f.procs = []jobUserProc{{PID: 77, RUID: 0, EUID: 651}}
	err := x.u.verifySlot(context.Background(), x.u.slotNamed("zj01"))
	if err == nil || !strings.Contains(err.Error(), "77") {
		t.Fatalf("verify = %v; want it to name the process left", err)
	}
	x.f.procs = []jobUserProc{{PID: 78, RUID: 652, EUID: 652}}
	if err := x.u.verifySlot(context.Background(), x.u.slotNamed("zj01")); err != nil {
		t.Errorf("another slot's process held this one up: %v", err)
	}
}

func TestResetRefusesATemporaryFolderOfTheWrongShapeBeforeRemovingAnything(t *testing.T) {
	for _, printed := range []string{"/", "/var/folders/", "/var/folders/ab/T/", "/Users/zj01/T/", "/var/folders/ab/cd/../../../etc/T/", "/var/folders/ab/cdef12/X/", ""} {
		x := startedJobUserFixture(t, 1)
		x.f.tempDir = printed
		err := x.u.removeUserTemp(context.Background(), x.u.slotNamed("zj01"))
		if err == nil {
			t.Errorf("getconf printing %q was accepted", printed)
		}
		if n := x.f.count("removeall"); n != 0 {
			t.Errorf("getconf printing %q still removed something: %v", printed, x.f.logged())
		}
	}
}

func TestResetEmptiesTheTemporaryFolderOnlyWhenTheSlotOwnsIt(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	parent := "/var/folders/ab/cdef12"
	dir, err := os.Lstat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stray, err := os.Lstat(filepath.Join(t.TempDir(), "."))
	if err != nil {
		t.Fatal(err)
	}
	x.f.lstat[parent] = dir
	entry := func(name string, isDir bool) fs.DirEntry {
		if isDir {
			return fs.FileInfoToDirEntry(namedInfo{dir, name})
		}
		return fs.FileInfoToDirEntry(namedInfo{fileInfo{stray}, name})
	}
	x.f.readDir[parent] = []fs.DirEntry{entry("0", true), entry("C", true), entry("T", true), entry("X", true), entry("stray", false)}
	x.f.readDir[parent+"/T"] = []fs.DirEntry{entry("build.o", false)}
	x.f.readDir[parent+"/C"] = []fs.DirEntry{entry("clang", true)}
	x.f.readDir[parent+"/0"] = nil
	x.f.readDir[parent+"/X"] = nil
	s := x.u.slotNamed("zj01")

	// Somebody else's folder with a name of the right shape is not touched.
	x.f.owners[parent] = [2]int{0, 0}
	if err := x.u.removeUserTemp(context.Background(), s); err == nil {
		t.Error("a folder root owns was emptied on the strength of its name")
	}
	if x.f.count("removeall") != 0 {
		t.Errorf("something was removed: %v", x.f.logged())
	}

	x.f.owners[parent] = [2]int{651, jobUserGID}
	if err := x.u.removeUserTemp(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	removed := map[string]bool{}
	for _, line := range x.f.logged() {
		if p, ok := strings.CutPrefix(line, "removeall "); ok {
			removed[p] = true
		}
	}
	for _, gone := range []string{parent + "/T/build.o", parent + "/C/clang", parent + "/stray"} {
		if !removed[gone] {
			t.Errorf("%s was left: %v", gone, x.f.logged())
		}
	}
	// macOS makes the folder and the four inside it with the sunlnk flag, which
	// stops even root unlinking them, so removing any of them fails the reset
	// and takes the slot out of service. They stay, empty.
	for _, kept := range []string{parent, parent + "/0", parent + "/C", parent + "/T", parent + "/X"} {
		if removed[kept] {
			t.Errorf("%s was removed, which macOS refuses: %v", kept, x.f.logged())
		}
	}
}

// namedInfo gives a real file's description another name, for a folder the
// test describes rather than makes.
type namedInfo struct {
	fs.FileInfo
	name string
}

func (n namedInfo) Name() string { return n.name }

// fileInfo is a description that says it is not a folder.
type fileInfo struct{ fs.FileInfo }

func (fileInfo) IsDir() bool       { return false }
func (fileInfo) Mode() fs.FileMode { return 0o644 }

func TestResetRemovesOnlyTheIPCObjectsTheSlotOwns(t *testing.T) {
	out := `IPC status from <running system> as of Wed Nov 25 12:00:00 UTC 2026
T     ID     KEY        MODE       OWNER    GROUP  CREATOR   CGROUP
Message Queues:

Shared Memory:
m  65536 0x0100000a --rw-rw-rw-     zj01   _zjobs     zj01   _zjobs
m  65537 0x0100000b --rw-------    alice    staff    alice    staff
m  65538 0x0100000c --rw-------      651      650      651      650
Semaphores:
s  32768 0x0100000d --ra-ra-ra-     root    wheel     zj01   _zjobs
s  32769 0x0100000e --ra-ra-ra-     root    wheel     root    wheel
`
	got := parseJobUserIPC(out, "zj01", 651)
	want := []ipcObject{{"-m", "65536"}, {"-m", "65538"}, {"-s", "32768"}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("object %d = %v, want %v", i, got[i], want[i])
		}
	}

	x := startedJobUserFixture(t, 1)
	x.f.ipcs = out
	if err := x.u.removeIPC(context.Background(), x.u.slotNamed("zj01")); err != nil {
		t.Fatal(err)
	}
	if x.f.count("ipcrm") != 3 || x.f.indexOf("ipcrm -m 65537") >= 0 || x.f.indexOf("ipcrm -s 32769") >= 0 {
		t.Errorf("ipcrm ran for the wrong objects: %v", x.f.logged())
	}
}

func TestResetStepsReadTheExitCodesLaunchctlAndCrontabUse(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	s := x.u.slotNamed("zj01")
	// "No such process" is launchd's answer for a domain that is not loaded.
	x.f.rules = append(x.f.rules,
		fakeRule{prefix: []string{"launchctl", "bootout"}, res: jobUserResult{ExitCode: 3, Output: "Boot-out failed: 3: No such process"}},
		fakeRule{prefix: []string{"crontab"}, res: jobUserResult{ExitCode: 1, Output: "crontab: no crontab for zj01"}},
		fakeRule{prefix: []string{"atq"}, res: jobUserResult{ExitCode: 1, Output: "atq: at is not enabled"}},
	)
	if err := x.u.resetSlot(context.Background(), s); err != nil {
		t.Fatalf("the usual answers of an idle account failed the reset: %v", err)
	}
	// Anything else from launchctl is a real failure.
	x.f.clear()
	x.f.answer("launchctl is on fire", "launchctl", "bootout")
	x.f.rules[0].res.ExitCode = 9
	if err := x.u.resetSlot(context.Background(), s); err == nil {
		t.Error("an unexpected launchctl failure was ignored")
	}
}

func TestResetRemovesTheAtJobsOfTheSlotAndNobodyElses(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	// atq on macOS prints a job number and a date and no owner, even to root, so
	// a reset that read it could never tell whose job was whose. The spool's
	// files carry their owner, and only the slot's are deleted.
	if err := x.u.removeScheduled(context.Background(), x.u.slotNamed("zj01")); err != nil {
		t.Fatal(err)
	}
	if x.f.indexOf("find -x -P /private/var/at/jobs -maxdepth 1 -type f -user 651 -delete") < 0 {
		t.Errorf("the slot's at jobs were not removed by owner: %v", x.f.logged())
	}
	if x.f.indexOf("atq") >= 0 || x.f.indexOf("atrm") >= 0 {
		t.Errorf("the reset still reads atq, which names no owner on macOS: %v", x.f.logged())
	}
}

func TestResetClearsEveryFlagBeforeMovingTheHome(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	home := filepath.Join(x.f.usersDir, "zj01")
	if err := x.u.resetSlot(context.Background(), x.u.slotNamed("zj01")); err != nil {
		t.Fatal(err)
	}
	// uappnd and sappnd stop a rename and a delete as surely as uchg does, and a
	// job can set any flag it owns the file for: all of them go, not a list.
	if x.f.indexOf("chflags -R nouchg,noschg") >= 0 {
		t.Errorf("only some flags were cleared: %v", x.f.logged())
	}
	if x.f.indexOf("chflags -R 0 "+home) < 0 {
		t.Errorf("flags were not all cleared: %v", x.f.logged())
	}
}

func TestResetUnmountsWhatTheJobMountedBeforeMovingTheHome(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	home := filepath.Join(x.f.usersDir, "zj01")
	x.f.mounts = []jobUserMount{
		{Path: home + "/dmg", Owner: 651},
		{Path: home + "/dmg/inner", Owner: 0},
		{Path: "/Volumes/job-image", Owner: 651},
		{Path: "/Volumes/somebody-elses", Owner: 501},
		{Path: "/", Owner: 0},
	}
	if err := x.u.resetSlot(context.Background(), x.u.slotNamed("zj01")); err != nil {
		t.Fatal(err)
	}
	// Under the home whoever mounted it, and anywhere else when this account did.
	for _, p := range []string{home + "/dmg/inner", home + "/dmg", "/Volumes/job-image"} {
		if x.f.indexOf("umount -f "+p) < 0 {
			t.Errorf("%s was not unmounted: %v", p, x.f.logged())
		}
	}
	for _, l := range x.f.logged() {
		if strings.Contains(l, "umount") && (strings.HasSuffix(l, " /Volumes/somebody-elses") || strings.HasSuffix(l, " /")) {
			t.Errorf("%q: a filesystem the job did not mount was unmounted", l)
		}
	}
	// The inner mount first, or the outer one is busy.
	inner := x.f.indexOf("umount -f " + home + "/dmg/inner")
	outer := x.f.indexAfter(inner+1, "umount -f "+home+"/dmg")
	move := x.f.indexOf("rename " + home)
	if inner < 0 || !(inner < outer && outer < move) {
		t.Errorf("inner at %d, outer at %d, move at %d; want the deepest mount first and all before the home moves", inner, outer, move)
	}
}

func TestResetFallsBackToDiskutilAndStopsWhenAMountWillNotGo(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	home := filepath.Join(x.f.usersDir, "zj01")
	s := x.u.slotNamed("zj01")
	x.f.mounts = []jobUserMount{{Path: home + "/dmg", Owner: 651}}
	x.f.failOnce("umount")
	if err := x.u.resetSlot(context.Background(), s); err != nil {
		t.Fatalf("a mount that diskutil could take was not enough: %v", err)
	}
	if x.f.indexOf("diskutil unmount force "+home+"/dmg") < 0 {
		t.Errorf("diskutil was not tried: %v", x.f.logged())
	}

	// Neither works: the home stays where it is, because moving it would take the
	// mount's contents along or leave the mount to be deleted through.
	x.f.reset()
	x.f.mounts = []jobUserMount{{Path: home + "/dmg", Owner: 651}}
	x.f.fail("umount")
	x.f.fail("diskutil")
	err := x.u.resetSlot(context.Background(), s)
	if err == nil || !strings.Contains(err.Error(), "dmg") {
		t.Fatalf("reset = %v; want a failure naming the mount", err)
	}
	if x.f.indexOf("rename") >= 0 || x.f.indexOf("createhomedir") >= 0 {
		t.Errorf("the home was replaced with a mount still in it: %v", x.f.logged())
	}
}

func TestTheCleanedTreesAreOneListThatHoldsLibraryCaches(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	// Cleaned because a job can write there when it is world-writable, which it is
	// on the Macs this was checked on. A tree that is not writable by a job holds
	// nothing the job owns, so cleaning it does no harm.
	found := false
	for _, tree := range x.u.sharedTrees() {
		found = found || tree == "/Library/Caches"
	}
	if !found {
		t.Errorf("the cleaned trees are %v; want /Library/Caches among them", x.u.sharedTrees())
	}
	// Reset and verify both read the same list.
	x.f.reset()
	if err := x.u.resetSlot(context.Background(), x.u.slotNamed("zj01")); err != nil {
		t.Fatal(err)
	}
	for _, tree := range x.u.sharedTrees() {
		if _, err := x.f.Lstat(tree); err != nil {
			continue
		}
		del, ver := x.f.indexOf("find -x -P "+tree+" -user 651 -delete"), x.f.indexOf("find -x -P "+tree+" -user 651 -print")
		if del < 0 || ver < 0 {
			t.Errorf("%s: cleaned at %d and verified at %d", tree, del, ver)
		}
	}
}

func TestResetTreatsAnAccountWithNoGuiDomainAsNothingToBootOut(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	// An account that has never logged in has no gui domain, and launchd says
	// so with exit 125 rather than "no such process".
	x.f.answerCode(125, "Boot-out failed: 125: Domain does not support specified action\n", "launchctl", "bootout", "gui/651")
	if err := x.u.resetSlot(context.Background(), x.u.slotNamed("zj01")); err != nil {
		t.Fatalf("a missing gui domain failed the reset: %v", err)
	}
}
