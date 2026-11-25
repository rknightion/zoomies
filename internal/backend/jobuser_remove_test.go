package backend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func removeFixture(t *testing.T) *jobUserFixture {
	x := startedJobUserFixture(t, 2)
	if err := os.MkdirAll(filepath.Join(x.f.usersDir, jobUserTrashName, "zj01-1"), 0o700); err != nil {
		t.Fatal(err)
	}
	x.f.reset()
	return x
}

func TestRemovingJobUsersDeletesWhatZoomiesMadeAndNothingElse(t *testing.T) {
	x := removeFixture(t)
	x.f.procs = []jobUserProc{{PID: 3, RUID: 652, EUID: 652}}

	err := RemoveJobUsers(context.Background(), RemoveJobUsersOptions{StateDir: x.state, UsersDir: x.f.usersDir, Logger: quietLogger(), system: x.f})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"zj01", "zj02", "zj03"} {
		if _, ok := x.f.users[name]; ok {
			t.Errorf("%s is still there", name)
		}
		if x.f.indexOf("sysadminctl -deleteUser "+name) < 0 {
			t.Errorf("%s was not deleted", name)
		}
	}
	if len(x.f.procs) != 0 {
		t.Error("a job user's process was left running")
	}
	// Processes first: an account is not deleted from under what runs as it.
	if kill, del := x.f.indexOf("pkill -KILL -U 652"), x.f.indexOf("sysadminctl -deleteUser zj02"); kill < 0 || kill > del {
		t.Errorf("kill at %d, delete at %d", kill, del)
	}
	if x.f.users["alice"] != 501 || x.f.users["root"] != 0 {
		t.Errorf("somebody else's account was touched: %v", x.f.users)
	}
	if _, ok := x.f.groups[jobUserGroup]; ok {
		t.Error("the group is still there")
	}
	if x.f.count("pfctl") != 0 {
		t.Errorf("pf was touched, and this mode never edits it: %v", x.f.logged())
	}
	if _, err := os.Stat(filepath.Join(x.f.usersDir, jobUserTrashName)); err == nil {
		t.Error("the trash is still there")
	}
	if _, err := os.Stat(x.state); err == nil {
		t.Error("the state folder is still there")
	}
}

func TestRemovingJobUsersRefusesAHostWhereAnAccountIsNotZoomiesOwn(t *testing.T) {
	x := removeFixture(t)
	x.f.users["zj02"] = 4242
	err := RemoveJobUsers(context.Background(), RemoveJobUsersOptions{StateDir: x.state, UsersDir: x.f.usersDir, Logger: quietLogger(), system: x.f})
	if !errors.Is(err, ErrBackendConfig) || x.f.count("deleteUser") != 0 {
		t.Fatalf("err = %v, deletions = %d; want a refusal before anything is deleted", err, x.f.count("deleteUser"))
	}
}

func TestRemovingJobUsersLeavesTheGroupWhenAnAccountCannotGo(t *testing.T) {
	x := removeFixture(t)
	x.f.fail("sysadminctl", "-deleteUser", "zj02")
	err := RemoveJobUsers(context.Background(), RemoveJobUsersOptions{StateDir: x.state, UsersDir: x.f.usersDir, Logger: quietLogger(), system: x.f})
	if err == nil || !strings.Contains(err.Error(), "zj02") {
		t.Fatalf("err = %v", err)
	}
	if _, ok := x.f.groups[jobUserGroup]; !ok {
		t.Error("the group went while an account was still there")
	}
}

func TestRemovingJobUsersNeedsTheStateFolder(t *testing.T) {
	x := removeFixture(t)
	if err := RemoveJobUsers(context.Background(), RemoveJobUsersOptions{UsersDir: x.f.usersDir, system: x.f}); err == nil {
		t.Error("removal with no state folder went ahead")
	}
}
