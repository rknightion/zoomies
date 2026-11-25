package backend

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestEnsureSlotsRefusesAnAccountWithTheWrongUID(t *testing.T) {
	x := newJobUserFixture(t, 2)
	// A person's account that happens to have one of our names.
	x.f.users["zj02"] = 501

	err := x.u.ensureSlots(context.Background())
	if err == nil || !errors.Is(err, ErrBackendConfig) || !strings.Contains(err.Error(), "zj02") || !strings.Contains(err.Error(), "501") {
		t.Fatalf("ensureSlots = %v; want a refusal naming zj02 and its UID 501", err)
	}
	// Nothing is made or wiped on a host that is not what Zoomies would have made.
	if n := x.f.count("sysadminctl"); n != 0 {
		t.Errorf("%d sysadminctl commands ran before the refusal", n)
	}
	if n := x.f.count("dscl . -create"); n != 0 {
		t.Errorf("%d dscl writes ran before the refusal", n)
	}
}

func TestEnsureSlotsRefusesAUIDHeldByAnotherName(t *testing.T) {
	x := newJobUserFixture(t, 2)
	// UID 652 is zj02's, and a different account has it.
	x.f.users["buildbot"] = 652

	err := x.u.ensureSlots(context.Background())
	if err == nil || !strings.Contains(err.Error(), "buildbot") || !strings.Contains(err.Error(), "652") {
		t.Fatalf("ensureSlots = %v; want a refusal naming buildbot and UID 652", err)
	}
	if x.f.count("sysadminctl") != 0 {
		t.Error("an account was made on a host where the UID range is somebody else's")
	}
}

func TestEnsureSlotsRefusesAGroupThatHasTheWrongGID(t *testing.T) {
	for name, groups := range map[string]map[string]int{
		"our group with another GID":      {jobUserGroup: 700},
		"another group with our GID":      {"builders": jobUserGID},
		"our group already right is fine": nil,
	} {
		x := newJobUserFixture(t, 1)
		for g, id := range groups {
			x.f.groups[g] = id
		}
		err := x.u.ensureSlots(context.Background())
		if groups == nil {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: ensureSlots went ahead", name)
		}
	}
}

func TestEnsureSlotsCreatesTheGroupBeforeTheAccounts(t *testing.T) {
	x := newJobUserFixture(t, 2)
	if err := x.u.ensureSlots(context.Background()); err != nil {
		t.Fatal(err)
	}
	group := x.f.indexOf("dscl . -create /Groups/_zjobs PrimaryGroupID 650")
	account := x.f.indexOf("sysadminctl -addUser zj01")
	if group < 0 || account < 0 || group > account {
		t.Fatalf("group created at %d and the first account at %d; the group has to come first, or the account starts in staff", group, account)
	}
	// Capacity 2 means three accounts, each in the new group and hidden.
	for _, name := range []string{"zj01", "zj02", "zj03"} {
		if x.f.indexOf("sysadminctl -addUser "+name+" -UID") < 0 {
			t.Errorf("%s was not made", name)
		}
		if x.f.indexOf("dscl . -create /Users/"+name+" PrimaryGroupID 650") < 0 || x.f.indexOf("dscl . -create /Users/"+name+" IsHidden 1") < 0 {
			t.Errorf("%s was not put in %s and hidden", name, jobUserGroup)
		}
	}
	if x.f.indexOf("zj04") >= 0 {
		t.Error("an account was made beyond capacity plus one")
	}
	if x.f.users["zj03"] != 653 {
		t.Errorf("zj03 has UID %d, want 653", x.f.users["zj03"])
	}
}

func TestEnsureSlotsGivesEachNewAccountARandomPasswordAndMakesNothingTwice(t *testing.T) {
	x := newJobUserFixture(t, 1)
	if err := x.u.ensureSlots(context.Background()); err != nil {
		t.Fatal(err)
	}
	cmd := x.f.logged()[x.f.indexOf("sysadminctl -addUser zj01")]
	fields := strings.Fields(cmd)
	var pw string
	for i, f := range fields {
		if f == "-password" && i+1 < len(fields) {
			pw = fields[i+1]
		}
	}
	if len(pw) < 40 {
		t.Fatalf("the password argument is %q; want 32 random bytes in base64", pw)
	}
	x.f.reset()
	// A second run finds the accounts there, in the group, and makes nothing.
	if err := x.u.ensureSlots(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := x.f.count("sysadminctl"); n != 0 {
		t.Errorf("%d accounts were made a second time", n)
	}
}

func TestEnsureSlotsRefusesAnExistingAccountInTheWrongGroup(t *testing.T) {
	x := newJobUserFixture(t, 1)
	x.f.users["zj01"] = 651
	x.f.users["zj02"] = 652
	x.f.groups[jobUserGroup] = jobUserGID
	// zj01 is in staff, which is how sysadminctl leaves an account, and the leak
	// the group exists to close.
	x.f.groupOf["zj01"] = 20
	x.f.groupOf["zj02"] = jobUserGID

	err := x.u.ensureSlots(context.Background())
	if err == nil || !strings.Contains(err.Error(), "zj01") || !strings.Contains(err.Error(), "primary group") {
		t.Fatalf("ensureSlots = %v; want a refusal about zj01's primary group", err)
	}
}

func TestEnsureSlotsNeitherMakesNorOffersAccountsAboveAReducedCapacity(t *testing.T) {
	x := newJobUserFixture(t, 1)
	for n := 1; n <= 4; n++ {
		x.f.users[jobUserName(n)] = jobUserUID(n)
		x.f.groupOf[jobUserName(n)] = jobUserGID
	}
	x.f.groups[jobUserGroup] = jobUserGID

	if err := x.u.ensureSlots(context.Background()); err != nil {
		t.Fatal(err)
	}
	// They are checked, because they are Zoomies's to wipe when a job that was
	// running in one is removed, but not made, deleted or changed.
	if x.f.count("sysadminctl") != 0 || x.f.count("dscl . -create /Users/zj03") != 0 || x.f.count("dscl . -create /Users/zj04") != 0 {
		t.Errorf("an account above capacity plus one was changed: %v", x.f.logged())
	}
	if x.u.slotNamed("zj03").offered {
		t.Error("zj03 is offered to jobs")
	}
}

func TestEnsureSlotsGivesNewAccountsNoLoginShell(t *testing.T) {
	x := newJobUserFixture(t, 1)
	if err := x.u.ensureSlots(context.Background()); err != nil {
		t.Fatal(err)
	}
	// With Remote Login open to every user, a login shell would let a job write
	// an authorized_keys file and have somebody log in as the slot afterwards.
	for _, name := range []string{"zj01", "zj02"} {
		if got := x.f.shellOf[name]; got != "/usr/bin/false" {
			t.Errorf("%s has the login shell %q; want /usr/bin/false", name, got)
		}
	}
	if x.f.indexOf("-shell /bin/zsh") >= 0 {
		t.Errorf("an account was made with a real login shell: %v", x.f.logged())
	}
}

func TestEnsureSlotsCorrectsAnExistingAccountsLoginShell(t *testing.T) {
	x := newJobUserFixture(t, 1)
	x.f.users["zj01"] = 651
	x.f.groupOf["zj01"] = jobUserGID
	x.f.shellOf["zj01"] = "/bin/zsh"
	x.f.groups[jobUserGroup] = jobUserGID

	if err := x.u.ensureSlots(context.Background()); err != nil {
		t.Fatal(err)
	}
	if x.f.shellOf["zj01"] != "/usr/bin/false" || x.f.indexOf("dscl . -create /Users/zj01 UserShell /usr/bin/false") < 0 {
		t.Errorf("zj01's shell is %q and the log is %v", x.f.shellOf["zj01"], x.f.logged())
	}
}

func TestEnsureSlotsRefusesAnExistingAccountThatIsAnAdministratorOrLivesElsewhere(t *testing.T) {
	for name, tc := range map[string]struct {
		set  func(f *fakeJobUsers)
		want string
	}{
		"an administrator": {func(f *fakeJobUsers) { f.admins["zj02"] = true }, "admin"},
		"a home elsewhere": {func(f *fakeJobUsers) { f.homeOf["zj02"] = "/Users/alice" }, "/Users/alice"},
	} {
		x := newJobUserFixture(t, 2)
		x.f.groups[jobUserGroup] = jobUserGID
		for _, n := range []string{"zj01", "zj02"} {
			x.f.users[n] = jobUserUID(int(n[3] - '0'))
			x.f.groupOf[n] = jobUserGID
		}
		// A shell that would be corrected, so that a refusal that came late would show.
		x.f.shellOf["zj01"] = "/bin/zsh"
		tc.set(x.f)

		err := x.u.ensureSlots(context.Background())
		if err == nil || !errors.Is(err, ErrBackendConfig) || !strings.Contains(err.Error(), "zj02") || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: ensureSlots = %v; want a refusal naming zj02 and %q", name, err, tc.want)
		}
		// Whatever the account is, the host is not changed on the way to refusing it.
		if x.f.count("sysadminctl") != 0 || x.f.count("dscl . -create") != 0 {
			t.Errorf("%s: the host was changed before the refusal: %v", name, x.f.logged())
		}
	}
}

func TestEnsureSlotsRefusesWhenItCannotTellWhetherAnAccountIsAnAdministrator(t *testing.T) {
	x := newJobUserFixture(t, 1)
	x.f.groups[jobUserGroup] = jobUserGID
	x.f.users["zj01"] = 651
	x.f.groupOf["zj01"] = jobUserGID
	x.f.answer("something nobody expected\n", "dseditgroup")
	if err := x.u.ensureSlots(context.Background()); err == nil || !strings.Contains(err.Error(), "zj01") {
		t.Fatalf("ensureSlots = %v; want a refusal, because an account that may be an administrator is not wiped", err)
	}
}

func TestParseJobUserProcessesReadsPsAndRefusesWhatItCannotRead(t *testing.T) {
	procs, err := parseJobUserProcesses("  1     0     0\n 4242   651   650\n")
	if err != nil || len(procs) != 2 || procs[1] != (jobUserProc{PID: 4242, RUID: 651, EUID: 650}) {
		t.Fatalf("got %v, %v", procs, err)
	}
	if _, err := parseJobUserProcesses("12 x 0\n"); err == nil {
		t.Error("a line that is not numbers was read")
	}
	if _, err := parseJobUserProcesses("12 0\n"); err == nil {
		t.Error("a short line was read")
	}
}

func TestJobUserRetryDelayIsAMinuteThenFiveThenFifteen(t *testing.T) {
	want := []string{"1m0s", "1m0s", "5m0s", "15m0s", "15m0s"}
	for i, w := range want {
		if got := jobUserRetryDelay(i).String(); got != w {
			t.Errorf("failure %d: retry after %s, want %s", i, got, w)
		}
	}
}

func TestEnsureSlotsSetsTheUIDWhenSysadminctlIgnoresIt(t *testing.T) {
	x := newJobUserFixture(t, 1)
	// On a real Mac sysadminctl gave the next free UID from 503 and ignored
	// -UID, which left the accounts outside the range the agent keys to.
	x.f.ignoreUID = true
	if err := x.u.ensureSlots(context.Background()); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]int{"zj01": 651, "zj02": 652} {
		if got := x.f.users[name]; got != want {
			t.Errorf("%s has UID %d, want %d", name, got, want)
		}
	}
}
