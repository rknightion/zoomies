package backend

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestEgressProbeIsRunAsTheReservedSlot(t *testing.T) {
	x := startedJobUserFixture(t, 2)
	s, err := x.u.admit(context.Background(), "runner-dir")
	if err != nil {
		t.Fatal(err)
	}
	if s.name != "zj01" || s.holder != "runner-dir" {
		t.Fatalf("admitted %s held by %q", s.name, s.holder)
	}
	var probes []jobUserCommand
	for _, c := range x.f.cmds {
		if len(c.Argv) > 2 && c.Argv[1] == "agent" && c.Argv[2] == "egress-probe" {
			probes = append(probes, c)
		}
	}
	// One probe for the must-allow list and one for the must-block target.
	if len(probes) != 2 {
		t.Fatalf("%d probes ran: %v", len(probes), x.f.logged())
	}
	for _, p := range probes {
		if !p.AsUser || p.UID != 651 || p.GID != jobUserGID {
			t.Errorf("a probe ran as uid %d gid %d (as user: %v), not as zj01's 651:650", p.UID, p.GID, p.AsUser)
		}
		if p.Argv[0] != "/usr/local/bin/zoomies" || p.Argv[3] != "--timeout" {
			t.Errorf("argv = %v", p.Argv)
		}
	}
	if probes[0].Argv[len(probes[0].Argv)-1] != "github.com:443" || probes[1].Argv[len(probes[1].Argv)-1] != "198.51.100.10:443" {
		t.Errorf("the probes asked about %v and %v", probes[0].Argv, probes[1].Argv)
	}
}

func TestAMustBlockTargetThatAnswersIsABreachThatHoldsTheHostAndStopsJobs(t *testing.T) {
	x := startedJobUserFixture(t, 2)
	x.f.probe = func(targets []string) []string {
		out := make([]string, len(targets))
		for i := range out {
			out[i] = vmpalEgressConnected
		}
		return out
	}
	x.f.procs = []jobUserProc{{PID: 600, RUID: 653, EUID: 653}}

	_, err := x.u.admit(context.Background(), "runner-dir")
	var egress *jobUserEgressError
	if !errors.As(err, &egress) || !egress.failure.Breach {
		t.Fatalf("admit = %v; want a breach", err)
	}
	if !strings.Contains(err.Error(), "198.51.100.10:443") || !strings.Contains(err.Error(), "job user") {
		t.Errorf("the error does not say what answered: %v", err)
	}
	if held := x.u.state.held(); !errors.Is(held, errJobUsersHeld) {
		t.Errorf("held = %v", held)
	}
	if len(x.f.procs) != 0 {
		t.Error("a job admitted under a policy that does not hold was left running")
	}
	if x.u.slotNamed("zj01").holder != "" {
		t.Error("the slot stayed reserved after the refusal")
	}
	// A refusal and a connection both mean packets got there.
	x.f.probe = func(targets []string) []string {
		out := make([]string, len(targets))
		for i := range out {
			out[i] = vmpalEgressRefused
		}
		return out
	}
	x.u.state.file.HoldUntil = x.u.now().Add(-1)
	if _, err := x.u.admit(context.Background(), "again"); !errors.As(err, &egress) {
		t.Errorf("a refusal was not treated as a breach: %v", err)
	}
}

func TestAMustBlockTargetTheAgentCannotReachProvesNothing(t *testing.T) {
	x := startedJobUserFixture(t, 1, func(o *JobUserOptions) {
		o.EgressDial = func(context.Context, string) error { return errors.New("no route") }
	})
	_, err := x.u.admit(context.Background(), "runner-dir")
	var egress *jobUserEgressError
	if !errors.As(err, &egress) || egress.failure.Breach {
		t.Fatalf("admit = %v; want a check that could not tell, not a breach", err)
	}
	if !strings.Contains(err.Error(), "the Mac could not reach must-block target 198.51.100.10:443") {
		t.Errorf("error = %v", err)
	}
	if x.u.state.held() == nil {
		t.Error("a check that could not tell did not hold the host")
	}
}

func TestAMustAllowTargetThatCannotBeReachedFailsTheCheck(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	x.f.probe = func(targets []string) []string {
		out := make([]string, len(targets))
		for i, tg := range targets {
			out[i] = vmpalEgressTimeout
			if strings.HasPrefix(tg, "github") {
				out[i] = vmpalEgressUnreachable
			}
		}
		return out
	}
	_, err := x.u.admit(context.Background(), "runner-dir")
	if err == nil || !strings.Contains(err.Error(), "the job user could not reach github.com:443") {
		t.Fatalf("admit = %v", err)
	}
}

func TestAProbeThatCannotRunOrBeReadFailsTheCheck(t *testing.T) {
	for name, set := range map[string]func(x *jobUserFixture){
		"exits non-zero": func(x *jobUserFixture) { x.f.fail("zoomies", "agent", "egress-probe") },
		"garbled": func(x *jobUserFixture) {
			x.f.answer("hello\n", "zoomies", "agent", "egress-probe")
		},
		"cut short": func(x *jobUserFixture) {
			x.f.answer("zoomies-egress v1 target 0 connected\n", "zoomies", "agent", "egress-probe")
		},
	} {
		x := startedJobUserFixture(t, 1)
		set(x)
		_, err := x.u.admit(context.Background(), "runner-dir")
		if err == nil || !strings.Contains(err.Error(), "could not run the check") {
			t.Errorf("%s: admit = %v", name, err)
		}
	}
}

func TestAHeldHostRefusesBeforeAnythingIsReserved(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	x.u.state.startHold(vmpalEgressHold, "testing")
	x.f.reset()
	_, err := x.u.admit(context.Background(), "runner-dir")
	if !errors.Is(err, errJobUsersHeld) || !strings.Contains(err.Error(), "testing") {
		t.Fatalf("admit = %v", err)
	}
	if len(x.f.logged()) != 0 || x.u.slotNamed("zj01").holder != "" {
		t.Errorf("a held host ran %v", x.f.logged())
	}
}

func TestAnUncleanSlotIsResetAndAnUncleanableOneIsSkipped(t *testing.T) {
	x := startedJobUserFixture(t, 2)
	x.f.procs = []jobUserProc{{PID: 1, RUID: 651, EUID: 651}}
	// zj01 has a process left: it is reset first and then used.
	s, err := x.u.admit(context.Background(), "a")
	if err != nil || s.name != "zj01" {
		t.Fatalf("admit = %v, %v", s, err)
	}
	if x.f.indexOf("createhomedir -c -u zj01") < 0 {
		t.Error("an unclean slot was used without a reset")
	}
	// zj02 cannot be cleaned: the next job gets zj03 and zj02 is out of service.
	x.f.fail("createhomedir", "-c", "-u", "zj02")
	x.f.procs = []jobUserProc{{PID: 2, RUID: 652, EUID: 652}}
	s, err = x.u.admit(context.Background(), "b")
	if err != nil || s.name != "zj03" {
		t.Fatalf("admit = %v, %v; want zj03", s, err)
	}
	if x.u.slotNamed("zj02").healthy {
		t.Error("zj02 is still in service")
	}
	if got := x.u.unhealthy(); len(got) != 1 || !strings.Contains(got[0], fmt.Sprint("zj02")) {
		t.Errorf("unhealthy = %v", got)
	}
}

func TestAMustBlockTargetThatIsUnreachableFromTheJobUserAloneCountsAsBlocked(t *testing.T) {
	// The agent reached the target over the same routes, so the firewall is the
	// only difference between the two. pf can answer a packet it blocks with an
	// error from the kernel as well as with silence.
	x := startedJobUserFixture(t, 1)
	x.f.probe = func(targets []string) []string {
		out := make([]string, len(targets))
		for i, tg := range targets {
			out[i] = vmpalEgressUnreachable
			if strings.HasPrefix(tg, "github") {
				out[i] = vmpalEgressConnected
			}
		}
		return out
	}
	if _, err := x.u.admit(context.Background(), "runner-dir"); err != nil {
		t.Fatalf("a must-block target the agent reached and the job user got EHOSTUNREACH for was not read as blocked: %v", err)
	}
	if x.u.state.held() != nil {
		t.Error("the host was held for a firewall that works")
	}

	// A target the agent cannot reach proves nothing, whatever the job user gets.
	y := startedJobUserFixture(t, 1, func(o *JobUserOptions) {
		o.EgressDial = func(context.Context, string) error { return errors.New("no route") }
	})
	y.f.probe = x.f.probe
	_, err := y.u.admit(context.Background(), "runner-dir")
	var egress *jobUserEgressError
	if !errors.As(err, &egress) || egress.failure.Breach {
		t.Fatalf("admit = %v; want a check that could not tell", err)
	}
}

func TestANetworkErrorOtherThanUnreachableStillFailsTheCheck(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	x.f.probe = func(targets []string) []string {
		out := make([]string, len(targets))
		for i, tg := range targets {
			out[i] = vmpalEgressError
			if strings.HasPrefix(tg, "github") {
				out[i] = vmpalEgressConnected
			}
		}
		return out
	}
	_, err := x.u.admit(context.Background(), "runner-dir")
	var egress *jobUserEgressError
	if !errors.As(err, &egress) || egress.failure.Breach || !strings.Contains(err.Error(), "rather than timing out") {
		t.Fatalf("admit = %v; want a doubt about an error that is neither a timeout nor unreachable", err)
	}
}

func TestABreachStopsTheJobsOfEveryAccountThatExistsAndNotOnlyTheOfferedOnes(t *testing.T) {
	// Capacity 1 offers zj01 and zj02; zj04 and zj05 are what a bigger capacity
	// left, and a job that survived an agent restart can be running as one.
	x := startedJobUserFixtureWithAccounts(t, 1, 5)
	x.f.probe = func(targets []string) []string {
		out := make([]string, len(targets))
		for i := range out {
			out[i] = vmpalEgressConnected
		}
		return out
	}
	x.f.procs = []jobUserProc{{PID: 700, RUID: 654, EUID: 654}, {PID: 701, RUID: 655, EUID: 655}, {PID: 702, RUID: 501, EUID: 501}}
	_, err := x.u.admit(context.Background(), "runner-dir")
	var egress *jobUserEgressError
	if !errors.As(err, &egress) || !egress.failure.Breach {
		t.Fatalf("admit = %v; want a breach", err)
	}
	if len(x.f.procs) != 1 || x.f.procs[0].PID != 702 {
		t.Errorf("processes left = %v; want only the person's, at UID 501", x.f.procs)
	}
}

func TestALostFirewallStopsTheJobsOfEveryAccountThatExists(t *testing.T) {
	x := startedJobUserFixtureWithAccounts(t, 1, 5)
	x.f.procs = []jobUserProc{{PID: 700, RUID: 654, EUID: 654}, {PID: 701, RUID: 655, EUID: 655}, {PID: 702, RUID: 501, EUID: 501}}
	x.f.pfRules = ""
	x.u.watchOnce(context.Background())
	if len(x.f.procs) != 1 || x.f.procs[0].PID != 702 {
		t.Errorf("processes left = %v; want only the person's, at UID 501", x.f.procs)
	}
}

func TestACreatePastTheFirewallCheckDoesNotStartWhenTheHostIsHeldAfterwards(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	ctx := context.Background()
	fired := false
	x.f.mu.Lock()
	x.f.onRun = func(c jobUserCommand) {
		// The create's egress check: its last question is the must-block target,
		// asked as the job user. The watcher finds the firewall gone just then.
		if fired || !c.AsUser || !slices.Contains(c.Argv, "198.51.100.10:443") {
			return
		}
		fired = true
		x.u.firewallLost(ctx, errors.New("flushed behind the agent's back"))
	}
	x.f.mu.Unlock()

	_, err := x.b.CreateWithResult(ctx, jobUserSpec("runner-a"))
	if !fired {
		t.Fatal("the test never reached the egress check")
	}
	if !errors.Is(err, errJobUsersHeld) {
		t.Fatalf("create = %v; want the hold that started while it was being made", err)
	}
	if len(x.f.started) != 0 {
		t.Error("a runner was started after the firewall was found lost, so it would run unwatched until the next pass")
	}
	if x.u.slotNamed("zj01").holder != "" {
		t.Error("the slot stayed reserved")
	}
	if entries, _ := os.ReadDir(filepath.Join(x.root, runnersDirName)); len(entries) != 0 {
		t.Errorf("%d records left", len(entries))
	}
}
