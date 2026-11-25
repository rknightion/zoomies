package backend

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderAnchorBlocksEveryInterfaceAddressButLoopback(t *testing.T) {
	got := renderJobUserAnchor([]string{"zj01", "zj02"}, []jobUserIface{
		{Name: "utun3", HasAddr: true},
		{Name: "lo0", HasAddr: true},
		{Name: "en0", HasAddr: true},
		{Name: "bridge100"}, // no address: nothing to block
		{Name: "en1; pass all", HasAddr: true},
	})
	want := `block drop out quick inet from any to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 } user { zj01, zj02 }
block drop out quick inet6 from any to ! ::1 user { zj01, zj02 }
block drop out quick from any to { (en0), (utun3) } user { zj01, zj02 }
`
	if got != want {
		t.Fatalf("anchor:\n%s\nwant:\n%s", got, want)
	}
	// Loopback has to stay open for a job's own servers, and nothing here may
	// block "to self" or "on ! lo0", neither of which does what it seems to.
	for _, bad := range []string{"lo0", "to self", "! lo0", "127."} {
		if strings.Contains(got, bad) {
			t.Errorf("the anchor mentions %q", bad)
		}
	}
}

func TestRenderAnchorLeavesOutTheInterfaceRuleWhenNothingHasAnAddress(t *testing.T) {
	got := renderJobUserAnchor([]string{"zj01"}, []jobUserIface{{Name: "lo0", HasAddr: true}})
	if strings.Count(got, "\n") != 2 || strings.Contains(got, "{ }") {
		t.Fatalf("anchor:\n%s", got)
	}
}

func TestLoadingTheAnchorSendsItsTextOnStandardInputAndKeepsPFsReadBack(t *testing.T) {
	x := startedJobUserFixture(t, 2)
	// StartJobUsers loaded it once already; this is a restart.
	x.f.reset()
	if err := x.u.pf.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	var load *jobUserCommand
	for i := range x.f.cmds {
		if hasPrefix(x.f.cmds[i].Argv, []string{"pfctl", "-a", jobUserAnchor, "-f", "-"}) {
			load = &x.f.cmds[i]
		}
	}
	if load == nil {
		t.Fatalf("the anchor was not loaded: %v", x.f.logged())
	}
	for _, name := range []string{"zj01", "zj02", "zj03"} {
		if !strings.Contains(load.Stdin, name) {
			t.Errorf("the anchor does not name %s", name)
		}
	}
	// The earlier reference is released, so restarts do not pile up references
	// that keep pf on after the agent is gone, but only after the new one is
	// taken: released first, pf would be off between the two whenever this
	// agent held its only reference.
	release := x.f.indexOf("pfctl -X 42")
	take := x.f.indexOf("pfctl -E")
	if release < 0 || take < 0 || release < take {
		t.Errorf("release at %d, enable at %d; want the new token taken first: %v", release, take, x.f.logged())
	}
	tok, err := os.ReadFile(filepath.Join(x.state, "pf.token"))
	if err != nil || strings.TrimSpace(string(tok)) != "43" {
		t.Errorf("token file = %q, %v; want 43", tok, err)
	}
	if x.u.pf.baseline != strings.TrimSpace(x.f.pfRules) {
		t.Errorf("baseline %q is not what pf read back %q", x.u.pf.baseline, x.f.pfRules)
	}
}

func TestVerifyingTheAnchorFindsItMissingDifferentOrPFOff(t *testing.T) {
	cases := map[string]func(x *jobUserFixture){
		"flushed":         func(x *jobUserFixture) { x.f.pfRules = "" },
		"changed":         func(x *jobUserFixture) { x.f.pfRules = "pass all\n" },
		"pf switched off": func(x *jobUserFixture) { x.f.answer("Status: Disabled\n", "pfctl", "-s", "info") },
		"pfctl failing":   func(x *jobUserFixture) { x.f.fail("pfctl", "-a") },
	}
	for name, break_ := range cases {
		x := startedJobUserFixture(t, 1)
		if err := x.u.pf.verify(context.Background()); err != nil {
			t.Fatalf("%s: a fresh anchor did not verify: %v", name, err)
		}
		break_(x)
		if err := x.u.pf.verify(context.Background()); err == nil {
			t.Errorf("%s: the anchor was accepted", name)
		}
	}
}

func TestVerifyingTheAnchorReloadsItWhenTheInterfacesChange(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	x.f.ifaces = append(x.f.ifaces, jobUserIface{Name: "utun9", HasAddr: true})
	x.f.reset()

	if err := x.u.pf.verify(context.Background()); err != nil {
		t.Fatalf("a changed interface list is not an incident: %v", err)
	}
	if x.f.indexOf("pfctl -a "+jobUserAnchor+" -f -") < 0 || !strings.Contains(x.f.pfRules, "(utun9)") {
		t.Errorf("the anchor was not rendered again: %q", x.f.pfRules)
	}
	if err := x.u.pf.verify(context.Background()); err != nil {
		t.Errorf("after the reload: %v", err)
	}
}

func TestAFailedEnableLeavesTheEarlierReferenceInPlace(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	x.f.fail("pfctl", "-E")
	if err := x.u.pf.load(context.Background()); err == nil {
		t.Fatal("a pfctl -E that failed was accepted")
	}
	if x.f.indexOf("pfctl -X") >= 0 {
		t.Errorf("the old reference was released although no new one was taken, so pf could be left off: %v", x.f.logged())
	}
	tok, err := os.ReadFile(filepath.Join(x.state, "pf.token"))
	if err != nil || strings.TrimSpace(string(tok)) != "42" {
		t.Errorf("token file = %q, %v; want the earlier 42 kept", tok, err)
	}
}

func TestTheAnchorBlocksAllIPv6ButLoopbackForJobUsers(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	var v6 []string
	for _, line := range strings.Split(x.f.pfRules, "\n") {
		if strings.Contains(line, "inet6") {
			v6 = append(v6, line)
		}
	}
	if len(v6) != 1 || !strings.Contains(v6[0], "to ! ::1") || strings.Contains(v6[0], "fc00") {
		t.Fatalf("IPv6 rules = %q; want one rule blocking everything but ::1, because a dual-stack LAN's hosts have global addresses a list of private ranges would miss", v6)
	}
}

func TestTheAnchorNamesEveryAccountThatExistsAndNotOnlyTheOfferedOnes(t *testing.T) {
	// An earlier agent ran with a bigger capacity and left zj03 to zj05 behind.
	// A job that survives a restart can be running as one of them.
	x := startedJobUserFixtureWithAccounts(t, 1, 5)
	for _, name := range []string{"zj01", "zj02", "zj03", "zj04", "zj05"} {
		if !strings.Contains(x.f.pfRules, name) {
			t.Errorf("the anchor does not name %s: %s", name, x.f.pfRules)
		}
	}
	if strings.Contains(x.f.pfRules, "zj06") {
		t.Errorf("the anchor names an account that does not exist, which pf would refuse: %s", x.f.pfRules)
	}
}

func TestAnAnchorThatReadsBackEmptyIsNotAccepted(t *testing.T) {
	x := newJobUserFixture(t, 1)
	x.f.answer("", "pfctl", "-a", jobUserAnchor, "-sr")
	if err := x.u.pf.load(context.Background()); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("load = %v; want a refusal of an anchor that reads back empty", err)
	}
}
