package config

import (
	"strings"
	"testing"
)

// jobUsersReady is a configuration job-user isolation can run with on a Mac.
func jobUsersReady() *Config {
	c := Default()
	c.Agent.Embedded = false
	c.Agent.ControllerURL = "https://zoomies.example.com"
	c.Agent.ProcessIsolation = ProcessIsolationUser
	c.Agent.Backend = "process"
	c.Agent.Capacity = 4
	c.Agent.FinishedRetention = 0
	c.Note("agent.process_isolation", SourceFile)
	return c
}

func jobUsersFindings(c *Config, goos string) Findings {
	var out Findings
	c.validateAgentOn(goos, func(f Finding) { out = append(out, f) })
	return out
}

func findingCodes(fs Findings) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Code)
	}
	return out
}

func TestJobUsersAcceptsAConfigurationItCanRunWith(t *testing.T) {
	got := jobUsersFindings(jobUsersReady(), "darwin")
	for _, f := range got {
		if f.Severity == SeverityError {
			t.Errorf("a ready configuration was refused: %s: %s", f.Code, f.Title)
		}
	}
}

func TestJobUsersIsRefusedOffMacOS(t *testing.T) {
	for _, goos := range []string{"linux", "windows"} {
		if got := jobUsersFindings(jobUsersReady(), goos); !hasCode(got, "agent.job_users_not_macos") {
			t.Errorf("%s: %v", goos, findingCodes(got))
		}
	}
	if got := jobUsersFindings(jobUsersReady(), "darwin"); hasCode(got, "agent.job_users_not_macos") {
		t.Error("a Mac was refused")
	}
}

func TestJobUsersIsRefusedOnAnEmbeddedAgent(t *testing.T) {
	c := jobUsersReady()
	c.Agent.Embedded = true
	if got := jobUsersFindings(c, "darwin"); !hasCode(got, "agent.job_users_embedded") {
		t.Errorf("embedded: %v", findingCodes(got))
	}
	c = jobUsersReady()
	c.Agent.ControllerURL = ""
	if got := jobUsersFindings(c, "darwin"); !hasCode(got, "agent.job_users_embedded") {
		t.Errorf("no controller URL: %v", findingCodes(got))
	}
}

func TestJobUsersIsRefusedWithAFinishedRetention(t *testing.T) {
	c := jobUsersReady()
	c.Agent.FinishedRetention = 10 * 60 * 1e9
	if got := jobUsersFindings(c, "darwin"); !hasCode(got, "agent.job_users_finished_retention") {
		t.Errorf("%v", findingCodes(got))
	}
}

func TestJobUsersIsRefusedWithACapacityOver47(t *testing.T) {
	c := jobUsersReady()
	c.Agent.Capacity = MaxJobUsersCapacity + 1
	if got := jobUsersFindings(c, "darwin"); !hasCode(got, "agent.job_users_capacity") {
		t.Errorf("%v", findingCodes(got))
	}
	c.Agent.Capacity = MaxJobUsersCapacity
	if got := jobUsersFindings(c, "darwin"); hasCode(got, "agent.job_users_capacity") {
		t.Error("47 was refused")
	}
}

// The two warnings say the job runs as the agent's user and as root, and in this
// mode it is neither. process_root is the one this exists to keep from firing,
// because the agent has to be root to start each job as its own account.
func TestJobUsersHostGetsNeitherProcessWarning(t *testing.T) {
	old := euid
	euid = func() int { return 0 }
	t.Cleanup(func() { euid = old })

	got := jobUsersFindings(jobUsersReady(), "darwin")
	for _, code := range []string{"agent.process_backend", "agent.process_root"} {
		if hasCode(got, code) {
			t.Errorf("a job-user host was warned with %s", code)
		}
	}
	// Both still fire where they are true.
	none := jobUsersReady()
	none.Agent.ProcessIsolation = ProcessIsolationNone
	got = jobUsersFindings(none, "darwin")
	for _, code := range []string{"agent.process_backend", "agent.process_root"} {
		if !hasCode(got, code) {
			t.Errorf("isolation none no longer warns with %s", code)
		}
	}
}

func TestJobUsersIsAProcessIsolationChoiceTheRemoteMacRuleKnows(t *testing.T) {
	c := jobUsersReady()
	// In the environment only, it does not count, as for the other modes.
	c.Note("agent.process_isolation", SourceEnvironment)
	got := c.ProcessIsolationFindings("darwin")
	var required *Finding
	for i := range got {
		if got[i].Code == "agent.process_isolation_required" {
			required = &got[i]
		}
	}
	if required == nil || !strings.Contains(required.Fix, "process_isolation: user") {
		t.Fatalf("findings = %v; want the file rule, naming user as a choice", findingCodes(got))
	}
	if got := jobUsersReady().ProcessIsolationFindings("darwin"); hasCode(got, "agent.process_isolation_required") || hasCode(got, "agent.vmpal_invalid") {
		t.Errorf("user was refused as an unknown mode: %v", findingCodes(got))
	}
}

// The mode takes no settings of its own: it restricts no network traffic, so
// there is no list of targets to check, and agent.capacity is the only dial.
func TestJobUsersHasNoSettingsOfItsOwn(t *testing.T) {
	for _, s := range Settings() {
		if strings.HasPrefix(s.Key, "agent.job_users") {
			t.Errorf("%s is a setting; job users are chosen with agent.process_isolation and sized with agent.capacity", s.Key)
		}
	}
}
