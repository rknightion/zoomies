package config

import (
	"os"
	"path/filepath"
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
	c.Agent.JobUsers = JobUsersConfig{
		EgressMustAllow: []string{"github.com:443"},
		EgressMustBlock: []string{"198.51.100.10:443", "203.0.113.7:22"},
	}
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

func TestJobUsersIsRefusedWithoutBothEgressLists(t *testing.T) {
	cases := map[string]struct {
		change  func(*JobUsersConfig)
		setting string
	}{
		"no allow list":           {func(j *JobUsersConfig) { j.EgressMustAllow = nil }, "agent.job_users.egress_must_allow"},
		"no block list":           {func(j *JobUsersConfig) { j.EgressMustBlock = nil }, "agent.job_users.egress_must_block"},
		"an allow target no port": {func(j *JobUsersConfig) { j.EgressMustAllow = []string{"github.com"} }, "agent.job_users.egress_must_allow"},
		"a block target by name":  {func(j *JobUsersConfig) { j.EgressMustBlock = []string{"example.com:443"} }, "agent.job_users.egress_must_block"},
		"an IPv6 block target":    {func(j *JobUsersConfig) { j.EgressMustBlock = []string{"[2001:db8::1]:443"} }, "agent.job_users.egress_must_block"},
		"a loopback block target": {func(j *JobUsersConfig) { j.EgressMustBlock = []string{"127.0.0.1:22"} }, "agent.job_users.egress_must_block"},
		"an IPv6 allow target":    {func(j *JobUsersConfig) { j.EgressMustAllow = []string{"[2001:db8::1]:443"} }, "agent.job_users.egress_must_allow"},
		"more than eight in total": {func(j *JobUsersConfig) {
			j.EgressMustBlock = []string{"198.51.100.1:1", "198.51.100.2:1", "198.51.100.3:1", "198.51.100.4:1", "198.51.100.5:1", "198.51.100.6:1", "198.51.100.7:1", "198.51.100.8:1"}
		}, "agent.job_users.egress_must_allow"},
	}
	for name, tc := range cases {
		c := jobUsersReady()
		tc.change(&c.Agent.JobUsers)
		found := false
		for _, f := range jobUsersFindings(c, "darwin") {
			if f.Code == "agent.job_users_invalid" && f.Setting == tc.setting && f.Severity == SeverityError && f.Fix != "" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no agent.job_users_invalid naming %s", name, tc.setting)
		}
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

func TestLoadJobUsersFileIsStrict(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "job-users.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	got, err := LoadJobUsersFile(write("agent:\n  job_users:\n    egress_must_allow: [\"github.com:443\"]\n    egress_must_block: [\"198.51.100.10:443\"]\n"))
	if err != nil || len(got.EgressMustAllow) != 1 || got.EgressMustBlock[0] != "198.51.100.10:443" {
		t.Fatalf("got %+v, %v", got, err)
	}
	for name, body := range map[string]string{
		"a misspelt key":  "agent:\n  job_users:\n    egress_must_alow: [x]\n",
		"another section": "agent:\n  capacity: 4\n",
		"two documents":   "agent:\n  job_users: {}\n---\nagent: {}\n",
		"nothing":         "",
	} {
		if _, err := LoadJobUsersFile(write(body)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := LoadJobUsersFile(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("a missing file was accepted")
	}
}

func TestJobUsersSettingsAreInTheRegistryAndTheEnvironment(t *testing.T) {
	t.Setenv("ZOOMIES_AGENT_JOB_USERS_EGRESS_MUST_ALLOW", "github.com:443")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Agent.JobUsers.EgressMustAllow) != 1 || c.Agent.JobUsers.EgressMustAllow[0] != "github.com:443" {
		t.Errorf("job_users.egress_must_allow = %v", c.Agent.JobUsers.EgressMustAllow)
	}
	for _, key := range []string{"agent.job_users.egress_must_allow", "agent.job_users.egress_must_block"} {
		found := false
		for _, s := range Settings() {
			if s.Key == key && s.Scope == ScopeLocal {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is not a local setting in the registry", key)
		}
	}
}
