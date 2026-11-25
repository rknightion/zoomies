package installer

import (
	"strings"
	"testing"

	"github.com/eyupio/zoomies/internal/config"
	"github.com/eyupio/zoomies/internal/store"
)

func jobUsersJoinOptions() JoinOptions {
	return JoinOptions{
		ControllerURL:    "https://zoomies.example.com",
		ProcessIsolation: config.ProcessIsolationUser,
		Capacity:         4,
	}
}

func TestJoinAcceptsUserIsolationOnlyAsRoot(t *testing.T) {
	mac := Detection{OS: "darwin", Root: true, CPUs: 10}
	got, err := decideJoinIsolation(jobUsersJoinOptions(), mac)
	if err != nil || !got.usesUser() {
		t.Fatalf("as root on a Mac: %+v, %v", got, err)
	}

	cases := []struct {
		name   string
		change func(*JoinOptions, *Detection)
		want   string
	}{
		{"not root", func(_ *JoinOptions, d *Detection) { d.Root = false }, "as root"},
		{"not a Mac", func(_ *JoinOptions, d *Detection) { d.OS = "linux" }, "only runs on a Mac"},
		{"the docker backend", func(o *JoinOptions, _ *Detection) { o.Backend = store.BackendDocker }, "--backend"},
		{"a Docker socket", func(o *JoinOptions, _ *Detection) { o.DockerHost = "unix:///var/run/docker.sock" }, "--docker-host"},
		{"a capacity over 47", func(o *JoinOptions, _ *Detection) { o.Capacity = 48 }, "agent.capacity"},
		{"a Mac that was not asked", func(o *JoinOptions, _ *Detection) { o.ProcessIsolation = "" }, "--process-isolation user"},
	}
	for _, tc := range cases {
		opts, det := jobUsersJoinOptions(), mac
		tc.change(&opts, &det)
		_, err := decideJoinIsolation(opts, det)
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "nothing has been redeemed") {
			t.Errorf("%s: err = %v; want %q and an unspent token", tc.name, err, tc.want)
		}
	}
}

func TestTheLaunchdPlistCarriesTheEnvironmentOfARootAgent(t *testing.T) {
	spec := ServiceSpec{
		Unit: UnitAgent, ExecPath: "/usr/local/bin/zoomies", ConfigFile: JobUsersSupportDir + "/zoomies.yaml",
		User: "root", Group: "wheel", StateDir: JobUsersSupportDir,
		Env: []ServiceEnv{{Name: "ZOOMIES_CONFIG_DIR", Value: JobUsersSupportDir}, {Name: "ZOOMIES_STATE_DIR", Value: JobUsersSupportDir}},
	}
	got, err := RenderLaunchdPlist(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"<key>ZOOMIES_CONFIG_DIR</key>\n\t\t<string>/Library/Application Support/zoomies</string>",
		"<key>ZOOMIES_STATE_DIR</key>",
		"<string>/usr/local/bin/zoomies</string>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("plist lacks %q:\n%s", want, got)
		}
	}
	// Without Env the plist is what it always was.
	spec.Env = nil
	plain, err := RenderLaunchdPlist(spec)
	if err != nil || strings.Contains(plain, "ZOOMIES_CONFIG_DIR") {
		t.Errorf("a spec with no Env still has it: %v", err)
	}
	spec.Env = []ServiceEnv{{Name: "A", Value: "x\ny"}}
	if _, err := RenderLaunchdPlist(spec); err == nil {
		t.Error("a line break in an environment value was written into a plist")
	}
}

func TestTheRootDaemonsPlistIsWrittenWhereLaunchdLoadsDaemons(t *testing.T) {
	if got := LaunchdPlistPath("sh.zoomies.agent", true); got != "/Library/LaunchDaemons/sh.zoomies.agent.plist" {
		t.Errorf("plist path = %s", got)
	}
}
