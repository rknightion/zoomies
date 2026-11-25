package backend

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/eyupio/zoomies/internal/store"
)

// The runner's PATH, locale and umask are the VM guest's, and the VM guest's are
// a shell script. This reads the script, so a change to either side fails here
// and not on a Mac.
func TestJobUserEnvMatchesTheVMGuestRecipe(t *testing.T) {
	data, err := os.ReadFile("vmpal_guest.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)

	base := regexp.MustCompile(`RUNNER_PATH=\$\{PATH:-([^}]+)\}`).FindStringSubmatch(script)
	extra := regexp.MustCompile(`for dir in ([^;]+); do`).FindStringSubmatch(script)
	if base == nil || extra == nil {
		t.Fatal("the guest script no longer has the PATH recipe this test reads")
	}
	want := base[1] + ":" + strings.Join(strings.Fields(extra[1]), ":")
	if jobUserPath != want {
		t.Errorf("jobUserPath = %q; the guest builds %q", jobUserPath, want)
	}
	if !strings.Contains(script, `LANG="${LANG:-`+jobUserLocale+`}"`) || !strings.Contains(script, `LC_ALL="${LC_ALL:-`+jobUserLocale+`}"`) {
		t.Errorf("the guest does not default LANG and LC_ALL to %s", jobUserLocale)
	}
	if !strings.Contains(script, "umask 022") {
		t.Error("the guest no longer runs the runner under umask 022")
	}
}

func TestJobUserEnvIsBuiltFromNothingWithThePoolsOwnSettingsLast(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "from-the-agent")
	s := &jobUserSlot{n: 3, name: "zj03", uid: 653}
	spec := Spec{Name: "runner-a", Ephemeral: true, Credentials: Credentials{JITConfig: "jit-secret"},
		Env: map[string]string{"LANG": "C", "EXTRA": "1"}}
	env := jobUserEnv(s, "/Users/zj03", "/var/folders/ab/cd/T/", "", spec)
	got := envMap(env)

	for k, v := range map[string]string{
		"HOME": "/Users/zj03", "USER": "zj03", "LOGNAME": "zj03", "SHELL": "/bin/zsh",
		"TMPDIR": "/var/folders/ab/cd/T/", "PATH": jobUserPath, "LC_ALL": "en_US.UTF-8",
		EnvRunnerName: "runner-a", EnvEphemeral: "true", EnvUpstreamJITConfig: "jit-secret", "EXTRA": "1",
	} {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["RUNNER_ALLOW_RUNASROOT"]; ok {
		t.Error("RUNNER_ALLOW_RUNASROOT is set, and the runner is never root here")
	}
	if _, ok := got["AWS_SECRET_ACCESS_KEY"]; ok {
		t.Error("a variable of the agent's own reached the job")
	}
	// A later duplicate wins in an exec environment, and the pool's comes last.
	last := ""
	for _, e := range env {
		if strings.HasPrefix(e, "LANG=") {
			last = e
		}
	}
	if last != "LANG=C" {
		t.Errorf("the last LANG is %q; the pool's must win", last)
	}
}

func TestCheckJobUserEnvRefusesWhatZoomiesKeepsForItself(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"the upstream registration": {EnvUpstreamJITConfig: "x"},
		"the Zoomies registration":  {EnvJITConfig: "x"},
		"a name no shell exports":   {"A-B": "x"},
		"a NUL in a value":          {"A": "x\x00y"},
	} {
		err := checkJobUserEnv(Spec{PoolName: "mac", Env: env})
		if err == nil || !strings.Contains(err.Error(), "mac") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := checkJobUserEnv(Spec{Env: map[string]string{"FOO": "line\nbreak"}}); err != nil {
		t.Errorf("a line break in a value is fine in an environment: %v", err)
	}
	_ = store.BackendProcess
}
