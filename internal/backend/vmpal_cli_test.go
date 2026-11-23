//go:build !windows

package backend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// scriptedVMPal writes a shell script to stand in for the vmpal command.
func scriptedVMPal(t *testing.T, body string) (*vmpalCLI, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "vmpal")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := newVMPalCLI(path)
	c.stopGrace = 100 * time.Millisecond
	return c, dir
}

func readScriptOutput(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A hung vmpal must cost one step and not the agent: every create, stop and
// removal on the host queues behind these calls.
func TestAVMPalCallThatHangsIsStoppedAtItsLimit(t *testing.T) {
	c, _ := scriptedVMPal(t, "exec sleep 30")
	start := time.Now()
	_, err := c.run(context.Background(), 150*time.Millisecond, nil, "list")
	var call *vmpalCallError
	if !errors.As(err, &call) || !call.TimedOut {
		t.Fatalf("a hung command returned %v, want a timeout", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the call took %s to give up", took)
	}
}

// SIGTERM comes first so vmpal can stop the guest command, but a command that
// ignores it must still not hold the caller.
func TestAVMPalCallThatIgnoresSIGTERMIsStillStopped(t *testing.T) {
	c, _ := scriptedVMPal(t, "trap '' TERM\nwhile :; do sleep 1; done")
	start := time.Now()
	if _, err := c.run(context.Background(), 150*time.Millisecond, nil, "list"); err == nil {
		t.Fatal("a command that never ended was reported as a success")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the call took %s to give up", took)
	}
}

// The JIT configuration registers a runner. On a command line any process on
// the Mac could read it, and in an error it would reach the logs and the UI.
func TestASecretGivenToVMPalStaysOutOfItsArgumentsAndErrors(t *testing.T) {
	const secret = "jit-config-value"
	c, dir := scriptedVMPal(t, `printf '%s\n' "$@" > "$(dirname "$0")/args"
printf '%s' "$RUNNER_SECRET" > "$(dirname "$0")/seen"
echo "failed while using $RUNNER_SECRET" >&2
exit 3`)
	out, err := c.Exec(context.Background(), "clone-1", time.Second, map[string]string{"RUNNER_SECRET": secret}, "/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	if got := readScriptOutput(t, filepath.Join(dir, "seen")); got != secret {
		t.Fatalf("vmpal saw %q in its environment", got)
	}
	args := readScriptOutput(t, filepath.Join(dir, "args"))
	if strings.Contains(args, secret) {
		t.Fatalf("the secret is in vmpal's arguments:\n%s", args)
	}
	if !strings.Contains(args, "--env\nRUNNER_SECRET\n") {
		t.Fatalf("the variable was not named with --env:\n%s", args)
	}
	if strings.Contains(out.Stderr, secret) {
		t.Fatalf("the secret came back in the output: %q", out.Stderr)
	}

	_, err = c.checked(context.Background(), time.Second, map[string]string{"RUNNER_SECRET": secret}, "set", "clone-1")
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("the error was %v", err)
	}
}

// A pool's environment is written by whoever can edit a pool, and nothing it
// sets may change how the program that controls the VMs loads or behaves.
func TestVMPalDoesNotInheritTheAgentsEnvironment(t *testing.T) {
	t.Setenv("DYLD_INSERT_LIBRARIES", "/tmp/not-a-library.dylib")
	c, dir := scriptedVMPal(t, `/usr/bin/env > "$(dirname "$0")/env"`)
	if _, err := c.run(context.Background(), time.Second, nil, "list"); err != nil {
		t.Fatal(err)
	}
	env := readScriptOutput(t, filepath.Join(dir, "env"))
	if strings.Contains(env, "DYLD_INSERT_LIBRARIES") {
		t.Fatalf("the agent's environment reached vmpal:\n%s", env)
	}
	if !strings.Contains(env, "PATH=/usr/bin:/bin:/usr/sbin:/sbin") {
		t.Fatalf("vmpal did not get the fixed PATH:\n%s", env)
	}
}

// After a job starts, the guest decides what its commands print.
func TestOutputFromVMPalIsCappedAndSaysSo(t *testing.T) {
	c, _ := scriptedVMPal(t, "i=0; while [ $i -lt 200 ]; do printf 0123456789; i=$((i+1)); done")
	c.outputCap = 64
	out, err := c.run(context.Background(), 2*time.Second, nil, "exec")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Stdout) != 64 || !out.Truncated {
		t.Fatalf("kept %d bytes, truncated=%v", len(out.Stdout), out.Truncated)
	}
}

// The hardening check can only refuse a setting it can see.
func TestASettingThisVersionHasNeverHeardOfSurvivesDecoding(t *testing.T) {
	c, _ := scriptedVMPal(t, `cat <<'JSON'
{"id":"ID-1","name":"clone-1","guest":"macOS","state":"running","installed":true,
 "internetAddress":"192.0.2.10","pendingSettings":[],
 "sessionHardware":{"networkMode":"shared","localNetworkCard":false,"bridgedInterface":null},
 "tools":{"connected":true,"version":"0.42"},
 "settings":{"networkMode":"shared","aNewWayToShareTheMac":true}}
JSON`)
	info, err := c.Info(context.Background(), "clone-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := info.Settings["aNewWayToShareTheMac"]; !ok {
		t.Fatalf("the unknown setting was dropped: %v", info.Settings)
	}
	if info.SessionHardware == nil || info.SessionHardware.NetworkMode != "shared" || info.InternetAddress != "192.0.2.10" {
		t.Fatalf("decoded %+v", info)
	}
}

// Without --permanently each deleted clone sits in the Trash holding its disk.
func TestDeletingAVMRemovesItForGood(t *testing.T) {
	c, dir := scriptedVMPal(t, `printf '%s\n' "$@" > "$(dirname "$0")/args"`)
	if err := c.Delete(context.Background(), "clone-1"); err != nil {
		t.Fatal(err)
	}
	args := readScriptOutput(t, filepath.Join(dir, "args"))
	for _, want := range []string{"--force", "--permanently"} {
		if !strings.Contains(args, want) {
			t.Fatalf("delete was not given %s:\n%s", want, args)
		}
	}
}

// A template name is configuration, and vmpal would read this one as a flag.
func TestAVMNameCannotBeReadAsAnOption(t *testing.T) {
	c, dir := scriptedVMPal(t, `touch "$(dirname "$0")/ran"`)
	if err := c.Clone(context.Background(), "--shut-down", "clone-1"); err == nil {
		t.Fatal("a template named like an option was accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "ran")); err == nil {
		t.Fatal("vmpal was run with a name that reads as an option")
	}
}
