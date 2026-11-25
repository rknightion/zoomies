package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eyupio/zoomies/internal/backend"
	"github.com/eyupio/zoomies/internal/config"
	"github.com/eyupio/zoomies/internal/installer"
	"github.com/eyupio/zoomies/internal/store"
)

func jobUsersAgentConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Agent.WorkDir = t.TempDir()
	cfg.Agent.ControllerURL = "https://zoomies.example.com"
	cfg.Agent.ProcessIsolation = config.ProcessIsolationUser
	cfg.Agent.Capacity = 3
	cfg.Agent.JobUsers = config.JobUsersConfig{
		EgressMustAllow: []string{"github.com:443"},
		EgressMustBlock: []string{"198.51.100.10:443"},
	}
	return cfg
}

// jobUsersHost stands in for a Mac whose files are all as they should be, and
// records what the agent asked of it. The job-user machinery itself is tested
// against a fake host in internal/backend; here the question is what this
// command builds and what it refuses before building.
type jobUsersHost struct {
	started  int
	opts     backend.ProcessOptions
	binaries []string
}

func stubJobUsersHost(t *testing.T) *jobUsersHost {
	t.Helper()
	h := &jobUsersHost{}
	oldE, oldB, oldP, oldX, oldS, oldN := jobUserEUID, checkJobUserBinary, checkJobUserPaths, jobUserExecutable, startJobUsers, newJobUserProcess
	t.Cleanup(func() {
		jobUserEUID, checkJobUserBinary, checkJobUserPaths, jobUserExecutable, startJobUsers, newJobUserProcess = oldE, oldB, oldP, oldX, oldS, oldN
	})
	jobUserEUID = func() int { return 0 }
	checkJobUserBinary = func(b string) error { h.binaries = append(h.binaries, b); return nil }
	checkJobUserPaths = func(installer.JobUserPaths) error { return nil }
	jobUserExecutable = func() (string, error) { return "/usr/local/bin/zoomies", nil }
	startJobUsers = func(context.Context, *backend.ProcessBackend) error { h.started++; return nil }
	// The real constructor refuses off a Mac; the plain backend stands in, and
	// what it was asked to be is what is checked.
	newJobUserProcess = func(o backend.ProcessOptions) (*backend.ProcessBackend, error) {
		h.opts = o
		o.JobUsers = nil
		return backend.NewProcess(o)
	}
	return h
}

func quietCmdLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestJobUserAgentRegistersOnlyTheJobUserBackend(t *testing.T) {
	h := stubJobUsersHost(t)
	cfg := jobUsersAgentConfig(t)
	prepareVMPalAgent(cfg)

	reg, err := buildAgentBackends(context.Background(), cfg, quietCmdLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reg.Close)

	if kinds := reg.Kinds(); len(kinds) != 1 || kinds[0] != store.BackendProcess {
		t.Fatalf("registry holds %v; want only the process kind", kinds)
	}
	for _, kind := range []store.BackendKind{store.BackendDocker, store.BackendPodman} {
		if _, err := reg.Get(kind); err == nil {
			t.Errorf("the registry offers %s, which would be a way for a job to run as root", kind)
		}
	}
	if h.started != 1 {
		t.Errorf("the job users were set up %d times", h.started)
	}
	jo := h.opts.JobUsers
	if jo == nil || jo.Capacity != 3 || jo.Executable != "/usr/local/bin/zoomies" ||
		len(jo.EgressMustAllow) != 1 || jo.EgressMustBlock[0] != "198.51.100.10:443" || filepath.Base(jo.StateDir) != "job-users" {
		t.Errorf("the backend was given %+v", jo)
	}
	if len(h.binaries) != 1 || h.binaries[0] != "/usr/local/bin/zoomies" {
		t.Errorf("the binary checked was %v", h.binaries)
	}
}

func TestJobUserAgentRefusesToStartWhenNotRoot(t *testing.T) {
	h := stubJobUsersHost(t)
	jobUserEUID = func() int { return 501 }
	_, err := buildAgentBackends(context.Background(), jobUsersAgentConfig(t), quietCmdLogger())
	if err == nil || !strings.Contains(err.Error(), "run as root") {
		t.Fatalf("err = %v; want a refusal that says the agent must be root", err)
	}
	if h.started != 0 || len(h.binaries) != 0 {
		t.Error("something was set up before the refusal")
	}
}

func TestJobUserAgentRefusesAConfigReadableByOthers(t *testing.T) {
	h := stubJobUsersHost(t)
	checkJobUserPaths = installer.CheckJobUserPaths
	cfg := jobUsersAgentConfig(t)
	file := filepath.Join(t.TempDir(), "zoomies.yaml")
	if err := os.WriteFile(file, []byte("agent: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(file); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Agent = cfg.Agent
	_, err = buildAgentBackends(context.Background(), loaded, quietCmdLogger())
	if err == nil || !strings.Contains(err.Error(), file) {
		t.Fatalf("err = %v; want a refusal naming %s", err, file)
	}
	if h.started != 0 {
		t.Error("the job users were set up on a host whose secrets others can read")
	}
}

func TestJobUserAgentRefusesABinaryOthersCouldReplace(t *testing.T) {
	h := stubJobUsersHost(t)
	checkJobUserBinary = func(string) error { return errors.New("the zoomies binary is writable by the world") }
	_, err := buildAgentBackends(context.Background(), jobUsersAgentConfig(t), quietCmdLogger())
	if err == nil || !strings.Contains(err.Error(), "writable by the world") || h.started != 0 {
		t.Fatalf("err = %v, started = %d", err, h.started)
	}
}

func TestJobUserAgentDoesNotStartWhenItsAccountsCannotBeSetUp(t *testing.T) {
	stubJobUsersHost(t)
	startJobUsers = func(context.Context, *backend.ProcessBackend) error {
		return errors.New("an account named zj02 already exists")
	}
	_, err := buildAgentBackends(context.Background(), jobUsersAgentConfig(t), quietCmdLogger())
	if err == nil || !strings.Contains(err.Error(), "zj02") {
		t.Fatalf("err = %v", err)
	}
}

func TestOnlyAVMPalOrJobUserAgentHasItsEmbeddedDefaultCleared(t *testing.T) {
	cfg := jobUsersAgentConfig(t)
	prepareVMPalAgent(cfg)
	if cfg.Agent.Embedded || cfg.Agent.Backend != string(store.BackendProcess) {
		t.Errorf("embedded %v, backend %q; want a standalone process agent", cfg.Agent.Embedded, cfg.Agent.Backend)
	}
}

func TestEgressProbeClassifiesEachOutcomeAsTheGuestDoes(t *testing.T) {
	open, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { open.Close() })
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	closed.Close()

	e, out, _ := newTestEnv(t)
	err = runAgent(context.Background(), e, []string{"egress-probe", "--timeout", "2s", open.Addr().String(), closedAddr, "not-a-target"})
	if err != nil {
		t.Fatal(err)
	}
	want := "zoomies-egress v1 target 0 connected\n" +
		"zoomies-egress v1 target 1 refused\n" +
		"zoomies-egress v1 target 2 error\n" +
		"zoomies-egress v1 end 3\n"
	if out.String() != want {
		t.Errorf("output:\n%s\nwant:\n%s", out.String(), want)
	}
	// The probe is not in the reference, which is made from what each command's
	// help lists, and it needs a target.
	e, _, _ = newTestEnv(t)
	if err := runAgent(context.Background(), e, []string{"egress-probe"}); err == nil {
		t.Error("a probe with nothing to try was accepted")
	}
	e, _, _ = newTestEnv(t)
	if err := runAgent(context.Background(), e, []string{"egress-probe", "--timeout", "0s", "127.0.0.1:1"}); err == nil {
		t.Error("a zero timeout was accepted")
	}
}

func TestJobUsersRemoveRefusesWhileTheAgentIsLoaded(t *testing.T) {
	stubJobUsersHost(t)
	oldLoaded, oldRemove := agentDaemonLoaded, removeJobUsers
	t.Cleanup(func() { agentDaemonLoaded, removeJobUsers = oldLoaded, oldRemove })
	var removed []backend.RemoveJobUsersOptions
	removeJobUsers = func(_ context.Context, o backend.RemoveJobUsersOptions) error {
		removed = append(removed, o)
		return nil
	}

	agentDaemonLoaded = func(context.Context) (bool, error) { return true, nil }
	e, _, _ := newTestEnv(t)
	err := runAgent(context.Background(), e, []string{"job-users", "remove"})
	if err == nil || !strings.Contains(err.Error(), "is loaded") || !strings.Contains(err.Error(), "bootout") || len(removed) != 0 {
		t.Fatalf("err = %v, removed = %v; want a refusal that says how to stop it", err, removed)
	}

	agentDaemonLoaded = func(context.Context) (bool, error) { return false, errors.New("launchctl is not there") }
	e, _, _ = newTestEnv(t)
	if err := runAgent(context.Background(), e, []string{"job-users", "remove"}); err == nil || len(removed) != 0 {
		t.Errorf("an unknown state was taken as not loaded: %v", err)
	}

	agentDaemonLoaded = func(context.Context) (bool, error) { return false, nil }
	e, out, _ := newTestEnv(t)
	if err := runAgent(context.Background(), e, []string{"job-users", "remove"}); err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || filepath.Base(removed[0].StateDir) != "job-users" || !strings.Contains(out.String(), "removed the job users") {
		t.Errorf("removed = %v, output = %q", removed, out.String())
	}

	jobUserEUID = func() int { return 501 }
	e, _, _ = newTestEnv(t)
	if err := runAgent(context.Background(), e, []string{"job-users", "remove"}); err == nil || !strings.Contains(err.Error(), "root") {
		t.Errorf("remove as an ordinary user = %v", err)
	}
	e, _, _ = newTestEnv(t)
	if err := runAgent(context.Background(), e, []string{"job-users"}); err == nil {
		t.Error("job-users with no subcommand was accepted")
	}
}

func TestAgentJoinHandsTheJobUsersFlagsToTheJoin(t *testing.T) {
	var got installer.JoinOptions
	installerJoin = func(_ context.Context, opts installer.JoinOptions) error {
		got = opts
		return nil
	}
	t.Cleanup(func() { installerJoin = installer.Join })

	e, _, _ := newTestEnv(t)
	err := runAgent(context.Background(), e, []string{"join", "https://zoomies.example.com", "--token", "zoojoin_test",
		"--non-interactive", "--process-isolation", "user", "--job-users-config", "job-users.yaml", "--capacity", "4"})
	if err != nil {
		t.Fatal(err)
	}
	if got.ProcessIsolation != config.ProcessIsolationUser || got.JobUsersConfigFile != "job-users.yaml" || got.Capacity != 4 {
		t.Fatalf("the join was given %+v", got)
	}
}
