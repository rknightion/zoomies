package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/eyupio/zoomies/internal/backend"
	"github.com/eyupio/zoomies/internal/config"
	"github.com/eyupio/zoomies/internal/installer"
	"github.com/eyupio/zoomies/internal/store"
)

func vmpalAgentConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Agent.WorkDir = t.TempDir()
	cfg.Agent.ControllerURL = "https://zoomies.example.com"
	cfg.Agent.ProcessIsolation = config.ProcessIsolationVMPal
	cfg.Agent.VMPal = config.VMPalConfig{
		// Never the real command: the probe must not reach a real vmpal.
		Binary:          filepath.Join(t.TempDir(), "no-vmpal"),
		Template:        "example-macos-template",
		MaxVMs:          1,
		GuestCIDR:       "192.0.2.0/24",
		PolicyCheck:     "/usr/local/libexec/example-policy-check",
		EgressMustAllow: []string{"github.com:443"},
		EgressMustBlock: []string{"198.51.100.10:443"},
	}
	return cfg
}

// Any other backend in this registry is a way for a job to run on the Mac.
func TestAVMPalAgentHoldsTheVMBackendAndNothingElse(t *testing.T) {
	cfg := vmpalAgentConfig(t)
	prepareVMPalAgent(cfg)
	reg, err := buildAgentBackends(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reg.Close)

	if kinds := reg.Kinds(); len(kinds) != 1 || kinds[0] != store.BackendProcess {
		t.Fatalf("registry holds %v; want only the process kind", kinds)
	}
	b, err := reg.Get(store.BackendProcess)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.(*backend.VMPalBackend); !ok {
		t.Fatalf("the process kind is a %T, which would run jobs on the host", b)
	}
	for _, kind := range []store.BackendKind{store.BackendDocker, store.BackendPodman} {
		if _, err := reg.Get(kind); err == nil {
			t.Errorf("the registry offers %s", kind)
		}
	}
}

func TestAnAgentWithoutVMPalKeepsItsOrdinaryBackends(t *testing.T) {
	for _, mode := range []string{"", config.ProcessIsolationNone} {
		cfg := vmpalAgentConfig(t)
		cfg.Agent.ProcessIsolation = mode
		cfg.Agent.Backend = string(store.BackendProcess)
		reg, err := buildAgentBackends(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			t.Fatal(err)
		}
		b, err := reg.Get(store.BackendProcess)
		if err != nil {
			t.Fatal(err)
		}
		if _, isVM := b.(*backend.VMPalBackend); isVM {
			t.Errorf("isolation %q was given the VM backend", mode)
		}
		reg.Close()
	}
}

// The validator refuses vmpal on an embedded agent, and embedded is the default,
// so the agent command has to say it is not one or no hand-written file passes.
func TestOnlyAVMPalAgentHasItsEmbeddedDefaultCleared(t *testing.T) {
	cfg := vmpalAgentConfig(t)
	prepareVMPalAgent(cfg)
	if cfg.Agent.Embedded || cfg.Agent.Backend != string(store.BackendProcess) {
		t.Errorf("embedded %v, backend %q; want a standalone process agent", cfg.Agent.Embedded, cfg.Agent.Backend)
	}

	other := vmpalAgentConfig(t)
	other.Agent.ProcessIsolation = config.ProcessIsolationNone
	prepareVMPalAgent(other)
	if !other.Agent.Embedded || other.Agent.Backend != "docker" {
		t.Errorf("an agent without VMs was changed: embedded %v, backend %q", other.Agent.Embedded, other.Agent.Backend)
	}
}

func TestAgentJoinHandsTheIsolationFlagsToTheJoin(t *testing.T) {
	var got installer.JoinOptions
	installerJoin = func(_ context.Context, opts installer.JoinOptions) error {
		got = opts
		return nil
	}
	t.Cleanup(func() { installerJoin = installer.Join })

	e, _, _ := newTestEnv(t)
	err := runAgent(context.Background(), e, []string{"join", "https://zoomies.example.com", "--token", "zoojoin_test",
		"--non-interactive", "--no-service", "--process-isolation", "vmpal", "--vmpal-config", "vmpal.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	if got.ProcessIsolation != config.ProcessIsolationVMPal || got.VMPalConfigFile != "vmpal.yaml" {
		t.Fatalf("the join was given isolation %q and file %q", got.ProcessIsolation, got.VMPalConfigFile)
	}
}

func TestAnAgentOffAMacRefusesVMPalBeforeBuildingAnything(t *testing.T) {
	if runtime.GOOS == "darwin" || config.VMPalAnyOS {
		t.Skip("this is the refusal for a host that is not a Mac")
	}
	path := filepath.Join(t.TempDir(), "zoomies.yaml")
	// No embedded: false, as in a file written by hand: the agent command has
	// to clear that default itself or it is refused as an embedded agent.
	body := "agent:\n  controller_url: https://zoomies.example.com\n  work_dir: " + t.TempDir() + "\n  process_isolation: vmpal\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	e, _, _ := newTestEnv(t)
	err := runAgent(context.Background(), e, []string{"--config", path})
	if err == nil || !strings.Contains(err.Error(), "only runs on a Mac") {
		t.Fatalf("want the Mac-only refusal, got: %v", err)
	}
	if strings.Contains(err.Error(), "needs a standalone agent") {
		t.Errorf("zoomies agent was refused as an embedded agent:\n%v", err)
	}
}

// The registry test above proves the branch; this proves the daemon takes it.
// It cannot be reached by running the daemon, because the validator stops vmpal
// off a Mac first, and the plain builder here would put jobs on the Mac.
func TestTheAgentDaemonBuildsItsBackendsThroughTheIsolationBranch(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "agent.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string]int{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "runAgentDaemon" {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok {
					calls[id.Name]++
				}
			}
			return true
		})
	}
	if calls["buildAgentBackends"] != 1 || calls["buildBackends"] != 0 {
		t.Fatalf("runAgentDaemon calls buildAgentBackends %d times and buildBackends %d times; want once and never",
			calls["buildAgentBackends"], calls["buildBackends"])
	}
}
