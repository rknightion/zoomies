//go:build !windows

package fakevmpal_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"sync"
	"testing"

	"github.com/eyupio/zoomies/test/fakevmpal"
)

func TestMain(m *testing.M) {
	code := m.Run()
	fakevmpal.CleanUp()
	os.Exit(code)
}

type outcome struct {
	stdout, stderr string
	code           int
}

// try runs the built command the way the backend does, and is safe to call
// from a goroutine, which t.Fatal is not.
func try(f *fakevmpal.Fake, env []string, args ...string) (outcome, error) {
	cmd := exec.Command(f.Path(), args...)
	cmd.Env = append(os.Environ(), env...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	o := outcome{stdout: so.String(), stderr: se.String()}
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		o.code = ee.ExitCode()
	case err != nil:
		return o, err
	}
	return o, nil
}

func run(t *testing.T, f *fakevmpal.Fake, args ...string) outcome {
	t.Helper()
	o, err := try(f, nil, args...)
	if err != nil {
		t.Fatalf("running %v: %v", args, err)
	}
	return o
}

func mustRun(t *testing.T, f *fakevmpal.Fake, args ...string) outcome {
	t.Helper()
	o := run(t, f, args...)
	if o.code != 0 {
		t.Fatalf("%v exited %d: %s", args, o.code, o.stderr)
	}
	return o
}

func info(t *testing.T, f *fakevmpal.Fake, vm string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(mustRun(t, f, "info", vm, "--json").stdout), &m); err != nil {
		t.Fatalf("info %s was not JSON: %v", vm, err)
	}
	return m
}

func session(t *testing.T, f *fakevmpal.Fake, vm string) map[string]any {
	t.Helper()
	s, ok := info(t, f, vm)["sessionHardware"].(map[string]any)
	if !ok {
		t.Fatalf("%s has no session hardware", vm)
	}
	return s
}

func start(t *testing.T, f *fakevmpal.Fake, vm string) outcome {
	t.Helper()
	return run(t, f, "start", vm, "--background", "--wait", "--timeout", "30s")
}

func TestCloneRefusesATemplateThatIsRunning(t *testing.T) {
	// Bug caught: a fake that clones a running template would hide a backend
	// that has stopped refusing to touch a template somebody is working in.
	f := fakevmpal.New(t)
	f.AddTemplate("base")
	mustRun(t, f, "start", "base", "--background", "--wait", "--timeout", "30s")

	o := run(t, f, "clone", "base", "--name", "job-1", "-q")
	if o.code == 0 {
		t.Fatal("cloning a running template succeeded")
	}
	if _, ok := f.VM("job-1"); ok {
		t.Fatal("the refused clone was created anyway")
	}
}

func TestCloneRefusesADuplicateNameAndCopiesTheTemplate(t *testing.T) {
	// Bug caught: a clone that does not copy settings, or that overwrites a
	// VM of the same name, would let a backend rely on neither.
	f := fakevmpal.New(t)
	f.AddTemplate("base")
	mustRun(t, f, "set", "base", "--clipboard", "on")

	id := mustRun(t, f, "clone", "base", "--name", "job-1", "-q").stdout
	clone, ok := f.VM("job-1")
	if !ok || id != clone.ID+"\n" || clone.State != "stopped" {
		t.Fatalf("clone = %+v, printed %q", clone, id)
	}
	if clone.Settings["clipboard"] != true {
		t.Fatal("the clone did not copy the template's settings")
	}
	if o := run(t, f, "clone", "base", "--name", "job-1", "-q"); o.code == 0 {
		t.Fatal("a duplicate name was accepted")
	}
}

func TestACloneOfTheDefaultTemplateBootsBridged(t *testing.T) {
	// Bug caught: a fake that resolves "default" to shared would hide the
	// hazard the backend exists to catch.
	f := fakevmpal.New(t)
	f.AddTemplate("base")
	mustRun(t, f, "clone", "base", "--name", "job-1", "-q")
	mustRun(t, f, "start", "job-1", "--background", "--wait", "--timeout", "30s")

	if got := session(t, f, "job-1")["networkMode"]; got != "bridged" {
		t.Fatalf("session network mode = %v, want bridged", got)
	}
}

func TestHardeningWithSetBootsShared(t *testing.T) {
	// Bug caught: set that does not persist, or a start that ignores the
	// stored settings, so a hardened VM still boots bridged.
	f := fakevmpal.New(t)
	f.AddTemplate("base")
	mustRun(t, f, "clone", "base", "--name", "job-1", "-q")
	mustRun(t, f, "set", "job-1", "--network-mode", "shared", "--local-network", "off")
	if o := start(t, f, "job-1"); o.code != 0 {
		t.Fatal(o.stderr)
	}
	s := session(t, f, "job-1")
	if s["networkMode"] != "shared" || s["localNetworkCard"] != false || s["bridgedInterface"] != nil {
		t.Fatalf("session = %v, want shared with no local card and no bridge", s)
	}
	if addr, _ := info(t, f, "job-1")["internetAddress"].(string); len(addr) < 9 || addr[:8] != "192.0.2." {
		t.Fatalf("internetAddress = %q, want one in 192.0.2.0/24", addr)
	}
}

func TestSetMapsEachFlagToItsSetting(t *testing.T) {
	// Bug caught: a flag wired to the wrong settings key, or on/off not
	// turned into a boolean, which would let a hardening check pass on nothing.
	f := fakevmpal.New(t)
	f.AddTemplate("base")
	for _, tc := range []struct {
		flag, value, key string
		want             any
	}{
		{"--clipboard", "on", "clipboard", true},
		{"--drag-and-drop", "on", "dragAndDrop", true},
		{"--speakers", "off", "speakers", false},
		{"--microphone", "on", "microphone", true},
		{"--camera", "on", "camera", true},
		{"--start-at-login", "on", "startAtLogin", true},
		{"--agent-control", "off", "agentControl", false},
		{"--network-mode", "shared", "networkMode", "shared"},
		{"--local-network", "off", "localNetwork", "off"},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			name := "vm" + tc.flag
			mustRun(t, f, "clone", "base", "--name", name, "-q")
			mustRun(t, f, "set", name, tc.flag, tc.value)
			if got := info(t, f, name)["settings"].(map[string]any)[tc.key]; got != tc.want {
				t.Fatalf("%s = %v, want %v", tc.key, got, tc.want)
			}
		})
	}
}

func TestSetRefusesWhatItDoesNotKnow(t *testing.T) {
	// Bug caught: a lenient fake that swallows a flag the real tool rejects,
	// so a typo in the backend only fails on a real Mac.
	f := fakevmpal.New(t)
	f.AddTemplate("base")
	for _, args := range [][]string{
		{"set", "base", "--no-such-flag", "on"},
		{"set", "base", "--clipboard", "maybe"},
		{"set", "base", "--clipboard"},
	} {
		if o := run(t, f, args...); o.code == 0 {
			t.Errorf("%v succeeded", args)
		}
	}
}

func TestSetRemovesSharedFoldersAndForwards(t *testing.T) {
	// Bug caught: unshare or unforward that reports success and removes
	// nothing, which would pass a hardening step that did not harden.
	f := fakevmpal.New(t)
	tpl := f.AddTemplate("base")
	_ = tpl
	f.AddVM(fakevmpal.VM{Name: "job-1", Installed: true, Settings: map[string]any{
		"sharedFolders":  []any{"/srv/a", map[string]any{"path": "/srv/b"}},
		"forwardedPorts": []any{float64(8080), float64(9090)},
		"vsockForwards":  []any{float64(5000)},
	}})
	mustRun(t, f, "set", "job-1", "--unshare", "/srv/a", "--unshare", "/srv/b", "--unforward", "8080", "--vsock-unforward", "5000")

	got, _ := f.VM("job-1")
	if len(got.Settings["sharedFolders"].([]any)) != 0 || len(got.Settings["vsockForwards"].([]any)) != 0 {
		t.Fatalf("settings = %v", got.Settings)
	}
	if ports := got.Settings["forwardedPorts"].([]any); len(ports) != 1 || ports[0] != float64(9090) {
		t.Fatalf("forwardedPorts = %v, want only 9090", ports)
	}
}

func TestTheThirdMacOSVMIsRefused(t *testing.T) {
	// Bug caught: a fake with no two-VM limit would let a backend that
	// ignores Apple's limit look correct.
	f := fakevmpal.New(t)
	for _, n := range []string{"a", "b", "c"} {
		f.AddTemplate(n)
	}
	for _, n := range []string{"a", "b"} {
		if o := start(t, f, n); o.code != 0 {
			t.Fatalf("start %s: %s", n, o.stderr)
		}
	}
	o := start(t, f, "c")
	if o.code == 0 || !bytes.Contains([]byte(o.stderr), []byte("two macOS VMs")) {
		t.Fatalf("third start: exit %d, stderr %q", o.code, o.stderr)
	}
	if vm, _ := f.VM("c"); vm.State != "stopped" {
		t.Fatalf("the refused VM is %s", vm.State)
	}
	mustRun(t, f, "stop", "a", "--force", "--timeout", "30s")
	if o := start(t, f, "c"); o.code != 0 {
		t.Fatalf("start after freeing a slot: %s", o.stderr)
	}
}

func TestDeleteGoesToTheTrashUnlessPermanent(t *testing.T) {
	// Bug caught: a delete that always removes for good, so a backend that
	// forgot --permanently would leak a disk per job and no test would see it.
	for _, tc := range []struct {
		name        string
		args        []string
		wantTrashed bool
		wantFail    bool
	}{
		{"permanent", []string{"--force", "--permanently"}, false, false},
		{"without permanently", []string{"--force"}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fakevmpal.New(t)
			f.AddTemplate("base")
			mustRun(t, f, "clone", "base", "--name", "job-1", "-q")
			mustRun(t, f, append([]string{"delete", "job-1"}, tc.args...)...)
			if _, ok := f.VM("job-1"); ok {
				t.Fatal("the VM is still listed")
			}
			if got := slices.Contains(f.Trashed(), "job-1"); got != tc.wantTrashed {
				t.Fatalf("trashed = %v, want %v", f.Trashed(), tc.wantTrashed)
			}
		})
	}
}

func TestDeleteOfARunningVMNeedsForce(t *testing.T) {
	// Bug caught: a delete that ignores the running state, hiding a backend
	// that stops deleting a VM it has not stopped.
	f := fakevmpal.New(t)
	f.AddTemplate("base")
	start(t, f, "base")
	if o := run(t, f, "delete", "base", "--permanently"); o.code == 0 {
		t.Fatal("deleting a running VM without --force succeeded")
	}
	if _, ok := f.VM("base"); !ok {
		t.Fatal("the VM vanished anyway")
	}
}

func TestExecRecordsEnvValuesAndAnswersFromARule(t *testing.T) {
	// Bug caught: an exec that drops --env or its value, or answers from the
	// wrong rule, so what the backend sent to the guest goes unchecked.
	f := fakevmpal.New(t)
	f.AddTemplate("base")
	start(t, f, "base")
	f.OnExec("git status", fakevmpal.ExecReply{Stdout: "clean\n"})
	f.OnExec("false", fakevmpal.ExecReply{ExitCode: 1})
	f.OnExec("false", fakevmpal.ExecReply{ExitCode: 4, Stderr: "nope\n"})

	for _, tc := range []struct {
		name       string
		argv       []string
		wantOut    string
		wantStderr string
		wantCode   int
	}{
		{"a matching rule answers", []string{"git", "status"}, "clean\n", "", 0},
		{"a later rule for the same match replaces the earlier one", []string{"false"}, "", "nope\n", 4},
		{"no rule means success and silence", []string{"echo", "hi"}, "", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"exec", "base", "--timeout", "30s", "--env", "EXAMPLE_TOKEN", "--"}, tc.argv...)
			o, err := try(f, []string{"EXAMPLE_TOKEN=example-value"}, args...)
			if err != nil {
				t.Fatal(err)
			}
			if o.stdout != tc.wantOut || o.stderr != tc.wantStderr || o.code != tc.wantCode {
				t.Fatalf("got %+v", o)
			}
		})
	}
	calls := f.Execs()
	if len(calls) != 3 {
		t.Fatalf("recorded %d calls, want 3", len(calls))
	}
	if calls[0].VM != "base" || !slices.Equal(calls[0].Argv, []string{"git", "status"}) || calls[0].Env["EXAMPLE_TOKEN"] != "example-value" {
		t.Fatalf("first call = %+v", calls[0])
	}
}

func TestExecIsRefusedUntilToolsAreConnected(t *testing.T) {
	// Bug caught: an exec that works on a VM whose Tools never connected,
	// which would hide a backend that stops waiting for them.
	f := fakevmpal.New(t)
	f.AddTemplate("base")
	if o := run(t, f, "exec", "base", "--timeout", "5s", "--", "true"); o.code != 125 {
		t.Fatalf("exec on a stopped VM exited %d, want 125", o.code)
	}
	f.ToolsNeverConnect(true)
	if o := start(t, f, "base"); o.code == 0 || !bytes.Contains([]byte(o.stderr), []byte("Tools")) {
		t.Fatalf("start --wait = %+v, want a Tools timeout", o)
	}
	vm, _ := f.VM("base")
	if vm.State != "running" || vm.Tools.Connected {
		t.Fatalf("after the timeout: state %s, tools connected %v", vm.State, vm.Tools.Connected)
	}
	if o := run(t, f, "exec", "base", "--timeout", "5s", "--", "true"); o.code != 125 {
		t.Fatalf("exec without Tools exited %d, want 125", o.code)
	}
	if len(f.Execs()) != 0 {
		t.Fatal("a refused exec was recorded")
	}
}

func TestRebootStopsEveryRunningVM(t *testing.T) {
	// Bug caught: a Reboot that leaves a session behind, so a backend's
	// recovery from a host restart would never be exercised.
	f := fakevmpal.New(t)
	f.AddTemplate("a")
	f.AddTemplate("b")
	start(t, f, "a")
	f.Reboot()
	for _, vm := range f.VMs() {
		if vm.State != "stopped" || vm.SessionHardware != nil {
			t.Fatalf("%s: state %s, session %v", vm.Name, vm.State, vm.SessionHardware)
		}
	}
	if s := info(t, f, "a")["sessionHardware"]; s != nil {
		t.Fatalf("info still reports a session: %v", s)
	}
}

func TestConcurrentClonesDoNotCorruptState(t *testing.T) {
	// Bug caught: state read and written without the lock, so two clones at
	// once lose one of them or hand out the same ID twice.
	f := fakevmpal.New(t)
	f.AddTemplate("base")
	const n = 12
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o, err := try(f, nil, "clone", "base", "--name", fmt.Sprintf("job-%d", i), "-q")
			if err == nil && o.code != 0 {
				err = fmt.Errorf("clone %d exited %d: %s", i, o.code, o.stderr)
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	ids := map[string]bool{}
	for _, vm := range f.VMs() {
		ids[vm.ID] = true
	}
	if len(f.VMs()) != n+1 || len(ids) != n+1 {
		t.Fatalf("%d VMs and %d distinct IDs, want %d of each", len(f.VMs()), len(ids), n+1)
	}
}

func TestAFaultAppliesOnlyTheNumberOfTimesAsked(t *testing.T) {
	// Bug caught: a fault counter that is not kept between invocations, so a
	// "fail once" fault would fail every call and no retry could be tested.
	f := fakevmpal.New(t)
	f.AddTemplate("base")
	f.Fail("stop", fakevmpal.Fault{Stderr: "boom\n", ExitCode: 7, Times: 1})
	if o := run(t, f, "stop", "base", "--force", "--timeout", "5s"); o.code != 7 || o.stderr != "boom\n" {
		t.Fatalf("first stop = %+v", o)
	}
	if o := run(t, f, "stop", "base", "--force", "--timeout", "5s"); o.code != 0 {
		t.Fatalf("second stop = %+v, want success", o)
	}
}

func TestSettingsThatDoNotStickStayUnchanged(t *testing.T) {
	// Bug caught: a backend that trusts set's exit status instead of reading
	// the setting back would pass against a fake that always honours it.
	f := fakevmpal.New(t)
	f.AddTemplate("base")
	f.SettingsDoNotStick("speakers")
	mustRun(t, f, "set", "base", "--speakers", "off", "--clipboard", "on")
	vm, _ := f.VM("base")
	if vm.Settings["speakers"] != true || vm.Settings["clipboard"] != true {
		t.Fatalf("speakers = %v, clipboard = %v; want true, true", vm.Settings["speakers"], vm.Settings["clipboard"])
	}
}

func TestBridgeAtBootOverridesTheSettingsAndUnknownSettingsAreReported(t *testing.T) {
	// Bug caught: a backend that checks only the stored settings would miss a
	// session that came up bridged anyway, or a setting it never classified.
	f := fakevmpal.New(t)
	f.AddTemplate("base")
	mustRun(t, f, "set", "base", "--network-mode", "shared")
	f.BridgeAtBoot(true)
	f.AddUnknownSetting("holographicDisplay")
	start(t, f, "base")

	m := info(t, f, "base")
	if got := m["sessionHardware"].(map[string]any)["networkMode"]; got != "bridged" {
		t.Fatalf("session network mode = %v, want bridged", got)
	}
	if got := m["settings"].(map[string]any)["networkMode"]; got != "shared" {
		t.Fatalf("stored network mode = %v, want shared", got)
	}
	if _, ok := m["settings"].(map[string]any)["holographicDisplay"]; !ok {
		t.Fatal("the unknown setting is not reported")
	}
}

func TestADeletedVMCanStayListedForAMoment(t *testing.T) {
	// Bug caught: a fake that drops a VM the moment delete returns would pass a
	// backend that frees its slot before the real VM has gone.
	f := fakevmpal.New(t)
	f.AddTemplate("base")
	mustRun(t, f, "clone", "base", "--name", "job-1", "-q")
	f.DeleteLingers(1)
	mustRun(t, f, "delete", "job-1", "--force", "--permanently")

	listed := func() bool {
		var doc struct {
			VMs []struct {
				Name string `json:"name"`
			} `json:"vms"`
		}
		if err := json.Unmarshal([]byte(mustRun(t, f, "list", "--json").stdout), &doc); err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(doc.VMs, func(v struct {
			Name string `json:"name"`
		}) bool {
			return v.Name == "job-1"
		})
	}
	if !listed() {
		t.Fatal("the VM left the list as soon as delete returned")
	}
	if listed() {
		t.Fatal("the VM never left the list")
	}
}
