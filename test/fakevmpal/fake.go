//go:build !windows

// Package fakevmpal is a test-only stand-in for the vmpal command.
//
// The backend runs vmpal as a child process with a scrubbed environment, so a
// fake that lived in the test binary, or found its state through a variable,
// would never be exercised the way production runs it. This one is a real
// executable: it keeps its state in a state/ directory beside itself, under a
// flock, and the Go API edits those same files.
//
// It never executes anything. exec records what it was asked and answers from
// scripted rules, because the point is to see what the backend sent, not to
// run it.
package fakevmpal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// maxRunningMacOS is the limit Apple puts on one Mac, and the reason start can
// refuse.
const maxRunningMacOS = 2

// toolsTimeoutDelay is how long start --wait takes to give up when Tools never
// connect: long enough that the VM is visibly running, short enough for a test.
const toolsTimeoutDelay = 300 * time.Millisecond

// SessionHardware is what a running VM actually has, as opposed to what its
// settings promise for the next start.
type SessionHardware struct {
	NetworkMode      string  `json:"networkMode"`
	LocalNetworkCard bool    `json:"localNetworkCard"`
	BridgedInterface *string `json:"bridgedInterface"`
	CPUCount         int     `json:"cpuCount"`
	MemoryGB         int     `json:"memoryGB"`
	GPUAcceleration  bool    `json:"gpuAcceleration"`
	Microphone       bool    `json:"microphone"`
	Speakers         bool    `json:"speakers"`
}

// Tools is the guest agent's state.
type Tools struct {
	Connected bool   `json:"connected"`
	Latest    bool   `json:"latest"`
	Version   string `json:"version"`
}

// VM is one machine. Settings holds the keys the real tool reports; numbers
// read back from the fake are float64, because the state is JSON.
type VM struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Guest           string           `json:"guest"`
	State           string           `json:"state"`
	Installed       bool             `json:"installed"`
	AgentControl    bool             `json:"agentControl"`
	InternetAddress string           `json:"internetAddress"`
	Settings        map[string]any   `json:"settings"`
	PendingSettings []map[string]any `json:"pendingSettings"`
	SessionHardware *SessionHardware `json:"sessionHardware"`
	Tools           Tools            `json:"tools"`
}

// Fault makes one command fail. Times of zero means every call.
type Fault struct {
	Stderr   string
	ExitCode int // zero is treated as 1, since a fault that exits 0 is not one
	Hang     bool
	Times    int
}

// ExecReply is what a scripted exec answers.
type ExecReply struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Hang     bool
}

// ExecCall is one recorded exec.
type ExecCall struct {
	VM   string            `json:"vm"`
	Argv []string          `json:"argv"`
	Env  map[string]string `json:"env"`
}

type faultState struct {
	Fault Fault
	Used  int
}

type execRule struct {
	Match string
	Reply ExecReply
}

type state struct {
	NextID            int
	VMs               []VM
	Trash             []string
	Faults            map[string]*faultState
	Rules             []execRule
	Egress            map[string]string
	ToolsNeverConnect bool
	BridgeAtBoot      bool
	BootCPUs          int
	BootMemoryGB      int
	NoStick           []string
	UnknownSettings   []string
	// DeleteLinger is how many further list calls a deleted VM stays in. The
	// real command returns from a permanent delete a few seconds before the VM
	// has left its list, and a caller that trusts the return miscounts its slots.
	DeleteLinger int
	Lingering    []lingeringVM
}

type lingeringVM struct {
	VM    VM
	Lists int
}

// ---- Go API ----

// Fake is a built command and the state directory beside it.
type Fake struct {
	t    *testing.T
	path string
	dir  string
}

// New builds the command into the test's temporary directory.
func New(t *testing.T) *Fake {
	t.Helper()
	built := builtCommand(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "vmpal")
	// A hard link, because the command finds its state beside the path it was
	// run by, and because a copy written here could still be open in a process
	// another test is forking at that moment, which fails the exec as busy.
	if err := os.Link(built, path); err != nil {
		data, err := os.ReadFile(built)
		if err != nil {
			t.Fatalf("fakevmpal: reading the built command: %v", err)
		}
		if err := os.WriteFile(path, data, 0o755); err != nil {
			t.Fatalf("fakevmpal: copying the built command: %v", err)
		}
	}
	return &Fake{t: t, path: path, dir: filepath.Join(dir, "state")}
}

// build is the command compiled once for this test process. Linking takes over
// a second, and a suite that needs a clean fake per case would spend minutes on it.
var build struct {
	sync.Mutex
	dir, path string
}

func builtCommand(t *testing.T) string {
	t.Helper()
	build.Lock()
	defer build.Unlock()
	if build.path != "" {
		return build.path
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("fakevmpal: cannot locate its own source to find the module root")
	}
	dir, err := os.MkdirTemp("", "fakevmpal-")
	if err != nil {
		t.Fatalf("fakevmpal: %v", err)
	}
	path := filepath.Join(dir, "vmpal")
	cmd := exec.Command("go", "build", "-o", path, "./test/fakevmpal/cmd")
	cmd.Dir = filepath.Join(filepath.Dir(file), "..", "..")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		os.RemoveAll(dir)
		t.Fatalf("fakevmpal: building the command: %v\n%s", err, out)
	}
	build.dir, build.path = dir, path
	return path
}

// CleanUp removes the compiled command. It outlives any one test, so a package
// using this fake calls it from TestMain.
func CleanUp() {
	build.Lock()
	defer build.Unlock()
	if build.dir != "" {
		os.RemoveAll(build.dir)
		build.dir, build.path = "", ""
	}
}

// Path is the command to hand to the backend.
func (f *Fake) Path() string { return f.path }

func (f *Fake) edit(fn func(*state)) {
	f.t.Helper()
	unlock, err := lockDir(f.dir)
	if err != nil {
		f.t.Fatalf("fakevmpal: %v", err)
	}
	defer unlock()
	st, err := load(f.dir)
	if err != nil {
		f.t.Fatalf("fakevmpal: %v", err)
	}
	fn(st)
	if err := save(f.dir, st); err != nil {
		f.t.Fatalf("fakevmpal: %v", err)
	}
}

// AddTemplate adds a stopped, installed macOS VM in the state a freshly built
// template is in: its network mode and local network are still "default".
func (f *Fake) AddTemplate(name string) VM {
	f.t.Helper()
	f.AddVM(VM{
		Name:         name,
		Installed:    true,
		AgentControl: true,
		Tools:        Tools{Latest: true, Version: "0.42"},
		Settings:     defaultSettings(),
	})
	vm, _ := f.VM(name)
	return vm
}

// AddVM adds a VM as given. An empty ID, State, Guest or Settings is filled in.
func (f *Fake) AddVM(vm VM) {
	f.t.Helper()
	f.edit(func(s *state) {
		if vm.Name == "" {
			f.t.Fatal("fakevmpal: a VM needs a name")
		}
		if s.find(vm.Name) >= 0 {
			f.t.Fatalf("fakevmpal: a VM called %q already exists", vm.Name)
		}
		if vm.ID == "" {
			vm.ID = s.newID()
		}
		if vm.State == "" {
			vm.State = "stopped"
		}
		if vm.Guest == "" {
			vm.Guest = "macOS"
		}
		if vm.Settings == nil {
			vm.Settings = defaultSettings()
		}
		s.VMs = append(s.VMs, vm)
	})
}

// VM returns the VM with that name or ID.
func (f *Fake) VM(name string) (VM, bool) {
	f.t.Helper()
	var out VM
	var found bool
	f.edit(func(s *state) {
		if i := s.find(name); i >= 0 {
			out, found = s.VMs[i], true
		}
	})
	return out, found
}

// VMs returns every VM.
func (f *Fake) VMs() []VM {
	f.t.Helper()
	var out []VM
	f.edit(func(s *state) { out = slices.Clone(s.VMs) })
	return out
}

// Trashed names the VMs deleted without --permanently.
func (f *Fake) Trashed() []string {
	f.t.Helper()
	var out []string
	f.edit(func(s *state) { out = slices.Clone(s.Trash) })
	return out
}

// Fail makes the named command fail.
func (f *Fake) Fail(command string, fault Fault) {
	f.t.Helper()
	f.edit(func(s *state) { s.Faults[command] = &faultState{Fault: fault} })
}

// ToolsNeverConnect makes start --wait time out with the VM left running.
func (f *Fake) ToolsNeverConnect(on bool) {
	f.t.Helper()
	f.edit(func(s *state) { s.ToolsNeverConnect = on })
}

// SettingsDoNotStick makes set report success and change nothing for these
// settings keys, which is how a tool that ignores a flag looks from outside.
func (f *Fake) SettingsDoNotStick(keys ...string) {
	f.t.Helper()
	f.edit(func(s *state) { s.NoStick = slices.Clone(keys) })
}

// AddUnknownSetting reports a settings key in every VM, as a later release
// of the real tool might.
func (f *Fake) AddUnknownSetting(key string) {
	f.t.Helper()
	f.edit(func(s *state) {
		if !slices.Contains(s.UnknownSettings, key) {
			s.UnknownSettings = append(s.UnknownSettings, key)
		}
	})
}

// BridgeAtBoot makes a session come up bridged whatever the settings say.
func (f *Fake) BridgeAtBoot(on bool) {
	f.t.Helper()
	f.edit(func(s *state) { s.BridgeAtBoot = on })
}

// BootWithSize makes a session come up with this hardware whatever the settings
// say. Zero leaves that value following the settings.
func (f *Fake) BootWithSize(cpus, memoryGB int) {
	f.t.Helper()
	f.edit(func(s *state) { s.BootCPUs, s.BootMemoryGB = cpus, memoryGB })
}

// DeleteLingers keeps a permanently deleted VM in list for n more calls.
func (f *Fake) DeleteLingers(n int) {
	f.edit(func(s *state) { s.DeleteLinger = n })
}

// Reboot stops every running VM, as a host restart does.
func (f *Fake) Reboot() {
	f.t.Helper()
	f.edit(func(s *state) {
		for i := range s.VMs {
			if s.VMs[i].State == "running" {
				s.VMs[i].stop()
			}
		}
	})
}

// OnExec scripts an answer for any exec whose space-joined argv contains
// match. The first matching rule answers; a later rule for the same match
// replaces the earlier one in place.
func (f *Fake) OnExec(match string, r ExecReply) {
	f.t.Helper()
	f.edit(func(s *state) {
		for i := range s.Rules {
			if s.Rules[i].Match == match {
				s.Rules[i].Reply = r
				return
			}
		}
		s.Rules = append(s.Rules, execRule{Match: match, Reply: r})
	})
}

// OnEgress answers the helper's egress subcommand target by target, in its
// grammar, from the targets the backend actually passed. A target with no
// answer here reports error. An OnExec rule matching the same command wins, which
// is how a test scripts output that is not in the grammar.
func (f *Fake) OnEgress(answers map[string]string) {
	f.t.Helper()
	f.edit(func(s *state) {
		s.Egress = make(map[string]string, len(answers))
		for target, answer := range answers {
			s.Egress[target] = answer
		}
	})
}

// Execs returns the recorded exec calls, oldest first.
func (f *Fake) Execs() []ExecCall {
	f.t.Helper()
	var out []ExecCall
	f.edit(func(*state) {
		data, err := os.ReadFile(filepath.Join(f.dir, "exec.log"))
		if err != nil {
			return
		}
		for _, line := range bytes.Split(data, []byte("\n")) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var c ExecCall
			if err := json.Unmarshal(line, &c); err != nil {
				f.t.Fatalf("fakevmpal: bad exec log line: %v", err)
			}
			out = append(out, c)
		}
	})
	return out
}

// ---- state ----

func defaultSettings() map[string]any {
	return map[string]any{
		"agentControl":     true,
		"bluetooth":        false,
		"bridgedInterface": nil,
		"camera":           false,
		"clipboard":        false,
		"cpuCount":         4,
		"diskLimitGB":      64,
		"display":          "1920x1080",
		"dragAndDrop":      false,
		"forwardedPorts":   []any{},
		"gpuAcceleration":  false,
		"localNetwork":     "default",
		"location":         false,
		"memoryGB":         8,
		"microphone":       false,
		"naturalScrolling": false,
		"network":          true,
		"networkMode":      "default",
		"sharedFolders":    []any{},
		"speakers":         true,
		"startAtLogin":     false,
		"vsockForwards":    []any{},
	}
}

func (s *state) find(ref string) int {
	for i := range s.VMs {
		if s.VMs[i].Name == ref {
			return i
		}
	}
	for i := range s.VMs {
		if s.VMs[i].ID == ref {
			return i
		}
	}
	return -1
}

func (s *state) newID() string {
	s.NextID++
	return fmt.Sprintf("vm-%04d", s.NextID)
}

func (vm *VM) stop() {
	vm.State = "stopped"
	vm.SessionHardware = nil
	vm.InternetAddress = ""
	vm.Tools.Connected = false
}

func lockDir(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	lf, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		lf.Close()
		return nil, err
	}
	return func() {
		syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
		lf.Close()
	}, nil
}

func load(dir string) (*state, error) {
	s := &state{}
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	switch {
	case os.IsNotExist(err):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(data, s); err != nil {
			return nil, fmt.Errorf("state is corrupt: %w", err)
		}
	}
	if s.Faults == nil {
		s.Faults = map[string]*faultState{}
	}
	return s, nil
}

// save writes through a rename so a reader that somehow skipped the lock sees
// the old file or the new one, never half of one.
func save(dir string, s *state) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "state.json.tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "state.json"))
}

// ---- the command ----

// Main is the command's entry point.
func Main() int {
	return run(os.Args[1:], os.Stdout, os.Stderr)
}

type result struct {
	out, err string
	code     int
	hang     bool
	delay    time.Duration
}

func fail(code int, format string, a ...any) result {
	return result{err: "vmpal: " + fmt.Sprintf(format, a...) + "\n", code: code}
}

func usage(format string, a ...any) result { return fail(2, format, a...) }

func run(args []string, stdout, stderr io.Writer) int {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "vmpal: cannot find itself:", err)
		return 70
	}
	dir := filepath.Join(filepath.Dir(exe), "state")
	unlock, err := lockDir(dir)
	if err != nil {
		fmt.Fprintln(stderr, "vmpal: cannot lock its state:", err)
		return 70
	}
	st, err := load(dir)
	if err != nil {
		unlock()
		fmt.Fprintln(stderr, "vmpal:", err)
		return 70
	}
	res := dispatch(st, dir, args)
	if err := save(dir, st); err != nil {
		unlock()
		fmt.Fprintln(stderr, "vmpal: cannot save its state:", err)
		return 70
	}
	// Released before any delay or hang, so a stuck command never holds up
	// the next invocation.
	unlock()

	io.WriteString(stdout, res.out)
	io.WriteString(stderr, res.err)
	time.Sleep(res.delay)
	for res.hang {
		time.Sleep(time.Hour)
	}
	return res.code
}

func dispatch(st *state, dir string, args []string) result {
	if len(args) == 0 {
		return usage("a command is required")
	}
	cmd, rest := args[0], args[1:]
	if fs, ok := st.Faults[cmd]; ok && (fs.Fault.Times == 0 || fs.Used < fs.Fault.Times) {
		fs.Used++
		code := fs.Fault.ExitCode
		if code == 0 {
			code = 1
		}
		return result{err: fs.Fault.Stderr, code: code, hang: fs.Fault.Hang}
	}
	switch cmd {
	case "list":
		return cmdList(st, rest)
	case "info":
		return cmdInfo(st, rest)
	case "clone":
		return cmdClone(st, rest)
	case "set":
		return cmdSet(st, rest)
	case "start":
		return cmdStart(st, rest)
	case "exec":
		return cmdExec(st, dir, rest)
	case "stop":
		return cmdStop(st, rest)
	case "delete":
		return cmdDelete(st, rest)
	}
	return usage("unknown command %q", cmd)
}

type parsed struct {
	pos     []string
	vals    map[string][]string
	flags   map[string]bool
	rest    []string
	hasRest bool
}

// parseArgs accepts flags before or after the positionals, and refuses any it
// was not told about: a flag the backend invents should fail here, not pass.
func parseArgs(args []string, valued, boolean []string) (parsed, error) {
	p := parsed{vals: map[string][]string{}, flags: map[string]bool{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			p.rest, p.hasRest = args[i+1:], true
			return p, nil
		case len(a) > 1 && strings.HasPrefix(a, "-"):
			switch {
			case slices.Contains(boolean, a):
				p.flags[a] = true
			case slices.Contains(valued, a):
				if i+1 >= len(args) {
					return p, fmt.Errorf("%s needs a value", a)
				}
				i++
				p.vals[a] = append(p.vals[a], args[i])
			default:
				return p, fmt.Errorf("unknown flag %s", a)
			}
		default:
			p.pos = append(p.pos, a)
		}
	}
	return p, nil
}

func checkTimeout(p parsed) error {
	for _, v := range p.vals["--timeout"] {
		n, err := strconv.Atoi(strings.TrimSuffix(v, "s"))
		if err != nil || n <= 0 || !strings.HasSuffix(v, "s") {
			return fmt.Errorf("--timeout wants a number of seconds such as 30s, not %q", v)
		}
	}
	return nil
}

func notFound(ref string) result {
	return fail(1, "no VM named or numbered %q", ref)
}

func cmdList(st *state, args []string) result {
	p, err := parseArgs(args, nil, []string{"--json"})
	if err != nil || len(p.pos) != 0 || !p.flags["--json"] {
		return usage("list: this fake only speaks list --json")
	}
	type row struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		Guest           string `json:"guest"`
		State           string `json:"state"`
		Installed       bool   `json:"installed"`
		AgentControl    bool   `json:"agentControl"`
		InternetAddress string `json:"internetAddress"`
	}
	rows := []row{}
	for _, vm := range st.VMs {
		rows = append(rows, row{vm.ID, vm.Name, vm.Guest, vm.State, vm.Installed, vm.AgentControl, vm.InternetAddress})
	}
	kept := st.Lingering[:0]
	for _, l := range st.Lingering {
		rows = append(rows, row{l.VM.ID, l.VM.Name, l.VM.Guest, "stopping", l.VM.Installed, l.VM.AgentControl, ""})
		if l.Lists--; l.Lists > 0 {
			kept = append(kept, l)
		}
	}
	st.Lingering = kept
	return jsonResult(map[string]any{"vms": rows})
}

func jsonResult(v any) result {
	data, err := json.Marshal(v)
	if err != nil {
		return fail(70, "%v", err)
	}
	return result{out: string(data) + "\n"}
}

// resolveMode is what "default" means on the host this fake models: bridged.
func resolveMode(settings map[string]any) string {
	if m, _ := settings["networkMode"].(string); m != "" && m != "default" {
		return m
	}
	return "bridged"
}

func effective(st *state, vm VM) VM {
	s := map[string]any{}
	for k, v := range vm.Settings {
		s[k] = v
	}
	for _, k := range st.UnknownSettings {
		s[k] = true
	}
	s["name"] = vm.Name
	s["agentControl"] = vm.AgentControl
	mode, card := resolveMode(vm.Settings), vm.Settings["localNetwork"] == "on"
	if vm.SessionHardware != nil {
		mode, card = vm.SessionHardware.NetworkMode, vm.SessionHardware.LocalNetworkCard
	}
	s["networkModeInEffect"] = mode
	s["localNetworkInEffect"] = card
	s["bridgedInterfaceInEffect"] = nil
	if mode == "bridged" {
		s["bridgedInterfaceInEffect"] = "en0"
	}
	vm.Settings = s
	if vm.PendingSettings == nil {
		vm.PendingSettings = []map[string]any{}
	}
	return vm
}

func cmdInfo(st *state, args []string) result {
	p, err := parseArgs(args, nil, []string{"--json"})
	if err != nil || len(p.pos) != 1 || !p.flags["--json"] {
		return usage("info: want info <vm> --json")
	}
	i := st.find(p.pos[0])
	if i < 0 {
		return notFound(p.pos[0])
	}
	return jsonResult(effective(st, st.VMs[i]))
}

func cmdClone(st *state, args []string) result {
	p, err := parseArgs(args, []string{"--name"}, []string{"-q"})
	if err != nil || len(p.pos) != 1 || len(p.vals["--name"]) != 1 {
		return usage("clone: want clone <template> --name <name> -q")
	}
	i := st.find(p.pos[0])
	if i < 0 {
		return notFound(p.pos[0])
	}
	name := p.vals["--name"][0]
	if st.VMs[i].State != "stopped" {
		return fail(1, "%q is %s; stop it before cloning", st.VMs[i].Name, st.VMs[i].State)
	}
	if st.find(name) >= 0 {
		return fail(1, "a VM named %q already exists", name)
	}
	data, _ := json.Marshal(st.VMs[i])
	var c VM
	if err := json.Unmarshal(data, &c); err != nil {
		return fail(70, "%v", err)
	}
	c.ID, c.Name = st.newID(), name
	c.State, c.InternetAddress, c.SessionHardware, c.PendingSettings = "stopped", "", nil, nil
	c.Tools.Connected = false
	st.VMs = append(st.VMs, c)
	if p.flags["-q"] {
		return result{out: c.ID + "\n"}
	}
	return result{out: fmt.Sprintf("Cloned %s as %s (%s)\n", st.VMs[i].Name, name, c.ID)}
}

var boolSettings = map[string]string{
	"--clipboard": "clipboard", "--drag-and-drop": "dragAndDrop", "--speakers": "speakers",
	"--microphone": "microphone", "--camera": "camera", "--start-at-login": "startAtLogin",
	"--agent-control": "agentControl",
}

var stringSettings = map[string]string{"--network-mode": "networkMode", "--local-network": "localNetwork"}

var listSettings = map[string]string{"--unshare": "sharedFolders", "--unforward": "forwardedPorts", "--vsock-unforward": "vsockForwards"}

// sizeSettings take a whole number; memory also needs the unit the real command
// asks for, so a backend that forgets it fails here.
var sizeSettings = map[string]string{"--cpus": "cpuCount", "--memory": "memoryGB"}

func cmdSet(st *state, args []string) result {
	var valued []string
	for _, m := range []map[string]string{boolSettings, stringSettings, listSettings, sizeSettings} {
		for f := range m {
			valued = append(valued, f)
		}
	}
	p, err := parseArgs(args, valued, nil)
	if err != nil {
		return usage("set: %v", err)
	}
	if len(p.pos) != 1 {
		return usage("set: want set <vm> <flags>")
	}
	i := st.find(p.pos[0])
	if i < 0 {
		return notFound(p.pos[0])
	}
	vm := &st.VMs[i]
	change := func(key string, val any) {
		if slices.Contains(st.NoStick, key) {
			return
		}
		vm.Settings[key] = val
		if key == "agentControl" {
			vm.AgentControl = val.(bool)
		}
		if vm.State == "running" {
			vm.PendingSettings = append(vm.PendingSettings, map[string]any{"key": key, "value": val})
		}
	}
	for flag, key := range boolSettings {
		for _, v := range p.vals[flag] {
			switch v {
			case "on":
				change(key, true)
			case "off":
				change(key, false)
			default:
				return usage("set: %s wants on or off, not %q", flag, v)
			}
		}
	}
	for flag, key := range stringSettings {
		for _, v := range p.vals[flag] {
			if v == "" {
				return usage("set: %s needs a value", flag)
			}
			change(key, v)
		}
	}
	for flag, key := range sizeSettings {
		for _, v := range p.vals[flag] {
			digits := v
			if flag == "--memory" {
				var ok bool
				if digits, ok = strings.CutSuffix(v, "G"); !ok {
					return usage("set: --memory wants a size such as 10G, not %q", v)
				}
			}
			n, err := strconv.Atoi(digits)
			if err != nil || n <= 0 {
				return usage("set: %s wants a positive whole number, not %q", flag, v)
			}
			change(key, n)
		}
	}
	for flag, key := range listSettings {
		for _, v := range p.vals[flag] {
			list, _ := vm.Settings[key].([]any)
			kept := []any{}
			for _, e := range list {
				if entryKey(e) != v {
					kept = append(kept, e)
				}
			}
			change(key, kept)
		}
	}
	return result{}
}

// entryKey reads a list entry as the path or port it names, whether the entry
// is a bare value or an object.
func entryKey(e any) string {
	switch v := e.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case map[string]any:
		for _, k := range []string{"path", "port", "hostPort"} {
			if x, ok := v[k]; ok {
				return entryKey(x)
			}
		}
	}
	return ""
}

func num(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	}
	return 0
}

func cmdStart(st *state, args []string) result {
	p, err := parseArgs(args, []string{"--timeout"}, []string{"--background", "--wait"})
	if err == nil {
		err = checkTimeout(p)
	}
	if err != nil || len(p.pos) != 1 {
		return usage("start: want start <vm> --background --wait --timeout <Ns>")
	}
	i := st.find(p.pos[0])
	if i < 0 {
		return notFound(p.pos[0])
	}
	vm := &st.VMs[i]
	switch {
	case !vm.Installed:
		return fail(1, "%q has no operating system installed", vm.Name)
	case vm.State == "running":
		return fail(1, "%q is already running", vm.Name)
	}
	if vm.Guest == "macOS" {
		running := 0
		for _, o := range st.VMs {
			if o.Guest == "macOS" && o.State == "running" {
				running++
			}
		}
		if running >= maxRunningMacOS {
			return fail(1, "cannot start %q: two macOS VMs are already running, which is the limit Apple allows on one Mac", vm.Name)
		}
	}
	mode := resolveMode(vm.Settings)
	if st.BridgeAtBoot {
		mode = "bridged"
	}
	hw := &SessionHardware{
		NetworkMode:      mode,
		LocalNetworkCard: vm.Settings["localNetwork"] == "on",
		CPUCount:         num(vm.Settings["cpuCount"]),
		MemoryGB:         num(vm.Settings["memoryGB"]),
	}
	if st.BootCPUs > 0 {
		hw.CPUCount = st.BootCPUs
	}
	if st.BootMemoryGB > 0 {
		hw.MemoryGB = st.BootMemoryGB
	}
	if mode == "bridged" {
		en0 := "en0"
		hw.BridgedInterface = &en0
	}
	h := fnv.New32a()
	h.Write([]byte(vm.ID))
	vm.State, vm.SessionHardware, vm.PendingSettings = "running", hw, nil
	vm.InternetAddress = fmt.Sprintf("192.0.2.%d", 10+h.Sum32()%240)
	vm.Tools.Connected = !st.ToolsNeverConnect
	if st.ToolsNeverConnect && p.flags["--wait"] {
		return result{err: "vmpal: timed out waiting for VMPal Tools to connect\n", code: 1, delay: toolsTimeoutDelay}
	}
	return result{}
}

func cmdExec(st *state, dir string, args []string) result {
	p, err := parseArgs(args, []string{"--timeout", "--env"}, nil)
	if err == nil {
		err = checkTimeout(p)
	}
	if err != nil || len(p.pos) != 1 || !p.hasRest || len(p.rest) == 0 {
		return usage("exec: want exec <vm> --timeout <Ns> [--env NAME], a literal double hyphen, then the command")
	}
	i := st.find(p.pos[0])
	if i < 0 {
		return notFound(p.pos[0])
	}
	vm := st.VMs[i]
	if vm.State != "running" || !vm.Tools.Connected {
		return fail(125, "%q is not running with VMPal Tools connected", vm.Name)
	}
	env := map[string]string{}
	for _, n := range p.vals["--env"] {
		env[n] = os.Getenv(n)
	}
	line, _ := json.Marshal(ExecCall{VM: vm.Name, Argv: p.rest, Env: env})
	f, err := os.OpenFile(filepath.Join(dir, "exec.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fail(70, "%v", err)
	}
	_, err = f.Write(append(line, '\n'))
	f.Close()
	if err != nil {
		return fail(70, "%v", err)
	}
	joined := strings.Join(p.rest, " ")
	for _, r := range st.Rules {
		if strings.Contains(joined, r.Match) {
			return result{out: r.Reply.Stdout, err: r.Reply.Stderr, code: r.Reply.ExitCode, hang: r.Reply.Hang}
		}
	}
	if st.Egress != nil && strings.Contains(joined, "helper.sh egress") {
		return result{out: egressAnswer(st.Egress, env["ZOOMIES_EGRESS_TARGETS"])}
	}
	return result{}
}

func egressAnswer(answers map[string]string, targets string) string {
	var out strings.Builder
	fields := strings.Fields(targets)
	for i, target := range fields {
		answer, ok := answers[target]
		if !ok {
			answer = "error"
		}
		fmt.Fprintf(&out, "zoomies-egress v1 target %d %s\n", i, answer)
	}
	fmt.Fprintf(&out, "zoomies-egress v1 end %d\n", len(fields))
	return out.String()
}

func cmdStop(st *state, args []string) result {
	p, err := parseArgs(args, []string{"--timeout"}, []string{"--force"})
	if err == nil {
		err = checkTimeout(p)
	}
	if err != nil || len(p.pos) != 1 {
		return usage("stop: want stop <vm> --force --timeout <Ns>")
	}
	i := st.find(p.pos[0])
	if i < 0 {
		return notFound(p.pos[0])
	}
	st.VMs[i].stop()
	return result{}
}

func cmdDelete(st *state, args []string) result {
	p, err := parseArgs(args, nil, []string{"--force", "--permanently"})
	if err != nil || len(p.pos) != 1 {
		return usage("delete: want delete <vm> --force --permanently")
	}
	i := st.find(p.pos[0])
	if i < 0 {
		return notFound(p.pos[0])
	}
	vm := st.VMs[i]
	if vm.State == "running" && !p.flags["--force"] {
		return fail(1, "%q is running; stop it or pass --force", vm.Name)
	}
	st.VMs = slices.Delete(st.VMs, i, i+1)
	if !p.flags["--permanently"] {
		st.Trash = append(st.Trash, vm.Name)
		return result{out: "moved to the Trash\n"}
	}
	if st.DeleteLinger > 0 {
		st.Lingering = append(st.Lingering, lingeringVM{VM: vm, Lists: st.DeleteLinger})
	}
	return result{}
}
