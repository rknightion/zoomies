package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"time"
)

const (
	// vmpalOutputCap bounds what one call may leave in memory. Once a job is
	// running the guest writes what its commands print, and VMPal will carry up
	// to a gibibyte of it per stream.
	vmpalOutputCap = 1 << 20
	// vmpalStopGrace is how long a command gets to act on SIGTERM. vmpal
	// forwards that signal to the command in the guest, which a SIGKILL cannot
	// do, and a command left running there keeps one of the VM's two exec slots.
	vmpalStopGrace = 5 * time.Second
	// vmpalQueryLimit keeps a read short enough for Probe to make two of them
	// inside the agent's probe budget.
	vmpalQueryLimit  = 4 * time.Second
	vmpalCloneLimit  = 45 * time.Second
	vmpalSetLimit    = 30 * time.Second
	vmpalDeleteLimit = 60 * time.Second
	// vmpalDetailLimit is how much of a failed command's stderr reaches an
	// error message, and from there the operator's screen.
	vmpalDetailLimit = 500
)

// vmpalCLI runs the documented vmpal command. It is the only code that does,
// so the rules every call has to follow are kept in one place: a time limit, a
// bounded output, a minimal environment and no secret in an argument.
type vmpalCLI struct {
	binary    string
	outputCap int
	stopGrace time.Duration
}

func newVMPalCLI(binary string) *vmpalCLI {
	return &vmpalCLI{binary: binary, outputCap: vmpalOutputCap, stopGrace: vmpalStopGrace}
}

// vmpalOutput is what one command left behind. A non-zero ExitCode is not an
// error here, because for exec it is the guest command's own answer.
type vmpalOutput struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Truncated bool
}

// vmpalCallError says which command failed without repeating its arguments,
// which can name a guest path or a VM an operator has no reason to read about.
type vmpalCallError struct {
	Command  string
	ExitCode int
	TimedOut bool
	Detail   string
}

func (e *vmpalCallError) Error() string {
	if e.TimedOut {
		return fmt.Sprintf("vmpal %s did not finish in time; check that VMPal is running in the logged-in session on this Mac", e.Command)
	}
	if e.Detail == "" {
		return fmt.Sprintf("vmpal %s failed with exit status %d", e.Command, e.ExitCode)
	}
	return fmt.Sprintf("vmpal %s failed with exit status %d: %s", e.Command, e.ExitCode, e.Detail)
}

// vmpalVM is one row of vmpal list, and the part of vmpal info they share.
type vmpalVM struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Guest           string `json:"guest"`
	State           string `json:"state"`
	Installed       bool   `json:"installed"`
	AgentControl    bool   `json:"agentControl"`
	InternetAddress string `json:"internetAddress"`
}

// vmpalSessionHardware is what a running VM actually has, as opposed to the
// settings it will have at its next start.
type vmpalSessionHardware struct {
	NetworkMode string `json:"networkMode"`
	// A pointer and a raw value, because absent has to differ from the safe
	// answer: a release that stops reporting one of these has not shown that
	// the clone is isolated. BridgedInterface holds the literal null when the
	// field is there and empty, and nothing at all when it is missing.
	LocalNetworkCard *bool           `json:"localNetworkCard"`
	BridgedInterface json.RawMessage `json:"bridgedInterface"`
	// Pointers, so a release that stops reporting the size reads as unknown
	// rather than as zero. Floats, so a fractional size fails the comparison
	// rather than failing to decode the whole answer.
	CPUCount *float64 `json:"cpuCount"`
	MemoryGB *float64 `json:"memoryGB"`
}

type vmpalTools struct {
	Connected bool   `json:"connected"`
	Version   string `json:"version"`
}

// vmpalInfo is one VM in full. Settings stays a map on purpose: the hardening
// check refuses a key it has not classified, so a sharing feature a later
// VMPal adds cannot pass unread, and a struct would drop that key here.
type vmpalInfo struct {
	vmpalVM
	PendingSettings []json.RawMessage          `json:"pendingSettings"`
	Settings        map[string]json.RawMessage `json:"settings"`
	SessionHardware *vmpalSessionHardware      `json:"sessionHardware"`
	Tools           vmpalTools                 `json:"tools"`
}

// List returns every VM VMPal knows about, including ones this agent must
// never touch. Deciding which are ours is the caller's job.
func (c *vmpalCLI) List(ctx context.Context) ([]vmpalVM, error) {
	out, err := c.checked(ctx, vmpalQueryLimit, nil, "list", "--json")
	if err != nil {
		return nil, err
	}
	// A pointer, because an answer with no list says nothing about what is on
	// the Mac. Read as an empty list it would make every clone look gone, and a
	// live job would be reaped for it.
	var doc struct {
		VMs *[]vmpalVM `json:"vms"`
	}
	if err := decodeVMPal(out, "list", &doc); err != nil {
		return nil, err
	}
	if doc.VMs == nil {
		return nil, &vmpalCallError{Command: "list", Detail: "its output had no list of VMs; check that this version of VMPal is supported"}
	}
	return *doc.VMs, nil
}

// Info returns one VM in full.
func (c *vmpalCLI) Info(ctx context.Context, vm string) (vmpalInfo, error) {
	var info vmpalInfo
	if err := checkVMPalRef(vm); err != nil {
		return info, err
	}
	out, err := c.checked(ctx, vmpalQueryLimit, nil, "info", vm, "--json")
	if err != nil {
		return info, err
	}
	return info, decodeVMPal(out, "info", &info)
}

// Clone makes a stopped clone. It never passes --shut-down: the template may be
// running because somebody is working on it, and that is theirs to finish.
func (c *vmpalCLI) Clone(ctx context.Context, template, name string) error {
	if err := checkVMPalRef(template); err != nil {
		return err
	}
	if err := checkVMPalRef(name); err != nil {
		return err
	}
	_, err := c.checked(ctx, vmpalCloneLimit, nil, "clone", template, "--name", name, "-q")
	return err
}

// Set changes a VM's settings.
func (c *vmpalCLI) Set(ctx context.Context, vm string, flags ...string) error {
	if err := checkVMPalRef(vm); err != nil {
		return err
	}
	_, err := c.checked(ctx, vmpalSetLimit, nil, append([]string{"set", vm}, flags...)...)
	return err
}

// Start boots a VM without a window and waits until it can run commands.
func (c *vmpalCLI) Start(ctx context.Context, vm string, limit time.Duration) error {
	if err := checkVMPalRef(vm); err != nil {
		return err
	}
	_, err := c.checked(ctx, limit+c.stopGrace, nil, "start", vm, "--background", "--wait", "--timeout", vmpalDuration(limit))
	return err
}

// Exec runs a command in a running VM. Values in env reach vmpal through its
// environment and are named with --env NAME, which is the form that keeps them
// off this Mac's process list.
func (c *vmpalCLI) Exec(ctx context.Context, vm string, limit time.Duration, env map[string]string, argv ...string) (vmpalOutput, error) {
	if err := checkVMPalRef(vm); err != nil {
		return vmpalOutput{}, err
	}
	args := []string{"exec", vm, "--timeout", vmpalDuration(limit)}
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		args = append(args, "--env", name)
	}
	args = append(args, "--")
	args = append(args, argv...)
	return c.run(ctx, limit+c.stopGrace, env, args...)
}

// Stop turns a VM off at once.
func (c *vmpalCLI) Stop(ctx context.Context, vm string, limit time.Duration) error {
	if err := checkVMPalRef(vm); err != nil {
		return err
	}
	_, err := c.checked(ctx, limit+c.stopGrace, nil, "stop", vm, "--force", "--timeout", vmpalDuration(limit))
	return err
}

// Delete removes a VM for good. Without --permanently a deleted clone goes to
// the Trash, and each one there still holds its disk.
func (c *vmpalCLI) Delete(ctx context.Context, vm string) error {
	if err := checkVMPalRef(vm); err != nil {
		return err
	}
	_, err := c.checked(ctx, vmpalDeleteLimit, nil, "delete", vm, "--force", "--permanently")
	return err
}

// checked is run for the commands whose non-zero exit is a failure.
func (c *vmpalCLI) checked(ctx context.Context, limit time.Duration, env map[string]string, args ...string) (vmpalOutput, error) {
	out, err := c.run(ctx, limit, env, args...)
	if err != nil {
		return out, err
	}
	if out.ExitCode != 0 {
		detail := strings.TrimSpace(out.Stderr)
		if len(detail) > vmpalDetailLimit {
			detail = detail[len(detail)-vmpalDetailLimit:]
		}
		return out, &vmpalCallError{Command: args[0], ExitCode: out.ExitCode, Detail: detail}
	}
	return out, nil
}

func (c *vmpalCLI) run(ctx context.Context, limit time.Duration, env map[string]string, args ...string) (vmpalOutput, error) {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	stdout, stderr := &cappedBuffer{limit: c.outputCap}, &cappedBuffer{limit: c.outputCap}
	cmd := exec.CommandContext(ctx, c.binary, args...)
	cmd.Env = vmpalChildEnv(env)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = c.stopGrace

	err := cmd.Run()
	out := vmpalOutput{
		Stdout:    redactVMPalValues(stdout.String(), env),
		Stderr:    redactVMPalValues(stderr.String(), env),
		Truncated: stdout.truncated || stderr.truncated,
	}
	if ctx.Err() != nil {
		return out, &vmpalCallError{Command: args[0], ExitCode: -1, TimedOut: true}
	}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		out.ExitCode = exit.ExitCode()
	case errors.Is(err, exec.ErrWaitDelay):
		// The command finished and something it started kept the pipe open.
		out.ExitCode = cmd.ProcessState.ExitCode()
	default:
		return out, fmt.Errorf("%w: could not run %s: %v", ErrUnavailable, c.binary, err)
	}
	return out, nil
}

// vmpalChildEnv is built from nothing rather than filtered from this process's
// environment, so a variable that changes how a program loads (DYLD_ and the
// like) cannot reach a command that controls the VMs.
func vmpalChildEnv(extra map[string]string) []string {
	env := []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	for _, name := range []string{"HOME", "USER"} {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	for name, value := range extra {
		env = append(env, name+"="+value)
	}
	return env
}

// checkVMPalRef refuses a name vmpal would read as an option. A template name
// comes from configuration, and "--force" is not a VM.
func checkVMPalRef(ref string) error {
	if ref == "" || strings.HasPrefix(ref, "-") {
		return fmt.Errorf("%q is not a VM name vmpal can be given", ref)
	}
	return nil
}

func decodeVMPal(out vmpalOutput, command string, into any) error {
	if out.Truncated {
		return &vmpalCallError{Command: command, Detail: "its output was too large to read"}
	}
	if err := json.Unmarshal([]byte(out.Stdout), into); err != nil {
		return &vmpalCallError{Command: command, Detail: "its output was not the JSON this version of Zoomies expects: " + err.Error()}
	}
	return nil
}

func vmpalDuration(d time.Duration) string {
	return fmt.Sprintf("%ds", max(int(d.Seconds()), 1))
}

func redactVMPalValues(s string, env map[string]string) string {
	for _, value := range env {
		if value != "" {
			s = strings.ReplaceAll(s, value, "[redacted]")
		}
	}
	return s
}

// cappedBuffer keeps the first limit bytes and swallows the rest. It never
// reports a short write, because failing the write would kill a command for
// being talkative and lose the exit status the caller came for.
type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	room := b.limit - b.buf.Len()
	if room < len(p) {
		b.truncated = true
		if room > 0 {
			b.buf.Write(p[:room])
		}
		return len(p), nil
	}
	b.buf.Write(p)
	return len(p), nil
}

func (b *cappedBuffer) String() string { return b.buf.String() }
