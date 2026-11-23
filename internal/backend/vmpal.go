package backend

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eyupio/zoomies/internal/store"
)

// A macOS VM backend runs each job in a throwaway clone of a prepared template,
// through the documented vmpal command. It reports itself as the process kind,
// so the controller needs no change to schedule it.
//
// Two things shape everything below. A clone is not trusted with a credential
// until it has been shown to be on the expected network, and from the moment a
// job has run in it the guest is not trusted at all: what it prints is parsed
// strictly and the host runs nothing it supplies.

const (
	vmpalProbeLimit     = 8 * time.Second
	vmpalBootLimit      = 7 * time.Minute
	vmpalVerifyLimit    = 90 * time.Second
	vmpalGuestStepLimit = 15 * time.Second
	vmpalArmLimit       = 3 * time.Minute
	vmpalDeliverLimit   = 30 * time.Second
	// vmpalCleanupLimit is what a failed create gets to remove its clone, on a
	// context of its own: the create's own may have just run out.
	vmpalCleanupLimit = 60 * time.Second
	// vmpalForceOffLimit plus the command's stop grace is the 20 seconds the
	// agent's 30-second stop margin leaves room for, after a read that overran
	// its deadline by that same grace.
	vmpalForceOffLimit = 15 * time.Second
	vmpalStopPoll      = 2 * time.Second
	// vmpalRemoveWait is how long a removal waits for a deleted VM to leave the
	// list, which it does a few seconds after the command has returned.
	vmpalRemoveWait  = 20 * time.Second
	vmpalRemoveEvery = 500 * time.Millisecond
	// vmpalDeleteAgain is how long a delete that was accepted is left to finish
	// before it is issued again.
	vmpalDeleteAgain = 60 * time.Second
	// vmpalAddressWait covers a guest that can run commands a moment before its
	// DHCP lease shows up in vmpal info.
	vmpalAddressWait = 15 * time.Second
	vmpalLogPoll     = 2 * time.Second
	// vmpalMacOSLimit is Apple's limit on macOS VMs running on one Mac, counting
	// those of every other app.
	vmpalMacOSLimit = 2
	// vmpalFinalRead bounds the whole of a removal's wait for a guest's exit
	// record. GitHub can report a job finished just before the guest has written
	// it, so a "running" answer is asked again, but the clone is being deleted
	// either way and a guest must not be able to put that off.
	vmpalFinalRead = 3 * time.Second
	// vmpalFinalReadEvery is how often that look is repeated while the guest
	// says its runner has not finished.
	vmpalFinalReadEvery = 250 * time.Millisecond
	// vmpalSpentKeep is how long a runner stays refused after its registration
	// was sent, which is far longer than a redelivered create can arrive.
	vmpalSpentKeep = 24 * time.Hour
	// vmpalDefaultBinary is where VMPal installs its command.
	vmpalDefaultBinary = "/usr/local/bin/vmpal"
)

// VMPalSlotsOccupiedDetail opens Probe's answer when VMs Zoomies does not manage
// hold every slot. The installer reads it, because that host works and is only
// full for now, and Info has no reason field to carry it without a wire change.
const VMPalSlotsOccupiedDetail = "macOS VMs Zoomies does not manage hold all"

// vmpalGate decides whether a clone may be made and whether a booted clone may receive a credential.
type vmpalGate interface {
	// Held says why this host is refusing new clones for now, or nil. It runs
	// no command, so a host on hold refuses at once.
	Held() error
	// Admit runs under the admission lock, before the ledger entry is written.
	Admit(ctx context.Context, slots vmpalSlotUse) error
	// Verify runs after the network read-back and session check, before anything is delivered.
	Verify(ctx context.Context, clone vmpalInfo) error
	// RunnerExited records one finished runner for the breaker.
	RunnerExited(tookJob, stopRequested bool)
}

// errVMPalHeld is a refusal to make a clone for now. It wraps neither
// ErrUnavailable, which would raise a false container-runtime incident, nor the
// busy sentinel, which the agent answers by retrying at once.
var errVMPalHeld = errors.New("backend: this Mac is not taking new VM runners for now")

// vmpalRefusingGate is the gate of a backend nobody gave one. It refuses both
// questions, so that no configuration can reach a credential delivery without
// the check that is meant to come before it.
type vmpalRefusingGate struct {
	// reason says what is missing from the policy, when that is known.
	reason string
}

func (g vmpalRefusingGate) refusal() error {
	reason := g.reason
	if reason == "" {
		reason = "this agent has no check that the Mac's network policy is in force"
	}
	return fmt.Errorf("%w: %s, so it makes no clone and delivers no credential", errVMPalHeld, reason)
}

func (g vmpalRefusingGate) Held() error                               { return g.refusal() }
func (g vmpalRefusingGate) Admit(context.Context, vmpalSlotUse) error { return g.refusal() }
func (g vmpalRefusingGate) Verify(context.Context, vmpalInfo) error   { return g.refusal() }
func (vmpalRefusingGate) RunnerExited(bool, bool)                     {}

// VMPalOptions configures the macOS VM backend.
type VMPalOptions struct {
	// GOOS is the host's operating system. Empty means the real one.
	GOOS string
	// Now is the clock. Nil means the real one.
	Now func() time.Time
	// Binary is the vmpal command. Empty means where VMPal installs it.
	Binary string
	// Template is the shut-down VM every clone is made from.
	Template string
	// MaxVMs is how many clones this agent may hold at once.
	MaxVMs int
	// CPUs and MemoryGB size each clone. Zero inherits the template's value.
	CPUs     int
	MemoryGB int
	// GuestCIDR is the IPv4 network a clone must come up on.
	GuestCIDR string
	// EgressMustAllow and EgressMustBlock are the host:port targets of the
	// egress check.
	EgressMustAllow []string
	EgressMustBlock []string
	// PolicyCheck is the command that attests the host's firewall policy.
	PolicyCheck string
	// EgressDial is how the Mac itself connects to a must-block target. Nil
	// means a real TCP connection.
	EgressDial func(ctx context.Context, address string) error
	// WorkDir is the agent's work directory; state lives under vmpal/ in it.
	WorkDir string
	// RunnerVersion is the actions/runner release used when a pool pins none.
	RunnerVersion string
	// RunnerSHA256 is the archive's digest for RunnerVersion. There is no
	// unverified-download override here: a guest runs what it is given.
	RunnerSHA256 string
	// DownloadBaseURL overrides where the guest fetches the runner from.
	DownloadBaseURL string
	// Gate decides admission and delivery. Nil builds the real one from the
	// policy above, and refuses both if that policy is incomplete.
	Gate   vmpalGate
	Logger *slog.Logger
}

// VMPalBackend runs each runner in its own clone.
type VMPalBackend struct {
	// probedHeld is whether the last Probe found a hold, and reprobe asks for a
	// fresh one. A healthy host is probed every five minutes, and until the next
	// probe the controller goes on minting registrations for a host that is
	// refusing them.
	probedHeld atomic.Bool
	reprobe    atomic.Bool

	cli         *vmpalCLI
	goos        string
	template    string
	maxVMs      int
	cpus        int
	memoryGB    int
	guestNet    *net.IPNet
	mustAllow   []string
	mustBlock   []string
	policyCheck string
	spentDir    string
	installID   string
	version     string
	sha256      string
	baseURL     string
	gate        vmpalGate
	now         func() time.Time
	log         *slog.Logger

	// admitMu holds one admission at a time across the list it decides from,
	// so two creates cannot both take the last slot. It is separate from mu
	// because that list is a subprocess, and List and Status must not queue
	// behind it.
	admitMu sync.Mutex
	// mu guards the ledger and the maps below. Keeping the ledger under it is
	// what lets List read "this entry is at Intent" and "a create owns it" as
	// one fact.
	mu       sync.Mutex
	ledger   *vmpalLedger
	creating map[string]bool
	watchers map[string]*vmpalWatcher
	slots    map[string]*vmpalSlots
	// removing is the clones the agent has asked to have deleted, until they
	// have gone. It lasts across the retries of a slow delete, and it is memory
	// on purpose: after a restart nobody is known to have asked.
	removing map[string]bool
	// forcedOff is the clones this process turned off itself, so that a VM seen
	// stopped before its result could be written is not taken for a guest that
	// powered itself off.
	forcedOff map[string]bool
	// abandoned is the clones a breach purge has condemned. It is separate from
	// removing because nobody asked for this end: a purged clone whose exit
	// could not be written is a failure to report, not a removal in progress.
	// It is memory for the same reason removing is, and because the disk being
	// full is the case it exists for.
	abandoned map[string]bool
	// deliveries cancels the credential delivery a clone has in flight.
	deliveries map[string]context.CancelFunc
	closed     bool

	baseCtx    context.Context
	baseCancel context.CancelFunc
	wg         sync.WaitGroup

	// Intervals, held here so a test can shorten them.
	watchEvery  time.Duration
	stopPoll    time.Duration
	removeWait  time.Duration
	removeEvery time.Duration
	logPoll     time.Duration
	addressWait time.Duration
	finalRead   time.Duration
	// finalWait is how long a removal goes on asking a guest that answers
	// "still running". The whole wait is held to the larger of this and
	// finalRead, and in production the two are the same budget.
	finalWait  time.Duration
	finalEvery time.Duration
	// afterDropRemoved runs in List just after dropRemoved, so a test can finish
	// a removal at that exact point. Nil outside tests.
	afterDropRemoved func()
}

var (
	_ Backend      = (*VMPalBackend)(nil)
	_ TimedCreator = (*VMPalBackend)(nil)
)

// NewVMPal builds the backend and its state directories.
func NewVMPal(opts VMPalOptions) (*VMPalBackend, error) {
	work := strings.TrimSpace(opts.WorkDir)
	if work == "" {
		return nil, fmt.Errorf("%w: the macOS VM backend needs agent.work_dir set to a writable directory", ErrBackendConfig)
	}
	work, err := filepath.Abs(work)
	if err != nil {
		return nil, fmt.Errorf("backend: resolving the work directory: %w", err)
	}
	if err := checkVMPalRef(opts.Template); err != nil {
		return nil, fmt.Errorf("%w: agent.vmpal.template: %v", ErrBackendConfig, err)
	}
	_, guestNet, err := net.ParseCIDR(strings.TrimSpace(opts.GuestCIDR))
	if err != nil || guestNet.IP.To4() == nil {
		return nil, fmt.Errorf("%w: agent.vmpal.guest_cidr must be an IPv4 network such as 192.0.2.0/24", ErrBackendConfig)
	}
	if opts.CPUs < 0 || opts.MemoryGB < 0 {
		return nil, fmt.Errorf("%w: a macOS VM's CPU count and memory must be positive, or zero to inherit them from the template", ErrBackendConfig)
	}
	binary := opts.Binary
	if binary == "" {
		binary = vmpalDefaultBinary
	}
	if !filepath.IsAbs(binary) {
		return nil, fmt.Errorf("%w: agent.vmpal.binary must be an absolute path", ErrBackendConfig)
	}

	root := filepath.Join(work, "vmpal")
	clones := filepath.Join(root, "clones")
	if err := os.MkdirAll(clones, 0o700); err != nil {
		return nil, fmt.Errorf("backend: creating the VM state directory: %w", err)
	}
	spentDir := filepath.Join(root, "spent")
	if err := os.MkdirAll(spentDir, 0o700); err != nil {
		return nil, fmt.Errorf("backend: creating the VM state directory: %w", err)
	}
	installID, err := loadVMPalInstallID(root)
	if err != nil {
		return nil, err
	}

	goos := opts.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	version := strings.TrimPrefix(strings.TrimSpace(opts.RunnerVersion), "v")
	if version == "" {
		version = DefaultRunnerVersion
	}
	base := strings.TrimSuffix(strings.TrimSpace(opts.DownloadBaseURL), "/")
	if base == "" {
		base = defaultRunnerDownloadURL
	}
	maxVMs := opts.MaxVMs
	if maxVMs <= 0 {
		maxVMs = 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &VMPalBackend{
		cli:         newVMPalCLI(binary),
		goos:        goos,
		template:    opts.Template,
		maxVMs:      maxVMs,
		cpus:        opts.CPUs,
		memoryGB:    opts.MemoryGB,
		guestNet:    guestNet,
		mustAllow:   slices.Clone(opts.EgressMustAllow),
		mustBlock:   slices.Clone(opts.EgressMustBlock),
		policyCheck: strings.TrimSpace(opts.PolicyCheck),
		spentDir:    spentDir,
		installID:   installID,
		version:     version,
		sha256:      strings.ToLower(strings.TrimSpace(opts.RunnerSHA256)),
		baseURL:     base,
		gate:        opts.Gate,
		now:         now,
		log:         logger.With("backend", "vmpal"),
		ledger:      &vmpalLedger{dir: clones},
		creating:    make(map[string]bool),
		watchers:    make(map[string]*vmpalWatcher),
		slots:       make(map[string]*vmpalSlots),
		removing:    make(map[string]bool),
		forcedOff:   make(map[string]bool),
		abandoned:   make(map[string]bool),
		deliveries:  make(map[string]context.CancelFunc),
		baseCtx:     ctx,
		baseCancel:  cancel,
		watchEvery:  vmpalWatchEvery,
		stopPoll:    vmpalStopPoll,
		removeWait:  vmpalRemoveWait,
		removeEvery: vmpalRemoveEvery,
		logPoll:     vmpalLogPoll,
		addressWait: vmpalAddressWait,
		finalRead:   vmpalFinalRead,
		finalWait:   vmpalFinalRead,
		finalEvery:  vmpalFinalReadEvery,
	}
	if b.gate == nil {
		b.gate = b.policyGate(opts, filepath.Join(root, "state.json"))
	}
	return b, nil
}

// NewVMPalRegistry is a registry holding only the VM backend. Docker, Podman
// and the bare process backend are left out on purpose: any of them on this
// host would be a way for a job to run on the Mac itself.
func NewVMPalRegistry(opts VMPalOptions) (*Registry, error) {
	b, err := NewVMPal(opts)
	if err != nil {
		return nil, err
	}
	return NewRegistry(b), nil
}

// Kind is process: the controller schedules this as a process pool.
func (b *VMPalBackend) Kind() store.BackendKind { return store.BackendProcess }

// Close stops the watchers. It leaves every clone running: a runner outlives an
// agent restart, and the next agent adopts it from the ledger.
func (b *VMPalBackend) Close() {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.baseCancel()
	b.wg.Wait()
}

// ---- ownership ----

func (b *VMPalBackend) vmName(runnerID string) string {
	return "zoomies-vm-" + b.installID + "-" + runnerID
}

// ownedRunner returns the runner a VM belongs to, if it belongs to this agent.
// Everything that deletes or stops a VM starts here.
func (b *VMPalBackend) ownedRunner(name string) (string, bool) {
	m := vmpalNamePattern.FindStringSubmatch(name)
	if m == nil || m[1] != b.installID || name == b.template {
		return "", false
	}
	return m[2], true
}

func errVMPalNotOurs(name string) error {
	return fmt.Errorf("backend: refusing to act on VM %q, which this agent did not create", name)
}

func (b *VMPalBackend) readEntry(name string) (vmpalEntry, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ledger.read(name)
}

// advance moves a clone to a later stage. It fails once the clone is being
// deleted, so a create cannot carry on delivering to a VM that is on its way out.
func (b *VMPalBackend) advance(name string, stage vmpalStage, change func(*vmpalEntry)) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok, err := b.ledger.read(name)
	if err != nil {
		return err
	}
	// removing and abandoned as well as the stage, because on a full disk the
	// stage may never have been written.
	if !ok || e.Stage == vmpalStageDeleting || b.removing[name] || b.abandoned[name] {
		return fmt.Errorf("backend: clone %s is being deleted, so its create was abandoned", name)
	}
	if stage.rank() > e.Stage.rank() {
		e.Stage = stage
	}
	if change != nil {
		change(&e)
	}
	e.UpdatedAt = b.now()
	return b.ledger.write(e)
}

// ---- exec slots ----

// vmpalSlots is one VM's share of VMPal's two concurrent commands. A log reader
// needs a second token as well, so however many followers there are, they can
// hold only one slot and the watcher and Stop always have the other.
type vmpalSlots struct {
	exec chan struct{}
	logs chan struct{}
}

func (b *VMPalBackend) slotsFor(name string) *vmpalSlots {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.slots[name]
	if s == nil {
		s = &vmpalSlots{exec: make(chan struct{}, 2), logs: make(chan struct{}, 1)}
		b.slots[name] = s
	}
	return s
}

func (s *vmpalSlots) acquire(ctx context.Context) (func(), error) {
	select {
	case s.exec <- struct{}{}:
		return func() { <-s.exec }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *vmpalSlots) acquireForLogs(ctx context.Context) (func(), error) {
	select {
	case s.logs <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	release, err := s.acquire(ctx)
	if err != nil {
		<-s.logs
		return nil, err
	}
	return func() { release(); <-s.logs }, nil
}

// helper runs one helper subcommand in a slot. Output from a subcommand that
// runs after delivery stays out of the error: by then the guest writes it, and
// it would go straight to an operator's screen.
func (b *VMPalBackend) helper(ctx context.Context, name string, limit time.Duration, env map[string]string, sub string, args ...string) (vmpalOutput, error) {
	release, err := b.slotsFor(name).acquire(ctx)
	if err != nil {
		return vmpalOutput{}, err
	}
	defer release()
	return b.runHelper(ctx, name, limit, env, sub, args...)
}

func (b *VMPalBackend) runHelper(ctx context.Context, name string, limit time.Duration, env map[string]string, sub string, args ...string) (vmpalOutput, error) {
	out, err := b.cli.Exec(ctx, name, limit, env, vmpalHelperArgv(sub, args...)...)
	if err != nil {
		return out, err
	}
	if out.ExitCode != 0 {
		call := &vmpalCallError{Command: "exec " + sub, ExitCode: out.ExitCode}
		if sub == "session" || sub == "arm" {
			call.Detail = strings.TrimSpace(out.Stderr)
			if len(call.Detail) > vmpalDetailLimit {
				call.Detail = call.Detail[len(call.Detail)-vmpalDetailLimit:]
			}
		}
		return out, call
	}
	return out, nil
}

// ---- Probe ----

// Probe says whether this host can take a clone now, and why not in words an
// operator can act on. A Mac busy with its own clones is still available.
func (b *VMPalBackend) Probe(ctx context.Context) Info {
	info := Info{Kind: store.BackendProcess, Endpoint: b.cli.binary}
	refuse := func(detail string) Info {
		info.Detail = detail
		return info
	}
	if b.goos != "darwin" {
		return refuse("the macOS VM backend only runs on a Mac; this host runs " + b.goos)
	}
	held := b.gate.Held()
	b.probedHeld.Store(held != nil)
	if held != nil {
		return refuse(strings.TrimPrefix(held.Error(), "backend: "))
	}
	if b.policyCheck == "" {
		return refuse("no network policy check is configured, so this host will not start VM runners; set agent.vmpal.policy_check")
	}
	ctx, cancel := context.WithTimeout(ctx, vmpalProbeLimit)
	defer cancel()
	vms, err := b.cli.List(ctx)
	if err != nil {
		return refuse(fmt.Sprintf("could not list VMs: %v", err))
	}
	// Only other people's VMs can make this host unavailable. Its own clones
	// filling every slot is a busy host doing its job.
	if foreign := countVMPalSlots(vms, nil, b.ownedRunner).Foreign; len(foreign) >= vmpalMacOSLimit {
		return refuse(fmt.Sprintf("%s %d of this host's VM slots (%s); shut one down to free a slot", VMPalSlotsOccupiedDetail, vmpalMacOSLimit, strings.Join(foreign, ", ")))
	}
	template, err := b.cli.Info(ctx, b.template)
	if err != nil {
		return refuse(fmt.Sprintf("could not read the template %q: %v", b.template, err))
	}
	if err := checkVMPalTemplate(template); err != nil {
		return refuse(err.Error())
	}
	info.Available = true
	return info
}

var _ ProbeInvalidator = (*VMPalBackend)(nil)

// ProbeStale says the last Probe no longer describes this host: a hold has
// started or ended, or a clone failed. It clears on read, so each change costs
// one extra probe.
func (b *VMPalBackend) ProbeStale() bool {
	held := b.gate.Held() != nil
	changed := b.probedHeld.Swap(held) != held
	return b.reprobe.Swap(false) || changed
}

// checkVMPalTemplate holds a template to what a clone of it needs.
func checkVMPalTemplate(t vmpalInfo) error {
	switch {
	case t.Guest != "macOS":
		return fmt.Errorf("the template %q is a %s VM; it must be macOS", t.Name, t.Guest)
	case !t.Installed:
		return fmt.Errorf("the template %q has no system installed", t.Name)
	case t.State != "stopped":
		return fmt.Errorf("the template %q is %s; shut it down, because only a shut-down VM can be cloned", t.Name, t.State)
	case !t.AgentControl:
		return fmt.Errorf("the template %q has agent control off; turn it on", t.Name)
	case !vmpalToolsAtLeast(t.Tools.Version, 0, 34):
		return fmt.Errorf("the template %q has VMPal Tools %q; it needs 0.34 or later", t.Name, t.Tools.Version)
	}
	return nil
}

func vmpalToolsAtLeast(version string, major, minor int) bool {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false
	}
	gotMajor, err1 := strconv.Atoi(parts[0])
	gotMinor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return gotMajor > major || (gotMajor == major && gotMinor >= minor)
}

// ---- Create ----

// Create starts one runner in a new clone.
func (b *VMPalBackend) Create(ctx context.Context, spec Spec) (Handle, error) {
	r, err := b.CreateWithResult(ctx, spec)
	return r.Handle, err
}

// CreateWithResult is Create with its timing. There is no image to pull.
func (b *VMPalBackend) CreateWithResult(ctx context.Context, spec Spec) (CreateResult, error) {
	started := time.Now()
	if err := b.checkSpec(spec); err != nil {
		return CreateResult{}, err
	}
	source, err := b.runnerSource(spec.RunnerVersion)
	if err != nil {
		return CreateResult{}, err
	}
	payload, err := vmpalEnvPayload(spec)
	if err != nil {
		return CreateResult{}, err
	}
	name := b.vmName(spec.RunnerID)
	if err := b.admit(ctx, name, spec); err != nil {
		return CreateResult{}, err
	}
	defer b.endCreate(name)
	if err := b.provision(ctx, name, spec, source, payload); err != nil {
		var failed *vmpalEgressFailure
		if errors.As(err, &failed) && failed.Breach {
			b.purgeClones(ctx)
		}
		b.discard(ctx, name)
		return CreateResult{}, err
	}
	b.ensureWatcher(name)
	b.log.Info("macOS VM runner started", "vm", name, "pool", spec.PoolName, "runner_version", source.version)
	return CreateResult{Handle: Handle(name), CreateDuration: time.Since(started)}, nil
}

// checkSpec refuses what this backend will not run. A JIT config is required
// because it is single-use: a reusable registration token inside a guest would
// be a credential the job could carry out with it.
func (b *VMPalBackend) checkSpec(spec Spec) error {
	if b.goos != "darwin" {
		return fmt.Errorf("%w: the macOS VM backend only runs on a Mac; this host runs %s", ErrBackendConfig, b.goos)
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	switch {
	case spec.Credentials.JITConfig == "":
		return fmt.Errorf("%w: pool %q has no JIT configuration; a macOS VM runner must be ephemeral, so that no reusable registration token reaches a guest", ErrBackendConfig, spec.PoolName)
	case !spec.Ephemeral:
		return fmt.Errorf("%w: pool %q is not ephemeral; a macOS VM runner gets one clone for one job, so set the pool to ephemeral", ErrBackendConfig, spec.PoolName)
	case spec.DockerMode != "" && spec.DockerMode != store.DockerNone:
		return fmt.Errorf("%w: pool %q asks for Docker mode %q, which a macOS VM runner cannot provide; set it to none", ErrBackendConfig, spec.PoolName, spec.DockerMode)
	case !vmpalRunnerID.MatchString(spec.RunnerID):
		return fmt.Errorf("backend: %q is not a runner ID this backend can name a VM after", spec.RunnerID)
	}
	return nil
}

type vmpalRunnerSource struct {
	version string
	digest  string
	url     string
}

var (
	vmpalVersionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,3}$`)
	vmpalDigestPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// runnerSource is the archive a guest will fetch. With no known digest the
// create fails: the process backend's unverified-download override does not
// apply, because the guest it would be for is about to be given a credential.
func (b *VMPalBackend) runnerSource(requested string) (vmpalRunnerSource, error) {
	version := strings.TrimPrefix(strings.TrimSpace(requested), "v")
	if version == "" {
		version = b.version
	}
	if !vmpalVersionPattern.MatchString(version) {
		return vmpalRunnerSource{}, fmt.Errorf("%w: %q is not a runner version", ErrBackendConfig, version)
	}
	digest, asset, err := resolveRunnerDigest("darwin", "arm64", version, b.sha256, b.version)
	if err != nil {
		return vmpalRunnerSource{}, err
	}
	if !vmpalDigestPattern.MatchString(digest) {
		return vmpalRunnerSource{}, fmt.Errorf("%w: no SHA-256 is known for %s, so it will not be installed in a guest; set agent.runner_sha256 for runner version %s", ErrBackendConfig, asset, version)
	}
	return vmpalRunnerSource{version: version, digest: digest, url: fmt.Sprintf("%s/v%s/%s", b.baseURL, version, asset)}, nil
}

// admit decides under one lock whether this clone may exist and writes its
// ledger entry, so the slot is taken before the next create can count them.
func (b *VMPalBackend) admit(ctx context.Context, name string, spec Spec) error {
	// Before the lock and the list: a host on hold refuses at once, however
	// slow vmpal is being, and that may be why it is on hold.
	if err := b.gate.Held(); err != nil {
		return err
	}
	b.admitMu.Lock()
	defer b.admitMu.Unlock()

	b.pruneSpent()
	if spent, err := b.runnerSpent(spec.RunnerID); err != nil {
		return err
	} else if spent {
		return fmt.Errorf("%w: runner %s has already been sent its registration, which works only once; the controller should start a new runner", ErrContainerConflict, spec.RunnerID)
	}

	vms, err := b.cli.List(ctx)
	if err != nil {
		return err
	}
	for _, vm := range vms {
		if vm.Name == name {
			return fmt.Errorf("%w: VM %s already exists; a second create must not deliver a registration again", ErrContainerConflict, name)
		}
	}
	// Every admitted create has an entry by now, because this lock is held
	// from the count to the write. So the ledger alone is what is in flight,
	// what is running and what is still being deleted.
	b.mu.Lock()
	entries, err := b.ledger.all()
	b.mu.Unlock()
	if err != nil {
		return err
	}
	if _, known := entries[name]; known {
		return fmt.Errorf("%w: runner %s already has a ledger entry; a second create must not deliver a registration again", ErrContainerConflict, spec.RunnerID)
	}
	if err := b.gate.Admit(ctx, countVMPalSlots(vms, entries, b.ownedRunner)); err != nil {
		return err
	}

	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.creating[name] = true
	err = b.ledger.write(vmpalEntry{
		RunnerID: spec.RunnerID, RunnerName: spec.Name, PoolID: spec.PoolID, VMName: name,
		Stage: vmpalStageIntent, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		delete(b.creating, name)
	}
	return err
}

// A spent marker says a runner's registration may have left this host. The
// ledger entry cannot say so for long, because it goes with the clone, and a
// create redelivered after a lease expiry would then send the same registration
// to a new guest. The marker's modification time is when it was spent.
func (b *VMPalBackend) spentPath(runnerID string) string {
	return filepath.Join(b.spentDir, runnerID)
}

func (b *VMPalBackend) markSpent(runnerID string) error {
	path := b.spentPath(runnerID)
	if err := writeFileAtomic(path, nil, 0o600); err != nil {
		return fmt.Errorf("backend: recording that a registration is being used, in %s: %w", b.spentDir, err)
	}
	now := b.now()
	if err := os.Chtimes(path, now, now); err != nil {
		return fmt.Errorf("backend: recording that a registration is being used, in %s: %w", b.spentDir, err)
	}
	return nil
}

func (b *VMPalBackend) runnerSpent(runnerID string) (bool, error) {
	_, err := os.Stat(b.spentPath(runnerID))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	}
	// Not knowing is not the same as not spent, and the cost of refusing is one
	// runner the controller replaces.
	return false, fmt.Errorf("backend: checking whether a registration was already used, in %s: %w", b.spentDir, err)
}

// pruneSpent drops markers past the point where a redelivered create could
// still arrive. A failure here only leaves a small file for the next pass.
func (b *VMPalBackend) pruneSpent() {
	files, err := os.ReadDir(b.spentDir)
	if err != nil {
		b.log.Warn("could not read the used-registration markers", "dir", b.spentDir, "error", err)
		return
	}
	now := b.now()
	for _, f := range files {
		info, err := f.Info()
		if err != nil || now.Sub(info.ModTime()) <= vmpalSpentKeep {
			continue
		}
		if err := os.Remove(filepath.Join(b.spentDir, f.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			b.log.Warn("could not remove an old used-registration marker", "file", f.Name(), "error", err)
		}
	}
}

// abandonLocked condemns a clone: no later stage, no watcher and no credential.
// A delivery already under way is cancelled, because the check it passed
// described a host that has since been shown not to hold. The caller holds mu.
func (b *VMPalBackend) abandonLocked(name string) {
	b.abandoned[name] = true
	if cancel := b.deliveries[name]; cancel != nil {
		cancel()
	}
}

// claimDelivery is the last check before a credential moves, and it registers
// how to cancel that delivery under the same lock an abandon takes. Either the
// abandon comes first and this refuses, or this comes first and the abandon
// cancels the command, which a context already cancelled never starts.
func (b *VMPalBackend) claimDelivery(name string, cancel context.CancelFunc) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.abandoned[name] || b.removing[name] {
		return fmt.Errorf("backend: clone %s is being deleted, so its registration was not sent", name)
	}
	b.deliveries[name] = cancel
	return nil
}

func (b *VMPalBackend) endDelivery(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.deliveries, name)
}

func (b *VMPalBackend) endCreate(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.creating, name)
}

func (b *VMPalBackend) provision(ctx context.Context, name string, spec Spec, source vmpalRunnerSource, payload string) error {
	if err := b.cli.Clone(ctx, b.template, name); err != nil {
		// Most often the template has been started, which Probe reports.
		b.reprobe.Store(true)
		return err
	}
	cloned, err := b.cli.Info(ctx, name)
	if err != nil {
		return err
	}
	if err := b.advance(name, vmpalStageCloned, func(e *vmpalEntry) { e.VMPalID = cloned.ID }); err != nil {
		return err
	}
	if err := b.harden(ctx, name, cloned); err != nil {
		return err
	}
	if err := b.advance(name, vmpalStageHardened, nil); err != nil {
		return err
	}
	if err := b.advance(name, vmpalStageBooting, nil); err != nil {
		return err
	}
	if err := b.cli.Start(ctx, name, vmpalBootLimit); err != nil {
		return b.startError(ctx, name, err)
	}
	if err := b.advance(name, vmpalStageVerifying, nil); err != nil {
		return err
	}
	if err := b.verify(ctx, name); err != nil {
		return err
	}
	// Without its monotonic reading, which stops while a Mac sleeps.
	verifiedAt := b.now().Round(0)
	if err := b.advance(name, vmpalStageArming, nil); err != nil {
		return err
	}
	armCtx, cancelArm := context.WithTimeout(ctx, vmpalArmLimit)
	defer cancelArm()
	out, err := b.helper(armCtx, name, vmpalArmLimit, nil, "arm", source.version, source.digest, source.url)
	if err != nil {
		return fmt.Errorf("backend: preparing the runner in the guest: %w", err)
	}
	if _, err := parseVMPalArm(out.Stdout); err != nil {
		return fmt.Errorf("backend: preparing the runner in the guest: %w", err)
	}

	// The egress result describes the network as it was when it was taken, and
	// the watcher that notices a sleep does not start until after this.
	if gap := b.now().Round(0).Sub(verifiedAt); gap > vmpalWakeGap {
		return fmt.Errorf("backend: the Mac was asleep or stalled for %s after this clone's network check, so the check no longer counts; the clone is being deleted and nothing was delivered, and the Mac should be kept from sleeping", gap.Round(time.Second))
	}

	// Recorded before the credential moves. From here a restarted agent treats
	// the registration as spent, whether or not it arrived.
	if err := b.advance(name, vmpalStageDelivering, nil); err != nil {
		return err
	}
	// This one outlives the clone. If it cannot be written the registration is
	// not sent, because nothing would then stop it being sent a second time.
	if err := b.markSpent(spec.RunnerID); err != nil {
		return err
	}
	deliverCtx, cancelDeliver := context.WithTimeout(ctx, vmpalDeliverLimit)
	defer cancelDeliver()
	if err := b.claimDelivery(name, cancelDeliver); err != nil {
		return err
	}
	defer b.endDelivery(name)
	out, err = b.helper(deliverCtx, name, vmpalGuestStepLimit, map[string]string{
		EnvUpstreamJITConfig: spec.Credentials.JITConfig,
		vmpalEnvVar:          payload,
	}, "deliver")
	if err != nil {
		return fmt.Errorf("backend: delivering the runner's registration: %w", err)
	}
	if err := checkVMPalLine(out.Stdout, vmpalDeliverOK); err != nil {
		return fmt.Errorf("backend: delivering the runner's registration: %w", err)
	}
	out, err = b.helper(deliverCtx, name, vmpalGuestStepLimit, nil, "start")
	if err != nil {
		return fmt.Errorf("backend: starting the runner in the guest: %w", err)
	}
	if err := checkVMPalLine(out.Stdout, vmpalStartOK); err != nil {
		return fmt.Errorf("backend: starting the runner in the guest: %w", err)
	}
	return b.advance(name, vmpalStageRunning, func(e *vmpalEntry) { e.StartedAt = b.now() })
}

// startError says a start that failed because Apple's limit was reached is the
// host being busy. It counts the VMs rather than reading vmpal's sentence, which
// is prose and free to change between releases.
func (b *VMPalBackend) startError(ctx context.Context, name string, err error) error {
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), vmpalProbeLimit)
	defer cancel()
	vms, listErr := b.cli.List(lctx)
	if listErr != nil {
		return err
	}
	running := 0
	for _, vm := range vms {
		if vm.Name != name && vm.Guest == "macOS" && vm.State == "running" {
			running++
		}
	}
	if running >= vmpalMacOSLimit {
		return busyErr(fmt.Errorf("%d macOS VMs are already running, which is all Apple allows on one Mac: %w", running, err))
	}
	return err
}

// discard removes a clone whose create failed. If it cannot, the entry stays at
// Deleting: the VM still takes up a slot, and the agent removes it from List.
func (b *VMPalBackend) discard(ctx context.Context, name string) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), vmpalCleanupLimit)
	defer cancel()
	if err := b.removeClone(cctx, name); err != nil {
		b.log.Warn("could not delete a clone whose create failed; it still counts against this Mac and will be retried", "vm", name, "error", err)
	}
}

// ---- Hardening ----

// The settings a clone is held to. The list is closed: a key that is in none of
// these tables fails the check, so a sharing feature a later VMPal adds cannot
// reach a job unread.
var (
	vmpalRequiredSettings = map[string]string{
		"agentControl": "true", "network": "true", "networkMode": `"shared"`, "localNetwork": `"off"`,
		"bridgedInterface": "null", "sharedFolders": "[]", "forwardedPorts": "[]", "vsockForwards": "[]",
		"bluetooth": "false", "camera": "false", "clipboard": "false", "dragAndDrop": "false",
		"location": "false", "microphone": "false", "speakers": "false", "startAtLogin": "false",
	}
	// vmpalBootSettings are resolved values: they say what a stopped VM would
	// probably get, so they are only held to the requirement once it is running.
	vmpalBootSettings = map[string]string{
		"networkModeInEffect": `"shared"`, "localNetworkInEffect": "false", "bridgedInterfaceInEffect": "null",
	}
	vmpalInheritedSettings = []string{"cpuCount", "memoryGB", "diskLimitGB", "display", "gpuAcceleration", "naturalScrolling", "name"}
)

// vmpalSettingProblems lists what is wrong with a settings object.
func vmpalSettingProblems(settings map[string]json.RawMessage, running bool) []string {
	var problems []string
	check := func(want map[string]string) {
		for key, value := range want {
			raw, ok := settings[key]
			if !ok {
				problems = append(problems, key+" is missing")
				continue
			}
			var compact bytes.Buffer
			if json.Compact(&compact, raw) != nil || compact.String() != value {
				problems = append(problems, key+" must be "+value)
			}
		}
	}
	check(vmpalRequiredSettings)
	if running {
		check(vmpalBootSettings)
	}
	for key := range settings {
		_, required := vmpalRequiredSettings[key]
		_, boot := vmpalBootSettings[key]
		if !required && !boot && !slices.Contains(vmpalInheritedSettings, key) {
			problems = append(problems, key+" is a setting this version of Zoomies has not reviewed")
		}
	}
	slices.Sort(problems)
	return problems
}

func vmpalHardenFlags(settings map[string]json.RawMessage) ([]string, error) {
	flags := []string{
		"--network-mode", "shared", "--local-network", "off", "--clipboard", "off",
		"--drag-and-drop", "off", "--speakers", "off", "--microphone", "off", "--camera", "off",
		"--start-at-login", "off", "--agent-control", "on",
	}
	for _, list := range []struct{ key, flag string }{
		{"sharedFolders", "--unshare"}, {"forwardedPorts", "--unforward"}, {"vsockForwards", "--vsock-unforward"},
	} {
		raw, ok := settings[list.key]
		if !ok {
			continue
		}
		var entries []json.RawMessage
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, fmt.Errorf("%w: the template's %s is not a list this version of Zoomies can read", ErrBackendConfig, list.key)
		}
		for _, entry := range entries {
			key, ok := vmpalListEntryKey(entry)
			if !ok || strings.HasPrefix(key, "-") {
				return nil, fmt.Errorf("%w: the template has an entry in %s that cannot be removed automatically; remove it from the template", ErrBackendConfig, list.key)
			}
			flags = append(flags, list.flag, key)
		}
	}
	return flags, nil
}

// vmpalListEntryKey reads a shared folder or forward as the path or port that
// names it to vmpal set, whether the entry is a bare value or an object.
func vmpalListEntryKey(raw json.RawMessage) (string, bool) {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text, text != ""
	}
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		return number.String(), true
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return "", false
	}
	for _, field := range []string{"path", "port", "hostPort"} {
		if value, ok := object[field]; ok {
			return vmpalListEntryKey(value)
		}
	}
	return "", false
}

func (b *VMPalBackend) harden(ctx context.Context, name string, cloned vmpalInfo) error {
	flags, err := vmpalHardenFlags(cloned.Settings)
	if err != nil {
		return err
	}
	flags = append(flags, b.sizeFlags()...)
	// A template that is already hardened answers "Nothing changed." and exits
	// zero, so the read-back below is what proves anything.
	if err := b.cli.Set(ctx, name, flags...); err != nil {
		return err
	}
	info, err := b.cli.Info(ctx, name)
	if err != nil {
		return err
	}
	problems := append(vmpalSettingProblems(info.Settings, false), b.sizeSettingProblems(info.Settings)...)
	if len(problems) > 0 {
		return fmt.Errorf("%w: clone %s did not take the required settings (%s); check the template and this version of VMPal", ErrBackendConfig, name, strings.Join(problems, "; "))
	}
	return nil
}

// ---- Verify ----

// verify establishes what the running clone really is, then asks the gate.
// sessionHardware is the evidence: settings describe the next start, and only
// the session says what this boot was given.
func (b *VMPalBackend) verify(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(ctx, vmpalVerifyLimit)
	defer cancel()

	info, err := b.cli.Info(ctx, name)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(b.addressWait)
	for info.InternetAddress == "" && time.Now().Before(deadline) {
		if !sleepVMPal(ctx, min(time.Second, b.addressWait)) {
			break
		}
		if info, err = b.cli.Info(ctx, name); err != nil {
			return err
		}
	}
	if problems := b.sessionProblems(info); len(problems) > 0 {
		return fmt.Errorf("%w: clone %s did not boot as required (%s); check the template's network settings and the configured CPU and memory", ErrBackendConfig, name, strings.Join(problems, "; "))
	}
	if err := b.installHelper(ctx, name); err != nil {
		return err
	}
	out, err := b.helper(ctx, name, vmpalGuestStepLimit, nil, "session")
	if err != nil {
		return fmt.Errorf("backend: checking for a signed-in session in the guest: %w", err)
	}
	if err := parseVMPalSession(out.Stdout); err != nil {
		return fmt.Errorf("backend: checking for a signed-in session in the guest: %w", err)
	}
	return b.gate.Verify(ctx, info)
}

func (b *VMPalBackend) sessionProblems(info vmpalInfo) []string {
	problems := vmpalSettingProblems(info.Settings, true)
	hw := info.SessionHardware
	switch {
	case hw == nil:
		problems = append(problems, "the VM reports no running session")
	default:
		if hw.NetworkMode != "shared" {
			problems = append(problems, "the session's network mode is not shared")
		}
		switch {
		case hw.LocalNetworkCard == nil:
			problems = append(problems, "the session does not say whether it has a local network card")
		case *hw.LocalNetworkCard:
			problems = append(problems, "the session has a local network card")
		}
		switch {
		case hw.BridgedInterface == nil:
			problems = append(problems, "the session does not say whether it is bridged")
		case string(hw.BridgedInterface) != "null":
			problems = append(problems, "the session is bridged")
		}
		problems = append(problems, b.sessionSizeProblems(hw)...)
	}
	switch {
	case info.PendingSettings == nil:
		problems = append(problems, "the VM does not report its pending settings")
	case len(info.PendingSettings) != 0:
		problems = append(problems, "the VM has settings waiting for its next start")
	}
	ip := net.ParseIP(info.InternetAddress)
	if ip == nil || ip.To4() == nil || !b.guestNet.Contains(ip) {
		problems = append(problems, fmt.Sprintf("its address is not inside %s", b.guestNet))
	}
	return problems
}

// sizeFlags sets the clone's size when one is configured. Without them a clone
// keeps the template's, which is not always the size jobs are meant to get.
func (b *VMPalBackend) sizeFlags() []string {
	var flags []string
	if b.cpus > 0 {
		flags = append(flags, "--cpus", strconv.Itoa(b.cpus))
	}
	if b.memoryGB > 0 {
		flags = append(flags, "--memory", strconv.Itoa(b.memoryGB)+"G")
	}
	return flags
}

// sizeSettingProblems holds the settings to the configured size. A value that is
// missing or is not a number fails, because it does not show the size was taken.
func (b *VMPalBackend) sizeSettingProblems(settings map[string]json.RawMessage) []string {
	var problems []string
	check := func(key string, want int) {
		if want == 0 {
			return
		}
		var got float64
		raw, ok := settings[key]
		if !ok || json.Unmarshal(raw, &got) != nil || got != float64(want) {
			problems = append(problems, fmt.Sprintf("%s must be %d", key, want))
		}
	}
	check("cpuCount", b.cpus)
	check("memoryGB", b.memoryGB)
	return problems
}

// sessionSizeProblems holds this boot to the configured size. Settings describe
// the next start, so only the session says what the guest was really given.
func (b *VMPalBackend) sessionSizeProblems(hw *vmpalSessionHardware) []string {
	var problems []string
	check := func(key string, got *float64, want int) {
		if want != 0 && (got == nil || *got != float64(want)) {
			problems = append(problems, fmt.Sprintf("the session's %s must be %d", key, want))
		}
	}
	check("cpuCount", hw.CPUCount, b.cpus)
	check("memoryGB", hw.MemoryGB, b.memoryGB)
	return problems
}

func (b *VMPalBackend) installHelper(ctx context.Context, name string) error {
	release, err := b.slotsFor(name).acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	encoded := base64.StdEncoding.EncodeToString([]byte(vmpalHelperScript))
	out, err := b.cli.Exec(ctx, name, vmpalGuestStepLimit, map[string]string{vmpalHelperVar: encoded}, vmpalInstallArgv()...)
	if err != nil {
		return fmt.Errorf("backend: installing the guest helper: %w", err)
	}
	if out.ExitCode != 0 {
		return fmt.Errorf("backend: installing the guest helper: %w", &vmpalCallError{Command: "exec", ExitCode: out.ExitCode})
	}
	return nil
}

func sleepVMPal(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// ---- Status, List, Stats ----

// Status reads the ledger and vmpal list and runs nothing in the guest.
func (b *VMPalBackend) Status(ctx context.Context, h Handle) (Status, error) {
	name := string(h)
	if _, ours := b.ownedRunner(name); !ours {
		return Status{}, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	vms, err := b.cli.List(ctx)
	if err != nil {
		return Status{}, err
	}
	vm, present := findVMPalVM(vms, name)
	b.mu.Lock()
	e, ok, err := b.ledger.read(name)
	creating, removing, abandoned := b.creating[name], b.removing[name], b.abandoned[name]
	b.mu.Unlock()
	if err != nil {
		return Status{}, err
	}
	if !ok {
		if !present {
			return Status{}, fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		e = b.unledgeredEntry(vm)
	}
	st := vmpalStatus(e, vm, present, creating, removing, abandoned)
	b.noteGuestPowerOff(e, vm, st)
	return st, nil
}

// noteGuestPowerOff feeds the breaker for a clone that went off with its runner
// up and nobody having asked. Nothing in the guest can say how that runner
// ended, and a template that dies after registering would otherwise register
// without limit. Only a clone this process is watching counts: a Mac restart or
// logout stops the agent too, so a clone first seen stopped by a new process is
// the host's doing and no evidence about the job or the template.
func (b *VMPalBackend) noteGuestPowerOff(e vmpalEntry, vm vmpalVM, st Status) {
	if e.Exit != nil || vm.State != "stopped" || st.Phase != PhaseFailed || st.Message != vmpalMsgVMStopped {
		return
	}
	// Read again under the lock: the entry above can be from before a stop
	// request, and that stop is what would have turned the VM off.
	b.mu.Lock()
	e, ok, err := b.ledger.read(vm.Name)
	if err != nil || !ok || e.Exit != nil || !e.StopRequestedAt.IsZero() || e.Stage == vmpalStageDeleting ||
		e.Stage.preparing() || b.creating[vm.Name] || b.removing[vm.Name] || b.forcedOff[vm.Name] ||
		b.watchers[vm.Name] == nil {
		b.mu.Unlock()
		return
	}
	err = b.writeExitLocked(e, PhaseFailed, 1, vmpalMsgVMStopped)
	b.mu.Unlock()
	if err != nil {
		// Not counted, so the next pass can try again without counting it twice.
		b.log.Warn("could not record that a clone powered off", "vm", vm.Name, "error", err)
		return
	}
	b.gate.RunnerExited(false, false)
}

func findVMPalVM(vms []vmpalVM, name string) (vmpalVM, bool) {
	for _, vm := range vms {
		if vm.Name == name {
			return vm, true
		}
	}
	return vmpalVM{}, false
}

// unledgeredEntry is a record for a VM whose name is ours and whose file is
// gone. The runner ID comes from the name, so the controller can decide about
// it, and a live job is not deleted because a file was lost.
func (b *VMPalBackend) unledgeredEntry(vm vmpalVM) vmpalEntry {
	runnerID, _ := b.ownedRunner(vm.Name)
	now := b.now()
	return vmpalEntry{
		RunnerID: runnerID, VMName: vm.Name, VMPalID: vm.ID,
		Stage: vmpalStageRunning, CreatedAt: now, UpdatedAt: now, Recovered: true,
	}
}

// recoverEntry writes that record, so the watcher can follow the VM from here.
func (b *VMPalBackend) recoverEntry(vm vmpalVM) (vmpalEntry, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.creating[vm.Name] {
		return vmpalEntry{}, false
	}
	if e, ok, err := b.ledger.read(vm.Name); err == nil && ok {
		return e, true
	}
	e := b.unledgeredEntry(vm)
	if err := b.ledger.write(e); err != nil {
		b.log.Warn("could not rebuild a clone's ledger entry", "vm", vm.Name, "error", err)
	}
	return e, true
}

// List reports every clone this agent owns from vmpal list and the ledger. It
// runs nothing in a guest, so a job that breaks Tools in its own VM cannot stall
// or fail the listing for anyone else.
func (b *VMPalBackend) List(ctx context.Context) ([]Workload, error) {
	// The ledger is read first. A record seen here whose VM is missing from the
	// later list really has gone, and a VM cloned after this read is caught by
	// recoverEntry, which looks again under the lock.
	b.mu.Lock()
	entries, err := b.ledger.all()
	creating := make(map[string]bool, len(b.creating))
	for name := range b.creating {
		creating[name] = true
	}
	b.mu.Unlock()
	if err != nil {
		return nil, err
	}
	vms, err := b.cli.List(ctx)
	if err != nil {
		return nil, err
	}

	removing, abandoned := b.dropRemoved(entries, vms)
	if b.afterDropRemoved != nil {
		b.afterDropRemoved()
	}

	out := make([]Workload, 0, len(entries))
	add := func(e vmpalEntry, vm vmpalVM, present, inFlight bool) {
		st := vmpalStatus(e, vm, present, inFlight, removing[e.VMName], abandoned[e.VMName])
		b.noteGuestPowerOff(e, vm, st)
		out = append(out, Workload{
			Handle: Handle(e.VMName), Name: firstNonEmpty(e.RunnerName, e.VMName),
			RunnerID: e.RunnerID, PoolID: e.PoolID, Status: st,
		})
		if st.Phase == PhaseRunning && !inFlight {
			b.ensureWatcher(e.VMName)
		}
	}
	for name, e := range entries {
		vm, present := findVMPalVM(vms, name)
		add(e, vm, present, creating[name])
	}
	for _, vm := range vms {
		if _, ours := b.ownedRunner(vm.Name); !ours {
			continue
		}
		if _, known := entries[vm.Name]; known {
			continue
		}
		if e, ok := b.recoverEntry(vm); ok {
			add(e, vm, true, false)
		}
	}
	slices.SortFunc(out, func(x, y Workload) int { return strings.Compare(string(x.Handle), string(y.Handle)) })
	return out, nil
}

// dropRemoved forgets records whose removal finished after the ledger was read.
// Their VM has gone from the later list, and without this they would be reported
// as a clone lost from under a job that this agent has just finished removing.
// It returns what is being removed and abandoned from the same lock hold: a
// removal finishing between the two looks would be in neither, and read as lost.
func (b *VMPalBackend) dropRemoved(entries map[string]vmpalEntry, vms []vmpalVM) (removing, abandoned map[string]bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for name := range entries {
		if _, present := findVMPalVM(vms, name); present {
			continue
		}
		if _, ok, err := b.ledger.read(name); err == nil && !ok {
			delete(entries, name)
		}
	}
	return maps.Clone(b.removing), maps.Clone(b.abandoned)
}

// Stats returns nothing: the host cannot see inside a guest's use of its slot.
func (b *VMPalBackend) Stats(context.Context, Handle) (Stats, error) { return Stats{}, nil }

// ---- Logs ----

// Logs streams the runner's output through the helper, one bounded read at a
// time, so a follower never holds an exec slot while it waits.
func (b *VMPalBackend) Logs(ctx context.Context, h Handle, opts LogOptions) (io.ReadCloser, error) {
	name := string(h)
	if _, ours := b.ownedRunner(name); !ours {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if _, ok, err := b.readEntry(name); err != nil {
		return nil, err
	} else if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	ctx, cancel := context.WithCancel(ctx)
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(b.streamLogs(ctx, name, opts, pw))
	}()
	return &vmpalLogReader{PipeReader: pr, cancel: cancel}, nil
}

type vmpalLogReader struct {
	*io.PipeReader
	cancel context.CancelFunc
}

func (r *vmpalLogReader) Close() error {
	r.cancel()
	return r.PipeReader.Close()
}

func (b *VMPalBackend) readLog(ctx context.Context, name string, offset, size int64) ([]byte, int64, error) {
	release, err := b.slotsFor(name).acquireForLogs(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer release()
	out, err := b.runHelper(ctx, name, vmpalWatchRead, nil, "log", strconv.FormatInt(offset, 10), strconv.FormatInt(size, 10))
	if err != nil {
		return nil, 0, err
	}
	return parseVMPalLog(out.Stdout, size)
}

func (b *VMPalBackend) streamLogs(ctx context.Context, name string, opts LogOptions, w io.Writer) error {
	var offset int64
	if opts.Tail > 0 {
		// An offset past the end is answered with the end, which is how the
		// size of the log is learned without a subcommand of its own.
		_, total, err := b.readLog(ctx, name, 1<<59, 0)
		if err != nil {
			return err
		}
		start := max(total-vmpalLogChunk, 0)
		data, next, err := b.readLog(ctx, name, start, vmpalLogChunk)
		if err != nil {
			return err
		}
		if _, err := w.Write(vmpalLastLines(data, opts.Tail, start > 0)); err != nil {
			return err
		}
		offset = next
		if !opts.Follow {
			return nil
		}
	}
	for {
		data, next, err := b.readLog(ctx, name, offset, vmpalLogChunk)
		if err != nil {
			return err
		}
		if len(data) > 0 {
			if _, err := w.Write(data); err != nil {
				return err
			}
		}
		offset = next
		if len(data) == vmpalLogChunk {
			continue
		}
		if !opts.Follow {
			return nil
		}
		if len(data) == 0 {
			e, ok, err := b.readEntry(name)
			if err != nil {
				return err
			}
			if !ok || e.Exit != nil {
				return nil
			}
		}
		if !sleepVMPal(ctx, b.logPoll) {
			return ctx.Err()
		}
	}
}

// vmpalLastLines keeps the last n lines of a window onto a log. partial says the
// window starts part way through the log, so its first line is not a whole one.
func vmpalLastLines(data []byte, n int, partial bool) []byte {
	if partial {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	end := len(data)
	if end > 0 && data[end-1] == '\n' {
		end--
	}
	for i := end - 1; i >= 0; i-- {
		if data[i] == '\n' {
			if n--; n == 0 {
				return data[i+1:]
			}
		}
	}
	return data
}

// ---- Stop and Remove ----

// Stop asks the runner to finish, then forces the VM off. A runner that was
// asked to stop and exits is a clean end, whatever its code.
func (b *VMPalBackend) Stop(ctx context.Context, h Handle, timeout time.Duration) error {
	name := string(h)
	if _, ours := b.ownedRunner(name); !ours {
		return errVMPalNotOurs(name)
	}
	vms, err := b.cli.List(ctx)
	if err != nil {
		return err
	}
	vm, present := findVMPalVM(vms, name)
	if !present {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	e, ok, err := b.readEntry(name)
	if err != nil {
		return err
	}
	if !ok {
		if e, ok = b.recoverEntry(vm); !ok {
			return fmt.Errorf("backend: clone %s is still being created", name)
		}
	}
	if e.Exit != nil {
		return nil
	}
	// Written first, so a restart part way through still knows the exit that
	// follows was asked for.
	if err := b.markStopRequested(name); err != nil {
		return err
	}
	if vm.State != "running" {
		return nil
	}
	if !e.Stage.preparing() && timeout > 0 {
		if b.stopGracefully(ctx, name, timeout) {
			return nil
		}
	}
	if err := b.cli.Stop(ctx, name, vmpalForceOffLimit); err != nil {
		// A VM that went off by itself in the meantime is what was wanted.
		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), vmpalProbeLimit)
		defer cancel()
		if vms, listErr := b.cli.List(lctx); listErr == nil {
			if vm, there := findVMPalVM(vms, name); !there || vm.State != "running" {
				return nil
			}
		}
		return err
	}
	return nil
}

func (b *VMPalBackend) markStopRequested(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok, err := b.ledger.read(name)
	if err != nil || !ok {
		return err
	}
	if e.StopRequestedAt.IsZero() {
		e.StopRequestedAt = b.now()
		e.UpdatedAt = e.StopRequestedAt
		return b.ledger.write(e)
	}
	return nil
}

// stopGracefully signals the guest's LaunchAgent and waits for its exit record,
// reporting whether the runner ended inside the timeout.
func (b *VMPalBackend) stopGracefully(ctx context.Context, name string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	limit := min(timeout, vmpalWatchRead)
	if _, err := b.helper(ctx, name, limit, nil, "stop"); err != nil {
		// The guest may be past answering, which is what the force-off is for.
		b.log.Warn("could not signal a VM's runner to stop; it will be forced off", "vm", name, "error", err)
		return false
	}
	for {
		finished, err := b.readGuestExit(ctx, name, limit)
		if err == nil && finished {
			return true
		}
		if !sleepVMPal(ctx, b.stopPoll) {
			return false
		}
	}
}

// Remove deletes a clone and its ledger entry. The entry stays until the VM has
// been seen to leave vmpal list, because until then it still holds a VM slot.
func (b *VMPalBackend) Remove(ctx context.Context, h Handle) error {
	name := string(h)
	if _, ours := b.ownedRunner(name); !ours {
		return errVMPalNotOurs(name)
	}
	b.stopWatcher(name)
	b.readFinalExit(ctx, name)
	// Only now: from here a runner with no record reads as ended with its exit
	// unknown, which must not win a race with the record being read.
	b.mu.Lock()
	b.removing[name] = true
	b.mu.Unlock()
	return b.removeClone(ctx, name)
}

// readFinalExit makes a bounded attempt to learn how a runner ended before its
// clone goes. On the normal path the controller's remove gets here before the
// watcher's next tick, and often before the guest has written its record, which
// it does only once the runner has exited; without this a real job would rarely
// clear the breaker. So "running" is asked again until the budget ends, while a
// read that fails ends the wait at once, because that guest is not going to say.
// readGuestExit stores the first account only, so a watcher read in flight
// cannot make it count twice. No answer is not evidence that no job ran, so it
// counts for nothing and the delete goes ahead. A retried removal has had its
// wait, and a purged clone is not worth one.
func (b *VMPalBackend) readFinalExit(ctx context.Context, name string) {
	b.mu.Lock()
	e, ok, err := b.ledger.read(name)
	skip := b.creating[name] || b.removing[name] || b.abandoned[name]
	b.mu.Unlock()
	if err != nil || !ok || skip || e.Exit != nil ||
		(e.Stage != vmpalStageDelivering && e.Stage != vmpalStageRunning) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, max(b.finalRead, b.finalWait))
	defer cancel()
	askUntil := time.Now().Add(b.finalWait)
	for {
		finished, err := b.readGuestExit(ctx, name, b.finalRead)
		if err != nil {
			b.log.Info("could not read a runner's exit record before deleting its clone", "vm", name, "error", err)
			return
		}
		if finished || !time.Now().Before(askUntil) || !sleepVMPal(ctx, b.finalEvery) {
			return
		}
	}
}

func (b *VMPalBackend) removeClone(ctx context.Context, name string) error {
	e, known, err := b.markDeleting(name)
	if err != nil {
		return err
	}
	if err := b.deleteVM(ctx, name, e, known); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.slots, name)
	if err := b.ledger.remove(name); err != nil {
		return err
	}
	delete(b.removing, name)
	delete(b.abandoned, name)
	delete(b.forcedOff, name)
	return nil
}

// markDeleting records that a clone is going. A failed write is logged and does
// not stop it: losing this record costs one repeated delete, and refusing would
// mean a full disk keeps an untrusted guest running, even through a breach purge.
// A failed read is still an error, because the record holds the ID that shows
// the VM is the clone this agent made.
func (b *VMPalBackend) markDeleting(name string) (vmpalEntry, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok, err := b.ledger.read(name)
	if err != nil || !ok {
		return e, false, err
	}
	if e.Stage != vmpalStageDeleting {
		e.Stage = vmpalStageDeleting
		e.UpdatedAt = b.now()
		if err := b.ledger.write(e); err != nil {
			b.log.Warn("could not record that a clone is being deleted; deleting it anyway", "vm", name, "error", err)
		}
	}
	return e, true, nil
}

// deleteVM re-reads the VM before it deletes it. The name alone is not enough
// to act on: a VM with this name and another ID is a VM somebody else made.
func (b *VMPalBackend) deleteVM(ctx context.Context, name string, e vmpalEntry, known bool) error {
	vms, err := b.cli.List(ctx)
	if err != nil {
		return err
	}
	vm, present := findVMPalVM(vms, name)
	if !present {
		return nil
	}
	if known && e.VMPalID != "" && vm.ID != e.VMPalID {
		return fmt.Errorf("backend: refusing to delete VM %s: its ID is not the one this agent recorded, so it is not the clone that was created; delete it by hand if it should go", name)
	}
	if template, ok := findVMPalVM(vms, b.template); name == b.template || (ok && template.ID == vm.ID) {
		return fmt.Errorf("backend: refusing to delete VM %s, which is the template", name)
	}

	if !known || e.DeleteIssuedAt.IsZero() || b.now().Sub(e.DeleteIssuedAt) >= vmpalDeleteAgain {
		if known {
			if err := b.markDeleteIssued(name); err != nil {
				b.log.Warn("could not record that a delete was issued; it may be issued again", "vm", name, "error", err)
			}
		}
		if err := b.cli.Delete(ctx, name); err != nil {
			// Delete can report failure for a VM that has in fact gone.
			if vms, listErr := b.cli.List(ctx); listErr == nil {
				if _, there := findVMPalVM(vms, name); !there {
					return nil
				}
			}
			return err
		}
	}

	// delete returns a few seconds before the VM leaves the list.
	deadline := time.Now().Add(b.removeWait)
	for {
		vms, err := b.cli.List(ctx)
		if err != nil {
			return err
		}
		if _, there := findVMPalVM(vms, name); !there {
			return nil
		}
		if !time.Now().Before(deadline) || !sleepVMPal(ctx, b.removeEvery) {
			return removingErr(fmt.Errorf("vmpal is still deleting %s; it holds a VM slot until it has gone", name))
		}
	}
}

func (b *VMPalBackend) markDeleteIssued(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok, err := b.ledger.read(name)
	if err != nil || !ok {
		return err
	}
	e.DeleteIssuedAt = b.now()
	e.UpdatedAt = e.DeleteIssuedAt
	return b.ledger.write(e)
}
