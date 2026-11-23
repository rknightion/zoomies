package installer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/eyupio/zoomies/internal/agent"
	"github.com/eyupio/zoomies/internal/backend"
	"github.com/eyupio/zoomies/internal/config"
	"github.com/eyupio/zoomies/internal/naming"
	"github.com/eyupio/zoomies/internal/store"
	"github.com/eyupio/zoomies/internal/version"
)

// JoinOptions configures `zoomies agent join`.
//
// A join is short: a token, a controller, and a host that can start
// containers. Everything else is detected, because the operator running this
// has usually just pasted a one-line command out of the UI.
type JoinOptions struct {
	ControllerURL string
	JoinToken     string
	// Name is how this host appears in the UI. It defaults to the hostname,
	// which is what an operator will recognise on the Hosts page.
	Name     string
	Capacity int
	Labels   map[string]string
	// Backend forces one; empty picks the best one this host has.
	Backend    store.BackendKind
	DockerHost string
	// CAFile pins the controller's certificate, which is how a private
	// deployment is verified without buying a public name.
	CAFile             string
	ClientCertFile     string
	ClientKeyFile      string
	InsecureSkipVerify bool
	// AllowInsecureHTTP permits a plain http:// controller URL that is not on
	// loopback. The transport refuses one otherwise, because the agent token
	// and every runner's registration credentials would cross in the clear.
	AllowInsecureHTTP bool

	ConfigDir  string
	StateDir   string
	BinaryPath string
	// ServiceUser is the account the agent service runs as.
	ServiceUser string
	// Service selects the supervisor; empty detects one.
	Service ServiceKind

	Answers        *Answers
	NonInteractive bool
	// AssumeYes accepts the one confirmation a join asks for: replacing
	// credentials this host already has. It does not answer the update helper
	// question, which is a grant of root and has its own flag.
	AssumeYes bool
	// UpdateHelper adds the update helper without asking, so that the web UI can
	// update this host (UpdateHelperExplained).
	UpdateHelper bool
	// ProcessIsolation is agent.process_isolation: "vmpal", "none", or empty for
	// a host that was not asked. A Mac must be asked (decideJoinIsolation).
	ProcessIsolation string
	// VMPalConfigFile holds the agent.vmpal settings, for "vmpal" and only then.
	VMPalConfigFile string
	// Interactive is whether a person is at a terminal to answer a question that
	// defaults to no. NonInteractive alone cannot say it: a join run with neither
	// flag and no terminal would otherwise read an answer off whatever its input
	// is.
	Interactive bool
	Out         io.Writer
	In          io.Reader
	Logger      *slog.Logger

	// detection lets `zoomies init` hand over what it already found instead of
	// probing the host twice.
	detection *Detection

	// helperHost and run stand in for what the update helper question reads
	// from the host and the commands it runs, as in UpgradeOptions.
	helperHost *upgradeHelperHost
	run        commandRunner

	// vmpalRegistry stands in for backend.NewVMPalRegistry. The real backend only
	// reports itself available on a Mac with a working network policy check, and
	// a test has neither.
	vmpalRegistry func(backend.VMPalOptions) (*backend.Registry, error)
}

func (o JoinOptions) configDir() string {
	if o.ConfigDir != "" {
		return o.ConfigDir
	}
	return config.ConfigDir()
}

func (o JoinOptions) stateDir() string {
	if o.StateDir != "" {
		return o.StateDir
	}
	return config.StateDir()
}

// Join enrols this host with a controller: it probes the local backends,
// redeems the join token, writes the credentials and a minimal agent config,
// installs the service and confirms the controller can see the host.
//
// Every failure here has a specific cause and a specific remedy, so the errors
// name both rather than reporting "join failed".
func Join(ctx context.Context, opts JoinOptions) error {
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if opts.In == nil {
		opts.In = os.Stdin
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	log := opts.Logger.With("component", "installer.join")
	u := newUI(opts.Out)

	var det Detection
	if opts.detection != nil {
		det = *opts.detection
	} else {
		det = Detect(ctx, Options{ConfigDir: opts.ConfigDir, StateDir: opts.StateDir, InstalledBinary: opts.BinaryPath, NonInteractive: opts.NonInteractive})
		u.step("Checking this host")
		for _, f := range det.Fields() {
			u.field(f.Key, f.Value)
		}
		u.blank()
	}

	if opts.ControllerURL == "" {
		return errors.New("installer: no controller URL; run `zoomies agent join https://zoomies.example.com --token zoojoin_...`, " +
			"copying the line the UI shows under Hosts -> Add a host")
	}
	if opts.JoinToken == "" {
		return errors.New("installer: no join token; mint one in the UI under Hosts -> Add a host, or with " +
			"`zoomies hosts join-token create --ttl 15m`, and pass it as --token")
	}

	// A name the controller would refuse is refused here instead. It would be
	// refused there too, and before the token is redeemed, but the answer is a
	// 422 that the transport reads as a rejected join token, so the operator
	// would be told to mint another for a token that was never the trouble.
	if opts.Name != "" {
		if err := naming.ValidateHostName(strings.TrimSpace(opts.Name)); err != nil {
			return fmt.Errorf("installer: the name given with --name cannot be used: %v. Pass another with --name; "+
				"nothing has been redeemed", err)
		}
	}

	// Before anything is written or redeemed, for the same reason as the check
	// below: the token is single use, and a host refused after spending it is
	// left as an offline record on the controller.
	isolation, err := decideJoinIsolation(opts, det)
	if err != nil {
		return err
	}

	// Decided before anything is written or redeemed. The join token is single
	// use, and the unit goes to /etc/systemd/system, which a user without root
	// cannot write: finding that out after a.Join leaves a spent token,
	// credentials in the operator's home directory and an offline host on the
	// controller for someone to remove.
	kind := opts.Service
	if kind == "" {
		kind = DetectServiceKind(det)
	}
	if kind == ServiceSystemd && !det.Root {
		return errors.New("installer: installing the agent as a systemd service needs root, and the join token is single-use, " +
			"so nothing has been redeemed; re-run with sudo, or pass --no-service to join without installing a unit " +
			"and start the agent yourself")
	}

	workDir := filepath.Join(opts.stateDir(), "work")
	configFile := filepath.Join(opts.configDir(), "zoomies.yaml")
	name := opts.Name
	if name == "" {
		// Not the bare hostname: a fleet's Hosts page reads much better when
		// each row says what the machine is, and the hostname is still the
		// last part of the canonical name.
		name = det.HostName()
	}
	capacity := opts.Capacity
	if capacity <= 0 {
		capacity = defaultCapacity(det)
	}
	if isolation.usesVMPal() {
		// decideJoinIsolation has refused any other figure that was asked for.
		capacity = isolation.vmpal.MaxVMs
	}
	serviceUser, serviceGroup := opts.ServiceUser, opts.ServiceUser
	if serviceUser == "" {
		serviceUser, serviceGroup = defaultServiceUser(det)
	}

	// --- Directories and the service account ---------------------------
	u.step("Service user and directories")
	if det.Root && det.OS != "darwin" {
		created, err := ensureServiceUser(ctx, serviceUser, serviceGroup, opts.stateDir())
		if err != nil {
			return err
		}
		if created {
			u.ok("created the system user " + serviceUser)
		}
	}
	if err := prepareDirs(ctx, runtime.GOOS, runCommand, opts.configDir(), opts.stateDir(), workDir); err != nil {
		return err
	}
	u.ok(opts.configDir() + " and " + opts.stateDir() + " are ready")

	// --- An identity this host already has -------------------------------
	if err := confirmRejoin(opts, u, workDir); err != nil {
		return err
	}

	// --- Backends -------------------------------------------------------
	u.step("Backends")
	var registry *backend.Registry
	var chosen store.BackendKind
	if isolation.usesVMPal() {
		// Never buildRegistry: it would offer Docker and the bare process backend,
		// and either one is a way for a job to run on the Mac itself.
		registry, err = opts.newVMPalRegistry(isolation.vmpal, workDir, log)
		if err != nil {
			return fmt.Errorf("installer: the VM backend cannot start, and nothing has been redeemed: %w", err)
		}
		defer registry.Close()
		chosen = store.BackendProcess
	} else {
		registry, chosen, err = buildRegistry(ctx, det, opts, workDir)
		if err != nil {
			return err
		}
	}
	infos := registry.Probe(ctx)
	for _, info := range infos {
		if info.Available {
			u.ok(fmt.Sprintf("%s available%s", info.Kind, socketSuffix(info.Endpoint)))
		} else {
			u.note(fmt.Sprintf("%s unavailable: %s", info.Kind, firstLine(info.Detail)))
		}
	}
	if isolation.usesVMPal() {
		if err := refuseVMPalProbe(infos); err != nil {
			return err
		}
		u.ok("this host will run each job in its own macOS VM")
	} else {
		u.ok("this host will run jobs with the " + string(chosen) + " backend")
	}
	for _, info := range infos {
		if info.Kind == chosen {
			ensureCgroupDelegation(ctx, u, det, info.Kind, info.Rootless, info.Endpoint, info.Limits, runCommand)
			break
		}
	}

	// --- Join ------------------------------------------------------------
	u.step("Joining " + agent.DisplayController(opts.ControllerURL))
	transport, err := agent.NewHTTPTransport(agent.HTTPOptions{
		ControllerURL:      opts.ControllerURL,
		CAFile:             opts.CAFile,
		ClientCertFile:     opts.ClientCertFile,
		ClientKeyFile:      opts.ClientKeyFile,
		InsecureSkipVerify: opts.InsecureSkipVerify,
		AllowInsecureHTTP:  opts.AllowInsecureHTTP,
		Logger:             log,
	})
	if err != nil {
		return err
	}

	defer transport.Close()
	// The capability belongs in agent.json, never the ordinary configuration.
	opts.ControllerURL = transport.Describe()
	a, err := agent.New(agent.Options{
		Name:           name,
		WorkDir:        workDir,
		Capacity:       capacity,
		Labels:         opts.Labels,
		Backends:       registry,
		DefaultBackend: chosen,
		Transport:      transport,
		Logger:         log,
	})
	if err != nil {
		return err
	}
	if err := a.Join(ctx, opts.JoinToken); err != nil {
		return explainJoinError(err, opts)
	}
	u.ok("joined as host " + a.HostID())

	// --- Confirm the controller sees us ----------------------------------
	// The join response alone proves the token was good. A heartbeat proves the
	// long-lived agent token works too, which is the credential every later
	// call depends on and the one an operator cannot check by hand.
	beatCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if _, err := transport.Heartbeat(beatCtx, agent.HeartbeatRequest{
		ProtocolVersion: agent.ProtocolVersion,
		Capacity:        capacity,
		Version:         version.Version,
		Backends:        registry.Probe(beatCtx),
	}); err != nil {
		u.warn("the controller accepted the join but rejected the first heartbeat: " + err.Error())
	} else {
		u.ok("the controller sees this host as " + name + " with capacity " + fmt.Sprint(capacity))
	}

	// --- Config ----------------------------------------------------------
	u.step("Configuration")
	cfg := config.Default()
	cfg.Agent.Embedded = false
	cfg.Agent.Name = name
	cfg.Agent.Capacity = capacity
	cfg.Agent.Backend = string(chosen)
	cfg.Agent.DockerHost = opts.DockerHost
	cfg.Agent.WorkDir = workDir
	cfg.Agent.ControllerURL = opts.ControllerURL
	cfg.Agent.CAFile = opts.CAFile
	cfg.Agent.ClientCertFile = opts.ClientCertFile
	cfg.Agent.ClientKeyFile = opts.ClientKeyFile
	cfg.Agent.InsecureSkipVerify = opts.InsecureSkipVerify
	cfg.Agent.AllowInsecureHTTP = opts.AllowInsecureHTTP
	cfg.Agent.Labels = opts.Labels
	// Written even as "none": on a Mac the next start refuses a file without it.
	cfg.Agent.ProcessIsolation = isolation.mode
	if isolation.usesVMPal() {
		cfg.Agent.VMPal = isolation.vmpal
	}
	cfg.Database.Path = filepath.Join(opts.stateDir(), "agent.db")
	// The agent token lives in the credentials file the join just wrote, with
	// mode 0600, and never in the config file: zoomies.yaml is 0640 and ends up
	// in backups and configuration management.
	for _, f := range cfg.Validate().Warnings() {
		if f.Setting == "server.external_url" {
			continue // an agent has no listener, so this warning is noise here
		}
		u.warn(f.Title)
	}
	if err := cfg.Save(configFile); err != nil {
		return fmt.Errorf("installer: writing %s: %w", configFile, err)
	}
	u.ok("wrote " + configFile)
	u.note("credentials are in " + agent.StatePath(workDir) + " (mode 0600)")

	if det.Root && det.OS != "darwin" {
		if uid, gid, err := lookupUser(serviceUser, serviceGroup); err == nil {
			for _, p := range []string{opts.configDir(), opts.stateDir(), workDir, configFile, agent.StatePath(workDir)} {
				_ = os.Chown(p, uid, gid)
			}
		}
	}

	// --- Service ---------------------------------------------------------
	u.step("Service")
	if kind != ServiceSystemd && kind != ServiceLaunchd && kind != ServiceWindows {
		u.note("no service manager here; start the agent yourself with:")
		u.note("  " + det.BinaryPath + " agent --config " + configFile)
		if runningUnderWSL() {
			u.blank()
			for _, l := range wslServiceNotes() {
				u.note(l)
			}
		}
		return nil
	}

	mgr, err := NewServiceManager(kind, UnitAgent)
	if err != nil {
		return err
	}
	path, err := mgr.Install(ctx, ServiceSpec{
		Unit:        UnitAgent,
		ExecPath:    det.BinaryPath,
		ConfigFile:  configFile,
		User:        serviceUser,
		Group:       serviceGroup,
		StateDir:    opts.stateDir(),
		ConfigDir:   opts.configDir(),
		WantsDocker: chosen != store.BackendProcess,
		RuntimeName: string(chosen),
	})
	if err != nil {
		return err
	}
	u.ok("installed " + path)
	if err := mgr.Enable(ctx); err != nil {
		return fmt.Errorf("installer: enabling the agent service: %w", err)
	}
	if err := mgr.Start(ctx); err != nil {
		if out, logErr := mgr.Logs(ctx, 20); logErr == nil && out != "" {
			u.blank()
			u.note(out)
		}
		return fmt.Errorf("installer: starting the agent service: %w (see %s)", err, mgr.LogCommand())
	}
	status, _ := mgr.Status(ctx)
	u.ok("started (" + status + ")")

	// A WSL2 distro stops when its last Windows session closes, taking the agent
	// with it, so a join there offers to keep it up.
	if kind == ServiceSystemd {
		offerWSLSelfManagement(ctx, wslOffer{Out: opts.Out, In: opts.In, Interactive: opts.Interactive,
			AssumeYes: opts.AssumeYes, Binary: det.BinaryPath, User: serviceUser})
	}

	// The service is installed and the account it runs as can be read back from
	// its unit. A refusal is a warning: the token is spent and the host is
	// joined, and neither is worse for the helper being left for later. Another
	// supervisor has no helper to offer, but --update-helper still says so.
	if kind == ServiceSystemd || opts.UpdateHelper {
		opts.offerUpdateHelper(ctx)
	}

	u.blank()
	u.step("Done")
	u.field("host", name+" ("+a.HostID()+")")

	// What this host is, and what it just told the controller it is.
	//
	// None of this used to be printed. The figures went on the wire, the skew
	// between the two builds went to a log at warn level in the middle of the
	// installer's prose, and the last thing an operator saw was that a service
	// had started -- so a host that joined on the wrong build, or measured
	// nothing at all, looked exactly like one that did neither. Both are worth
	// a line each while the operator is still at the terminal, because both are
	// answered by running the install again with different arguments, and
	// neither is visible until somebody opens the Hosts page and reads a badge.
	rep := a.Reported()
	u.field("agent", version.Short())
	if rep.ControllerVersion != "" {
		u.field("controller", rep.ControllerVersion)
	}
	u.field("size", reportedSize(rep))
	u.field("logs", mgr.LogCommand())

	if rep.ControllerVersion != "" && version.CompareBuilds(version.Version, rep.ControllerVersion) != version.SkewNone {
		u.blank()
		u.warn("this agent is " + version.Version + " and that controller is " + rep.ControllerVersion +
			"; the fleet will show this host as a different build.")
		u.note("to match it, install that version and restart the agent:")
		u.note("  curl -fsSL https://zoomies.sh/install.sh | sh -s -- --no-init --version <tag>")
	}
	if rep.CPUs == 0 {
		u.blank()
		u.warn("this agent reported no CPUs, memory or disk, so the fleet cannot fit a pool's " +
			"resource limits against this host.")
		u.note("agents learnt to measure themselves after 0.2-beta; a newer one reports on its next heartbeat.")
	}

	u.note("It should be on the Hosts page of " + opts.ControllerURL + " within a heartbeat.")
	return nil
}

// reportedSize renders what the agent measured, or says plainly that it did
// not. An empty field would read as "nothing to say" when what it means is
// "this host cannot say".
func reportedSize(r agent.Reported) string {
	if r.CPUs <= 0 && r.MemoryMB <= 0 && r.DiskTotalMB <= 0 {
		return "not reported by this agent"
	}
	out := fmt.Sprintf("%d vCPU", r.CPUs)
	if r.MemoryMB > 0 {
		out += fmt.Sprintf(" - %d GB", r.MemoryMB/1024)
	}
	if r.DiskTotalMB > 0 {
		out += fmt.Sprintf(" - %d GB free of %d", r.DiskFreeMB/1024, r.DiskTotalMB/1024)
	}
	return out
}

// confirmRejoin stops a second join from silently replacing an identity this
// host already has. The old host record does not disappear when it does: it
// stays on the controller as an offline host somebody has to notice and
// remove, which is worth one question.
func confirmRejoin(opts JoinOptions, u *ui, workDir string) error {
	path := agent.StatePath(workDir)
	if !exists(path) || opts.AssumeYes {
		return nil
	}
	creds, err := agent.Load(path)
	if err != nil {
		// Unreadable or incomplete credentials are exactly what a re-join is
		// for, so this is not something to stop over.
		return nil
	}
	u.warn("this host has already joined " + creds.Controller + " as " + creds.HostID)
	u.note("joining again replaces the credentials in " + path + "; the old host record stays on the")
	u.note("controller as an offline host until you remove it there.")
	if opts.NonInteractive {
		return fmt.Errorf("installer: %s already holds credentials for %s; re-run with --yes to replace them, "+
			"or remove the old host on the controller first", path, creds.Controller)
	}
	ok, err := askYesNo(opts.In, opts.Out, "Replace them and join again? [y/N]: ")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("installer: nothing was changed; this host is still joined to " + creds.Controller)
	}
	return nil
}

// buildRegistry probes what this host can run jobs with and picks a default.
// An agent with no working backend is refused here rather than three minutes
// later when the first task arrives.
func buildRegistry(ctx context.Context, det Detection, opts JoinOptions, workDir string) (*backend.Registry, store.BackendKind, error) {
	var backends []backend.Backend

	docker, err := backend.NewDocker(backend.DockerOptions{Host: opts.DockerHost, WorkDir: workDir, Logger: opts.Logger})
	if err == nil {
		backends = append(backends, docker)
	}
	podman, err := backend.NewPodman(backend.DockerOptions{Host: opts.DockerHost, WorkDir: workDir, Logger: opts.Logger})
	if err == nil {
		backends = append(backends, podman)
	}
	proc, err := backend.NewProcess(backend.ProcessOptions{WorkDir: workDir, Logger: opts.Logger})
	if err == nil {
		backends = append(backends, proc)
	}
	registry := backend.NewRegistry(backends...)

	if opts.Backend != "" {
		b, err := registry.Get(opts.Backend)
		if err != nil {
			return nil, "", fmt.Errorf("installer: backend %q is not available on this host: %w", opts.Backend, err)
		}
		if info := b.Probe(ctx); !info.Available {
			return nil, "", fmt.Errorf("installer: the %s backend was requested but is not usable here: %s", opts.Backend, info.Detail)
		}
		return registry, opts.Backend, nil
	}

	for _, c := range backendChoices(det) {
		if c.Available {
			if _, err := registry.Get(c.Kind); err == nil {
				return registry, c.Kind, nil
			}
		}
	}
	return nil, "", errors.New("installer: this host has no usable backend: no Docker or Podman socket answered, and the process backend could not be prepared. " +
		"Start a runtime (systemctl --user start docker, or systemctl --user enable --now podman.socket) and run the join again")
}

// joinIsolation is what a join decided about how this host's jobs are isolated.
type joinIsolation struct {
	mode  string
	vmpal config.VMPalConfig
}

func (i joinIsolation) usesVMPal() bool { return i.mode == config.ProcessIsolationVMPal }

// decideJoinIsolation applies the join's rules for process isolation. It writes
// nothing and contacts nothing, so that every refusal leaves the token unspent.
func decideJoinIsolation(opts JoinOptions, det Detection) (joinIsolation, error) {
	const unspent = "nothing has been redeemed"
	mode, file := opts.ProcessIsolation, opts.VMPalConfigFile
	switch mode {
	case "", config.ProcessIsolationNone, config.ProcessIsolationVMPal:
	default:
		return joinIsolation{}, fmt.Errorf("installer: --process-isolation %q is not a mode; use vmpal or none. %s", mode, unspent)
	}
	if mode == "" && det.OS == "darwin" {
		return joinIsolation{}, fmt.Errorf("installer: on a Mac, say what keeps jobs off this machine: run zoomies agent join "+
			"with --process-isolation vmpal --vmpal-config <file> to run each job in a VM, or --process-isolation none to run "+
			"jobs directly on this Mac; %s", unspent)
	}
	if mode != config.ProcessIsolationVMPal {
		if file != "" {
			return joinIsolation{}, fmt.Errorf("installer: --vmpal-config only applies with --process-isolation vmpal; "+
				"add that flag or remove the file. %s", unspent)
		}
		return joinIsolation{mode: mode}, nil
	}

	if file == "" {
		return joinIsolation{}, fmt.Errorf("installer: --process-isolation vmpal needs --vmpal-config <file> holding the agent.vmpal settings; %s", unspent)
	}
	if det.Root {
		return joinIsolation{}, fmt.Errorf("installer: VM isolation must be joined as the logged-in user and not as root, "+
			"because root would install a LaunchDaemon outside the session VMPal runs in. Run this again without sudo; %s", unspent)
	}
	if opts.Backend != "" && opts.Backend != store.BackendProcess {
		return joinIsolation{}, fmt.Errorf("installer: --backend %s cannot be used with --process-isolation vmpal, which only runs "+
			"jobs in VMs. Remove --backend; %s", opts.Backend, unspent)
	}
	if opts.DockerHost != "" {
		return joinIsolation{}, fmt.Errorf("installer: --docker-host cannot be used with --process-isolation vmpal, which never "+
			"uses a container runtime. Remove it; %s", unspent)
	}
	settings, err := config.LoadVMPalFile(file)
	if err != nil {
		return joinIsolation{}, fmt.Errorf("installer: %w; %s", err, unspent)
	}
	if opts.Capacity != 0 && opts.Capacity != settings.MaxVMs {
		return joinIsolation{}, fmt.Errorf("installer: --capacity %d does not match max_vms %d in %s. Leave --capacity out, "+
			"or make them equal; %s", opts.Capacity, settings.MaxVMs, file, unspent)
	}
	candidate := config.Default()
	candidate.Agent.Embedded = false
	candidate.Agent.ControllerURL = opts.ControllerURL
	candidate.Agent.ProcessIsolation = mode
	candidate.Agent.VMPal = settings
	// The file this join writes is where the value will come from.
	candidate.Note("agent.process_isolation", config.SourceFile)
	if err := candidate.ProcessIsolationFindings(det.OS).Err(); err != nil {
		return joinIsolation{}, fmt.Errorf("installer: %s cannot be used, and %s: %w", file, unspent, err)
	}
	return joinIsolation{mode: mode, vmpal: settings}, nil
}

// newVMPalRegistry builds the VM-only registry from what the join decided.
func (o JoinOptions) newVMPalRegistry(settings config.VMPalConfig, workDir string, log *slog.Logger) (*backend.Registry, error) {
	cfg := config.Default()
	cfg.Agent.WorkDir = workDir
	cfg.Agent.VMPal = settings
	build := o.vmpalRegistry
	if build == nil {
		build = backend.NewVMPalRegistry
	}
	return build(VMPalBackendOptions(cfg, log))
}

// VMPalBackendOptions is the one place the settings become the backend's
// options, so that a join and the agent it installs cannot build different ones.
func VMPalBackendOptions(cfg *config.Config, log *slog.Logger) backend.VMPalOptions {
	v := cfg.Agent.VMPal
	opts := backend.VMPalOptions{
		Binary:          v.Binary,
		Template:        v.Template,
		MaxVMs:          v.MaxVMs,
		GuestCIDR:       v.GuestCIDR,
		EgressMustAllow: v.EgressMustAllow,
		EgressMustBlock: v.EgressMustBlock,
		PolicyCheck:     v.PolicyCheck,
		CPUs:            v.CPUs,
		MemoryGB:        v.MemoryGB,
		WorkDir:         cfg.Agent.WorkDir,
		RunnerVersion:   cfg.GitHub.RunnerVersion,
		RunnerSHA256:    cfg.Agent.RunnerSHA256,
		DownloadBaseURL: cfg.Agent.RunnerDownloadURL,
		Logger:          log,
	}
	if config.VMPalAnyOS {
		// The test build drives a fake vmpal on Linux, and the backend would
		// otherwise refuse the host before it asked the fake anything.
		opts.GOOS = "darwin"
	}
	return opts
}

// refuseVMPalProbe stops a join on any probe failure except occupied VM slots.
// Those are a state of the moment that clears when somebody shuts a VM down,
// and every other failure is a host that could not safely run a job.
func refuseVMPalProbe(infos []backend.Info) error {
	if len(infos) == 0 {
		return errors.New("installer: the VM backend reported nothing, so this host cannot be shown to work; nothing has been redeemed")
	}
	for _, info := range infos {
		if info.Available || strings.Contains(info.Detail, backend.VMPalSlotsOccupiedDetail) {
			continue
		}
		return fmt.Errorf("installer: the VM backend is not usable here: %s. Fix that and run this again; nothing has been redeemed", firstLine(info.Detail))
	}
	return nil
}

// explainJoinError turns a transport failure into an instruction. The five
// things that go wrong here look almost identical on the wire and have
// completely different remedies, which is the whole reason this exists.
func explainJoinError(err error, opts JoinOptions) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, agent.ErrUnauthorized):
		return fmt.Errorf("installer: %s rejected this join token: it has expired, or it has already been used "+
			"(join tokens are single-use and short-lived by design). Mint another with `zoomies hosts join-token create --ttl 15m` "+
			"and run this again: %w", opts.ControllerURL, err)
	case errors.Is(err, agent.ErrHostGone):
		return fmt.Errorf("installer: %s no longer has a record of this host; mint a fresh join token and try again: %w", opts.ControllerURL, err)
	}

	var certErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	switch {
	case errors.As(err, &certErr), errors.As(err, &unknownAuthority):
		return fmt.Errorf("installer: could not verify %s's TLS certificate. If the controller serves a self-signed or "+
			"private certificate, pin it with --ca-file /path/to/ca.pem (copy it from the controller). Do not disable "+
			"verification: anything on the network path could then impersonate the controller and hand this agent "+
			"containers to run: %w", opts.ControllerURL, err)
	case errors.As(err, &hostnameErr):
		return fmt.Errorf("installer: %s presented a certificate for a different name (%s). Join using the name on the "+
			"certificate, or reissue it for this one: %w", opts.ControllerURL, hostnameErr.Host, err)
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return fmt.Errorf("installer: %s does not resolve from this host (%s). Check the name, or use the controller's "+
			"IP address: %w", opts.ControllerURL, dnsErr.Name, err)
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) || errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("installer: could not reach %s from this host. The agent only ever connects outbound, so check "+
			"that the controller is running, that its external URL is right, and that a firewall between here and there "+
			"allows the connection: %w", opts.ControllerURL, err)
	}

	var httpErr *agent.HTTPError
	if errors.As(err, &httpErr) && httpErr.Status == http.StatusNotFound {
		return fmt.Errorf("installer: %s answered, but has no join endpoint. That URL may be a reverse proxy pointing "+
			"somewhere else, or the controller may be older than this agent: %w", opts.ControllerURL, err)
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && errors.Is(urlErr.Err, context.DeadlineExceeded) {
		return fmt.Errorf("installer: %s did not answer in time; check that it is running and reachable from this host: %w", opts.ControllerURL, err)
	}
	return err
}

// insecureLoopbackTransport is used for one thing only: the installer's own
// health check against 127.0.0.1, where the certificate may be the self-signed
// one generated a moment ago and there is nothing on the loopback interface to
// impersonate it.
func insecureLoopbackTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			// #nosec G402 -- loopback only; see the comment above.
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
				return nil, fmt.Errorf("installer: refusing to skip certificate verification for %s; this transport is for loopback health checks only", addr)
			}
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
	}
}
