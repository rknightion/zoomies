package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/eyupio/zoomies/internal/backend"
	"github.com/eyupio/zoomies/internal/config"
	"github.com/eyupio/zoomies/internal/installer"
)

// jobUserLaunchdLabel is the label of the agent's LaunchDaemon, which the
// removal command refuses to run beside.
const jobUserLaunchdLabel = "sh.zoomies.agent"

// What the job-user agent asks of the host, as variables so that a test can
// stand in for a Mac.
var (
	jobUserEUID        = os.Geteuid
	checkJobUserBinary = installer.CheckJobUserBinary
	checkJobUserPaths  = installer.CheckJobUserPaths
	jobUserExecutable  = os.Executable
	startJobUsers      = func(ctx context.Context, b *backend.ProcessBackend) error { return b.StartJobUsers(ctx) }
	removeJobUsers     = backend.RemoveJobUsers
	newJobUserProcess  = backend.NewProcess
	// agentDaemonLoaded says whether launchd has the agent's LaunchDaemon.
	agentDaemonLoaded = func(ctx context.Context) (bool, error) {
		err := exec.CommandContext(ctx, "/bin/launchctl", "print", "system/"+jobUserLaunchdLabel).Run()
		var exit *exec.ExitError
		switch {
		case err == nil:
			return true, nil
		case errors.As(err, &exit):
			// launchctl print exits non-zero for a service it has no record of.
			return false, nil
		}
		return false, err
	}
)

// jobUserProcessOptions is the one place the settings become the process
// backend's job-user options.
func jobUserProcessOptions(cfg *config.Config, log *slog.Logger) backend.ProcessOptions {
	return backend.ProcessOptions{
		WorkDir:                 cfg.Agent.WorkDir,
		RunnerVersion:           cfg.GitHub.RunnerVersion,
		RunnerSHA256:            cfg.Agent.RunnerSHA256,
		AllowUnverifiedDownload: cfg.Agent.AllowUnverifiedRunnerDownload,
		DownloadBaseURL:         cfg.Agent.RunnerDownloadURL,
		Logger:                  log,
		JobUsers: &backend.JobUserOptions{
			Capacity: cfg.Agent.Capacity,
			StateDir: filepath.Join(config.StateDir(), "job-users"),
		},
	}
}

// buildJobUserBackends is the registry of an agent in job-user mode. It holds
// the process backend with job users and nothing else: Docker, Podman or the
// plain process launcher beside it would each be a way for a job to run as root
// or as the agent.
//
// It refuses to start unless it is root and everything that holds its secrets, or
// that it runs as root, is root's alone. Those are the rules the job users'
// isolation rests on, so a host that does not meet them does not run jobs.
func buildJobUserBackends(ctx context.Context, cfg *config.Config, log *slog.Logger) (*backend.Registry, error) {
	if jobUserEUID() != 0 {
		return nil, errors.New("agent.process_isolation is user, which needs the agent to run as root: it starts each job as its own local account. " +
			"Run it as a LaunchDaemon, which `sudo zoomies agent join --process-isolation user` installs")
	}
	exe, err := jobUserExecutable()
	if err != nil {
		return nil, fmt.Errorf("finding this binary: %w", err)
	}
	if err := checkJobUserBinary(exe); err != nil {
		return nil, err
	}
	if err := checkJobUserPaths(installer.JobUserPaths{
		ConfigFile: cfg.Path(),
		StateDir:   config.StateDir(),
		WorkDir:    cfg.Agent.WorkDir,
		Plist:      installer.LaunchdPlistPath(jobUserLaunchdLabel, true),
	}); err != nil {
		return nil, err
	}
	b, err := newJobUserProcess(jobUserProcessOptions(cfg, log))
	if err != nil {
		return nil, err
	}
	if err := startJobUsers(ctx, b); err != nil {
		return nil, fmt.Errorf("setting up the job users: %w", err)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	reg := backend.NewRegistry(b)
	for _, info := range reg.Probe(probeCtx) {
		if info.Available {
			log.Info("job-user backend available", "detail", info.Detail)
		} else {
			log.Warn("job-user backend not available", "detail", info.Detail)
		}
	}
	return reg, nil
}

// runAgentJobUsers is `zoomies agent job-users`.
func runAgentJobUsers(ctx context.Context, e *env, args []string) error {
	if len(args) == 0 || args[0] != "remove" {
		return usagef("agent job-users", "the one subcommand is remove")
	}
	fs := newFlagSet(e, "zoomies agent job-users remove",
		"Delete the job users a job-user agent made: their accounts, homes and the group. The agent's LaunchDaemon must be stopped first.")
	if err := fs.parse(args[1:]); err != nil {
		return err
	}
	if err := fs.noMoreArgs(); err != nil {
		return err
	}
	if jobUserEUID() != 0 {
		return errors.New("removing job users needs root: run it with sudo")
	}
	loaded, err := agentDaemonLoaded(ctx)
	if err != nil {
		return fmt.Errorf("could not tell whether the agent's LaunchDaemon is loaded, so nothing was removed: %w", err)
	}
	if loaded {
		return fmt.Errorf("the agent's LaunchDaemon %s is loaded, and it would make the job users again: stop it first with `sudo launchctl bootout system/%s`", jobUserLaunchdLabel, jobUserLaunchdLabel)
	}
	log, _ := setupLogging(config.Default())
	if err := removeJobUsers(ctx, backend.RemoveJobUsersOptions{StateDir: filepath.Join(config.StateDir(), "job-users"), Logger: log}); err != nil {
		return err
	}
	fmt.Fprintln(e.out, "removed the job users and their group")
	return nil
}
