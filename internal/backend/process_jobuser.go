package backend

// The job-user launcher of the process backend: the same runner, the same
// records and the same adoption after an agent restart, but started as a local
// account of its own whose home is wiped after the job. The agent runs as root
// in this mode, which is what lets it start the runner directly as that account,
// so the recorded pid is the listener itself and every existing check on it
// (liveness, identity, the process-group signals) works unchanged.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	// jobUserDiagLimit is the most of a job's _diag folder that is kept.
	jobUserDiagLimit = 20 << 20
	// jobUserDiagDir is where the copies land, one folder for each runner, under
	// the work folder. They are not in the runner's record, which is deleted with
	// it: the point of keeping them is that they outlive both the record and the
	// home. Only the newest jobUserDiagKeep are kept.
	jobUserDiagDir  = "job-diag"
	jobUserDiagKeep = 50
)

var _ SlotSized = (*ProcessBackend)(nil)

// SlotSized is true in job-user mode: capacity is the number of accounts the
// operator chose, not a share of the Mac's cores and memory, so the controller's
// automatic capacity adjustment leaves the host alone.
func (b *ProcessBackend) SlotSized() bool { return b.jobUsers != nil }

var _ ProbeInvalidator = (*ProcessBackend)(nil)

// ProbeStale says the last Probe no longer describes this host: a hold started
// or ended, or a slot changed health. It clears on read.
func (b *ProcessBackend) ProbeStale() bool {
	u := b.jobUsers
	if u == nil {
		return false
	}
	held := u.state.held() != nil
	changed := u.probedHeld.Swap(held) != held
	return u.reprobe.Swap(false) || changed
}

// Close stops the watcher. It leaves every runner running.
func (b *ProcessBackend) Close() {
	if b.jobUsers != nil {
		b.jobUsers.close()
	}
}

// StartJobUsers makes the accounts, finds the jobs an earlier agent left, cleans
// every slot nobody holds, loads the firewall and starts the watcher. Nothing
// is admitted before it returns. It refuses to go on if an account or the group
// is not what Zoomies would have made, and holds the host, without refusing to
// start, if the firewall could not be loaded: running jobs are not in this
// agent's way, and a held host says why on the Hosts page.
func (b *ProcessBackend) StartJobUsers(ctx context.Context) error {
	u := b.jobUsers
	if u == nil {
		return nil
	}
	// Every job inherits this: a checkout under the agent's own, stricter, mask
	// would write a tracked 0755 script as 0700.
	u.sys.SetUmask(0o022)
	if err := u.sys.MkdirAll(u.stateDir, 0o700); err != nil {
		return fmt.Errorf("backend: making the job-user state folder %s: %w", u.stateDir, err)
	}
	if err := u.ensureSlots(ctx); err != nil {
		return err
	}
	b.adoptJobUserRecords()
	for _, s := range u.offered() {
		u.mu.Lock()
		busy := s.holder != ""
		u.mu.Unlock()
		if busy {
			continue
		}
		// Always the full reset, never the cheap check: an agent that was killed
		// part way through a job or a reset cannot say what it left, and the
		// cheap check sees only the home and the processes.
		if err := u.resetSlot(ctx, s); err != nil {
			u.markUnhealthy(s, err)
		}
	}
	if err := u.pf.load(ctx); err != nil {
		reason := fmt.Sprintf("the firewall for job users could not be loaded: %v", err)
		u.state.startHold(vmpalEgressHold, reason)
		u.log.Error("the job users' firewall could not be loaded, so the host is held", "error", err)
	}
	u.startWatch(context.WithoutCancel(ctx))
	u.started.Store(true)
	return nil
}

// adoptJobUserRecords rebuilds which slot each runner holds from the records on
// disk, so a restarted agent neither offers a busy slot nor loses the one its
// running job will need cleaned.
func (b *ProcessBackend) adoptJobUserRecords() {
	u := b.jobUsers
	root := filepath.Join(b.root, runnersDirName)
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		meta, err := readMeta(dir)
		if err != nil || meta.Slot == "" {
			continue
		}
		s := u.slotNamed(meta.Slot)
		if s == nil {
			b.log.Warn("a runner record names a job user this agent has no slot for", "dir", dir, "slot", meta.Slot)
			continue
		}
		u.mu.Lock()
		if s.holder != "" && s.holder != dir {
			b.log.Warn("two runner records name the same job user; the first keeps it", "slot", s.name, "dir", dir, "holder", s.holder)
		} else {
			s.holder = dir
		}
		u.mu.Unlock()
	}
}

// probeJobUsers is Probe in job-user mode.
func (b *ProcessBackend) probeJobUsers(ctx context.Context) Info {
	u := b.jobUsers
	info := Info{Kind: b.Kind(), Version: b.version, Endpoint: b.root, Rootless: true}
	if _, err := runnerAsset(runtime.GOOS, runtime.GOARCH, b.version); err != nil {
		info.Detail = err.Error()
		return info
	}
	if err := b.checkWritable(); err != nil {
		info.Detail = err.Error()
		return info
	}
	if !u.started.Load() {
		info.Detail = "the job users have not been set up yet; the agent makes them when it starts"
		return info
	}
	held := u.state.held()
	u.probedHeld.Store(held != nil)
	if held != nil {
		info.Detail = strings.TrimPrefix(held.Error(), "backend: ")
		return info
	}
	if u.healthyCount() == 0 {
		info.Detail = "no job user can take a job: " + strings.Join(u.unhealthy(), "; ")
		return info
	}
	info.Available = true
	info.Detail = fmt.Sprintf("actions/runner %s; each job runs as its own job user (%s to %s), never as root or as the agent",
		b.version, jobUserName(1), jobUserName(u.capacity+1))
	if out := u.unhealthy(); len(out) > 0 {
		info.Detail += "; out of service until they can be cleaned: " + strings.Join(out, "; ")
	}
	return info
}

// createJobUser is CreateWithResult in job-user mode. Every refusal here is made
// before a slot is reserved or, if after, gives the slot back.
func (b *ProcessBackend) createJobUser(ctx context.Context, spec Spec, started time.Time) (CreateResult, error) {
	u := b.jobUsers
	if !spec.Ephemeral {
		return CreateResult{}, fmt.Errorf("%w: pool %q is not ephemeral, and a job-user host runs only ephemeral runners: a runner that kept one slot across jobs would be the leftover state this mode removes", ErrBackendConfig, spec.PoolName)
	}
	if spec.Credentials.JITConfig == "" {
		return CreateResult{}, fmt.Errorf("%w: pool %q gave no just-in-time runner configuration, which is the only way a job-user host registers a runner", ErrBackendConfig, spec.PoolName)
	}
	if err := checkJobUserEnv(spec); err != nil {
		return CreateResult{}, err
	}
	if !u.started.Load() {
		return CreateResult{}, errors.New("backend: the job users have not been set up yet, so this host is not taking jobs; the agent makes them when it starts")
	}

	version := strings.TrimPrefix(strings.TrimSpace(spec.RunnerVersion), "v")
	if version == "" {
		version = b.version
	}
	tools, err := b.ensureRelease(ctx, version)
	if err != nil {
		return CreateResult{}, err
	}

	dir := b.runnerDir(spec.Name)
	if err := b.wipe(ctx, dir); err != nil {
		return CreateResult{}, err
	}

	slot, err := u.admit(ctx, dir)
	if err != nil {
		return CreateResult{}, err
	}
	handedOver := false
	defer func() {
		// A slot whose runner never started goes back as it is. If a step left
		// something in the home, the next admission's check finds it and resets.
		if !handedOver {
			u.release(slot)
		}
	}()

	tmp, err := u.userTempDir(ctx, slot)
	if err != nil {
		return CreateResult{}, fmt.Errorf("backend: asking for %s's temporary folder: %w", slot.name, err)
	}
	runDir := u.runDir(slot)
	// Cloned, not hard-linked as the plain backend does: chowning a linked file
	// would chown the release cache's copy too. A clone shares blocks until one
	// side writes and costs almost nothing.
	if _, err := u.run(ctx, "/bin/cp", "-c", "-R", "-P", tools, runDir); err != nil {
		return CreateResult{}, fmt.Errorf("backend: laying out the runner in %s: %w", runDir, err)
	}
	if _, err := u.run(ctx, "/usr/sbin/chown", "-R", "-h", fmt.Sprintf("%d:%d", slot.uid, jobUserGID), runDir); err != nil {
		return CreateResult{}, fmt.Errorf("backend: giving the runner in %s to %s: %w", runDir, slot.name, err)
	}

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return CreateResult{}, fmt.Errorf("backend: creating the runner record %s: %w", dir, err)
	}
	// The registration is in the environment only, as in the plain backend, and
	// never touches disk.
	env := jobUserEnv(slot, u.home(slot), tmp, spec)
	if err := b.startRunner(dir, runDir, slot, []string{"run"}, env, spec, version); err != nil {
		_ = os.RemoveAll(dir)
		return CreateResult{}, err
	}
	handedOver = true
	b.log.Info("runner process started as a job user", "runner", spec.Name, "pool", spec.PoolName, "slot", slot.name, "dir", dir, "runner_version", version)
	return CreateResult{Handle: Handle(dir), CreateDuration: time.Since(started)}, nil
}

// admit reserves a slot and proves the host is fit to run a job in it: the slot
// is clean, the firewall is in force and the egress check passes as that
// account. A slot that cannot be cleaned is taken out of service and the next is
// tried; a firewall that fails holds the whole host.
func (u *jobUsers) admit(ctx context.Context, holder string) (*jobUserSlot, error) {
	if err := u.state.held(); err != nil {
		return nil, err
	}
	for {
		s, err := u.reserve(holder)
		if err != nil {
			return nil, err
		}
		if err := u.ensureClean(ctx, s); err != nil {
			u.markUnhealthy(s, err)
			continue
		}
		if err := u.pf.verify(ctx); err != nil {
			u.release(s)
			u.firewallLost(ctx, err)
			return nil, u.state.held()
		}
		if err := u.checkEgress(ctx, s); err != nil {
			u.release(s)
			return nil, err
		}
		return s, nil
	}
}

// noteStop records that the agent asked a runner to stop, so that the breaker
// does not count its exit as a runner that failed to take a job.
func (u *jobUsers) noteStop(dir string) {
	u.mu.Lock()
	u.stopped[dir] = true
	u.mu.Unlock()
}

// finishJobUser is what removing a job-user runner adds to removing a plain one:
// keep the diagnostics, clean the account and give the slot back. It runs after
// the runner has stopped and its exit has been recorded, and it never fails the
// removal: a slot that could not be cleaned is out of service and retried, and
// the runner is gone either way.
func (b *ProcessBackend) finishJobUser(ctx context.Context, dir string) {
	u := b.jobUsers
	meta, err := readMeta(dir)
	if err != nil || meta.Slot == "" {
		return
	}
	s := u.slotNamed(meta.Slot)
	if s == nil {
		b.log.Warn("a runner record names a job user this agent has no slot for", "dir", dir, "slot", meta.Slot)
		return
	}
	ctx = context.WithoutCancel(ctx)
	// Nothing of the job may still be running while its folder is read as root:
	// a process that outlived the runner could swap a file for a link under it.
	if err := u.stopProcesses(ctx, s); err != nil {
		b.log.Warn("could not stop what the job left running, so its diagnostics are not copied", "slot", s.name, "error", err)
	} else {
		keep := filepath.Join(b.root, jobUserDiagDir)
		u.copyDiag(meta.RunDir, filepath.Join(keep, filepath.Base(dir)))
		pruneJobUserDiag(keep, jobUserDiagKeep, b.log)
	}
	tookJob := u.tookJob(meta.RunDir)
	u.mu.Lock()
	stopped := u.stopped[dir]
	delete(u.stopped, dir)
	u.mu.Unlock()
	u.state.runnerExited(tookJob, stopped)
	if err := u.resetAndFree(ctx, s); err != nil {
		b.log.Error("a job user could not be cleaned after its job, so it is out of service and will be retried", "slot", s.name, "error", err)
	}
}

// pruneJobUserDiag deletes the oldest folders of kept diagnostics beyond keep.
func pruneJobUserDiag(dir string, keep int, log *slog.Logger) {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) <= keep {
		return
	}
	type aged struct {
		name string
		mod  time.Time
	}
	var all []aged
	for _, e := range entries {
		if info, err := e.Info(); err == nil {
			all = append(all, aged{e.Name(), info.ModTime()})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].mod.Before(all[j].mod) })
	for _, a := range all[:max(0, len(all)-keep)] {
		if err := os.RemoveAll(filepath.Join(dir, a.name)); err != nil {
			log.Warn("could not delete old runner diagnostics", "dir", a.name, "error", err)
		}
	}
}

// tookJob says whether the runner ran a job, which it does if it left a worker
// log. That is the only evidence of one that outlives the runner, and the
// breaker counts on it.
func (u *jobUsers) tookJob(runDir string) bool {
	if runDir == "" {
		return false
	}
	entries, err := u.sys.ReadDir(filepath.Join(runDir, "_diag"))
	if err != nil {
		return false
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "Worker_") {
			return true
		}
	}
	return false
}

// copyDiag keeps the runner's _diag folder, which would be lost with the home.
// Only regular files are copied, found without following links, and 20 MB in
// all, because the folder belongs to the job and is read here as root.
func (u *jobUsers) copyDiag(runDir, dest string) {
	if runDir == "" {
		return
	}
	src := filepath.Join(runDir, "_diag")
	entries, err := u.sys.ReadDir(src)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			u.log.Warn("could not read the runner's diagnostics; the reset goes ahead", "dir", src, "error", err)
		}
		return
	}
	left := int64(jobUserDiagLimit)
	made := false
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		data, err := u.sys.ReadFile(filepath.Join(src, e.Name()), left)
		if err != nil {
			u.log.Warn("could not copy a diagnostics file; the reset goes ahead", "file", e.Name(), "error", err)
			continue
		}
		if !made {
			if err := os.MkdirAll(dest, 0o750); err != nil {
				u.log.Warn("could not make the folder for the runner's diagnostics; the reset goes ahead", "dir", dest, "error", err)
				return
			}
			made = true
		}
		if err := os.WriteFile(filepath.Join(dest, e.Name()), data, 0o640); err != nil {
			u.log.Warn("could not save a diagnostics file; the reset goes ahead", "file", e.Name(), "error", err)
			continue
		}
		left -= int64(len(data))
	}
}
