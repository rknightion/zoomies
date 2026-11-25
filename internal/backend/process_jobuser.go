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

// ProbeStale says the last Probe no longer describes this host: a slot changed
// health. It clears on read.
func (b *ProcessBackend) ProbeStale() bool {
	u := b.jobUsers
	if u == nil {
		return false
	}
	return u.reprobe.Swap(false)
}

// Close stops the watcher. It leaves every runner running.
func (b *ProcessBackend) Close() {
	if b.jobUsers != nil {
		b.jobUsers.close()
	}
}

// StartJobUsers makes the accounts, finds the jobs an earlier agent left, cleans
// every slot nobody holds and starts the watcher. Nothing is admitted before it
// returns. It refuses to go on if an account or the group is not what Zoomies
// would have made.
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
	// Every account that exists, not only those offered: one above a capacity that
	// was lowered holds nothing now, and nothing says what was left in it.
	for _, s := range u.covered() {
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
	u.startWatch(context.WithoutCancel(ctx))
	u.started.Store(true)
	return nil
}

// adoptJobUserRecords rebuilds which slot each runner holds from the records on
// disk, so a restarted agent neither offers a busy slot nor loses the one its
// running job will need cleaned.
//
// Two records can name one slot, when an agent died between giving a slot back
// and deleting the record, or a record could not be deleted. The slot belongs to
// the record whose runner process is alive, because that is the job using the
// account; with none alive, the first. The record that loses has its claim
// cleared, so that cleaning it up later can never reset an account that is not
// its own.
//
// A slot above the capacity now set is adopted all the same, and drains: it is
// never offered again, and it is cleaned when its job ends.
func (b *ProcessBackend) adoptJobUserRecords() {
	u := b.jobUsers
	root := filepath.Join(b.root, runnersDirName)
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	type claim struct {
		dir  string
		meta processMeta
	}
	claims := make(map[string][]claim)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		meta, err := readMeta(dir)
		if err != nil || meta.Slot == "" {
			continue
		}
		if u.slotNamed(meta.Slot) == nil {
			b.log.Warn("a runner record names a job user this agent has no slot for", "dir", dir, "slot", meta.Slot)
			continue
		}
		claims[meta.Slot] = append(claims[meta.Slot], claim{dir, meta})
	}
	for _, s := range u.slots {
		cs := claims[s.name]
		if len(cs) == 0 {
			continue
		}
		winner := 0
		for i, c := range cs {
			if runnerProcessAlive(c.dir, c.meta) {
				winner = i
				break
			}
		}
		u.mu.Lock()
		s.holder = cs[winner].dir
		u.mu.Unlock()
		if !s.offered {
			b.log.Info("a job is still running in a job user above the capacity now set; it is cleaned when the job ends and is not offered again", "slot", s.name, "dir", cs[winner].dir)
		}
		for i, c := range cs {
			if i == winner {
				continue
			}
			b.log.Warn("two runner records name the same job user; the slot goes to the one whose runner is running, or the first", "slot", s.name, "dir", c.dir, "holder", cs[winner].dir)
			if err := clearSlotClaim(c.dir); err != nil {
				b.log.Warn("could not clear the claim of a runner record that lost its job user", "dir", c.dir, "error", err)
			}
		}
	}
}

// runnerProcessAlive says whether the runner a record describes is running: its
// process exists and is the one the record was written for, not a process that
// has since been given the same number.
func runnerProcessAlive(dir string, meta processMeta) bool {
	pid := readPID(dir)
	return pid > 0 && processAlive(pid) && verifyProcessIdentity(meta, pid) == nil
}

// clearSlotClaim takes the job user out of a runner's record, so that nothing
// that reads the record afterwards takes the account for its own. If the record
// cannot be rewritten it is deleted: a record with no metadata is not a claim on
// anything, and is cleaned up as an abandoned folder.
func clearSlotClaim(dir string) error {
	meta, err := readMeta(dir)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	if meta.Slot == "" {
		return nil
	}
	meta.Slot = ""
	werr := writeMeta(dir, meta)
	if werr == nil {
		return nil
	}
	if rerr := os.Remove(filepath.Join(dir, runnerMetaFile)); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		return fmt.Errorf("could not rewrite the record in %s (%v) or delete it: %w", dir, werr, rerr)
	}
	return nil
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

	// The registration is in the environment only, as in the plain backend, and
	// never touches disk.
	// The pool's cache is made ready now, with the slot reserved and the job not
	// started: the one moment it can be pruned.
	env := jobUserEnv(slot, u.home(slot), tmp, u.prepareCache(ctx, slot, spec), spec)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return CreateResult{}, fmt.Errorf("backend: creating the runner record %s: %w", dir, err)
	}
	if err := b.startRunner(dir, runDir, slot, []string{"run"}, env, spec, version); err != nil {
		_ = os.RemoveAll(dir)
		return CreateResult{}, err
	}
	handedOver = true
	b.log.Info("runner process started as a job user", "runner", spec.Name, "pool", spec.PoolName, "slot", slot.name, "dir", dir, "runner_version", version)
	return CreateResult{Handle: Handle(dir), CreateDuration: time.Since(started)}, nil
}

// admit reserves a slot and proves it is clean. A slot that cannot be cleaned is
// taken out of service and the next is tried.
func (u *jobUsers) admit(ctx context.Context, holder string) (*jobUserSlot, error) {
	for {
		s, err := u.reserve(holder)
		if err != nil {
			return nil, err
		}
		if err := u.ensureClean(ctx, s); err != nil {
			u.markUnhealthy(s, err)
			continue
		}
		return s, nil
	}
}

// finishJobUser is what removing a job-user runner adds to removing a plain one:
// keep the diagnostics, clean the account and give the slot back. It runs after
// the runner has stopped and its exit has been recorded. A slot that could not be
// cleaned does not fail the removal: it is out of service and retried, and the
// runner is gone either way.
//
// It acts on the slot only if this record's directory is the slot's holder. A
// record that names a slot another runner holds, or nobody does, is a leftover,
// and resetting the account would kill a live job and wipe its home; that record
// has its claim cleared and nothing else done. And the claim is cleared from the
// record before the slot is given back, whether the reset worked or not, because
// once it is free the next create can take it, and a record that still named it
// would be a claim on somebody else's job. If the claim cannot be cleared the
// slot is not given back and the removal fails, to be tried again, with the slot
// still this record's.
func (b *ProcessBackend) finishJobUser(ctx context.Context, dir string) error {
	u := b.jobUsers
	meta, err := readMeta(dir)
	if err != nil || meta.Slot == "" {
		return nil
	}
	s := u.slotNamed(meta.Slot)
	if s == nil {
		b.log.Warn("a runner record names a job user this agent has no slot for", "dir", dir, "slot", meta.Slot)
		return nil
	}
	u.mu.Lock()
	mine := s.holder == dir
	holder := s.holder
	u.mu.Unlock()
	if !mine {
		b.log.Warn("a runner record names a job user it does not hold, so the account is left alone", "dir", dir, "slot", s.name, "holder", holder)
		return clearSlotClaim(dir)
	}
	ctx = context.WithoutCancel(ctx)
	// Nothing of the job may still be running while its folder is read as root:
	// a process that outlived the runner could swap a file for a link under it.
	if err := u.stopProcesses(ctx, s); err != nil {
		b.log.Warn("could not stop what the job left running, so its diagnostics are not copied", "slot", s.name, "error", err)
	} else {
		keep := filepath.Join(b.root, jobUserDiagDir)
		u.copyDiag(s, filepath.Join(keep, filepath.Base(dir)))
		pruneJobUserDiag(keep, jobUserDiagKeep, b.log)
	}
	resetErr := u.resetSlot(ctx, s)
	if err := clearSlotClaim(dir); err != nil {
		return fmt.Errorf("backend: the account %s was cleaned but could not be taken out of the runner's record, so it is kept for this runner until the record can be removed: %w", s.name, err)
	}
	if err := u.free(s, resetErr); err != nil {
		b.log.Error("a job user could not be cleaned after its job, so it is out of service and will be retried", "slot", s.name, "error", err)
	}
	return nil
}

// jobUserStats is Stats in job-user mode. A job runs entirely as its slot's
// account, so its usage is the sum over every process that account owns, real
// or effective: the runner, the steps it starts and whatever they leave behind.
// That is what a container's cgroup would have said, and it works on a Mac,
// which has no /proc and no cgroup.
//
// CPU is ps's figure, percent of one CPU, which is the unit the container
// backends report (a job using two cores reads about 200), so the controller
// reads both alike. It is the kernel's smoothed figure, not a rate over an
// interval of ours, which keeps this free of state between samples. Memory is
// the sum of resident sets, which counts a page shared between two processes
// twice; for sizing advice that errs towards too much, which is the safe side.
//
// It is best effort, as the interface asks: a runner no slot holds (its job
// has ended and the account is given back), a ps that will not run or an
// account running nothing all report nothing, and never an error.
func (b *ProcessBackend) jobUserStats(ctx context.Context, dir string) Stats {
	u := b.jobUsers
	var slot *jobUserSlot
	u.mu.Lock()
	for _, s := range u.slots {
		if s.holder == dir {
			slot = s
			break
		}
	}
	u.mu.Unlock()
	if slot == nil {
		return Stats{}
	}
	procs, err := u.processesOf(ctx, slot.uid)
	if err != nil || len(procs) == 0 {
		return Stats{}
	}
	var out Stats
	for _, p := range procs {
		out.CPUPercent += p.CPUPercent
		out.MemoryBytes += p.RSSBytes
	}
	at := u.now()
	out.SampledAt = &at
	return out
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

// copyDiag keeps the runner's _diag folder, which would be lost with the home.
// Only regular files that the slot owns are copied, 20 MB in all, and only if no
// step of the way to them from the slot's home is a link: the folder belongs to
// the job and is read here as root, so a link at any depth would have root copy
// whatever it points to. Nothing of the job is running, which stopProcesses has
// just shown, so what is looked at is what is read.
func (u *jobUsers) copyDiag(s *jobUserSlot, dest string) {
	src := filepath.Join(u.runDir(s), "_diag")
	for _, step := range []string{u.home(s), u.runDir(s), src} {
		info, err := u.sys.Lstat(step)
		if errors.Is(err, fs.ErrNotExist) {
			return
		}
		if err != nil {
			u.log.Warn("could not look at the runner's diagnostics; the reset goes ahead", "dir", step, "error", err)
			return
		}
		if !info.IsDir() {
			u.log.Warn("the runner's diagnostics are behind a link or something that is not a folder, which only a job makes it, so they are not copied; the reset goes ahead", "path", step)
			return
		}
	}
	entries, err := u.sys.ReadDir(src)
	if err != nil {
		u.log.Warn("could not read the runner's diagnostics; the reset goes ahead", "dir", src, "error", err)
		return
	}
	left := int64(jobUserDiagLimit)
	made := false
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		path := filepath.Join(src, e.Name())
		// A hard link to a file of root's is a regular file in the job's folder.
		info, err := e.Info()
		if err != nil {
			continue
		}
		if uid, _, ok := u.sys.Owner(path, info); !ok || uid != s.uid {
			u.log.Warn("a diagnostics file is not the job user's, so it is not copied", "file", e.Name())
			continue
		}
		data, err := u.sys.ReadFile(path, left)
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
