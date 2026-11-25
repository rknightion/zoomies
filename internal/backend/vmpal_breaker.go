package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"sync"
	"time"
)

const (
	// vmpalEgressHold is how long a failed egress check, or a state file that
	// cannot be believed, keeps new clones off this Mac.
	vmpalEgressHold = 10 * time.Minute
	// vmpalBreakerThreshold is how many runners in a row may exit without
	// taking a job before registrations stop.
	vmpalBreakerThreshold = 3
)

// vmpalBreakerHolds are the holds the breaker starts, in order. The last one
// repeats. They are what bounds the registrations a repeating failure can make,
// because the controller's own backoff stops counting a runner once it has
// registered.
var vmpalBreakerHolds = []time.Duration{10 * time.Minute, 20 * time.Minute, 40 * time.Minute, 60 * time.Minute}

// vmpalHostFile is state.json: what must outlive the agent, because a restart
// that forgot a hold would be a way past it.
type vmpalHostFile struct {
	HoldUntil  time.Time `json:"hold_until,omitzero"`
	HoldReason string    `json:"hold_reason,omitempty"`
	Count      int       `json:"breaker_count"`
	Level      int       `json:"breaker_level"`
}

// believable reports whether a loaded file could have been written by this
// code. A hold further off than the longest there is would otherwise keep a
// host out of service for as long as a damaged date said to.
func (f vmpalHostFile) believable(now time.Time) bool {
	longest := vmpalBreakerHolds[len(vmpalBreakerHolds)-1]
	return f.Count >= 0 && f.Count < vmpalBreakerThreshold &&
		f.Level >= 0 && f.Level < len(vmpalBreakerHolds) &&
		!f.HoldUntil.After(now.Add(longest))
}

// withHold applies a hold. The later end wins and keeps its own reason, so a
// short hold can never shorten a longer one that is already running.
func (f vmpalHostFile) withHold(until time.Time, reason string) vmpalHostFile {
	if until.After(f.HoldUntil) {
		f.HoldUntil, f.HoldReason = until, reason
	}
	return f
}

// afterExit is the breaker. Only evidence moves it: a runner that took a job
// proves the host works, and one the agent stopped itself proves nothing either
// way, so short real jobs can never trip it however many there are.
func (f vmpalHostFile) afterExit(tookJob, stopRequested bool, now time.Time) vmpalHostFile {
	switch {
	case tookJob:
		f.Count, f.Level = 0, 0
	case stopRequested:
	default:
		// An exit during a hold counts too: the runner registered, and the
		// next round should start knowing that.
		f.Count++
		if f.Count >= vmpalBreakerThreshold {
			hold := vmpalBreakerHolds[f.Level]
			f.Count = 0
			f.Level = min(f.Level+1, len(vmpalBreakerHolds)-1)
			f = f.withHold(now.Add(hold), fmt.Sprintf("%d runners in a row exited without taking a job, so new registrations are stopped for %s; read a failed runner's log, and check the template and that the Mac can reach GitHub", vmpalBreakerThreshold, hold))
		}
	}
	return f
}

// vmpalHostState is the file and the lock around it.
type vmpalHostState struct {
	mu   sync.Mutex
	path string
	now  func() time.Time
	log  *slog.Logger
	file vmpalHostFile
}

// openVMPalHostState loads state.json. A file that cannot be believed starts a
// hold and is replaced: it may have been recording one, and carrying on as if
// it had not would make damaging the file a way past it.
func openVMPalHostState(path string, now func() time.Time, log *slog.Logger) *vmpalHostState {
	s := &vmpalHostState{path: path, now: now, log: log}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s
	}
	var file vmpalHostFile
	if err == nil {
		err = json.Unmarshal(data, &file)
	}
	if err == nil && !file.believable(s.clock()) {
		err = errors.New("its values are out of range")
	}
	if err != nil {
		log.Warn("the macOS VM state file cannot be read; holding new runners and rewriting it", "path", path, "error", err)
		s.file = vmpalHostFile{}.withHold(s.clock().Add(vmpalEgressHold), fmt.Sprintf("the state file %s was unreadable, so an earlier hold may have been lost; new runners resume when this hold ends", path))
		s.saveLocked()
		return s
	}
	s.file = file
	return s
}

// clock has no monotonic reading. That clock stops while a Mac sleeps, and a
// hold is a promise about the wall clock.
func (s *vmpalHostState) clock() time.Time { return s.now().Round(0) }

// saveLocked keeps going on a failed write. The hold is still in force in this
// process, and refusing work because the disk is full would not make it safer.
func (s *vmpalHostState) saveLocked() {
	data, err := json.MarshalIndent(s.file, "", "  ")
	if err == nil {
		err = writeFileAtomic(s.path, data, 0o600)
	}
	if err != nil {
		s.log.Warn("could not save the macOS VM state file; a hold will not survive an agent restart", "path", s.path, "error", err)
	}
}

// held returns the refusal while a hold is running.
func (s *vmpalHostState) held() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.clock().Before(s.file.HoldUntil) {
		return nil
	}
	return fmt.Errorf("%w: held until %s: %s", errVMPalHeld, s.file.HoldUntil.UTC().Format(time.RFC3339), s.file.HoldReason)
}

// startHold holds new work for d from now.
func (s *vmpalHostState) startHold(d time.Duration, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.file = s.file.withHold(s.clock().Add(d), reason)
	s.saveLocked()
}

// runnerExited feeds one finished runner to the breaker.
func (s *vmpalHostState) runnerExited(tookJob, stopRequested bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.file.afterExit(tookJob, stopRequested, s.clock())
	if next == s.file {
		return
	}
	s.file = next
	s.saveLocked()
}
