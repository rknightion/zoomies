package backend

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// vmpalStage is how far one clone has got. The ledger records a stage before
// the step that depends on it, so an agent that dies at any moment can tell
// from what it finds whether a credential may have reached the guest.
type vmpalStage string

const (
	vmpalStageIntent     vmpalStage = "intent"
	vmpalStageCloned     vmpalStage = "cloned"
	vmpalStageHardened   vmpalStage = "hardened"
	vmpalStageBooting    vmpalStage = "booting"
	vmpalStageVerifying  vmpalStage = "verifying"
	vmpalStageArming     vmpalStage = "arming"
	vmpalStageDelivering vmpalStage = "delivering"
	vmpalStageRunning    vmpalStage = "running"
	vmpalStageExited     vmpalStage = "exited"
	vmpalStageDeleting   vmpalStage = "deleting"
)

var vmpalStageOrder = []vmpalStage{
	vmpalStageIntent, vmpalStageCloned, vmpalStageHardened, vmpalStageBooting, vmpalStageVerifying,
	vmpalStageArming, vmpalStageDelivering, vmpalStageRunning, vmpalStageExited, vmpalStageDeleting,
}

func (s vmpalStage) rank() int { return slices.Index(vmpalStageOrder, s) }

// preparing reports a stage before anything was delivered. A clone found here
// by an agent that did not make it holds no credential, and the one it was
// going to get died with the old process, so it can only be thrown away.
func (s vmpalStage) preparing() bool {
	return s.rank() >= 0 && s.rank() < vmpalStageDelivering.rank()
}

// vmpalExitResult is how a runner ended, as the agent will report it. It is
// the mapped result rather than the raw record, so a restart reports the same
// thing the watcher saw.
type vmpalExitResult struct {
	Phase   Phase     `json:"phase"`
	Code    int       `json:"code"`
	Message string    `json:"message,omitempty"`
	At      time.Time `json:"at"`
}

// vmpalEntry is one clone's ledger record. It never holds a credential.
type vmpalEntry struct {
	RunnerID        string           `json:"runner_id"`
	RunnerName      string           `json:"runner_name,omitempty"`
	PoolID          string           `json:"pool_id,omitempty"`
	VMName          string           `json:"vm_name"`
	VMPalID         string           `json:"vmpal_id,omitempty"`
	Stage           vmpalStage       `json:"stage"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
	StartedAt       time.Time        `json:"started_at,omitzero"`
	StopRequestedAt time.Time        `json:"stop_requested_at,omitzero"`
	DeleteIssuedAt  time.Time        `json:"delete_issued_at,omitzero"`
	Exit            *vmpalExitResult `json:"exit,omitempty"`
	// Recovered marks a record rebuilt from a VM's name after its file was lost,
	// when how the clone got here is no longer known.
	Recovered bool `json:"recovered,omitempty"`
}

// vmpalNamePattern is the whole of what makes a VM this agent's to touch. It
// is anchored so that a name merely containing it, such as a copy an operator
// made of a clone, belongs to nobody.
var vmpalNamePattern = regexp.MustCompile(`^zoomies-vm-([0-9a-f]{8})-(run_[A-Za-z0-9]+)$`)

var vmpalRunnerID = regexp.MustCompile(`^run_[A-Za-z0-9]+$`)

// vmpalLedger keeps one small file per clone. Callers hold the backend's lock:
// a stage change is a read followed by a write, and the watcher and a stop can
// both be making one.
type vmpalLedger struct {
	dir string
}

func (l *vmpalLedger) path(name string) string {
	return filepath.Join(l.dir, name+".json")
}

// read returns the record for one VM. A file that cannot be believed reads as
// no file: the VM's name still identifies the runner, and a live job must not
// be deleted because its record was damaged.
func (l *vmpalLedger) read(name string) (vmpalEntry, bool, error) {
	var e vmpalEntry
	if !vmpalNamePattern.MatchString(name) {
		return e, false, nil
	}
	data, err := os.ReadFile(l.path(name))
	if errors.Is(err, fs.ErrNotExist) {
		return e, false, nil
	}
	if err != nil {
		return e, false, fmt.Errorf("backend: reading the VM ledger: %w", err)
	}
	if json.Unmarshal(data, &e) != nil {
		return vmpalEntry{}, false, nil
	}
	m := vmpalNamePattern.FindStringSubmatch(name)
	if e.VMName != name || e.RunnerID != m[2] || e.Stage.rank() < 0 {
		return vmpalEntry{}, false, nil
	}
	return e, true, nil
}

func (l *vmpalLedger) write(e vmpalEntry) error {
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return fmt.Errorf("backend: encoding the VM ledger: %w", err)
	}
	if err := writeFileAtomic(l.path(e.VMName), data, 0o600); err != nil {
		return fmt.Errorf("backend: writing the VM ledger in %s: %w", l.dir, err)
	}
	return nil
}

func (l *vmpalLedger) remove(name string) error {
	err := os.Remove(l.path(name))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("backend: removing a VM's ledger entry: %w", err)
	}
	return nil
}

func (l *vmpalLedger) all() (map[string]vmpalEntry, error) {
	files, err := os.ReadDir(l.dir)
	if err != nil {
		return nil, fmt.Errorf("backend: reading the VM ledger in %s: %w", l.dir, err)
	}
	out := make(map[string]vmpalEntry, len(files))
	for _, f := range files {
		name, ok := strings.CutSuffix(f.Name(), ".json")
		if !ok || f.IsDir() {
			continue
		}
		e, found, err := l.read(name)
		if err != nil {
			return nil, err
		}
		if found {
			out[name] = e
		}
	}
	return out, nil
}

var vmpalInstallIDPattern = regexp.MustCompile(`^[0-9a-f]{8}$`)

// loadVMPalInstallID returns this installation's ID, making one the first time.
// A file that exists and is wrong is an error and is never replaced: a new ID
// would disown every clone on the Mac while they were still running jobs.
func loadVMPalInstallID(dir string) (string, error) {
	path := filepath.Join(dir, "install-id")
	data, err := os.ReadFile(path)
	if err == nil {
		id := strings.TrimSpace(string(data))
		if !vmpalInstallIDPattern.MatchString(id) {
			return "", fmt.Errorf("backend: %s does not hold an install ID; restore it, or delete it after removing this agent's clones with vmpal delete, because a new ID disowns them", path)
		}
		return id, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("backend: reading the VM install ID: %w", err)
	}
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("backend: generating a VM install ID: %w", err)
	}
	id := hex.EncodeToString(raw[:])
	if err := writeFileAtomic(path, []byte(id+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("backend: saving the VM install ID: %w", err)
	}
	return id, nil
}

// vmpalExitOutcome maps a guest's exit record to what the agent is told. It is
// the one place that does, because the code decides the fault the controller
// records: a code the guest chose must not be able to claim one of the meanings
// exitFault gives the reserved codes.
func vmpalExitOutcome(g vmpalGuestExit, stopRequested bool) (Phase, int, string) {
	switch {
	case g.TookJob && g.Code == 0:
		return PhaseExited, 0, ""
	case g.TookJob:
		code := g.Code
		if slices.Contains([]int{7, 64, 69, 78, 137}, code) {
			code = 1
		}
		return PhaseFailed, code, fmt.Sprintf("the job's runner exited with code %d", g.Code)
	case stopRequested:
		return PhaseExited, 0, ""
	case g.Code == 7:
		return PhaseFailed, 7, "the runner version is outdated"
	}
	return PhaseFailed, 1, "the runner exited without taking a job"
}

// The sentences for every way a runner ends without an exit record to read.
const (
	vmpalMsgUnreadable  = "the guest's exit record was unreadable"
	vmpalMsgInterrupted = "the agent restarted while this clone was being prepared; its registration was never delivered, and the clone is being deleted"
	vmpalMsgVMStopped   = "the clone stopped while its runner was running, as it does when the Mac restarts or its user logs out; the clone is being deleted"
	vmpalMsgVMGone      = "the clone is no longer on this Mac; it was deleted outside Zoomies"
	vmpalMsgDeleting    = "the clone was being deleted when the agent last ran; deleting it again"
)

// vmpalStatus is the recovery table: what one ledger record and the VM it names
// mean, reading nothing from the guest.
func vmpalStatus(e vmpalEntry, vm vmpalVM, present, creating bool) Status {
	st := Status{Handle: Handle(e.VMName), StartedAt: e.StartedAt}
	if st.StartedAt.IsZero() {
		st.StartedAt = e.CreatedAt
	}
	stopped := !e.StopRequestedAt.IsZero()
	fail := func(message string) Status {
		st.Phase, st.ExitCode, st.Message = PhaseFailed, 1, message
		return st
	}
	switch {
	case creating:
		st.Phase = PhaseStarting
	case e.Exit != nil:
		st.Phase, st.ExitCode, st.Message, st.ExitedAt = e.Exit.Phase, e.Exit.Code, e.Exit.Message, e.Exit.At
	case !present && stopped:
		st.Phase = PhaseGone
	case !present:
		st.Phase, st.ExitCode, st.Message = PhaseGone, 1, vmpalMsgVMGone
	case e.Stage == vmpalStageDeleting && stopped:
		st.Phase = PhaseExited
	case e.Stage == vmpalStageDeleting:
		return fail(vmpalMsgDeleting)
	case e.Stage.preparing():
		return fail(vmpalMsgInterrupted)
	case vm.State == "running":
		st.Phase = PhaseRunning
	case stopped:
		st.Phase = PhaseExited
	case e.Recovered:
		// Nothing says how it ended, and calling it either would be a guess.
		st.Phase = PhaseExitUnknown
	default:
		return fail(vmpalMsgVMStopped)
	}
	return st
}
