package backend

// Everything the job-user machinery does to the host goes through one
// interface, so that a test on any machine can drive it against a fake that
// records what it was asked and a Mac runs the real one. The real one is in
// jobuser_system_darwin.go and a stub that refuses is in
// jobuser_system_other.go.

import (
	"context"
	"io/fs"
	"os/exec"
)

// jobUserCommand is one command the job-user machinery runs.
type jobUserCommand struct {
	Argv []string
	// AsUser runs the command as UID and GID with no supplementary groups, which
	// is how the machinery sees the host the way a job does.
	AsUser   bool
	UID, GID int
}

// jobUserResult is what a command printed (standard output and standard error
// together, cut at a limit) and how it ended.
type jobUserResult struct {
	Output   string
	ExitCode int
}

// jobUserProc is one running process as ps reports it. Both user IDs matter: a
// set-user-ID program can hold a different effective one than the account that
// started it.
type jobUserProc struct {
	PID, RUID, EUID int
}

// jobUserMount is one mounted filesystem: where it is mounted, and the user who
// mounted it, which the kernel records.
type jobUserMount struct {
	Path  string
	Owner int
}

// jobUserSystem is the host, as far as job users are concerned.
type jobUserSystem interface {
	// Run runs a command and waits for it. The error is for a command that could
	// not be run at all; a command that ran and failed has its exit code in the
	// result, because whether that matters is the caller's to say.
	Run(ctx context.Context, c jobUserCommand) (jobUserResult, error)
	Lstat(path string) (fs.FileInfo, error)
	ReadDir(path string) ([]fs.DirEntry, error)
	Rename(oldPath, newPath string) error
	RemoveAll(path string) error
	MkdirAll(path string, perm fs.FileMode) error
	Chown(path string, uid, gid int) error
	// Owner says who owns a file that Lstat or ReadDir described.
	Owner(path string, fi fs.FileInfo) (uid, gid int, ok bool)
	// Dev says which filesystem a file that Lstat or ReadDir described is on, so
	// that a walk can refuse to cross into a mounted one.
	Dev(path string, fi fs.FileInfo) (dev uint64, ok bool)
	// Mounts reads the kernel's mount table.
	Mounts() ([]jobUserMount, error)
	// ReadFile reads a regular file, refusing a link at the final step and
	// anything larger than max, because the files it is used on belong to a job.
	ReadFile(path string, max int64) ([]byte, error)
	Processes(ctx context.Context) ([]jobUserProc, error)
	// Start starts cmd as uid and gid with no supplementary groups. cmd has its
	// own process group already.
	Start(cmd *exec.Cmd, uid, gid int) error
	// SetUmask sets this process's file creation mask, which every job inherits.
	SetUmask(mask int)
}
