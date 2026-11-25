//go:build darwin

package backend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// jobUserOutputLimit bounds what one command may have us hold. find can print
// a long list, and a job controls the names in it.
const jobUserOutputLimit = 256 << 10

// jobUserCommandEnv is the whole environment of a command the machinery runs.
// Built from nothing, as the VM backend's is, so that nothing the agent was
// started with reaches a command that runs as root or as a job user.
var jobUserCommandEnv = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=en_US.UTF-8"}

type darwinJobUserSystem struct{}

func newJobUserSystem() (jobUserSystem, error) { return darwinJobUserSystem{}, nil }

func (darwinJobUserSystem) Run(ctx context.Context, c jobUserCommand) (jobUserResult, error) {
	if len(c.Argv) == 0 {
		return jobUserResult{}, errors.New("no command to run")
	}
	cmd := exec.CommandContext(ctx, c.Argv[0], c.Argv[1:]...)
	cmd.Env = jobUserCommandEnv
	cmd.Dir = "/"
	if c.Stdin != "" {
		cmd.Stdin = strings.NewReader(c.Stdin)
	}
	out := &cappedBuffer{limit: jobUserOutputLimit}
	cmd.Stdout, cmd.Stderr = out, out
	if c.AsUser {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(c.UID), Gid: uint32(c.GID)}}
	}
	// A child that a command left holding the pipe must not hold this up.
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	res := jobUserResult{Output: out.String()}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
	default:
		return res, fmt.Errorf("could not run %s: %w", c.Argv[0], err)
	}
	return res, nil
}

func (darwinJobUserSystem) Lstat(path string) (fs.FileInfo, error) { return os.Lstat(path) }
func (darwinJobUserSystem) ReadDir(path string) ([]fs.DirEntry, error) {
	return os.ReadDir(path)
}
func (darwinJobUserSystem) Rename(oldPath, newPath string) error { return os.Rename(oldPath, newPath) }
func (darwinJobUserSystem) RemoveAll(path string) error          { return os.RemoveAll(path) }
func (darwinJobUserSystem) MkdirAll(path string, perm fs.FileMode) error {
	return os.MkdirAll(path, perm)
}
func (darwinJobUserSystem) Chown(path string, uid, gid int) error {
	return os.Lchown(path, uid, gid)
}

func (darwinJobUserSystem) Owner(_ string, fi fs.FileInfo) (uid, gid int, ok bool) {
	return fileOwner(fi)
}

func (darwinJobUserSystem) ReadFile(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return io.ReadAll(io.LimitReader(f, max))
}

func (s darwinJobUserSystem) Processes(ctx context.Context) ([]jobUserProc, error) {
	res, err := s.Run(ctx, jobUserCommand{Argv: []string{"/bin/ps", "-ax", "-o", "pid=,ruid=,uid="}})
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("ps exited %d: %s", res.ExitCode, strings.TrimSpace(res.Output))
	}
	return parseJobUserProcesses(res.Output)
}

func (darwinJobUserSystem) Interfaces() ([]jobUserIface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]jobUserIface, 0, len(ifaces))
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, fmt.Errorf("reading the addresses of %s: %w", i.Name, err)
		}
		out = append(out, jobUserIface{Name: i.Name, HasAddr: len(addrs) > 0})
	}
	return out, nil
}

func (darwinJobUserSystem) Start(cmd *exec.Cmd, uid, gid int) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	// No Groups: the child's supplementary groups are cleared, so the runner
	// does not carry the agent's.
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	return cmd.Start()
}

func (darwinJobUserSystem) SetUmask(mask int) { syscall.Umask(mask) }
