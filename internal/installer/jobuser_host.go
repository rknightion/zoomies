//go:build unix

package installer

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// JobUserPaths are the files and folders a job-user agent holds to the rules of
// docs/macos-job-users.md before it starts.
type JobUserPaths struct {
	// ConfigFile, StateDir and WorkDir hold the agent's settings and credentials.
	ConfigFile, StateDir, WorkDir string
	// Plist is the LaunchDaemon that starts the agent.
	Plist string
}

// CheckJobUserBinary refuses a zoomies binary that anybody but root could
// replace, or that sits under a folder anybody but root can change. A job-user
// agent runs as root and starts every job's account from this file, so one a job
// could rewrite would be a job running as root.
func CheckJobUserBinary(binary string) error {
	info, err := os.Lstat(binary)
	if err != nil {
		return fmt.Errorf("cannot look at the zoomies binary %s: %w; install it as /usr/local/bin/zoomies, owned by root", binary, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("the zoomies binary %s is a %s and not a plain file; install the real file as /usr/local/bin/zoomies, owned by root", binary, fileKind(info.Mode()))
	}
	uid, _, ok := fileOwner(info)
	switch {
	case !ok:
		return fmt.Errorf("cannot tell who owns the zoomies binary %s", binary)
	case uid != 0:
		return fmt.Errorf("the zoomies binary %s is owned by uid %d and not by root; the job-user agent runs as root, so give it to root (chown root:wheel %s)", binary, uid, binary)
	case info.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("the zoomies binary %s is writable by its group or the world (mode %o); make it writable by root alone (chmod 755 %s)", binary, info.Mode().Perm(), binary)
	case info.Mode().Perm()&0o111 == 0:
		return fmt.Errorf("the zoomies binary %s is not executable (mode %o)", binary, info.Mode().Perm())
	}
	for dir := filepath.Dir(binary); ; dir = filepath.Dir(dir) {
		if err := checkFolderAboveBinary(dir, fileOwner); err != nil {
			return fmt.Errorf("the job-user agent refuses to run a binary under a folder others can change: %w", err)
		}
		if dir == filepath.Dir(dir) {
			return nil
		}
	}
}

// CheckJobUserPaths refuses an agent whose settings, credentials or work folder
// could be read by anybody but root, or whose service file could be rewritten by
// anybody but root. A job runs as another account on the same Mac, and the
// agent's credentials must be out of its reach.
func CheckJobUserPaths(p JobUserPaths) error {
	for _, f := range []struct {
		what, path string
		isDir      bool
	}{
		{"configuration file", p.ConfigFile, false},
		{"state folder", p.StateDir, true},
		{"work folder", p.WorkDir, true},
	} {
		if f.path == "" {
			continue
		}
		info, err := os.Stat(f.path)
		if err != nil {
			return fmt.Errorf("cannot look at the agent's %s %s: %w", f.what, f.path, err)
		}
		uid, _, ok := fileOwner(info)
		if err := checkRootOnly(f.what, f.path, uid, ok, info.Mode().Perm(), f.isDir); err != nil {
			return err
		}
	}
	if p.Plist != "" {
		info, err := os.Lstat(p.Plist)
		if err != nil {
			return fmt.Errorf("cannot look at the agent's service file %s: %w", p.Plist, err)
		}
		uid, _, ok := fileOwner(info)
		switch {
		case !ok || uid != 0:
			return fmt.Errorf("the agent's service file %s is not owned by root; give it to root (chown root:wheel %s)", p.Plist, p.Plist)
		case info.Mode().Perm()&0o022 != 0:
			return fmt.Errorf("the agent's service file %s is writable by its group or the world (mode %o), so a job could change what runs as root; chmod 644 %s", p.Plist, info.Mode().Perm(), p.Plist)
		}
	}
	return nil
}

// checkRootOnly is the rule for what holds the agent's secrets: root's, and no
// access for its group or anybody else.
func checkRootOnly(what, path string, uid int, ownerKnown bool, perm fs.FileMode, isDir bool) error {
	mode := "600"
	if isDir {
		mode = "700"
	}
	switch {
	case !ownerKnown || uid != 0:
		return fmt.Errorf("the agent's %s %s is not owned by root; give it to root and close it to everybody else (chown root:wheel %s && chmod %s %s)", what, path, path, mode, path)
	case perm&0o077 != 0:
		return fmt.Errorf("the agent's %s %s is open to its group or the world (mode %o), and a job runs on this Mac as another account; chmod %s %s", what, path, perm, mode, path)
	}
	return nil
}
