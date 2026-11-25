//go:build unix

package installer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheAgentsFilesMustBeRootsAndClosedToEverybodyElse(t *testing.T) {
	cases := []struct {
		name  string
		uid   int
		known bool
		perm  os.FileMode
		dir   bool
		want  string
	}{
		{"root's private file", 0, true, 0o600, false, ""},
		{"root's private folder", 0, true, 0o700, true, ""},
		{"a file the agent's user owns", 501, true, 0o600, false, "not owned by root"},
		{"a file whose owner cannot be told", 0, false, 0o600, false, "not owned by root"},
		{"a file the group can read", 0, true, 0o640, false, "open to its group or the world"},
		{"a file the world can read", 0, true, 0o644, false, "open to its group or the world"},
		{"a folder others can enter", 0, true, 0o755, true, "chmod 700"},
	}
	for _, tc := range cases {
		err := checkRootOnly("configuration file", "/Library/Application Support/zoomies/zoomies.yaml", tc.uid, tc.known, tc.perm, tc.dir)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: err = %v; want %q", tc.name, err, tc.want)
		}
	}
}

func TestCheckingAnAgentsPathsNamesTheOneThatIsWrong(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "zoomies.yaml")
	if err := os.WriteFile(cfg, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Whoever runs the test, a file open to the world is refused: as root for its
	// mode and as anybody else for its owner.
	err := CheckJobUserPaths(JobUserPaths{ConfigFile: cfg})
	if err == nil || !strings.Contains(err.Error(), cfg) {
		t.Errorf("err = %v; want it to name %s", err, cfg)
	}
	if err := CheckJobUserPaths(JobUserPaths{ConfigFile: filepath.Join(dir, "missing")}); err == nil {
		t.Error("a missing file was accepted")
	}
	// A service file anybody can write is a way to run what they like as root.
	plist := filepath.Join(dir, "sh.zoomies.agent.plist")
	if err := os.WriteFile(plist, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(plist, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := CheckJobUserPaths(JobUserPaths{Plist: plist}); err == nil || !strings.Contains(err.Error(), plist) {
		t.Errorf("plist: err = %v", err)
	}
	if err := CheckJobUserPaths(JobUserPaths{}); err != nil {
		t.Errorf("nothing to check: %v", err)
	}
}

func TestCheckingTheBinaryRefusesWhatOthersCouldReplace(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "zoomies")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := CheckJobUserBinary(bin); err == nil {
		t.Error("a binary anybody can write was accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(bin, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckJobUserBinary(link); err == nil || !strings.Contains(err.Error(), "not a plain file") {
		t.Errorf("a link was accepted: %v", err)
	}
	if err := CheckJobUserBinary(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing binary was accepted")
	}
}
