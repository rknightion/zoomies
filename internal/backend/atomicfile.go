package backend

import (
	"os"
	"path/filepath"
)

// writeFileAtomic replaces path with data in one step. A reader sees the old
// file or the new one and never half of either, which is what lets an agent
// killed in the middle of a write trust whatever it finds on its next start.
//
// The temporary file sits beside the target because a rename is only atomic
// within one filesystem, and it is named so that nothing listing the directory
// for the target's extension can mistake a leftover for a record.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
