//go:build unix

package backend

import (
	"io/fs"
	"syscall"
)

// fileDev reads which filesystem a file is on.
func fileDev(fi fs.FileInfo) (dev uint64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Dev), true
}

// fileOwner reads a file's uid and gid.
func fileOwner(fi fs.FileInfo) (uid, gid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
