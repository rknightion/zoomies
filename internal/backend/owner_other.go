//go:build !unix

package backend

import "io/fs"

// fileDev has no answer off unix.
func fileDev(fs.FileInfo) (dev uint64, ok bool) { return 0, false }

// fileOwner has no answer off unix, where a folder has no owning uid for a
// Linux runner to be refused by.
func fileOwner(fs.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }
