//go:build !unix

package installer

import "errors"

// JobUserPaths is the unix build's; nothing here runs off a Mac.
type JobUserPaths struct {
	ConfigFile, StateDir, WorkDir, Plist string
}

var errNoJobUsers = errors.New("job-user isolation only runs on a Mac")

func CheckJobUserBinary(string) error { return errNoJobUsers }

func CheckJobUserPaths(JobUserPaths) error { return errNoJobUsers }
