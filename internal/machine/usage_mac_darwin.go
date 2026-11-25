//go:build darwin

package machine

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// defaultMacSource reads this Mac through its sysctls and the stock top.
// golang.org/x/sys/unix is what a binary built without cgo has to reach them.
func defaultMacSource() *macSource {
	return newMacSource(runtime.NumCPU(), func(name string) ([]byte, error) { return unix.SysctlRaw(name) }, runTop)
}
