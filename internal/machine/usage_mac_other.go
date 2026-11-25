//go:build !darwin

package machine

// defaultMacSource is nil off a Mac: procfs answers there, and a sampler with a
// macSource set (only a test does) is the one that reads sysctls.
func defaultMacSource() *macSource { return nil }
