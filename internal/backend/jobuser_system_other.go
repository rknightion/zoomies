//go:build !darwin

package backend

import "fmt"

// newJobUserSystem refuses off a Mac. The validator refuses the mode there as
// well; this is the backstop for a caller that never validated.
func newJobUserSystem() (jobUserSystem, error) {
	return nil, fmt.Errorf("%w: job users only run on macOS", ErrBackendConfig)
}
