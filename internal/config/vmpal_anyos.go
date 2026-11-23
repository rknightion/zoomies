//go:build zoomies_vmpal_anyos

package config

// VMPalAnyOS lets the macOS VM backend be configured away from a Mac. It is true
// only in a test build, which drives a fake vmpal command on Linux; a shipped
// binary never has it.
const VMPalAnyOS = true
