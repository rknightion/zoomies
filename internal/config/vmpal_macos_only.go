//go:build !zoomies_vmpal_anyos

package config

// VMPalAnyOS is false in every shipped build: the macOS VM backend is a Mac's.
const VMPalAnyOS = false
