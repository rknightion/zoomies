//go:build !windows

// Command vmpal is the test-only stand-in for the real vmpal tool. All of its
// behaviour lives in the fakevmpal package, so a test can edit the same state
// the command reads.
package main

import (
	"os"

	"github.com/eyupio/zoomies/test/fakevmpal"
)

func main() { os.Exit(fakevmpal.Main()) }
