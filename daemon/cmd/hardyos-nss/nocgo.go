//go:build !cgo

// Command hardyos-nss must be built with cgo (CGO_ENABLED=1): without it,
// Go's user lookup never asks winbind. This build refuses to run rather
// than give wrong answers. See main.go.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "hardyos-nss was built without cgo and can't look up domain users; rebuild it with CGO_ENABLED=1")
	os.Exit(1)
}
