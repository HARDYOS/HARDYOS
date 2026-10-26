//go:build !linux

package fileworker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
)

// ChildMain is only supported on Linux.
func ChildMain() {
	fmt.Fprintln(os.Stderr, "the file worker only runs on Linux")
	os.Exit(1)
}

func canOpenRoot(*root) bool { return false }

func (s *Server) spawn(context.Context, *Identity, []*root, Request) (json.RawMessage, *os.File, error) {
	return nil, nil, errorf(CodeFailed, "file access is only supported on Linux")
}
