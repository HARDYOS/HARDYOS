//go:build !linux

package shares

import (
	"context"
	"errors"
)

type treeStats struct {
	Changed, Seen, Skipped, Failed int
	First                          error
}

func applyTree(context.Context, string, uint64, int, bool, bool) (treeStats, error) {
	return treeStats{}, errors.New("POSIX ACLs are only supported on Linux")
}
