//go:build !linux

package shares

import (
	"context"
	"errors"
)

// FilesUID is the hardyos-files system user (see filesuser_linux.go).
const FilesUID = 29999

// EnsureFilesUser is only supported on Linux.
func (m *Manager) EnsureFilesUser(context.Context) error {
	return errors.New("POSIX ACLs are only supported on Linux")
}
