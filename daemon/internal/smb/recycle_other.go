//go:build !linux

package smb

import (
	"errors"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/shares"
)

func cleanRecycleDir(string, uint64, time.Time) (int, error) {
	return 0, errors.New("recycle bins are only supported on Linux")
}

func (m *Manager) ensureRecycle(*Domain, shares.Share, Resolver) {}
