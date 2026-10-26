//go:build !linux

package smb

import (
	"errors"
	"time"
)

func cleanRecycleDir(string, time.Time) (int, error) {
	return 0, errors.New("recycle bins are only cleaned on Linux")
}
