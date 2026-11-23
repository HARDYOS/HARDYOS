//go:build linux

package fence

import (
	"time"

	"golang.org/x/sys/unix"
)

// BootNow reads CLOCK_BOOTTIME: it keeps counting while the server is
// suspended, unlike Go's monotonic clock (CLOCK_MONOTONIC), so a deadline
// measured with it can't survive a suspend (decision 392).
func BootNow() time.Time {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return time.Now()
	}
	return time.Unix(0, ts.Nano())
}

// MonoNow reads CLOCK_MONOTONIC (stops during a suspend).
func MonoNow() time.Time {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return time.Now()
	}
	return time.Unix(0, ts.Nano())
}
