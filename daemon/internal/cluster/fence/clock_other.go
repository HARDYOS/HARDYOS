//go:build !linux

package fence

import "time"

// BootNow is the boot clock (Linux only; elsewhere the monotonic one).
func BootNow() time.Time { return time.Now() }

// MonoNow is the monotonic clock.
func MonoNow() time.Time { return time.Now() }
