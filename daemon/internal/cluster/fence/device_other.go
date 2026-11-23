//go:build !linux

package fence

func openDevice(string) (Device, error) { return nil, ErrNoWatchdog }
