//go:build !linux

package shares

import "errors"

var errNotLinux = errors.New("shared folders are only supported on Linux")

// OpenRoot is only supported on Linux.
func OpenRoot(string, uint64, int) (int, error) { return -1, errNotLinux }

// EnsureRecycle is only supported on Linux.
func EnsureRecycle(int) ([]string, error) { return nil, errNotLinux }

// CheckBin is only supported on Linux.
func CheckBin(int, uint32) (bool, error) { return false, errNotLinux }

// TightenBin is only supported on Linux.
func TightenBin(int) error { return errNotLinux }

func checkRoot(string, uint64) error { return errNotLinux }
