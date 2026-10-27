//go:build !linux

package shares

// GrantReadFD is only supported on Linux.
func GrantReadFD(int, uint32) error { return errNotLinux }
