//go:build linux

package fence

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fileDevice is /dev/watchdogN through the kernel's watchdog API.
type fileDevice struct{ f *os.File }

func openDevice(path string) (Device, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &fileDevice{f: f}, nil
}

func (d *fileDevice) SetTimeout(seconds int) (int, error) {
	v := int32(seconds)
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, d.f.Fd(), uintptr(unix.WDIOC_SETTIMEOUT), uintptr(unsafe.Pointer(&v))); e != 0 {
		return 0, e
	}
	return int(v), nil
}

func (d *fileDevice) Keepalive() error {
	var v int32
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, d.f.Fd(), uintptr(unix.WDIOC_KEEPALIVE), uintptr(unsafe.Pointer(&v))); e != 0 {
		return e
	}
	return nil
}

func (d *fileDevice) Close(magic bool) error {
	if magic {
		if _, err := d.f.Write([]byte("V")); err != nil {
			d.f.Close()
			return err
		}
	}
	return d.f.Close()
}
