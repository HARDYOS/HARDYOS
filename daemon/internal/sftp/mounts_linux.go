//go:build linux

package sftp

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// SysMounter is the real Mounter.
type SysMounter struct{}

func (SysMounter) List(dir string) ([]MountPoint, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseMountinfo(f, dir)
}

func (SysMounter) IsMount(dir string) (bool, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false, err
	}
	defer f.Close()
	return isMountIn(f, dir)
}

func (m SysMounter) MakePrivate(dir string) error {
	ok, err := m.IsMount(dir)
	if err != nil {
		return err
	}
	if !ok {
		if err := unix.Mount(dir, dir, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("making %s a mount point: %w", dir, err)
		}
	}
	if err := unix.Mount("", dir, "", unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("making %s private: %w", dir, err)
	}
	return nil
}

// openDir opens a folder as an O_PATH descriptor without following a link
// at its last step, and checks it is a folder.
func openDir(p string) (int, error) {
	fd, err := unix.Open(p, unix.O_PATH|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("%s: %w", p, err)
	}
	return fd, nil
}

func (SysMounter) Bind(src, dst string, ro bool) error {
	sfd, err := openDir(src)
	if err != nil {
		return err
	}
	defer unix.Close(sfd)
	dfd, err := openDir(dst)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	sp := "/proc/self/fd/" + strconv.Itoa(sfd)
	dp := "/proc/self/fd/" + strconv.Itoa(dfd)
	if err := unix.Mount(sp, dp, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind mounting %s on %s: %w", src, dst, err)
	}
	flags := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	if ro {
		flags |= unix.MS_RDONLY
	}
	if err := unix.Mount("", dst, "", flags, ""); err != nil {
		_ = unix.Unmount(dst, unix.MNT_DETACH)
		return fmt.Errorf("restricting the bind mount on %s: %w", dst, err)
	}
	return nil
}

// Unmount takes a bind away; while someone's SFTP session still uses it,
// it's detached (gone from the view, freed when they disconnect).
func (SysMounter) Unmount(dst string) error {
	err := unix.Unmount(dst, unix.UMOUNT_NOFOLLOW)
	if errors.Is(err, unix.EBUSY) {
		err = unix.Unmount(dst, unix.MNT_DETACH|unix.UMOUNT_NOFOLLOW)
	}
	if err != nil && !errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("unmounting %s: %w", dst, err)
	}
	return nil
}
