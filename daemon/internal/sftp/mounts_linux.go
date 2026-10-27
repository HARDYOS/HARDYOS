//go:build linux

package sftp

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"golang.org/x/sys/unix"
)

// SysMounter is the real Mounter.
type SysMounter struct {
	// NoNewAPI skips open_tree/mount_setattr/move_mount and uses the
	// mount(2) fallback (tests of the fallback).
	NoNewAPI bool
}

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
		// Recursive, so anything already mounted below stays reachable
		// through the new mount (and is made private with it below).
		if err := unix.Mount(dir, dir, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("making %s a mount point: %w", dir, err)
		}
	}
	// The root itself first, then everything below it: from here on no
	// unmount inside the views reaches another mount.
	if err := unix.Mount("", dir, "", unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("making %s private: %w", dir, err)
	}
	if err := unix.Mount("", dir, "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("making the mounts in %s private: %w", dir, err)
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

// errNoNewAPI: the kernel lacks open_tree/mount_setattr/move_mount (or
// refuses them here); the mount(2) fallback is used.
var errNoNewAPI = errors.New("the new mount API isn't available")

func (m SysMounter) Bind(src string, dev uint64, dst string, ro bool) error {
	// Only a shared folder's (or home's) verified mount, reached without
	// following any link.
	sfd, err := shares.OpenRoot(src, dev, unix.O_PATH)
	if err != nil {
		return err
	}
	defer unix.Close(sfd)
	dfd, err := openDir(dst)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	if !m.NoNewAPI {
		err := bindNew(sfd, dfd, ro)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errNoNewAPI) {
			return fmt.Errorf("bind mounting %s on %s: %w", src, dst, err)
		}
	}
	return bindOld(sfd, dfd, src, dst, ro)
}

// OPEN_TREE_CLOEXEC is O_CLOEXEC (x/sys has no name for it).
//
// bindNew clones the source mount alone (no AT_RECURSIVE: nothing mounted
// inside it comes along) into a detached mount, makes it private and
// restricted while it is still detached, and only then attaches it. At no
// point is the view's mount a peer of the source's.
func bindNew(sfd, dfd int, ro bool) error {
	tfd, err := unix.OpenTree(sfd, "", unix.OPEN_TREE_CLONE|unix.O_CLOEXEC|unix.AT_EMPTY_PATH)
	if err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) {
			return fmt.Errorf("%w: %v", errNoNewAPI, err)
		}
		return err
	}
	defer unix.Close(tfd)
	attr := &unix.MountAttr{
		Attr_set:    unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOEXEC,
		Propagation: unix.MS_PRIVATE,
	}
	if ro {
		attr.Attr_set |= unix.MOUNT_ATTR_RDONLY
	}
	if err := unix.MountSetattr(tfd, "", unix.AT_EMPTY_PATH, attr); err != nil {
		if errors.Is(err, unix.ENOSYS) {
			return fmt.Errorf("%w: %v", errNoNewAPI, err)
		}
		return fmt.Errorf("restricting the bind: %w", err)
	}
	if err := unix.MoveMount(tfd, "", dfd, "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH); err != nil {
		return fmt.Errorf("attaching the bind: %w", err)
	}
	return nil
}

// bindOld is the mount(2) way: a non-recursive MS_BIND joins the source's
// peer group, so it is made private at once, then restricted; anything
// that propagated in during that instant makes the bind be taken away.
func bindOld(sfd, dfd int, src, dst string, ro bool) error {
	sp := "/proc/self/fd/" + strconv.Itoa(sfd)
	dp := "/proc/self/fd/" + strconv.Itoa(dfd)
	if err := unix.Mount(sp, dp, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind mounting %s on %s: %w", src, dst, err)
	}
	undo := func(err error) error {
		_ = unix.Unmount(dst, unix.MNT_DETACH|unix.UMOUNT_NOFOLLOW)
		return err
	}
	if err := unix.Mount("", dst, "", unix.MS_PRIVATE, ""); err != nil {
		return undo(fmt.Errorf("making the bind mount on %s private: %w", dst, err))
	}
	flags := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	if ro {
		flags |= unix.MS_RDONLY
	}
	if err := unix.Mount("", dst, "", flags, ""); err != nil {
		return undo(fmt.Errorf("restricting the bind mount on %s: %w", dst, err))
	}
	if below, err := (SysMounter{}).List(dst); err != nil || len(below) > 0 {
		return undo(fmt.Errorf("a mount appeared inside the bind on %s while it was made; try again", dst))
	}
	return nil
}

// Unmount takes a bind away; while someone's SFTP session still uses it
// (or, for a view made by an older version, something is mounted inside
// it), it's detached: gone from the view, freed when they disconnect.
// The views' mounts are private (MakePrivate), so this never reaches the
// shared folders' own mounts.
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
