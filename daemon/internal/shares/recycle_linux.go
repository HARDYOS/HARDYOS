//go:build linux

package shares

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// OpenRoot opens a shared folder's root for work done as root: path is
// resolved from / without following any link (openat2 with
// RESOLVE_NO_SYMLINKS), must be a folder, and must be on dev, the device
// of the dataset's own mount that Manager.List verified (Share.RootDev).
// flags are added to O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC (O_RDONLY or
// O_PATH).
func OpenRoot(path string, dev uint64, flags int) (int, error) {
	if dev == 0 {
		return -1, fmt.Errorf("%s: %w", path, ErrUnverified)
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, fmt.Errorf("%q isn't a clean absolute path", path)
	}
	how := &unix.OpenHow{
		Flags:   uint64(flags | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}
	var fd int
	var err error
	for {
		fd, err = unix.Openat2(unix.AT_FDCWD, path, how)
		if err != unix.EINTR && err != unix.EAGAIN {
			break
		}
	}
	if err != nil {
		return -1, fmt.Errorf("opening %s: %w", path, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Dev != dev {
		unix.Close(fd)
		return -1, fmt.Errorf("%s isn't the shared folder's own file system: %w", path, ErrUnverified)
	}
	return fd, nil
}

// checkRoot verifies that path is still the verified mount (OpenRoot) for
// work done by path afterwards (setfacl on the folder itself).
func checkRoot(path string, dev uint64) error {
	fd, err := OpenRoot(path, dev, unix.O_PATH)
	if err != nil {
		return err
	}
	unix.Close(fd)
	return nil
}

func aclUnsupported(err error) bool {
	return errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP)
}

// EnsureRecycle makes sure the shared folder open on rootfd (O_PATH is
// enough) has a usable .recycle: a folder on the same file system, owned
// by this process's user (root in production), mode 1777, without ACL
// entries (a default ACL inherited from the share would give the share's
// people access to every bin made in it). A wrong owner, mode or ACL is
// fixed through a descriptor opened with O_NOFOLLOW; a link, a file or
// another file system there is refused, never followed. It returns what it
// fixed ("made", "owner", "acl", "mode").
func EnsureRecycle(rootfd int) ([]string, error) {
	var fixed []string
	err := unix.Mkdirat(rootfd, RecycleDir, 0o700)
	switch {
	case err == nil:
		fixed = append(fixed, "made")
	case err != unix.EEXIST:
		return nil, fmt.Errorf("making the recycle bin: %w", err)
	}
	fd, err := unix.Openat(rootfd, RecycleDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ENXIO) {
		return nil, binErr("%s at the top of the shared folder is a link or a file, not a folder, so it can't be the recycle bin; an administrator needs to move it away", RecycleDir)
	}
	if err != nil {
		return nil, fmt.Errorf("opening the recycle bin: %w", err)
	}
	defer unix.Close(fd)
	var rst, st unix.Stat_t
	if err := unix.Fstat(rootfd, &rst); err != nil {
		return nil, err
	}
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Dev != rst.Dev {
		return nil, binErr("%s is another file system mounted in the shared folder, so it can't be the recycle bin", RecycleDir)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if st.Uid != uid || st.Gid != gid {
		if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {
			return fixed, binErr("%s belongs to user %d and can't be given back to root (%v), so it can't be the recycle bin", RecycleDir, st.Uid, err)
		}
		fixed = append(fixed, "owner")
	}
	acc, aerr := getACL(fd, xattrAccess)
	def, derr := getACL(fd, xattrDefault)
	if (aerr == nil && acc.hasNamed()) || (derr == nil && def != nil) {
		for _, attr := range []string{xattrAccess, xattrDefault} {
			if err := unix.Fremovexattr(fd, attr); err != nil && !errors.Is(err, unix.ENODATA) && !aclUnsupported(err) {
				return fixed, fmt.Errorf("clearing the recycle bin's ACL: %w", err)
			}
		}
		fixed = append(fixed, "acl")
	} else if aerr != nil && !aclUnsupported(aerr) {
		return fixed, fmt.Errorf("reading the recycle bin's ACL: %w", aerr)
	}
	if err := unix.Fstat(fd, &st); err != nil {
		return fixed, err
	}
	if st.Mode&0o7777 != 0o1777 {
		if err := unix.Fchmod(fd, 0o1777); err != nil {
			return fixed, fmt.Errorf("setting the recycle bin's mode: %w", err)
		}
		fixed = append(fixed, "mode")
	}
	return fixed, nil
}

// CheckBin checks a person's bin, open on fd (a real descriptor, not
// O_PATH): a folder owned by uid that nobody else can enter, list or write
// (no group or other permission, no named ACL entry, no default ACL).
// Wrong owner is a *BinError that TightenBin can't fix; anything else can
// be fixed by the owner with TightenBin.
func CheckBin(fd int, uid uint32) (owner bool, err error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return false, binErr("the recycle bin isn't a folder")
	}
	if st.Uid != uid {
		return false, binErr("the recycle bin folder belongs to user %d, not to user %d", st.Uid, uid)
	}
	if st.Mode&0o077 != 0 {
		return true, binErr("the recycle bin folder can be used by others (mode %04o)", st.Mode&0o7777)
	}
	acc, err := getACL(fd, xattrAccess)
	if err != nil && !aclUnsupported(err) {
		return true, err
	}
	if acc.hasNamed() {
		return true, binErr("the recycle bin folder has ACL entries for others")
	}
	def, err := getACL(fd, xattrDefault)
	if err != nil && !aclUnsupported(err) {
		return true, err
	}
	if def != nil {
		return true, binErr("the recycle bin folder has a default ACL")
	}
	return true, nil
}

// TightenBin makes a bin owner-only: no ACLs, mode 0700. Only its owner
// (or root) can.
func TightenBin(fd int) error {
	for _, attr := range []string{xattrAccess, xattrDefault} {
		if err := unix.Fremovexattr(fd, attr); err != nil && !errors.Is(err, unix.ENODATA) && !aclUnsupported(err) {
			return err
		}
	}
	return unix.Fchmod(fd, 0o700)
}

// skipAtTop: names at the top of a shared folder that the ACL walkers
// never enter. The recycle bin's folders are each person's own (0700, no
// ACL entries) and must stay so; .zfs is the snapshots.
func skipAtTop(depth int, name string) bool {
	return depth == 0 && (name == RecycleDir || name == ".zfs")
}
