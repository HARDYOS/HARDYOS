//go:build linux

package cloudbackup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/hardyos/hardyos/daemon/internal/shares"
)

// Restores never write through a path: everything goes through descriptors
// beneath the folder restored into. Paths are opened with
// openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)
// from the folder's descriptor, entries are made with the *at calls on
// their parent's descriptor, and a link in a backup is made again as a
// link (never followed, never written through). Files are written under a
// fresh hidden name and renamed into place.

const resolveFlags = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS

// openBeneath opens rel (components) beneath dirfd as a folder.
func openBeneath(dirfd int, parts []string, flags int) (int, error) {
	p := strings.Join(parts, "/")
	if p == "" {
		p = "."
	}
	how := &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW), Resolve: resolveFlags}
	for {
		fd, err := unix.Openat2(dirfd, p, how)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		return fd, err
	}
}

// mkdirBeneath opens (making what's missing, mode 0755 owned by root unless
// fixed later) the folder rel beneath dirfd.
func mkdirBeneath(dirfd int, parts []string) (int, error) {
	fd, err := unix.Dup(dirfd)
	if err != nil {
		return -1, err
	}
	for _, c := range parts {
		next, err := openBeneath(fd, []string{c}, unix.O_RDONLY|unix.O_DIRECTORY)
		if errors.Is(err, unix.ENOENT) {
			if merr := unix.Mkdirat(fd, c, 0o755); merr != nil && !errors.Is(merr, unix.EEXIST) {
				unix.Close(fd)
				return -1, merr
			}
			next, err = openBeneath(fd, []string{c}, unix.O_RDONLY|unix.O_DIRECTORY)
		}
		unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("%s: %w", c, err)
		}
		fd = next
	}
	return fd, nil
}

// copyStats counts a restore's work.
type copyStats struct {
	Files, Dirs, Links, Skipped int
	Bytes                       int64
	Notes                       []string
	// keepOwner: restore owners and permissions as in the backup (root
	// restores). Otherwise new entries keep root's defaults (not used).
	keepOwner bool
	// allowLink says whether a link in the backup may be made again at
	// path (components below the folder restored into); nil allows every
	// link. Apps' and VMs' own files are read by root, so links there are
	// never restored (only below an app's data/).
	allowLink func(path []string) bool
	// cur is the folder being copied, below the one restored into.
	cur []string
}

// linksOnlyInData allows links only below an app's data folder.
func linksOnlyInData(path []string) bool { return len(path) > 1 && path[0] == "data" }

// noLinks allows no links at all (a VM's folder).
func noLinks([]string) bool { return false }

func (s *copyStats) note(format string, a ...any) {
	if len(s.Notes) < 20 {
		s.Notes = append(s.Notes, fmt.Sprintf(format, a...))
	}
	s.Skipped++
}

// aclXattrs are copied with ownership.
var aclXattrs = []string{"system.posix_acl_access", "system.posix_acl_default"}

func copyMeta(src, dst int, st *unix.Stat_t, isDir bool) error {
	if err := unix.Fchown(dst, int(st.Uid), int(st.Gid)); err != nil && !errors.Is(err, unix.EPERM) {
		return err
	}
	mode := st.Mode & 0o7777
	if !isDir {
		// Never a setuid file from a backup (setgid folders stay: group
		// inheritance is common in shared folders).
		mode &^= unix.S_ISUID | unix.S_ISGID
	}
	if err := unix.Fchmod(dst, mode); err != nil {
		return err
	}
	// ACLs: people's entries as in the backup, HardyOS's own (apps, NFS,
	// hardyos-files) as the destination has them now (decision 228).
	for _, x := range aclXattrs {
		isDefault := x == "system.posix_acl_default"
		if isDefault && !isDir {
			continue
		}
		merged, err := shares.MergeRestoredACL(getXattr(src, x), getXattr(dst, x), mode, isDefault)
		if err != nil {
			merged = nil // an ACL that can't be read doesn't come back
		}
		if merged == nil {
			_ = unix.Fremovexattr(dst, x)
			continue
		}
		_ = unix.Fsetxattr(dst, x, merged, 0)
	}
	return unix.Futimes(dst, []unix.Timeval{unix.NsecToTimeval(st.Atim.Nano()), unix.NsecToTimeval(st.Mtim.Nano())})
}

// copyEntry copies name in srcDir to dstName in dstDir (recursively for a
// folder). replace: an existing file or link there is replaced and a
// folder merged; otherwise an existing name is an error.
func copyEntry(ctx context.Context, srcDir int, name string, dstDir int, dstName string, replace bool, s *copyStats) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstatat(srcDir, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		return copyDir(ctx, srcDir, name, dstDir, dstName, replace, &st, s)
	case unix.S_IFREG:
		return copyFile(srcDir, name, dstDir, dstName, replace, &st, s)
	case unix.S_IFLNK:
		return copyLink(srcDir, name, dstDir, dstName, replace, &st, s)
	default:
		s.note("%s: devices, pipes and sockets aren't restored", name)
		return nil
	}
}

func tmpName() string { return ".hardyos-restore-" + randomID(8) }

func copyFile(srcDir int, name string, dstDir int, dstName string, replace bool, st *unix.Stat_t, s *copyStats) error {
	sfd, err := unix.Openat(srcDir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	src := os.NewFile(uintptr(sfd), name)
	defer src.Close()
	tmp := tmpName()
	dfd, err := unix.Openat(dstDir, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	dst := os.NewFile(uintptr(dfd), tmp)
	fail := func(err error) error {
		dst.Close()
		_ = unix.Unlinkat(dstDir, tmp, 0)
		return err
	}
	n, err := io.Copy(dst, src) // copy_file_range: ZFS can clone the blocks
	if err != nil {
		return fail(err)
	}
	if err := copyMeta(sfd, dfd, st, false); err != nil {
		return fail(err)
	}
	if err := dst.Close(); err != nil {
		_ = unix.Unlinkat(dstDir, tmp, 0)
		return err
	}
	if err := place(dstDir, tmp, dstName, replace); err != nil {
		_ = unix.Unlinkat(dstDir, tmp, 0)
		return err
	}
	s.Files++
	s.Bytes += n
	return nil
}

// place renames tmp to name in dir: over a file or link when replacing,
// never over a folder, never over anything otherwise.
func place(dir int, tmp, name string, replace bool) error {
	if !replace {
		err := unix.Renameat2(dir, tmp, dir, name, unix.RENAME_NOREPLACE)
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("%s is already there", name)
		}
		return err
	}
	var cur unix.Stat_t
	if err := unix.Fstatat(dir, name, &cur, unix.AT_SYMLINK_NOFOLLOW); err == nil && cur.Mode&unix.S_IFMT == unix.S_IFDIR {
		return fmt.Errorf("%s is a folder now; restore it to a new folder instead", name)
	}
	return unix.Renameat(dir, tmp, dir, name)
}

func copyLink(srcDir int, name string, dstDir int, dstName string, replace bool, st *unix.Stat_t, s *copyStats) error {
	if s.allowLink != nil && !s.allowLink(append(append([]string{}, s.cur...), dstName)) {
		s.note("%s: links aren't restored here", joinPath(s.cur, dstName))
		return nil
	}
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(srcDir, name, buf)
	if err != nil {
		return err
	}
	tmp := tmpName()
	if err := unix.Symlinkat(string(buf[:n]), dstDir, tmp); err != nil {
		return err
	}
	_ = unix.Fchownat(dstDir, tmp, int(st.Uid), int(st.Gid), unix.AT_SYMLINK_NOFOLLOW)
	if err := place(dstDir, tmp, dstName, replace); err != nil {
		_ = unix.Unlinkat(dstDir, tmp, 0)
		return err
	}
	s.Links++
	return nil
}

func copyDir(ctx context.Context, srcDir int, name string, dstDir int, dstName string, replace bool, st *unix.Stat_t, s *copyStats) error {
	sfd, err := openBeneath(srcDir, []string{name}, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer unix.Close(sfd)
	if err := unix.Mkdirat(dstDir, dstName, 0o700); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return err
		}
		var cur unix.Stat_t
		if err := unix.Fstatat(dstDir, dstName, &cur, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if cur.Mode&unix.S_IFMT != unix.S_IFDIR {
			if !replace {
				return fmt.Errorf("%s is already there", dstName)
			}
			if err := unix.Unlinkat(dstDir, dstName, 0); err != nil {
				return err
			}
			if err := unix.Mkdirat(dstDir, dstName, 0o700); err != nil {
				return err
			}
		} else if !replace {
			return fmt.Errorf("%s is already there", dstName)
		}
	}
	dfd, err := openBeneath(dstDir, []string{dstName}, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	names, err := readNames(sfd)
	if err != nil {
		return err
	}
	s.cur = append(s.cur, dstName)
	defer func() { s.cur = s.cur[:len(s.cur)-1] }()
	for _, n := range names {
		if err := copyEntry(ctx, sfd, n, dfd, n, replace, s); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.note("%s/%s: %v", name, n, err)
		}
	}
	s.Dirs++
	return copyMeta(sfd, dfd, st, true)
}

func readNames(dirfd int) ([]string, error) {
	fd, err := unix.Openat(dirfd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), ".")
	defer f.Close()
	return f.Readdirnames(-1)
}

// prune removes from dstDir what srcDir doesn't have (a rollback), never
// following links. top: hidden names (.recycle, .zfs, .hardyos*) are kept.
func prune(ctx context.Context, srcDir, dstDir int, top bool, hidden func(string) bool, s *copyStats) error {
	have, err := readNames(srcDir)
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, n := range have {
		keep[n] = true
	}
	names, err := readNames(dstDir)
	if err != nil {
		return err
	}
	for _, n := range names {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if top && hidden(n) {
			continue
		}
		if !keep[n] {
			if err := removeAll(dstDir, n); err != nil {
				s.note("%s: %v", n, err)
			}
			continue
		}
		var a, b unix.Stat_t
		if unix.Fstatat(srcDir, n, &a, unix.AT_SYMLINK_NOFOLLOW) != nil || unix.Fstatat(dstDir, n, &b, unix.AT_SYMLINK_NOFOLLOW) != nil {
			continue
		}
		if a.Mode&unix.S_IFMT == unix.S_IFDIR && b.Mode&unix.S_IFMT == unix.S_IFDIR {
			sfd, err := openBeneath(srcDir, []string{n}, unix.O_RDONLY|unix.O_DIRECTORY)
			if err != nil {
				continue
			}
			dfd, err := openBeneath(dstDir, []string{n}, unix.O_RDONLY|unix.O_DIRECTORY)
			if err != nil {
				unix.Close(sfd)
				continue
			}
			err = prune(ctx, sfd, dfd, false, hidden, s)
			unix.Close(sfd)
			unix.Close(dfd)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// removeAll deletes name in dir and everything below it, by descriptor.
func removeAll(dir int, name string) error {
	var st unix.Stat_t
	if err := unix.Fstatat(dir, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return unix.Unlinkat(dir, name, 0)
	}
	fd, err := openBeneath(dir, []string{name}, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	names, err := readNames(fd)
	if err == nil {
		for _, n := range names {
			if err = removeAll(fd, n); err != nil {
				break
			}
		}
	}
	unix.Close(fd)
	if err != nil {
		return err
	}
	return unix.Unlinkat(dir, name, unix.AT_REMOVEDIR)
}

// openFolder opens a verified folder (a share's root, an app's or VM's
// dataset, a staging dataset): resolved from / without any link, and on
// the device of its verified mount.
func openFolder(path string, dev uint64) (int, error) {
	how := &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, how)
	if err != nil {
		return -1, fmt.Errorf("opening %s: %w", path, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, err
	}
	if dev != 0 && st.Dev != dev {
		unix.Close(fd)
		return -1, fmt.Errorf("%s isn't the file system it should be", path)
	}
	return fd, nil
}

// openNoLinks opens a regular file for reading from /, following no link
// on the way.
func openNoLinks(path string) (int, error) {
	how := &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC), Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, how)
	if err != nil {
		return -1, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return fd, nil
}

// requireBlockDevice is off only in tests, which write "disks" to files.
var requireBlockDevice = true

// writeDevice writes r onto a block device opened exclusively (nothing
// else may have it open: a running VM, a mounted file system).
func writeDevice(dev string, r io.Reader) (int64, error) {
	how := &unix.OpenHow{Flags: uint64(unix.O_WRONLY | unix.O_EXCL | unix.O_CLOEXEC), Resolve: unix.RESOLVE_NO_MAGICLINKS}
	fd, err := unix.Openat2(unix.AT_FDCWD, dev, how)
	if err != nil {
		return 0, fmt.Errorf("opening %s: %w", dev, err)
	}
	f := os.NewFile(uintptr(fd), dev)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if fi.Mode()&os.ModeDevice == 0 && requireBlockDevice {
		return 0, fmt.Errorf("%s isn't a disk", dev)
	}
	n, err := io.Copy(f, r)
	if err != nil {
		return n, err
	}
	return n, f.Sync()
}

const (
	oRDONLY    = unix.O_RDONLY
	oDIRECTORY = unix.O_DIRECTORY
)

func closeFD(fd int) { _ = unix.Close(fd) }

// mkdirAt makes a new folder name in dir (it must not exist).
func mkdirAt(dir int, name string) error {
	err := unix.Mkdirat(dir, name, 0o755)
	if errors.Is(err, unix.EEXIST) {
		return problemf("there's already something called %s; choose another name", name)
	}
	return err
}

// readAllFD reads a regular file's descriptor (closing it), at most max bytes.
func readAllFD(fd int, max int64) ([]byte, error) {
	f := os.NewFile(uintptr(fd), "staged")
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, errors.New("not a small regular file")
	}
	return io.ReadAll(io.LimitReader(f, max))
}

// removeInRootDir removes a file from one of root's own directories: the
// directory is reached without following any link and must be root's
// (when running as root).
func removeInRootDir(p string) error {
	dir, name := filepath.Split(filepath.Clean(p))
	how := &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS}
	fd, err := unix.Openat2(unix.AT_FDCWD, dir, how)
	if err != nil {
		return &os.PathError{Op: "open", Path: dir, Err: err}
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if os.Geteuid() == 0 && (st.Uid != 0 || st.Mode&0o022 != 0) {
		return fmt.Errorf("%s isn't root's own folder", dir)
	}
	if err := unix.Unlinkat(fd, name, 0); err != nil {
		return &os.PathError{Op: "remove", Path: p, Err: err}
	}
	return nil
}

func joinPath(dir []string, name string) string {
	if len(dir) == 0 {
		return name
	}
	return strings.Join(dir, "/") + "/" + name
}

// getXattr reads one extended attribute (nil if it isn't there).
func getXattr(fd int, name string) []byte {
	buf := make([]byte, 64<<10)
	n, err := unix.Fgetxattr(fd, name, buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}
