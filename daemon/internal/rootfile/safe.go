package rootfile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Root writes state files into directories other accounts may own (the
// hardyd account owns /var/lib/hardyos). Writing "<path>.tmp" there with
// O_TRUNC and renaming it follows whatever hardyd planted at that name: a
// symlink to /etc/shadow gets truncated and rewritten by root. The helpers
// here never follow a symlink that someone other than root could have put
// in place, never reuse a predictable temporary name, and check the file
// they actually opened, not the name.

// MaxStateBytes bounds what ReadFile and ReadFileInRootDir read.
const MaxStateBytes = 16 << 20

// RootStateDir is root's own directory on the shared state dataset: owned
// by root, 0755, so every boot environment sees it and hardyd can read but
// not change what's in it. hardyd owns the parent, so it could rename this
// directory away and put its own in place: every access checks the
// directory it actually opened (EnsureRootDir, ReadFileInRootDir).
const RootStateDir = "/var/lib/hardyos/root"

// trustedDir reports whether a directory's owner is root and nobody else
// can write to it, so the names in it are root's.
func trustedDir(st *unix.Stat_t) bool {
	return st.Uid == 0 && st.Mode&0o022 == 0
}

// openDir walks to dir one component at a time without following
// symlinks, except a symlink in a directory only root can change (such as
// /var/run -> /run): root put that one there. With create, missing
// components are made with mode (as the caller, root on a server). The
// returned descriptor is a directory the caller must close.
func openDir(dir string, create bool, mode os.FileMode) (int, error) {
	if !filepath.IsAbs(dir) {
		return -1, fmt.Errorf("%s: not an absolute path", dir)
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	parts := strings.Split(filepath.Clean(dir), "/")
	walked := "/"
	for _, name := range parts {
		if name == "" {
			continue
		}
		if name == ".." {
			unix.Close(fd)
			return -1, fmt.Errorf("%s: no .. allowed", dir)
		}
		next, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) && create {
			if merr := unix.Mkdirat(fd, name, uint32(mode.Perm())); merr != nil && !errors.Is(merr, unix.EEXIST) {
				unix.Close(fd)
				return -1, fmt.Errorf("create %s: %w", filepath.Join(walked, name), merr)
			}
			next, err = unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			// A symlink (or not a directory). Follow it only if root alone
			// could have made it.
			var st unix.Stat_t
			if serr := unix.Fstat(fd, &st); serr != nil || !trustedDir(&st) {
				unix.Close(fd)
				return -1, fmt.Errorf("%s: %w", filepath.Join(walked, name), ErrNotTrusted)
			}
			next, err = unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		}
		unix.Close(fd)
		if err != nil {
			return -1, &os.PathError{Op: "open", Path: filepath.Join(walked, name), Err: err}
		}
		fd = next
		walked = filepath.Join(walked, name)
	}
	return fd, nil
}

// fileTrusted checks an opened state file: a regular file root owns,
// nobody else can write and with no other names (a hard link hardyd made
// to one of root's files elsewhere on the dataset).
func fileTrusted(st *unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Uid == 0 && st.Mode&0o022 == 0 && st.Nlink == 1
}

// readAt opens name in dirfd without following a symlink and, under
// Enforce, checks the file it got.
func readAt(dirfd int, name, path string) ([]byte, error) {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ELOOP) {
		return nil, fmt.Errorf("%s: %w", path, ErrNotTrusted)
	}
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || (Enforce && !fileTrusted(&st)) {
		return nil, fmt.Errorf("%s: %w", path, ErrNotTrusted)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxStateBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxStateBytes {
		return nil, fmt.Errorf("%s is too large", path)
	}
	return b, nil
}

// ReadFile reads path if root wrote it (under Enforce): the file actually
// opened, never through a symlink, must be root's regular file with one
// name that only root can write.
func ReadFile(path string) ([]byte, error) {
	dir, name := filepath.Split(filepath.Clean(path))
	dfd, err := openDir(dir, false, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dfd)
	return readAt(dfd, name, path)
}

// ReadFileInRootDir is ReadFile for a file in one of root's own
// directories (RootStateDir): the directory opened must be root's and
// writable by root only too.
func ReadFileInRootDir(path string) ([]byte, error) {
	dir, name := filepath.Split(filepath.Clean(path))
	dfd, err := openDir(dir, false, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dfd)
	if Enforce {
		var st unix.Stat_t
		if err := unix.Fstat(dfd, &st); err != nil {
			return nil, err
		}
		if !trustedDir(&st) {
			return nil, fmt.Errorf("%s: %w", dir, ErrNotTrusted)
		}
	}
	return readAt(dfd, name, path)
}

// EnsureRootDir makes dir (and missing parents) and checks it's a real
// directory of root's that only root can write. Running as root, a
// directory someone else made (or chmodded) in its place is moved aside
// (renamed to "<dir>.untrusted-<time>", its content is never used) and a
// fresh one made. Not running as root (tests), the ownership isn't checked.
func EnsureRootDir(dir string, mode os.FileMode) error {
	fd, err := ensureRootDir(dir, mode)
	if err != nil {
		return err
	}
	unix.Close(fd)
	return nil
}

func ensureRootDir(dir string, mode os.FileMode) (int, error) {
	dir = filepath.Clean(dir)
	parent, name := filepath.Split(dir)
	pfd, err := openDir(parent, true, 0o755)
	if err != nil {
		return -1, err
	}
	defer unix.Close(pfd)
	for attempt := 0; attempt < 2; attempt++ {
		if err := unix.Mkdirat(pfd, name, uint32(mode.Perm())); err != nil && !errors.Is(err, unix.EEXIST) {
			return -1, fmt.Errorf("create %s: %w", dir, err)
		}
		fd, err := unix.Openat(pfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err == nil {
			var st unix.Stat_t
			if err := unix.Fstat(fd, &st); err != nil {
				unix.Close(fd)
				return -1, err
			}
			if os.Geteuid() != 0 || trustedDir(&st) {
				return fd, nil
			}
			unix.Close(fd)
		} else if !errors.Is(err, unix.ELOOP) && !errors.Is(err, unix.ENOTDIR) {
			return -1, &os.PathError{Op: "open", Path: dir, Err: err}
		}
		if os.Geteuid() != 0 {
			return -1, fmt.Errorf("%s: %w", dir, ErrNotTrusted)
		}
		// Not root's (or not a directory): move it out of the way.
		aside := fmt.Sprintf("%s.untrusted-%d", name, time.Now().UnixNano())
		if err := unix.Renameat(pfd, name, pfd, aside); err != nil {
			return -1, fmt.Errorf("move the untrusted %s aside: %w", dir, err)
		}
	}
	return -1, fmt.Errorf("%s: %w", dir, ErrNotTrusted)
}

// WriteAtomic writes data to path so a power cut leaves the old or the new
// file, never half of one, and never follows a link someone planted: the
// parent is opened without following untrusted symlinks (missing parents
// are made 0755), the content goes to a new file with a random name
// created with O_EXCL|O_NOFOLLOW, which is synced and renamed over path
// within that same directory. A symlink at path itself is replaced, not
// followed.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	dir, name := filepath.Split(filepath.Clean(path))
	dfd, err := openDir(dir, true, 0o755)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	return writeAt(dfd, name, path, data, mode)
}

// WriteInRootDir is WriteAtomic into one of root's own directories, which
// EnsureRootDir makes (with dirMode) and checks first.
func WriteInRootDir(path string, data []byte, mode, dirMode os.FileMode) error {
	dir, name := filepath.Split(filepath.Clean(path))
	dfd, err := ensureRootDir(dir, dirMode)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	return writeAt(dfd, name, path, data, mode)
}

func writeAt(dfd int, name, path string, data []byte, mode os.FileMode) error {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	tmp := "." + name + "." + hex.EncodeToString(b) + ".tmp"
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return &os.PathError{Op: "create", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), tmp)
	fail := func(err error) error {
		f.Close()
		_ = unix.Unlinkat(dfd, tmp, 0)
		return err
	}
	if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil { // umask
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return err
	}
	if err := unix.Renameat(dfd, tmp, dfd, name); err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return &os.PathError{Op: "rename", Path: path, Err: err}
	}
	_ = unix.Fsync(dfd)
	return nil
}

// CreateExclusive creates path (a new file, never through a symlink) in a
// directory of root's (made with dirMode) and writes data. It fails if
// anything is already at path.
func CreateExclusive(path string, data []byte, mode, dirMode os.FileMode) error {
	dir, name := filepath.Split(filepath.Clean(path))
	dfd, err := ensureRootDir(dir, dirMode)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	fd, err := unix.Openat(dfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return &os.PathError{Op: "create", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	_ = unix.Fchmod(fd, uint32(mode.Perm()))
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = unix.Unlinkat(dfd, name, 0)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = unix.Unlinkat(dfd, name, 0)
		return err
	}
	return f.Close()
}

// OpenRegular opens path for reading without following a symlink at its
// last component and checks it's a regular file of at most maxBytes.
func OpenRegular(path string, maxBytes int64) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%s: %w", path, ErrNotTrusted)
		}
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s isn't a regular file", path)
	}
	if maxBytes > 0 && fi.Size() > maxBytes {
		f.Close()
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxBytes)
	}
	return f, nil
}
