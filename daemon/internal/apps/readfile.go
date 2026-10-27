package apps

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// MaxStateFileBytes bounds every file root reads from an app's dataset
// (state, manifest, settings, compose files, package, icon).
const MaxStateFileBytes = 4 << 20

// readStateFile reads a file of an app's dataset as root without trusting
// what's there: a dataset can come from another server (a restore) or an
// imported pool. No component of the path may be a symlink, the file must
// be regular (opened non-blocking, so a FIFO can't hang hardyd-priv), and
// at most MaxStateFileBytes are read. A missing file gives fs.ErrNotExist.
func readStateFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		path = abs
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for i, name := range parts {
		last := i == len(parts)-1
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if last {
			flags |= unix.O_NONBLOCK
		} else {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, name, flags, 0)
		unix.Close(fd)
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil, fmt.Errorf("%s: a link or something else where a %s should be", path, map[bool]string{true: "file", false: "folder"}[last])
		}
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: path, Err: err}
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s isn't a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxStateFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxStateFileBytes {
		return nil, fmt.Errorf("%s is too large", path)
	}
	return b, nil
}
