//go:build linux

package smb

import (
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// cleanRecycleDir removes files from a shared folder's .recycle folder
// that went into it before cutoff (Samba sets their access time when it
// moves them there, recycle:touch), and folders left empty. People can
// write in the recycle bin, so everything is opened relative to its parent
// with O_NOFOLLOW and removed with unlinkat: a link swapped in can't make
// root delete anything outside it. It stays on the share's file system.
func cleanRecycleDir(share string, cutoff time.Time) (removed int, err error) {
	sfd, err := unix.Open(share, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(sfd)
	var st unix.Stat_t
	if err := unix.Fstat(sfd, &st); err != nil {
		return 0, err
	}
	fd, err := unix.Openat(sfd, ".recycle", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	c := &recycleCleaner{dev: st.Dev, cutoff: cutoff.Unix()}
	c.dir(fd, 0)
	return c.removed, nil
}

type recycleCleaner struct {
	dev     uint64
	cutoff  int64
	removed int
}

// dir cleans the directory open on fd (and closes it); it reports whether
// the directory is empty afterwards.
func (c *recycleCleaner) dir(fd int, depth int) bool {
	f := os.NewFile(uintptr(fd), ".recycle")
	defer f.Close()
	empty := true
	for {
		names, err := f.Readdirnames(512)
		for _, name := range names {
			if !c.entry(fd, name, depth) {
				empty = false
			}
		}
		if errors.Is(err, io.EOF) {
			return empty
		}
		if err != nil {
			return false
		}
	}
}

// entry handles one name; it reports whether it's gone.
func (c *recycleCleaner) entry(dirfd int, name string, depth int) bool {
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false
	}
	if st.Dev != c.dev {
		return false
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		if depth >= 128 {
			return false
		}
		// A folder moved into the bin whole (File Manager) keeps its files'
		// old times; its own ctime says when it arrived, so leave the whole
		// folder until that's old too. (Also true while Samba is still
		// adding to it: things stay longer, never shorter.)
		if st.Ctim.Sec >= c.cutoff {
			return false
		}
		fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return false
		}
		if !c.dir(fd, depth+1) {
			return false
		}
		// Only folders that have been there a while: Samba may be about to
		// move a file into a fresh one.
		if st.Mtim.Sec >= c.cutoff || st.Ctim.Sec >= c.cutoff {
			return false
		}
		return unix.Unlinkat(dirfd, name, unix.AT_REMOVEDIR) == nil
	default:
		// Files, links and the rest: the link itself is removed, never
		// what it points to.
		// When it went into the bin: Samba touches it (recycle:touch), and
		// a move into the bin (the File Manager keeps the file's own
		// modification time) changes its ctime.
		if st.Atim.Sec >= c.cutoff || st.Ctim.Sec >= c.cutoff {
			return false
		}
		if unix.Unlinkat(dirfd, name, 0) != nil {
			return false
		}
		c.removed++
		return true
	}
}
