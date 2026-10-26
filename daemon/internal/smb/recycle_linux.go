//go:build linux

package smb

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"golang.org/x/sys/unix"
)

// quarantinePrefix starts the name a bin that wasn't its owner's is moved
// aside to (hidden from SMB by "veto files = /.hardyos*/", and from the File
// Manager).
const quarantinePrefix = ".hardyos-quarantine-"

// cleanRecycleDir removes files from a shared folder's .recycle folder
// that went into it before cutoff (Samba sets their access time when it
// moves them there, recycle:touch), and folders left empty. People can
// write in the recycle bin, so everything is opened relative to its parent
// with O_NOFOLLOW and removed with unlinkat: a link swapped in can't make
// root delete anything outside it. It stays on the share's file system,
// and the share must be its verified mount on dev.
func cleanRecycleDir(share string, dev uint64, cutoff time.Time) (removed int, err error) {
	sfd, err := shares.OpenRoot(share, dev, unix.O_RDONLY)
	if err != nil {
		return 0, err
	}
	defer unix.Close(sfd)
	var st unix.Stat_t
	if err := unix.Fstat(sfd, &st); err != nil {
		return 0, err
	}
	fd, err := unix.Openat(sfd, shares.RecycleDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var rst unix.Stat_t
	if err := unix.Fstat(fd, &rst); err != nil || rst.Dev != st.Dev {
		unix.Close(fd)
		return 0, fmt.Errorf("%s/.recycle is another file system", share)
	}
	c := &recycleCleaner{dev: st.Dev, cutoff: cutoff.Unix()}
	c.dir(fd, 0)
	return c.removed, nil
}

type recycleCleaner struct {
	dev     uint64
	cutoff  int64
	removed int
	// beforeOpen runs between looking at a folder and opening it (tests
	// swap the folder there).
	beforeOpen func(dirfd int, name string)
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
		if c.beforeOpen != nil {
			c.beforeOpen(dirfd, name)
		}
		fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return false
		}
		// The folder opened must be the one looked at: someone with write
		// access to the bin may have swapped another in since the lstat
		// (a newer folder, or one moved in from elsewhere). Its times are
		// read again from the descriptor.
		var fst unix.Stat_t
		if err := unix.Fstat(fd, &fst); err != nil || fst.Dev != st.Dev || fst.Ino != st.Ino ||
			fst.Mode&unix.S_IFMT != unix.S_IFDIR || fst.Ctim.Sec >= c.cutoff {
			unix.Close(fd)
			return false
		}
		if !c.dir(fd, depth+1) {
			return false
		}
		// Only folders that have been there a while: Samba may be about to
		// move a file into a fresh one.
		if fst.Mtim.Sec >= c.cutoff || fst.Ctim.Sec >= c.cutoff {
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

// ensureRecycle keeps a shared folder's recycle bin safe: .recycle root's,
// 1777, without ACL entries (shares.EnsureRecycle), and each bin in it its
// owner's alone (checkBins).
func (m *Manager) ensureRecycle(dom *Domain, sh shares.Share, names Resolver) {
	fd, err := shares.OpenRoot(sh.Path, sh.RootDev, unix.O_PATH)
	if err != nil {
		m.log().Warn("recycle bin: the shared folder can't be opened", "share", sh.ID, "err", err)
		return
	}
	defer unix.Close(fd)
	fixed, err := shares.EnsureRecycle(fd)
	switch {
	case slices.Contains(fixed, "owner"):
		m.log().Warn("recycle bin belonged to someone else; given back to root", "share", sh.ID, "fixed", fixed)
	case len(fixed) > 0:
		m.log().Info("recycle bin set up", "share", sh.ID, "fixed", fixed)
	}
	if err != nil {
		m.log().Warn("recycle bin can't be used", "share", sh.ID, "err", err)
		return
	}
	m.checkBins(fd, dom.NetBIOS, names, sh.ID)
}

// maxBins bounds one check of a shared folder's bins.
const maxBins = 100000

// checkBins looks at every bin in .recycle that belongs to someone by name
// (<netbios>.<user> in any case, as Samba's %U writes it, and
// hardyos-files): one that isn't a folder owned by that account (anyone may
// make folders in .recycle, so someone could make another person's bin to
// collect what they delete) is moved aside and locked (root's, 0700); one
// that's its owner's but open to others is closed up (0700, no ACLs).
func (m *Manager) checkBins(rootfd int, netbios string, names Resolver, share string) {
	rfd, err := unix.Openat(rootfd, shares.RecycleDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	f := os.NewFile(uintptr(rfd), shares.RecycleDir)
	defer f.Close()
	list, _ := f.Readdirnames(maxBins)
	prefix := strings.ToLower(netbios) + "."
	for _, n := range list {
		var want uint32
		switch {
		case n == shares.FilesBin:
			want = shares.FilesUID
		case strings.HasPrefix(strings.ToLower(n), prefix) && len(n) > len(prefix):
			uid, err := names.UserID(strings.ToUpper(netbios) + `\` + n[len(prefix):])
			if unknownName(err) {
				continue // a removed account's bin: emptied as it ages
			}
			if err != nil {
				m.log().Warn("recycle bins not checked: the domain's names can't be looked up", "share", share, "err", err)
				return
			}
			want = uid
		default:
			continue
		}
		m.checkBin(rfd, n, want, share)
	}
}

func (m *Manager) checkBin(rfd int, name string, uid uint32, share string) {
	var st unix.Stat_t
	if err := unix.Fstatat(rfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uid {
		m.quarantine(rfd, name, share, fmt.Sprintf("owned by %d (mode %o), not by %d", st.Uid, st.Mode, uid))
		return
	}
	fd, err := unix.Openat(rfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	var fst unix.Stat_t
	if unix.Fstat(fd, &fst) != nil || fst.Ino != st.Ino || fst.Dev != st.Dev {
		return
	}
	if _, err := shares.CheckBin(fd, uid); err != nil {
		if terr := shares.TightenBin(fd); terr != nil {
			m.log().Warn("recycle bin is open to others and can't be closed up", "share", share, "bin", name, "err", terr)
			return
		}
		m.log().Info("recycle bin closed up to its owner only", "share", share, "bin", name, "was", err)
	}
}

// quarantine moves a bin that isn't its owner's out of the way (so the
// owner's next delete makes a real one) and locks it.
func (m *Manager) quarantine(rfd int, name, share, why string) {
	q := fmt.Sprintf("%s%d-%s", quarantinePrefix, time.Now().Unix(), name)
	if len(q) > 255 {
		q = q[:255]
	}
	if err := unix.Renameat2(rfd, name, rfd, q, unix.RENAME_NOREPLACE); err != nil {
		m.log().Warn("recycle bin isn't its owner's and can't be moved aside", "share", share, "bin", name, "why", why, "err", err)
		return
	}
	if fd, err := unix.Openat(rfd, q, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0); err == nil {
		_ = unix.Fchown(fd, os.Geteuid(), os.Getegid())
		_ = shares.TightenBin(fd)
		unix.Close(fd)
	}
	m.log().Warn("recycle bin wasn't its owner's; moved aside and locked", "share", share, "bin", name, "why", why, "now", q)
}
