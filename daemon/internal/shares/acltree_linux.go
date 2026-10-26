//go:build linux

package shares

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// maxTreeDepth bounds the walk (each level keeps one directory open).
const maxTreeDepth = 256

// applyTree gives uid access to everything below root, or takes it away
// (revoke), as both access and default ACL entries, like
// setfacl -R -P -m u:UID:rwX,d:u:UID:rwX. It never follows a symbolic link
// and never leaves root's file system: every entry is opened relative to its
// parent directory's file descriptor with O_NOFOLLOW and the ACL is changed
// through that descriptor. An app with write access to the share can't
// steer it elsewhere by swapping a folder for a link mid-walk, which a
// path-based tool would be open to. Root itself is left alone (the caller
// sets it). Devices, pipes and sockets are skipped, and so are the recycle
// bin and .zfs at the top. root must be the verified mount on dev
// (OpenRoot).
func applyTree(ctx context.Context, root string, dev uint64, uid int, write, revoke bool) (treeStats, error) {
	var st treeStats
	fd, err := OpenRoot(root, dev, unix.O_RDONLY)
	if err != nil {
		return st, err
	}
	var rs unix.Stat_t
	if err := unix.Fstat(fd, &rs); err != nil {
		unix.Close(fd)
		return st, err
	}
	w := &treeWalker{ctx: ctx, dev: rs.Dev, uid: uint32(uid), write: write, revoke: revoke, st: &st}
	err = w.dir(fd, root, 0)
	return st, err
}

type treeStats struct {
	Changed int   // files and folders whose ACL changed
	Seen    int   // files and folders looked at
	Skipped int   // links, devices, other file systems, too deep
	Failed  int   // entries that couldn't be changed
	First   error // the first per-entry error
}

type treeWalker struct {
	ctx    context.Context
	dev    uint64
	uid    uint32
	write  bool
	revoke bool
	st     *treeStats
}

func (w *treeWalker) fail(path string, err error) {
	w.st.Failed++
	if w.st.First == nil {
		w.st.First = fmt.Errorf("%s: %w", path, err)
	}
}

// dir walks the directory open on fd (and closes it).
func (w *treeWalker) dir(fd int, path string, depth int) error {
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	for {
		names, err := f.Readdirnames(512)
		for _, name := range names {
			if err := w.ctx.Err(); err != nil {
				return err
			}
			if ferr := w.entry(fd, path, name, depth); ferr != nil {
				return ferr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			w.fail(path, err)
			return nil
		}
	}
}

// entry handles one name in the directory open on dirfd. It only returns
// errors that should stop the whole walk.
func (w *treeWalker) entry(dirfd int, parent, name string, depth int) error {
	path := parent + "/" + name
	if skipAtTop(depth, name) {
		w.st.Skipped++
		return nil
	}
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		w.fail(path, err)
		return nil
	}
	typ := st.Mode & unix.S_IFMT
	if st.Dev != w.dev || (typ != unix.S_IFREG && typ != unix.S_IFDIR) {
		w.st.Skipped++
		return nil
	}
	isDir := typ == unix.S_IFDIR
	if isDir && depth+1 >= maxTreeDepth {
		w.st.Skipped++
		return nil
	}
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NOCTTY | unix.O_NONBLOCK
	if isDir {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat(dirfd, name, flags, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ENOENT) {
			w.st.Skipped++ // replaced by a link or removed since the stat
			return nil
		}
		w.fail(path, err)
		return nil
	}
	var st2 unix.Stat_t
	if err := unix.Fstat(fd, &st2); err != nil || st2.Ino != st.Ino || st2.Dev != st.Dev || st2.Mode&unix.S_IFMT != typ {
		unix.Close(fd)
		w.st.Skipped++
		return nil
	}
	w.st.Seen++
	changed, err := w.apply(fd, isDir, st2.Mode)
	if err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
			unix.Close(fd)
			return fmt.Errorf("this file system doesn't support ACLs (set acltype=posixacl): %w", err)
		}
		w.fail(path, err)
	}
	if changed {
		w.st.Changed++
	}
	if isDir {
		return w.dir(fd, path, depth+1) // closes fd
	}
	unix.Close(fd)
	return nil
}

func getACL(fd int, attr string) (acl, error) {
	buf := make([]byte, 256)
	for {
		n, err := unix.Fgetxattr(fd, attr, buf)
		if errors.Is(err, unix.ENODATA) {
			return nil, nil
		}
		if errors.Is(err, unix.ERANGE) {
			sz, err := unix.Fgetxattr(fd, attr, nil)
			if err != nil {
				return nil, err
			}
			buf = make([]byte, sz+64)
			continue
		}
		if err != nil {
			return nil, err
		}
		return decodeACL(buf[:n])
	}
}

func setACL(fd int, attr string, a acl) error { return unix.Fsetxattr(fd, attr, a.encode(), 0) }

func (w *treeWalker) apply(fd int, isDir bool, mode uint32) (bool, error) {
	changed := false
	cur, err := getACL(fd, xattrAccess)
	if err != nil {
		return false, err
	}
	if w.revoke {
		if cur != nil {
			if next, ok := cur.withoutUser(w.uid); ok {
				if err := setACL(fd, xattrAccess, next); err != nil {
					return false, err
				}
				changed = true
			}
		}
	} else {
		base := cur
		if base == nil {
			base = aclFromMode(mode)
		}
		next := base.withUser(w.uid, grantPerm(w.write, isDir, mode))
		if cur == nil || !next.equal(cur) {
			if err := setACL(fd, xattrAccess, next); err != nil {
				return false, err
			}
			changed = true
		}
		cur = next
	}
	if !isDir {
		return changed, nil
	}
	def, err := getACL(fd, xattrDefault)
	if err != nil {
		return changed, err
	}
	if w.revoke {
		if def == nil {
			return changed, nil
		}
		next, ok := def.withoutUser(w.uid)
		if !ok {
			return changed, nil
		}
		if !next.hasNamed() {
			// Only the base entries were left; drop the default ACL so new
			// files follow the umask again.
			if err := unix.Fremovexattr(fd, xattrDefault); err != nil && !errors.Is(err, unix.ENODATA) {
				return changed, err
			}
			return true, nil
		}
		return true, setACL(fd, xattrDefault, next)
	}
	base := def
	if base == nil {
		// Like setfacl: a new default ACL starts from the access ACL's
		// owner, group and other entries.
		for _, e := range cur {
			if e.Tag == tagUserObj || e.Tag == tagGroupObj || e.Tag == tagOther {
				base = append(base, e)
			}
		}
	}
	next := base.withUser(w.uid, grantPerm(w.write, true, 0))
	if def != nil && next.equal(def) {
		return changed, nil
	}
	return true, setACL(fd, xattrDefault, next)
}
