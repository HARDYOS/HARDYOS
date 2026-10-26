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

// SetPeopleRoot sets p's entries on the share's root folder (access and
// default ACL, and the root's "other" permission). changed is false when
// the root already had exactly them. root must be the verified mount on
// dev; it is opened with OpenRoot (no link followed anywhere).
func SetPeopleRoot(root string, dev uint64, p PeopleACL) (changed bool, err error) {
	fd, err := OpenRoot(root, dev, unix.O_RDONLY)
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false, err
	}
	return applyPeopleFD(fd, true, st.Mode, p, true)
}

// PeopleRootMatches reports whether the share's root already carries
// exactly p's entries (so nothing needs doing).
func PeopleRootMatches(root string, dev uint64, p PeopleACL) (bool, error) {
	fd, err := OpenRoot(root, dev, unix.O_RDONLY)
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false, err
	}
	cur, next, def, nextDef, err := peopleACLs(fd, true, st.Mode, p, true)
	if err != nil {
		return false, err
	}
	return cur != nil && next.equal(cur) && def != nil && nextDef.equal(def), nil
}

// ApplyPeopleTree sets p's entries on everything below root (not root
// itself, see SetPeopleRoot), with the same no-follow, one-file-system walk
// as app grants: every entry is opened relative to its parent folder with
// O_NOFOLLOW and changed through its file descriptor. The recycle bin and
// .zfs at the top are never entered: each person's bin stays theirs alone.
func ApplyPeopleTree(ctx context.Context, root string, dev uint64, p PeopleACL) (PeopleStats, error) {
	var st PeopleStats
	fd, err := OpenRoot(root, dev, unix.O_RDONLY)
	if err != nil {
		return st, err
	}
	var rs unix.Stat_t
	if err := unix.Fstat(fd, &rs); err != nil {
		unix.Close(fd)
		return st, err
	}
	w := &peopleWalker{ctx: ctx, dev: rs.Dev, p: p, st: &st}
	err = w.dir(fd, root, 0)
	return st, err
}

type peopleWalker struct {
	ctx context.Context
	dev uint64
	p   PeopleACL
	st  *PeopleStats
}

func (w *peopleWalker) fail(path string, err error) {
	w.st.Failed++
	if w.st.First == nil {
		w.st.First = fmt.Errorf("%s: %w", path, err)
	}
}

func (w *peopleWalker) dir(fd int, path string, depth int) error {
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

func (w *peopleWalker) entry(dirfd int, parent, name string, depth int) error {
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
			w.st.Skipped++
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
	changed, err := applyPeopleFD(fd, isDir, st2.Mode, w.p, false)
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
		return w.dir(fd, path, depth+1)
	}
	unix.Close(fd)
	return nil
}

// peopleACLs reads an entry's ACLs and works out what they should be.
func peopleACLs(fd int, isDir bool, mode uint32, p PeopleACL, root bool) (cur, next, def, nextDef acl, err error) {
	cur, err = getACL(fd, xattrAccess)
	if err != nil {
		return
	}
	base := cur
	if base == nil {
		base = aclFromMode(mode)
	}
	next = p.applyPeople(base, isDir, mode)
	if root {
		next = setOther(next, p.RootOther)
	}
	if !isDir {
		return
	}
	def, err = getACL(fd, xattrDefault)
	if err != nil {
		return
	}
	dbase := def
	if dbase == nil {
		for _, e := range next {
			if e.Tag == tagUserObj || e.Tag == tagGroupObj || e.Tag == tagOther {
				dbase = append(dbase, e)
			}
		}
	}
	nextDef = p.applyPeople(dbase, true, 0)
	if root {
		nextDef = setOther(nextDef, p.RootOther)
	}
	return
}

func applyPeopleFD(fd int, isDir bool, mode uint32, p PeopleACL, root bool) (bool, error) {
	cur, next, def, nextDef, err := peopleACLs(fd, isDir, mode, p, root)
	if err != nil {
		return false, err
	}
	changed := false
	if cur == nil && !next.hasNamed() && !root {
		// No ACL and none needed: the mode already says it all.
	} else if cur == nil || !next.equal(cur) {
		if err := setACL(fd, xattrAccess, next); err != nil {
			return false, err
		}
		changed = true
	}
	if !isDir {
		return changed, nil
	}
	if def != nil && nextDef.equal(def) {
		return changed, nil
	}
	if def == nil && !nextDef.hasNamed() && !root {
		return changed, nil // nothing to inherit; keep following the umask
	}
	return true, setACL(fd, xattrDefault, nextDef)
}
