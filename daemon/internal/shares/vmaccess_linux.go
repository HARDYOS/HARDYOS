package shares

import (
	"errors"

	"golang.org/x/sys/unix"
)

// GrantReadFD gives uid read access (r, plus x on a folder) to the file or
// folder open at fd, with an access ACL entry. The VM engine uses it for
// the ISO library: QEMU reads installer discs as its own user, and libvirt
// is told not to take the files over (decision 122). fd must have been
// opened safely (OpenRoot, then openat2 beneath it), never by path.
func GrantReadFD(fd int, uid uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	mode := st.Mode & unix.S_IFMT
	if mode != unix.S_IFREG && mode != unix.S_IFDIR {
		return errors.New("only files and folders can be shared with VMs")
	}
	cur, err := getACL(fd, xattrAccess)
	if err != nil {
		return err
	}
	base := cur
	if base == nil {
		base = aclFromMode(st.Mode)
	}
	perm := uint16(permR)
	if mode == unix.S_IFDIR {
		perm |= permX
	}
	// Keep what the user already has (write, if a person's account is
	// also used for something else) and add read.
	for _, e := range base {
		if e.Tag == tagUser && e.ID == uid {
			perm |= e.Perm
		}
	}
	next := base.withUser(uid, perm)
	if cur != nil && next.equal(cur) {
		return nil
	}
	return setACL(fd, xattrAccess, next)
}
