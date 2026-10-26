package shares

// Access for a shared folder's NFS identity (internal/nfs). Every NFS
// client of a folder is squashed to one user ID from 31000-31999 that only
// that folder uses; it is given access on disk exactly like an app's user
// (POSIX ACL entries, the root at once, everything below in the background
// walker), but isn't recorded in org.hardyos:apps: the ID is kept in
// PropNFSUID.

import (
	"context"
	"fmt"
)

// PropNFSUID holds the folder's NFS user (and group) ID.
const PropNFSUID = "org.hardyos:nfs-uid"

// NFS user IDs.
const (
	FirstNFSUID = 31000
	LastNFSUID  = 31999
)

// ValidNFSUID checks an NFS user ID.
func ValidNFSUID(uid int) error {
	if uid < FirstNFSUID || uid > LastNFSUID {
		return invalid("NFS user ID %d is outside %d-%d", uid, FirstNFSUID, LastNFSUID)
	}
	return nil
}

// GrantNFS gives a folder's NFS user ID read (r-X) or write (rwX) access:
// access and default ACL entries on the folder now, on everything in it in
// the background. Granting again with another level replaces the entries.
func (m *Manager) GrantNFS(ctx context.Context, id string, uid int, write bool) error {
	return m.nfsACL(ctx, id, uid, write, false)
}

// RevokeNFS takes a folder's NFS user ID's entries away again.
func (m *Manager) RevokeNFS(ctx context.Context, id string, uid int) error {
	return m.nfsACL(ctx, id, uid, false, true)
}

func (m *Manager) nfsACL(ctx context.Context, id string, uid int, write, revoke bool) error {
	if err := ValidNFSUID(uid); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sh, err := m.Get(ctx, id)
	if err != nil {
		return err
	}
	if !sh.Mounted {
		return fmt.Errorf("the shared folder %s isn't available right now (is its pool imported and unlocked?)", sh.Name)
	}
	path := m.sys(sh.Path)
	if revoke {
		if err := m.setfacl(ctx, "-x", fmt.Sprintf("u:%d,d:u:%d", uid, uid), path); err != nil {
			return err
		}
	} else {
		perm := aclPerm(write)
		if err := m.setfacl(ctx, "-m", fmt.Sprintf("u:%d:%s,d:u:%d:%s", uid, perm, uid, perm), path); err != nil {
			return err
		}
	}
	m.background(sh.ID, path, uid, write, revoke)
	m.log().Info("shared folder NFS access", "share", sh.ID, "uid", uid, "write", write, "revoke", revoke)
	return nil
}
