//go:build linux

package shares

import (
	"context"
	"fmt"

	"golang.org/x/sys/unix"
)

// FilesUID is the hardyos-files system user: HardyOS administrators (local
// accounts) read and write files in the File Manager as it, never as root
// (docs/plans/file-sharing.md section 3). Like an app, it gets read and
// write on every shared folder through ACL entries.
const FilesUID = 29999

// EnsureFilesUser gives hardyos-files read and write on every mounted
// shared folder that doesn't have it yet: the folder itself at once, and
// everything in it in the background (the same no-follow walker as app
// grants). Folders made since the last run and pools imported from another
// server are picked up; folders that already have the entry cost one
// getxattr. hardyd-priv runs it at start-up, every 10 minutes and before an
// administrator's folders are listed.
func (m *Manager) EnsureFilesUser(ctx context.Context) error {
	l, err := m.List(ctx)
	if err != nil {
		return err
	}
	var first error
	for _, sh := range l {
		if !sh.Usable() {
			continue
		}
		path := m.sys(sh.Path)
		if hasFilesUser(path, sh.RootDev) {
			continue
		}
		m.mu.Lock()
		err := m.checkRoot(&sh)
		if err == nil {
			err = m.setfacl(ctx, "-m", fmt.Sprintf("u:%d:rwX,d:u:%d:rwX", FilesUID, FilesUID), path)
		}
		m.mu.Unlock()
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		m.background(sh.ID, path, sh.RootDev, FilesUID, true, false)
		m.log().Info("hardyos-files given the shared folder", "share", sh.ID)
	}
	return first
}

// hasFilesUser: the folder's access and default ACLs both give
// hardyos-files rwx.
func hasFilesUser(path string, dev uint64) bool {
	fd, err := OpenRoot(path, dev, unix.O_RDONLY)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	for _, attr := range []string{xattrAccess, xattrDefault} {
		a, err := getACL(fd, attr)
		if err != nil {
			return false
		}
		ok := false
		for _, e := range a {
			if e.Tag == tagUser && e.ID == FilesUID && e.Perm == permR|permW|permX {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
