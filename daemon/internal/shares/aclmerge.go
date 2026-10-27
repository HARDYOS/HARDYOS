package shares

// Restoring files from a backup (internal/cloudbackup). A file's ACL in a
// backup holds two kinds of entries: people's and groups' (part of the
// files, restored as they were) and HardyOS's own (hardyos-files, apps'
// users, folders' NFS identities), which say who HardyOS lets in today and
// must never come back from an old version (decision 178): an app removed
// since, or an NFS export turned off, would get its access back.

// ManagedUID reports whether uid's ACL entries on shared folders are
// HardyOS's own (hardyos-files, an app's user, a folder's NFS identity).
func ManagedUID(uid uint32) bool {
	return uid == FilesUID || (uid >= firstAppUID && uid <= lastAppUID) || (uid >= FirstNFSUID && uid <= LastNFSUID)
}

// MergeRestoredACL is the ACL (an xattr value, nil for none) a restored
// file or folder gets: the backup's entries without HardyOS's own, plus
// HardyOS's own entries the destination has now (for a new file, those it
// inherited from its folder). backup and current are xattr values (nil:
// none); mode is the restored mode, the base when the backup has no ACL.
// isDefault: the folder's default ACL (no base from the mode).
func MergeRestoredACL(backup, current []byte, mode uint32, isDefault bool) ([]byte, error) {
	var b, c acl
	var err error
	if backup != nil {
		if b, err = decodeACL(backup); err != nil {
			return nil, err
		}
	}
	if current != nil {
		if c, err = decodeACL(current); err != nil {
			return nil, err
		}
	}
	if b == nil {
		if isDefault {
			// Defaults only from what HardyOS gives today, on the
			// current default's base entries.
			for _, e := range c {
				if e.Tag == tagUserObj || e.Tag == tagGroupObj || e.Tag == tagOther {
					b = append(b, e)
				}
			}
			if b == nil {
				b = aclFromMode(mode)
			}
		} else {
			b = aclFromMode(mode)
		}
	}
	out := make(acl, 0, len(b)+len(c))
	mask, hadMask := uint16(0), false
	for _, e := range b {
		if e.Tag == tagMask {
			mask, hadMask = e.Perm, true
		}
		if e.Tag == tagUser && ManagedUID(e.ID) {
			continue
		}
		out = append(out, e)
	}
	var added uint16
	for _, e := range c {
		if e.Tag == tagUser && ManagedUID(e.ID) {
			out = append(out, e)
			added |= e.Perm
		}
	}
	out = out.normalize()
	if hadMask {
		// The backup's mask stays (a narrower one than its entries is a
		// choice someone made), widened only for HardyOS's entries.
		if i := out.find(tagMask); i >= 0 {
			out[i].Perm = (mask | added) & out[i].Perm
		}
	}
	if !out.hasNamed() {
		if isDefault && backup != nil {
			return out.encode(), nil
		}
		return nil, nil
	}
	return out.encode(), nil
}
