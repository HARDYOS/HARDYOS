package shares

// Access for people (domain users and groups, the guest account) as POSIX
// ACL entries, for file sharing. App grants (acltree_linux.go) give one
// app's user ID access; this sets a whole list of named entries at once and
// removes the ones file sharing put there before that aren't wanted any
// more. Entries outside Managed (apps, NFS identities, the file manager's
// user) are never touched.

import "sort"

// PersonEntry is one named ACL entry for a person or group.
type PersonEntry struct {
	Group bool   `json:"group"`
	ID    uint32 `json:"id"`
	// Level is read (r-X), write (rwX) or none (---, which denies a user
	// even when one of their groups may).
	Level string `json:"level"`
}

// PeopleACL is the set of named entries a shared folder should carry.
type PeopleACL struct {
	Entries []PersonEntry
	// Managed reports whether a named entry belongs to file sharing; such
	// entries not in Entries are removed.
	Managed func(group bool, id uint32) bool
	// RootOther is the "other" permission (0-7) set on the share's root
	// folder (access and default ACL). Below the root it is left alone.
	RootOther uint16
}

// PeopleStats summarises a walk.
type PeopleStats struct {
	Changed, Seen, Skipped, Failed int
	First                          error
}

func (p PeopleACL) sorted() []PersonEntry {
	out := append([]PersonEntry(nil), p.Entries...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Group != out[j].Group {
			return !out[i].Group
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func entryPerm(level string, dir bool, mode uint32) uint16 {
	switch level {
	case LevelWrite:
		return grantPerm(true, dir, mode)
	case LevelRead:
		return grantPerm(false, dir, mode)
	}
	return 0
}

// applyPeople returns a with the people entries set as wanted.
func (p PeopleACL) applyPeople(a acl, dir bool, mode uint32) acl {
	out := make(acl, 0, len(a)+len(p.Entries))
	for _, e := range a {
		if e.Tag == tagUser || e.Tag == tagGroup {
			if p.Managed != nil && p.Managed(e.Tag == tagGroup, e.ID) {
				continue
			}
			if p.wants(e.Tag == tagGroup, e.ID) {
				continue
			}
		}
		out = append(out, e)
	}
	for _, e := range p.sorted() {
		tag := uint16(tagUser)
		if e.Group {
			tag = tagGroup
		}
		out = append(out, aclEntry{Tag: tag, Perm: entryPerm(e.Level, dir, mode), ID: e.ID})
	}
	return out.normalize()
}

func (p PeopleACL) wants(group bool, id uint32) bool {
	for _, e := range p.Entries {
		if e.Group == group && e.ID == id {
			return true
		}
	}
	return false
}

func setOther(a acl, perm uint16) acl {
	out := append(acl{}, a...)
	if i := out.find(tagOther); i >= 0 {
		out[i].Perm = perm
	}
	return out
}
