package smb

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/shares"
)

// Built-in domain groups by name (winbind names, NETBIOS\name).
const (
	domainUsersGroup  = "Domain Users"
	domainAdminsGroup = "Domain Admins"
)

// shareLists is how a shared folder's access rules read in smb.conf.
type shareLists struct {
	Valid, Read, Write, Invalid []string
	// Skipped are rules that can't apply here (a HardyOS account or another
	// domain's name).
	Skipped []string
}

// ruleName turns a rule's name into this domain's spelling (HOME\alice),
// or "" when it isn't one of the domain's names.
func ruleName(nb, name string) string {
	pre, rest, ok := strings.Cut(name, `\`)
	if !ok || !strings.EqualFold(pre, nb) || rest == "" {
		return ""
	}
	return strings.ToUpper(nb) + `\` + rest
}

// mapLists turns access rules into Samba's user lists. Administrators
// (Domain Admins, and the HardyOS Admins group by SID when there is one)
// may always read and write. Everyone means the domain's users. Write wins
// over read in Samba's lists (the file system then applies a user's own
// rule over their groups', see shareACL); no access always wins.
func mapLists(nb string, rules []shares.Rule, guest bool, adminsSID string) shareLists {
	var l shareLists
	add := func(list *[]string, v string) {
		for _, x := range *list {
			if strings.EqualFold(x, v) {
				return
			}
		}
		*list = append(*list, v)
	}
	nb = strings.ToUpper(nb)
	admins := "@" + nb + `\` + domainAdminsGroup
	add(&l.Valid, admins)
	add(&l.Write, admins)
	if adminsSID != "" {
		add(&l.Valid, adminsSID)
		add(&l.Write, adminsSID)
	}
	for _, r := range rules {
		var n string
		switch r.Kind {
		case shares.KindEveryone:
			n = "@" + nb + `\` + domainUsersGroup
		case shares.KindGroup:
			if rn := ruleName(nb, r.Name); rn != "" {
				n = "@" + rn
			}
		case shares.KindUser:
			n = ruleName(nb, r.Name)
		}
		if n == "" {
			l.Skipped = append(l.Skipped, r.Name)
			continue
		}
		switch r.Level {
		case shares.LevelRead:
			add(&l.Valid, n)
			add(&l.Read, n)
		case shares.LevelWrite:
			add(&l.Valid, n)
			add(&l.Write, n)
		case shares.LevelNone:
			add(&l.Invalid, n)
		}
	}
	if guest {
		add(&l.Valid, "nobody")
		add(&l.Read, "nobody")
	}
	return l
}

// Resolver finds the Linux ID winbind gives a domain user or group.
type Resolver interface {
	UserID(name string) (uint32, error)
	GroupID(name string) (uint32, error)
	GroupIDBySID(sid string) (uint32, error)
}

// ErrUnknownName means winbind doesn't know the name (deleted, renamed).
type ErrUnknownName struct{ Name string }

func (e *ErrUnknownName) Error() string { return fmt.Sprintf("the domain has no %s", e.Name) }

// shareACL works out the POSIX ACL entries for a shared folder's rules,
// matching mapLists: write rwX, read r-X, a user with no access ---.
// Groups with no access can't be expressed in a POSIX ACL (any other
// group of the person's still lets them in); Samba's invalid users keeps
// them out over SMB. Names winbind doesn't know are skipped; any other
// lookup failure is returned (winbind down: change nothing).
func shareACL(nb string, rules []shares.Rule, guest bool, adminsSID string, r Resolver) (shares.PeopleACL, []string, error) {
	p := shares.PeopleACL{Managed: managedID, RootOther: 0}
	var skipped []string
	set := func(group bool, id uint32, level string) {
		for i, e := range p.Entries {
			if e.Group == group && e.ID == id {
				// The more generous of two rules for the same ID, except
				// that no access for a user always wins.
				if level == shares.LevelNone || (e.Level != shares.LevelNone && rank(level) > rank(e.Level)) {
					p.Entries[i].Level = level
				}
				return
			}
		}
		p.Entries = append(p.Entries, shares.PersonEntry{Group: group, ID: id, Level: level})
	}
	nb = strings.ToUpper(nb)
	gid, err := r.GroupID(nb + `\` + domainAdminsGroup)
	if err != nil {
		return p, nil, err
	}
	set(true, gid, shares.LevelWrite)
	if adminsSID != "" {
		if gid, err := r.GroupIDBySID(adminsSID); err == nil {
			set(true, gid, shares.LevelWrite)
		} else if !unknownName(err) {
			return p, nil, err
		}
	}
	for _, rule := range rules {
		var (
			id    uint32
			group bool
			err   error
		)
		switch rule.Kind {
		case shares.KindEveryone:
			group = true
			id, err = r.GroupID(nb + `\` + domainUsersGroup)
		case shares.KindGroup:
			n := ruleName(nb, rule.Name)
			if n == "" {
				skipped = append(skipped, rule.Name)
				continue
			}
			group = true
			id, err = r.GroupID(n)
		case shares.KindUser:
			n := ruleName(nb, rule.Name)
			if n == "" {
				skipped = append(skipped, rule.Name)
				continue
			}
			id, err = r.UserID(n)
		default:
			continue
		}
		if err != nil {
			if unknownName(err) {
				skipped = append(skipped, rule.Name)
				continue
			}
			return p, nil, err
		}
		if group && rule.Level == shares.LevelNone {
			continue
		}
		set(group, id, rule.Level)
	}
	if guest {
		set(false, NobodyUID, shares.LevelRead)
	}
	return p, skipped, nil
}

func rank(level string) int {
	switch level {
	case shares.LevelWrite:
		return 2
	case shares.LevelRead:
		return 1
	}
	return 0
}

// managedID: entries file sharing owns: domain IDs, the guest account and
// Samba's own range. Apps (30000-30999), NFS (31000-31999) and the file
// manager's user (29999) are someone else's.
func managedID(group bool, id uint32) bool {
	switch {
	case id >= IDMapDomainLow && id <= IDMapDomainHigh:
		return true
	case id >= IDMapDefaultLow && id <= IDMapDefaultHigh:
		return true
	case !group && id == NobodyUID:
		return true
	}
	return false
}

// aclHash identifies a set of entries (to tell whether a share's files
// already have them).
func aclHash(p shares.PeopleACL) string {
	b, _ := json.Marshal(struct {
		E []shares.PersonEntry
		O uint16
	}{p.Entries, p.RootOther})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}
