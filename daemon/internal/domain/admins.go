package domain

import (
	"context"
	"errors"
	"strings"
)

// AdminsGroupName is the group HardyOS creates for people who administer
// the HardyOS desktop without being domain administrators.
const AdminsGroupName = "HardyOS Admins"

const adminsGroupDescription = "Administrators of the HardyOS desktop"

// AdminsGroupArgs sets up the HardyOS Admins group.
type AdminsGroupArgs struct {
	// Adopt records a group that already has the name, after an
	// administrator checked its members. Without it such a group is
	// refused: anyone allowed to create or rename groups could have made it.
	Adopt bool `json:"adopt"`
}

// AdminsGroup is the recorded HardyOS Admins group.
type AdminsGroup struct {
	Name    string   `json:"name"`
	SID     string   `json:"sid"`
	Members []string `json:"members"`
	// Created: HardyOS made the group just now; Adopted: an existing group
	// was recorded. Neither: it was already recorded.
	Created bool `json:"created"`
	Adopted bool `json:"adopted"`
}

// AdminsGroupExistsError refuses to record a group HardyOS didn't create
// without the administrator's say-so.
type AdminsGroupExistsError struct {
	Members []string
}

func (e *AdminsGroupExistsError) Error() string {
	who := "no members"
	if len(e.Members) > 0 {
		who = "members: " + strings.Join(e.Members, ", ")
	}
	return "a group called " + AdminsGroupName + " already exists (" + who + "); HardyOS didn't create it, so check who's in it and confirm to use it"
}

// FindAdminsGroup returns the group recorded as HardyOS Admins (by SID,
// whatever it's called now) and the group merely named HardyOS Admins, if
// any, from a group list.
func FindAdminsGroup(c *Config, groups []Group) (recorded, named *Group) {
	for i := range groups {
		g := &groups[i]
		if c != nil && c.AdminsGroupSID != "" && strings.EqualFold(g.SID, c.AdminsGroupSID) {
			recorded = g
		}
		if strings.EqualFold(g.Name, AdminsGroupName) {
			named = g
		}
	}
	return recorded, named
}

// SetUpAdminsGroup creates the HardyOS Admins group, or with a.Adopt
// records an existing group of that name, and keeps its SID in the domain's
// settings (and so in its backups). Desktop sign-in makes the group's
// members administrators by that SID. Already recorded: nothing changes.
func (m *Manager) SetUpAdminsGroup(ctx context.Context, a AdminsGroupArgs) (*AdminsGroup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.Load()
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, ErrNotProvisioned
	}
	groups, err := m.Groups(ctx)
	if err != nil {
		return nil, err
	}
	recorded, named := FindAdminsGroup(c, groups)
	if recorded != nil {
		return &AdminsGroup{Name: recorded.Name, SID: recorded.SID, Members: recorded.Members}, nil
	}
	out := &AdminsGroup{}
	switch {
	case named != nil && !a.Adopt:
		return nil, &AdminsGroupExistsError{Members: named.Members}
	case named != nil:
		if named.Builtin {
			return nil, invalid("%s is one of the domain's own groups; rename it back, or delete the group HardyOS should use and create it again", named.Name)
		}
		*out = AdminsGroup{Name: named.Name, SID: named.SID, Members: named.Members, Adopted: true}
	default:
		g, err := m.CreateGroup(ctx, NewGroup{Name: AdminsGroupName, Description: adminsGroupDescription})
		if err != nil {
			return nil, err
		}
		*out = AdminsGroup{Name: g.Name, SID: g.SID, Members: g.Members, Created: true}
	}
	if !strings.HasPrefix(out.SID, "S-1-5-21-") {
		return nil, errors.New("the domain helper didn't say what the group's SID is; update HardyOS")
	}
	if out.Members == nil {
		out.Members = []string{}
	}
	c.AdminsGroupSID = out.SID
	if err := m.save(c); err != nil {
		return nil, err
	}
	m.log().Info("domain: recorded the HardyOS Admins group", "name", out.Name, "sid", out.SID, "created", out.Created)
	return out, nil
}
