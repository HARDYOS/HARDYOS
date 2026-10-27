package domain

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// User is a domain account.
type User struct {
	Username           string   `json:"username"`
	GivenName          string   `json:"givenName"`
	Surname            string   `json:"surname"`
	DisplayName        string   `json:"displayName"`
	Email              string   `json:"email"`
	Enabled            bool     `json:"enabled"`
	LockedOut          bool     `json:"lockedOut"`
	MustChangePassword bool     `json:"mustChangePassword"`
	Groups             []string `json:"groups"`
	Created            string   `json:"created"`
	LastLogon          int64    `json:"lastLogon"` // unix seconds, 0 = never
	Builtin            bool     `json:"builtin"`
}

// Group is a domain security group.
type Group struct {
	Name string `json:"name"`
	// SID is the group's objectSid; it stays the same when it's renamed.
	SID         string   `json:"sid"`
	Description string   `json:"description"`
	Members     []string `json:"members"`
	Builtin     bool     `json:"builtin"`
}

// NewUser creates an account.
type NewUser struct {
	Username           string   `json:"username"`
	GivenName          string   `json:"givenName,omitempty"`
	Surname            string   `json:"surname,omitempty"`
	Email              string   `json:"email,omitempty"`
	Password           string   `json:"password"`
	MustChangePassword bool     `json:"mustChangePassword"`
	Groups             []string `json:"groups,omitempty"`
}

// UserUpdate changes an account's details; nil fields stay as they are.
type UserUpdate struct {
	Username  string  `json:"username"`
	GivenName *string `json:"givenName,omitempty"`
	Surname   *string `json:"surname,omitempty"`
	Email     *string `json:"email,omitempty"`
}

// PasswordReset sets a new password.
type PasswordReset struct {
	Username           string `json:"username"`
	Password           string `json:"password"`
	MustChangePassword bool   `json:"mustChangePassword"`
}

// NewGroup creates a group.
type NewGroup struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members,omitempty"`
}

// GroupUpdate changes a group; Description nil leaves it.
type GroupUpdate struct {
	Name        string   `json:"name"`
	Description *string  `json:"description,omitempty"`
	Add         []string `json:"add,omitempty"`
	Remove      []string `json:"remove,omitempty"`
}

// admin runs the directory helper with args on stdin. Its exit status 1
// means the request can't be done (a user-fixable problem).
func (m *Manager) admin(ctx context.Context, cmd string, args any, out any) error {
	in, err := json.Marshal(args)
	if err != nil {
		return err
	}
	res, err := m.Runner.Run(ctx, in, AdminTool, m.SmbConf(), cmd)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(string(res.Stderr))
		if msg == "" {
			msg = "the domain helper failed"
		}
		if i := strings.LastIndex(msg, "\n"); i >= 0 && res.ExitCode != 1 {
			msg = msg[i+1:] // a traceback: its last line says what went wrong
		}
		if res.ExitCode == 1 {
			return invalid("%s", msg)
		}
		return fmt.Errorf("domain helper: %s", msg)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(res.Stdout, out); err != nil {
		return fmt.Errorf("reading the domain helper's answer: %w", err)
	}
	return nil
}

func (m *Manager) ready() error {
	c, err := m.Load()
	if err != nil {
		return err
	}
	if c == nil {
		return ErrNotProvisioned
	}
	return nil
}

// Users lists the domain's accounts.
func (m *Manager) Users(ctx context.Context) ([]User, error) {
	if err := m.ready(); err != nil {
		return nil, err
	}
	var out struct {
		Users []User `json:"users"`
	}
	if err := m.admin(ctx, "users", map[string]any{}, &out); err != nil {
		return nil, err
	}
	for i := range out.Users {
		if out.Users[i].Groups == nil {
			out.Users[i].Groups = []string{}
		}
	}
	return out.Users, nil
}

// Groups lists the domain's groups.
func (m *Manager) Groups(ctx context.Context) ([]Group, error) {
	if err := m.ready(); err != nil {
		return nil, err
	}
	var out struct {
		Groups []Group `json:"groups"`
	}
	if err := m.admin(ctx, "groups", map[string]any{}, &out); err != nil {
		return nil, err
	}
	for i := range out.Groups {
		if out.Groups[i].Members == nil {
			out.Groups[i].Members = []string{}
		}
	}
	return out.Groups, nil
}

func checkNames(names []string, check func(string) error) error {
	for _, n := range names {
		if err := check(n); err != nil {
			return err
		}
	}
	return nil
}

func cleanName(s string) string { return strings.TrimSpace(s) }

// UserGroups is what desktop sign-in needs about one account.
type UserGroups struct {
	// Exists is false when there's no such user (then nothing else is set).
	Exists      bool   `json:"exists"`
	Username    string `json:"username"` // as the directory spells it
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Enabled     bool   `json:"enabled"`
	LockedOut   bool   `json:"lockedOut"`
	// Expired: the account (not its password) has passed its expiry date.
	Expired            bool `json:"expired"`
	MustChangePassword bool `json:"mustChangePassword"`
	// Groups are every domain group the user is in, nested ones and the
	// primary group (Domain Users) included, without the domain prefix.
	Groups []string `json:"groups"`
	// DomainSID is the domain's SID; GroupSIDs are the objectSids of the
	// same groups (tokenGroups). The desktop role is decided by these, never
	// by the names.
	DomainSID string   `json:"domainSid"`
	GroupSIDs []string `json:"groupSids"`
	// SID and ObjectGUID identify the account itself. The GUID never
	// changes, not on a rename either: HardyOS's sign-in provider (OIDC)
	// uses it as the account's stable subject. Empty from an older helper.
	SID        string `json:"sid"`
	ObjectGUID string `json:"objectGuid"`
}

// UserGroups looks up an account's state and groups for sign-in.
func (m *Manager) UserGroups(ctx context.Context, username string) (*UserGroups, error) {
	if err := m.ready(); err != nil {
		return nil, err
	}
	username = cleanName(username)
	if err := CheckUsername(username); err != nil {
		return nil, err
	}
	var out UserGroups
	if err := m.admin(ctx, "user.groups", map[string]any{"username": username}, &out); err != nil {
		return nil, err
	}
	if out.Groups == nil {
		out.Groups = []string{}
	}
	if out.GroupSIDs == nil {
		out.GroupSIDs = []string{}
	}
	return &out, nil
}

// CreateUser adds an account.
func (m *Manager) CreateUser(ctx context.Context, u NewUser) (*User, error) {
	if err := m.ready(); err != nil {
		return nil, err
	}
	u.Username = cleanName(u.Username)
	if err := CheckUsername(u.Username); err != nil {
		return nil, err
	}
	if err := CheckPassword(u.Password, u.Username); err != nil {
		return nil, err
	}
	if err := checkNames(u.Groups, CheckGroupName); err != nil {
		return nil, err
	}
	if len(u.GivenName) > 64 || len(u.Surname) > 64 || len(u.Email) > 256 {
		return nil, invalid("names are 64 characters at most")
	}
	if u.Email != "" && !strings.Contains(u.Email, "@") {
		return nil, invalid("%q isn't an email address", u.Email)
	}
	var out User
	if err := m.admin(ctx, "user.create", u, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateUser changes an account's name or email.
func (m *Manager) UpdateUser(ctx context.Context, u UserUpdate) (*User, error) {
	if err := m.ready(); err != nil {
		return nil, err
	}
	if err := CheckUsername(u.Username); err != nil {
		return nil, err
	}
	for _, p := range []*string{u.GivenName, u.Surname} {
		if p != nil && len(*p) > 64 {
			return nil, invalid("names are 64 characters at most")
		}
	}
	if u.Email != nil && *u.Email != "" && !strings.Contains(*u.Email, "@") {
		return nil, invalid("%q isn't an email address", *u.Email)
	}
	var out User
	if err := m.admin(ctx, "user.update", u, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ResetPassword sets an account's password (and clears a lockout).
func (m *Manager) ResetPassword(ctx context.Context, p PasswordReset) (*User, error) {
	if err := m.ready(); err != nil {
		return nil, err
	}
	if err := CheckUsername(p.Username); err != nil {
		return nil, err
	}
	if err := CheckPassword(p.Password, p.Username); err != nil {
		return nil, err
	}
	var out User
	if err := m.admin(ctx, "user.password", p, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetUserEnabled turns an account on or off.
func (m *Manager) SetUserEnabled(ctx context.Context, username string, on bool) (*User, error) {
	if err := m.ready(); err != nil {
		return nil, err
	}
	if err := CheckUsername(username); err != nil {
		return nil, err
	}
	var out User
	if err := m.admin(ctx, "user.enable", map[string]any{"username": username, "enabled": on}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteUser removes an account.
func (m *Manager) DeleteUser(ctx context.Context, username string) error {
	if err := m.ready(); err != nil {
		return err
	}
	if err := CheckUsername(username); err != nil {
		return err
	}
	return m.admin(ctx, "user.delete", map[string]any{"username": username}, nil)
}

// CreateGroup adds a group.
func (m *Manager) CreateGroup(ctx context.Context, g NewGroup) (*Group, error) {
	if err := m.ready(); err != nil {
		return nil, err
	}
	g.Name = cleanName(g.Name)
	if err := CheckGroupName(g.Name); err != nil {
		return nil, err
	}
	if err := checkNames(g.Members, CheckUsername); err != nil {
		return nil, err
	}
	if len(g.Description) > 256 {
		return nil, invalid("the description is too long")
	}
	var out Group
	if err := m.admin(ctx, "group.create", g, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateGroup changes a group's description or members.
func (m *Manager) UpdateGroup(ctx context.Context, g GroupUpdate) (*Group, error) {
	if err := m.ready(); err != nil {
		return nil, err
	}
	if err := CheckGroupName(g.Name); err != nil {
		return nil, err
	}
	if err := checkNames(append(append([]string{}, g.Add...), g.Remove...), CheckUsername); err != nil {
		return nil, err
	}
	if g.Description != nil && len(*g.Description) > 256 {
		return nil, invalid("the description is too long")
	}
	var out Group
	if err := m.admin(ctx, "group.update", g, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteGroup removes a group (not its members).
func (m *Manager) DeleteGroup(ctx context.Context, name string) error {
	if err := m.ready(); err != nil {
		return err
	}
	if err := CheckGroupName(name); err != nil {
		return err
	}
	return m.admin(ctx, "group.delete", map[string]any{"name": name}, nil)
}
