package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Role is a user's permission level.
type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool { return r == RoleAdmin || r == RoleUser }

// Where an account comes from.
const (
	SourceLocal  = "local"
	SourceDomain = "domain"
)

// User is a HardyOS account: a local one, or a domain account that signed
// in to the desktop (see SignIn).
type User struct {
	ID          int64      `json:"id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"displayName"`
	Email       string     `json:"email"`
	Role        Role       `json:"role"`
	Disabled    bool       `json:"disabled"`
	BreakGlass  bool       `json:"breakGlass"`
	CreatedAt   time.Time  `json:"createdAt"`
	LastLoginAt *time.Time `json:"lastLoginAt"`
	// Source is SourceLocal or SourceDomain.
	Source string `json:"source"`
	// Principal is how access rules name this user: the username for local
	// accounts, NETBIOS\name for domain accounts (equal to Username).
	Principal string `json:"principal"`
	// Groups are a domain account's groups as NETBIOS\group, Domain Users
	// included; empty for local accounts.
	Groups []string `json:"groups"`

	passwordHash    string
	groupsCheckedAt time.Time
}

// IsAdmin reports whether the user may change system settings.
func (u *User) IsAdmin() bool { return u != nil && u.Role == RoleAdmin && !u.Disabled }

// Errors returned by the user store.
var (
	ErrUserExists     = errors.New("a user with that name already exists")
	ErrInvalidName    = errors.New("username must be 2-32 characters: lowercase letters, digits, '.', '-' or '_', starting with a letter")
	ErrLastAdmin      = errors.New("can't remove or demote the last active administrator")
	ErrBadCredentials = errors.New("incorrect username or password")
	ErrInvalidRole    = errors.New("role must be admin or user")
	// ErrDomainManaged refuses changes the domain owns: a domain account's
	// password, role, name and email.
	ErrDomainManaged = errors.New("this is a domain account: its password, name and groups are managed in Control Panel > Domain > Users")
)

var usernameRE = regexp.MustCompile(`^[a-z][a-z0-9._-]{1,31}$`)

// reservedNames can't be used because they clash with system accounts.
var reservedNames = map[string]bool{
	"root": true, "hardyd": true, "daemon": true, "nobody": true, "bin": true, "sys": true,
	"admin": false, // allowed: a common first-account name
}

// NormalizeUsername lowercases and validates a username.
func NormalizeUsername(name string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if !usernameRE.MatchString(n) || reservedNames[n] {
		return "", ErrInvalidName
	}
	return n, nil
}

// Users reads and writes accounts.
type Users struct{ DB *store.DB }

// NewUser holds the fields for creating an account.
type NewUser struct {
	Username    string
	DisplayName string
	Email       string
	Role        Role
	Password    string
	BreakGlass  bool
}

const userCols = `id, username, display_name, email, role, password_hash, disabled, break_glass, created_at, last_login_at, source, groups, groups_checked_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var created, groups string
	var lastLogin, groupsChecked sql.NullString
	var disabled, breakGlass int
	if err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Role, &u.passwordHash,
		&disabled, &breakGlass, &created, &lastLogin, &u.Source, &groups, &groupsChecked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	u.Disabled = disabled != 0
	u.BreakGlass = breakGlass != 0
	u.CreatedAt = store.ParseTime(created)
	if lastLogin.Valid {
		t := store.ParseTime(lastLogin.String)
		u.LastLoginAt = &t
	}
	u.Principal = u.Username
	u.Groups = []string{}
	if u.Source == SourceDomain {
		_ = json.Unmarshal([]byte(groups), &u.Groups)
		if u.Groups == nil {
			u.Groups = []string{}
		}
		if groupsChecked.Valid {
			u.groupsCheckedAt = store.ParseTime(groupsChecked.String)
		}
	}
	return &u, nil
}

// Count returns the number of local accounts. Domain accounts that signed in
// don't count: setup is about the first local administrator.
func (s *Users) Count(ctx context.Context) (int, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE source = 'local'`).Scan(&n)
	return n, err
}

// Create adds an account.
func (s *Users) Create(ctx context.Context, nu NewUser) (*User, error) {
	name, err := NormalizeUsername(nu.Username)
	if err != nil {
		return nil, err
	}
	if !nu.Role.Valid() {
		return nil, ErrInvalidRole
	}
	if err := ValidatePassword(nu.Password); err != nil {
		return nil, err
	}
	hash, err := HashPassword(nu.Password)
	if err != nil {
		return nil, err
	}
	return s.insert(ctx, name, nu, hash)
}

// CreateHashed adds an account whose password was hashed elsewhere (the
// installer hashes it before the system exists). nu.Password is ignored.
func (s *Users) CreateHashed(ctx context.Context, nu NewUser, hash string) (*User, error) {
	name, err := NormalizeUsername(nu.Username)
	if err != nil {
		return nil, err
	}
	if !nu.Role.Valid() {
		return nil, ErrInvalidRole
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		return nil, errors.New("unsupported password hash")
	}
	return s.insert(ctx, name, nu, hash)
}

func (s *Users) insert(ctx context.Context, name string, nu NewUser, hash string) (*User, error) {
	now := store.Now()
	res, err := s.DB.ExecContext(ctx, `INSERT INTO users
		(username, display_name, email, role, password_hash, break_glass, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		name, strings.TrimSpace(nu.DisplayName), strings.TrimSpace(nu.Email), nu.Role, hash, boolInt(nu.BreakGlass), now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, ErrUserExists
		}
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.Get(ctx, id)
}

// Get returns the account with the given ID.
func (s *Users) Get(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.DB.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// GetByName returns the account with the given username (for a domain
// account, its principal).
func (s *Users) GetByName(ctx context.Context, name string) (*User, error) {
	return scanUser(s.DB.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`, strings.ToLower(strings.TrimSpace(name))))
}

// List returns all accounts ordered by username: local ones, then domain
// accounts that have signed in.
func (s *Users) List(ctx context.Context) ([]*User, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY source = 'domain', username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UserUpdate holds optional changes to an account. Nil fields are left alone.
type UserUpdate struct {
	DisplayName *string
	Email       *string
	Role        *Role
	Disabled    *bool
}

// Update applies changes, refusing any that would leave no active admin. Of
// a domain account only Disabled (a HardyOS-side switch) can change; the
// rest comes from the domain and ErrDomainManaged is returned.
func (s *Users) Update(ctx context.Context, id int64, up UserUpdate) (*User, error) {
	u, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if up.Role != nil && !up.Role.Valid() {
		return nil, ErrInvalidRole
	}
	if u.Source == SourceDomain {
		changed := func(p *string, cur string) bool { return p != nil && strings.TrimSpace(*p) != cur }
		if changed(up.DisplayName, u.DisplayName) || changed(up.Email, u.Email) || (up.Role != nil && *up.Role != u.Role) {
			return nil, ErrDomainManaged
		}
		up.DisplayName, up.Email, up.Role = nil, nil, nil
	}
	losesAdmin := u.Source == SourceLocal && u.IsAdmin() &&
		((up.Role != nil && *up.Role != RoleAdmin) || (up.Disabled != nil && *up.Disabled))
	if losesAdmin {
		if err := s.ensureOtherAdmin(ctx, id); err != nil {
			return nil, err
		}
	}
	if up.DisplayName != nil {
		u.DisplayName = strings.TrimSpace(*up.DisplayName)
	}
	if up.Email != nil {
		u.Email = strings.TrimSpace(*up.Email)
	}
	if up.Role != nil {
		u.Role = *up.Role
	}
	if up.Disabled != nil {
		u.Disabled = *up.Disabled
	}
	_, err = s.DB.ExecContext(ctx, `UPDATE users SET display_name = ?, email = ?, role = ?, disabled = ?, updated_at = ? WHERE id = ?`,
		u.DisplayName, u.Email, u.Role, boolInt(u.Disabled), store.Now(), id)
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// SetPassword replaces a local account's password. A domain account's
// password lives in the domain: ErrDomainManaged.
func (s *Users) SetPassword(ctx context.Context, id int64, pw string) error {
	u, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if u.Source != SourceLocal {
		return ErrDomainManaged
	}
	if err := ValidatePassword(pw); err != nil {
		return err
	}
	hash, err := HashPassword(pw)
	if err != nil {
		return err
	}
	res, err := s.DB.ExecContext(ctx, `UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ? AND source = 'local'`, hash, store.Now(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// Delete removes an account, refusing to remove the last active admin. For
// a domain account this only forgets it here (and signs it out); it can
// sign in again while the domain allows it.
func (s *Users) Delete(ctx context.Context, id int64) error {
	u, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if u.Source == SourceLocal && u.IsAdmin() {
		if err := s.ensureOtherAdmin(ctx, id); err != nil {
			return err
		}
	}
	_, err = s.DB.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

// ensureOtherAdmin checks that a local administrator remains. Domain
// administrators don't count: the domain can take their role away, and the
// local break-glass account must always be there.
func (s *Users) ensureOtherAdmin(ctx context.Context, exceptID int64) error {
	var n int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND source = 'local' AND id != ?`, exceptID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrLastAdmin
	}
	return nil
}

// Authenticate checks a local username and password. It takes the same time
// for unknown users and wrong passwords, and returns ErrBadCredentials for
// both. Domain accounts never match here; SignIn handles them.
func (s *Users) Authenticate(ctx context.Context, name, pw string) (*User, error) {
	u, err := s.GetByName(ctx, name)
	if err == nil && u.Source != SourceLocal {
		err = store.ErrNotFound
	}
	if errors.Is(err, store.ErrNotFound) {
		VerifyPassword(pw, dummyHash)
		return nil, ErrBadCredentials
	}
	if err != nil {
		return nil, err
	}
	if !VerifyPassword(pw, u.passwordHash) || u.Disabled {
		return nil, ErrBadCredentials
	}
	s.touchLogin(ctx, u.ID)
	return u, nil
}

func (s *Users) touchLogin(ctx context.Context, id int64) {
	_, _ = s.DB.ExecContext(ctx, `UPDATE users SET last_login_at = ? WHERE id = ?`, store.Now(), id)
}

// DomainUpdate is what the domain says about an account at sign-in or at a
// group refresh.
type DomainUpdate struct {
	Principal   string // NETBIOS\name
	DisplayName string
	Email       string
	Role        Role
	Groups      []string // NETBIOS\group
}

// UpsertDomain records a domain account (creating its row the first time it
// signs in) with its current name, role and groups. It never touches a
// local account (their names can't contain a backslash anyway).
func (s *Users) UpsertDomain(ctx context.Context, d DomainUpdate) (*User, error) {
	if !strings.Contains(d.Principal, `\`) || !d.Role.Valid() {
		return nil, errors.New("not a domain principal")
	}
	groups := d.Groups
	if groups == nil {
		groups = []string{}
	}
	g, err := json.Marshal(groups)
	if err != nil {
		return nil, err
	}
	now := store.Now()
	_, err = s.DB.ExecContext(ctx, `INSERT INTO users
		(username, display_name, email, role, password_hash, source, groups, groups_checked_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, '', 'domain', ?, ?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
			display_name = excluded.display_name, email = excluded.email, role = excluded.role,
			groups = excluded.groups, groups_checked_at = excluded.groups_checked_at, updated_at = excluded.updated_at
		WHERE users.source = 'domain'`,
		d.Principal, strings.TrimSpace(d.DisplayName), strings.TrimSpace(d.Email), d.Role, string(g), now, now, now)
	if err != nil {
		return nil, err
	}
	u, err := s.GetByName(ctx, d.Principal)
	if err != nil {
		return nil, err
	}
	if u.Source != SourceDomain {
		return nil, ErrUserExists
	}
	return u, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
