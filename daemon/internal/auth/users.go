package auth

import (
	"context"
	"database/sql"
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

// User is a HardyOS account.
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

	passwordHash string
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

const userCols = `id, username, display_name, email, role, password_hash, disabled, break_glass, created_at, last_login_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var created string
	var lastLogin sql.NullString
	var disabled, breakGlass int
	if err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Role, &u.passwordHash,
		&disabled, &breakGlass, &created, &lastLogin); err != nil {
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
	return &u, nil
}

// Count returns the number of accounts.
func (s *Users) Count(ctx context.Context) (int, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
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

// GetByName returns the account with the given username.
func (s *Users) GetByName(ctx context.Context, name string) (*User, error) {
	return scanUser(s.DB.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`, strings.ToLower(strings.TrimSpace(name))))
}

// List returns all accounts ordered by username.
func (s *Users) List(ctx context.Context) ([]*User, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
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

// Update applies changes, refusing any that would leave no active admin.
func (s *Users) Update(ctx context.Context, id int64, up UserUpdate) (*User, error) {
	u, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if up.Role != nil && !up.Role.Valid() {
		return nil, ErrInvalidRole
	}
	losesAdmin := u.IsAdmin() && ((up.Role != nil && *up.Role != RoleAdmin) || (up.Disabled != nil && *up.Disabled))
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

// SetPassword replaces an account's password.
func (s *Users) SetPassword(ctx context.Context, id int64, pw string) error {
	if err := ValidatePassword(pw); err != nil {
		return err
	}
	hash, err := HashPassword(pw)
	if err != nil {
		return err
	}
	res, err := s.DB.ExecContext(ctx, `UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`, hash, store.Now(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// Delete removes an account, refusing to remove the last active admin.
func (s *Users) Delete(ctx context.Context, id int64) error {
	u, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if u.IsAdmin() {
		if err := s.ensureOtherAdmin(ctx, id); err != nil {
			return err
		}
	}
	_, err = s.DB.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

func (s *Users) ensureOtherAdmin(ctx context.Context, exceptID int64) error {
	var n int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND id != ?`, exceptID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrLastAdmin
	}
	return nil
}

// Authenticate checks a username and password. It takes the same time for
// unknown users and wrong passwords, and returns ErrBadCredentials for both.
func (s *Users) Authenticate(ctx context.Context, name, pw string) (*User, error) {
	u, err := s.GetByName(ctx, name)
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
	_, _ = s.DB.ExecContext(ctx, `UPDATE users SET last_login_at = ? WHERE id = ?`, store.Now(), u.ID)
	return u, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
