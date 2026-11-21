package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/hardyos/hardyos/daemon/internal/store"
)

// App password scopes: what a per-device password may sign in to.
const (
	ScopeFiles     = "files"     // WebDAV (/dav/)
	ScopeMail      = "mail"      // IMAP and SMTP
	ScopeCalendars = "calendars" // CalDAV and CardDAV (/dav-mail/)
)

// AppPasswordScopes lists every scope.
var AppPasswordScopes = []string{ScopeFiles, ScopeMail, ScopeCalendars}

// MaxAppPasswords is how many one account may have.
const MaxAppPasswords = 25

// Errors.
var (
	ErrAppPasswordName   = errors.New("give the app password a name of 1-64 characters (the device or app it's for)")
	ErrAppPasswordScopes = errors.New("pick at least one of files, mail and calendars")
	ErrTooManyAppPw      = errors.New("this account has too many app passwords; remove some first")
	ErrAppPasswordLocal  = errors.New("app passwords are for domain accounts (WebDAV, mail and calendars); HardyOS accounts don't use those services")
)

// AppPassword is one per-device password (never its value).
type AppPassword struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
	LastUsedIP string     `json:"lastUsedIp"`
}

// AppPasswords keeps them.
type AppPasswords struct{ DB *store.DB }

// LooksLikeAppPassword reports whether what someone typed has the shape of
// an app password (20 letters and digits of the code alphabet, dashes and
// spaces allowed), so other passwords are never compared with them.
func LooksLikeAppPassword(pw string) bool {
	c := normalizeCode(pw)
	if len(c) != appPasswordLen {
		return false
	}
	for i := range len(c) {
		if !strings.ContainsRune(codeAlphabet, rune(c[i])) {
			return false
		}
	}
	return true
}

func cleanName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 64 {
		return "", ErrAppPasswordName
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return "", ErrAppPasswordName
		}
	}
	return name, nil
}

func cleanScopes(scopes []string) ([]string, error) {
	var out []string
	for _, s := range scopes {
		s = strings.ToLower(strings.TrimSpace(s))
		if !slices.Contains(AppPasswordScopes, s) {
			return nil, ErrAppPasswordScopes
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, ErrAppPasswordScopes
	}
	slices.Sort(out)
	return out, nil
}

// Create makes an app password for u and returns it with its value (shown
// once, grouped as abcd-efgh-...).
func (a *AppPasswords) Create(ctx context.Context, u *User, name string, scopes []string) (*AppPassword, string, error) {
	if u.Source != SourceDomain {
		return nil, "", ErrAppPasswordLocal
	}
	name, err := cleanName(name)
	if err != nil {
		return nil, "", err
	}
	scopes, err = cleanScopes(scopes)
	if err != nil {
		return nil, "", err
	}
	var n int
	if err := a.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM app_passwords WHERE user_id = ?`, u.ID).Scan(&n); err != nil {
		return nil, "", err
	}
	if n >= MaxAppPasswords {
		return nil, "", ErrTooManyAppPw
	}
	secret, err := randomCode(appPasswordLen)
	if err != nil {
		return nil, "", err
	}
	sc, _ := json.Marshal(scopes)
	now := store.Now()
	res, err := a.DB.ExecContext(ctx, `INSERT INTO app_passwords (user_id, name, scopes, hash, created_at) VALUES (?, ?, ?, ?, ?)`,
		u.ID, name, string(sc), codeHash(secret), now)
	if err != nil {
		return nil, "", err
	}
	id, _ := res.LastInsertId()
	return &AppPassword{ID: id, Name: name, Scopes: scopes, CreatedAt: store.ParseTime(now)}, groupCode(secret), nil
}

// List returns u's app passwords, newest first.
func (a *AppPasswords) List(ctx context.Context, uid int64) ([]AppPassword, error) {
	rows, err := a.DB.QueryContext(ctx, `SELECT id, name, scopes, created_at, last_used_at, last_used_ip FROM app_passwords WHERE user_id = ? ORDER BY id DESC`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AppPassword{}
	for rows.Next() {
		var p AppPassword
		var sc, created string
		var used sql.NullString
		if err := rows.Scan(&p.ID, &p.Name, &sc, &created, &used, &p.LastUsedIP); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(sc), &p.Scopes)
		if p.Scopes == nil {
			p.Scopes = []string{}
		}
		p.CreatedAt = store.ParseTime(created)
		p.LastUsedAt = timePtr(used)
		out = append(out, p)
	}
	return out, rows.Err()
}

// Delete revokes one of uid's app passwords (store.ErrNotFound if it isn't
// theirs).
func (a *AppPasswords) Delete(ctx context.Context, uid, id int64) error {
	res, err := a.DB.ExecContext(ctx, `DELETE FROM app_passwords WHERE id = ? AND user_id = ?`, id, uid)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// RevokeBefore removes uid's app passwords made before t (the domain says
// the account's password was set then) and says how many went.
func (a *AppPasswords) RevokeBefore(ctx context.Context, uid int64, t time.Time) int64 {
	res, err := a.DB.ExecContext(ctx, `DELETE FROM app_passwords WHERE user_id = ? AND created_at < ?`, uid, store.FormatTime(t))
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return n
}

// Check reports whether pw is one of uid's app passwords with scope, and
// records its use.
func (a *AppPasswords) Check(ctx context.Context, uid int64, pw, scope, ip string) (bool, error) {
	if !LooksLikeAppPassword(pw) {
		return false, nil
	}
	var id int64
	var sc string
	err := a.DB.QueryRowContext(ctx, `SELECT id, scopes FROM app_passwords WHERE user_id = ? AND hash = ?`, uid, codeHash(normalizeCode(pw))).Scan(&id, &sc)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var scopes []string
	_ = json.Unmarshal([]byte(sc), &scopes)
	if !slices.Contains(scopes, scope) {
		return false, nil
	}
	if len(ip) > 64 {
		ip = ip[:64]
	}
	_, _ = a.DB.ExecContext(ctx, `UPDATE app_passwords SET last_used_at = ?, last_used_ip = ? WHERE id = ?`, store.Now(), ip, id)
	return true, nil
}

// PasswordPolicy says whether an account's own password may be used for a
// service that can't ask for a code: never from outside (two-factor sign-in
// is required there, so only app passwords work) and never once the
// account has two-factor sign-in.
func PasswordPolicy(enrolled, outside bool) bool { return !enrolled && !outside }
