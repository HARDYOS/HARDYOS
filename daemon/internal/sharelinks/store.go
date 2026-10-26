// Package sharelinks keeps web share links: a secret URL to one file or
// folder that people without an account can open (docs/plans/file-sharing.md
// section 4, decisions 96-98). Files are always read and written as the
// person who made the link, through files.Access, and the link is re-checked
// on every use.
package sharelinks

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Limits on what a link may be made with.
const (
	DefaultExpiryDays = 7
	MaxExpiryDays     = 90
	MinPasswordLength = 6
	MaxDownloadsLimit = 100000
	tokenBytes        = 32
)

// Link states.
const (
	StatusActive  = "active"
	StatusExpired = "expired"
	StatusRevoked = "revoked"
	StatusUsedUp  = "used-up"
)

// Why a link can't be used.
var (
	ErrNotFound = errors.New("this link doesn't work: check that you copied all of it")
	ErrExpired  = errors.New("this link has expired")
	ErrRevoked  = errors.New("this link was turned off by the person who shared it")
	ErrUsedUp   = errors.New("this link has been downloaded as many times as it allows")
	// ErrOwnerGone: the account that made the link is deleted or disabled,
	// or no longer has access to what it points at.
	ErrOwnerGone = errors.New("this link no longer works")
)

// Link is a share link as the API shows it. The token is never stored.
type Link struct {
	ID            int64      `json:"id"`
	Share         string     `json:"share"`
	Path          string     `json:"path"`
	Name          string     `json:"name"`
	Dir           bool       `json:"dir"`
	CreatedByID   int64      `json:"createdById"`
	CreatedBy     string     `json:"createdBy"`
	CreatedAt     time.Time  `json:"createdAt"`
	ExpiresAt     time.Time  `json:"expiresAt"`
	HasPassword   bool       `json:"hasPassword"`
	AllowUpload   bool       `json:"allowUpload"`
	MaxDownloads  int        `json:"maxDownloads"`
	DownloadCount int        `json:"downloadCount"`
	LastUsedAt    *time.Time `json:"lastUsedAt"`
	Revoked       bool       `json:"revoked"`
	Status        string     `json:"status"`

	passwordHash string
}

// CheckPassword reports whether pw opens the link (always true without a password).
func (l *Link) CheckPassword(pw string) bool {
	if l.passwordHash == "" {
		return true
	}
	return auth.VerifyPassword(pw, l.passwordHash)
}

// passwordStamp changes whenever the password does; unlock cookies carry it.
func (l *Link) passwordStamp() string { return l.passwordHash }

// Usable reports why the link can't be used now, or nil.
func (l *Link) Usable(now time.Time) error {
	switch {
	case l.Revoked:
		return ErrRevoked
	case !now.Before(l.ExpiresAt):
		return ErrExpired
	case l.MaxDownloads > 0 && l.DownloadCount >= l.MaxDownloads:
		return ErrUsedUp
	}
	return nil
}

func (l *Link) setStatus(now time.Time) {
	switch l.Usable(now) {
	case ErrRevoked:
		l.Status = StatusRevoked
	case ErrExpired:
		l.Status = StatusExpired
	case ErrUsedUp:
		l.Status = StatusUsedUp
	default:
		l.Status = StatusActive
	}
}

// Request is what a person asks for when making a link.
type Request struct {
	Share string `json:"share"`
	Path  string `json:"path"`
	// ExpiresInDays: 1-90; 0 means the default of 7.
	ExpiresInDays int    `json:"expiresInDays,omitempty"`
	Password      string `json:"password,omitempty"`
	AllowUpload   bool   `json:"allowUpload,omitempty"`
	// MaxDownloads: 0 for no limit.
	MaxDownloads int `json:"maxDownloads,omitempty"`
}

// Validate checks a request and cleans its path. dir says whether the path
// is a folder (known only after asking files.Access).
func (q *Request) Validate() []string {
	var probs []string
	q.Share = strings.TrimSpace(q.Share)
	if q.Share == "" {
		probs = append(probs, "Choose the shared folder the link is for.")
	}
	p, err := CleanPath(q.Path)
	if err != nil {
		probs = append(probs, err.Error())
	}
	q.Path = p
	if q.ExpiresInDays == 0 {
		q.ExpiresInDays = DefaultExpiryDays
	}
	if q.ExpiresInDays < 1 || q.ExpiresInDays > MaxExpiryDays {
		probs = append(probs, fmt.Sprintf("A link can last from 1 to %d days.", MaxExpiryDays))
	}
	if q.Password != "" {
		if utf8.RuneCountInString(q.Password) < MinPasswordLength {
			probs = append(probs, fmt.Sprintf("Use a password of at least %d characters, or none.", MinPasswordLength))
		} else if len(q.Password) > 1024 {
			probs = append(probs, "That password is too long.")
		}
	}
	if q.MaxDownloads < 0 || q.MaxDownloads > MaxDownloadsLimit {
		probs = append(probs, fmt.Sprintf("The download limit is a number from 0 (no limit) to %d.", MaxDownloadsLimit))
	}
	return probs
}

// Hidden reports whether a file or folder name is never shown through
// files or links: the recycle bin, snapshots and HardyOS's own files.
func Hidden(name string) bool {
	n := strings.ToLower(name)
	return n == ".recycle" || n == ".zfs" || strings.HasPrefix(n, ".hardyos")
}

// CleanPath checks a "/" separated path inside a share: no empty, "." or
// ".." parts, no hidden names, no NUL. Leading and trailing slashes are
// dropped; "" is the share's top.
func CleanPath(p string) (string, error) {
	p = strings.Trim(p, "/")
	if p == "" {
		return "", nil
	}
	if len(p) > 4096 || strings.ContainsRune(p, 0) {
		return "", errors.New("that path isn't allowed")
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." || Hidden(part) {
			return "", errors.New("that path isn't allowed")
		}
	}
	return p, nil
}

// Join appends a cleaned sub path to a link's path.
func Join(base, sub string) string {
	switch {
	case sub == "":
		return base
	case base == "":
		return sub
	}
	return base + "/" + sub
}

// Store reads and writes links in hardyd's database.
type Store struct {
	DB  *store.DB
	Now func() time.Time // tests
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// HashToken is how a token is looked up: hex SHA-256.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NewToken returns 32 random bytes, URL-safe base64 (43 characters).
func NewToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidToken reports whether s looks like a token (cheap check before the DB).
func ValidToken(s string) bool {
	if len(s) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil
}

// Owner is the person making a link.
type Owner struct {
	ID        int64
	Principal string
}

// Create stores a validated request and returns the link and its token,
// which is shown once and never again.
func (s *Store) Create(ctx context.Context, q Request, dir bool, owner Owner) (*Link, string, error) {
	if q.AllowUpload && !dir {
		return nil, "", errors.New("only links to folders can take uploads")
	}
	token, err := NewToken()
	if err != nil {
		return nil, "", err
	}
	var hash string
	if q.Password != "" {
		if hash, err = auth.HashPassword(q.Password); err != nil {
			return nil, "", err
		}
	}
	now := s.now()
	exp := now.Add(time.Duration(q.ExpiresInDays) * 24 * time.Hour)
	res, err := s.DB.ExecContext(ctx, `INSERT INTO share_links
		(token_hash, share, path, is_dir, created_by, created_by_name, created_at, expires_at, password_hash, allow_upload, max_downloads)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		HashToken(token), q.Share, q.Path, b2i(dir), owner.ID, owner.Principal, store.FormatTime(now), store.FormatTime(exp),
		hash, b2i(q.AllowUpload), q.MaxDownloads)
	if err != nil {
		return nil, "", err
	}
	id, _ := res.LastInsertId()
	l, err := s.Get(ctx, id)
	return l, token, err
}

const linkCols = `id, share, path, is_dir, created_by, created_by_name, created_at, expires_at, password_hash, allow_upload, max_downloads, download_count, last_used_at, revoked`

func (s *Store) scan(row interface{ Scan(...any) error }) (*Link, error) {
	var l Link
	var dir, upload, revoked int
	var created, expires, used string
	if err := row.Scan(&l.ID, &l.Share, &l.Path, &dir, &l.CreatedByID, &l.CreatedBy, &created, &expires,
		&l.passwordHash, &upload, &l.MaxDownloads, &l.DownloadCount, &used, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	l.Dir, l.AllowUpload, l.Revoked = dir != 0, upload != 0, revoked != 0
	l.CreatedAt, l.ExpiresAt = store.ParseTime(created), store.ParseTime(expires)
	if used != "" {
		t := store.ParseTime(used)
		l.LastUsedAt = &t
	}
	l.HasPassword = l.passwordHash != ""
	l.Name = path.Base(l.Path)
	if l.Path == "" {
		l.Name = ""
	}
	l.setStatus(s.now())
	return &l, nil
}

// Get returns one link by id.
func (s *Store) Get(ctx context.Context, id int64) (*Link, error) {
	return s.scan(s.DB.QueryRowContext(ctx, `SELECT `+linkCols+` FROM share_links WHERE id = ?`, id))
}

// ByToken finds the link a token opens (ErrNotFound if none).
func (s *Store) ByToken(ctx context.Context, token string) (*Link, error) {
	if !ValidToken(token) {
		return nil, ErrNotFound
	}
	return s.scan(s.DB.QueryRowContext(ctx, `SELECT `+linkCols+` FROM share_links WHERE token_hash = ?`, HashToken(token)))
}

// List returns links newest first: one person's (createdBy > 0) or all.
func (s *Store) List(ctx context.Context, createdBy int64) ([]*Link, error) {
	q := `SELECT ` + linkCols + ` FROM share_links`
	var args []any
	if createdBy > 0 {
		q += ` WHERE created_by = ?`
		args = append(args, createdBy)
	}
	rows, err := s.DB.QueryContext(ctx, q+` ORDER BY id DESC LIMIT 1000`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Link{}
	for rows.Next() {
		l, err := s.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// Revoke turns a link off for good.
func (s *Store) Revoke(ctx context.Context, id int64) (*Link, error) {
	if _, err := s.DB.ExecContext(ctx, `UPDATE share_links SET revoked = 1, revoked_at = ? WHERE id = ? AND revoked = 0`,
		store.FormatTime(s.now()), id); err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// CountDownload records one download, refusing when the link's limit is
// reached (atomically, so parallel downloads can't go over it).
func (s *Store) CountDownload(ctx context.Context, id int64) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE share_links SET download_count = download_count + 1, last_used_at = ?
		WHERE id = ? AND revoked = 0 AND (max_downloads = 0 OR download_count < max_downloads)`,
		store.FormatTime(s.now()), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUsedUp
	}
	return nil
}

// Touch records that the link was used (uploads, which don't count as downloads).
func (s *Store) Touch(ctx context.Context, id int64) {
	_, _ = s.DB.ExecContext(ctx, `UPDATE share_links SET last_used_at = ? WHERE id = ?`, store.FormatTime(s.now()), id)
}

// Prune removes links that expired or were revoked more than 30 days ago.
func (s *Store) Prune(ctx context.Context) (int64, error) {
	cut := store.FormatTime(s.now().Add(-30 * 24 * time.Hour))
	res, err := s.DB.ExecContext(ctx, `DELETE FROM share_links WHERE expires_at < ? OR (revoked = 1 AND revoked_at < ?)`, cut, cut)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
