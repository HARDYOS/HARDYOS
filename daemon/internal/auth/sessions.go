package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Session lifetimes.
const (
	// IdleTimeout ends a session that hasn't been used for this long.
	IdleTimeout = 24 * time.Hour
	// MaxLifetime ends a session this long after sign-in regardless of use.
	MaxLifetime = 30 * 24 * time.Hour
	// touchInterval limits how often last_seen_at is written.
	touchInterval = time.Minute
)

// ErrNoSession is returned for missing, expired or revoked sessions.
var ErrNoSession = errors.New("not signed in")

// Sessions issues and validates browser sessions.
type Sessions struct{ DB *store.DB }

// SessionInfo is the server-side record behind a session cookie.
type SessionInfo struct {
	UserID    int64
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
	// Source and Principal record which kind of account signed in
	// (SourceLocal "alice", SourceDomain "HOME\alice").
	Source    string
	Principal string
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Create starts a session for a local account and returns the token for the
// cookie. Use Start when the User is at hand.
func (s *Sessions) Create(ctx context.Context, userID int64, ip, userAgent string) (string, time.Time, error) {
	return s.create(ctx, userID, SourceLocal, "", ip, userAgent)
}

// Start starts a session for u, recording its source and principal.
func (s *Sessions) Start(ctx context.Context, u *User, ip, userAgent string) (string, time.Time, error) {
	src := u.Source
	if src == "" {
		src = SourceLocal
	}
	return s.create(ctx, u.ID, src, u.Principal, ip, userAgent)
}

func (s *Sessions) create(ctx context.Context, userID int64, source, principal, ip, userAgent string) (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	now := time.Now()
	expires := now.Add(IdleTimeout)
	if len(userAgent) > 256 {
		userAgent = userAgent[:256]
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO sessions (id_hash, user_id, created_at, last_seen_at, expires_at, ip, user_agent, source, principal)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		hashToken(token), userID, store.FormatTime(now), store.FormatTime(now), store.FormatTime(expires), ip, userAgent, source, principal)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// Validate returns the session for token, sliding its idle expiry forward.
func (s *Sessions) Validate(ctx context.Context, token string) (*SessionInfo, error) {
	if token == "" {
		return nil, ErrNoSession
	}
	id := hashToken(token)
	var info SessionInfo
	var created, seen, expires string
	err := s.DB.QueryRowContext(ctx, `SELECT user_id, created_at, last_seen_at, expires_at, source, principal FROM sessions WHERE id_hash = ?`, id).
		Scan(&info.UserID, &created, &seen, &expires, &info.Source, &info.Principal)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	info.CreatedAt, info.LastSeen, info.ExpiresAt = store.ParseTime(created), store.ParseTime(seen), store.ParseTime(expires)

	now := time.Now()
	if now.After(info.ExpiresAt) || now.Sub(info.CreatedAt) > MaxLifetime {
		_, _ = s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, id)
		return nil, ErrNoSession
	}
	if now.Sub(info.LastSeen) > touchInterval {
		newExpiry := now.Add(IdleTimeout)
		if hard := info.CreatedAt.Add(MaxLifetime); newExpiry.After(hard) {
			newExpiry = hard
		}
		_, _ = s.DB.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id_hash = ?`,
			store.FormatTime(now), store.FormatTime(newExpiry), id)
		info.LastSeen, info.ExpiresAt = now, newExpiry
	}
	return &info, nil
}

// Revoke ends one session.
func (s *Sessions) Revoke(ctx context.Context, token string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, hashToken(token))
	return err
}

// RevokeUser ends every session of a user (password change, disable, delete).
func (s *Sessions) RevokeUser(ctx context.Context, userID int64) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

// PurgeExpired deletes expired sessions and returns how many were removed.
func (s *Sessions) PurgeExpired(ctx context.Context) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, store.Now())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
