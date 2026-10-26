package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// peekSession is auth.Sessions.Validate without sliding the idle expiry:
// the app window proxy checks the desktop session every 30 seconds, and an
// app left open in a tab must not keep the desktop signed in forever.
//
// It reads the sessions table the way auth.Sessions writes it (a SHA-256
// hex of the token; TestPeekSessionMatchesValidate keeps the two in step).
// It belongs in auth.Sessions as Peek; it's here because that package is
// being changed on another branch.
func (s *Server) peekSession(ctx context.Context, token string) (*auth.SessionInfo, error) {
	if token == "" || s.cfg.DB == nil {
		return nil, auth.ErrNoSession
	}
	sum := sha256.Sum256([]byte(token))
	var info auth.SessionInfo
	var created, seen, expires string
	err := s.cfg.DB.QueryRowContext(ctx, `SELECT user_id, created_at, last_seen_at, expires_at, source, principal FROM sessions WHERE id_hash = ?`,
		hex.EncodeToString(sum[:])).Scan(&info.UserID, &created, &seen, &expires, &info.Source, &info.Principal)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, auth.ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	info.CreatedAt, info.LastSeen, info.ExpiresAt = store.ParseTime(created), store.ParseTime(seen), store.ParseTime(expires)
	now := time.Now()
	if now.After(info.ExpiresAt) || now.Sub(info.CreatedAt) > auth.MaxLifetime {
		return nil, auth.ErrNoSession
	}
	return &info, nil
}
