package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
)

// SessionCookie is the name of the browser session cookie.
const SessionCookie = "hardyos_session"

type ctxKey int

const userKey ctxKey = 1

// userFrom returns the signed-in user for a request inside authed/admin handlers.
func userFrom(r *http.Request) *auth.User {
	u, _ := r.Context().Value(userKey).(*auth.User)
	return u
}

type authedHandler func(w http.ResponseWriter, r *http.Request, u *auth.User)

// authed requires a valid session and an enabled account.
func (s *Server) authed(h authedHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.currentUser(w, r)
		if !ok {
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), userKey, u)), u)
	})
}

// admin requires a signed-in administrator.
func (s *Server) admin(h authedHandler) http.Handler {
	return s.authed(func(w http.ResponseWriter, r *http.Request, u *auth.User) {
		if !u.IsAdmin() {
			s.record(r, u, "authz.denied", r.Method+" "+r.URL.Path, audit.Denied, "")
			writeError(w, http.StatusForbidden, "forbidden", "administrator access required")
			return
		}
		h(w, r, u)
	})
}

func (s *Server) currentUser(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "sign in required")
		return nil, false
	}
	info, err := s.sessions.Validate(r.Context(), c.Value)
	if errors.Is(err, auth.ErrNoSession) {
		s.clearCookie(w, r)
		writeError(w, http.StatusUnauthorized, "unauthenticated", "session expired; sign in again")
		return nil, false
	}
	if err != nil {
		internalError(s, w, err)
		return nil, false
	}
	u, err := s.sessionUser(r, c.Value, info.UserID)
	if err != nil {
		s.clearCookie(w, r)
		writeError(w, http.StatusUnauthorized, "unauthenticated", "account unavailable")
		return nil, false
	}
	return u, true
}

// errAccountUnavailable: the account behind a session is gone or disabled.
var errAccountUnavailable = errors.New("account unavailable")

// sessionUser loads the account behind a valid session, the same way for
// the desktop's API and the app window proxy: a missing or disabled
// account ends the session (errAccountUnavailable); a domain account's
// groups (and with them its role) are refreshed every 10 minutes, and one
// deleted, turned off or expired in the domain ends all its sessions
// (auth.ErrAccountGone). r is used for the audit entry only.
func (s *Server) sessionUser(r *http.Request, token string, userID int64) (*auth.User, error) {
	ctx := r.Context()
	u, err := s.users.Get(ctx, userID)
	if err != nil || u.Disabled {
		_ = s.sessions.Revoke(ctx, token)
		return nil, errAccountUnavailable
	}
	if u.Source == auth.SourceDomain {
		nu, err := s.signin.Refresh(ctx, u)
		if errors.Is(err, auth.ErrAccountGone) {
			_ = s.sessions.RevokeUser(ctx, u.ID)
			s.record(r, u, "auth.session.end", u.Username, audit.Success, "the domain account was deleted, turned off or expired")
			return nil, err
		}
		if err != nil {
			s.log.Warn("refresh domain groups", "user", u.Username, "err", err)
		} else {
			u = nu
		}
	}
	return u, nil
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires.Add(auth.MaxLifetime - auth.IdleTimeout), // server enforces the real expiry
		HttpOnly: true,
		Secure:   r.TLS != nil || !s.cfg.Insecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: r.TLS != nil || !s.cfg.Insecure, SameSite: http.SameSiteStrictMode,
	})
}

// record writes an audit entry, logging (not failing) if the write fails.
func (s *Server) record(r *http.Request, u *auth.User, action, target string, outcome audit.Outcome, detail string) {
	e := audit.Entry{Action: action, Target: target, Outcome: outcome, Detail: detail, IP: clientIP(r), Actor: "anonymous"}
	if u != nil {
		id := u.ID
		e.ActorID, e.Actor = &id, u.Username
	}
	if err := s.audit.Record(r.Context(), e); err != nil {
		s.log.Error("audit write failed", "action", action, "err", err)
	}
}
