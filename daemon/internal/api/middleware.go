package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
)

// Desktop session cookies. Over HTTPS the cookie is __Host-hardyos_session:
// a browser takes a __Host- cookie only Secure, Path=/ and without Domain
// from the very host, so a page on a sibling subdomain (any published app
// at <app>.<base>) can neither set nor overwrite it. Over plain HTTP
// (development) browsers refuse __Host- cookies, so the old name is used.
//
// Over HTTPS the old name is never read (decision 268, ending the migration
// of decision 155): pages on another port of the desktop's host (app
// windows, the office origin) can set a plain cookie for the host, and it
// would sign the desktop in as whoever they chose. A new sign-in still
// expires the old name.
const (
	SessionCookie       = "__Host-hardyos_session"
	LegacySessionCookie = "hardyos_session"
)

// sessionCookieName is the name the desktop's session cookie has on r.
func (s *Server) sessionCookieName(r *http.Request) string {
	if r.TLS != nil {
		return SessionCookie
	}
	return LegacySessionCookie
}

// sessionToken is the desktop session token a request carries, if any.
func (s *Server) sessionToken(r *http.Request) (string, bool) {
	if r.TLS == nil {
		if c, err := r.Cookie(LegacySessionCookie); err == nil {
			return c.Value, true
		}
		return "", false
	}
	if c, err := r.Cookie(SessionCookie); err == nil {
		return c.Value, true
	}
	return "", false
}

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
	token, ok := s.sessionToken(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "sign in required")
		return nil, false
	}
	info, err := s.sessions.Validate(r.Context(), token)
	if errors.Is(err, auth.ErrNoSession) {
		s.clearCookie(w, r)
		writeError(w, http.StatusUnauthorized, "unauthenticated", "session expired; sign in again")
		return nil, false
	}
	if err != nil {
		internalError(s, w, err)
		return nil, false
	}
	u, err := s.sessionUser(r, token, info.UserID)
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
			s.endUserEverywhere(ctx, u.ID)
			why := "the domain account was deleted, turned off or expired"
			if errors.Is(err, auth.ErrAccountReplaced) {
				why = "the name now belongs to another domain account"
			}
			s.record(r, u, "auth.session.end", u.Username, audit.Success, why)
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
		Name:     s.sessionCookieName(r),
		Value:    token,
		Path:     "/",
		Expires:  expires.Add(auth.MaxLifetime - auth.IdleTimeout), // server enforces the real expiry
		HttpOnly: true,
		Secure:   r.TLS != nil || !s.cfg.Insecure,
		SameSite: http.SameSiteStrictMode,
	})
	if r.TLS != nil {
		// The old name goes (migration).
		http.SetCookie(w, &http.Cookie{Name: LegacySessionCookie, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	}
}

func (s *Server) clearCookie(w http.ResponseWriter, r *http.Request) {
	names := []string{LegacySessionCookie}
	if r.TLS != nil {
		names = append(names, SessionCookie)
	}
	for _, n := range names {
		http.SetCookie(w, &http.Cookie{
			Name: n, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, Secure: r.TLS != nil || !s.cfg.Insecure, SameSite: http.SameSiteStrictMode,
		})
	}
}

// endUserEverywhere ends every session a person has: desktop, app windows,
// published apps, HardyOS sign-in and the tokens apps hold.
func (s *Server) endUserEverywhere(ctx context.Context, id int64) {
	if s.sessions != nil {
		_ = s.sessions.RevokeUser(ctx, id)
	}
	s.proxy.endUser(id)
	s.endOIDCUser(ctx, id)
	s.office.dropUser(id, "the account's sessions were ended")
}

// record writes an audit entry, logging (not failing) if the write fails.
func (s *Server) record(r *http.Request, u *auth.User, action, target string, outcome audit.Outcome, detail string) {
	// clientIP: through the app gateway, the address NetBird's proxy saw.
	e := audit.Entry{Action: action, Target: target, Outcome: outcome, Detail: detail, IP: s.clientIP(r), Actor: "anonymous"}
	if u != nil {
		id := u.ID
		e.ActorID, e.Actor = &id, u.Username
	}
	if err := s.audit.Record(r.Context(), e); err != nil {
		s.log.Error("audit write failed", "action", action, "err", err)
	}
}
