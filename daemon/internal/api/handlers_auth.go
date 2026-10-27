package api

import (
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
)

// setupMu serializes first-admin creation so two browsers can't both win.
var setupMu sync.Mutex

type setupStatus struct {
	NeedsAdmin bool `json:"needsAdmin"`
	// DomainSignIn: this server has a domain, so its accounts can sign in.
	DomainSignIn bool `json:"domainSignIn"`
}

func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	n, err := s.users.Count(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	st := setupStatus{NeedsAdmin: n == 0}
	if !st.NeedsAdmin {
		st.DomainSignIn = s.domainSignInAvailable(r.Context())
	}
	writeJSON(w, http.StatusOK, st)
}

type setupAdminRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
}

// handleSetupAdmin creates the first administrator. It only works while the
// system has no accounts. That account is flagged break-glass: it stays a
// local account even after Samba AD becomes the user source.
func (s *Server) handleSetupAdmin(w http.ResponseWriter, r *http.Request) {
	var req setupAdminRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	setupMu.Lock()
	defer setupMu.Unlock()
	n, err := s.users.Count(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	if n > 0 {
		writeError(w, http.StatusConflict, "already_setup", "an administrator already exists; sign in instead")
		return
	}
	u, err := s.users.Create(r.Context(), auth.NewUser{
		Username: req.Username, Password: req.Password, DisplayName: req.DisplayName,
		Email: req.Email, Role: auth.RoleAdmin, BreakGlass: true,
	})
	if err != nil {
		writeUserError(s, w, err)
		return
	}
	s.record(r, u, "setup.admin", u.Username, audit.Success, "first administrator created")
	s.startSession(w, r, u)
	writeJSON(w, http.StatusCreated, u)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ip := s.clientIP(r)
	userKey := s.signin.LimitKey(r.Context(), req.Username)
	// From the internet (a public desktop through the app gateway): buckets
	// of their own that slow guessing down, so they can't lock anyone out
	// of signing in at home or over NetBird.
	var lim limiter = s.cfg.Limiter
	prefix := ""
	if publicOrigin(r) {
		lim, prefix = s.pubLimiter, "pub-"
	}
	ipKey, userKey := prefix+"ip:"+ip, prefix+userKey
	for _, key := range []string{ipKey, userKey} {
		if ok, wait := lim.Allowed(key); !ok {
			secs := int(math.Ceil(wait.Seconds()))
			w.Header().Set("Retry-After", fmt.Sprint(secs))
			s.record(r, nil, "auth.login", req.Username, audit.Denied, "rate limited")
			msg := fmt.Sprintf("too many failed sign-ins; try again in %d minutes", (secs+59)/60)
			if prefix != "" {
				msg = fmt.Sprintf("too many failed sign-ins; try again in %d seconds", secs)
			}
			writeError(w, http.StatusTooManyRequests, "rate_limited", msg)
			return
		}
	}

	u, err := s.signin.Authenticate(r.Context(), req.Username, req.Password)
	if err != nil {
		code, counts := loginError(w, err)
		if code == "" {
			internalError(s, w, err)
			return
		}
		if counts {
			lim.Fail(ipKey)
			lim.Fail(userKey)
		}
		detail := strings.ReplaceAll(code, "_", " ")
		s.record(r, nil, "auth.login", req.Username, audit.Failure, detail)
		return
	}
	lim.Succeed(ipKey)
	lim.Succeed(userKey)
	detail := ""
	if u.Source == auth.SourceDomain {
		detail = "domain account, role " + string(u.Role)
	}
	s.record(r, u, "auth.login", u.Username, audit.Success, detail)
	s.startSession(w, r, u)
	writeJSON(w, http.StatusOK, u)
}

// limiter is auth.LoginLimiter or, from the internet, auth.DelayLimiter.
type limiter interface {
	Allowed(key string) (bool, time.Duration)
	Fail(key string)
	Succeed(key string)
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u *auth.User) {
	token, expires, err := s.sessions.Start(r.Context(), u, s.clientIP(r), r.UserAgent())
	if err != nil {
		s.log.Error("create session", "err", err)
		return
	}
	s.setSessionCookie(w, r, token, expires)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if token, ok := s.sessionToken(r); ok {
		if info, err := s.sessions.Validate(r.Context(), token); err == nil {
			if u, err := s.users.Get(r.Context(), info.UserID); err == nil {
				s.record(r, u, "auth.logout", u.Username, audit.Success, "")
			}
		}
		_ = s.sessions.Revoke(r.Context(), token)
		s.proxy.endDesktopSession(token) // app windows and their WebSockets too
	}
	s.clearCookie(w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, u *auth.User) {
	writeJSON(w, http.StatusOK, u)
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req changePasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if u.Source == auth.SourceDomain {
		writeError(w, http.StatusForbidden, "domain_account",
			"your password belongs to the domain: change it on a computer in the domain, or ask an administrator to set a new one in Control Panel > Domain > Users")
		return
	}
	if _, err := s.users.Authenticate(r.Context(), u.Username, req.CurrentPassword); err != nil {
		s.record(r, u, "auth.password.change", u.Username, audit.Failure, "wrong current password")
		writeError(w, http.StatusForbidden, "bad_credentials", "current password is incorrect")
		return
	}
	if err := s.users.SetPassword(r.Context(), u.ID, req.NewPassword); err != nil {
		writeUserError(s, w, err)
		return
	}
	// Sign out every other session; keep this browser signed in with a fresh one.
	_ = s.sessions.RevokeUser(r.Context(), u.ID)
	s.proxy.endUser(u.ID)
	s.endOIDCUser(r.Context(), u.ID)
	s.startSession(w, r, u)
	s.record(r, u, "auth.password.change", u.Username, audit.Success, "")
	w.WriteHeader(http.StatusNoContent)
}
