package api

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
)

// setupMu serializes first-admin creation so two browsers can't both win.
var setupMu sync.Mutex

type setupStatus struct {
	NeedsAdmin bool `json:"needsAdmin"`
}

func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	n, err := s.users.Count(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, setupStatus{NeedsAdmin: n == 0})
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
	ip := clientIP(r)
	userKey := "user:" + strings.ToLower(strings.TrimSpace(req.Username))
	for _, key := range []string{"ip:" + ip, userKey} {
		if ok, wait := s.cfg.Limiter.Allowed(key); !ok {
			secs := int(math.Ceil(wait.Seconds()))
			w.Header().Set("Retry-After", fmt.Sprint(secs))
			s.record(r, nil, "auth.login", req.Username, audit.Denied, "rate limited")
			writeError(w, http.StatusTooManyRequests, "rate_limited",
				fmt.Sprintf("too many failed sign-ins; try again in %d minutes", (secs+59)/60))
			return
		}
	}

	u, err := s.users.Authenticate(r.Context(), req.Username, req.Password)
	if errors.Is(err, auth.ErrBadCredentials) {
		s.cfg.Limiter.Fail("ip:" + ip)
		s.cfg.Limiter.Fail(userKey)
		s.record(r, nil, "auth.login", req.Username, audit.Failure, "bad credentials")
		writeError(w, http.StatusUnauthorized, "bad_credentials", auth.ErrBadCredentials.Error())
		return
	}
	if err != nil {
		internalError(s, w, err)
		return
	}
	s.cfg.Limiter.Succeed("ip:" + ip)
	s.cfg.Limiter.Succeed(userKey)
	s.record(r, u, "auth.login", u.Username, audit.Success, "")
	s.startSession(w, r, u)
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u *auth.User) {
	token, expires, err := s.sessions.Create(r.Context(), u.ID, clientIP(r), r.UserAgent())
	if err != nil {
		s.log.Error("create session", "err", err)
		return
	}
	s.setSessionCookie(w, r, token, expires)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		if info, err := s.sessions.Validate(r.Context(), c.Value); err == nil {
			if u, err := s.users.Get(r.Context(), info.UserID); err == nil {
				s.record(r, u, "auth.logout", u.Username, audit.Success, "")
			}
		}
		_ = s.sessions.Revoke(r.Context(), c.Value)
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
	s.startSession(w, r, u)
	s.record(r, u, "auth.password.change", u.Username, audit.Success, "")
	w.WriteHeader(http.StatusNoContent)
}
