package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/oidc"
)

// OIDC returns HardyOS's sign-in provider (nil in the live installer or
// without a database). Remote Access uses its Clients.Ensure.
func (s *Server) OIDC() *oidc.Provider { return s.oidc }

// newOIDC builds the sign-in provider over the desktop's own sign-in.
func (s *Server) newOIDC() *oidc.Provider {
	p, err := oidc.New(oidc.Config{
		DB: s.cfg.DB, Users: s.users, SignIn: s.signin, Limiter: s.cfg.Limiter,
		Secrets: s.cfg.Secrets, Names: s.cfg.OIDCNames, FallbackHost: s.cfg.PublicHost,
		LoadUser:    s.oidcUser,
		DesktopUser: s.desktopUser,
		ClientIP:    s.clientIP,
		Audit: func(ctx context.Context, ip string, u *auth.User, action, target string, outcome audit.Outcome, detail string) {
			e := audit.Entry{Action: action, Target: target, Outcome: outcome, Detail: detail, IP: ip, Actor: "anonymous"}
			if u != nil {
				id := u.ID
				e.ActorID, e.Actor = &id, u.Username
			}
			if err := s.audit.Record(ctx, e); err != nil {
				s.log.Error("audit write failed", "action", action, "err", err)
			}
		},
		LoginError: func(err error) (string, int, bool, bool) {
			a, _, ok := classifyLoginError(err)
			return a.code, a.status, a.counts, ok
		},
		Insecure: s.cfg.Insecure,
		Log:      s.log,
	})
	if err != nil {
		s.log.Error("sign-in provider unavailable", "err", err)
		return nil
	}
	return p
}

// oidcUser loads an account for the sign-in provider the way the desktop
// loads one behind a session: turned off or gone is an error, a domain
// account's groups are refreshed every 10 minutes and one gone from the
// domain loses its desktop sessions too.
func (s *Server) oidcUser(ctx context.Context, id int64) (*auth.User, error) {
	u, err := s.users.Get(ctx, id)
	if err != nil || u.Disabled {
		return nil, errAccountUnavailable
	}
	if u.Source != auth.SourceDomain {
		return u, nil
	}
	nu, err := s.signin.Refresh(ctx, u)
	if errors.Is(err, auth.ErrAccountGone) {
		_ = s.sessions.RevokeUser(ctx, u.ID)
		s.proxy.endUser(u.ID)
		if s.oidc != nil {
			s.oidc.EndUser(ctx, u.ID)
		}
		return nil, err
	}
	if err != nil {
		s.log.Warn("refresh domain groups", "user", u.Username, "err", err)
		return u, nil
	}
	return nu, nil
}

// desktopUser is who is signed in to the desktop in this browser (the
// provider on the desktop's host reuses it), without sliding the session.
func (s *Server) desktopUser(r *http.Request) (*auth.User, time.Time, bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return nil, time.Time{}, false
	}
	info, err := s.peekSession(r.Context(), c.Value)
	if err != nil {
		return nil, time.Time{}, false
	}
	u, err := s.sessionUser(r, c.Value, info.UserID)
	if err != nil {
		return nil, time.Time{}, false
	}
	return u, info.CreatedAt, true
}

// endOIDCUser ends a person's app sign-ins (password changed, account
// turned off).
func (s *Server) endOIDCUser(ctx context.Context, id int64) {
	if s.oidc != nil {
		s.oidc.EndUser(ctx, id)
	}
}

func (s *Server) oidcRoutes() {
	if s.oidc == nil {
		return
	}
	m := s.mux
	m.Handle("GET /api/v1/oidc", s.admin(s.handleOIDCStatus))
	m.Handle("PATCH /api/v1/oidc", s.admin(s.handleOIDCSettings))
	m.Handle("POST /api/v1/oidc/keys/rotate", s.admin(s.handleOIDCRotate))
	m.Handle("GET /api/v1/oidc/presets", s.admin(s.handleOIDCPresets))
	m.Handle("GET /api/v1/oidc/clients", s.admin(s.handleOIDCClients))
	m.Handle("POST /api/v1/oidc/clients", s.admin(s.handleOIDCCreateClient))
	m.Handle("GET /api/v1/oidc/clients/{id}", s.admin(s.handleOIDCClient))
	m.Handle("PATCH /api/v1/oidc/clients/{id}", s.admin(s.handleOIDCUpdateClient))
	m.Handle("DELETE /api/v1/oidc/clients/{id}", s.admin(s.handleOIDCDeleteClient))
	m.Handle("POST /api/v1/oidc/clients/{id}/secret", s.admin(s.handleOIDCNewSecret))
	m.Handle("POST /api/v1/oidc/clients/{id}/revoke", s.admin(s.handleOIDCRevokeClient))
}

type oidcStatus struct {
	oidc.Settings
	Keys []oidc.KeyInfo `json:"keys"`
}

func (s *Server) handleOIDCStatus(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	keys, err := s.oidc.Keys(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, oidcStatus{Settings: s.oidc.GetSettings(r.Context()), Keys: keys})
}

type oidcSettingsRequest struct {
	// Issuer: "" goes back to the address HardyOS works out; nil leaves it.
	Issuer        *string `json:"issuer"`
	LocalAccounts *bool   `json:"localAccounts"`
}

func (s *Server) handleOIDCSettings(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req oidcSettingsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	if req.Issuer != nil {
		before := s.oidc.Issuer(ctx)
		if err := s.oidc.SetIssuer(ctx, *req.Issuer); err != nil {
			writeOIDCError(s, w, err)
			return
		}
		s.record(r, u, "oidc.settings", "issuer", audit.Success, before+" -> "+s.oidc.Issuer(ctx))
	}
	if req.LocalAccounts != nil {
		if err := s.oidc.SetLocalAccounts(ctx, *req.LocalAccounts); err != nil {
			internalError(s, w, err)
			return
		}
		state := "off"
		if *req.LocalAccounts {
			state = "on"
		}
		s.record(r, u, "oidc.settings", "local accounts", audit.Success, "HardyOS accounts may sign in to apps: "+state)
	}
	s.handleOIDCStatus(w, r, u)
}

func (s *Server) handleOIDCRotate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if err := s.oidc.CheckKeys(r.Context(), true); err != nil {
		s.record(r, u, "oidc.keys.rotate", "signing keys", audit.Failure, err.Error())
		writeError(w, http.StatusServiceUnavailable, "unavailable", "the signing keys can't be changed right now: "+err.Error())
		return
	}
	s.record(r, u, "oidc.keys.rotate", "signing keys", audit.Success, "rotated by an administrator")
	s.handleOIDCStatus(w, r, u)
}

func (s *Server) handleOIDCPresets(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	nb := r.URL.Query().Get("netbirdUrl")
	if nb == "" {
		nb = oidc.DefaultNetBirdURL
	}
	writeJSON(w, http.StatusOK, map[string]any{"presets": oidc.Presets(nb)})
}

func (s *Server) handleOIDCClients(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	list, err := s.oidc.Clients.List(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": list})
}

func (s *Server) handleOIDCClient(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	c, err := s.oidc.Clients.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeOIDCError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// oidcClientResult carries a new secret the one time it exists.
type oidcClientResult struct {
	Client *oidc.Client `json:"client"`
	Secret string       `json:"secret,omitempty"`
}

func (s *Server) handleOIDCCreateClient(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var spec oidc.ClientSpec
	if !decodeJSON(w, r, &spec) {
		return
	}
	c, secret, err := s.oidc.Clients.Create(r.Context(), spec)
	if err != nil {
		writeOIDCError(s, w, err)
		return
	}
	s.record(r, u, "oidc.client.create", c.Name+" ("+c.ID+")", audit.Success, clientSummary(c))
	writeJSON(w, http.StatusCreated, oidcClientResult{Client: c, Secret: secret})
}

func (s *Server) handleOIDCUpdateClient(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var spec oidc.ClientSpec
	if !decodeJSON(w, r, &spec) {
		return
	}
	c, secret, err := s.oidc.Clients.Update(r.Context(), r.PathValue("id"), spec)
	if err != nil {
		writeOIDCError(s, w, err)
		return
	}
	s.record(r, u, "oidc.client.update", c.Name+" ("+c.ID+")", audit.Success, clientSummary(c))
	writeJSON(w, http.StatusOK, oidcClientResult{Client: c, Secret: secret})
}

func (s *Server) handleOIDCDeleteClient(w http.ResponseWriter, r *http.Request, u *auth.User) {
	id := r.PathValue("id")
	c, err := s.oidc.Clients.Get(r.Context(), id)
	if err != nil {
		writeOIDCError(s, w, err)
		return
	}
	if err := s.oidc.Clients.Delete(r.Context(), id); err != nil {
		writeOIDCError(s, w, err)
		return
	}
	s.record(r, u, "oidc.client.delete", c.Name+" ("+c.ID+")", audit.Success, "its sign-ins and tokens were revoked")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleOIDCNewSecret(w http.ResponseWriter, r *http.Request, u *auth.User) {
	id := r.PathValue("id")
	c, err := s.oidc.Clients.Get(r.Context(), id)
	if err != nil {
		writeOIDCError(s, w, err)
		return
	}
	if c.ManagedBy != "" {
		writeOIDCError(s, w, oidc.ErrManaged)
		return
	}
	secret, err := s.oidc.Clients.NewSecret(r.Context(), id)
	if err != nil {
		writeOIDCError(s, w, err)
		return
	}
	s.record(r, u, "oidc.client.secret", c.Name+" ("+c.ID+")", audit.Success, "new client secret; the old one stopped working")
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret})
}

func (s *Server) handleOIDCRevokeClient(w http.ResponseWriter, r *http.Request, u *auth.User) {
	id := r.PathValue("id")
	c, err := s.oidc.Clients.Get(r.Context(), id)
	if err != nil {
		writeOIDCError(s, w, err)
		return
	}
	n, err := s.oidc.RevokeClient(r.Context(), id)
	if err != nil {
		internalError(s, w, err)
		return
	}
	s.record(r, u, "oidc.token.revoke", c.Name+" ("+c.ID+")", audit.Success, "every sign-in at this app revoked by an administrator")
	writeJSON(w, http.StatusOK, map[string]int64{"revoked": n})
}

func clientSummary(c *oidc.Client) string {
	parts := []string{c.Kind, "redirects " + strings.Join(c.RedirectURIs, " ")}
	if len(c.AllowedGroups) > 0 {
		parts = append(parts, "groups "+strings.Join(c.AllowedGroups, ", "))
	}
	if c.FirstParty {
		parts = append(parts, "no consent screen")
	}
	if c.Disabled {
		parts = append(parts, "turned off")
	}
	return strings.Join(parts, "; ")
}

func writeOIDCError(s *Server, w http.ResponseWriter, err error) {
	var ve *oidc.ValidationError
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Code: "invalid", Message: ve.Error(), Details: ve.Problems})
	case errors.Is(err, oidc.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, oidc.ErrManaged):
		writeError(w, http.StatusConflict, "managed", err.Error())
	default:
		internalError(s, w, err)
	}
}
