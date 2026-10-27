package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/oidc"
	"github.com/hardyos/hardyos/daemon/internal/store"
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
		PublicOrigin:  publicOrigin,
		PublicLimiter: s.pubLimiter,
		EndSessions: func(ctx context.Context, id int64) {
			if s.sessions != nil {
				_ = s.sessions.RevokeUser(ctx, id)
			}
			s.proxy.endUser(id)
		},
		ManagedAccess: s.photosAccess,
		Insecure:      s.cfg.Insecure,
		Log:           s.log,
	})
	if err != nil {
		s.log.Error("sign-in provider unavailable", "err", err)
		return nil
	}
	return p
}

// oidcUser loads an account for the sign-in provider the way the desktop
// loads one behind a session: turned off or gone is an error, a domain
// account's groups are refreshed every 10 minutes (checking that the name
// still belongs to the same directory object) and one gone from the domain
// or replaced loses its desktop sessions too.
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
		s.endUserEverywhere(ctx, u.ID)
		return nil, err
	}
	if err != nil {
		s.log.Warn("refresh domain groups", "user", u.Username, "err", err)
		return u, nil
	}
	return nu, nil
}

// passwordSet: the directory says u's password was set at. What was signed
// in before (desktop sessions, HardyOS sign-in sessions, app sign-ins and
// with them published apps' sessions) ends: a password changed on a
// computer in the domain otherwise reaches HardyOS only here.
func (s *Server) passwordSet(ctx context.Context, u *auth.User, at time.Time) {
	var n int64
	if s.cfg.DB != nil {
		if res, err := s.cfg.DB.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND created_at < ?`, u.ID, store.FormatTime(at)); err == nil {
			n, _ = res.RowsAffected()
		}
	}
	if s.oidc != nil {
		n += s.oidc.PasswordSet(ctx, u.ID, at)
	}
	if n > 0 {
		s.recordSystem(ctx, "auth.session.end", u.Username, "the password was changed in the domain; sign-ins made before it ended")
	}
}

// desktopUser is who is signed in to the desktop in this browser (the
// provider on the desktop's host reuses it), without sliding the session.
func (s *Server) desktopUser(r *http.Request) (*auth.User, time.Time, bool) {
	token, ok := s.sessionToken(r)
	if !ok {
		return nil, time.Time{}, false
	}
	info, err := s.peekSession(r.Context(), token)
	if err != nil {
		return nil, time.Time{}, false
	}
	u, err := s.sessionUser(r, token, info.UserID)
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

// ---- changes run as jobs ------------------------------------------------------

// Sign-in (OIDC) job kinds: every change to the provider's settings,
// clients, secrets and keys is a job (in the job history) and audited. The
// request waits for its job (they're quick database changes) and answers
// as before; a new client secret travels from the job to that request in
// memory only, never in the job's parameters or result.
const (
	JobKindOIDCSettings     = "oidc.settings"
	JobKindOIDCRotate       = "oidc.keys.rotate"
	JobKindOIDCClientCreate = "oidc.client.create"
	JobKindOIDCClientUpdate = "oidc.client.update"
	JobKindOIDCClientDelete = "oidc.client.delete"
	JobKindOIDCClientSecret = "oidc.client.secret"
	JobKindOIDCClientRevoke = "oidc.client.revoke"
)

// oidcJobParams are a sign-in job's parameters. Wait names the request
// waiting for the outcome.
type oidcJobParams struct {
	Wait          string           `json:"wait"`
	Issuer        *string          `json:"issuer,omitempty"`
	LocalAccounts *bool            `json:"localAccounts,omitempty"`
	PublicAdmins  *bool            `json:"publicAdmins,omitempty"`
	ClientID      string           `json:"clientId,omitempty"`
	Spec          *oidc.ClientSpec `json:"spec,omitempty"`
}

// oidcJobOutcome is what a sign-in job hands its request (in memory).
type oidcJobOutcome struct {
	Client  *oidc.Client
	Secret  string
	Revoked int64
	Detail  string
}

type jobOutcome struct {
	val any
	err error
}

// jobWaits connects a job to the request waiting for it.
type jobWaits struct {
	mu sync.Mutex
	m  map[string]chan jobOutcome
}

func (w *jobWaits) add() (string, chan jobOutcome) {
	ref := randomToken()
	ch := make(chan jobOutcome, 1)
	w.mu.Lock()
	if w.m == nil {
		w.m = map[string]chan jobOutcome{}
	}
	w.m[ref] = ch
	w.mu.Unlock()
	return ref, ch
}

func (w *jobWaits) deliver(ref string, v any, err error) {
	w.mu.Lock()
	ch := w.m[ref]
	delete(w.m, ref)
	w.mu.Unlock()
	if ch != nil {
		ch <- jobOutcome{v, err}
	}
}

func (w *jobWaits) drop(ref string) {
	w.mu.Lock()
	delete(w.m, ref)
	w.mu.Unlock()
}

func (s *Server) registerOIDCJobs(m *jobs.Manager) {
	lock := func(json.RawMessage) string { return "oidc" }
	kind := func(name string, run func(ctx context.Context, p oidcJobParams) (*oidcJobOutcome, error)) {
		m.Register(jobs.Kind{Name: name, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
			var p oidcJobParams
			if err := jc.Params(&p); err != nil {
				return nil, err
			}
			out, err := run(jc, p)
			s.waits.deliver(p.Wait, out, err)
			if err != nil {
				return nil, err
			}
			// The result never carries a secret.
			res := map[string]any{}
			if out.Client != nil {
				res["clientId"], res["name"] = out.Client.ID, out.Client.Name
			}
			if out.Secret != "" {
				res["newSecret"] = true
			}
			if out.Detail != "" {
				res["detail"] = out.Detail
			}
			if name == JobKindOIDCClientRevoke {
				res["revoked"] = out.Revoked
			}
			return res, nil
		}})
	}
	kind(JobKindOIDCSettings, func(ctx context.Context, p oidcJobParams) (*oidcJobOutcome, error) {
		var notes []string
		if p.Issuer != nil {
			before := s.oidc.Issuer(ctx)
			if err := s.oidc.SetIssuer(ctx, *p.Issuer); err != nil {
				return nil, err
			}
			notes = append(notes, "issuer: "+before+" -> "+s.oidc.Issuer(ctx))
			if s.cfg.Remote != nil {
				s.remote.trigger() // sso.<base> follows the issuer
			}
		}
		if p.LocalAccounts != nil {
			if err := s.oidc.SetLocalAccounts(ctx, *p.LocalAccounts); err != nil {
				return nil, err
			}
			notes = append(notes, "HardyOS accounts may sign in to apps: "+boolWord(*p.LocalAccounts))
		}
		if p.PublicAdmins != nil {
			if err := s.oidc.SetPublicAdmins(ctx, *p.PublicAdmins); err != nil {
				return nil, err
			}
			notes = append(notes, "administrators may sign in through public HardyOS sign-in: "+boolWord(*p.PublicAdmins))
		}
		return &oidcJobOutcome{Detail: strings.Join(notes, "; ")}, nil
	})
	kind(JobKindOIDCRotate, func(ctx context.Context, _ oidcJobParams) (*oidcJobOutcome, error) {
		if err := s.oidc.CheckKeys(ctx, true); err != nil {
			return nil, errors.New("the signing keys can't be changed right now: " + err.Error())
		}
		return &oidcJobOutcome{Detail: "rotated by an administrator"}, nil
	})
	kind(JobKindOIDCClientCreate, func(ctx context.Context, p oidcJobParams) (*oidcJobOutcome, error) {
		if p.Spec == nil {
			return nil, errors.New("no client")
		}
		c, secret, err := s.oidc.Clients.Create(ctx, *p.Spec)
		if err != nil {
			return nil, err
		}
		return &oidcJobOutcome{Client: c, Secret: secret}, nil
	})
	kind(JobKindOIDCClientUpdate, func(ctx context.Context, p oidcJobParams) (*oidcJobOutcome, error) {
		if p.Spec == nil {
			return nil, errors.New("no client")
		}
		c, secret, err := s.oidc.Clients.Update(ctx, p.ClientID, *p.Spec)
		if err != nil {
			return nil, err
		}
		return &oidcJobOutcome{Client: c, Secret: secret}, nil
	})
	kind(JobKindOIDCClientDelete, func(ctx context.Context, p oidcJobParams) (*oidcJobOutcome, error) {
		c, err := s.oidc.Clients.Get(ctx, p.ClientID)
		if err != nil {
			return nil, err
		}
		if err := s.oidc.Clients.Delete(ctx, p.ClientID); err != nil {
			return nil, err
		}
		return &oidcJobOutcome{Client: c}, nil
	})
	kind(JobKindOIDCClientSecret, func(ctx context.Context, p oidcJobParams) (*oidcJobOutcome, error) {
		c, err := s.oidc.Clients.Get(ctx, p.ClientID)
		if err != nil {
			return nil, err
		}
		if c.ManagedBy != "" {
			return nil, oidc.ErrManaged
		}
		secret, err := s.oidc.Clients.NewSecret(ctx, p.ClientID)
		if err != nil {
			return nil, err
		}
		return &oidcJobOutcome{Client: c, Secret: secret}, nil
	})
	kind(JobKindOIDCClientRevoke, func(ctx context.Context, p oidcJobParams) (*oidcJobOutcome, error) {
		c, err := s.oidc.Clients.Get(ctx, p.ClientID)
		if err != nil {
			return nil, err
		}
		n, err := s.oidc.RevokeClient(ctx, p.ClientID)
		if err != nil {
			return nil, err
		}
		return &oidcJobOutcome{Client: c, Revoked: n}, nil
	})
}

// oidcJobWait is how long a request waits for its sign-in job.
const oidcJobWait = 30 * time.Second

// runOIDCJob runs a sign-in change as a job and waits for it. ok is false
// when the answer (an error, or 202 with the job when it takes too long)
// was already written.
func (s *Server) runOIDCJob(w http.ResponseWriter, r *http.Request, u *auth.User, kind, title string, p oidcJobParams) (*oidcJobOutcome, bool) {
	if !s.jobsReady(w) {
		return nil, false
	}
	ref, ch := s.waits.add()
	p.Wait = ref
	id := u.ID
	j, err := s.cfg.Jobs.Submit(r.Context(), kind, title, p, &id)
	if err != nil {
		s.waits.drop(ref)
		internalError(s, w, err)
		return nil, false
	}
	select {
	case out := <-ch:
		if out.err != nil {
			s.record(r, u, kind, title, audit.Failure, out.err.Error()+" (job "+j.ID+")")
			writeOIDCError(s, w, out.err)
			return nil, false
		}
		res, _ := out.val.(*oidcJobOutcome)
		if res == nil {
			res = &oidcJobOutcome{}
		}
		return res, true
	case <-time.After(oidcJobWait):
		s.waits.drop(ref)
		writeJSON(w, http.StatusAccepted, JobAccepted{Job: j, Warnings: []string{"still running; see the job"}})
		return nil, false
	case <-r.Context().Done():
		s.waits.drop(ref)
		return nil, false
	}
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
	// PublicAdmins lets administrators sign in through HardyOS sign-in from
	// the internet (off by default).
	PublicAdmins *bool `json:"publicAdmins"`
}

func (s *Server) handleOIDCSettings(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req oidcSettingsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Issuer == nil && req.LocalAccounts == nil && req.PublicAdmins == nil {
		s.handleOIDCStatus(w, r, u)
		return
	}
	out, ok := s.runOIDCJob(w, r, u, JobKindOIDCSettings, "Change HardyOS sign-in's settings",
		oidcJobParams{Issuer: req.Issuer, LocalAccounts: req.LocalAccounts, PublicAdmins: req.PublicAdmins})
	if !ok {
		return
	}
	target := "settings"
	switch {
	case req.Issuer != nil:
		target = "issuer"
	case req.LocalAccounts != nil:
		target = "local accounts"
	case req.PublicAdmins != nil:
		target = "public admins"
	}
	s.record(r, u, "oidc.settings", target, audit.Success, out.Detail)
	s.handleOIDCStatus(w, r, u)
}

func (s *Server) handleOIDCRotate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if _, ok := s.runOIDCJob(w, r, u, JobKindOIDCRotate, "Rotate the signing key", oidcJobParams{}); !ok {
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
	out, ok := s.runOIDCJob(w, r, u, JobKindOIDCClientCreate, "Add "+clip(spec.Name, 64)+" to HardyOS sign-in", oidcJobParams{Spec: &spec})
	if !ok {
		return
	}
	s.record(r, u, "oidc.client.create", out.Client.Name+" ("+out.Client.ID+")", audit.Success, clientSummary(out.Client))
	writeJSON(w, http.StatusCreated, oidcClientResult{Client: out.Client, Secret: out.Secret})
}

func (s *Server) handleOIDCUpdateClient(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var spec oidc.ClientSpec
	if !decodeJSON(w, r, &spec) {
		return
	}
	id := r.PathValue("id")
	out, ok := s.runOIDCJob(w, r, u, JobKindOIDCClientUpdate, "Change "+clip(spec.Name, 64)+" in HardyOS sign-in", oidcJobParams{ClientID: id, Spec: &spec})
	if !ok {
		return
	}
	s.record(r, u, "oidc.client.update", out.Client.Name+" ("+out.Client.ID+")", audit.Success, clientSummary(out.Client))
	writeJSON(w, http.StatusOK, oidcClientResult{Client: out.Client, Secret: out.Secret})
}

func (s *Server) handleOIDCDeleteClient(w http.ResponseWriter, r *http.Request, u *auth.User) {
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
	if _, ok := s.runOIDCJob(w, r, u, JobKindOIDCClientDelete, "Remove "+c.Name+" from HardyOS sign-in", oidcJobParams{ClientID: id}); !ok {
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
	out, ok := s.runOIDCJob(w, r, u, JobKindOIDCClientSecret, "New secret for "+c.Name, oidcJobParams{ClientID: id})
	if !ok {
		return
	}
	s.record(r, u, "oidc.client.secret", c.Name+" ("+c.ID+")", audit.Success, "new client secret; the old one stopped working")
	writeJSON(w, http.StatusOK, map[string]string{"secret": out.Secret})
}

func (s *Server) handleOIDCRevokeClient(w http.ResponseWriter, r *http.Request, u *auth.User) {
	id := r.PathValue("id")
	c, err := s.oidc.Clients.Get(r.Context(), id)
	if err != nil {
		writeOIDCError(s, w, err)
		return
	}
	out, ok := s.runOIDCJob(w, r, u, JobKindOIDCClientRevoke, "Sign everyone out of "+c.Name, oidcJobParams{ClientID: id})
	if !ok {
		return
	}
	s.record(r, u, "oidc.token.revoke", c.Name+" ("+c.ID+")", audit.Success, "every sign-in at this app revoked by an administrator")
	writeJSON(w, http.StatusOK, map[string]int64{"revoked": out.Revoked})
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
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
	case strings.HasPrefix(err.Error(), "the signing keys can't be changed"):
		writeError(w, http.StatusServiceUnavailable, "unavailable", err.Error())
	default:
		internalError(s, w, err)
	}
}
