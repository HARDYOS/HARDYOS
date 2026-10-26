package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/domain"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// Domain job kinds.
const (
	JobKindDomainProvision = "domain.provision"
	JobKindDomainDestroy   = "domain.destroy"
)

// jobSecrets hands a password from a request to the job it starts without
// putting it in the job's parameters (those are kept in the job history).
// A secret lives only in memory, is read once, and expires.
var jobSecrets = &secretBox{m: map[string]secret{}}

type secret struct {
	value   string
	expires time.Time
}

type secretBox struct {
	mu sync.Mutex
	m  map[string]secret
}

func (b *secretBox) put(v string) string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	ref := hex.EncodeToString(buf)
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	for k, s := range b.m {
		if now.After(s.expires) {
			delete(b.m, k)
		}
	}
	b.m[ref] = secret{value: v, expires: now.Add(10 * time.Minute)}
	return ref
}

func (b *secretBox) take(ref string) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.m[ref]
	delete(b.m, ref)
	if !ok || time.Now().After(s.expires) {
		return "", false
	}
	return s.value, true
}

// domainProvisionParams are the provision job's parameters: the request
// without its password, which waits in jobSecrets.
type domainProvisionParams struct {
	domain.ProvisionArgs
	PasswordRef string `json:"passwordRef"`
}

type domainDestroyParams struct {
	Domain string `json:"domain"`
}

func registerDomainJobs(m *jobs.Manager, pc *priv.Client) {
	m.Register(jobs.Kind{
		Name:      JobKindDomainProvision,
		AdminOnly: true,
		LockKey:   func(json.RawMessage) string { return "domain" },
		Run: func(jc *jobs.Context) (any, error) {
			var p domainProvisionParams
			if err := jc.Params(&p); err != nil {
				return nil, err
			}
			pw, ok := jobSecrets.take(p.PasswordRef)
			if !ok {
				return nil, errors.New("the Administrator password was lost (HardyOS restarted); start the setup again")
			}
			args := p.ProvisionArgs
			args.AdminPassword = pw
			jc.Progress(10, "Creating the domain database (this takes about half a minute)")
			ctx, cancel := context.WithTimeout(jc, 8*time.Minute)
			defer cancel()
			var c domain.Config
			if err := pc.Call(ctx, priv.OpDomainProvision, args, &c); err != nil {
				return nil, err
			}
			jc.Progress(100, "The domain controller is running")
			return c, nil
		},
	})
	m.Register(jobs.Kind{
		Name:      JobKindDomainDestroy,
		AdminOnly: true,
		LockKey:   func(json.RawMessage) string { return "domain" },
		Run: func(jc *jobs.Context) (any, error) {
			var p domainDestroyParams
			if err := jc.Params(&p); err != nil {
				return nil, err
			}
			jc.Progress(20, "Stopping the domain controller and deleting the domain")
			ctx, cancel := context.WithTimeout(jc, 3*time.Minute)
			defer cancel()
			if err := pc.Call(ctx, priv.OpDomainDestroy, priv.DomainDestroyArgs{Confirm: p.Domain}, nil); err != nil {
				return nil, err
			}
			return map[string]string{"deleted": p.Domain}, nil
		},
	})
}

func (s *Server) domainRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/domain", s.admin(s.handleDomainStatus))
	m.Handle("GET /api/v1/domain/suggest", s.admin(s.handleDomainSuggest))
	m.Handle("POST /api/v1/domain", s.admin(s.handleDomainProvision))
	m.Handle("DELETE /api/v1/domain", s.admin(s.handleDomainDestroy))
	m.Handle("PUT /api/v1/domain/enabled", s.admin(s.handleDomainEnable))

	m.Handle("GET /api/v1/domain/users", s.admin(s.handleDomainUsers))
	m.Handle("POST /api/v1/domain/users", s.admin(s.handleDomainUserCreate))
	m.Handle("PATCH /api/v1/domain/users/{username}", s.admin(s.handleDomainUserUpdate))
	m.Handle("POST /api/v1/domain/users/{username}/password", s.admin(s.handleDomainUserPassword))
	m.Handle("PUT /api/v1/domain/users/{username}/enabled", s.admin(s.handleDomainUserEnable))
	m.Handle("DELETE /api/v1/domain/users/{username}", s.admin(s.handleDomainUserDelete))

	m.Handle("GET /api/v1/domain/groups", s.admin(s.handleDomainGroups))
	m.Handle("POST /api/v1/domain/groups", s.admin(s.handleDomainGroupCreate))
	m.Handle("PATCH /api/v1/domain/groups/{name}", s.admin(s.handleDomainGroupUpdate))
	m.Handle("DELETE /api/v1/domain/groups/{name}", s.admin(s.handleDomainGroupDelete))
}

func (s *Server) handleDomainStatus(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var st domain.Status
	if err := s.cfg.Priv.Call(r.Context(), priv.OpDomainStatus, nil, &st); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleDomainSuggest(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	var sg domain.Suggestion
	if err := s.cfg.Priv.Call(ctx, priv.OpDomainSuggest, nil, &sg); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sg)
}

func (s *Server) handleDomainProvision(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var a domain.ProvisionArgs
	if !decodeJSON(w, r, &a) {
		return
	}
	// Catch the quick mistakes before a long job.
	d, err := domain.NormalizeDomain(a.Domain)
	if err == nil && a.NetBIOS != "" {
		_, err = domain.NormalizeNetBIOS(a.NetBIOS)
	}
	if err == nil {
		err = domain.CheckPassword(a.AdminPassword, "Administrator")
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	var st domain.Status
	if err := s.cfg.Priv.Call(r.Context(), priv.OpDomainStatus, nil, &st); err != nil {
		s.writePrivError(w, err)
		return
	}
	if !st.Available {
		writeError(w, http.StatusConflict, "unavailable", "this HardyOS build doesn't include the domain controller")
		return
	}
	if st.Provisioned {
		writeError(w, http.StatusConflict, "exists", "a domain ("+st.Config.Domain+") already exists")
		return
	}
	p := domainProvisionParams{ProvisionArgs: a, PasswordRef: jobSecrets.put(a.AdminPassword)}
	p.AdminPassword = ""
	p.Domain = d
	s.submit(w, r, u, JobKindDomainProvision, "Create the domain "+d, p, "domain.provision", d, nil)
}

type domainDestroyRequest struct {
	Confirm string `json:"confirm"`
}

func (s *Server) handleDomainDestroy(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req domainDestroyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	var st domain.Status
	if err := s.cfg.Priv.Call(r.Context(), priv.OpDomainStatus, nil, &st); err != nil {
		s.writePrivError(w, err)
		return
	}
	if !st.Provisioned {
		writeError(w, http.StatusNotFound, "not_found", domain.ErrNotProvisioned.Error())
		return
	}
	if req.Confirm == "" || !strings.EqualFold(strings.TrimSpace(req.Confirm), st.Config.Domain) {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the domain name ("+st.Config.Domain+") to confirm: every account, group and joined computer is deleted")
		return
	}
	s.submit(w, r, u, JobKindDomainDestroy, "Delete the domain "+st.Config.Domain,
		domainDestroyParams{Domain: st.Config.Domain}, "domain.destroy", st.Config.Domain, nil)
}

func (s *Server) handleDomainEnable(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req priv.DomainEnableArgs
	if !decodeJSON(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	var st domain.Status
	action := "domain.stop"
	if req.Enabled {
		action = "domain.start"
	}
	if err := s.cfg.Priv.Call(ctx, priv.OpDomainEnable, req, &st); err != nil {
		s.record(r, u, action, "", audit.Failure, err.Error())
		s.writePrivError(w, err)
		return
	}
	s.record(r, u, action, domainName(&st), audit.Success, "")
	writeJSON(w, http.StatusOK, st)
}

func domainName(st *domain.Status) string {
	if st != nil && st.Config != nil {
		return st.Config.Domain
	}
	return ""
}

// domainCall runs a directory change and records it (never the password).
func (s *Server) domainCall(w http.ResponseWriter, r *http.Request, u *auth.User, op, action, target string, args, out any, status int) {
	if err := s.cfg.Priv.Call(r.Context(), op, args, out); err != nil {
		s.record(r, u, action, target, audit.Failure, err.Error())
		s.writePrivError(w, err)
		return
	}
	s.record(r, u, action, target, audit.Success, "")
	if out == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, status, out)
}

func (s *Server) handleDomainUsers(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var res priv.DomainUsersResult
	if err := s.cfg.Priv.Call(r.Context(), priv.OpDomainUsers, nil, &res); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDomainUserCreate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req domain.NewUser
	if !decodeJSON(w, r, &req) {
		return
	}
	var out domain.User
	s.domainCall(w, r, u, priv.OpDomainUserCreate, "domain.user.create", req.Username, req, &out, http.StatusCreated)
}

func (s *Server) handleDomainUserUpdate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req domain.UserUpdate
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Username = r.PathValue("username")
	var out domain.User
	s.domainCall(w, r, u, priv.OpDomainUserUpdate, "domain.user.update", req.Username, req, &out, http.StatusOK)
}

type domainPasswordRequest struct {
	Password           string `json:"password"`
	MustChangePassword bool   `json:"mustChangePassword"`
}

func (s *Server) handleDomainUserPassword(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req domainPasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	name := r.PathValue("username")
	var out domain.User
	s.domainCall(w, r, u, priv.OpDomainUserPassword, "domain.user.password", name,
		domain.PasswordReset{Username: name, Password: req.Password, MustChangePassword: req.MustChangePassword}, &out, http.StatusOK)
}

type enabledRequest struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) handleDomainUserEnable(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req enabledRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	name := r.PathValue("username")
	var out domain.User
	s.domainCall(w, r, u, priv.OpDomainUserEnable, "domain.user.enabled", name,
		priv.DomainUserEnableArgs{Username: name, Enabled: req.Enabled}, &out, http.StatusOK)
}

func (s *Server) handleDomainUserDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	name := r.PathValue("username")
	s.domainCall(w, r, u, priv.OpDomainUserDelete, "domain.user.delete", name, priv.DomainUserRef{Username: name}, nil, 0)
}

func (s *Server) handleDomainGroups(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var res priv.DomainGroupsResult
	if err := s.cfg.Priv.Call(r.Context(), priv.OpDomainGroups, nil, &res); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDomainGroupCreate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req domain.NewGroup
	if !decodeJSON(w, r, &req) {
		return
	}
	var out domain.Group
	s.domainCall(w, r, u, priv.OpDomainGroupCreate, "domain.group.create", req.Name, req, &out, http.StatusCreated)
}

func (s *Server) handleDomainGroupUpdate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req domain.GroupUpdate
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = r.PathValue("name")
	var out domain.Group
	s.domainCall(w, r, u, priv.OpDomainGroupUpdate, "domain.group.update", req.Name, req, &out, http.StatusOK)
}

func (s *Server) handleDomainGroupDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	name := r.PathValue("name")
	s.domainCall(w, r, u, priv.OpDomainGroupDelete, "domain.group.delete", name, priv.DomainGroupRef{Name: name}, nil, 0)
}
