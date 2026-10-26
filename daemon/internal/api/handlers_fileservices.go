package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/smb"
)

// File Services (SMB file server) job kinds.
const (
	JobKindFilesJoin     = "files.join"
	JobKindFilesLeave    = "files.leave"
	JobKindFilesSettings = "files.settings"
)

// filesJoinParams: the join request without its password (in jobSecrets).
type filesJoinParams struct {
	Domain      string `json:"domain,omitempty"`
	AdminUser   string `json:"adminUser,omitempty"`
	PasswordRef string `json:"passwordRef"`
}

// filesLeaveParams: PasswordRef is empty to only forget the domain here.
type filesLeaveParams struct {
	Domain      string `json:"domain"`
	AdminUser   string `json:"adminUser,omitempty"`
	PasswordRef string `json:"passwordRef,omitempty"`
}

func registerFileServiceJobs(m *jobs.Manager, pc *priv.Client) {
	lock := func(json.RawMessage) string { return "files" }
	lost := errors.New("the Administrator password was lost (HardyOS restarted); try again")
	m.Register(jobs.Kind{
		Name: JobKindFilesJoin, AdminOnly: true, LockKey: lock,
		Run: func(jc *jobs.Context) (any, error) {
			var p filesJoinParams
			if err := jc.Params(&p); err != nil {
				return nil, err
			}
			pw, ok := jobSecrets.take(p.PasswordRef)
			if !ok {
				return nil, lost
			}
			jc.Progress(10, "Joining the domain (about half a minute)")
			ctx, cancel := context.WithTimeout(jc, 5*time.Minute)
			defer cancel()
			var st smb.Status
			if err := pc.Call(ctx, priv.OpFilesJoin, smb.JoinArgs{Domain: p.Domain, AdminUser: p.AdminUser, AdminPassword: pw}, &st); err != nil {
				return nil, err
			}
			jc.Progress(100, "The shared folders can be opened from computers as \\\\"+st.ServerName)
			return st, nil
		},
	})
	m.Register(jobs.Kind{
		Name: JobKindFilesLeave, AdminOnly: true, LockKey: lock,
		Run: func(jc *jobs.Context) (any, error) {
			var p filesLeaveParams
			if err := jc.Params(&p); err != nil {
				return nil, err
			}
			pw := ""
			if p.PasswordRef != "" {
				var ok bool
				if pw, ok = jobSecrets.take(p.PasswordRef); !ok {
					return nil, lost
				}
			}
			jc.Progress(20, "Leaving "+p.Domain)
			ctx, cancel := context.WithTimeout(jc, 3*time.Minute)
			defer cancel()
			var st smb.Status
			if err := pc.Call(ctx, priv.OpFilesLeave, smb.LeaveArgs{Confirm: true, AdminUser: p.AdminUser, AdminPassword: pw}, &st); err != nil {
				return nil, err
			}
			return st, nil
		},
	})
	m.Register(jobs.Kind{
		Name: JobKindFilesSettings, AdminOnly: true, LockKey: lock,
		Run: func(jc *jobs.Context) (any, error) {
			var a smb.SettingsArgs
			if err := jc.Params(&a); err != nil {
				return nil, err
			}
			jc.Progress(20, "Saving the file services settings")
			ctx, cancel := context.WithTimeout(jc, 5*time.Minute)
			defer cancel()
			var st smb.Status
			if err := pc.Call(ctx, priv.OpFilesSettings, a, &st); err != nil {
				return nil, err
			}
			jc.Progress(100, "Saved")
			return st, nil
		},
	})
}

// joinFileServer joins this server's file server to the domain its own DC
// just created or joined, with the same password, inside that job. A
// failure doesn't fail the domain job: File Services offers the join.
func joinFileServer(jc *jobs.Context, pc *priv.Client, password string) {
	jc.Progress(95, "Sharing the shared folders with the domain's accounts")
	ctx, cancel := context.WithTimeout(jc, 5*time.Minute)
	defer cancel()
	var st smb.Status
	if err := pc.Call(ctx, priv.OpFilesStatus, nil, &st); err != nil || !st.Available || st.Joined {
		return
	}
	if err := pc.Call(ctx, priv.OpFilesJoin, smb.JoinArgs{AdminPassword: password}, &st); err != nil {
		jc.Progress(99, "The domain is ready, but the file server couldn't join it ("+err.Error()+"); join it from Control Panel > File Services")
	}
}

// leaveFileServer makes the file server forget a domain that was deleted.
func leaveFileServer(jc *jobs.Context, pc *priv.Client, dom string) {
	ctx, cancel := context.WithTimeout(jc, 2*time.Minute)
	defer cancel()
	var st smb.Status
	if err := pc.Call(ctx, priv.OpFilesStatus, nil, &st); err != nil || !st.Joined || st.Domain == nil || !strings.EqualFold(st.Domain.Domain, dom) {
		return
	}
	_ = pc.Call(ctx, priv.OpFilesLeave, smb.LeaveArgs{Confirm: true}, nil)
}

func (s *Server) fileServiceRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/files", s.authed(s.handleFilesStatus))
	m.Handle("POST /api/v1/files/join", s.admin(s.handleFilesJoin))
	m.Handle("POST /api/v1/files/leave", s.admin(s.handleFilesLeave))
	m.Handle("PATCH /api/v1/files/settings", s.admin(s.handleFilesSettings))
}

func (s *Server) filesStatus(w http.ResponseWriter, r *http.Request) (*smb.Status, bool) {
	var st smb.Status
	if err := s.cfg.Priv.Call(r.Context(), priv.OpFilesStatus, nil, &st); err != nil {
		s.writePrivError(w, err)
		return nil, false
	}
	return &st, true
}

// handleFilesStatus: everyone signed in sees how to connect; settings and
// per-folder details are for administrators.
func (s *Server) handleFilesStatus(w http.ResponseWriter, r *http.Request, u *auth.User) {
	st, ok := s.filesStatus(w, r)
	if !ok {
		return
	}
	if !u.IsAdmin() {
		st.Settings = smb.Settings{SMBEnabled: st.Settings.SMBEnabled, Homes: smb.HomesSettings{Enabled: st.Settings.Homes.Enabled}}
		st.Problem = ""
		for i := range st.Shares {
			st.Shares[i].Skipped = []string{}
		}
		if st.Domain != nil {
			st.Domain.DCs, st.Domain.AdminsGroupSID = nil, ""
		}
	}
	writeJSON(w, http.StatusOK, st)
}

type filesJoinRequest struct {
	Domain        string `json:"domain"`
	AdminUser     string `json:"adminUser"`
	AdminPassword string `json:"adminPassword"`
}

func (s *Server) handleFilesJoin(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req filesJoinRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.AdminPassword == "" {
		writeError(w, http.StatusBadRequest, "invalid", "enter the domain's Administrator password")
		return
	}
	st, ok := s.filesStatus(w, r)
	if !ok {
		return
	}
	if !st.Available {
		writeError(w, http.StatusConflict, "unavailable", "this HardyOS build doesn't include the SMB file server")
		return
	}
	if st.Joined {
		writeError(w, http.StatusConflict, "exists", "this server is already a member of "+st.Domain.Domain+"; leave it first")
		return
	}
	dom := strings.TrimSpace(req.Domain)
	if dom != "" {
		d, err := smb.NormalizeDomain(dom)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid", err.Error())
			return
		}
		dom = d
	} else if st.LocalDomain == "" {
		writeError(w, http.StatusBadRequest, "invalid", "enter the domain's name")
		return
	}
	target := dom
	if target == "" {
		target = st.LocalDomain
	}
	p := filesJoinParams{Domain: dom, AdminUser: strings.TrimSpace(req.AdminUser), PasswordRef: jobSecrets.put(req.AdminPassword)}
	s.submit(w, r, u, JobKindFilesJoin, "Join "+target+" for file sharing", p, "files.join", target, nil)
}

type filesLeaveRequest struct {
	Confirm       bool   `json:"confirm"`
	AdminUser     string `json:"adminUser"`
	AdminPassword string `json:"adminPassword"`
}

func (s *Server) handleFilesLeave(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req filesLeaveRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !req.Confirm {
		writeError(w, http.StatusBadRequest, "confirm_required", "confirm must be true: the shared folders stop being reachable from computers")
		return
	}
	st, ok := s.filesStatus(w, r)
	if !ok {
		return
	}
	if !st.Joined || st.Domain == nil {
		writeError(w, http.StatusConflict, "not_joined", "this server isn't a member of a domain")
		return
	}
	p := filesLeaveParams{Domain: st.Domain.Domain, AdminUser: strings.TrimSpace(req.AdminUser)}
	detail := st.Domain.Domain + " (computer account kept)"
	if req.AdminPassword != "" {
		p.PasswordRef = jobSecrets.put(req.AdminPassword)
		detail = st.Domain.Domain
	}
	s.submit(w, r, u, JobKindFilesLeave, "Leave "+st.Domain.Domain+" (file sharing)", p, "files.leave", detail, nil)
}

func (s *Server) handleFilesSettings(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req smb.SettingsArgs
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.SMBEnabled == nil && req.Homes == nil && req.SFTPEnabled == nil && req.WebDAVEnabled == nil {
		writeError(w, http.StatusBadRequest, "invalid", "nothing to change")
		return
	}
	if req.Homes != nil && req.Homes.Enabled && strings.TrimSpace(req.Homes.Pool) == "" {
		writeError(w, http.StatusBadRequest, "invalid", "choose a pool for the home folders")
		return
	}
	var parts []string
	if req.SMBEnabled != nil {
		parts = append(parts, "smb="+map[bool]string{true: "on", false: "off"}[*req.SMBEnabled])
	}
	if req.SFTPEnabled != nil {
		parts = append(parts, "sftp="+map[bool]string{true: "on", false: "off"}[*req.SFTPEnabled])
	}
	if req.WebDAVEnabled != nil {
		parts = append(parts, "webdav="+map[bool]string{true: "on", false: "off"}[*req.WebDAVEnabled])
	}
	if req.Homes != nil {
		parts = append(parts, "homes="+map[bool]string{true: "on:" + req.Homes.Pool, false: "off"}[req.Homes.Enabled])
	}
	s.submit(w, r, u, JobKindFilesSettings, "Change the file services settings", req, "files.settings", strings.Join(parts, " "), nil)
}
