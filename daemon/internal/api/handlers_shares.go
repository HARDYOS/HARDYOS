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
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// Shared folder job kinds.
const (
	JobKindSharesCreate  = "shares.create"
	JobKindSharesUpdate  = "shares.update"
	JobKindSharesDelete  = "shares.delete"
	JobKindSharesStarter = "shares.starter"
)

// registerShareJobs adds the shared folder jobs. They run one at a time.
func registerShareJobs(m *jobs.Manager, pc *priv.Client) {
	lock := func(json.RawMessage) string { return "shares" }
	call := func(jc *jobs.Context, op, msg string, args, out any) error {
		jc.Progress(20, msg)
		ctx, cancel := context.WithTimeout(jc, 2*time.Minute)
		defer cancel()
		return pc.Call(ctx, op, args, out)
	}
	m.Register(jobs.Kind{
		Name: JobKindSharesCreate, AdminOnly: true, LockKey: lock,
		Run: func(jc *jobs.Context) (any, error) {
			var a shares.NewShare
			if err := jc.Params(&a); err != nil {
				return nil, err
			}
			var sh shares.Share
			if err := call(jc, priv.OpSharesCreate, "Creating "+a.Name, a, &sh); err != nil {
				return nil, err
			}
			jc.Progress(100, sh.Name+" is ready")
			return sh, nil
		},
	})
	m.Register(jobs.Kind{
		Name: JobKindSharesUpdate, AdminOnly: true, LockKey: lock,
		Run: func(jc *jobs.Context) (any, error) {
			var a shares.ShareUpdate
			if err := jc.Params(&a); err != nil {
				return nil, err
			}
			var sh shares.Share
			if err := call(jc, priv.OpSharesUpdate, "Saving the shared folder's settings", a, &sh); err != nil {
				return nil, err
			}
			jc.Progress(100, "Saved")
			return sh, nil
		},
	})
	m.Register(jobs.Kind{
		Name: JobKindSharesDelete, AdminOnly: true, LockKey: lock,
		Run: func(jc *jobs.Context) (any, error) {
			var a priv.ShareDeleteArgs
			if err := jc.Params(&a); err != nil {
				return nil, err
			}
			if err := call(jc, priv.OpSharesDelete, "Deleting "+a.Confirm+" and its files", a, nil); err != nil {
				return nil, err
			}
			return map[string]string{"deleted": a.ID}, nil
		},
	})
	m.Register(jobs.Kind{
		Name: JobKindSharesStarter, AdminOnly: true, LockKey: lock,
		Run: func(jc *jobs.Context) (any, error) {
			var a shares.StarterArgs
			if err := jc.Params(&a); err != nil {
				return nil, err
			}
			var res priv.SharesResult
			if err := call(jc, priv.OpSharesStarter, "Creating the starter shared folders on "+a.Pool, a, &res); err != nil {
				return nil, err
			}
			jc.Progress(100, "The shared folders are ready")
			return res, nil
		},
	})
}

func (s *Server) shareRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/shares", s.authed(s.handleShares))
	m.Handle("POST /api/v1/shares", s.admin(s.handleShareCreate))
	m.Handle("POST /api/v1/shares/starter", s.admin(s.handleShareStarter))
	m.Handle("GET /api/v1/shares/{id}", s.authed(s.handleShare))
	m.Handle("PATCH /api/v1/shares/{id}", s.admin(s.handleShareUpdate))
	m.Handle("DELETE /api/v1/shares/{id}", s.admin(s.handleShareDelete))
	m.Handle("GET /api/v1/shares/{id}/folders", s.admin(s.handleShareFolders))
}

func (s *Server) listShares(ctx context.Context) ([]shares.Share, error) {
	var res priv.SharesResult
	if err := s.cfg.Priv.Call(ctx, priv.OpSharesList, nil, &res); err != nil {
		return nil, err
	}
	if res.Shares == nil {
		res.Shares = []shares.Share{}
	}
	return res.Shares, nil
}

// findShare answers 404 itself when the share doesn't exist.
func (s *Server) findShare(w http.ResponseWriter, r *http.Request, id string) (*shares.Share, []shares.Share, bool) {
	l, err := s.listShares(r.Context())
	if err != nil {
		s.writePrivError(w, err)
		return nil, nil, false
	}
	for i := range l {
		if l[i].ID == id {
			return &l[i], l, true
		}
	}
	writeError(w, http.StatusNotFound, "not_found", shares.ErrNotFound.Error())
	return nil, nil, false
}

// shareForUser hides the access rules, apps and storage details from
// people who aren't administrators.
func shareForUser(sh shares.Share, u *auth.User) shares.Share {
	if u.IsAdmin() {
		return sh
	}
	sh.Access, sh.Apps = []shares.Rule{}, []shares.AppGrant{}
	sh.Dataset, sh.Pool = "", ""
	return sh
}

func (s *Server) handleShares(w http.ResponseWriter, r *http.Request, u *auth.User) {
	l, err := s.listShares(r.Context())
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	for i := range l {
		l[i] = shareForUser(l[i], u)
	}
	writeJSON(w, http.StatusOK, priv.SharesResult{Shares: l})
}

func (s *Server) handleShare(w http.ResponseWriter, r *http.Request, u *auth.User) {
	sh, _, ok := s.findShare(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, shareForUser(*sh, u))
}

func validationMessage(err error) string {
	var ve *shares.ValidationError
	if errors.As(err, &ve) {
		return ve.Msg
	}
	return err.Error()
}

func (s *Server) handleShareCreate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req shares.NewShare
	if !decodeJSON(w, r, &req) {
		return
	}
	a, err := shares.CheckNew(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid", validationMessage(err))
		return
	}
	l, err := s.listShares(r.Context())
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	for _, sh := range l {
		if sh.ID == a.ID {
			writeError(w, http.StatusConflict, "exists", "there's already a shared folder with the id "+a.ID+" ("+sh.Name+")")
			return
		}
		if strings.EqualFold(sh.Name, a.Name) {
			writeError(w, http.StatusConflict, "exists", "there's already a shared folder called "+sh.Name)
			return
		}
	}
	s.submit(w, r, u, JobKindSharesCreate, "Create the shared folder "+a.Name, a, "shares.create", a.ID, nil)
}

func (s *Server) handleShareStarter(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req shares.StarterArgs
	if !decodeJSON(w, r, &req) {
		return
	}
	if !req.Media && !req.Backups {
		writeError(w, http.StatusBadRequest, "invalid", "choose at least one of the starter folders")
		return
	}
	if err := zfs.ValidPoolName(req.Pool); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", "choose a pool for the shared folders")
		return
	}
	var names []string
	if req.Media {
		names = append(names, "media")
	}
	if req.Backups {
		names = append(names, "backups")
	}
	s.submit(w, r, u, JobKindSharesStarter, "Create the starter shared folders", req, "shares.starter", req.Pool+": "+strings.Join(names, ", "), nil)
}

func (s *Server) handleShareUpdate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req shares.ShareUpdate
	if !decodeJSON(w, r, &req) {
		return
	}
	req.ID = r.PathValue("id")
	if req.Name != nil {
		n, err := shares.CleanName(*req.Name)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid", validationMessage(err))
			return
		}
		req.Name = &n
	}
	if req.Access != nil {
		rules, err := shares.CleanRules(*req.Access)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid", validationMessage(err))
			return
		}
		req.Access = &rules
	}
	sh, l, ok := s.findShare(w, r, req.ID)
	if !ok {
		return
	}
	if req.Name != nil {
		for _, o := range l {
			if o.ID != sh.ID && strings.EqualFold(o.Name, *req.Name) {
				writeError(w, http.StatusConflict, "exists", "there's already a shared folder called "+o.Name)
				return
			}
		}
	}
	s.submit(w, r, u, JobKindSharesUpdate, "Change the shared folder "+sh.Name, req, "shares.update", sh.ID, nil)
}

type shareDeleteRequest struct {
	Confirm string `json:"confirm"`
}

func (s *Server) handleShareDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req shareDeleteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	sh, _, ok := s.findShare(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	if !strings.EqualFold(strings.Join(strings.Fields(req.Confirm), " "), sh.Name) {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the shared folder's name ("+sh.Name+") to confirm: every file in it is deleted")
		return
	}
	if len(sh.Apps) > 0 {
		apps := make([]string, 0, len(sh.Apps))
		for _, g := range sh.Apps {
			apps = append(apps, g.App)
		}
		writeError(w, http.StatusConflict, "in_use", sh.Name+" is used by "+strings.Join(apps, ", ")+"; take it away from those apps first")
		return
	}
	s.submit(w, r, u, JobKindSharesDelete, "Delete the shared folder "+sh.Name,
		priv.ShareDeleteArgs{ID: sh.ID, Confirm: sh.Name}, "shares.delete", sh.ID, nil)
}

func (s *Server) handleShareFolders(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var res priv.ShareFoldersResult
	args := priv.ShareFoldersArgs{ID: r.PathValue("id"), Path: r.URL.Query().Get("path")}
	if err := s.cfg.Priv.Call(r.Context(), priv.OpSharesFolders, args, &res); err != nil {
		var pe *priv.Error
		if errors.As(err, &pe) && pe.Message == shares.ErrNotFound.Error() {
			writeError(w, http.StatusNotFound, "not_found", pe.Message)
			return
		}
		s.writePrivError(w, err)
		return
	}
	if res.Folders == nil {
		res.Folders = []string{}
	}
	writeJSON(w, http.StatusOK, res)
}
