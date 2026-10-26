package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/nfs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/snapshots"
)

// Shared folder snapshot job kinds.
const (
	JobKindSnapshotsCreate = "snapshots.create"
	JobKindSnapshotsDelete = "snapshots.delete"
)

// registerSnapshotJobs adds the snapshot jobs. They share the shared
// folders' lock, so a folder isn't deleted while it's being snapshotted.
func registerSnapshotJobs(m *jobs.Manager, pc *priv.Client) {
	lock := func(json.RawMessage) string { return "shares" }
	call := func(jc *jobs.Context, op, msg string, args, out any) error {
		jc.Progress(20, msg)
		ctx, cancel := context.WithTimeout(jc, 2*time.Minute)
		defer cancel()
		return pc.Call(ctx, op, args, out)
	}
	m.Register(jobs.Kind{
		Name: JobKindSnapshotsCreate, AdminOnly: true, LockKey: lock,
		Run: func(jc *jobs.Context) (any, error) {
			var a priv.SnapshotsCreateArgs
			if err := jc.Params(&a); err != nil {
				return nil, err
			}
			var sn snapshots.Snapshot
			if err := call(jc, priv.OpSnapshotsCreate, "Taking a snapshot", a, &sn); err != nil {
				return nil, err
			}
			jc.Progress(100, "Snapshot "+sn.Name+" taken")
			return sn, nil
		},
	})
	m.Register(jobs.Kind{
		Name: JobKindSnapshotsDelete, AdminOnly: true, LockKey: lock,
		Run: func(jc *jobs.Context) (any, error) {
			var a priv.SnapshotsDeleteArgs
			if err := jc.Params(&a); err != nil {
				return nil, err
			}
			if err := call(jc, priv.OpSnapshotsDelete, "Deleting the snapshot "+a.Snapshot, a, nil); err != nil {
				return nil, err
			}
			return map[string]string{"deleted": a.Snapshot}, nil
		},
	})
}

func (s *Server) snapshotRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/shares/{id}/snapshots", s.authed(s.handleShareSnapshots))
	m.Handle("POST /api/v1/shares/{id}/snapshots", s.admin(s.handleShareSnapshotCreate))
	m.Handle("DELETE /api/v1/shares/{id}/snapshots/{snapshot}", s.admin(s.handleShareSnapshotDelete))
	m.Handle("GET /api/v1/shares/{id}/nfs", s.admin(s.handleShareNFS))
}

// canUseShare reports whether a person may use a shared folder: always
// for administrators; otherwise a matching read or write rule and no
// matching "none" rule (none wins, as SMB's invalid users do), or guest
// access on the folder.
func canUseShare(sh *shares.Share, who auth.Identity) bool {
	if who.IsAdmin() {
		return true
	}
	allowed := false
	for _, r := range sh.Access {
		if !who.Matches(r.Kind, r.Name) {
			continue
		}
		if r.Level == shares.LevelNone {
			return false
		}
		allowed = true
	}
	return allowed || sh.Guest
}

func (s *Server) handleShareSnapshots(w http.ResponseWriter, r *http.Request, u *auth.User) {
	sh, _, ok := s.findShare(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	if !canUseShare(sh, u) {
		// Same answer as a folder that doesn't exist.
		writeError(w, http.StatusNotFound, "not_found", shares.ErrNotFound.Error())
		return
	}
	var res priv.SnapshotsResult
	if !s.callPriv(w, r, priv.OpSnapshotsList, priv.SnapshotsListArgs{Share: sh.ID}, &res) {
		return
	}
	if res.Snapshots == nil {
		res.Snapshots = []snapshots.Snapshot{}
	}
	writeJSON(w, http.StatusOK, res)
}

type snapshotCreateRequest struct {
	Name string `json:"name"`
}

func (s *Server) handleShareSnapshotCreate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req snapshotCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	name, err := snapshots.CleanName(req.Name, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid", validationMessage(err))
		return
	}
	sh, _, ok := s.findShare(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	s.submit(w, r, u, JobKindSnapshotsCreate, "Take a snapshot of "+sh.Name,
		priv.SnapshotsCreateArgs{Share: sh.ID, Name: name}, "shares.snapshot.create", sh.ID+"@"+name, nil)
}

type snapshotDeleteRequest struct {
	Confirm string `json:"confirm"`
}

func (s *Server) handleShareSnapshotDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req snapshotDeleteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	snap := r.PathValue("snapshot")
	if snap == "" || strings.TrimSpace(req.Confirm) != snap {
		writeError(w, http.StatusBadRequest, "confirm_required", "confirm with the snapshot's name ("+snap+"): what only it holds is gone for good")
		return
	}
	sh, _, ok := s.findShare(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	s.submit(w, r, u, JobKindSnapshotsDelete, "Delete the snapshot "+snap+" of "+sh.Name,
		priv.SnapshotsDeleteArgs{Share: sh.ID, Snapshot: snap, Confirm: snap}, "shares.snapshot.delete", sh.ID+"@"+snap, nil)
}

// ShareNFS is how a shared folder is reached over NFS.
type ShareNFS struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
	// UID is the folder's NFS identity (0 until NFS is first turned on).
	UID     int    `json:"uid"`
	Running bool   `json:"running"`
	Problem string `json:"problem,omitempty"`
}

func (s *Server) handleShareNFS(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	sh, _, ok := s.findShare(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	var st nfs.Status
	if !s.callPriv(w, r, priv.OpNFSStatus, nil, &st) {
		return
	}
	res := ShareNFS{Enabled: sh.Services.NFS.Enabled, Path: sh.Path, UID: st.UIDs[sh.ID], Running: st.Running, Problem: st.Problem}
	writeJSON(w, http.StatusOK, res)
}

// callPriv calls the root helper and answers the error itself.
func (s *Server) callPriv(w http.ResponseWriter, r *http.Request, op string, args, out any) bool {
	if err := s.cfg.Priv.Call(r.Context(), op, args, out); err != nil {
		s.writePrivError(w, err)
		return false
	}
	return true
}
