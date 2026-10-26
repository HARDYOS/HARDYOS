package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// Boot disk job kinds.
const (
	JobKindBootReplace = "storage.boot.replace"
	JobKindBootAttach  = "storage.boot.attach"
	JobKindBootDetach  = "storage.boot.detach"
)

func registerBootJobs(m *jobs.Manager, pc *priv.Client) {
	lock := func(json.RawMessage) string { return "boot-disks" }
	run := func(op, msg string, args func(*jobs.Context) (any, error)) func(*jobs.Context) (any, error) {
		return func(jc *jobs.Context) (any, error) {
			a, err := args(jc)
			if err != nil {
				return nil, err
			}
			jc.Progress(10, msg)
			ctx, cancel := context.WithTimeout(jc, 15*time.Minute)
			defer cancel()
			var st zfs.Status
			if err := pc.Call(ctx, op, a, &st); err != nil {
				return nil, err
			}
			return st, nil
		}
	}
	m.Register(jobs.Kind{Name: JobKindBootReplace, AdminOnly: true, LockKey: lock, Run: run(priv.OpBootReplace,
		"Partitioning the new disk and installing the boot loader",
		func(jc *jobs.Context) (any, error) {
			var a priv.BootReplaceArgs
			return a, jc.Params(&a)
		})})
	m.Register(jobs.Kind{Name: JobKindBootAttach, AdminOnly: true, LockKey: lock, Run: run(priv.OpBootAttach,
		"Partitioning the new disk and installing the boot loader",
		func(jc *jobs.Context) (any, error) {
			var a priv.BootAttachArgs
			return a, jc.Params(&a)
		})})
	m.Register(jobs.Kind{Name: JobKindBootDetach, AdminOnly: true, LockKey: lock, Run: run(priv.OpBootDetach,
		"Removing the disk from the boot mirror",
		func(jc *jobs.Context) (any, error) {
			var a priv.BootDetachArgs
			return a, jc.Params(&a)
		})})
}

func (s *Server) bootRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/storage/boot", s.admin(s.handleBootDisks))
	m.Handle("POST /api/v1/storage/boot/replace", s.admin(s.handleBootReplace))
	m.Handle("POST /api/v1/storage/boot/attach", s.admin(s.handleBootAttach))
	m.Handle("POST /api/v1/storage/boot/detach", s.admin(s.handleBootDetach))
}

func (s *Server) handleBootDisks(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var res priv.BootDisksResult
	if err := s.cfg.Priv.Call(r.Context(), priv.OpBootDisks, nil, &res); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleBootReplace(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var a priv.BootReplaceArgs
	if !decodeJSON(w, r, &a) {
		return
	}
	if !a.ConfirmWipe {
		writeError(w, http.StatusBadRequest, "invalid", "confirmWipe must be true: the new disk will be erased")
		return
	}
	s.submit(w, r, u, JobKindBootReplace, "Replace a boot disk", a, "storage.boot.replace", a.Old+" -> "+a.Disk, nil)
}

func (s *Server) handleBootAttach(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var a priv.BootAttachArgs
	if !decodeJSON(w, r, &a) {
		return
	}
	if !a.ConfirmWipe {
		writeError(w, http.StatusBadRequest, "invalid", "confirmWipe must be true: the new disk will be erased")
		return
	}
	s.submit(w, r, u, JobKindBootAttach, "Add a boot disk", a, "storage.boot.attach", a.Disk, nil)
}

func (s *Server) handleBootDetach(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var a priv.BootDetachArgs
	if !decodeJSON(w, r, &a) {
		return
	}
	s.submit(w, r, u, JobKindBootDetach, "Remove a boot disk", a, "storage.boot.detach", a.Device, nil)
}
