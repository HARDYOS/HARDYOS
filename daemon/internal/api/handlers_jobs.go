package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

func (s *Server) jobsReady(w http.ResponseWriter) bool {
	if s.cfg.Jobs == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "job system not running")
		return false
	}
	return true
}

// canSee reports whether u may view job j: admins see all, others their own.
func canSee(u *auth.User, j *jobs.Job) bool {
	return u.IsAdmin() || (j.CreatedBy != nil && *j.CreatedBy == u.ID)
}

func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if !s.jobsReady(w) {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	var only *int64
	if !u.IsAdmin() {
		id := u.ID
		only = &id
	}
	list, err := s.cfg.Jobs.List(r.Context(), only, limit)
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if !s.jobsReady(w) {
		return
	}
	j, err := s.cfg.Jobs.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && !canSee(u, j)) {
		writeError(w, http.StatusNotFound, "not_found", "job not found")
		return
	}
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, j)
}

func (s *Server) handleCancelJob(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if !s.jobsReady(w) {
		return
	}
	id := r.PathValue("id")
	j, err := s.cfg.Jobs.Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !canSee(u, j)) {
		writeError(w, http.StatusNotFound, "not_found", "job not found")
		return
	}
	if err != nil {
		internalError(s, w, err)
		return
	}
	if err := s.cfg.Jobs.Cancel(r.Context(), id); err != nil {
		writeError(w, http.StatusConflict, "not_cancellable", err.Error())
		return
	}
	s.record(r, u, "job.cancel", id, audit.Success, j.Kind)
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	query := audit.Query{Action: q.Get("action"), Limit: limit, Before: before}
	if a := q.Get("actorId"); a != "" {
		if id, err := strconv.ParseInt(a, 10, 64); err == nil {
			query.ActorID = &id
		}
	}
	entries, err := s.audit.List(r.Context(), query)
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}
