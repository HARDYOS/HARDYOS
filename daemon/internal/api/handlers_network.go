package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/network"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// JobKindNetworkApply applies new network settings.
const JobKindNetworkApply = "system.network.apply"

func registerNetworkJobs(m *jobs.Manager, pc *priv.Client) {
	m.Register(jobs.Kind{
		Name:      JobKindNetworkApply,
		AdminOnly: true,
		LockKey:   func(json.RawMessage) string { return "network" },
		Run: func(jc *jobs.Context) (any, error) {
			var c network.Config
			if err := jc.Params(&c); err != nil {
				return nil, err
			}
			jc.Progress(20, "Restarting the network with the new settings")
			ctx, cancel := context.WithTimeout(jc, 3*time.Minute)
			defer cancel()
			var info network.PendingInfo
			if err := pc.Call(ctx, priv.OpNetworkApply, c, &info); err != nil {
				return nil, err
			}
			jc.Progress(90, "Waiting for confirmation")
			return info, nil
		},
	})
}

func (s *Server) networkRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/network", s.admin(s.handleNetworkStatus))
	m.Handle("PUT /api/v1/network", s.admin(s.handleNetworkApply))
	m.Handle("POST /api/v1/network/confirm", s.admin(s.handleNetworkConfirm))
	m.Handle("POST /api/v1/network/revert", s.admin(s.handleNetworkRevert))
	m.Handle("GET /api/v1/system/time", s.authed(s.handleTimeStatus))
	m.Handle("PUT /api/v1/system/time", s.admin(s.handleTimeSet))
	m.Handle("POST /api/v1/system/time/clock", s.admin(s.handleTimeSetClock))
}

func (s *Server) handleNetworkStatus(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var st network.Status
	if err := s.cfg.Priv.Call(r.Context(), priv.OpNetworkStatus, nil, &st); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleNetworkApply(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var c network.Config
	if !decodeJSON(w, r, &c) {
		return
	}
	// Check here first so the form can list every problem at once.
	var st network.Status
	if err := s.cfg.Priv.Call(r.Context(), priv.OpNetworkStatus, nil, &st); err != nil {
		s.writePrivError(w, err)
		return
	}
	if st.Pending != nil {
		writeError(w, http.StatusConflict, "pending", network.ErrPending.Error())
		return
	}
	c.Normalize()
	if err := c.Validate(st.Ports); err != nil {
		var ve *network.ValidationError
		if errors.As(err, &ve) {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Code: "invalid", Message: "Some settings need fixing.", Details: ve.Problems})
			return
		}
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	s.submit(w, r, u, JobKindNetworkApply, "Apply network settings", c, "network.apply", c.Hostname, nil)
}

func (s *Server) handleNetworkConfirm(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var c network.Config
	if err := s.cfg.Priv.Call(r.Context(), priv.OpNetworkConfirm, nil, &c); err != nil {
		s.record(r, u, "network.confirm", "", audit.Failure, err.Error())
		s.writePrivError(w, err)
		return
	}
	s.record(r, u, "network.confirm", c.Hostname, audit.Success, "")
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) handleNetworkRevert(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if err := s.cfg.Priv.Call(r.Context(), priv.OpNetworkRevert, nil, nil); err != nil {
		s.record(r, u, "network.revert", "", audit.Failure, err.Error())
		s.writePrivError(w, err)
		return
	}
	s.record(r, u, "network.revert", "", audit.Success, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleTimeStatus(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var st network.TimeStatus
	if err := s.cfg.Priv.Call(r.Context(), priv.OpTimeStatus, nil, &st); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleTimeSet(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var t network.TimeConfig
	if !decodeJSON(w, r, &t) {
		return
	}
	var st network.TimeStatus
	if err := s.cfg.Priv.Call(r.Context(), priv.OpTimeSet, t, &st); err != nil {
		s.record(r, u, "system.time.set", t.Timezone, audit.Failure, err.Error())
		s.writePrivError(w, err)
		return
	}
	s.record(r, u, "system.time.set", t.Timezone, audit.Success, "")
	writeJSON(w, http.StatusOK, st)
}

type setClockRequest struct {
	Time time.Time `json:"time"`
}

func (s *Server) handleTimeSetClock(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req setClockRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	var st network.TimeStatus
	if err := s.cfg.Priv.Call(r.Context(), priv.OpTimeSetClock, priv.SetClockArgs{Time: req.Time}, &st); err != nil {
		s.record(r, u, "system.time.clock", req.Time.Format(time.RFC3339), audit.Failure, err.Error())
		s.writePrivError(w, err)
		return
	}
	s.record(r, u, "system.time.clock", req.Time.Format(time.RFC3339), audit.Success, "")
	writeJSON(w, http.StatusOK, st)
}
