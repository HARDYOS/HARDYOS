package api

import (
	"context"
	"net/http"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/version"
)

// HealthResponse is returned by GET /api/v1/health.
type HealthResponse struct {
	Status        string  `json:"status"`
	UptimeSeconds float64 `json:"uptimeSeconds"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, HealthResponse{Status: "ok", UptimeSeconds: time.Since(s.started).Seconds()})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, version.Get())
}

// JobKindSelfTest checks that the job pipeline and the root helper both work.
const JobKindSelfTest = "system.selftest"

// RegisterJobKinds adds the job kinds the API submits. Call before starting the manager.
func RegisterJobKinds(m *jobs.Manager, pc *priv.Client) {
	m.Register(jobs.Kind{
		Name:      JobKindSelfTest,
		AdminOnly: true,
		Run: func(jc *jobs.Context) (any, error) {
			jc.Progress(10, "Contacting the root helper")
			if pc == nil {
				return nil, priv.Errorf(priv.CodeUnavailable, "no root helper configured")
			}
			ctx, cancel := context.WithTimeout(jc, 10*time.Second)
			defer cancel()
			var res priv.PingResult
			if err := pc.Call(ctx, priv.OpPing, nil, &res); err != nil {
				return nil, err
			}
			jc.Progress(90, "Root helper answered")
			return map[string]any{"priv": res, "api": version.Get()}, nil
		},
	})
}

func (s *Server) handleSelfTest(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if s.cfg.Jobs == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "job system not running")
		return
	}
	id := u.ID
	j, err := s.cfg.Jobs.Submit(r.Context(), JobKindSelfTest, "System self-test", nil, &id)
	if err != nil {
		internalError(s, w, err)
		return
	}
	s.record(r, u, "system.selftest", j.ID, audit.Success, "")
	writeJSON(w, http.StatusAccepted, j)
}
