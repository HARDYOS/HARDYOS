package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/monitor"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/ups"
)

// Job kinds for monitoring.
const (
	JobKindSmartTest = "monitor.smart.test"
	JobKindUPSApply  = "ups.apply"
)

func (s *Server) monitorRoutes() {
	if s.cfg.Monitor == nil {
		return
	}
	m := s.mux
	m.Handle("GET /api/v1/monitor/series", s.authed(s.handleSeries))
	m.Handle("GET /api/v1/monitor/history", s.authed(s.handleHistory))
	m.Handle("GET /api/v1/monitor/conditions", s.admin(s.handleConditions))
	m.Handle("GET /api/v1/monitor/settings", s.admin(s.handleMonitorSettings))
	m.Handle("PUT /api/v1/monitor/settings", s.admin(s.handleSaveMonitorSettings))
	m.Handle("GET /api/v1/monitor/disks", s.admin(s.handleMonitorDisks))
	m.Handle("POST /api/v1/monitor/disks/{name}/test", s.admin(s.handleDiskTest))
	if s.cfg.Monitor.UPS != nil {
		m.Handle("GET /api/v1/ups", s.admin(s.handleUPS))
		m.Handle("PUT /api/v1/ups", s.admin(s.handleSaveUPS))
		m.Handle("GET /api/v1/ups/detect", s.admin(s.handleUPSDetect))
	}
}

// RegisterMonitorJobs adds the monitoring job kinds (SMART self-tests, UPS
// setup) to the manager.
func RegisterMonitorJobs(m *jobs.Manager, mon *monitor.Service, pc *priv.Client) {
	if mon == nil {
		return
	}
	m.Register(jobs.Kind{Name: JobKindSmartTest, AdminOnly: true,
		LockKey: func(raw json.RawMessage) string {
			var p smartTestParams
			_ = json.Unmarshal(raw, &p)
			return "smart:" + p.ByID
		},
		Run: func(jc *jobs.Context) (any, error) {
			var p smartTestParams
			if err := jc.Params(&p); err != nil {
				return nil, err
			}
			jc.Progress(20, "Asking the disk to test itself")
			if err := mon.StartTest(jc, p.ByID, p.Test, true); err != nil {
				return nil, err
			}
			msg := "The disk is testing itself in the background; the result appears in Storage Manager and as a notification."
			return map[string]string{"message": msg}, nil
		}})
	if mon.UPS != nil && pc != nil {
		m.Register(jobs.Kind{Name: JobKindUPSApply, AdminOnly: true,
			LockKey: func(json.RawMessage) string { return "ups" },
			Run: func(jc *jobs.Context) (any, error) {
				cfg, sec, err := mon.UPS.Config(jc)
				if err != nil {
					return nil, err
				}
				jc.Progress(30, "Writing the UPS settings and starting NUT")
				ctx, cancel := context.WithTimeout(jc, 3*time.Minute)
				defer cancel()
				var res ups.ApplyResult
				if err := pc.Call(ctx, priv.OpUPSApply, ups.ApplyArgs{Config: cfg, Secrets: sec}, &res); err != nil {
					return nil, err
				}
				jc.Progress(90, "Reading the UPS")
				mon.UPS.Poll(jc)
				return res, nil
			}})
	}
}

type smartTestParams struct {
	ByID string `json:"byId"`
	Name string `json:"name"`
	Test string `json:"test"`
}

func (s *Server) handleSeries(w http.ResponseWriter, _ *http.Request, _ *auth.User) {
	if s.cfg.Monitor.History == nil {
		writeJSON(w, http.StatusOK, []monitor.SeriesInfo{})
		return
	}
	writeJSON(w, http.StatusOK, s.cfg.Monitor.History.Series())
}

// historyRanges are the ranges the Resource Monitor offers.
var historyRanges = map[string]time.Duration{
	"1h": time.Hour, "6h": 6 * time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour,
	"30d": 30 * 24 * time.Hour, "90d": 90 * 24 * time.Hour, "1y": 365 * 24 * time.Hour, "2y": 730 * 24 * time.Hour,
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	h := s.cfg.Monitor.History
	if h == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "history isn't being kept")
		return
	}
	q := r.URL.Query()
	var pats []string
	for _, p := range strings.Split(q.Get("series"), ",") {
		if p = strings.TrimSpace(p); p != "" {
			if len(p) > 200 {
				writeError(w, http.StatusBadRequest, "invalid", "series name too long")
				return
			}
			pats = append(pats, p)
		}
	}
	if len(pats) == 0 {
		writeError(w, http.StatusBadRequest, "invalid", "name at least one series (series=cpu.percent,app.cpu:*)")
		return
	}
	names := h.ExpandNames(pats)
	if len(names) > monitor.MaxQuerySeries {
		names = names[:monitor.MaxQuerySeries]
	}
	now := time.Now()
	to := now
	rng := historyRanges[q.Get("range")]
	if rng == 0 {
		rng = time.Hour
	}
	from := to.Add(-rng)
	if f, err := time.Parse(time.RFC3339, q.Get("from")); err == nil {
		from = f
		if t, err := time.Parse(time.RFC3339, q.Get("to")); err == nil {
			to = t
		}
	}
	points, _ := strconv.Atoi(q.Get("points"))
	res, err := h.Query(r.Context(), names, from, to, now, points)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleConditions(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	list, err := s.cfg.Monitor.Conditions(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleMonitorSettings(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	writeJSON(w, http.StatusOK, s.cfg.Monitor.Settings(r.Context()))
}

func (s *Server) handleSaveMonitorSettings(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var st monitor.Settings
	if !decodeJSON(w, r, &st) {
		return
	}
	saved, err := s.cfg.Monitor.SaveSettings(r.Context(), st)
	var ve *monitor.ValidationError
	if errors.As(err, &ve) {
		writeError(w, http.StatusBadRequest, "invalid", ve.Msg)
		return
	}
	if err != nil {
		internalError(s, w, err)
		return
	}
	s.record(r, u, "monitor.settings.save", "", audit.Success,
		"short every "+strconv.Itoa(saved.SMART.ShortDays)+"d, long every "+strconv.Itoa(saved.SMART.LongDays)+"d, pools "+strconv.Itoa(saved.PoolWarnPct)+"/"+strconv.Itoa(saved.PoolCritPct)+"%")
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleMonitorDisks(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	list, err := s.cfg.Monitor.Disks(r.Context())
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

type diskTestRequest struct {
	Test string `json:"test"` // short or long
}

func (s *Server) handleDiskTest(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req diskTestRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Test != hw.TestShort && req.Test != hw.TestLong {
		writeError(w, http.StatusBadRequest, "invalid", "test must be short or long")
		return
	}
	name := r.PathValue("name")
	disks, err := s.cfg.Monitor.Disks(r.Context())
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	for _, d := range disks {
		if d.Disk.Name != name {
			continue
		}
		if d.Tests != nil && d.Tests.Running != "" {
			writeError(w, http.StatusConflict, "busy", "a "+d.Tests.Running+" self-test is already running on "+name)
			return
		}
		title := map[string]string{hw.TestShort: "Short", hw.TestLong: "Long"}[req.Test] + " self-test of " + name
		s.submit(w, r, u, JobKindSmartTest, title, smartTestParams{ByID: d.Disk.ByID, Name: name, Test: req.Test},
			"monitor.smart.test", d.Disk.ByID+" "+req.Test, nil)
		return
	}
	writeError(w, http.StatusNotFound, "not_found", "no disk named "+name)
}

func (s *Server) handleUPS(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	v, err := s.cfg.Monitor.UPS.View(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

type upsRequest struct {
	Config  ups.Config               `json:"config"`
	Secrets *monitor.UPSSecretsInput `json:"secrets,omitempty"`
}

func (s *Server) handleSaveUPS(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req upsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	cfg, _, err := s.cfg.Monitor.UPS.Save(r.Context(), req.Config, req.Secrets)
	var ve *ups.ValidationError
	if errors.As(err, &ve) {
		writeError(w, http.StatusBadRequest, "invalid", ve.Msg)
		return
	}
	if err != nil {
		internalError(s, w, err)
		return
	}
	target := cfg.Mode
	switch cfg.Mode {
	case ups.ModeLocal:
		target += " " + cfg.Driver + " network=" + strconv.FormatBool(cfg.ServeNetwork)
	case ups.ModeNetClient:
		target += " " + cfg.RemoteUPS + "@" + cfg.RemoteHost
	}
	s.submit(w, r, u, JobKindUPSApply, "Set up the UPS", map[string]string{"mode": cfg.Mode}, "ups.apply", target, nil)
}

func (s *Server) handleUPSDetect(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var devs []ups.Device
	if err := s.cfg.Priv.Call(r.Context(), priv.OpUPSDetect, nil, &devs); err != nil {
		s.writePrivError(w, err)
		return
	}
	if devs == nil {
		devs = []ups.Device{}
	}
	writeJSON(w, http.StatusOK, devs)
}
