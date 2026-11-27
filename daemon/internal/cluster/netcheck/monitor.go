package netcheck

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// Local is what the monitor uses of this server's cluster core.
type Local interface {
	Self() (cluster.Node, error)
	State() cluster.State
	// Identity is this server's cluster key (nil outside a cluster).
	Identity() *cluster.Identity
	// DialPeer opens the peer API to a member at exactly this address,
	// its pin checked (no path fallback).
	DialPeer(ctx context.Context, addr string, peer cluster.Node) (net.Conn, error)
}

// Monitor runs this server's probes, keeps its latest report, answers the
// peer API's probe and report paths and is the Source of Status.
type Monitor struct {
	Local Local
	Peers cluster.PeerClient
	// Interval between rounds (default 30 s).
	Interval   time.Duration
	Port       int
	Interfaces func() ([]Iface, error)
	// OnChange is told when this server's own result changes (after two
	// rounds in a row agree; the first known state too when it is bad).
	OnChange func(ctx context.Context, mine MemberResult, all Result)
	Log      *slog.Logger

	mu      sync.Mutex
	report  *Report
	lastRun time.Time
	runMu   sync.Mutex
	known   *bool // this server's last notified state
	pending *bool // the state seen once, waiting for a second round
	cache   *Result
	cacheAt time.Time
}

var _ Source = (*Monitor)(nil)

func (m *Monitor) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

func (m *Monitor) interfaces() func() ([]Iface, error) {
	if m.Interfaces != nil {
		return m.Interfaces
	}
	return Interfaces
}

// Mux is where the monitor registers its peer endpoints.
type Mux interface {
	Handle(pattern string, h http.Handler)
	Caller(r *http.Request) (cluster.Node, bool)
}

// Register adds the probe, report and run endpoints to the peer API.
func (m *Monitor) Register(mux Mux) {
	rs := &Responder{Identity: m.Local.Identity, Caller: mux.Caller, Interfaces: m.interfaces(), Self: func() cluster.NodeID {
		n, _ := m.Local.Self()
		return n.ID
	}}
	mux.Handle("POST /"+ProbePath, rs)
	mux.Handle("GET /"+ReportPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, m.Latest())
	}))
	// Another member asks for a fresh round ("Check now"): at most every
	// 10 s, answered with the report.
	mux.Handle("POST /"+RunPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, ok := mux.Caller(r); !ok || (c.Role != cluster.RoleCompute && c.Role != cluster.RoleStorage) {
			http.Error(w, "only compute and storage servers ask", http.StatusForbidden)
			return
		}
		writeJSON(w, m.RunNow(r.Context()))
	}))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// Latest is this server's latest report (nil before the first round).
func (m *Monitor) Latest() *Report {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.report == nil {
		return nil
	}
	r := *m.report
	return &r
}

// Snapshot implements Source: nil outside a cluster.
func (m *Monitor) Snapshot() *cluster.Snapshot {
	if _, err := m.Local.Self(); err != nil {
		return nil
	}
	return m.Local.State().Snapshot()
}

// Reports implements Source: this server's own report locally, the others'
// over the peer API (in parallel, 3 s each).
func (m *Monitor) Reports(ctx context.Context, nodes []cluster.NodeID) (map[cluster.NodeID]*Report, map[cluster.NodeID]error) {
	self, _ := m.Local.Self()
	reps, errs := map[cluster.NodeID]*Report{}, map[cluster.NodeID]error{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, id := range nodes {
		if id == self.ID {
			if r := m.Latest(); r != nil {
				reps[id] = r
			}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			var r *Report
			err := m.Peers.Call(cctx, id, http.MethodGet, "/"+ReportPath, nil, &r)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				errs[id] = err
			case r == nil:
				errs[id] = errors.New("it has no report yet")
			default:
				reps[id] = r
			}
		}()
	}
	wg.Wait()
	return reps, errs
}

// Status is Status(ctx, m), cached for 5 seconds (the Move dialog and the
// overview ask often).
func (m *Monitor) Status(ctx context.Context) Result {
	m.mu.Lock()
	if m.cache != nil && time.Since(m.cacheAt) < 5*time.Second {
		r := *m.cache
		m.mu.Unlock()
		return r
	}
	m.mu.Unlock()
	r := Status(ctx, m)
	m.mu.Lock()
	m.cache, m.cacheAt = &r, time.Now()
	m.mu.Unlock()
	return r
}

// Fresh asks every member to probe now, then judges (Check now).
func (m *Monitor) Fresh(ctx context.Context) Result {
	s := m.Snapshot()
	if s == nil {
		return Status(ctx, m)
	}
	self, _ := m.Local.Self()
	var wg sync.WaitGroup
	for _, n := range Checked(s) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if n.ID == self.ID {
				m.RunNow(ctx)
				return
			}
			cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			_ = m.Peers.Call(cctx, n.ID, http.MethodPost, "/"+RunPath, nil, nil)
		}()
	}
	wg.Wait()
	m.mu.Lock()
	m.cache = nil
	m.mu.Unlock()
	return m.Status(ctx)
}

// RunNow runs a round unless one ran in the last 10 seconds, and returns
// the latest report.
func (m *Monitor) RunNow(ctx context.Context) *Report {
	m.runMu.Lock()
	defer m.runMu.Unlock()
	m.mu.Lock()
	recent := time.Since(m.lastRun) < 10*time.Second && m.report != nil
	m.mu.Unlock()
	if !recent {
		m.round(ctx)
	}
	return m.Latest()
}

func (m *Monitor) round(ctx context.Context) {
	self, err := m.Local.Self()
	if err != nil || (self.Role != cluster.RoleCompute && self.Role != cluster.RoleStorage) {
		m.mu.Lock()
		m.report, m.lastRun = nil, time.Now()
		m.mu.Unlock()
		return
	}
	p := &Prober{Dial: m.Local.DialPeer, Port: m.Port, Interfaces: m.interfaces()}
	s := m.Local.State().Snapshot()
	rep := p.Probe(ctx, self, Checked(s))
	m.mu.Lock()
	m.report, m.lastRun, m.cache = &rep, time.Now(), nil
	m.mu.Unlock()
}

// Run probes every Interval until ctx ends, and tells OnChange when this
// server's own result changes.
func (m *Monitor) Run(ctx context.Context) {
	iv := m.Interval
	if iv <= 0 {
		iv = 30 * time.Second
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		m.runMu.Lock()
		m.round(ctx)
		m.runMu.Unlock()
		if ctx.Err() != nil {
			return
		}
		m.observe(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// observe judges the cluster and notifies about this server's own part
// when it changed for two rounds in a row.
func (m *Monitor) observe(ctx context.Context) {
	self, err := m.Local.Self()
	if err != nil || m.OnChange == nil {
		return
	}
	m.mu.Lock()
	m.cache = nil
	m.mu.Unlock()
	all := m.Status(ctx)
	var mine *MemberResult
	for i := range all.PerMember {
		if all.PerMember[i].Node == self.ID {
			mine = &all.PerMember[i]
		}
	}
	if mine == nil || mine.Skipped {
		return
	}
	ok := mine.OK
	m.mu.Lock()
	notify := false
	switch {
	case m.pending == nil || *m.pending != ok:
		m.pending = &ok
	case m.known == nil:
		// The first state known: worth telling only when it's bad.
		m.known = &ok
		notify = !ok
	case *m.known != ok:
		m.known = &ok
		notify = true
	}
	m.mu.Unlock()
	if notify {
		m.log().Info("cluster: local-network check changed", "ok", ok, "reason", mine.Reason)
		m.OnChange(ctx, *mine, all)
	}
}
