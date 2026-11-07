package ha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/fence"
	"github.com/hardyos/hardyos/daemon/internal/cluster/moves"
	"github.com/hardyos/hardyos/daemon/internal/cluster/placement"
	"github.com/hardyos/hardyos/daemon/internal/cluster/runtime"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Parts are what parts A and B provide on this node. Any may be nil until
// those parts land (or outside a cluster): the service then answers "not
// a member" and runs nothing.
type Parts struct {
	Membership cluster.Membership
	Peers      cluster.PeerClient
	Mux        cluster.PeerMux
	Attacher   cluster.StorageAttacher
	// Stream dials the hardyos-migrate/1 relay (part A's stream layer);
	// nil: a streamed peer request (moves.PeerStream).
	Stream moves.StreamDialer
	Power  cluster.PowerFencer
}

// Service is part C on one node (hardyd): it registers the appliers, runs
// the reconciler, the fence agent, the pre-puller and (on the leader) the
// HA coordinator, serves the move steps, and backs the cluster HA API.
type Service struct {
	Parts   Parts
	Priv    *priv.Client
	Jobs    *jobs.Manager
	DB      *store.DB
	Audit   *audit.Log
	Publish moves.PublishHandoff
	Log     *slog.Logger

	Scheduler   *placement.Scheduler
	Mover       *moves.Mover
	Coordinator *Coordinator
	Agent       *fence.Agent
	Reconciler  *runtime.Reconciler
	Prepuller   *runtime.Prepuller
	Node        *moves.Node
	Announcer   *Announcer

	reqMu sync.Mutex
	reqs  map[cluster.WorkloadRef]*cluster.Requirements
}

// ErrNotMember: this server isn't in a cluster (or part A isn't there).
var ErrNotMember = cluster.ErrNotMember

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Member reports whether this server is in a cluster.
func (s *Service) Member() bool {
	if s == nil || s.Parts.Membership == nil {
		return false
	}
	_, err := s.Parts.Membership.Self()
	return err == nil
}

// Init builds the parts and registers the appliers and job kinds. Call
// before the FSM replays the log and before jobs start.
func (s *Service) Init() {
	s.reqs = map[cluster.WorkloadRef]*cluster.Requirements{}
	s.Scheduler = &placement.Scheduler{Requirements: s.cachedRequirements}
	s.registerJobs()
	m := s.Parts.Membership
	if m == nil {
		return
	}
	m.Register(state.Placements{})
	m.Register(state.Fences{})
	vmRT := &runtime.VMRuntime{Priv: s.Priv, HostModel: func() string {
		if n, err := m.Self(); err == nil && n.Compute != nil {
			return n.Compute.CPUModel
		}
		return ""
	}}
	appRT := &runtime.AppRuntime{Priv: s.Priv}
	rts := []cluster.Runtime{vmRT, appRT}
	s.Reconciler = &runtime.Reconciler{Cluster: m, Attacher: s.Parts.Attacher, Runtimes: rts, BootID: bootID, Log: s.Log}
	s.Agent = &fence.Agent{Cluster: m, Watchdog: runtime.PrivWatchdog{Priv: s.Priv},
		Fencer: runtime.SelfFencer{Priv: s.Priv, Attacher: s.Parts.Attacher, Log: s.Log}, Running: s.Reconciler.Local, Log: s.Log,
		OnChange: func(st fence.AgentStatus) { s.audit("cluster.fence."+string(st.State), "this server", st.Problem) }}
	images := runtime.PrivImages{Priv: s.Priv}
	if s.Parts.Peers != nil {
		s.Mover = &moves.Mover{Cluster: m, Peers: s.Parts.Peers, Scheduler: s.Scheduler, Log: s.Log}
		s.Prepuller = &runtime.Prepuller{Cluster: m, Images: images, Log: s.Log,
			Source: moves.PeerImages{Peers: s.Parts.Peers, Priv: s.Priv, Self: func() cluster.NodeID {
				n, _ := m.Self()
				return n.ID
			}}}
	}
	stream := s.Parts.Stream
	if stream == nil && s.Parts.Peers != nil {
		stream = moves.PeerStream{Peers: s.Parts.Peers}
	}
	s.Node = &moves.Node{Cluster: m, Reconciler: s.Reconciler, Attacher: s.Parts.Attacher, Runtimes: rts, Priv: s.Priv,
		Images: images, Publish: s.Publish, Stream: stream, Log: s.Log}
	if s.Parts.Mux != nil {
		s.Node.Caller = s.Parts.Mux.Caller
		s.Node.Register(s.Parts.Mux)
	}
	s.Coordinator = &Coordinator{Cluster: m, Scheduler: s.Scheduler, Actions: s, Requirements: s.cachedRequirements,
		Power: s.Parts.Power, Log: s.Log}
	if s.Priv != nil {
		s.Announcer = &Announcer{Cluster: m, Priv: s.Priv}
	}
	if s.Mover != nil {
		s.Coordinator.Mover = s.Mover
	}
}

// Start runs the node's loops until ctx ends.
func (s *Service) Start(ctx context.Context) {
	m := s.Parts.Membership
	if m == nil {
		return
	}
	var wg sync.WaitGroup
	run := func(f func(context.Context)) {
		wg.Add(1)
		go func() { defer wg.Done(); f(ctx) }()
	}
	run(func(ctx context.Context) { _ = s.Agent.Run(ctx) })
	run(func(ctx context.Context) { _ = s.Reconciler.Run(ctx, m.Subscribe(ctx)) })
	run(func(ctx context.Context) { _ = s.Coordinator.Run(ctx) })
	if s.Prepuller != nil {
		run(func(ctx context.Context) { _ = s.Prepuller.Run(ctx, m.Subscribe(ctx)) })
	}
	run(s.refreshRequirements)
	if s.Announcer != nil {
		run(s.Announcer.Run)
	}
	wg.Wait()
}

func bootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// ---- requirements cache -----------------------------------------------------------

func (s *Service) cachedRequirements(w cluster.WorkloadRef) *cluster.Requirements {
	s.reqMu.Lock()
	defer s.reqMu.Unlock()
	return s.reqs[w]
}

// refreshRequirements asks each workload's owner what it needs, every two
// minutes, so recovery can place it after the owner is gone.
func (s *Service) refreshRequirements(ctx context.Context) {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		if s.Parts.Peers != nil && s.Member() {
			snap := s.Parts.Membership.State().Snapshot()
			for w, p := range snap.Placements {
				if p.Owner == "" || ownerGone(snap, p.Owner) {
					continue
				}
				var res struct {
					Requirements cluster.Requirements `json:"requirements"`
				}
				q := url.Values{"kind": {string(w.Kind)}, "id": {w.ID}}
				cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
				err := s.Parts.Peers.Call(cctx, p.Owner, http.MethodGet, cluster.PeerPathPrefix+moves.PathRequirements+"?"+q.Encode(), nil, &res)
				cancel()
				if err == nil {
					r := res.Requirements
					s.reqMu.Lock()
					s.reqs[w] = &r
					s.reqMu.Unlock()
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func ownerGone(s *cluster.Snapshot, n cluster.NodeID) bool {
	node := s.Nodes[n]
	return node == nil || node.State == cluster.NodeDead || node.State == cluster.NodeFenced || node.State == cluster.NodeRemoved
}

// ---- jobs and audit -----------------------------------------------------------------

// Job kinds a person starts.
const (
	JobMove     = "cluster.move"
	JobDrain    = "cluster.drain"
	JobPolicy   = "cluster.ha.policy"
	JobRequest  = "cluster.request"
	JobWatchdog = "cluster.ha.watchdog"
	JobTimings  = "cluster.ha.timings"
)

// systemKinds are the coordinator's actions: run at once by the
// coordinator (failover can't wait behind other jobs) and recorded as
// finished jobs.
var systemKinds = []string{JobDead, JobIsolate, JobRecover, JobRelocate, JobPending, JobCollapse, JobEvacuate, JobFailBack}

// systemOutcome is a coordinator action's recorded outcome.
type systemOutcome struct {
	Target string `json:"target"`
	Error  string `json:"error,omitempty"`
}

func (s *Service) registerJobs() {
	if s.Jobs == nil {
		return
	}
	for _, k := range systemKinds {
		s.Jobs.Register(jobs.Kind{Name: k, AdminOnly: true, Run: func(jc *jobs.Context) (any, error) {
			var o systemOutcome
			if err := jc.Params(&o); err != nil {
				return nil, err
			}
			if o.Error != "" {
				return nil, errors.New(o.Error)
			}
			return o, nil
		}})
	}
	lockW := func(raw json.RawMessage) string {
		var p struct {
			Workload cluster.WorkloadRef `json:"workload"`
		}
		_ = json.Unmarshal(raw, &p)
		return "cluster:" + string(p.Workload.Kind) + ":" + p.Workload.ID
	}
	reg := func(name string, lock func(json.RawMessage) string, run jobs.RunFunc) {
		s.Jobs.Register(jobs.Kind{Name: name, AdminOnly: true, LockKey: lock, Run: run})
	}
	reg(JobMove, lockW, s.runMove)
	reg(JobDrain, func(raw json.RawMessage) string {
		var p DrainParams
		_ = json.Unmarshal(raw, &p)
		return "cluster:drain:" + string(p.Node)
	}, s.runDrain)
	reg(JobPolicy, lockW, s.runPolicy)
	reg(JobRequest, lockW, s.runRequest)
	reg(JobWatchdog, nil, s.runWatchdog)
	reg(JobTimings, func(json.RawMessage) string { return "cluster:timings" }, s.runTimings)
}

// Run implements Actions: the coordinator's change runs now; the job and
// the audit entry record it.
func (s *Service) Run(ctx context.Context, kind, title, target string, fn func(ctx context.Context) error) error {
	err := fn(ctx)
	o := systemOutcome{Target: target}
	if err != nil {
		o.Error = err.Error()
	}
	if s.Jobs != nil {
		if _, jerr := s.Jobs.Submit(context.WithoutCancel(ctx), kind, title, o, nil); jerr != nil {
			s.log().Warn("ha: recording the action as a job", "kind", kind, "err", jerr)
		}
	}
	detail := title
	if err != nil {
		detail += ": " + err.Error()
	}
	s.auditOutcome(kind, target, detail, err)
	return err
}

func (s *Service) audit(action, target, detail string) { s.auditOutcome(action, target, detail, nil) }

func (s *Service) auditOutcome(action, target, detail string, err error) {
	if s.Audit == nil {
		return
	}
	out := audit.Success
	if err != nil {
		out = audit.Failure
	}
	via := ""
	if s.Parts.Membership != nil {
		if n, e := s.Parts.Membership.Self(); e == nil {
			via = " (via " + string(n.ID) + ")"
		}
	}
	_ = s.Audit.Record(context.Background(), audit.Entry{Actor: "HardyOS HA" + via, Action: action, Target: target, Outcome: out, Detail: detail})
}

// ActorFor is the cluster actor for a person using this node.
func (s *Service) ActorFor(name string, domain bool) cluster.Actor {
	a := cluster.Actor{Kind: "local", Name: name}
	if domain {
		a.Kind = "domain"
	}
	if s.Parts.Membership != nil {
		if n, err := s.Parts.Membership.Self(); err == nil {
			a.Via = n.ID
		}
	}
	return a
}

// MoveParams are a move job's parameters.
type MoveParams struct {
	Workload   cluster.WorkloadRef `json:"workload"`
	To         cluster.NodeID      `json:"to,omitempty"`
	Mode       cluster.MoveMode    `json:"mode"`
	Generation uint64              `json:"generation"`
	Confirm    string              `json:"confirm,omitempty"`
	Actor      cluster.Actor       `json:"actor"`
}

func (s *Service) runMove(jc *jobs.Context) (any, error) {
	var p MoveParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	if s.Mover == nil {
		return nil, ErrNotMember
	}
	started := time.Now()
	res, err := s.Mover.MoveWith(jc, cluster.MoveRequest{Workload: p.Workload, To: p.To, Mode: p.Mode, Generation: p.Generation}, p.Actor,
		moves.Options{Confirm: p.Confirm, Progress: jc.Progress})
	s.recordMove(jc.ID(), p, res, err, started)
	return res, err
}

// DrainParams are a drain job's parameters.
type DrainParams struct {
	Node       cluster.NodeID `json:"node"`
	StopOthers bool           `json:"stopOthers"`
	Actor      cluster.Actor  `json:"actor"`
}

func (s *Service) runDrain(jc *jobs.Context) (any, error) {
	var p DrainParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	if s.Mover == nil {
		return nil, ErrNotMember
	}
	res, err := s.Mover.DrainWith(jc, p.Node, p.StopOthers, p.Actor, jc.Progress)
	if err != nil {
		return nil, &jobs.FailedWith{Err: err, Result: res}
	}
	return res, nil
}

// PolicyParams set a workload's HA policy.
type PolicyParams struct {
	Workload cluster.WorkloadRef `json:"workload"`
	Policy   cluster.HAPolicy    `json:"policy"`
	Actor    cluster.Actor       `json:"actor"`
}

func (s *Service) propose(ctx context.Context, t cluster.CommandType, body any, actor cluster.Actor) error {
	m := s.Parts.Membership
	if m == nil {
		return ErrNotMember
	}
	idx, err := m.Propose(ctx, t, body, actor)
	if err != nil {
		return err
	}
	return m.WaitApplied(ctx, idx)
}

// applied checks a proposal took effect (an applier that refused it makes
// it a no-op in the log).
func (s *Service) applied(check func(*cluster.Snapshot) error) error {
	return check(s.Parts.Membership.State().Snapshot())
}

func (s *Service) runPolicy(jc *jobs.Context) (any, error) {
	var p PolicyParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	if err := s.propose(jc, cluster.CmdHAPolicy, state.HAPolicySet{Workload: p.Workload, Policy: p.Policy}, p.Actor); err != nil {
		return nil, err
	}
	return nil, s.applied(func(snap *cluster.Snapshot) error {
		pl := snap.Placements[p.Workload]
		if pl == nil || pl.HA.Enabled != p.Policy.Enabled {
			return errors.New("the cluster refused the policy (see the server's log)")
		}
		return nil
	})
}

// RequestParams start or stop a cluster workload.
type RequestParams struct {
	Workload   cluster.WorkloadRef `json:"workload"`
	Generation uint64              `json:"generation"`
	Requested  cluster.Requested   `json:"requested"`
	Actor      cluster.Actor       `json:"actor"`
}

func (s *Service) runRequest(jc *jobs.Context) (any, error) {
	var p RequestParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	if err := s.propose(jc, cluster.CmdRequested, state.RequestedSet{Workload: p.Workload, Generation: p.Generation, Requested: p.Requested}, p.Actor); err != nil {
		return nil, err
	}
	return nil, s.applied(func(snap *cluster.Snapshot) error {
		pl := snap.Placements[p.Workload]
		if pl == nil || pl.Requested != p.Requested {
			return cluster.ErrStaleGeneration
		}
		return nil
	})
}

// WatchdogParams allow or stop allowing HA without a hardware watchdog.
type WatchdogParams struct {
	Node    cluster.NodeID `json:"node"`
	Allow   bool           `json:"allow"`
	Confirm string         `json:"confirm"`
	Actor   cluster.Actor  `json:"actor"`
}

func (s *Service) runWatchdog(jc *jobs.Context) (any, error) {
	var p WatchdogParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	if err := s.propose(jc, cluster.CmdHAWatchdog, state.WatchdogOverrideBody{Node: p.Node, Allow: p.Allow, Confirm: p.Confirm}, p.Actor); err != nil {
		return nil, err
	}
	return nil, s.applied(func(snap *cluster.Snapshot) error {
		if _, ok := snap.HAOverrides[p.Node]; ok != p.Allow {
			return errors.New("the cluster refused the change (see the server's log)")
		}
		return nil
	})
}

// TimingsParams change the cluster's timings.
type TimingsParams struct {
	Timings cluster.Timings `json:"timings"`
	Actor   cluster.Actor   `json:"actor"`
}

func (s *Service) runTimings(jc *jobs.Context) (any, error) {
	var p TimingsParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	if err := state.ValidateTimings(p.Timings); err != nil {
		return nil, err
	}
	if err := s.propose(jc, cluster.CmdTimings, p.Timings, p.Actor); err != nil {
		return nil, err
	}
	return nil, s.applied(func(snap *cluster.Snapshot) error {
		if snap.Timings != p.Timings {
			return errors.New("the cluster refused the timings (see the server's log)")
		}
		return nil
	})
}

// ---- move history -----------------------------------------------------------------

// MoveRecord is one move in the history.
type MoveRecord struct {
	JobID      string    `json:"jobId"`
	Kind       string    `json:"kind"`
	Workload   string    `json:"workload"`
	From       string    `json:"from"`
	To         string    `json:"to"`
	Mode       string    `json:"mode"`
	Started    time.Time `json:"started"`
	Finished   time.Time `json:"finished"`
	DowntimeMs int64     `json:"downtimeMs"`
	OK         bool      `json:"ok"`
	Problem    string    `json:"problem,omitempty"`
	Actor      string    `json:"actor"`
}

func (s *Service) recordMove(jobID string, p MoveParams, res *cluster.MoveResult, err error, started time.Time) {
	if s.DB == nil {
		return
	}
	rec := MoveRecord{JobID: jobID, Kind: string(p.Workload.Kind), Workload: p.Workload.ID, To: string(p.To), Mode: string(p.Mode),
		Started: started.UTC(), Finished: time.Now().UTC(), OK: err == nil, Actor: p.Actor.Name}
	if res != nil {
		rec.From, rec.To, rec.DowntimeMs = string(res.From), string(res.To), res.Downtime.Milliseconds()
	}
	if err != nil {
		rec.Problem = err.Error()
	}
	if _, e := s.DB.ExecContext(context.Background(), `INSERT INTO cluster_moves (job_id, kind, workload, from_node, to_node, mode, started_at, finished_at, downtime_ms, ok, problem, actor)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, rec.JobID, rec.Kind, rec.Workload, rec.From, rec.To, rec.Mode,
		store.FormatTime(rec.Started), store.FormatTime(rec.Finished), rec.DowntimeMs, boolInt(rec.OK), rec.Problem, rec.Actor); e != nil {
		s.log().Warn("ha: recording a move", "err", e)
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Moves lists the latest moves started on this server.
func (s *Service) Moves(ctx context.Context, limit int) ([]MoveRecord, error) {
	out := []MoveRecord{}
	if s.DB == nil {
		return out, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT job_id, kind, workload, from_node, to_node, mode, started_at, finished_at, downtime_ms, ok, problem, actor
		FROM cluster_moves ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r MoveRecord
		var st, fi string
		var ok int
		if err := rows.Scan(&r.JobID, &r.Kind, &r.Workload, &r.From, &r.To, &r.Mode, &st, &fi, &r.DowntimeMs, &ok, &r.Problem, &r.Actor); err != nil {
			return nil, err
		}
		r.Started = store.ParseTime(st)
		r.Finished = store.ParseTime(fi)
		r.OK = ok != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---- status -----------------------------------------------------------------------

// NodeHA is one compute node's HA readiness.
type NodeHA struct {
	ID       cluster.NodeID    `json:"id"`
	Name     string            `json:"name"`
	State    cluster.NodeState `json:"state"`
	Watchdog string            `json:"watchdog"`
	Eligible bool              `json:"eligible"`
	Reason   string            `json:"reason,omitempty"`
	Override bool              `json:"override"`
}

// StatusView is the HA page's data.
type StatusView struct {
	Member      bool                      `json:"member"`
	Self        cluster.NodeID            `json:"self,omitempty"`
	Quorate     bool                      `json:"quorate"`
	Timings     cluster.Timings           `json:"timings"`
	Nodes       []NodeHA                  `json:"nodes"`
	Placements  []cluster.Placement       `json:"placements"`
	Coordinator *Status                   `json:"coordinator,omitempty"`
	Fence       *fence.AgentStatus        `json:"fence,omitempty"`
	Prepull     []runtime.PrepullStatus   `json:"prepull"`
	Watchdog    *fence.Status             `json:"watchdog,omitempty"`
	Leader      cluster.NodeID            `json:"leader,omitempty"`
	CPUBaseline string                    `json:"cpuBaseline,omitempty"`
	Grants      map[string]*cluster.Grant `json:"grants"`
}

// Status builds the HA page's data.
func (s *Service) Status(ctx context.Context) (*StatusView, error) {
	v := &StatusView{Nodes: []NodeHA{}, Placements: []cluster.Placement{}, Prepull: []runtime.PrepullStatus{}, Grants: map[string]*cluster.Grant{}}
	if !s.Member() {
		return v, nil
	}
	m := s.Parts.Membership
	self, _ := m.Self()
	snap := m.State().Snapshot()
	v.Member, v.Self = true, self.ID
	v.Quorate, _ = m.Quorate()
	v.Timings = snap.Timings
	if v.Timings.Dead == 0 {
		v.Timings = cluster.DefaultTimings
	}
	v.CPUBaseline = snap.CPUBaseline
	if l, ok := m.Leader(); ok {
		v.Leader = l
	}
	for _, n := range computeNodes(snap) {
		ok, why := state.HAEligible(snap, n.ID)
		wd := ""
		if n.Compute != nil {
			wd = n.Compute.Watchdog
		}
		v.Nodes = append(v.Nodes, NodeHA{ID: n.ID, Name: n.Name, State: n.State, Watchdog: wd, Eligible: ok, Reason: why, Override: snap.HAOverrides[n.ID] != nil})
	}
	for _, p := range state.SortedPlacements(snap) {
		v.Placements = append(v.Placements, *p)
		if g := snap.Grants[p.Workload]; g != nil {
			v.Grants[string(p.Workload.Kind)+":"+p.Workload.ID] = g
		}
	}
	if s.Coordinator != nil {
		st := s.Coordinator.Status()
		v.Coordinator = &st
	}
	if s.Agent != nil {
		st := s.Agent.Status()
		v.Fence = &st
	}
	if s.Prepuller != nil {
		v.Prepull = s.Prepuller.Status()
	}
	if s.Priv != nil {
		var wd fence.Status
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err := s.Priv.Call(cctx, priv.OpClusterWatchdogStatus, nil, &wd); err == nil {
			v.Watchdog = &wd
		}
		cancel()
	}
	return v, nil
}

// Candidate is one node in the Move dialog.
type Candidate struct {
	ID     cluster.NodeID `json:"id"`
	Name   string         `json:"name"`
	Fits   bool           `json:"fits"`
	Reason string         `json:"reason,omitempty"`
}

// Candidates lists where a workload could move, and whether it can move
// live.
func (s *Service) Candidates(ctx context.Context, w cluster.WorkloadRef) (*CandidatesView, error) {
	if !s.Member() {
		return nil, ErrNotMember
	}
	m := s.Parts.Membership
	snap := m.State().Snapshot()
	p := snap.Placements[w]
	if p == nil {
		return nil, fmt.Errorf("%s isn't a cluster workload", w.ID)
	}
	health, err := m.Health(ctx)
	if err != nil {
		return nil, err
	}
	req := cluster.Requirements{}
	if r := s.cachedRequirements(w); r != nil {
		req = *r
	}
	out := &CandidatesView{Placement: *p, Candidates: []Candidate{}}
	out.OwnerDown = p.Owner == "" || ownerGone(snap, p.Owner)
	out.Pinned = p.Pinned || len(req.Devices) > 0
	out.Live = w.Kind == cluster.KindVM && p.State == cluster.PlacementRunning && !out.Pinned && !out.OwnerDown
	switch {
	case w.Kind != cluster.KindVM:
		out.LiveReason = "apps move offline (a short stop)"
	case out.Pinned:
		out.LiveReason = "it has passthrough devices"
	case p.State != cluster.PlacementRunning:
		out.LiveReason = "it isn't running"
	case out.OwnerDown:
		out.LiveReason = "its server is down"
	}
	for _, n := range computeNodes(snap) {
		if n.ID == p.Owner {
			continue
		}
		why := s.Scheduler.Fits(snap, health, w, req, n.ID)
		out.Candidates = append(out.Candidates, Candidate{ID: n.ID, Name: n.Name, Fits: why == "", Reason: why})
	}
	return out, nil
}

// CandidatesView is the Move dialog's data.
type CandidatesView struct {
	Placement  cluster.Placement `json:"placement"`
	Candidates []Candidate       `json:"candidates"`
	Live       bool              `json:"live"`
	LiveReason string            `json:"liveReason,omitempty"`
	Pinned     bool              `json:"pinned"`
	OwnerDown  bool              `json:"ownerDown"`
}
