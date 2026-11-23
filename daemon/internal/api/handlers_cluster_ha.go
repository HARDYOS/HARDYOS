package api

// Cluster HA (Phase 8 part C, docs/plans/cluster.md section 7): the HA
// page's status, workloads' HA policies and start/stop requests, the
// per-node watchdog override and the cluster's timings. Every change is a
// job (and audited); the change itself is a signed command in the cluster's
// log.

import (
	"net/http"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
)

func (s *Server) clusterHARoutes() {
	m := s.mux
	m.Handle("GET /api/v1/cluster/ha", s.admin(s.handleClusterHA))
	m.Handle("PUT /api/v1/cluster/ha/watchdog/{node}", s.admin(s.handleClusterWatchdog))
	m.Handle("PUT /api/v1/cluster/ha/timings", s.admin(s.handleClusterTimings))
	m.Handle("PUT /api/v1/cluster/workloads/{kind}/{id}/ha", s.admin(s.handleClusterPolicy))
	m.Handle("POST /api/v1/cluster/workloads/{kind}/{id}/request", s.admin(s.handleClusterRequest))
	s.clusterMoveRoutes()
}

// clusterHA returns the service when this server is in a cluster, or
// answers 409.
func (s *Server) clusterHA(w http.ResponseWriter) (*ha.Service, bool) {
	svc := s.cfg.ClusterHA
	if !svc.Member() {
		writeError(w, http.StatusConflict, "not_member", "this server isn't in a cluster")
		return nil, false
	}
	if !s.jobsReady(w) {
		return nil, false
	}
	return svc, true
}

func (s *Server) clusterActor(svc *ha.Service, u *auth.User) cluster.Actor {
	return svc.ActorFor(u.Principal, u.Source == auth.SourceDomain)
}

func (s *Server) handleClusterHA(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	if s.cfg.ClusterHA == nil {
		writeJSON(w, http.StatusOK, &ha.StatusView{Nodes: []ha.NodeHA{}, Placements: []cluster.Placement{}})
		return
	}
	v, err := s.cfg.ClusterHA.Status(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func workloadRef(r *http.Request) (cluster.WorkloadRef, bool) {
	w := cluster.WorkloadRef{Kind: cluster.WorkloadKind(r.PathValue("kind")), ID: r.PathValue("id")}
	if w.Kind != cluster.KindVM && w.Kind != cluster.KindApp {
		return w, false
	}
	if l := len(w.ID); l == 0 || l > 63 {
		return w, false
	}
	return w, true
}

// placementOf finds a cluster workload, or answers 404.
func (s *Server) placementOf(w http.ResponseWriter, svc *ha.Service, ref cluster.WorkloadRef) (*cluster.Snapshot, *cluster.Placement, bool) {
	snap := svc.Parts.Membership.State().Snapshot()
	p := snap.Placements[ref]
	if p == nil {
		writeError(w, http.StatusNotFound, "not_found", "that isn't a cluster workload")
		return nil, nil, false
	}
	return snap, p, true
}

// ClusterPolicyRequest sets a workload's HA policy.
type ClusterPolicyRequest struct {
	Policy cluster.HAPolicy `json:"policy"`
}

func (s *Server) handleClusterPolicy(w http.ResponseWriter, r *http.Request, u *auth.User) {
	ref, ok := workloadRef(r)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such workload")
		return
	}
	var req ClusterPolicyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	svc, ok := s.clusterHA(w)
	if !ok {
		return
	}
	snap, p, ok := s.placementOf(w, svc, ref)
	if !ok {
		return
	}
	pol := state.NormalizePolicy(req.Policy)
	if err := state.ValidatePolicy(snap, p, pol); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	title := "Turn high availability off for " + p.Name
	if pol.Enabled {
		title = "Make " + p.Name + " highly available"
	}
	s.submit(w, r, u, ha.JobPolicy, title, ha.PolicyParams{Workload: ref, Policy: pol, Actor: s.clusterActor(svc, u)}, "cluster.ha.policy", string(ref.Kind)+":"+ref.ID, nil)
}

// ClusterRequestRequest starts or stops a cluster workload.
type ClusterRequestRequest struct {
	Requested  cluster.Requested `json:"requested"`
	Generation uint64            `json:"generation"`
}

func (s *Server) handleClusterRequest(w http.ResponseWriter, r *http.Request, u *auth.User) {
	ref, ok := workloadRef(r)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such workload")
		return
	}
	var req ClusterRequestRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Requested != cluster.RequestRunning && req.Requested != cluster.RequestStopped {
		writeError(w, http.StatusBadRequest, "invalid", "requested is running or stopped")
		return
	}
	svc, ok := s.clusterHA(w)
	if !ok {
		return
	}
	_, p, ok := s.placementOf(w, svc, ref)
	if !ok {
		return
	}
	if req.Generation != 0 && req.Generation != p.Generation {
		writeError(w, http.StatusConflict, "stale", cluster.ErrStaleGeneration.Error())
		return
	}
	verb := "Start "
	if req.Requested == cluster.RequestStopped {
		verb = "Stop "
	}
	s.submit(w, r, u, ha.JobRequest, verb+p.Name, ha.RequestParams{Workload: ref, Generation: p.Generation, Requested: req.Requested, Actor: s.clusterActor(svc, u)},
		"cluster.request."+string(req.Requested), string(ref.Kind)+":"+ref.ID, nil)
}

// ClusterWatchdogRequest allows (or stops allowing) HA workloads on a node
// without a hardware watchdog. Confirm is the node's name.
type ClusterWatchdogRequest struct {
	Allow   bool   `json:"allow"`
	Confirm string `json:"confirm"`
}

func (s *Server) handleClusterWatchdog(w http.ResponseWriter, r *http.Request, u *auth.User) {
	node := cluster.NodeID(r.PathValue("node"))
	var req ClusterWatchdogRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	svc, ok := s.clusterHA(w)
	if !ok {
		return
	}
	snap := svc.Parts.Membership.State().Snapshot()
	n := snap.Nodes[node]
	if n == nil || n.Role != cluster.RoleCompute {
		writeError(w, http.StatusNotFound, "not_found", "no compute server called "+string(node))
		return
	}
	if req.Confirm != string(node) {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the server's name ("+string(node)+") to confirm")
		return
	}
	title := "Allow HA on " + string(node) + " without a hardware watchdog"
	if !req.Allow {
		title = "Require a hardware watchdog for HA on " + string(node)
	}
	s.submit(w, r, u, ha.JobWatchdog, title, ha.WatchdogParams{Node: node, Allow: req.Allow, Confirm: req.Confirm, Actor: s.clusterActor(svc, u)},
		"cluster.ha.watchdog", string(node), nil)
}

// ClusterTimings are the cluster's timings in milliseconds.
type ClusterTimings struct {
	HeartbeatMs       int64 `json:"heartbeatMs"`
	SuspectMs         int64 `json:"suspectMs"`
	QuorumLeaseMs     int64 `json:"quorumLeaseMs"`
	SelfStopMs        int64 `json:"selfStopMs"`
	WatchdogMs        int64 `json:"watchdogMs"`
	DeadMs            int64 `json:"deadMs"`
	StorageIsolatedMs int64 `json:"storageIsolatedMs"`
	LANIsolatedMs     int64 `json:"lanIsolatedMs"`
	FenceAckMs        int64 `json:"fenceAckMs"`
}

func (t ClusterTimings) timings() cluster.Timings {
	ms := func(v int64) time.Duration { return time.Duration(v) * time.Millisecond }
	return cluster.Timings{Heartbeat: ms(t.HeartbeatMs), Suspect: ms(t.SuspectMs), QuorumLease: ms(t.QuorumLeaseMs), SelfStop: ms(t.SelfStopMs),
		Watchdog: ms(t.WatchdogMs), Dead: ms(t.DeadMs), StorageIsolated: ms(t.StorageIsolatedMs), LANIsolated: ms(t.LANIsolatedMs), FenceAck: ms(t.FenceAckMs)}
}

func (s *Server) handleClusterTimings(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req ClusterTimings
	if !decodeJSON(w, r, &req) {
		return
	}
	t := req.timings()
	if err := state.ValidateTimings(t); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	svc, ok := s.clusterHA(w)
	if !ok {
		return
	}
	s.submit(w, r, u, ha.JobTimings, "Change the cluster's failover timings", ha.TimingsParams{Timings: t, Actor: s.clusterActor(svc, u)},
		"cluster.ha.timings", "cluster", nil)
}
