package api

// Cluster moves (Phase 8 part C, docs/plans/cluster.md section 6.4): the
// Move dialog's candidates, moving a workload (offline or live), draining a
// server, and the history of moves started here.

import (
	"net/http"
	"strconv"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha"
)

func (s *Server) clusterMoveRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/cluster/moves", s.admin(s.handleClusterMoves))
	m.Handle("POST /api/v1/cluster/moves", s.admin(s.handleClusterMove))
	m.Handle("GET /api/v1/cluster/moves/candidates", s.admin(s.handleClusterCandidates))
	m.Handle("POST /api/v1/cluster/moves/drain", s.admin(s.handleClusterDrain))
}

func (s *Server) handleClusterMoves(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	if s.cfg.ClusterHA == nil {
		writeJSON(w, http.StatusOK, []ha.MoveRecord{})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	l, err := s.cfg.ClusterHA.Moves(r.Context(), limit)
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, l)
}

func (s *Server) handleClusterCandidates(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	ref := cluster.WorkloadRef{Kind: cluster.WorkloadKind(r.URL.Query().Get("kind")), ID: r.URL.Query().Get("id")}
	if ref.Kind != cluster.KindVM && ref.Kind != cluster.KindApp || ref.ID == "" {
		writeError(w, http.StatusBadRequest, "invalid", "kind (vm or app) and id are needed")
		return
	}
	svc := s.cfg.ClusterHA
	if !svc.Member() {
		writeError(w, http.StatusConflict, "not_member", "this server isn't in a cluster")
		return
	}
	v, err := svc.Candidates(r.Context(), ref)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// ClusterMoveRequest moves a workload. Confirm is the workload's display
// name, needed for a VM with passthrough devices and for starting a
// workload of a server that is down somewhere else.
type ClusterMoveRequest struct {
	Kind       cluster.WorkloadKind `json:"kind"`
	ID         string               `json:"id"`
	To         cluster.NodeID       `json:"to,omitempty"`
	Mode       cluster.MoveMode     `json:"mode"`
	Generation uint64               `json:"generation"`
	Confirm    string               `json:"confirm,omitempty"`
}

func (s *Server) handleClusterMove(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req ClusterMoveRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ref := cluster.WorkloadRef{Kind: req.Kind, ID: req.ID}
	if ref.Kind != cluster.KindVM && ref.Kind != cluster.KindApp || ref.ID == "" {
		writeError(w, http.StatusBadRequest, "invalid", "kind (vm or app) and id are needed")
		return
	}
	if req.Mode == "" {
		req.Mode = cluster.MoveOffline
	}
	if req.Mode != cluster.MoveOffline && req.Mode != cluster.MoveLive {
		writeError(w, http.StatusBadRequest, "invalid", "mode is offline or live")
		return
	}
	if req.Mode == cluster.MoveLive && ref.Kind != cluster.KindVM {
		writeError(w, http.StatusBadRequest, "invalid", "only VMs move live")
		return
	}
	svc, ok := s.clusterHA(w)
	if !ok {
		return
	}
	v, err := svc.Candidates(r.Context(), ref)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	p := v.Placement
	if req.Generation != 0 && req.Generation != p.Generation {
		writeError(w, http.StatusConflict, "stale", cluster.ErrStaleGeneration.Error())
		return
	}
	if req.Mode == cluster.MoveLive && !v.Live {
		writeError(w, http.StatusBadRequest, "not_live", "it can't move live: "+v.LiveReason)
		return
	}
	// Forced moves: the person types the workload's name.
	if (v.Pinned || v.OwnerDown) && req.Confirm != p.Name {
		why := "it has passthrough devices"
		if v.OwnerDown {
			why = "its server " + string(p.Owner) + " is down"
		}
		writeError(w, http.StatusBadRequest, "confirm_required", why+": type its name ("+p.Name+") to confirm")
		return
	}
	if (v.Pinned || v.OwnerDown && p.Pinned) && req.To == "" {
		writeError(w, http.StatusBadRequest, "invalid", "choose the server: it has passthrough devices, which that server must have too")
		return
	}
	if req.To != "" {
		found := false
		for _, c := range v.Candidates {
			if c.ID == req.To {
				found = true
				if !c.Fits {
					writeError(w, http.StatusBadRequest, "no_fit", string(req.To)+" can't take it: "+c.Reason)
					return
				}
			}
		}
		if !found {
			writeError(w, http.StatusBadRequest, "invalid", string(req.To)+" isn't another compute server")
			return
		}
	}
	title := "Move " + p.Name
	if req.To != "" {
		title += " to " + string(req.To)
	}
	if req.Mode == cluster.MoveLive {
		title += " (live)"
	}
	if v.OwnerDown {
		title = "Start " + p.Name + " on another server"
	}
	s.submit(w, r, u, ha.JobMove, title, ha.MoveParams{Workload: ref, To: req.To, Mode: req.Mode, Generation: p.Generation,
		Confirm: req.Confirm, Actor: s.clusterActor(svc, u)}, "cluster.move", string(ref.Kind)+":"+ref.ID, nil)
}

// ClusterDrainRequest moves everything off a server. StopOthers also
// stops what can't move (Confirm = the server's name then).
type ClusterDrainRequest struct {
	Node       cluster.NodeID `json:"node"`
	StopOthers bool           `json:"stopOthers"`
	Confirm    string         `json:"confirm,omitempty"`
}

func (s *Server) handleClusterDrain(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req ClusterDrainRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	svc, ok := s.clusterHA(w)
	if !ok {
		return
	}
	snap := svc.Parts.Membership.State().Snapshot()
	if n := snap.Nodes[req.Node]; n == nil || n.Role != cluster.RoleCompute {
		writeError(w, http.StatusNotFound, "not_found", "no compute server called "+string(req.Node))
		return
	}
	if req.StopOthers && req.Confirm != string(req.Node) {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the server's name ("+string(req.Node)+") to stop what can't move")
		return
	}
	s.submit(w, r, u, ha.JobDrain, "Move everything off "+string(req.Node), ha.DrainParams{Node: req.Node, StopOthers: req.StopOthers, Actor: s.clusterActor(svc, u)},
		"cluster.drain", string(req.Node), nil)
}
