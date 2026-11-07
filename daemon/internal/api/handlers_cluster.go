package api

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/member"
)

// The cluster core's endpoints (phase 8 part A, docs/cluster.md): status,
// create, join, leave, dissolve, join codes, removing members, the witness,
// the merged event stream and the per-node API proxy
// (/api/v1/nodes/{node}/..., clusterproxy.go). They are added to a running
// Server by AttachCluster (cmd/hardyd's wireClusterA), so server.go's route
// table stays as it is.

// clusterAPI holds the cluster service for the routes.
type clusterAPI struct {
	s   *Server
	svc *member.Service

	sidMu sync.Mutex
	sids  map[string]sidEntry // domain principal -> SID (entry side)
}

type sidEntry struct {
	sid string
	at  time.Time
}

// ClusterAPI is the handle parts B and C use to add their own routes.
type ClusterAPI struct{ c *clusterAPI }

// Service is the cluster service.
func (c *ClusterAPI) Service() *member.Service { return c.c.svc }

// HandleAdmin registers an administrators' route (parts B and C).
func (c *ClusterAPI) HandleAdmin(pattern string, h func(w http.ResponseWriter, r *http.Request, u *auth.User)) {
	c.c.s.mux.Handle(pattern, c.c.s.admin(h))
}

// AttachCluster adds the cluster routes and makes this server the target
// of relayed requests (its relay handler is set on every core the service
// makes). Call once, before serving.
func (s *Server) AttachCluster(svc *member.Service) *ClusterAPI {
	c := &clusterAPI{s: s, svc: svc, sids: map[string]sidEntry{}}
	svc.Configure = append(svc.Configure, func(core *cluster.Core) { core.SetRelay(c.relayHandler()) })
	m := s.mux
	m.Handle("GET /api/v1/cluster", s.admin(c.handleStatus))
	m.Handle("GET /api/v1/cluster/nodes", s.authed(c.handleNodes))
	m.Handle("POST /api/v1/cluster", s.admin(c.handleCreate))
	m.Handle("POST /api/v1/cluster/join", s.admin(c.handleJoin))
	m.Handle("POST /api/v1/cluster/leave", s.admin(c.handleLeave))
	m.Handle("POST /api/v1/cluster/dissolve", s.admin(c.handleDissolve))
	m.Handle("GET /api/v1/cluster/join-codes", s.admin(c.handleJoinCodes))
	m.Handle("POST /api/v1/cluster/join-codes", s.admin(c.handleJoinCodeCreate))
	m.Handle("DELETE /api/v1/cluster/join-codes/{id}", s.admin(c.handleJoinCodeDelete))
	m.Handle("DELETE /api/v1/cluster/nodes/{node}", s.admin(c.handleRemove))
	m.Handle("POST /api/v1/cluster/witness/script", s.admin(c.handleWitnessScript))
	m.Handle("GET /api/v1/cluster/events", s.authed(c.handleEvents))
	m.Handle("/api/v1/nodes/{node}/{rest...}", s.authed(c.handleNodeProxy))
	return &ClusterAPI{c: c}
}

func (c *clusterAPI) core() *cluster.Core { return c.svc.Core() }

// TakeJobSecret hands a job the secret a request left for it (the cluster
// join code), once.
func TakeJobSecret(ref string) (string, bool) { return jobSecrets.take(ref) }

func actorOf(u *auth.User, via cluster.NodeID) cluster.Actor {
	a := cluster.Actor{Kind: "local", Name: u.Username, Via: via}
	if u.Source == auth.SourceDomain {
		a.Kind = "domain"
	}
	return a
}

func (c *clusterAPI) err(w http.ResponseWriter, err error) {
	var re *cluster.ErrRefused
	var jr *cluster.JoinRefused
	switch {
	case errors.Is(err, cluster.ErrNotMember):
		writeError(w, http.StatusConflict, "not_member", "this server isn't in a cluster")
	case errors.Is(err, cluster.ErrNoQuorum):
		writeError(w, http.StatusServiceUnavailable, "no_quorum", err.Error())
	case errors.As(err, &re):
		writeError(w, http.StatusConflict, "refused", re.Reason)
	case errors.As(err, &jr):
		writeJSON(w, http.StatusConflict, ErrorResponse{Code: "join_refused", Message: "the server can't join", Details: jr.Problems})
	case errors.Is(err, cluster.ErrUnreachable):
		writeError(w, http.StatusBadGateway, "unreachable", err.Error())
	default:
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
	}
}

func (c *clusterAPI) handleStatus(w http.ResponseWriter, r *http.Request, u *auth.User) {
	writeJSON(w, http.StatusOK, c.svc.Status(r.Context()))
}

// ClusterNode is what the server switcher shows.
type ClusterNode struct {
	ID      cluster.NodeID `json:"id"`
	Name    string         `json:"name"`
	Role    cluster.Role   `json:"role"`
	State   string         `json:"state"`
	Self    bool           `json:"self"`
	Leader  bool           `json:"leader"`
	Healthy bool           `json:"healthy"`
}

// ClusterNodes is GET /cluster/nodes.
type ClusterNodes struct {
	Member  bool          `json:"member"`
	Name    string        `json:"name"`
	Quorate bool          `json:"quorate"`
	Nodes   []ClusterNode `json:"nodes"`
}

func (c *clusterAPI) handleNodes(w http.ResponseWriter, r *http.Request, u *auth.User) {
	st := c.svc.Status(r.Context())
	out := ClusterNodes{Member: st.Member, Name: st.Name, Quorate: st.Quorate, Nodes: []ClusterNode{}}
	for _, n := range st.Nodes {
		if n.Role == cluster.RoleWitness {
			continue
		}
		healthy := n.Health != nil && !n.Health.Suspect
		if n.ID == st.Self {
			healthy = st.Quorate
		}
		out.Nodes = append(out.Nodes, ClusterNode{ID: n.ID, Name: n.Name, Role: n.Role, State: string(n.State),
			Self: n.ID == st.Self, Leader: n.ID == st.Leader, Healthy: healthy})
	}
	writeJSON(w, http.StatusOK, out)
}

type clusterCreateRequest struct {
	Name          string       `json:"name"`
	Role          cluster.Role `json:"role"`
	StorageSubnet string       `json:"storageSubnet"`
}

func (c *clusterAPI) handleCreate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req clusterCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 64 {
		writeError(w, http.StatusBadRequest, "invalid", "give the cluster a name (1-64 characters)")
		return
	}
	if req.Role != cluster.RoleCompute && req.Role != cluster.RoleStorage {
		writeError(w, http.StatusBadRequest, "invalid", "this server's role is compute or storage")
		return
	}
	if c.core().Info() != nil {
		writeError(w, http.StatusConflict, "member", "this server is in a cluster already")
		return
	}
	c.s.submit(w, r, u, member.JobCreate, "Create the cluster "+req.Name, member.CreateParams{Name: req.Name, Role: req.Role,
		StorageSubnet: req.StorageSubnet, Actor: actorOf(u, "")}, "cluster.create", req.Name, nil)
}

type clusterJoinRequest struct {
	Address string       `json:"address"`
	Code    string       `json:"code"`
	Role    cluster.Role `json:"role"`
}

func (c *clusterAPI) handleJoin(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req clusterJoinRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Address = strings.TrimSpace(req.Address)
	if req.Address == "" || len(req.Address) > 255 || strings.ContainsAny(req.Address, "/ @") {
		writeError(w, http.StatusBadRequest, "invalid", "give the member's address (host or host:port)")
		return
	}
	if _, err := cluster.ParseCode(req.Code); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if req.Role != cluster.RoleCompute && req.Role != cluster.RoleStorage {
		writeError(w, http.StatusBadRequest, "invalid", "this server joins as compute or storage")
		return
	}
	if c.core().Info() != nil {
		writeError(w, http.StatusConflict, "member", "this server is in a cluster already")
		return
	}
	ref := jobSecrets.put(req.Code)
	c.s.submit(w, r, u, member.JobJoin, "Join the cluster through "+req.Address,
		member.JoinParams{Address: req.Address, Role: req.Role, SecretRef: ref}, "cluster.join", req.Address, nil)
}

type clusterConfirm struct {
	Confirm string `json:"confirm"`
}

func (c *clusterAPI) handleLeave(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req clusterConfirm
	if !decodeJSON(w, r, &req) {
		return
	}
	core := c.core()
	if core.Info() == nil {
		c.err(w, cluster.ErrNotMember)
		return
	}
	name := core.Machine().Snapshot().Name
	if req.Confirm != name {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the cluster's name to confirm")
		return
	}
	c.s.submit(w, r, u, member.JobLeave, "Leave the cluster "+name, member.LeaveParams{Confirm: req.Confirm, Actor: actorOf(u, core.ID())},
		"cluster.leave", name, nil)
}

func (c *clusterAPI) handleDissolve(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req clusterConfirm
	if !decodeJSON(w, r, &req) {
		return
	}
	core := c.core()
	if core.Info() == nil {
		c.err(w, cluster.ErrNotMember)
		return
	}
	name := core.Machine().Snapshot().Name
	if req.Confirm != name {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the cluster's name to confirm")
		return
	}
	c.s.submit(w, r, u, member.JobDissolve, "Dissolve the cluster "+name, member.LeaveParams{Confirm: req.Confirm, Actor: actorOf(u, core.ID())},
		"cluster.dissolve", name, nil)
}

func (c *clusterAPI) handleRemove(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req clusterConfirm
	if !decodeJSON(w, r, &req) {
		return
	}
	core := c.core()
	id := cluster.NodeID(r.PathValue("node"))
	m, ok := core.Machine().Node(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such member")
		return
	}
	if req.Confirm != m.Name && req.Confirm != string(m.ID) {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the server's name to confirm")
		return
	}
	if id == core.ID() {
		writeError(w, http.StatusBadRequest, "invalid", "use Leave on this server")
		return
	}
	c.s.submit(w, r, u, member.JobRemove, "Remove "+m.Name+" from the cluster",
		member.RemoveParams{Node: id, Confirm: req.Confirm, Actor: actorOf(u, core.ID())}, "cluster.remove", string(id), nil)
}

// JoinCodeInfo is an open code without the code itself.
type JoinCodeInfo struct {
	ID        string       `json:"id"`
	Role      cluster.Role `json:"role"`
	Expires   time.Time    `json:"expires"`
	Failures  int          `json:"failures"`
	CreatedBy string       `json:"createdBy"`
}

func (c *clusterAPI) handleJoinCodes(w http.ResponseWriter, r *http.Request, u *auth.User) {
	l, err := c.svc.Store().JoinCodes(r.Context(), time.Now())
	if err != nil {
		internalError(c.s, w, err)
		return
	}
	out := []JoinCodeInfo{}
	for _, jc := range l {
		out = append(out, JoinCodeInfo{ID: jc.ID, Role: jc.Role, Expires: jc.Expires, Failures: jc.Failures, CreatedBy: jc.CreatedBy})
	}
	writeJSON(w, http.StatusOK, out)
}

type joinCodeRequest struct {
	Role cluster.Role `json:"role"`
}

func (c *clusterAPI) handleJoinCodeCreate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req joinCodeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Role != cluster.RoleCompute && req.Role != cluster.RoleStorage {
		writeError(w, http.StatusBadRequest, "invalid", "a join code admits a compute or a storage server (the witness has its own script)")
		return
	}
	off, err := c.core().OpenJoinCode(r.Context(), req.Role, u.Username)
	if err != nil {
		c.err(w, err)
		return
	}
	c.s.record(r, u, "cluster.joincode.create", string(req.Role), audit.Success, "expires "+off.Expires.Format(time.RFC3339))
	writeJSON(w, http.StatusCreated, off)
}

func (c *clusterAPI) handleJoinCodeDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if err := c.svc.Store().TakeJoinCode(r.Context(), r.PathValue("id")); err != nil {
		internalError(c.s, w, err)
		return
	}
	c.s.record(r, u, "cluster.joincode.delete", r.PathValue("id"), audit.Success, "")
	w.WriteHeader(http.StatusNoContent)
}

// WitnessScript is POST /cluster/witness/script's answer.
type WitnessScript struct {
	Script  string    `json:"script"`
	Expires time.Time `json:"expires"`
}

func (c *clusterAPI) handleWitnessScript(w http.ResponseWriter, r *http.Request, u *auth.User) {
	script, off, err := c.svc.WitnessScript(r.Context(), u.Username)
	if err != nil {
		c.err(w, err)
		return
	}
	c.s.record(r, u, "cluster.witness.script", "witness", audit.Success, "join code expires "+off.Expires.Format(time.RFC3339))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, WitnessScript{Script: string(script), Expires: off.Expires})
}
