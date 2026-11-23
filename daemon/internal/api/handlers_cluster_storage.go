package api

// Cluster storage (Phase 8 part B, docs/plans/cluster.md sections 5 and
// 6.1): the storage network wizard, the storage node's overview, per-node
// storage status, exports, cluster shared folders, snapshots of cluster
// workloads on the storage node, an app's NFS/block mode, and CHAP
// rotation. Every change is a job (and audited when submitted); the
// storage node audits again what it does for the requesting person.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/cluster/storagesvc"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/network"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// Cluster storage job kinds.
const (
	JobKindClusterStorageNet      = "cluster.storage.network"
	JobKindClusterStorageShare    = "cluster.storage.share"
	JobKindClusterStorageSnapshot = "cluster.storage.snapshot"
	JobKindClusterStorageRollback = "cluster.storage.rollback"
	JobKindClusterStorageSnapDel  = "cluster.storage.snapshot.delete"
	JobKindClusterStorageMode     = "cluster.storage.mode"
	JobKindClusterStorageCHAP     = "cluster.storage.chap.rotate"
)

// ClusterStorage is part B's runtime, handed to the API by cmd/hardyd's
// wireClusterB.
type ClusterStorage struct {
	Service *storagesvc.Service
	Agent   *storagesvc.Agent
}

// ClusterStorageRoutes registers the cluster storage endpoints and jobs.
func (s *Server) ClusterStorageRoutes(cs ClusterStorage) {
	if cs.Service == nil || s.cfg.Jobs == nil || s.cfg.Priv == nil {
		return
	}
	h := &clusterStorageAPI{s: s, cs: cs}
	h.registerJobs(s.cfg.Jobs)
	m := s.mux
	m.Handle("GET /api/v1/cluster/storage", s.admin(h.overview))
	m.Handle("GET /api/v1/cluster/storage/nodes", s.admin(h.nodes))
	m.Handle("GET /api/v1/cluster/storage/exports", s.admin(h.exports))
	m.Handle("GET /api/v1/cluster/storage/network", s.admin(h.network))
	m.Handle("POST /api/v1/cluster/storage/network", s.admin(h.networkApply))
	m.Handle("PUT /api/v1/cluster/storage/shares/{pool}/{id}", s.admin(h.share))
	m.Handle("GET /api/v1/cluster/storage/workloads/{kind}/{id}/snapshots", s.admin(h.snapshots))
	m.Handle("POST /api/v1/cluster/storage/workloads/{kind}/{id}/snapshots", s.admin(h.snapshotCreate))
	m.Handle("POST /api/v1/cluster/storage/workloads/{kind}/{id}/rollback", s.admin(h.rollback))
	m.Handle("POST /api/v1/cluster/storage/workloads/{kind}/{id}/snapshots/{name}/delete", s.admin(h.snapshotDelete))
	m.Handle("POST /api/v1/cluster/storage/apps/{id}/mode", s.admin(h.mode))
	m.Handle("POST /api/v1/cluster/storage/nodes/{node}/chap/rotate", s.admin(h.chapRotate))
}

type clusterStorageAPI struct {
	s  *Server
	cs ClusterStorage
}

func (h *clusterStorageAPI) actor(u *auth.User) cluster.Actor {
	a := cluster.Actor{Kind: "local", Name: u.Username}
	if u.Source == auth.SourceDomain {
		a.Kind = "domain"
	}
	if h.cs.Service.M != nil {
		if me, err := h.cs.Service.M.Self(); err == nil {
			a.Via = me.ID
		}
	}
	return a
}

func (h *clusterStorageAPI) clusterErr(w http.ResponseWriter, err error) {
	var pe *cluster.PeerError
	switch {
	case errors.Is(err, cluster.ErrNotMember):
		writeError(w, http.StatusConflict, "not_member", "This server isn't in a cluster.")
	case errors.Is(err, storagesvc.ErrNoStorageNode):
		writeError(w, http.StatusConflict, "no_storage", err.Error())
	case errors.Is(err, cluster.ErrNoQuorum), errors.Is(err, cluster.ErrStaleGeneration):
		writeError(w, http.StatusConflict, "conflict", err.Error())
	case errors.As(err, &pe):
		writeError(w, http.StatusBadGateway, "peer", pe.Error())
	default:
		h.s.writePrivError(w, err)
	}
}

// ---- jobs ------------------------------------------------------------------------

type storageNetJob struct {
	Plan network.StoragePlan `json:"plan"`
}

type workloadJob struct {
	Workload cluster.WorkloadRef `json:"workload"`
	Name     string              `json:"name,omitempty"`
	Confirm  string              `json:"confirm,omitempty"`
	Actor    cluster.Actor       `json:"actor"`
}

type chapJob struct {
	Node  cluster.NodeID `json:"node"`
	Actor cluster.Actor  `json:"actor"`
}

func (h *clusterStorageAPI) registerJobs(m *jobs.Manager) {
	svc := h.cs.Service
	pc := h.s.cfg.Priv
	lock := func(json.RawMessage) string { return "cluster-storage" }
	m.Register(jobs.Kind{Name: JobKindClusterStorageNet, AdminOnly: true, LockKey: func(json.RawMessage) string { return "network" },
		Run: func(jc *jobs.Context) (any, error) {
			var p storageNetJob
			if err := jc.Params(&p); err != nil {
				return nil, err
			}
			jc.Progress(10, "Reading the network settings")
			var st network.Status
			if err := pc.Call(jc, priv.OpNetworkStatus, nil, &st); err != nil {
				return nil, err
			}
			if st.Pending != nil {
				return nil, network.ErrPending
			}
			if err := p.Plan.Validate(st); err != nil {
				return nil, err
			}
			c, err := network.ApplyStoragePlan(st.Config, p.Plan)
			if err != nil {
				return nil, err
			}
			if err := c.Validate(st.Ports); err != nil {
				return nil, err
			}
			if svc.Store != nil {
				if err := svc.Store.SaveStorageNet(jc, p.Plan); err != nil {
					return nil, err
				}
			}
			if p.Plan.Kind == network.StorageShared {
				return map[string]any{"changed": false}, nil
			}
			jc.Progress(30, "Setting up the storage network")
			ctx, cancel := context.WithTimeout(jc, 3*time.Minute)
			defer cancel()
			var info network.PendingInfo
			if err := pc.Call(ctx, priv.OpNetworkApply, c, &info); err != nil {
				return nil, err
			}
			jc.Progress(90, "Waiting for confirmation in Network settings")
			return map[string]any{"changed": true, "pending": info}, nil
		}})
	m.Register(jobs.Kind{Name: JobKindClusterStorageShare, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		var r storagesvc.ShareRequest
		if err := jc.Params(&r); err != nil {
			return nil, err
		}
		return map[string]bool{"in": r.In}, svc.SetShareCluster(jc, r)
	}})
	m.Register(jobs.Kind{Name: JobKindClusterStorageSnapshot, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		var r workloadJob
		if err := jc.Params(&r); err != nil {
			return nil, err
		}
		jc.Progress(20, "Taking the snapshot on the storage server")
		return svc.Snapshot(jc, r.Workload, r.Name, r.Actor)
	}})
	m.Register(jobs.Kind{Name: JobKindClusterStorageRollback, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		var r workloadJob
		if err := jc.Params(&r); err != nil {
			return nil, err
		}
		jc.Progress(20, "Rolling back on the storage server")
		return map[string]string{"snapshot": r.Name}, svc.Rollback(jc, r.Workload, r.Name, r.Confirm, r.Actor)
	}})
	m.Register(jobs.Kind{Name: JobKindClusterStorageSnapDel, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		var r workloadJob
		if err := jc.Params(&r); err != nil {
			return nil, err
		}
		return map[string]string{"snapshot": r.Name}, svc.DeleteSnapshot(jc, r.Workload, r.Name, r.Confirm, r.Actor)
	}})
	m.Register(jobs.Kind{Name: JobKindClusterStorageMode, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		var r storagesvc.ModeRequest
		if err := jc.Params(&r); err != nil {
			return nil, err
		}
		jc.Progress(10, "Moving the app's data on the storage server")
		res, err := svc.SwitchAppMode(jc, r)
		if err == nil && svc.Store != nil {
			_ = svc.Store.SaveAppMode(jc, storagesvc.AppMode{App: r.App, Mode: r.To, FS: res.Storage.BlockFS})
		}
		return res, err
	}})
	m.Register(jobs.Kind{Name: JobKindClusterStorageCHAP, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		var r chapJob
		if err := jc.Params(&r); err != nil {
			return nil, err
		}
		return map[string]string{"node": string(r.Node)}, svc.RotateCHAP(jc, r.Node, r.Actor)
	}})
}

// ---- reads -------------------------------------------------------------------------

// ClusterStorageWorkload is one workload's storage as the state has it.
type ClusterStorageWorkload struct {
	Workload   cluster.WorkloadRef     `json:"workload"`
	Name       string                  `json:"name"`
	Owner      cluster.NodeID          `json:"owner"`
	Nodes      []cluster.NodeID        `json:"nodes"`
	Generation uint64                  `json:"generation"`
	Applied    bool                    `json:"applied"`
	Migration  bool                    `json:"migration"`
	State      cluster.PlacementState  `json:"state"`
	Storage    cluster.WorkloadStorage `json:"storage"`
}

// ClusterStorageOverview is GET /cluster/storage.
type ClusterStorageOverview struct {
	Member        bool                     `json:"member"`
	Self          *cluster.Node            `json:"self,omitempty"`
	StorageNode   *cluster.Node            `json:"storageNode,omitempty"`
	StorageSubnet string                   `json:"storageSubnet"`
	Health        *cluster.StorageHealth   `json:"health,omitempty"`
	Agent         *storagesvc.AgentStatus  `json:"agent,omitempty"`
	Workloads     []ClusterStorageWorkload `json:"workloads"`
	Fences        []cluster.Fence          `json:"fences"`
	Shares        []cluster.ClusterShare   `json:"shares"`
}

func (h *clusterStorageAPI) overview(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	out := ClusterStorageOverview{Workloads: []ClusterStorageWorkload{}, Fences: []cluster.Fence{}, Shares: []cluster.ClusterShare{}}
	svc := h.cs.Service
	if svc.M == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	me, err := svc.M.Self()
	if err != nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	snap := svc.M.State().Snapshot()
	out.Member, out.Self = true, &me
	if snap.StorageSubnet.IsValid() {
		out.StorageSubnet = snap.StorageSubnet.String()
	}
	if sn, ok := storagesvc.StorageNode(snap); ok {
		out.StorageNode = sn
	}
	if hl, err := svc.Health(r.Context()); err == nil {
		out.Health = hl
	}
	if h.cs.Agent != nil {
		st := h.cs.Agent.Status()
		out.Agent = &st
	}
	for wr, g := range snap.Grants {
		p := snap.Placements[wr]
		if p == nil {
			continue
		}
		out.Workloads = append(out.Workloads, ClusterStorageWorkload{Workload: wr, Name: p.Name, Owner: p.Owner, Nodes: g.Nodes,
			Generation: g.Generation, Applied: g.Applied, Migration: g.Mode == cluster.GrantMigration, State: p.State, Storage: p.Storage})
	}
	for wr, p := range snap.Placements {
		if _, ok := snap.Grants[wr]; !ok {
			out.Workloads = append(out.Workloads, ClusterStorageWorkload{Workload: wr, Name: p.Name, Owner: p.Owner, Nodes: []cluster.NodeID{},
				Generation: p.Generation, State: p.State, Storage: p.Storage})
		}
	}
	sort.Slice(out.Workloads, func(i, j int) bool {
		a, b := out.Workloads[i].Workload, out.Workloads[j].Workload
		return a.Kind < b.Kind || a.Kind == b.Kind && a.ID < b.ID
	})
	for _, f := range snap.Fences {
		out.Fences = append(out.Fences, *f)
	}
	sort.Slice(out.Fences, func(i, j int) bool { return out.Fences[i].Node < out.Fences[j].Node })
	for _, sh := range snap.ClusterShares {
		out.Shares = append(out.Shares, *sh)
	}
	sort.Slice(out.Shares, func(i, j int) bool { return out.Shares[i].ID < out.Shares[j].ID })
	writeJSON(w, http.StatusOK, out)
}

func (h *clusterStorageAPI) nodes(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	svc := h.cs.Service
	out := []storagesvc.NodeStatus{}
	if svc.M == nil {
		writeJSON(w, http.StatusOK, map[string]any{"nodes": out})
		return
	}
	me, err := svc.M.Self()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"nodes": out})
		return
	}
	snap := svc.M.State().Snapshot()
	ids := make([]cluster.NodeID, 0, len(snap.Nodes))
	for id, n := range snap.Nodes {
		if n.Role != cluster.RoleWitness && n.State != cluster.NodeRemoved {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	type result struct {
		i  int
		st storagesvc.NodeStatus
	}
	res := make([]storagesvc.NodeStatus, len(ids))
	done := make(chan result, len(ids))
	for i, id := range ids {
		go func() {
			ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
			defer cancel()
			var st storagesvc.NodeStatus
			var err error
			if id == me.ID {
				var p *storagesvc.NodeStatus
				if p, err = svc.LocalStatus(ctx); p != nil {
					st = *p
				}
			} else if svc.Peers != nil {
				err = svc.Peers.Call(ctx, id, "POST", "storage/status", struct{}{}, &st)
			} else {
				err = cluster.ErrStorageUnavailable
			}
			if err != nil {
				st = storagesvc.NodeStatus{Node: id, Role: snap.Nodes[id].Role, Problem: err.Error(), Attached: nil, Checked: time.Now().UTC()}
			}
			st.Node, st.Role = id, snap.Nodes[id].Role
			done <- result{i, st}
		}()
	}
	for range ids {
		x := <-done
		res[x.i] = x.st
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": res})
}

func (h *clusterStorageAPI) exports(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	st, err := h.cs.Service.Exports(r.Context())
	if err != nil {
		h.clusterErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// StorageNetworkInfo is GET /cluster/storage/network.
type StorageNetworkInfo struct {
	Candidates []network.StorageCandidate `json:"candidates"`
	Plan       *network.StoragePlan       `json:"plan"`
	// Subnet is the cluster's storage subnet, or the suggestion.
	Subnet string `json:"subnet"`
	// Suggested is a free address for this server in Subnet.
	Suggested string `json:"suggested"`
	// Current is this server's address on the storage network, if any.
	Current   string                  `json:"current"`
	Interface string                  `json:"interface"`
	Jumbo     map[string]bool         `json:"jumbo"`
	Live      []network.LiveInterface `json:"live"`
	Pending   bool                    `json:"pending"`
}

func (h *clusterStorageAPI) network(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var st network.Status
	if err := h.s.cfg.Priv.Call(r.Context(), priv.OpNetworkStatus, nil, &st); err != nil {
		h.s.writePrivError(w, err)
		return
	}
	out := StorageNetworkInfo{Candidates: network.StorageCandidates(st), Jumbo: map[string]bool{}, Live: st.Live, Pending: st.Pending != nil}
	if out.Candidates == nil {
		out.Candidates = []network.StorageCandidate{}
	}
	for _, c := range out.Candidates {
		out.Jumbo[c.Interface] = network.JumboCapable(st, c.Interface)
	}
	svc := h.cs.Service
	if svc.Store != nil {
		out.Plan, _ = svc.Store.StorageNet(r.Context())
	}
	subnet := network.DefaultStorageSubnet
	taken := map[netip.Addr]bool{}
	if svc.M != nil {
		if _, err := svc.M.Self(); err == nil {
			snap := svc.M.State().Snapshot()
			if snap.StorageSubnet.IsValid() {
				subnet = snap.StorageSubnet
			}
			for _, n := range snap.Nodes {
				if n.Addresses.Storage.IsValid() {
					taken[n.Addresses.Storage] = true
				}
			}
		}
	}
	out.Subnet = subnet.String()
	if a, iface, ok := network.StorageAddress(st, subnet); ok {
		out.Current, out.Interface = a.String(), iface
	}
	// Suggest .10 for the first server (the storage node) and .21 up for the
	// others, skipping addresses members already use.
	for _, host := range append([]int{10}, rangeInts(21, 250)...) {
		a := subnet.Masked().Addr().As4()
		a[3] = byte(host)
		cand := netip.AddrFrom4(a)
		if subnet.Contains(cand) && !taken[cand] {
			out.Suggested = netip.PrefixFrom(cand, subnet.Bits()).String()
			break
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func rangeInts(a, b int) []int {
	out := make([]int, 0, b-a+1)
	for i := a; i <= b; i++ {
		out = append(out, i)
	}
	return out
}

func (h *clusterStorageAPI) networkApply(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var p network.StoragePlan
	if !decodeJSON(w, r, &p) {
		return
	}
	var st network.Status
	if err := h.s.cfg.Priv.Call(r.Context(), priv.OpNetworkStatus, nil, &st); err != nil {
		h.s.writePrivError(w, err)
		return
	}
	if st.Pending != nil {
		writeError(w, http.StatusConflict, "pending", network.ErrPending.Error())
		return
	}
	if err := p.Validate(st); err != nil {
		var ve *network.ValidationError
		if errors.As(err, &ve) {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Code: "invalid", Message: "Some settings need fixing.", Details: ve.Problems})
			return
		}
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	// In a cluster: the address must fit the cluster's storage network and
	// be this server's alone (M1); a changed address needs the typed name
	// (and the storage server's administrator confirms it there); the LAN
	// itself can't carry a VM's or app's own data (H2).
	if svc := h.cs.Service; svc.M != nil {
		if me, err := svc.M.Self(); err == nil {
			chk := storagesvc.CheckStoragePlan(svc.M.State().Snapshot(), me, p, r.URL.Query().Get("confirm"))
			if len(chk.Problems) > 0 {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Code: "invalid", Message: "Some settings need fixing.", Details: chk.Problems})
				return
			}
			if chk.NeedsConfirm {
				writeError(w, http.StatusConflict, "confirm", chk.ConfirmMessage)
				return
			}
		}
	}
	h.s.submit(w, r, u, JobKindClusterStorageNet, "Set up the storage network", storageNetJob{Plan: p}, "cluster.storage.network", p.StorageInterface()+" "+p.Address, nil)
}

type shareInClusterRequest struct {
	InCluster bool `json:"inCluster"`
}

func (h *clusterStorageAPI) share(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var q shareInClusterRequest
	if !decodeJSON(w, r, &q) {
		return
	}
	req := storagesvc.ShareRequest{Pool: r.PathValue("pool"), ID: r.PathValue("id"), In: q.InCluster, Actor: h.actor(u)}
	title := "Use a shared folder in the cluster"
	if !q.InCluster {
		title = "Stop using a shared folder in the cluster"
	}
	h.s.submit(w, r, u, JobKindClusterStorageShare, title, req, "cluster.storage.share", req.Pool+"/"+req.ID, nil)
}

func workloadFromPath(w http.ResponseWriter, r *http.Request) (cluster.WorkloadRef, bool) {
	wr := cluster.WorkloadRef{Kind: cluster.WorkloadKind(r.PathValue("kind")), ID: r.PathValue("id")}
	if wr.Kind != cluster.KindVM && wr.Kind != cluster.KindApp {
		writeError(w, http.StatusBadRequest, "invalid", "kind must be vm or app")
		return wr, false
	}
	return wr, true
}

func (h *clusterStorageAPI) snapshots(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	wr, ok := workloadFromPath(w, r)
	if !ok {
		return
	}
	l, err := h.cs.Service.Snapshots(r.Context(), wr)
	if err != nil {
		h.clusterErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"snapshots": l})
}

type clusterSnapshotRequest struct {
	Name    string `json:"name"`
	Confirm string `json:"confirm"`
}

func (h *clusterStorageAPI) snapshotCreate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	wr, ok := workloadFromPath(w, r)
	if !ok {
		return
	}
	var q clusterSnapshotRequest
	if !decodeJSON(w, r, &q) {
		return
	}
	if q.Name == "" {
		q.Name = "manual-" + time.Now().UTC().Format("20060102-150405")
	}
	h.s.submit(w, r, u, JobKindClusterStorageSnapshot, "Snapshot "+wr.ID, workloadJob{Workload: wr, Name: q.Name, Actor: h.actor(u)},
		"cluster.storage.snapshot", string(wr.Kind)+" "+wr.ID+"@"+q.Name, nil)
}

func (h *clusterStorageAPI) rollback(w http.ResponseWriter, r *http.Request, u *auth.User) {
	wr, ok := workloadFromPath(w, r)
	if !ok {
		return
	}
	var q clusterSnapshotRequest
	if !decodeJSON(w, r, &q) {
		return
	}
	if q.Confirm == "" || q.Confirm != q.Name {
		writeError(w, http.StatusBadRequest, "confirm", "Type the snapshot's name to roll back to it.")
		return
	}
	h.s.submit(w, r, u, JobKindClusterStorageRollback, "Roll "+wr.ID+" back", workloadJob{Workload: wr, Name: q.Name, Confirm: q.Confirm, Actor: h.actor(u)},
		"cluster.storage.rollback", string(wr.Kind)+" "+wr.ID+"@"+q.Name, nil)
}

func (h *clusterStorageAPI) snapshotDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	wr, ok := workloadFromPath(w, r)
	if !ok {
		return
	}
	var q clusterSnapshotRequest
	if !decodeJSON(w, r, &q) {
		return
	}
	name := r.PathValue("name")
	if q.Confirm != name {
		writeError(w, http.StatusBadRequest, "confirm", "Type the snapshot's name to delete it.")
		return
	}
	h.s.submit(w, r, u, JobKindClusterStorageSnapDel, "Delete a snapshot of "+wr.ID, workloadJob{Workload: wr, Name: name, Confirm: q.Confirm, Actor: h.actor(u)},
		"cluster.storage.snapshot.delete", string(wr.Kind)+" "+wr.ID+"@"+name, nil)
}

type modeRequest struct {
	To        cluster.StorageMode `json:"to"`
	FS        string              `json:"fs"`
	SizeGB    int                 `json:"sizeGB"`
	RemoveOld bool                `json:"removeOld"`
	Confirm   string              `json:"confirm"`
}

func (h *clusterStorageAPI) mode(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var q modeRequest
	if !decodeJSON(w, r, &q) {
		return
	}
	id := r.PathValue("id")
	if q.To != cluster.StorageNFS && q.To != cluster.StorageBlock {
		writeError(w, http.StatusBadRequest, "invalid", "to must be nfs or block")
		return
	}
	if q.FS != "" && q.FS != san.BlockExt4 && q.FS != san.BlockXFS {
		writeError(w, http.StatusBadRequest, "invalid", "the file system must be ext4 or xfs")
		return
	}
	if q.SizeGB < 0 || q.SizeGB > san.MaxVolumeGB {
		writeError(w, http.StatusBadRequest, "invalid", "size out of range")
		return
	}
	if q.Confirm != id {
		writeError(w, http.StatusBadRequest, "confirm", "Type the app's name to move its data.")
		return
	}
	req := storagesvc.ModeRequest{App: id, To: q.To, FS: q.FS, SizeGB: q.SizeGB, RemoveOld: q.RemoveOld, Confirm: q.Confirm, Actor: h.actor(u)}
	h.s.submit(w, r, u, JobKindClusterStorageMode, "Move "+id+"'s data to "+string(q.To)+" storage", req, "cluster.storage.mode", id+" "+string(q.To), nil)
}

type chapRotateRequest struct {
	Confirm string `json:"confirm"`
}

func (h *clusterStorageAPI) chapRotate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var q chapRotateRequest
	if !decodeJSON(w, r, &q) {
		return
	}
	node := cluster.NodeID(r.PathValue("node"))
	if san.ValidNode(node) != nil || q.Confirm != string(node) {
		writeError(w, http.StatusBadRequest, "confirm", "Type the server's name to give it new CHAP secrets.")
		return
	}
	h.s.submit(w, r, u, JobKindClusterStorageCHAP, "New CHAP secrets for "+string(node), chapJob{Node: node, Actor: h.actor(u)}, "cluster.storage.chap.rotate", string(node), nil)
}
