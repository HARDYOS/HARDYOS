package convert

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/hacopy"
	"github.com/hardyos/hardyos/daemon/internal/cluster/storagesvc"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// KeptCopy is a parked copy and where it is.
type KeptCopy struct {
	hacopy.Parked
	// Node holds it.
	Node cluster.NodeID `json:"node"`
	// DeleteOn is the server whose API deletes it ("": this one, which
	// deletes its own and, through the storage server's peer API, the
	// storage server's; another member's is deleted through that member's
	// own API, with its own guards).
	DeleteOn cluster.NodeID `json:"deleteOn,omitempty"`
}

// Peer paths of conversions (between members).
const (
	// PathKept is a member's own kept copies.
	PathKept = "ha/kept"
	// PathAppShares is the shared folders a cluster app placed on that
	// member uses (make local refuses apps that use any).
	PathAppShares = "ha/app-shares"
)

// ownKept lists this server's own parked copies.
func (c *Converter) ownKept(ctx context.Context) ([]hacopy.Parked, error) {
	var mine struct {
		Parked []hacopy.Parked `json:"parked"`
	}
	if err := c.Priv.Call(ctx, hacopy.OpParkedList, struct{}{}, &mine); err != nil {
		return nil, err
	}
	if mine.Parked == nil {
		mine.Parked = []hacopy.Parked{}
	}
	return mine.Parked, nil
}

// Kept lists the parked copies of every member (decision 505): this
// server's, the storage server's (through its storage peer API, as
// before) and every other member's (asked over the peer API, as the
// failover history is merged); a member that doesn't answer is left out.
func (c *Converter) Kept(ctx context.Context) ([]KeptCopy, error) {
	out := []KeptCopy{}
	self, err := c.Cluster.Self()
	if err != nil {
		return out, nil
	}
	if l, err := c.ownKept(ctx); err == nil {
		for _, p := range l {
			out = append(out, KeptCopy{Parked: p, Node: self.ID})
		}
	}
	snap := c.snapshot()
	sn, hasStorage := storagesvc.StorageNode(snap)
	if self.Role != cluster.RoleStorage && hasStorage {
		if l, err := c.Storage.HAParked(ctx); err == nil {
			for _, p := range l {
				out = append(out, KeptCopy{Parked: p, Node: sn.ID})
			}
		}
	}
	if c.Peers == nil {
		return out, nil
	}
	for id, n := range snap.Nodes {
		if id == self.ID || n.Role == cluster.RoleWitness || n.State == cluster.NodeRemoved || (hasStorage && id == sn.ID) {
			continue
		}
		var l []hacopy.Parked
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := c.Peers.Call(cctx, id, http.MethodGet, cluster.PeerPathPrefix+PathKept, nil, &l)
		cancel()
		if err != nil {
			continue
		}
		for _, p := range l {
			if len(out) >= 2000 {
				break
			}
			out = append(out, KeptCopy{Parked: p, Node: id, DeleteOn: id})
		}
	}
	slices.SortStableFunc(out, func(a, b KeptCopy) int {
		if x := strings.Compare(string(a.Node), string(b.Node)); x != 0 {
			return x
		}
		return strings.Compare(a.Pool+"/"+a.Name, b.Pool+"/"+b.Name)
	})
	return out, nil
}

// RegisterPeer serves this member's own kept copies and its cluster apps'
// shared folders to the other members (any member but the witness; both
// only read).
func (c *Converter) RegisterPeer(mux cluster.PeerMux) {
	if mux == nil {
		return
	}
	member := func(r *http.Request) bool {
		n, ok := mux.Caller(r)
		return ok && n.Role != cluster.RoleWitness
	}
	mux.Handle("GET "+cluster.PeerPathPrefix+PathKept, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !member(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		l, err := c.ownKept(r.Context())
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(l)
	}))
	mux.Handle("GET "+cluster.PeerPathPrefix+PathAppShares, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !member(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		id := r.URL.Query().Get("id")
		if !appIDRE.MatchString(id) {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		var res apps.HACheckResult
		if err := c.Priv.Call(r.Context(), priv.OpAppsHACheck, priv.AppRef{ID: id}, &res); err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if res.Shares == nil {
			res.Shares = []apps.HAShare{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"shares": res.Shares})
	}))
}

var appIDRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)

// DropParams delete a kept copy now (Confirm: the workload's id;
// LastCopy: one without an expiry, which may be the only good copy).
type DropParams struct {
	Node     cluster.NodeID `json:"node"`
	Pool     string         `json:"pool"`
	Name     string         `json:"name"`
	Confirm  string         `json:"confirm"`
	LastCopy bool           `json:"lastCopy,omitempty"`
	Actor    cluster.Actor  `json:"actor"`
}

func (c *Converter) runDrop(jc *jobs.Context) (any, error) {
	var p DropParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	self, err := c.Cluster.Self()
	if err != nil {
		return nil, err
	}
	if p.Node == self.ID {
		err = c.Priv.Call(jc, hacopy.OpParkedDestroy, hacopy.ParkedDestroyArgs{Pool: p.Pool, Name: p.Name, Confirm: p.Confirm, LastCopy: p.LastCopy}, nil)
	} else {
		sn, ok := storagesvc.StorageNode(c.snapshot())
		if !ok || sn.ID != p.Node {
			return nil, errors.New("kept copies are deleted on their own server or on the storage server")
		}
		err = c.Storage.HAParkedDestroy(jc, storagesvc.HAParkedDestroy{Pool: p.Pool, Name: p.Name, Confirm: p.Confirm, LastCopy: p.LastCopy, Actor: p.Actor})
	}
	c.audit(p.Actor, "cluster.ha.parked.delete", string(p.Node)+":"+p.Pool+"/"+p.Name, "", err)
	if err != nil {
		return nil, err
	}
	return map[string]bool{"deleted": true}, nil
}

// RegisterJobs registers the conversion jobs.
func (c *Converter) RegisterJobs(m *jobs.Manager) {
	if m == nil {
		return
	}
	lock := func(raw json.RawMessage) string {
		var p struct {
			Workload cluster.WorkloadRef `json:"workload"`
			Conv     string              `json:"conv"`
		}
		_ = json.Unmarshal(raw, &p)
		if p.Workload.ID == "" && p.Conv != "" && c.DB != nil {
			if r, err := c.Get(context.Background(), p.Conv); err == nil {
				p.Workload = r.Ref()
			}
		}
		return ClusterLock(p.Workload)
	}
	reg := func(name string, run jobs.RunFunc) {
		m.Register(jobs.Kind{Name: name, AdminOnly: true, LockKey: lock, Run: run})
	}
	reg(JobToHA, c.runToHA)
	reg(JobToLocal, c.runToLocal)
	reg(JobUndo, c.runUndo)
	reg(JobAbandon, c.runAbandon)
	m.Register(jobs.Kind{Name: JobParkedDrop, AdminOnly: true, Run: c.runDrop})
}

// CleanupInterval is how often expired kept copies are deleted.
var CleanupInterval = 10 * time.Minute

// Run deletes kept copies past their grace period (on whichever server
// holds them) and starts the grace period of copies kept for workloads
// that first ran from their new storage since.
func (c *Converter) Run(ctx context.Context) {
	t := time.NewTicker(CleanupInterval)
	defer t.Stop()
	for {
		c.Cleanup(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Cleanup is one round of Run.
func (c *Converter) Cleanup(ctx context.Context) {
	if c.Priv == nil {
		return
	}
	var mine struct {
		Parked []hacopy.Parked `json:"parked"`
	}
	if err := c.Priv.Call(ctx, hacopy.OpParkedList, struct{}{}, &mine); err != nil {
		return
	}
	now := c.now()
	for _, p := range mine.Parked {
		if p.KeepUntil.IsZero() || now.Before(p.KeepUntil) {
			continue
		}
		err := c.Priv.Call(ctx, hacopy.OpParkedDestroy, hacopy.ParkedDestroyArgs{Pool: p.Pool, Name: p.Name, Confirm: p.ID}, nil)
		c.audit(cluster.Actor{Kind: "system", Name: "HardyOS"}, "cluster.ha.parked.expire", p.Pool+"/"+p.Name,
			"kept since "+p.Created.Format(time.RFC3339), err)
	}
	if !c.Member() || c.DB == nil {
		return
	}
	// Workloads that were off when they moved: their kept copy's grace
	// period starts once they ran from cluster storage.
	l, err := c.List(ctx, 200)
	if err != nil {
		return
	}
	snap := c.snapshot()
	for i := range l {
		r := &l[i]
		if !r.Options.AwaitStart || r.Options.ParkedName == "" || r.Options.ClusterChanged {
			continue
		}
		var ran bool
		switch {
		case r.Direction == DirHA && r.State == StateDone:
			// Made highly available while off: it ran from cluster storage.
			pl := snap.Placements[r.Ref()]
			ran = pl != nil && pl.State == cluster.PlacementRunning
		case (r.Direction == DirHA && r.State == StateUndone) || (r.Direction == DirLocal && r.State == StateDone):
			// Back on this server's own storage: it ran from there.
			ran = c.localRunning(ctx, r.Ref())
		}
		if !ran {
			continue
		}
		if err := c.keepFor(ctx, hacopy.Side(r.Options.ParkedSide), r.Options.ParkedPool, r.Options.ParkedName, c.grace(), cluster.Actor{Kind: "system", Name: "HardyOS"}); err != nil {
			continue
		}
		// The shared folders kept with it (decision 503).
		c.keepShares(ctx, r, cluster.Actor{Kind: "system", Name: "HardyOS"})
		r.Options.AwaitStart = false
		_ = c.save(ctx, r)
	}
}

// localRunning: this server runs w from its own storage.
func (c *Converter) localRunning(ctx context.Context, w cluster.WorkloadRef) bool {
	if w.Kind == cluster.KindApp {
		var res apps.HACheckResult
		return c.Priv.Call(ctx, priv.OpAppsHACheck, priv.AppRef{ID: w.ID}, &res) == nil && res.Running
	}
	var v vms.VM
	return c.Priv.Call(ctx, priv.OpVMsGet, priv.VMRef{ID: w.ID}, &v) == nil && v.Backend != vms.BackendCluster && v.State == "running"
}
