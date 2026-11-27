package ha

// Failover history and alerts (docs/plans/make-ha.md, decision 484): the
// leader that coordinated a recovery records it in its own database and
// raises an alert; the history the desktop shows is every HardyOS
// member's, merged (leadership moves).

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"time"

	"errors"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

var errChanged = errors.New("the approved settings changed meanwhile")

func stateSpec(w cluster.WorkloadRef, gen uint64, h string) state.WorkloadSpecSet {
	return state.WorkloadSpecSet{Workload: w, Generation: gen, SpecHash: h}
}

// PathFailovers is the peer path of a member's failover history.
const PathFailovers = "ha/failovers"

func (s *Service) recordFailover(f Failover) {
	if s.DB != nil {
		if _, err := s.DB.ExecContext(context.Background(), `INSERT INTO cluster_failovers (at, kind, workload, name, from_node, to_node, outcome, problem, priority, coordinator)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, store.FormatTime(f.At), string(f.Workload.Kind), f.Workload.ID, f.Name, string(f.From), string(f.To),
			f.Outcome, f.Problem, f.Priority, string(f.Coordinator)); err != nil {
			s.log().Warn("ha: recording a failover", "err", err)
		}
	}
	if s.Notify == nil {
		return
	}
	ev := notify.Event{Link: "cluster", Time: f.At}
	switch f.Outcome {
	case FailoverRestarted:
		ev.Kind, ev.Severity = "cluster.ha.failover", notify.SeverityWarning
		if f.From != "" {
			ev.Title = f.Name + " is restarting on " + string(f.To)
			ev.Body = string(f.From) + " is down (its storage access is cut off); " + f.Name + " restarts on " + string(f.To) + " from cluster storage."
		} else {
			ev.Title = f.Name + " is starting on " + string(f.To)
			ev.Body = "A server can run it again."
		}
	case FailoverPending:
		ev.Kind, ev.Severity = "cluster.ha.nowhere", notify.SeverityCritical
		ev.Title = "No server can run " + f.Name
		ev.Body = "It waits and is tried again every 30 seconds. " + f.Problem
	default:
		ev.Kind, ev.Severity = "cluster.ha.failover", notify.SeverityCritical
		ev.Title = "Restarting " + f.Name + " elsewhere failed"
		ev.Body = f.Problem
	}
	s.Notify.Notify(context.Background(), ev)
}

// LocalFailovers lists the failovers this server coordinated, newest
// first.
func (s *Service) LocalFailovers(ctx context.Context, limit int) ([]Failover, error) {
	out := []Failover{}
	if s.DB == nil {
		return out, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT at, kind, workload, name, from_node, to_node, outcome, problem, priority, coordinator
		FROM cluster_failovers ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var f Failover
		var at, kind, from, to, coord string
		if err := rows.Scan(&at, &kind, &f.Workload.ID, &f.Name, &from, &to, &f.Outcome, &f.Problem, &f.Priority, &coord); err != nil {
			return nil, err
		}
		f.At = store.ParseTime(at)
		f.Workload.Kind, f.From, f.To, f.Coordinator = cluster.WorkloadKind(kind), cluster.NodeID(from), cluster.NodeID(to), cluster.NodeID(coord)
		out = append(out, f)
	}
	return out, rows.Err()
}

// Failovers merges every reachable HardyOS member's history (newest
// first, at most limit).
func (s *Service) Failovers(ctx context.Context, limit int) ([]Failover, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	all, err := s.LocalFailovers(ctx, limit)
	if err != nil {
		return nil, err
	}
	if s.Member() && s.Parts.Peers != nil {
		self, _ := s.Parts.Membership.Self()
		snap := s.Parts.Membership.State().Snapshot()
		for id, n := range snap.Nodes {
			if id == self.ID || n.Role == cluster.RoleWitness || n.State == cluster.NodeRemoved {
				continue
			}
			var l []Failover
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := s.Parts.Peers.Call(cctx, id, http.MethodGet, cluster.PeerPathPrefix+PathFailovers+"?limit="+strconv.Itoa(limit), nil, &l)
			cancel()
			if err == nil {
				all = append(all, l...)
			}
		}
	}
	slices.SortStableFunc(all, func(a, b Failover) int { return b.At.Compare(a.At) })
	if len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

// registerFailovers serves this member's history to the others.
func (s *Service) registerFailovers(mux cluster.PeerMux) {
	mux.Handle("GET "+cluster.PeerPathPrefix+PathFailovers, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, ok := mux.Caller(r); !ok || c.Role == cluster.RoleWitness {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		l, err := s.LocalFailovers(r.Context(), limit)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(l)
	}))
}

// Hold keeps this server's reconciler off a workload until the release
// (a conversion attaching and writing its settings).
func (s *Service) Hold(w cluster.WorkloadRef) func() {
	if s.Reconciler == nil {
		return func() {}
	}
	return s.Reconciler.Hold(w)
}

// ---- unattended installs that end on a cluster VM (decision 486) -----------------

// InstallApproveInterval is how often root's finished installs are
// approved.
var InstallApproveInterval = 30 * time.Second

type installDone struct {
	ID     string `json:"id"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// approveInstalls records, for each cluster VM placed here whose
// unattended install root ended, exactly that change of its settings as
// approved: the placement's hash must be the one before root's change and
// the stored spec must hash to the one after.
func (s *Service) approveInstalls(ctx context.Context) {
	t := time.NewTicker(InstallApproveInterval)
	defer t.Stop()
	for {
		s.ApproveInstallsOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ApproveInstallsOnce is one round of approveInstalls.
func (s *Service) ApproveInstallsOnce(ctx context.Context) {
	if s.Priv == nil || !s.Member() {
		return
	}
	self, err := s.Parts.Membership.Self()
	if err != nil || self.Role != cluster.RoleCompute {
		return
	}
	var res struct {
		Done []installDone `json:"done"`
	}
	if err := s.Priv.Call(ctx, priv.OpVMsClusterInstall, map[string]any{}, &res); err != nil {
		return
	}
	var ack []string
	for _, d := range res.Done {
		w := cluster.WorkloadRef{Kind: cluster.KindVM, ID: d.ID}
		p, ok := s.Parts.Membership.State().Placement(w)
		if !ok || p == nil || p.Owner != self.ID {
			ack = append(ack, d.ID)
			continue
		}
		if p.SpecHash == d.After {
			ack = append(ack, d.ID)
			continue
		}
		if p.SpecHash != d.Before {
			s.log().Warn("ha: a cluster VM's install ended, but its approved settings changed meanwhile; not approving", "vm", d.ID)
			s.auditOutcome("cluster.spec.install", "vm:"+d.ID, "the approved settings changed meanwhile; save the VM's settings again", errChanged)
			ack = append(ack, d.ID)
			continue
		}
		h, err := s.SpecHash(ctx, w)
		if err != nil || h != d.After {
			s.log().Warn("ha: a cluster VM's install ended, but its settings aren't root's own change; not approving", "vm", d.ID, "err", err)
			ack = append(ack, d.ID)
			continue
		}
		actor := cluster.Actor{Kind: "system", Name: "HardyOS (Windows install finished)", Via: self.ID}
		err = s.propose(ctx, cluster.CmdWorkloadSpec, stateSpec(w, p.Generation, h), actor)
		s.auditOutcome("cluster.spec.install", "vm:"+d.ID, "the unattended install's own change of the settings, approved", err)
		if err == nil {
			ack = append(ack, d.ID)
		}
	}
	if len(ack) > 0 {
		_ = s.Priv.Call(ctx, priv.OpVMsClusterInstall, map[string]any{"ack": ack}, &res)
	}
}
