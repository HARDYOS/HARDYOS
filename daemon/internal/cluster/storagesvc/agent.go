package storagesvc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
	"github.com/hardyos/hardyos/daemon/internal/network"
)

// systemActor is HardyOS itself acting (the storage agent).
func systemActor(self cluster.NodeID) cluster.Actor {
	return cluster.Actor{Kind: "system", Name: "storage agent", Via: self}
}

// AgentStatus is the agent's last pass.
type AgentStatus struct {
	At       time.Time        `json:"at"`
	Index    uint64           `json:"index"`
	Problem  string           `json:"problem,omitempty"`
	Fenced   []cluster.NodeID `json:"fenced,omitempty"`
	Acked    int              `json:"acked"`
	Targets  int              `json:"targets"`
	LUNs     int              `json:"luns"`
	Exports  int              `json:"exports"`
	Firewall bool             `json:"firewall"`
}

// Agent turns the applied state into this node's storage configuration:
// on the storage node LIO, exports, firewall, fences and their
// acknowledgements; on a compute node the cluster shares' mounts and the
// live-migration firewall. It runs on every applied change and every
// Interval.
type Agent struct {
	S        *Service
	Interval time.Duration

	mu   sync.Mutex
	last AgentStatus
	pass sync.Mutex
}

// NewAgent makes the agent and lets the service run a pass on demand
// (offline work on the storage node).
func NewAgent(s *Service) *Agent {
	a := &Agent{S: s}
	s.reconcile = a.Reconcile
	return a
}

// Status returns the last pass.
func (a *Agent) Status() AgentStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.last
}

// Run reconciles until ctx ends.
func (a *Agent) Run(ctx context.Context) {
	if a.S.M == nil {
		return
	}
	iv := a.Interval
	if iv == 0 {
		iv = 15 * time.Second
	}
	events := a.S.M.Subscribe(ctx)
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		if err := a.Reconcile(ctx); err != nil && !errors.Is(err, cluster.ErrNotMember) {
			a.S.log().Warn("storage agent", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case _, ok := <-events:
			if !ok {
				events = nil
			}
			// Coalesce a burst of applied entries.
			drain := time.After(200 * time.Millisecond)
		loop:
			for {
				select {
				case <-events:
				case <-drain:
					break loop
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

// Reconcile runs one pass. Passes never overlap, so a pass that started
// before a hold can't map the held storage again after it.
func (a *Agent) Reconcile(ctx context.Context) error {
	a.pass.Lock()
	defer a.pass.Unlock()
	me, snap, err := a.S.self()
	if err != nil {
		return err
	}
	st := AgentStatus{At: time.Now().UTC(), Index: snap.Index}
	switch me.Role {
	case cluster.RoleStorage:
		err = a.reconcileStorage(ctx, me, snap, &st)
	case cluster.RoleCompute:
		err = a.reconcileCompute(ctx, me, snap, &st)
	}
	if err != nil {
		st.Problem = err.Error()
	}
	a.mu.Lock()
	a.last = st
	a.mu.Unlock()
	return err
}

func (a *Agent) propose(ctx context.Context, self cluster.NodeID, t cluster.CommandType, body any) error {
	idx, err := a.S.M.Propose(ctx, t, body, systemActor(self))
	if err != nil {
		return err
	}
	return a.S.M.WaitApplied(ctx, idx)
}

func (a *Agent) reconcileStorage(ctx context.Context, me cluster.Node, snap *cluster.Snapshot, st *AgentStatus) error {
	s := a.S
	p := BuildDesired(snap, me.ID)
	for _, w := range s.held() {
		p.Hold(w)
	}
	var errs []error
	// 1. Fences: root records and enforces them, then the log learns.
	for _, f := range p.Fences {
		if err := s.FenceNode(ctx, f.Node, f.Epoch); err != nil {
			errs = append(errs, fmt.Errorf("fencing %s: %w", f.Node, err))
			continue // retried next pass; recovery waits for storage.fenced
		}
		st.Fenced = append(st.Fenced, f.Node)
		if err := a.propose(ctx, me.ID, cluster.CmdStorageFenced, state.StorageFencedBody{Node: f.Node, Epoch: f.Epoch}); err != nil {
			errs = append(errs, fmt.Errorf("confirming %s's fence: %w", f.Node, err))
		}
	}
	// 2. Unfences of rejoining nodes.
	for _, f := range p.Unfences {
		if err := s.UnfenceNode(ctx, f.Node, f.Epoch); err != nil {
			errs = append(errs, fmt.Errorf("unfencing %s: %w", f.Node, err))
			continue
		}
		if err := a.propose(ctx, me.ID, cluster.CmdStorageUnfence, state.StorageUnfencedBody{Node: f.Node, Epoch: f.Epoch}); err != nil {
			errs = append(errs, err)
		}
	}
	// 3. LIO, exports, firewall.
	applied := true
	var sst san.Status
	if err := s.Priv.Call(ctx, san.OpApply, san.ApplyArgs{Desired: p.SAN, Addresses: p.Addresses, Keys: p.Keys, Subnet: p.Subnet}, &sst); err != nil {
		errs = append(errs, fmt.Errorf("iSCSI targets: %w", err))
		applied = false
	}
	if s.sharedLAN(ctx) {
		// A VM's or app's own data is exported without root squashing, so
		// only on a dedicated storage network or VLAN (H2); root refuses
		// it on the LAN as well.
		if n := p.DropOwnerExports(); n > 0 {
			errs = append(errs, fmt.Errorf("%d VM or app data exports are off: the storage network is the LAN itself; use a dedicated port or a VLAN", n))
		}
	}
	if err := s.Priv.Call(ctx, san.OpNFSClusterSet, san.NFSApplyArgs{Exports: p.Exports, Index: snap.Index}, nil); err != nil {
		errs = append(errs, fmt.Errorf("cluster exports: %w", err))
		applied = false
	}
	if iface, _, err := s.StorageInterface(ctx, snap.StorageSubnet); err == nil && snap.StorageSubnet.IsValid() {
		spec := san.FirewallSpec{Role: cluster.RoleStorage, Interface: iface, Subnet: snap.StorageSubnet.Masked(), Members: p.Members, Fenced: p.Fenced, Index: snap.Index}
		if err := s.Priv.Call(ctx, san.OpFirewallApply, spec, nil); err != nil {
			errs = append(errs, fmt.Errorf("storage firewall: %w", err))
		} else {
			st.Firewall = true
		}
	}
	st.Targets = len(p.SAN.Targets)
	for _, t := range p.SAN.Targets {
		st.LUNs += len(t.LUNs)
	}
	st.Exports = len(p.Exports)
	// 4. Acknowledge what is now in place.
	if applied && len(p.Acks) > 0 {
		if err := a.propose(ctx, me.ID, cluster.CmdStorageApplied, state.StorageAppliedBody{Grants: p.Acks}); err != nil {
			errs = append(errs, fmt.Errorf("acknowledging grants: %w", err))
		} else {
			st.Acked = len(p.Acks)
		}
	}
	return errors.Join(errs...)
}

// sendRejoin hands the storage node this node's signed rejoin statement
// once node.rejoin is applied for it (H3): root lifts the fence only with
// it. Sent on every pass while the node is rejoining.
func (s *Service) sendRejoin(ctx context.Context, me cluster.Node, snap *cluster.Snapshot) error {
	f := snap.Fences[me.ID]
	if me.State != cluster.NodeRejoining || f == nil || !f.Confirmed {
		return nil
	}
	sn, ok := StorageNode(snap)
	if !ok || s.Peers == nil {
		return nil
	}
	c := s.core()
	if c == nil || c.Identity() == nil {
		return errors.New("the cluster key isn't available")
	}
	stmt, err := san.SignRejoin(c.Identity().Key, san.RejoinStatement{Cluster: snap.Cluster, Node: me.ID, Epoch: f.Epoch, BootID: me.BootID})
	if err != nil {
		return err
	}
	if err := s.Peers.Call(ctx, sn.ID, "POST", "storage/rejoin", stmt, nil); err != nil {
		return err
	}
	s.rejoinMu.Lock()
	s.rejoinSent = f.Epoch
	s.rejoinMu.Unlock()
	return nil
}

// sharedLAN reports whether this storage node's storage network is the
// LAN itself (its saved plan says so).
func (s *Service) sharedLAN(ctx context.Context) bool {
	if s.Store == nil {
		return false
	}
	p, err := s.Store.StorageNet(ctx)
	return err == nil && p != nil && p.Kind == network.StorageShared
}

func (a *Agent) reconcileCompute(ctx context.Context, me cluster.Node, snap *cluster.Snapshot, st *AgentStatus) error {
	s := a.S
	var errs []error
	if err := s.sendRejoin(ctx, me, snap); err != nil {
		errs = append(errs, fmt.Errorf("asking the storage server to let this server back in: %w", err))
	}
	if err := s.SyncShares(ctx); err != nil {
		errs = append(errs, fmt.Errorf("cluster shares: %w", err))
	}
	if iface, _, err := s.StorageInterface(ctx, snap.StorageSubnet); err == nil && snap.StorageSubnet.IsValid() {
		p := BuildDesired(snap, me.ID)
		spec := san.FirewallSpec{Role: cluster.RoleCompute, Interface: iface, Subnet: snap.StorageSubnet.Masked(), Members: p.Members, Fenced: p.Fenced, Index: snap.Index}
		if err := s.Priv.Call(ctx, san.OpFirewallApply, spec, nil); err != nil {
			errs = append(errs, fmt.Errorf("live migration firewall: %w", err))
		} else {
			st.Firewall = true
		}
	}
	return errors.Join(errs...)
}
