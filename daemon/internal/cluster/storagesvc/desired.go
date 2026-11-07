// Package storagesvc is hardyd's side of cluster storage
// (docs/plans/cluster.md sections 5 and 6.1): the storage node's agent
// that turns the applied cluster state into LIO, exports and firewall
// (through hardyd-priv's san.* operations) and acknowledges grants and
// fences in the log; the StorageService any member calls (it runs on the
// storage node over the peer API); the compute node's StorageAttacher;
// CHAP distribution; and the VM freeze and app dump the storage node
// forwards to a workload's owner around its snapshots.
//
// The one rule that keeps disks safe lives in BuildDesired: what is mapped
// and exported comes from the applied, signed cluster state only, never
// from a request. Root checks it again (san.Desired.Validate, the datasets'
// own properties, its recorded fences).
package storagesvc

import (
	"net/netip"
	"slices"
	"sort"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
	"github.com/hardyos/hardyos/daemon/internal/network"
	"github.com/hardyos/hardyos/daemon/internal/nfs"
)

// Plan is what the storage node should look like for one applied state.
type Plan struct {
	SAN       san.Desired
	Addresses map[cluster.NodeID]netip.Addr
	// Keys are the compute nodes' cluster keys (root pins them with the
	// addresses); Subnet is the storage network.
	Keys   map[cluster.NodeID][]byte
	Subnet netip.Prefix
	// Exports name datasets and clients; root fills in paths and GUIDs.
	Exports []nfs.ClusterExport
	// Members and Fenced are storage addresses for the firewall.
	Members []netip.Addr
	Fenced  []netip.Addr
	// Acks are the grants this plan applies that aren't acknowledged yet.
	Acks []state.GrantAck
	// Fences to put in place (a dead or isolated node's unconfirmed
	// fence), and fences to lift (a rejoining node, confirmed fence).
	Fences   []cluster.Fence
	Unfences []cluster.Fence
}

// Hold takes a workload's storage out of the plan: nothing of it is mapped
// or exported while the storage node works on it offline (a rollback, a
// move between NFS and block mode). Its grant isn't acknowledged either.
func (p *Plan) Hold(w cluster.WorkloadRef) {
	var drop []string
	keep := p.SAN.Backstores[:0]
	for _, b := range p.SAN.Backstores {
		if b.Workload == w {
			drop = append(drop, b.Name)
			continue
		}
		keep = append(keep, b)
	}
	p.SAN.Backstores = keep
	for i := range p.SAN.Targets {
		p.SAN.Targets[i].LUNs = slices.DeleteFunc(p.SAN.Targets[i].LUNs, func(l string) bool { return slices.Contains(drop, l) })
	}
	ds := w.ID
	p.Exports = slices.DeleteFunc(p.Exports, func(e nfs.ClusterExport) bool {
		parts := splitDataset(e.Dataset)
		return len(parts) == 3 && parts[2] == ds && ((w.Kind == cluster.KindVM && parts[1] == "vms") || (w.Kind == cluster.KindApp && parts[1] == "apps"))
	})
	p.Acks = slices.DeleteFunc(p.Acks, func(a state.GrantAck) bool { return a.Workload == w })
}

// DropOwnerExports takes the VM state and app data exports (owner-only,
// no_root_squash) out of the plan, with the acknowledgements of the
// workloads that had them; it returns how many it took out.
func (p *Plan) DropOwnerExports() int {
	var gone []cluster.WorkloadRef
	p.Exports = slices.DeleteFunc(p.Exports, func(e nfs.ClusterExport) bool {
		if e.Kind != nfs.KindVMState && e.Kind != nfs.KindAppData {
			return false
		}
		parts := splitDataset(e.Dataset)
		if len(parts) == 3 {
			w := cluster.WorkloadRef{Kind: cluster.KindVM, ID: parts[2]}
			if e.Kind == nfs.KindAppData {
				w.Kind = cluster.KindApp
			}
			gone = append(gone, w)
		}
		return true
	})
	p.Acks = slices.DeleteFunc(p.Acks, func(a state.GrantAck) bool { return slices.Contains(gone, a.Workload) })
	return len(gone)
}

func splitDataset(ds string) []string {
	var out []string
	start := 0
	for i := 0; i < len(ds); i++ {
		if ds[i] == '/' {
			out = append(out, ds[start:i])
			start = i + 1
		}
	}
	return append(out, ds[start:])
}

// fencedNode reports whether a node must have no access now.
func fencedNode(s *cluster.Snapshot, n *cluster.Node) bool {
	if _, ok := s.Fences[n.ID]; ok {
		return true
	}
	switch n.State {
	case cluster.NodeDead, cluster.NodeFenced, cluster.NodeRejoining, cluster.NodeRemoved:
		return true
	}
	return false
}

// usableStorageAddrs says which compute nodes' storage addresses may be
// used (M1): a host address inside the cluster's storage subnet, not one
// of the storage node's own, and held by that node alone (two nodes
// claiming one address both get nothing until it is fixed).
func usableStorageAddrs(s *cluster.Snapshot, self cluster.NodeID, nodes []*cluster.Node) map[cluster.NodeID]bool {
	var own []netip.Addr
	if me := s.Nodes[self]; me != nil {
		own = append(own, me.Addresses.Storage)
		for _, p := range me.Addresses.Portals {
			own = append(own, p.Addr())
		}
	}
	count := map[netip.Addr]int{}
	for _, n := range nodes {
		if n.Role == cluster.RoleCompute && n.State != cluster.NodeRemoved && n.Addresses.Storage.IsValid() {
			count[n.Addresses.Storage]++
		}
	}
	out := map[cluster.NodeID]bool{}
	sub := s.StorageSubnet.Masked()
	for _, n := range nodes {
		a := n.Addresses.Storage
		switch {
		case n.Role != cluster.RoleCompute || !a.Is4():
		case s.StorageSubnet.IsValid() && (!sub.Contains(a) || a == sub.Addr()):
		case slices.Contains(own, a), count[a] > 1:
		default:
			out[n.ID] = true
		}
	}
	return out
}

// PlanCheck is CheckStoragePlan's answer.
type PlanCheck struct {
	Problems []string
	// NeedsConfirm: the plan changes this member's storage address; the
	// typed name confirms it.
	NeedsConfirm   bool
	ConfirmMessage string
}

// CheckStoragePlan checks a member's storage network plan against the
// cluster (M1, H2): the address inside the cluster's storage subnet, a
// host address no other member (nor the storage node) uses; a changed
// address only with the server's name typed (confirm), since the storage
// server's root then turns this server's target off until its
// administrator confirms the new address there too; and never the LAN
// itself while the cluster has VMs or apps in NFS mode, whose own data is
// exported without root squashing.
func CheckStoragePlan(s *cluster.Snapshot, me cluster.Node, p network.StoragePlan, confirm string) PlanCheck {
	var out PlanCheck
	pre, err := netip.ParsePrefix(p.Address)
	if err != nil {
		return out // the plan's own validation reports it
	}
	a := pre.Addr()
	if s.StorageSubnet.IsValid() {
		sub := s.StorageSubnet.Masked()
		if !sub.Contains(a) || pre.Masked() != sub {
			out.Problems = append(out.Problems, "the cluster's storage network is "+sub.String()+"; use an address in it with the same size")
		}
	}
	for _, n := range s.Nodes {
		if n.ID == me.ID {
			continue
		}
		taken := n.Addresses.Storage == a
		for _, pt := range n.Addresses.Portals {
			taken = taken || pt.Addr() == a
		}
		if taken {
			out.Problems = append(out.Problems, a.String()+" is "+string(n.ID)+"'s storage address")
		}
	}
	if p.Kind == network.StorageShared {
		for _, pl := range s.Placements {
			if pl.Workload.Kind == cluster.KindVM || pl.Storage.Mode != cluster.StorageBlock {
				out.Problems = append(out.Problems, "the cluster has VMs or apps whose own data is shared over NFS without root squashing; that needs a dedicated storage port or a VLAN, not the LAN itself")
				break
			}
		}
	}
	if cur := me.Addresses.Storage; cur.IsValid() && cur != a && confirm != string(me.ID) {
		out.NeedsConfirm = true
		out.ConfirmMessage = "This changes " + string(me.ID) + "'s storage address from " + cur.String() + " to " + a.String() +
			". Type the server's name to confirm; the storage server keeps " + string(me.ID) + " cut off until its administrator also runs " +
			"`hardyctl cluster-storage repin " + string(me.ID) + "` there."
	}
	return out
}

// sharesClient: nodes that mount cluster shares.
func sharesClient(n *cluster.Node) bool {
	return n.State == cluster.NodeActive || n.State == cluster.NodeMaintenance
}

// BuildDesired derives the storage node's configuration from the applied
// state. self is the storage node. Only compute nodes get targets; a node
// that is dead, fenced, rejoining or removed gets nothing (its target is
// disabled); a grant maps its workload's volumes into each named node's
// target (two only with GrantMigration) and exports its state or data to
// those nodes only; cluster shares go to every active compute node.
func BuildDesired(s *cluster.Snapshot, self cluster.NodeID) Plan {
	p := Plan{Addresses: map[cluster.NodeID]netip.Addr{}, Keys: map[cluster.NodeID][]byte{}}
	d := san.Desired{Cluster: s.Cluster, Index: s.Index}
	if me := s.Nodes[self]; me != nil {
		if len(me.Addresses.Portals) > 0 {
			d.Portals = slices.Clone(me.Addresses.Portals)
		} else if me.Addresses.Storage.IsValid() {
			d.Portals = []netip.AddrPort{netip.AddrPortFrom(me.Addresses.Storage, san.ISCSIPort)}
		}
	}
	nodes := make([]*cluster.Node, 0, len(s.Nodes))
	for _, n := range s.Nodes {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	p.Subnet = s.StorageSubnet
	usable := usableStorageAddrs(s, self, nodes)
	targets := map[cluster.NodeID]*san.Target{}
	for _, n := range nodes {
		if n.Role != cluster.RoleCompute || n.State == cluster.NodeRemoved {
			continue
		}
		if san.ValidNode(n.ID) != nil {
			continue
		}
		if len(n.PublicKey) > 0 {
			p.Keys[n.ID] = n.PublicKey
		}
		a := n.Addresses.Storage
		if !usable[n.ID] {
			a = netip.Addr{}
		}
		if a.IsValid() {
			p.Addresses[n.ID] = a
		}
		t := &san.Target{Node: n.ID, Enabled: !fencedNode(s, n), LUNs: []string{}}
		if f := s.Fences[n.ID]; f != nil {
			t.FenceEpoch = f.Epoch
		}
		targets[n.ID] = t
		if !a.IsValid() {
			continue
		}
		if fencedNode(s, n) {
			p.Fenced = append(p.Fenced, a)
		} else {
			p.Members = append(p.Members, a)
		}
	}
	// Fences and unfences.
	fids := make([]cluster.NodeID, 0, len(s.Fences))
	for id := range s.Fences {
		fids = append(fids, id)
	}
	slices.Sort(fids)
	for _, id := range fids {
		f := s.Fences[id]
		n := s.Nodes[id]
		if n == nil || n.Role != cluster.RoleCompute {
			continue
		}
		switch {
		case !f.Confirmed:
			p.Fences = append(p.Fences, *f)
		case n.State == cluster.NodeRejoining:
			p.Unfences = append(p.Unfences, *f)
		}
	}
	// Grants.
	refs := make([]cluster.WorkloadRef, 0, len(s.Grants))
	for w := range s.Grants {
		refs = append(refs, w)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Kind != refs[j].Kind {
			return refs[i].Kind < refs[j].Kind
		}
		return refs[i].ID < refs[j].ID
	})
	for _, w := range refs {
		g := s.Grants[w]
		pl := s.Placements[w]
		if pl == nil || state.ValidWorkloadStorage(w, pl.Storage) != nil {
			continue
		}
		holders := []cluster.NodeID{}
		for _, n := range g.Nodes {
			if t := targets[n]; t != nil && t.Enabled && !slices.Contains(holders, n) {
				holders = append(holders, n)
			}
		}
		limit := 1
		if g.Mode == cluster.GrantMigration {
			limit = 2
		}
		if len(holders) > limit {
			holders = holders[:limit]
		}
		for _, v := range pl.Storage.Volumes {
			b := san.Backstore{
				Name: san.BackstoreName(w, v.Disk), Workload: w, Dataset: v.Dataset, Disk: v.Disk,
				Generation: g.Generation, Migration: g.Mode == cluster.GrantMigration && len(holders) == 2,
			}
			d.Backstores = append(d.Backstores, b)
			for _, n := range holders {
				targets[n].LUNs = append(targets[n].LUNs, b.Name)
			}
		}
		var clients []netip.Addr
		for _, n := range holders {
			if a, ok := p.Addresses[n]; ok {
				clients = append(clients, a)
			}
		}
		for _, e := range pl.Storage.Exports {
			if e.Kind != cluster.ExportVMState && e.Kind != cluster.ExportAppData {
				continue
			}
			if len(clients) == 0 {
				continue
			}
			p.Exports = append(p.Exports, nfs.ClusterExport{Kind: string(e.Kind), Dataset: e.Dataset, Path: e.Path, GUID: e.FSID, Clients: slices.Clone(clients)})
		}
		if !g.Applied && len(holders) > 0 {
			p.Acks = append(p.Acks, state.GrantAck{Workload: w, Generation: g.Generation})
		}
	}
	// Shares.
	var shareClients []netip.Addr
	for _, n := range nodes {
		if a, ok := p.Addresses[n.ID]; ok && n.Role == cluster.RoleCompute && sharesClient(n) && !fencedNode(s, n) {
			shareClients = append(shareClients, a)
		}
	}
	sids := make([]string, 0, len(s.ClusterShares))
	for id := range s.ClusterShares {
		sids = append(sids, id)
	}
	slices.Sort(sids)
	for _, id := range sids {
		sh := s.ClusterShares[id]
		if len(shareClients) == 0 || state.ValidClusterShare(*sh) != nil {
			continue
		}
		p.Exports = append(p.Exports, nfs.ClusterExport{Kind: nfs.KindShare, Dataset: sh.Dataset, Path: sh.Path, GUID: sh.FSID, Clients: slices.Clone(shareClients)})
	}
	for _, n := range nodes {
		if t := targets[n.ID]; t != nil {
			d.Targets = append(d.Targets, *t)
		}
	}
	d.Normalize()
	p.SAN = d
	return p
}
