// Package clustertest is an in-process cluster for part C's tests
// (docs/plans/cluster.md section 10): one linear replicated state with the
// real appliers, fake part A (membership, quorum leases, partitions,
// leader), a fake part B storage node (LUN mapping, grants, fences), and
// per node fake runtimes, attachers and watchdogs, all on a fake clock.
// It records every moment two nodes could write one workload's disk.
package clustertest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/fence"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha"
	"github.com/hardyos/hardyos/daemon/internal/cluster/placement"
	"github.com/hardyos/hardyos/daemon/internal/cluster/runtime"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
)

// Clock is a fake clock (monotonic enough for the code under test).
type Clock struct {
	mu  sync.Mutex
	now time.Time
}

// NewClock starts at a fixed time.
func NewClock() *Clock { return &Clock{now: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)} }

// Now returns the fake time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock on.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// Part B's command types as the fake storage node proposes them.
const (
	cmdApplied  = cluster.CmdStorageApplied
	cmdFenced   = cluster.CmdStorageFenced
	cmdUnfenced = cluster.CmdStorageUnfence
)

type storageBody struct {
	Workload   cluster.WorkloadRef `json:"workload,omitempty"`
	Generation uint64              `json:"generation,omitempty"`
	Node       cluster.NodeID      `json:"node,omitempty"`
	Epoch      uint64              `json:"epoch,omitempty"`
}

// fakeB is a stand-in for part B's storage.* appliers.
type fakeB struct{}

func (fakeB) Types() []cluster.CommandType {
	return []cluster.CommandType{cmdApplied, cmdFenced, cmdUnfenced}
}
func (fakeB) Signers(cluster.CommandType) []cluster.Role { return []cluster.Role{cluster.RoleStorage} }
func (fakeB) Apply(s *cluster.Snapshot, c cluster.Command) error {
	var b storageBody
	if err := json.Unmarshal(c.Body, &b); err != nil {
		return err
	}
	switch c.Type {
	case cmdApplied:
		g := s.Grants[b.Workload]
		if g == nil || g.Generation != b.Generation {
			return cluster.ErrStaleGeneration
		}
		g.Applied = true
	case cmdFenced:
		f := s.Fences[b.Node]
		n := s.Nodes[b.Node]
		if f == nil || n == nil || f.Epoch != b.Epoch || n.FenceEpoch != b.Epoch {
			return cluster.ErrStaleGeneration
		}
		f.Confirmed, f.ConfirmedAt = true, c.Time
		if n.State == cluster.NodeDead {
			n.State = cluster.NodeFenced
		}
	case cmdUnfenced:
		n := s.Nodes[b.Node]
		if n == nil || n.State != cluster.NodeRejoining {
			return errors.New("not rejoining")
		}
		n.State = cluster.NodeActive
	}
	return nil
}

// World is the whole in-process cluster.
type World struct {
	T     testing.TB
	Clock *Clock

	mu         sync.Mutex
	snap       *cluster.Snapshot
	appliers   map[cluster.CommandType]cluster.Applier
	index      uint64
	seq        map[cluster.NodeID]uint64
	Nodes      map[cluster.NodeID]*Node
	order      []cluster.NodeID
	leader     cluster.NodeID
	mapped     map[cluster.WorkloadRef][]cluster.NodeID
	storageUp  bool
	Applied    []string // "type proposer ok|err"
	Violations []string
	Rejected   []string
	// Requirements override what the fake runtimes report per workload.
	Requirements map[cluster.WorkloadRef]*cluster.Requirements
	resets     map[cluster.NodeID]int
}

// Node is one member.
type Node struct {
	w           *World
	ID          cluster.NodeID
	Role        cluster.Role
	reg         []cluster.Applier
	mu          sync.Mutex
	Connected   bool // reaches the leader's side (quorum)
	Crashed     bool // powered off
	frozen      *cluster.Snapshot
	lastContact time.Time
	StorageOK   bool
	LANOK       bool
	BootID      string
	Running     map[cluster.WorkloadRef]uint64 // processes and the generation each started under
	attached    map[cluster.WorkloadRef]uint64
	// watchdog
	Armed    bool
	petUntil time.Time
	wdTime   time.Duration
	// SelfFenceFails: killing workloads hangs (stuck I/O).
	SelfFenceFails bool
	// WatchdogKind is what the node's watchdog is.
	WatchdogKind string

	Agent *fence.Agent
	Rec   *runtime.Reconciler
	Coord *ha.Coordinator
	Mover cluster.Mover
}

// New makes a cluster: a storage node "nas" and compute nodes.
func New(t testing.TB, compute ...cluster.NodeID) *World {
	w := &World{T: t, Clock: NewClock(), appliers: map[cluster.CommandType]cluster.Applier{}, seq: map[cluster.NodeID]uint64{},
		Nodes: map[cluster.NodeID]*Node{}, mapped: map[cluster.WorkloadRef][]cluster.NodeID{}, storageUp: true, resets: map[cluster.NodeID]int{}}
	for _, a := range []cluster.Applier{state.Placements{}, state.Fences{}, fakeB{}} {
		for _, ty := range a.Types() {
			w.appliers[ty] = a
		}
	}
	s := &cluster.Snapshot{Cluster: "testclusterid", Name: "test", Timings: cluster.DefaultTimings,
		StorageSubnet: mustPrefix("10.77.0.0/24"), CPUBaseline: "x86-64-v2",
		Nodes: map[cluster.NodeID]*cluster.Node{}, Placements: map[cluster.WorkloadRef]*cluster.Placement{},
		Grants: map[cluster.WorkloadRef]*cluster.Grant{}, Fences: map[cluster.NodeID]*cluster.Fence{}, Seq: map[cluster.NodeID]uint64{},
		HAOverrides: map[cluster.NodeID]*cluster.WatchdogOverride{}}
	w.snap = s
	add := func(id cluster.NodeID, role cluster.Role, i int) {
		n := &cluster.Node{ID: id, Name: string(id), Role: role, State: cluster.NodeActive, Suffrage: cluster.Voter, BootID: "boot-1",
			Addresses: cluster.Addresses{LAN: mustAddr(fmt.Sprintf("192.168.1.%d", 20+i)), Storage: mustAddr(fmt.Sprintf("10.77.0.%d", 20+i))}}
		if role == cluster.RoleCompute {
			n.Compute = &cluster.ComputeInfo{CPUs: 16, MemoryMB: 65536, CPUModel: "Skylake", Watchdog: "hardware", KVM: true, Bridges: map[string][]int{"br0": {-1}}}
		}
		s.Nodes[id] = n
		w.Nodes[id] = &Node{w: w, ID: id, Role: role, Connected: true, StorageOK: true, LANOK: true, BootID: "boot-1",
			Running: map[cluster.WorkloadRef]uint64{}, attached: map[cluster.WorkloadRef]uint64{}, WatchdogKind: "hardware"}
		w.order = append(w.order, id)
	}
	add("nas", cluster.RoleStorage, 0)
	for i, id := range compute {
		add(id, cluster.RoleCompute, i+1)
	}
	for _, n := range w.Nodes {
		n.lastContact = w.Clock.Now()
	}
	w.leader = "nas"
	if len(compute) > 0 {
		w.leader = compute[0]
	}
	for _, id := range w.order {
		w.wire(w.Nodes[id])
	}
	return w
}

func (w *World) wire(n *Node) {
	if n.Role != cluster.RoleCompute && n.Role != cluster.RoleStorage {
		return
	}
	rts := []cluster.Runtime{&fakeRuntime{n: n, kind: cluster.KindVM}, &fakeRuntime{n: n, kind: cluster.KindApp}}
	n.Rec = &runtime.Reconciler{Cluster: n, Attacher: &fakeAttacher{n: n}, Runtimes: rts, BootID: func() string { return n.BootID }, Now: w.Clock.Now}
	n.Agent = &fence.Agent{Cluster: n, Watchdog: &fakeWatchdog{n: n}, Fencer: &fakeFencer{n: n}, Running: n.Rec.Local, Now: w.Clock.Now}
	n.Coord = &ha.Coordinator{Cluster: n, Scheduler: &placement.Scheduler{ReservedMB: 1024}, Now: w.Clock.Now}
}

// Leader sets the leader.
func (w *World) SetLeader(id cluster.NodeID) {
	w.mu.Lock()
	w.leader = id
	w.mu.Unlock()
}

// Snapshot is a copy of the applied state.
func (w *World) Snapshot() *cluster.Snapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	return clone(w.snap)
}

// Mapped is which nodes the storage node maps w's LUNs to.
func (w *World) Mapped(ref cluster.WorkloadRef) []cluster.NodeID {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.mapped[ref])
}

// SetStorageUp turns the fake storage node's agent on or off (off: no
// grants applied, no fences confirmed).
func (w *World) SetStorageUp(up bool) {
	w.mu.Lock()
	w.storageUp = up
	w.mu.Unlock()
	if up {
		w.storageAgent()
	}
}

// Resets says how often a node's watchdog reset it.
func (w *World) Resets(id cluster.NodeID) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.resets[id]
}

// Propose applies a command as id (for test setup).
func (w *World) Propose(id cluster.NodeID, t cluster.CommandType, body any) error {
	_, err := w.Nodes[id].Propose(context.Background(), t, body, cluster.Actor{Kind: "local", Name: "test", Via: id})
	return err
}

func (w *World) apply(proposer cluster.NodeID, t cluster.CommandType, body any) (uint64, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	w.mu.Lock()
	idx, err := w.applyLocked(proposer, t, raw)
	w.mu.Unlock()
	if err == nil {
		w.storageAgent()
	}
	return idx, err
}

func (w *World) applyLocked(proposer cluster.NodeID, t cluster.CommandType, raw json.RawMessage) (uint64, error) {
	a, ok := w.appliers[t]
	if !ok {
		return 0, fmt.Errorf("no applier for %s", t)
	}
	pn := w.snap.Nodes[proposer]
	if pn == nil || !slices.Contains(a.Signers(t), pn.Role) {
		w.Rejected = append(w.Rejected, string(t)+" by "+string(proposer)+": signer")
		return 0, fmt.Errorf("%s may not sign %s", proposer, t)
	}
	w.seq[proposer]++
	c := cluster.Command{Type: t, Cluster: w.snap.Cluster, Proposer: proposer, Seq: w.seq[proposer], Time: w.Clock.Now(), Body: raw}
	next := clone(w.snap)
	if err := a.Apply(next, c); err != nil {
		w.Rejected = append(w.Rejected, string(t)+" by "+string(proposer)+": "+err.Error())
		w.Applied = append(w.Applied, string(t)+" "+string(proposer)+" err")
		return 0, err
	}
	w.index++
	next.Index = w.index
	next.Seq[proposer] = c.Seq
	w.snap = next
	w.Applied = append(w.Applied, string(t)+" "+string(proposer)+" ok")
	return w.index, nil
}

// storageAgent is part B's storage node: fences first (revoking access),
// then grants (unmapping before mapping), then rejoins.
func (w *World) storageAgent() {
	for i := 0; i < 20; i++ {
		w.mu.Lock()
		if !w.storageUp || w.Nodes["nas"].Crashed || !w.Nodes["nas"].Connected {
			w.mu.Unlock()
			return
		}
		did := false
		for _, id := range sortedNodes(w.snap) {
			f := w.snap.Fences[id]
			n := w.snap.Nodes[id]
			if f != nil && !f.Confirmed && f.Epoch == n.FenceEpoch {
				for ref, l := range w.mapped {
					w.mapped[ref] = slices.DeleteFunc(l, func(x cluster.NodeID) bool { return x == id })
				}
				raw, _ := json.Marshal(storageBody{Node: id, Epoch: f.Epoch})
				if _, err := w.applyLocked("nas", cmdFenced, raw); err == nil {
					did = true
				}
			}
		}
		for _, ref := range sortedRefs(w.snap) {
			g := w.snap.Grants[ref]
			if g == nil || g.Applied {
				continue
			}
			var nodes []cluster.NodeID
			for _, n := range g.Nodes {
				if st := w.snap.Nodes[n]; st != nil && (st.State == cluster.NodeActive || st.State == cluster.NodeMaintenance || st.State == cluster.NodeRejoining) {
					nodes = append(nodes, n)
				}
			}
			w.mapped[ref] = nodes // one history: the old nodes lose access in the same step
			raw, _ := json.Marshal(storageBody{Workload: ref, Generation: g.Generation})
			if _, err := w.applyLocked("nas", cmdApplied, raw); err == nil {
				did = true
			}
		}
		for _, id := range sortedNodes(w.snap) {
			if w.snap.Nodes[id].State == cluster.NodeRejoining {
				raw, _ := json.Marshal(storageBody{Node: id})
				if _, err := w.applyLocked("nas", cmdUnfenced, raw); err == nil {
					did = true
				}
			}
		}
		w.mu.Unlock()
		if !did {
			return
		}
	}
}

func sortedNodes(s *cluster.Snapshot) []cluster.NodeID {
	var out []cluster.NodeID
	for id := range s.Nodes {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

func sortedRefs(s *cluster.Snapshot) []cluster.WorkloadRef {
	var out []cluster.WorkloadRef
	for r := range s.Grants {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Writers are the nodes that run w with access to its disk now.
func (w *World) Writers(ref cluster.WorkloadRef) []cluster.NodeID {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writersLocked(ref)
}

func (w *World) writersLocked(ref cluster.WorkloadRef) []cluster.NodeID {
	var out []cluster.NodeID
	for _, id := range w.order {
		n := w.Nodes[id]
		n.mu.Lock()
		_, run := n.Running[ref]
		crashed := n.Crashed
		n.mu.Unlock()
		if run && !crashed && slices.Contains(w.mapped[ref], id) {
			out = append(out, id)
		}
	}
	return out
}

// Tick advances the clock by d and runs every node once (reconciler and
// fence agent), then the leader's coordinator, then the watchdogs, and
// checks that no workload has two writers.
func (w *World) Tick(d time.Duration) {
	w.Clock.Advance(d)
	now := w.Clock.Now()
	for _, id := range w.order {
		n := w.Nodes[id]
		n.mu.Lock()
		if n.Connected && !n.Crashed {
			n.lastContact = now
		}
		n.mu.Unlock()
	}
	ctx := context.Background()
	for _, id := range w.order {
		n := w.Nodes[id]
		if n.isCrashed() || n.Role != cluster.RoleCompute {
			continue
		}
		n.Rec.Step(ctx)
		n.Agent.Step(ctx)
		n.waitAgent()
	}
	w.mu.Lock()
	leader := w.leader
	w.mu.Unlock()
	if l := w.Nodes[leader]; l != nil && !l.isCrashed() {
		l.Coord.Tick(ctx)
	}
	w.storageAgent()
	// Watchdogs: an armed watchdog fires W after root's last pet.
	for _, id := range w.order {
		n := w.Nodes[id]
		n.mu.Lock()
		fire := n.Armed && !n.Crashed && !now.Before(n.petUntil.Add(n.wdTime))
		n.mu.Unlock()
		if fire {
			w.reset(n)
		}
	}
	w.check()
}

// Run ticks every second for d.
func (w *World) Run(d time.Duration) {
	for i := time.Duration(0); i < d; i += time.Second {
		w.Tick(time.Second)
	}
}

func (w *World) reset(n *Node) {
	w.mu.Lock()
	w.resets[n.ID]++
	w.mu.Unlock()
	n.mu.Lock()
	n.Running = map[cluster.WorkloadRef]uint64{}
	n.attached = map[cluster.WorkloadRef]uint64{}
	n.Armed = false
	n.BootID = fmt.Sprintf("boot-%d", w.resets[n.ID]+1)
	n.mu.Unlock()
	// A new hardyd: its reconciler and agent start empty.
	w.wire(n)
}

func (w *World) check() {
	w.mu.Lock()
	defer w.mu.Unlock()
	refs := map[cluster.WorkloadRef]bool{}
	for _, id := range w.order {
		n := w.Nodes[id]
		n.mu.Lock()
		for r := range n.Running {
			refs[r] = true
		}
		n.mu.Unlock()
	}
	for r := range refs {
		if ws := w.writersLocked(r); len(ws) > 1 {
			w.Violations = append(w.Violations, fmt.Sprintf("%s at %s: %v write its disk", r.ID, w.Clock.Now().Format(time.TimeOnly), ws))
		}
	}
}

// ---- node: part A's Membership ----------------------------------------------------

func (n *Node) isCrashed() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.Crashed
}

// waitAgent waits for a self-fence the agent started in the background.
func (n *Node) waitAgent() {
	for i := 0; i < 2000; i++ {
		running, _, _ := n.Agent.SelfFenceDone()
		if !running {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// Disconnect cuts the node off from the leader's side (a partition; its
// storage network stays unless StorageOK is changed).
func (n *Node) Disconnect() {
	snap := n.w.Snapshot()
	n.mu.Lock()
	n.Connected = false
	n.frozen = snap
	n.mu.Unlock()
}

// Reconnect joins the node back.
func (n *Node) Reconnect() {
	n.mu.Lock()
	n.Connected = true
	n.frozen = nil
	n.mu.Unlock()
}

// Crash powers the node off (processes gone, nothing answers).
func (n *Node) Crash() {
	n.Disconnect()
	n.mu.Lock()
	n.Crashed = true
	n.Running = map[cluster.WorkloadRef]uint64{}
	n.attached = map[cluster.WorkloadRef]uint64{}
	n.Armed = false
	n.mu.Unlock()
}

// Boot powers a crashed node on again with a new boot id.
func (n *Node) Boot() {
	n.mu.Lock()
	n.Crashed = false
	n.BootID += "+"
	n.mu.Unlock()
	n.w.wire(n)
}

// Self implements Membership.
func (n *Node) Self() (cluster.Node, error) {
	s := n.State().Snapshot()
	m, ok := s.Nodes[n.ID]
	if !ok {
		return cluster.Node{}, cluster.ErrNotMember
	}
	return *m, nil
}

type stateView struct{ s *cluster.Snapshot }

func (v stateView) Snapshot() *cluster.Snapshot { return clone(v.s) }
func (v stateView) Node(id cluster.NodeID) (*cluster.Node, bool) {
	x, ok := v.s.Nodes[id]
	return x, ok
}
func (v stateView) Placement(w cluster.WorkloadRef) (*cluster.Placement, bool) {
	x, ok := v.s.Placements[w]
	return x, ok
}
func (v stateView) Grant(w cluster.WorkloadRef) (*cluster.Grant, bool) {
	x, ok := v.s.Grants[w]
	return x, ok
}
func (v stateView) Index() uint64 { return v.s.Index }

// State implements Membership: the applied state, or the last one seen
// while cut off.
func (n *Node) State() cluster.State {
	n.mu.Lock()
	frozen := n.frozen
	n.mu.Unlock()
	if frozen != nil {
		return stateView{s: frozen}
	}
	return stateView{s: n.w.Snapshot()}
}

// Leader implements Membership.
func (n *Node) Leader() (cluster.NodeID, bool) {
	n.mu.Lock()
	ok := n.Connected && !n.Crashed
	n.mu.Unlock()
	if !ok {
		return "", false
	}
	n.w.mu.Lock()
	defer n.w.mu.Unlock()
	return n.w.leader, true
}

// Quorate implements Membership: the lease runs Q from the last answered
// heartbeat.
func (n *Node) Quorate() (bool, time.Time) {
	q := n.w.Snapshot().Timings.QuorumLease
	n.mu.Lock()
	defer n.mu.Unlock()
	until := n.lastContact.Add(q)
	if n.Crashed {
		return false, until
	}
	return n.w.Clock.Now().Before(until), until
}

// Health implements Membership (the leader's view).
func (n *Node) Health(context.Context) ([]cluster.Health, error) {
	var out []cluster.Health
	now := n.w.Clock.Now()
	for _, id := range n.w.order {
		m := n.w.Nodes[id]
		q, _ := m.Quorate()
		m.mu.Lock()
		h := cluster.Health{Node: id, LastHeard: m.lastContact, Path: cluster.PathLAN, Quorate: q, StorageOK: m.StorageOK, LANOK: m.LANOK,
			Suspect: now.Sub(m.lastContact) >= cluster.DefaultTimings.Suspect}
		for r, g := range m.attached {
			if _, run := m.Running[r]; run {
				h.Running = append(h.Running, cluster.RunningWorkload{Workload: r, Generation: g})
			}
		}
		m.mu.Unlock()
		out = append(out, h)
	}
	return out, nil
}

// Propose implements Membership: only with quorum.
func (n *Node) Propose(_ context.Context, t cluster.CommandType, body any, _ cluster.Actor) (uint64, error) {
	n.mu.Lock()
	ok := n.Connected && !n.Crashed
	n.mu.Unlock()
	if !ok {
		return 0, cluster.ErrNoQuorum
	}
	return n.w.apply(n.ID, t, body)
}

// WaitApplied implements Membership (applying is synchronous here).
func (n *Node) WaitApplied(context.Context, uint64) error { return nil }

// Subscribe implements Membership.
func (n *Node) Subscribe(ctx context.Context) <-chan cluster.Event {
	ch := make(chan cluster.Event)
	go func() { <-ctx.Done(); close(ch) }()
	return ch
}

// Register implements Membership.
func (n *Node) Register(a cluster.Applier) { n.reg = append(n.reg, a) }

// Attached is what the node has attached (workload -> generation).
func (n *Node) Attached() map[cluster.WorkloadRef]uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := map[cluster.WorkloadRef]uint64{}
	for k, v := range n.attached {
		out[k] = v
	}
	return out
}

// RunningGen is the generation w runs under here (0, false: not running).
func (n *Node) RunningGen(ref cluster.WorkloadRef) (uint64, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	g, ok := n.Running[ref]
	return g, ok
}

// StartProcess makes w run here (a stale process, for tests).
func (n *Node) StartProcess(ref cluster.WorkloadRef, gen uint64) {
	n.mu.Lock()
	n.Running[ref] = gen
	n.attached[ref] = gen
	n.mu.Unlock()
}

// Kill makes w crash here.
func (n *Node) Kill(ref cluster.WorkloadRef) {
	n.mu.Lock()
	delete(n.Running, ref)
	n.mu.Unlock()
}

// ---- fakes ------------------------------------------------------------------------

type fakeRuntime struct {
	n    *Node
	kind cluster.WorkloadKind
}

func (r *fakeRuntime) Kind() cluster.WorkloadKind { return r.kind }
func (r *fakeRuntime) Requirements(_ context.Context, ref cluster.WorkloadRef) (*cluster.Requirements, error) {
	r.n.w.mu.Lock()
	req := r.n.w.Requirements[ref]
	r.n.w.mu.Unlock()
	if req != nil {
		c := *req
		return &c, nil
	}
	return &cluster.Requirements{MemoryMB: 2048, CPUs: 2}, nil
}
func (r *fakeRuntime) Start(_ context.Context, ref cluster.WorkloadRef, a *cluster.Attachment) error {
	n := r.n
	n.w.mu.Lock()
	mapped := slices.Contains(n.w.mapped[ref], n.ID)
	n.w.mu.Unlock()
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.Crashed {
		return errors.New("crashed")
	}
	if !mapped || n.attached[ref] != a.Generation {
		return cluster.ErrStorageUnavailable
	}
	n.Running[ref] = a.Generation
	return nil
}
func (r *fakeRuntime) Stop(_ context.Context, ref cluster.WorkloadRef, _ cluster.StopMode) error {
	r.n.mu.Lock()
	delete(r.n.Running, ref)
	r.n.mu.Unlock()
	return nil
}
func (r *fakeRuntime) Status(context.Context) ([]cluster.WorkloadStatus, error) {
	n := r.n
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []cluster.WorkloadStatus
	for ref := range n.Running {
		if ref.Kind != r.kind {
			continue
		}
		st := cluster.WorkloadStatus{Workload: ref, Running: true}
		if g, ok := n.attached[ref]; ok {
			st.Generation = g
		} else {
			st.Problem = "its storage isn't attached here"
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Workload.ID < out[j].Workload.ID })
	return out, nil
}

type fakeAttacher struct{ n *Node }

func (a *fakeAttacher) Attach(_ context.Context, _ cluster.WorkloadStorage, g cluster.Grant) (*cluster.Attachment, error) {
	n := a.n
	s := n.w.Snapshot()
	cur := s.Grants[g.Workload]
	if cur == nil || cur.Generation != g.Generation || !cur.Applied || !slices.Contains(cur.Nodes, n.ID) {
		return nil, cluster.ErrStorageUnavailable
	}
	if !slices.Contains(n.w.Mapped(g.Workload), n.ID) {
		return nil, cluster.ErrStorageUnavailable
	}
	n.mu.Lock()
	n.attached[g.Workload] = g.Generation
	n.mu.Unlock()
	return &cluster.Attachment{Workload: g.Workload, Generation: g.Generation, StateDir: "/mnt/hc/tank/x/" + g.Workload.ID}, nil
}
func (a *fakeAttacher) Detach(_ context.Context, ref cluster.WorkloadRef, _ bool) error {
	a.n.mu.Lock()
	delete(a.n.attached, ref)
	a.n.mu.Unlock()
	return nil
}
func (a *fakeAttacher) Attached(context.Context) ([]cluster.Attachment, error) {
	a.n.mu.Lock()
	defer a.n.mu.Unlock()
	var out []cluster.Attachment
	for r, g := range a.n.attached {
		out = append(out, cluster.Attachment{Workload: r, Generation: g})
	}
	return out, nil
}
func (a *fakeAttacher) Healthy(context.Context) (bool, string) {
	a.n.mu.Lock()
	defer a.n.mu.Unlock()
	return a.n.StorageOK, ""
}

// fakeWatchdog models root's feeder: the device fires W after the last
// moment root petted it (root pets while now < the deadline hardyd gave).
type fakeWatchdog struct{ n *Node }

func (f *fakeWatchdog) Arm(_ context.Context, timeout time.Duration) (string, error) {
	n := f.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.WatchdogKind == "" {
		return "", fence.ErrNoWatchdog
	}
	if !n.Armed {
		n.Armed = true
		n.petUntil = n.w.Clock.Now()
	}
	n.wdTime = timeout
	return n.WatchdogKind, nil
}
func (f *fakeWatchdog) Pet(_ context.Context, validFor time.Duration) error {
	n := f.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.Armed {
		return errors.New("not armed")
	}
	n.petUntil = n.w.Clock.Now().Add(validFor)
	return nil
}
func (f *fakeWatchdog) Disarm(context.Context) error {
	f.n.mu.Lock()
	f.n.Armed = false
	f.n.mu.Unlock()
	return nil
}
func (f *fakeWatchdog) Expire(context.Context) error {
	n := f.n
	n.mu.Lock()
	if now := n.w.Clock.Now(); n.petUntil.After(now) {
		n.petUntil = now
	}
	n.mu.Unlock()
	return nil
}

type fakeFencer struct{ n *Node }

func (f *fakeFencer) SelfFence(_ context.Context, _ uint64, ws []cluster.WorkloadRef) error {
	n := f.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.SelfFenceFails {
		return errors.New("stuck in I/O")
	}
	for _, r := range ws {
		delete(n.Running, r)
		delete(n.attached, r)
	}
	return nil
}

// ---- helpers ----------------------------------------------------------------------

func clone(s *cluster.Snapshot) *cluster.Snapshot {
	c := *s
	c.Nodes = map[cluster.NodeID]*cluster.Node{}
	for k, v := range s.Nodes {
		x := *v
		if v.Compute != nil {
			ci := *v.Compute
			ci.Bridges = map[string][]int{}
			for b, l := range v.Compute.Bridges {
				ci.Bridges[b] = slices.Clone(l)
			}
			x.Compute = &ci
		}
		x.Features = slices.Clone(v.Features)
		c.Nodes[k] = &x
	}
	c.Placements = map[cluster.WorkloadRef]*cluster.Placement{}
	for k, v := range s.Placements {
		x := *v
		x.HA.Preferred = slices.Clone(v.HA.Preferred)
		x.Storage.Volumes = slices.Clone(v.Storage.Volumes)
		x.Storage.Exports = slices.Clone(v.Storage.Exports)
		x.Storage.Shares = slices.Clone(v.Storage.Shares)
		c.Placements[k] = &x
	}
	c.Grants = map[cluster.WorkloadRef]*cluster.Grant{}
	for k, v := range s.Grants {
		x := *v
		x.Nodes = slices.Clone(v.Nodes)
		c.Grants[k] = &x
	}
	c.Fences = map[cluster.NodeID]*cluster.Fence{}
	for k, v := range s.Fences {
		x := *v
		c.Fences[k] = &x
	}
	c.Seq = map[cluster.NodeID]uint64{}
	for k, v := range s.Seq {
		c.Seq[k] = v
	}
	c.HAOverrides = map[cluster.NodeID]*cluster.WatchdogOverride{}
	for k, v := range s.HAOverrides {
		x := *v
		c.HAOverrides[k] = &x
	}
	c.AppUIDs = map[string]int{}
	for k, v := range s.AppUIDs {
		c.AppUIDs[k] = v
	}
	return &c
}

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func mustAddr(s string) netip.Addr     { return netip.MustParseAddr(s) }

// Clone deep-copies a snapshot.
func Clone(s *cluster.Snapshot) *cluster.Snapshot { return clone(s) }

// SetCompute changes a node's hardware in the state (tests).
func (w *World) SetCompute(id cluster.NodeID, f func(*cluster.ComputeInfo)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	next := clone(w.snap)
	f(next.Nodes[id].Compute)
	w.snap = next
}

// AddVM adds an HA (or not) VM placed on owner, asked to run.
func (w *World) AddVM(id string, owner cluster.NodeID, ha bool, priority int) cluster.WorkloadRef {
	ref := cluster.WorkloadRef{Kind: cluster.KindVM, ID: id}
	err := w.Propose(owner, cluster.CmdWorkloadAdd, state.WorkloadAdd{Workload: ref, Name: id, Owner: owner, Requested: cluster.RequestRunning,
		HA: cluster.HAPolicy{Enabled: ha, Priority: priority}, Storage: cluster.WorkloadStorage{Pool: "tank"}})
	if err != nil {
		w.T.Fatalf("adding %s: %v", id, err)
	}
	return ref
}
