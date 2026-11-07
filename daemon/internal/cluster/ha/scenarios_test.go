package ha_test

import (
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha/clustertest"
)

// The scenarios of docs/plans/cluster.md section 7.4 on an in-process
// cluster with a fake clock. Every tick checks that no workload has two
// nodes able to write its disk.

func noViolations(t *testing.T, w *clustertest.World) {
	t.Helper()
	if len(w.Violations) > 0 {
		t.Fatalf("two writers on one disk:\n%s", strings.Join(w.Violations, "\n"))
	}
}

func running(w *clustertest.World, ref cluster.WorkloadRef) []cluster.NodeID {
	var out []cluster.NodeID
	for _, id := range []cluster.NodeID{"c1", "c2", "c3"} {
		if n := w.Nodes[id]; n != nil {
			if _, ok := n.RunningGen(ref); ok {
				out = append(out, id)
			}
		}
	}
	return out
}

func start(t *testing.T) (*clustertest.World, cluster.WorkloadRef) {
	t.Helper()
	w := clustertest.New(t, "c1", "c2", "c3")
	w.SetLeader("c3")
	vm := w.AddVM("web", "c1", true, 80)
	w.Run(3 * time.Second)
	if r := running(w, vm); len(r) != 1 || r[0] != "c1" {
		t.Fatalf("web should run on c1, runs on %v", r)
	}
	if !w.Nodes["c1"].Armed {
		t.Fatal("c1 runs an HA VM without an armed watchdog")
	}
	if w.Nodes["c2"].Armed {
		t.Fatal("c2 has no HA workload but armed its watchdog")
	}
	return w, vm
}

func TestNodeDeathRecoversAfterFence(t *testing.T) {
	w, vm := start(t)
	w.Nodes["c1"].Crash()
	tm := w.Snapshot().Timings
	// Not before F.
	w.Run(tm.Dead - 2*time.Second)
	if n := w.Snapshot().Nodes["c1"]; n.State != cluster.NodeActive {
		t.Fatalf("c1 declared %s before F", n.State)
	}
	w.Run(5 * time.Second)
	s := w.Snapshot()
	if s.Nodes["c1"].State != cluster.NodeFenced || !s.Fences["c1"].Confirmed {
		t.Fatalf("c1 should be fenced: %+v %+v", s.Nodes["c1"], s.Fences["c1"])
	}
	w.Run(3 * time.Second)
	r := running(w, vm)
	if len(r) != 1 || r[0] == "c1" {
		t.Fatalf("web should run on another node, runs on %v", r)
	}
	p := w.Snapshot().Placements[vm]
	if p.Owner != r[0] || p.State != cluster.PlacementRunning || p.Generation < 2 {
		t.Fatalf("placement after recovery: %+v", p)
	}
	noViolations(t, w)
}

func TestNoRecoveryWithoutStorageFence(t *testing.T) {
	w, vm := start(t)
	w.SetStorageUp(false) // the storage node can't confirm a fence
	w.Nodes["c1"].Crash()
	w.Run(2 * time.Minute)
	s := w.Snapshot()
	if s.Nodes["c1"].State != cluster.NodeDead {
		t.Fatalf("c1 should be dead (fence pending), is %s", s.Nodes["c1"].State)
	}
	if p := s.Placements[vm]; p.State != cluster.PlacementRecovering || p.Owner != "c1" {
		t.Fatalf("web must wait for the fence: %+v", p)
	}
	if r := running(w, vm); len(r) != 0 {
		t.Fatalf("web runs on %v before the fence", r)
	}
	w.SetStorageUp(true)
	w.Run(3 * time.Second)
	if r := running(w, vm); len(r) != 1 {
		t.Fatalf("web should run once fenced: %v", r)
	}
	noViolations(t, w)
}

func TestPartitionedNodeSelfFencesBeforeRecovery(t *testing.T) {
	w, vm := start(t)
	c1 := w.Nodes["c1"]
	c1.Disconnect() // c1 keeps its storage network: only self-fencing protects the disk
	tm := w.Snapshot().Timings
	w.Run(tm.QuorumLease + tm.SelfStop)
	if _, ok := c1.RunningGen(vm); ok {
		t.Fatal("c1 still runs web after its lease and the self-stop time")
	}
	if c1.Agent.State() == cluster.FenceArmed {
		t.Fatal("c1's agent stays armed without quorum")
	}
	w.Run(tm.Dead)
	r := running(w, vm)
	if len(r) != 1 || r[0] == "c1" {
		t.Fatalf("web should run on the majority side, runs on %v", r)
	}
	noViolations(t, w)
}

func TestStuckSelfFenceEndsInWatchdogReset(t *testing.T) {
	w, vm := start(t)
	c1 := w.Nodes["c1"]
	c1.SelfFenceFails = true
	c1.Disconnect()
	tm := w.Snapshot().Timings
	w.Run(tm.QuorumLease + tm.Watchdog + 2*time.Second)
	if w.Resets("c1") != 1 {
		t.Fatalf("c1 should have been reset by its watchdog once, was %d times", w.Resets("c1"))
	}
	if _, ok := c1.RunningGen(vm); ok {
		t.Fatal("web survived the reset")
	}
	w.Run(tm.Dead)
	if r := running(w, vm); len(r) != 1 || r[0] == "c1" {
		t.Fatalf("web should be recovered elsewhere: %v", r)
	}
	noViolations(t, w)
}

func TestStorageIsolatedNodeIsFencedAndRecovered(t *testing.T) {
	w, vm := start(t)
	c1 := w.Nodes["c1"]
	c1.StorageOK = false
	tm := w.Snapshot().Timings
	w.Run(tm.StorageIsolated + 2*time.Second)
	s := w.Snapshot()
	if f := s.Fences["c1"]; f == nil || f.Reason != "isolated" {
		t.Fatalf("c1 should be isolated: %+v", f)
	}
	if _, ok := c1.RunningGen(vm); ok {
		t.Fatal("an isolated node keeps its HA workload")
	}
	// Recovery waits W + 10 s after the fence holds.
	w.Run(tm.Watchdog)
	if r := running(w, vm); len(r) != 0 {
		t.Fatalf("recovered before W+10s: %v", r)
	}
	w.Run(15 * time.Second)
	if r := running(w, vm); len(r) != 1 || r[0] == "c1" {
		t.Fatalf("web should run elsewhere: %v", r)
	}
	noViolations(t, w)
}

func TestStorageLostEverywhereHoldsFailover(t *testing.T) {
	w, vm := start(t)
	for _, id := range []cluster.NodeID{"c1", "c2", "c3"} {
		w.Nodes[id].StorageOK = false
	}
	w.Run(3 * time.Minute)
	s := w.Snapshot()
	for _, id := range []cluster.NodeID{"c1", "c2", "c3"} {
		if s.Nodes[id].State != cluster.NodeActive {
			t.Fatalf("%s is %s: storage loss must not isolate anyone", id, s.Nodes[id].State)
		}
	}
	if p := s.Placements[vm]; p.Owner != "c1" {
		t.Fatalf("web moved during a storage outage: %+v", p)
	}
	if !w.Nodes["c3"].Coord.Status().StorageLost {
		t.Fatal("the coordinator should report storage lost")
	}
	noViolations(t, w)
}

func TestWitnessLossChangesNothing(t *testing.T) {
	w, vm := start(t)
	before := len(w.Applied)
	// The witness isn't a workload host; losing it (quorum still held by
	// the HardyOS voters) must not trigger any HA action.
	w.Run(2 * time.Minute)
	for _, a := range w.Applied[before:] {
		if strings.HasPrefix(a, "node.") || strings.HasPrefix(a, "placement.set") {
			t.Fatalf("unexpected HA action: %s", a)
		}
	}
	if r := running(w, vm); len(r) != 1 || r[0] != "c1" {
		t.Fatalf("web moved: %v", r)
	}
}

func TestFlappingNodeIsNotDeclaredDead(t *testing.T) {
	w, vm := start(t)
	c1 := w.Nodes["c1"]
	tm := w.Snapshot().Timings
	for i := 0; i < 10; i++ {
		c1.Disconnect()
		w.Run(tm.Suspect + 2*time.Second) // suspect, below Q
		c1.Reconnect()
		w.Run(2 * time.Second)
	}
	s := w.Snapshot()
	if s.Nodes["c1"].State != cluster.NodeActive {
		t.Fatalf("a flapping node was declared %s", s.Nodes["c1"].State)
	}
	if r := running(w, vm); len(r) != 1 || r[0] != "c1" {
		t.Fatalf("web should stay on c1: %v", r)
	}
	noViolations(t, w)
}

func TestRejoinStopsStaleWorkloads(t *testing.T) {
	w, vm := start(t)
	c1 := w.Nodes["c1"]
	// c1 hangs: no heartbeats, its agent can't act; the VM process stays.
	c1.Disconnect()
	c1.SelfFenceFails = true
	c1.WatchdogKind = "hardware"
	tm := w.Snapshot().Timings
	// Make the hang total: the watchdog would reset it; simulate a node
	// whose watchdog never fired (worst case) by disarming it by hand.
	w.Run(2 * time.Second)
	c1.Armed = false
	c1.StartProcess(vm, 1) // the stale process
	// c1's own loops are stuck too: only the others tick.
	w.Nodes["c1"].Crashed = true
	w.Run(tm.Dead + 5*time.Second)
	if r := running(w, vm); len(r) != 2 {
		t.Fatalf("expected the stale process on c1 and the recovered one: %v", r)
	}
	// The stale process can't write: the storage node unmapped c1.
	if ws := w.Writers(vm); len(ws) != 1 || ws[0] == "c1" {
		t.Fatalf("writers: %v", ws)
	}
	// c1 thaws and reconnects without a reboot: it must stop the stale VM
	// at once and may not rejoin on the same boot.
	w.Nodes["c1"].Crashed = false
	c1.Reconnect()
	c1.SelfFenceFails = false
	w.Tick(time.Second)
	if _, ok := c1.RunningGen(vm); ok {
		t.Fatal("c1 kept its stale VM after rejoining the network")
	}
	w.Run(40 * time.Second)
	if s := w.Snapshot(); s.Nodes["c1"].State != cluster.NodeFenced {
		t.Fatalf("c1 rejoined without a reboot: %s", s.Nodes["c1"].State)
	}
	// After a reboot it rejoins and is active, with nothing placed on it.
	c1.Crash()
	c1.Boot()
	c1.Reconnect()
	w.Run(40 * time.Second)
	s := w.Snapshot()
	if s.Nodes["c1"].State != cluster.NodeActive {
		t.Fatalf("c1 should be active after rejoining: %s (%v)", s.Nodes["c1"].State, w.Rejected)
	}
	if p := s.Placements[vm]; p.Owner == "c1" {
		t.Fatalf("web moved back to c1: %+v", p)
	}
	if r := running(w, vm); len(r) != 1 || r[0] == "c1" {
		t.Fatalf("web runs on %v", r)
	}
	noViolations(t, w)
}

func TestLeaderChangeDoesNotShortenDeadTime(t *testing.T) {
	w, _ := start(t)
	c1 := w.Nodes["c1"]
	c1.Crash()
	tm := w.Snapshot().Timings
	w.Run(tm.Dead - 5*time.Second)
	w.SetLeader("c2") // a new coordinator starts c1's clock at its election
	w.Run(10 * time.Second)
	if s := w.Snapshot(); s.Nodes["c1"].State != cluster.NodeActive {
		t.Fatalf("a leader change shortened F: c1 is %s", s.Nodes["c1"].State)
	}
	w.Run(tm.Dead)
	if s := w.Snapshot(); s.Nodes["c1"].State != cluster.NodeFenced {
		t.Fatalf("c1 should be fenced eventually: %s", s.Nodes["c1"].State)
	}
}

func TestPriorityOrderAndPending(t *testing.T) {
	w := clustertest.New(t, "c1", "c2")
	w.SetLeader("c2")
	// c2 has room for one 40 GB VM only.
	w.SetCompute("c2", func(ci *cluster.ComputeInfo) { ci.MemoryMB = 48 * 1024 })
	hi := w.AddVM("db", "c1", true, 90)
	lo := w.AddVM("wiki", "c1", true, 10)
	for _, n := range w.Nodes {
		if n.Coord != nil {
			f := func(cluster.WorkloadRef) *cluster.Requirements {
				return &cluster.Requirements{MemoryMB: 40 * 1024, CPUs: 2}
			}
			n.Coord.Requirements = f
			n.Coord.Scheduler.Requirements = f
		}
	}
	w.Run(3 * time.Second)
	w.Nodes["c1"].Crash()
	w.Run(w.Snapshot().Timings.Dead + 10*time.Second)
	s := w.Snapshot()
	if p := s.Placements[hi]; p.Owner != "c2" {
		t.Fatalf("the high-priority VM should be recovered first: %+v", p)
	}
	if p := s.Placements[lo]; p.State != cluster.PlacementPending || p.Problem == "" {
		t.Fatalf("the low-priority VM should be pending with a reason: %+v", p)
	}
	noViolations(t, w)
}

func TestNonHAWorkloadIsOrphanedNotRecovered(t *testing.T) {
	w := clustertest.New(t, "c1", "c2")
	w.SetLeader("c2")
	vm := w.AddVM("lab", "c1", false, 0)
	w.Run(3 * time.Second)
	if w.Nodes["c1"].Armed {
		t.Fatal("a node with only non-HA workloads armed its watchdog")
	}
	w.Nodes["c1"].Crash()
	w.Run(time.Minute)
	p := w.Snapshot().Placements[vm]
	if p.Owner != "c1" || !strings.Contains(p.Problem, "orphaned") {
		t.Fatalf("a non-HA VM should be orphaned on c1: %+v", p)
	}
	if r := running(w, vm); len(r) != 0 {
		t.Fatalf("lab runs on %v", r)
	}
}

func TestQuorumLossStopsHAButKeepsNonHA(t *testing.T) {
	w := clustertest.New(t, "c1", "c2")
	w.SetLeader("c2")
	havm := w.AddVM("db", "c1", true, 50)
	plain := w.AddVM("lab", "c1", false, 0)
	w.Run(3 * time.Second)
	for _, id := range []cluster.NodeID{"c1", "c2", "nas"} {
		w.Nodes[id].Disconnect()
	}
	w.Run(30 * time.Second)
	if _, ok := w.Nodes["c1"].RunningGen(havm); ok {
		t.Fatal("an HA VM kept running without quorum")
	}
	if _, ok := w.Nodes["c1"].RunningGen(plain); !ok {
		t.Fatal("a non-HA VM was stopped by a quorum loss")
	}
	for _, id := range []cluster.NodeID{"c1", "c2", "nas"} {
		w.Nodes[id].Reconnect()
	}
	w.Run(5 * time.Second)
	if g, ok := w.Nodes["c1"].RunningGen(havm); !ok || g != 1 {
		t.Fatalf("the HA VM should start again where it was once quorum is back (gen %d, %v)", g, ok)
	}
	noViolations(t, w)
}

func TestCrashedWorkloadRestartsThenRelocates(t *testing.T) {
	w, vm := start(t)
	c1 := w.Nodes["c1"]
	for i := 0; i < 4; i++ {
		c1.Kill(vm)
		w.Run(2 * time.Second)
	}
	s := w.Snapshot()
	p := s.Placements[vm]
	if p.Owner == "c1" && p.State != cluster.PlacementError {
		// MaxRestarts (3) restarts in place, then error, then the
		// coordinator relocates it.
		t.Fatalf("after 4 crashes: %+v", p)
	}
	w.Run(3 * time.Second)
	p = w.Snapshot().Placements[vm]
	if p.Owner == "c1" || p.State != cluster.PlacementRunning {
		t.Fatalf("web should be relocated after too many restarts: %+v", p)
	}
	noViolations(t, w)
}
