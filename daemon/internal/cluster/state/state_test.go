package state

import (
	"encoding/json"
	"errors"
	"math/rand"
	"slices"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

func snap() *cluster.Snapshot {
	s := &cluster.Snapshot{Nodes: map[cluster.NodeID]*cluster.Node{}, Timings: cluster.DefaultTimings}
	for _, id := range []cluster.NodeID{"c1", "c2", "c3"} {
		s.Nodes[id] = &cluster.Node{ID: id, Role: cluster.RoleCompute, State: cluster.NodeActive,
			Compute: &cluster.ComputeInfo{CPUs: 8, MemoryMB: 32768, Watchdog: "hardware"}}
	}
	s.Nodes["nas"] = &cluster.Node{ID: "nas", Role: cluster.RoleStorage, State: cluster.NodeActive}
	ensure(s)
	return s
}

var t0 = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

func cmd(t cluster.CommandType, by cluster.NodeID, body any) cluster.Command {
	b, _ := json.Marshal(body)
	return cluster.Command{Type: t, Proposer: by, Time: t0, Body: b}
}

func apply(s *cluster.Snapshot, t cluster.CommandType, by cluster.NodeID, body any) error {
	var a cluster.Applier = Placements{}
	if slices.Contains(Fences{}.Types(), t) {
		a = Fences{}
	}
	return a.Apply(s, cmd(t, by, body))
}

// grantApplied is part B's storage.applied.
func grantApplied(s *cluster.Snapshot, w cluster.WorkloadRef) {
	s.Grants[w].Applied = true
}

// fenced is part B's storage.fenced.
func fenced(s *cluster.Snapshot, n cluster.NodeID) {
	s.Fences[n].Confirmed = true
	s.Nodes[n].State = cluster.NodeFenced
}

var vm = cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web"}

func addVM(t *testing.T, s *cluster.Snapshot, ha bool) {
	t.Helper()
	if err := apply(s, cluster.CmdWorkloadAdd, "c1", WorkloadAdd{Workload: vm, Name: "web", Owner: "c1", Requested: cluster.RequestRunning, HA: cluster.HAPolicy{Enabled: ha}}); err != nil {
		t.Fatal(err)
	}
	grantApplied(s, vm)
	if err := apply(s, cluster.CmdWorkloadState, "c1", WorkloadStateReport{Workload: vm, Generation: 1, State: cluster.PlacementRunning}); err != nil {
		t.Fatal(err)
	}
}

func TestWorkloadAddGrantsOwnerAtGenerationOne(t *testing.T) {
	s := snap()
	if err := apply(s, cluster.CmdWorkloadAdd, "c1", WorkloadAdd{Workload: vm, Name: "web", Owner: "nas"}); err == nil {
		t.Fatal("placed on the storage node")
	}
	addVM(t, s, true)
	p, g := s.Placements[vm], s.Grants[vm]
	if p.Generation != 1 || g.Generation != 1 || g.Mode != cluster.GrantExclusive || !slices.Equal(g.Nodes, []cluster.NodeID{"c1"}) {
		t.Fatalf("%+v %+v", p, g)
	}
	if err := apply(s, cluster.CmdWorkloadAdd, "c1", WorkloadAdd{Workload: vm, Name: "web", Owner: "c2"}); err == nil {
		t.Fatal("added twice")
	}
}

func TestOwnerReportsOnly(t *testing.T) {
	s := snap()
	addVM(t, s, false)
	if err := apply(s, cluster.CmdWorkloadState, "c2", WorkloadStateReport{Workload: vm, Generation: 1, State: cluster.PlacementStopped}); err == nil {
		t.Fatal("another node reported the owner's workload")
	}
	if err := apply(s, cluster.CmdWorkloadState, "c1", WorkloadStateReport{Workload: vm, Generation: 2, State: cluster.PlacementStopped}); !errors.Is(err, cluster.ErrStaleGeneration) {
		t.Fatalf("a report for another generation: %v", err)
	}
}

func TestOwnerChangesOnlyWhenReleased(t *testing.T) {
	s := snap()
	addVM(t, s, false)
	// Running on c1: no hand-over.
	err := apply(s, cluster.CmdPlacementSet, "c2", PlacementSet{Workload: vm, Expected: 1, Owner: "c2", State: cluster.PlacementStarting})
	if err == nil {
		t.Fatal("a running workload changed owner")
	}
	// Reported stopped: it may move, with a new generation and grant.
	if err := apply(s, cluster.CmdWorkloadState, "c1", WorkloadStateReport{Workload: vm, Generation: 1, State: cluster.PlacementStopped}); err != nil {
		t.Fatal(err)
	}
	if err := apply(s, cluster.CmdPlacementSet, "c2", PlacementSet{Workload: vm, Expected: 1, Owner: "c2", State: cluster.PlacementStarting}); err != nil {
		t.Fatal(err)
	}
	p, g := s.Placements[vm], s.Grants[vm]
	if p.Owner != "c2" || p.Generation != 2 || g.Generation != 2 || g.Applied || !slices.Equal(g.Nodes, []cluster.NodeID{"c2"}) {
		t.Fatalf("%+v %+v", p, g)
	}
	// The old generation is refused from now on.
	if err := apply(s, cluster.CmdPlacementSet, "c2", PlacementSet{Workload: vm, Expected: 1, Owner: "c3", State: cluster.PlacementStarting}); !errors.Is(err, cluster.ErrStaleGeneration) {
		t.Fatalf("a stale hand-over: %v", err)
	}
	if MayRun(s, "c2", vm, 2) != cluster.ErrStorageUnavailable {
		t.Fatal("c2 may run before the storage node applied the grant")
	}
	grantApplied(s, vm)
	if err := MayRun(s, "c2", vm, 2); err != nil {
		t.Fatal(err)
	}
	if MayRun(s, "c1", vm, 1) == nil || MayRun(s, "c1", vm, 2) == nil {
		t.Fatal("the old owner may still run it")
	}
}

func TestRecoveryNeedsConfirmedFence(t *testing.T) {
	s := snap()
	addVM(t, s, true)
	if err := apply(s, cluster.CmdNodeDead, "c2", NodeDeadBody{Node: "c1", Epoch: 2, Reason: "dead"}); err == nil {
		t.Fatal("a skipped epoch was accepted")
	}
	if err := apply(s, cluster.CmdNodeDead, "c2", NodeDeadBody{Node: "c1", Epoch: 1, Reason: "dead"}); err != nil {
		t.Fatal(err)
	}
	if p := s.Placements[vm]; p.State != cluster.PlacementRecovering {
		t.Fatalf("%+v", p)
	}
	if MayRun(s, "c1", vm, 1) != cluster.ErrFenced {
		t.Fatal("a dead node may run its workload")
	}
	// Before storage.fenced: refused.
	if err := apply(s, cluster.CmdPlacementSet, "c2", PlacementSet{Workload: vm, Expected: 1, Owner: "c2", State: cluster.PlacementStarting}); err == nil {
		t.Fatal("recovered before the fence was confirmed")
	}
	fenced(s, "c1")
	if err := apply(s, cluster.CmdPlacementSet, "c2", PlacementSet{Workload: vm, Expected: 1, Owner: "c2", State: cluster.PlacementStarting}); err != nil {
		t.Fatal(err)
	}
	if err := apply(s, cluster.CmdNodeDead, "c2", NodeDeadBody{Node: "nas", Epoch: 1, Reason: "dead"}); err == nil {
		t.Fatal("the storage node was declared dead")
	}
}

func TestRejoinRules(t *testing.T) {
	s := snap()
	addVM(t, s, false)
	s.Nodes["c1"].BootID = "b1"
	_ = apply(s, cluster.CmdNodeDead, "c2", NodeDeadBody{Node: "c1", Epoch: 1, Reason: "dead"})
	if err := apply(s, cluster.CmdNodeRejoin, "c1", NodeRejoinBody{Node: "c1", Epoch: 1, BootID: "b2"}); err == nil {
		t.Fatal("rejoined before the fence was confirmed")
	}
	fenced(s, "c1")
	if err := apply(s, cluster.CmdNodeRejoin, "c2", NodeRejoinBody{Node: "c1", Epoch: 1, BootID: "b2"}); err == nil {
		t.Fatal("another node proposed c1's rejoin")
	}
	if err := apply(s, cluster.CmdNodeRejoin, "c1", NodeRejoinBody{Node: "c1", Epoch: 1, BootID: "b1", Clean: true}); err == nil {
		t.Fatal("a dead node rejoined without a restart")
	}
	if err := apply(s, cluster.CmdNodeRejoin, "c1", NodeRejoinBody{Node: "c1", Epoch: 1, BootID: "b2"}); err != nil {
		t.Fatal(err)
	}
	p, g := s.Placements[vm], s.Grants[vm]
	if s.Nodes["c1"].State != cluster.NodeRejoining || p.Generation != 2 || p.State != cluster.PlacementStopped || g.Generation != 2 || g.Applied {
		t.Fatalf("after rejoin: %+v %+v %+v", s.Nodes["c1"], p, g)
	}
	// A process of generation 1 still on c1 may not run.
	if MayRun(s, "c1", vm, 1) == nil {
		t.Fatal("a stale generation may run after rejoining")
	}
}

func TestIsolatedCleanRejoinSameBoot(t *testing.T) {
	s := snap()
	s.Nodes["c1"].BootID = "b1"
	if err := apply(s, cluster.CmdNodeIsolated, "c2", NodeDeadBody{Node: "c1", Epoch: 1}); err != nil {
		t.Fatal(err)
	}
	if s.Fences["c1"].Reason != "isolated" {
		t.Fatal(s.Fences["c1"])
	}
	fenced(s, "c1")
	if err := apply(s, cluster.CmdNodeRejoin, "c1", NodeRejoinBody{Node: "c1", Epoch: 1, BootID: "b1"}); err == nil {
		t.Fatal("rejoined on the same boot without saying it stopped everything")
	}
	if err := apply(s, cluster.CmdNodeRejoin, "c1", NodeRejoinBody{Node: "c1", Epoch: 1, BootID: "b1", Clean: true}); err != nil {
		t.Fatal(err)
	}
}

func TestLiveMigrationGrant(t *testing.T) {
	s := snap()
	addVM(t, s, false)
	if err := apply(s, cluster.CmdMoveBegin, "c3", MoveBegin{Workload: vm, Generation: 1, To: "c2", Mode: cluster.MoveLive}); err != nil {
		t.Fatal(err)
	}
	p, g := s.Placements[vm], s.Grants[vm]
	if g.Mode != cluster.GrantMigration || !slices.Equal(g.Nodes, []cluster.NodeID{"c1", "c2"}) || p.Generation != 2 || p.State != cluster.PlacementMigrating {
		t.Fatalf("%+v %+v", p, g)
	}
	grantApplied(s, vm)
	if MayRun(s, "c1", vm, 2) != nil || MayRun(s, "c2", vm, 2) != nil || MayRun(s, "c3", vm, 2) == nil {
		t.Fatal("a migration grant is for its two nodes only")
	}
	// It can't collapse onto a third node while both are up.
	if err := apply(s, cluster.CmdPlacementSet, "c3", PlacementSet{Workload: vm, Expected: 2, Owner: "c3", State: cluster.PlacementStarting}); err == nil {
		t.Fatal("a migration collapsed onto a third node")
	}
	if err := apply(s, cluster.CmdPlacementSet, "c3", PlacementSet{Workload: vm, Expected: 2, Owner: "c2", State: cluster.PlacementRunning, Reason: "migrated"}); err != nil {
		t.Fatal(err)
	}
	g = s.Grants[vm]
	if g.Mode != cluster.GrantExclusive || !slices.Equal(g.Nodes, []cluster.NodeID{"c2"}) || s.Placements[vm].Generation != 3 {
		t.Fatalf("%+v", g)
	}
}

func TestLiveMigrationRefusals(t *testing.T) {
	s := snap()
	addVM(t, s, false)
	s.Placements[vm].Pinned = true
	if err := apply(s, cluster.CmdMoveBegin, "c3", MoveBegin{Workload: vm, Generation: 1, To: "c2", Mode: cluster.MoveLive}); err == nil {
		t.Fatal("a pinned VM migrated live")
	}
	s.Placements[vm].Pinned = false
	app := cluster.WorkloadRef{Kind: cluster.KindApp, ID: "wiki"}
	_ = apply(s, cluster.CmdWorkloadAdd, "c1", WorkloadAdd{Workload: app, Name: "wiki", Owner: "c1"})
	if err := apply(s, cluster.CmdMoveBegin, "c3", MoveBegin{Workload: app, Generation: 1, To: "c2", Mode: cluster.MoveLive}); err == nil {
		t.Fatal("an app migrated live")
	}
}

func TestHAPolicyNeedsHardwareWatchdog(t *testing.T) {
	s := snap()
	addVM(t, s, false)
	s.Nodes["c1"].Compute.Watchdog = "softdog"
	if err := apply(s, cluster.CmdHAPolicy, "c1", HAPolicySet{Workload: vm, Policy: cluster.HAPolicy{Enabled: true}}); err == nil {
		t.Fatal("HA on a softdog node without an override")
	}
	if err := apply(s, cluster.CmdHAWatchdog, "c2", WatchdogOverrideBody{Node: "c1", Allow: true, Confirm: "c2"}); err == nil {
		t.Fatal("an override without the right confirmation")
	}
	if err := apply(s, cluster.CmdHAWatchdog, "c2", WatchdogOverrideBody{Node: "c1", Allow: true, Confirm: "c1"}); err != nil {
		t.Fatal(err)
	}
	if err := apply(s, cluster.CmdHAPolicy, "c1", HAPolicySet{Workload: vm, Policy: cluster.HAPolicy{Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	if err := apply(s, cluster.CmdHAWatchdog, "c2", WatchdogOverrideBody{Node: "c1", Allow: false, Confirm: "c1"}); err == nil {
		t.Fatal("the override was removed while c1 runs an HA workload")
	}
	// The override is for the watchdog the node had: losing even softdog
	// lapses it.
	s.Nodes["c1"].Compute.Watchdog = ""
	if ok, _ := HAEligible(s, "c1"); ok {
		t.Fatal("an override for softdog covers a node with no watchdog")
	}
	s.Placements[vm].Pinned = true
	if err := ValidatePolicy(s, s.Placements[vm], cluster.HAPolicy{Enabled: true, Priority: 50}); err == nil {
		t.Fatal("a pinned (passthrough) VM made HA")
	}
}

func TestPlacementSigners(t *testing.T) {
	for _, ty := range append(Placements{}.Types(), Fences{}.Types()...) {
		var a cluster.Applier = Placements{}
		if slices.Contains(Fences{}.Types(), ty) {
			a = Fences{}
		}
		if slices.Contains(a.Signers(ty), cluster.RoleWitness) {
			t.Errorf("the witness may sign %s", ty)
		}
	}
}

func TestValidateTimings(t *testing.T) {
	if err := ValidateTimings(cluster.DefaultTimings); err != nil {
		t.Fatalf("the defaults: %v", err)
	}
	bad := cluster.DefaultTimings
	bad.Dead = bad.QuorumLease + bad.Watchdog + 5*time.Second
	if ValidateTimings(bad) == nil {
		t.Fatal("F < Q + W + 10 s accepted")
	}
	bad = cluster.DefaultTimings
	bad.SelfStop = bad.Watchdog
	if ValidateTimings(bad) == nil {
		t.Fatal("S >= W accepted")
	}
	bad = cluster.DefaultTimings
	bad.QuorumLease = 3 * time.Second
	if ValidateTimings(bad) == nil {
		t.Fatal("a 3 s lease accepted")
	}
	slow := cluster.DefaultTimings
	slow.QuorumLease, slow.Dead = 60*time.Second, 90*time.Second
	if err := ValidateTimings(slow); err != nil {
		t.Fatalf("longer timings within bounds: %v", err)
	}
}

// TestNeverTwoRunners applies random command sequences and checks after
// every entry that at most one node may run each workload (two only with
// a migration grant, and then only its two nodes), and that a recovery
// never happened before a confirmed fence.
func TestNeverTwoRunners(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	nodes := []cluster.NodeID{"c1", "c2", "c3"}
	refs := []cluster.WorkloadRef{vm, {Kind: cluster.KindVM, ID: "db"}, {Kind: cluster.KindApp, ID: "wiki"}}
	for round := 0; round < 300; round++ {
		s := snap()
		for _, r := range refs {
			_ = apply(s, cluster.CmdWorkloadAdd, "c1", WorkloadAdd{Workload: r, Name: r.ID, Owner: nodes[rng.Intn(3)], Requested: cluster.RequestRunning, HA: cluster.HAPolicy{Enabled: rng.Intn(2) == 0}})
		}
		for step := 0; step < 60; step++ {
			r := refs[rng.Intn(len(refs))]
			n := nodes[rng.Intn(3)]
			p := s.Placements[r]
			gen := p.Generation
			if rng.Intn(5) == 0 {
				gen += uint64(rng.Intn(3)) - 1
			}
			prevOwner := p.Owner
			var err error
			switch rng.Intn(10) {
			case 0:
				err = apply(s, cluster.CmdPlacementSet, n, PlacementSet{Workload: r, Expected: gen, Owner: nodes[rng.Intn(3)], State: []cluster.PlacementState{cluster.PlacementStarting, cluster.PlacementRunning, cluster.PlacementStopped}[rng.Intn(3)]})
			case 1:
				err = apply(s, cluster.CmdWorkloadState, n, WorkloadStateReport{Workload: r, Generation: gen, State: []cluster.PlacementState{cluster.PlacementRunning, cluster.PlacementStopped, cluster.PlacementError}[rng.Intn(3)]})
			case 2:
				err = apply(s, cluster.CmdMoveBegin, n, MoveBegin{Workload: r, Generation: gen, To: nodes[rng.Intn(3)], Mode: []cluster.MoveMode{cluster.MoveLive, cluster.MoveOffline}[rng.Intn(2)]})
			case 3:
				d := nodes[rng.Intn(3)]
				err = apply(s, cluster.CmdNodeDead, n, NodeDeadBody{Node: d, Epoch: s.Nodes[d].FenceEpoch + 1, Reason: "dead"})
			case 4:
				for id, f := range s.Fences {
					if !f.Confirmed && rng.Intn(2) == 0 {
						fenced(s, id)
					}
				}
			case 5:
				d := nodes[rng.Intn(3)]
				err = apply(s, cluster.CmdNodeRejoin, d, NodeRejoinBody{Node: d, Epoch: s.Nodes[d].FenceEpoch, BootID: "b" + string(rune('a'+step%26))})
				if err == nil {
					s.Nodes[d].State = cluster.NodeActive // storage.unfenced
				}
			case 6, 7:
				if g := s.Grants[r]; g != nil {
					g.Applied = true
				}
			case 8:
				err = apply(s, cluster.CmdMoveEnd, n, MoveEnd{Workload: r, Generation: gen, OK: rng.Intn(2) == 0})
			case 9:
				err = apply(s, cluster.CmdRequested, n, RequestedSet{Workload: r, Generation: gen, Requested: cluster.RequestStopped})
			}
			_ = err
			for _, w := range refs {
				pl, g := s.Placements[w], s.Grants[w]
				var may []cluster.NodeID
				for _, x := range nodes {
					if MayRun(s, x, w, pl.Generation) == nil {
						may = append(may, x)
					}
				}
				switch {
				case len(may) > 2:
					t.Fatalf("round %d step %d: %v may all run %s", round, step, may, w.ID)
				case len(may) == 2 && (g.Mode != cluster.GrantMigration || !slices.Equal(may, sortedCopy(g.Nodes))):
					t.Fatalf("round %d step %d: %v may run %s without a migration grant (%+v)", round, step, may, w.ID, g)
				}
				if g.Mode == cluster.GrantExclusive && len(g.Nodes) > 1 {
					t.Fatalf("an exclusive grant with %v", g.Nodes)
				}
			}
			// An owner change away from a node that isn't released.
			if p2 := s.Placements[r]; p2.Owner != prevOwner && prevOwner != "" && p2.Generation != p.Generation {
				node := s.Nodes[prevOwner]
				fenceOK := s.Fences[prevOwner] != nil && s.Fences[prevOwner].Confirmed
				_ = node
				if p.State == cluster.PlacementRunning && !fenceOK && s.Grants[r].Mode == cluster.GrantExclusive &&
					!(p.Target != "" && p2.Owner == p.Target) {
					t.Fatalf("round %d step %d: %s moved off %s while it ran there", round, step, r.ID, prevOwner)
				}
			}
		}
	}
}

func sortedCopy(l []cluster.NodeID) []cluster.NodeID {
	c := slices.Clone(l)
	slices.Sort(c)
	return c
}
