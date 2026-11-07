package state

import (
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// Part C safety fixes (decisions 385-394).

const hashB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestWorkloadNeedsSpecHashAndOnlyOwnerChangesIt(t *testing.T) {
	s := snap()
	if err := apply(s, cluster.CmdWorkloadAdd, "c1", WorkloadAdd{Workload: vm, Name: "web", Owner: "c1"}); err == nil {
		t.Fatal("a workload was added without the hash of its approved settings")
	}
	addVM(t, s, false)
	if s.Placements[vm].SpecHash == "" {
		t.Fatal("the hash wasn't recorded")
	}
	if err := apply(s, cluster.CmdWorkloadSpec, "c2", WorkloadSpecSet{Workload: vm, Generation: 1, SpecHash: hashB}); err == nil {
		t.Fatal("another member changed the approved settings")
	}
	if err := apply(s, cluster.CmdWorkloadSpec, "c1", WorkloadSpecSet{Workload: vm, Generation: 1, SpecHash: "md5:x"}); err == nil {
		t.Fatal("a malformed hash was accepted")
	}
	if err := apply(s, cluster.CmdWorkloadSpec, "c1", WorkloadSpecSet{Workload: vm, Generation: 1, SpecHash: hashB}); err != nil {
		t.Fatal(err)
	}
	if s.Placements[vm].SpecHash != hashB {
		t.Fatal(s.Placements[vm].SpecHash)
	}
}

func TestMigrationTargetMayNotColdStart(t *testing.T) {
	s := snap()
	addVM(t, s, false)
	if err := apply(s, cluster.CmdMoveBegin, "c3", MoveBegin{Workload: vm, Generation: 1, To: "c2", Mode: cluster.MoveLive}); err != nil {
		t.Fatal(err)
	}
	grantApplied(s, vm)
	if err := MayRunFor(s, "c2", vm, 2, IntentStart); err == nil {
		t.Fatal("the destination of a live migration may start the VM from cold")
	}
	if err := MayRunFor(s, "c1", vm, 2, IntentStart); err == nil {
		t.Fatal("the source may cold-start the VM under a two-node grant")
	}
	if err := MayRunFor(s, "c2", vm, 2, IntentReceive); err != nil {
		t.Fatalf("the destination may not receive: %v", err)
	}
	if err := MayRunFor(s, "c1", vm, 2, IntentReceive); err == nil {
		t.Fatal("the source may receive its own VM")
	}
	if MayRun(s, "c1", vm, 2) != nil || MayRun(s, "c2", vm, 2) != nil {
		t.Fatal("either node of the migration may keep it running")
	}
	// After the collapse the owner may start it, nobody else.
	if err := apply(s, cluster.CmdPlacementSet, "c3", PlacementSet{Workload: vm, Expected: 2, Owner: "c2", State: cluster.PlacementRunning, Reason: "migrated"}); err != nil {
		t.Fatal(err)
	}
	grantApplied(s, vm)
	if err := MayRunFor(s, "c2", vm, 3, IntentStart); err != nil {
		t.Fatal(err)
	}
	if err := MayRunFor(s, "c1", vm, 3, IntentStart); err == nil {
		t.Fatal("the old source may start it")
	}
}

func TestOnlyTheMoverEndsAMove(t *testing.T) {
	s := snap()
	addVM(t, s, false)
	if err := apply(s, cluster.CmdMoveBegin, "c3", MoveBegin{Workload: vm, Generation: 1, To: "c2", Mode: cluster.MoveLive}); err != nil {
		t.Fatal(err)
	}
	if s.Placements[vm].MoveBy != "c3" {
		t.Fatalf("move.begin didn't record its proposer: %+v", s.Placements[vm])
	}
	grantApplied(s, vm)
	// c1 (the source) is a member, but didn't begin the move.
	if err := apply(s, cluster.CmdPlacementSet, "c1", PlacementSet{Workload: vm, Expected: 2, Owner: "c1", State: cluster.PlacementRunning, Reason: "migration-failed"}); err == nil {
		t.Fatal("a member other than the mover ended the migration")
	}
	// A timed-out migration grant may be ended by the coordinator.
	c := cmd(cluster.CmdPlacementSet, "c1", PlacementSet{Workload: vm, Expected: 2, Owner: "c1", State: cluster.PlacementRunning, Reason: "migration-timeout"})
	if err := (Placements{}).Apply(s, c); err == nil {
		t.Fatal("a fresh migration was ended as timed out")
	}
	c.Time = t0.Add(MigrationGrantTimeout)
	if err := (Placements{}).Apply(s, c); err != nil {
		t.Fatal(err)
	}
	if p := s.Placements[vm]; p.Owner != "c1" || p.MoveBy != "" {
		t.Fatalf("%+v", p)
	}

	// Offline: move.end only from the mover or the move's nodes.
	if err := apply(s, cluster.CmdMoveBegin, "c3", MoveBegin{Workload: vm, Generation: 3, To: "c2", Mode: cluster.MoveOffline}); err != nil {
		t.Fatal(err)
	}
	s.Nodes["c4"] = &cluster.Node{ID: "c4", Role: cluster.RoleCompute, State: cluster.NodeActive}
	if err := apply(s, cluster.CmdMoveEnd, "c4", MoveEnd{Workload: vm, Generation: 3}); err == nil {
		t.Fatal("a bystander ended the move")
	}
	if err := apply(s, cluster.CmdMoveEnd, "c3", MoveEnd{Workload: vm, Generation: 3}); err != nil {
		t.Fatal(err)
	}
}

func TestMoverKeepsDrivingAfterHandOver(t *testing.T) {
	s := snap()
	addVM(t, s, false)
	if err := apply(s, cluster.CmdMoveBegin, "c3", MoveBegin{Workload: vm, Generation: 1, To: "c2", Mode: cluster.MoveOffline}); err != nil {
		t.Fatal(err)
	}
	if err := apply(s, cluster.CmdWorkloadState, "c1", WorkloadStateReport{Workload: vm, Generation: 1, State: cluster.PlacementStopped}); err != nil {
		t.Fatal(err)
	}
	if err := apply(s, cluster.CmdPlacementSet, "c2", PlacementSet{Workload: vm, Expected: 1, Owner: "c2", State: cluster.PlacementStarting, Reason: "move"}); err == nil {
		t.Fatal("the destination took the workload over by itself")
	}
	if err := apply(s, cluster.CmdPlacementSet, "c3", PlacementSet{Workload: vm, Expected: 1, Owner: "c2", State: cluster.PlacementStarting, Reason: "move"}); err != nil {
		t.Fatal(err)
	}
	if p := s.Placements[vm]; p.MoveBy != "c3" || p.Owner != "c2" {
		t.Fatalf("%+v", p)
	}
}

func TestRelocationsAreCountedInTheLog(t *testing.T) {
	s := snap()
	addVM(t, s, true)
	_ = apply(s, cluster.CmdWorkloadState, "c1", WorkloadStateReport{Workload: vm, Generation: 1, State: cluster.PlacementError})
	c := cmd(cluster.CmdPlacementSet, "c2", PlacementSet{Workload: vm, Expected: 1, Owner: "c2", State: cluster.PlacementStarting, Reason: "relocate"})
	if err := (Placements{}).Apply(s, c); err != nil {
		t.Fatal(err)
	}
	if got := s.Placements[vm].Relocated; len(got) != 1 || !got[0].Equal(t0) {
		t.Fatalf("%v", got)
	}
	_ = apply(s, cluster.CmdWorkloadState, "c2", WorkloadStateReport{Workload: vm, Generation: 2, State: cluster.PlacementError})
	c = cmd(cluster.CmdPlacementSet, "c2", PlacementSet{Workload: vm, Expected: 2, Owner: "c3", State: cluster.PlacementStarting, Reason: "relocate"})
	c.Time = t0.Add(2 * time.Hour)
	if err := (Placements{}).Apply(s, c); err != nil {
		t.Fatal(err)
	}
	if got := s.Placements[vm].Relocated; len(got) != 1 {
		t.Fatalf("relocations older than an hour were kept: %v", got)
	}
}

func TestRejoinComparesTheBootOfTheFence(t *testing.T) {
	s := snap()
	s.Nodes["c1"].BootID = "b1"
	if err := apply(s, cluster.CmdNodeDead, "c2", NodeDeadBody{Node: "c1", Epoch: 1, Reason: "dead"}); err != nil {
		t.Fatal(err)
	}
	if s.Fences["c1"].BootID != "b1" {
		t.Fatalf("%+v", s.Fences["c1"])
	}
	fenced(s, "c1")
	// A later record of the node's boot (say a member.update that slipped
	// in) doesn't let the same boot rejoin.
	s.Nodes["c1"].BootID = "b9"
	if err := apply(s, cluster.CmdNodeRejoin, "c1", NodeRejoinBody{Node: "c1", Epoch: 1, BootID: "b1"}); err == nil {
		t.Fatal("the boot that was declared dead rejoined")
	}
	if err := apply(s, cluster.CmdNodeRejoin, "c1", NodeRejoinBody{Node: "c1", Epoch: 1, BootID: "b2"}); err != nil {
		t.Fatal(err)
	}
}

func TestNoOverrideWithoutAnyWatchdog(t *testing.T) {
	s := snap()
	s.Nodes["c1"].Compute.Watchdog = ""
	if err := apply(s, cluster.CmdHAWatchdog, "c2", WatchdogOverrideBody{Node: "c1", Allow: true, Confirm: "c1"}); err == nil {
		t.Fatal("HA was allowed on a server without any watchdog")
	}
	s.HAOverrides["c1"] = &cluster.WatchdogOverride{Node: "c1", Kind: ""}
	if ok, _ := HAEligible(s, "c1"); ok {
		t.Fatal("an old override for no watchdog still counts")
	}
	s.Nodes["c1"].Compute.Watchdog = "softdog"
	if err := apply(s, cluster.CmdHAWatchdog, "c2", WatchdogOverrideBody{Node: "c1", Allow: true, Confirm: "c1"}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := HAEligible(s, "c1"); !ok {
		t.Fatal("softdog override didn't count")
	}
}
