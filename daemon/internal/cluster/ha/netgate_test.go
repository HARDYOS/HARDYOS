package ha_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha"
	"github.com/hardyos/hardyos/daemon/internal/cluster/netcheck"
)

// A failing network check between two servers (decisions 487, 492) never
// holds back a failover: with every pair failing it, a dead server's HA
// VM still restarts elsewhere.
func TestFailingNetworkNeverBlocksFailover(t *testing.T) {
	w, vm := start(t)
	var asked atomic.Int32
	for _, n := range w.Nodes {
		n.Coord.LiveOK = func(context.Context, cluster.NodeID, cluster.NodeID) (bool, string) {
			asked.Add(1)
			return false, "the storage network between them doesn't answer"
		}
	}
	w.Nodes["c1"].Crash()
	tm := w.Snapshot().Timings
	w.Run(tm.Dead + 8*time.Second)
	r := running(w, vm)
	if len(r) != 1 || r[0] == "c1" {
		t.Fatalf("web should run on another node despite the network check, runs on %v", r)
	}
	if asked.Load() != 0 {
		t.Fatalf("a restart asked the live-move network check (%d times)", asked.Load())
	}
	noViolations(t, w)
}

// evacMover fails evacuations while fail is set.
type evacMover struct {
	countingMover
	evacs atomic.Int32
	fail  atomic.Bool
}

func (m *evacMover) Evacuate(context.Context, cluster.MoveRequest, cluster.Actor) (*cluster.MoveResult, error) {
	m.evacs.Add(1)
	if m.fail.Load() {
		return nil, errors.New("not moved live: no storage network with any server that could take it")
	}
	return &cluster.MoveResult{}, nil
}

// Evacuating a LAN-isolated server (decision 487): it can't pass the LAN
// check, so the coordinator never asks it (the Mover checks the storage
// network per destination); a refused evacuation isn't marked done and is
// tried again after EvacuateRetry.
func TestEvacuationSkipsLANCheckAndRetries(t *testing.T) {
	m := &evacMover{}
	m.fail.Store(true)
	var lanAsked atomic.Int32
	c := &ha.Coordinator{Mover: m, LiveOK: func(context.Context, cluster.NodeID, cluster.NodeID) (bool, string) {
		lanAsked.Add(1)
		return false, "c1 lost its LAN"
	}}
	c.SetLeaderForTest(true)
	p := &cluster.Placement{Workload: cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web"}, Name: "web", Owner: "c1"}
	c.EvacuateForTest(context.Background(), "c3", p)
	c.Wait()
	if m.evacs.Load() != 1 || m.moves.Load() != 0 || lanAsked.Load() != 0 {
		t.Fatalf("evacuations %d, plain moves %d, LAN checks %d", m.evacs.Load(), m.moves.Load(), lanAsked.Load())
	}
	done, retryAt := c.EvacuationStateForTest("c1")
	if done || retryAt.IsZero() || time.Until(retryAt) > ha.EvacuateRetry {
		t.Fatalf("after a refused evacuation: done %v, retry at %v", done, retryAt)
	}
}

// The storage network rule an evacuation uses: both servers probed each
// other there, successfully; the LAN doesn't count.
func TestStoragePathOK(t *testing.T) {
	path := func(peer cluster.NodeID, p cluster.Path, ok bool) netcheck.PathResult {
		return netcheck.PathResult{Peer: peer, Path: p, OK: ok}
	}
	r := netcheck.Result{OK: false, Reason: "c1 → c2 on the LAN: not reachable", PerMember: []netcheck.MemberResult{
		{Node: "c1", Paths: []netcheck.PathResult{path("c2", cluster.PathLAN, false), path("c2", cluster.PathStorage, true)}},
		{Node: "c2", Paths: []netcheck.PathResult{path("c1", cluster.PathLAN, false), path("c1", cluster.PathStorage, true)}},
	}}
	if ok, why := ha.StoragePathOK(r, "c1", "c2"); !ok {
		t.Fatalf("the storage network works both ways: %s", why)
	}
	r.PerMember[1].Paths[1].OK = false
	if ok, _ := ha.StoragePathOK(r, "c1", "c2"); ok {
		t.Fatal("passed with c2 → c1 failing on the storage network")
	}
	if ok, _ := ha.StoragePathOK(netcheck.Result{}, "c1", "c2"); ok {
		t.Fatal("passed without any storage network probe")
	}
}

type countingMover struct{ moves atomic.Int32 }

func (m *countingMover) Move(context.Context, cluster.MoveRequest, cluster.Actor) (*cluster.MoveResult, error) {
	m.moves.Add(1)
	return &cluster.MoveResult{}, nil
}

// The coordinator's own live moves (evacuations, fail back) ask the same
// pair check as any live move, and don't start while it fails.
func TestFailingNetworkBlocksCoordinatorLiveMoves(t *testing.T) {
	for _, ok := range []bool{false, true} {
		m := &countingMover{}
		var from, to cluster.NodeID
		c := &ha.Coordinator{Mover: m, LiveOK: func(_ context.Context, f, t cluster.NodeID) (bool, string) {
			from, to = f, t
			return ok, "no route on the LAN"
		}}
		c.SetLeaderForTest(true)
		c.BackgroundForTest(context.Background(), "c3", &cluster.Placement{Workload: cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web"}, Name: "web", Owner: "c1"}, "c2")
		c.Wait()
		if from != "c1" || to != "c2" {
			t.Fatalf("checked %s -> %s, not the move's two servers", from, to)
		}
		if got := m.moves.Load(); (got == 1) != ok {
			t.Fatalf("network ok %v: %d live moves started", ok, got)
		}
	}
}
