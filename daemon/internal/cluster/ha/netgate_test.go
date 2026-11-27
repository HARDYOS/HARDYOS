package ha_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha"
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
