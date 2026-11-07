package ha_test

import (
	"context"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
)

type resolver struct {
	calls []string
}

func (r *resolver) ResolveMigration(_ context.Context, w cluster.WorkloadRef, gen uint64, from, to cluster.NodeID, _ cluster.Actor, reason string) (cluster.NodeID, error) {
	r.calls = append(r.calls, w.ID+" "+string(from)+"->"+string(to)+" "+reason)
	return from, nil
}

// The leader ends a live migration grant that stood longer than the send
// limit and a margin, through root's view of both nodes (decision 388).
func TestStalledMigrationIsEndedByTheLeader(t *testing.T) {
	w, vm := start(t)
	r := &resolver{}
	w.Nodes["c3"].Coord.Migrations = r
	if err := w.Propose("c2", cluster.CmdMoveBegin, state.MoveBegin{Workload: vm, Generation: 1, To: "c2", Mode: cluster.MoveLive}); err != nil {
		t.Fatal(err)
	}
	w.Run(state.MigrationGrantTimeout - time.Minute)
	if len(r.calls) != 0 {
		t.Fatalf("ended too early: %v", r.calls)
	}
	w.Run(2 * time.Minute)
	if len(r.calls) == 0 || r.calls[0] != "web c1->c2 migration-timeout" {
		t.Fatalf("calls %v", r.calls)
	}
	noViolations(t, w)
}

// Relocations are counted in the log, so a new leader doesn't start the
// count again.
func TestRelocationLimitSurvivesALeaderChange(t *testing.T) {
	w, vm := start(t)
	w.Mutate(func(s *cluster.Snapshot) { s.Placements[vm].HA.MaxRelocations = 1 })
	crashLoop := func(n cluster.NodeID) {
		for i := 0; i < 5; i++ {
			w.Nodes[n].Kill(vm)
			w.Run(2 * time.Second)
		}
		w.Run(3 * time.Second)
	}
	crashLoop("c1")
	p := w.Snapshot().Placements[vm]
	if p.Owner == "c1" || len(p.Relocated) != 1 {
		t.Fatalf("first relocation: %+v", p)
	}
	w.SetLeader("c2")
	if p.Owner == "c2" {
		w.SetLeader("c3")
	}
	owner := p.Owner
	crashLoop(owner)
	p = w.Snapshot().Placements[vm]
	if p.Owner != owner || p.State != cluster.PlacementError {
		t.Fatalf("a new leader relocated past the limit: %+v", p)
	}
	noViolations(t, w)
}
