package ha

import (
	"context"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

func TestDeadTimeKeepsTheOldFForOneOldF(t *testing.T) {
	c := &Coordinator{}
	t0 := time.Unix(1000, 0)
	tm := cluster.DefaultTimings
	tm.Dead = 60 * time.Second
	if d := c.deadAfter(tm, t0); d != 60*time.Second {
		t.Fatal(d)
	}
	tm.Dead = 30 * time.Second
	if d := c.deadAfter(tm, t0.Add(time.Second)); d != 60*time.Second {
		t.Fatalf("a shorter F applied at once: %s", d)
	}
	if d := c.deadAfter(tm, t0.Add(62*time.Second)); d != 30*time.Second {
		t.Fatalf("the old F lasted beyond one old F: %s", d)
	}
}

type blockingMover struct{ stopped chan struct{} }

func (b *blockingMover) Move(ctx context.Context, _ cluster.MoveRequest, _ cluster.Actor) (*cluster.MoveResult, error) {
	<-ctx.Done()
	close(b.stopped)
	return nil, ctx.Err()
}

func TestBackgroundMovesStopWhenLeadershipIsLost(t *testing.T) {
	m := &blockingMover{stopped: make(chan struct{})}
	c := &Coordinator{Mover: m}
	c.setLeader(true, time.Now())
	c.background(context.Background(), "c3", &cluster.Placement{Workload: cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web"}, Name: "web"}, JobFailBack, "x", "c1")
	c.setLeader(false, time.Time{})
	select {
	case <-m.stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("a former leader's move kept running")
	}
	c.Wait()
}
