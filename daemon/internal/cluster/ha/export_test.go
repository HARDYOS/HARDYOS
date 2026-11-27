package ha

import (
	"context"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// SetLeaderForTest makes c the leader (or not) as of now.
func (c *Coordinator) SetLeaderForTest(on bool) { c.setLeader(on, time.Now()) }

// EvacuateForTest starts the evacuation of p off its (LAN-isolated) owner.
func (c *Coordinator) EvacuateForTest(ctx context.Context, self cluster.NodeID, p *cluster.Placement) {
	c.mu.Lock()
	if c.evacuated == nil {
		c.evacuated, c.evacRetry = map[cluster.NodeID]bool{}, map[cluster.NodeID]time.Time{}
	}
	c.evacuated[p.Owner] = true
	c.mu.Unlock()
	c.background(ctx, self, p, JobEvacuate, "Move "+p.Name+" off "+string(p.Owner), "")
}

// EvacuationStateForTest is whether node counts as evacuated and when a
// failed evacuation of it is tried again.
func (c *Coordinator) EvacuationStateForTest(node cluster.NodeID) (bool, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.evacuated[node], c.evacRetry[node]
}

// BackgroundForTest starts one of the coordinator's background live moves
// (a fail back) of p to the server to.
func (c *Coordinator) BackgroundForTest(ctx context.Context, self cluster.NodeID, p *cluster.Placement, to cluster.NodeID) {
	c.background(ctx, self, p, JobFailBack, "Move "+p.Name+" back", to)
}
