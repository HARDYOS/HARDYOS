package ha

import (
	"context"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// SetLeaderForTest makes c the leader (or not) as of now.
func (c *Coordinator) SetLeaderForTest(on bool) { c.setLeader(on, time.Now()) }

// BackgroundForTest starts one of the coordinator's background live moves
// (a fail back) of p to the server to.
func (c *Coordinator) BackgroundForTest(ctx context.Context, self cluster.NodeID, p *cluster.Placement, to cluster.NodeID) {
	c.background(ctx, self, p, JobFailBack, "Move "+p.Name+" back", to)
}
