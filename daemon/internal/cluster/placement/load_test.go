package placement

import (
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// Failover picks the least-loaded server by its busier resource: a server
// with free memory but every CPU committed loses to one with less free
// memory and idle CPUs (decision 484); a preferred server still comes
// first.
func TestPlaceLeastLoadedByCPUAndMemory(t *testing.T) {
	s, h := world()
	cpuBusy := cluster.WorkloadRef{Kind: cluster.KindVM, ID: "cpu"}
	memBusy := cluster.WorkloadRef{Kind: cluster.KindVM, ID: "mem"}
	s.Placements[cpuBusy] = &cluster.Placement{Workload: cpuBusy, Owner: "c1", Requested: cluster.RequestRunning}
	s.Placements[memBusy] = &cluster.Placement{Workload: memBusy, Owner: "c2", Requested: cluster.RequestRunning}
	s.Nodes["c3"].State = cluster.NodeMaintenance
	sc := &Scheduler{Requirements: func(r cluster.WorkloadRef) *cluster.Requirements {
		switch r {
		case cpuBusy:
			return &cluster.Requirements{MemoryMB: 1024, CPUs: 8} // c1: every CPU committed
		case memBusy:
			return &cluster.Requirements{MemoryMB: 12000, CPUs: 1} // c2: memory 40% committed
		}
		return nil
	}}
	got, _, err := sc.Place(s, h, w, cluster.Requirements{MemoryMB: 1024, CPUs: 1}, nil)
	if err != nil || got != "c2" {
		t.Fatalf("got %s %v; c1's CPUs are all committed", got, err)
	}
	s.Placements[w] = &cluster.Placement{Workload: w, HA: cluster.HAPolicy{Enabled: true, Preferred: []cluster.NodeID{"c1"}}}
	if got, _, _ := sc.Place(s, h, w, cluster.Requirements{MemoryMB: 1024, CPUs: 1}, nil); got != "c1" {
		t.Fatalf("the preferred server comes first: %s", got)
	}
}
