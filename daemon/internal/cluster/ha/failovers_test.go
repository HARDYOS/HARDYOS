package ha_test

import (
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
)

// Every recovery decision reaches OnFailover (history and alerts,
// decision 484): a dead server's HA VMs restart elsewhere, higher priority
// first, only after the fence; a VM that fits nowhere is "nowhere to run".
func TestFailoverRecords(t *testing.T) {
	w, vm := start(t)
	low := w.AddVM("low", "c1", true, 10)
	w.Run(3 * time.Second)
	var mu sync.Mutex
	var got []ha.Failover
	w.Nodes["c3"].Coord.OnFailover = func(f ha.Failover) {
		mu.Lock()
		got = append(got, f)
		mu.Unlock()
	}
	w.Nodes["c1"].Crash()
	w.Run(w.Snapshot().Timings.Dead + 20*time.Second)
	noViolations(t, w)
	mu.Lock()
	defer mu.Unlock()
	if len(got) < 2 {
		t.Fatalf("failovers %+v", got)
	}
	if got[0].Workload != vm || got[1].Workload != low {
		t.Fatalf("higher priority first: %+v", got)
	}
	for _, f := range got[:2] {
		if f.Outcome != ha.FailoverRestarted || f.From != "c1" || (f.To != "c2" && f.To != "c3") || f.Coordinator != "c3" {
			t.Fatalf("failover %+v", f)
		}
		fence := w.Snapshot().Fences["c1"]
		if fence == nil || !fence.Confirmed || f.At.Before(fence.ConfirmedAt) {
			t.Fatalf("restarted before the fence was confirmed: %+v %+v", f, fence)
		}
	}
}

func TestFailoverNowhereToRun(t *testing.T) {
	w, _ := start(t)
	var mu sync.Mutex
	var got []ha.Failover
	w.Nodes["c3"].Coord.OnFailover = func(f ha.Failover) {
		mu.Lock()
		got = append(got, f)
		mu.Unlock()
	}
	// Nowhere else to go: it may only run on c1.
	vm := cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web"}
	if err := w.Propose("c3", cluster.CmdHAPolicy, state.HAPolicySet{Workload: vm,
		Policy: cluster.HAPolicy{Enabled: true, Priority: 80, Preferred: []cluster.NodeID{"c1"}, Restricted: true}}); err != nil {
		t.Fatal(err)
	}
	w.Nodes["c1"].Crash()
	w.Run(w.Snapshot().Timings.Dead + 20*time.Second)
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, f := range got {
		if f.Outcome == ha.FailoverPending && f.To == "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no 'nowhere to run' among %+v (placement %+v)", got, w.Snapshot().Placements[cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web"}])
	}
}
