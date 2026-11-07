package placement

import (
	"errors"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

func world() (*cluster.Snapshot, []cluster.Health) {
	s := &cluster.Snapshot{Nodes: map[cluster.NodeID]*cluster.Node{}, Placements: map[cluster.WorkloadRef]*cluster.Placement{},
		Grants: map[cluster.WorkloadRef]*cluster.Grant{}, Fences: map[cluster.NodeID]*cluster.Fence{}, HAOverrides: map[cluster.NodeID]*cluster.WatchdogOverride{}}
	var h []cluster.Health
	for _, id := range []cluster.NodeID{"c1", "c2", "c3"} {
		s.Nodes[id] = &cluster.Node{ID: id, Role: cluster.RoleCompute, State: cluster.NodeActive,
			Compute: &cluster.ComputeInfo{CPUs: 8, MemoryMB: 32768, CPUModel: "Skylake", Watchdog: "hardware", KVM: true, Bridges: map[string][]int{"br0": {10, 20}}}}
		h = append(h, cluster.Health{Node: id, Quorate: true, StorageOK: true, LANOK: true})
	}
	s.Nodes["nas"] = &cluster.Node{ID: "nas", Role: cluster.RoleStorage, State: cluster.NodeActive}
	return s, h
}

var w = cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web"}

func TestPlacePrefersLeastCommitted(t *testing.T) {
	s, h := world()
	busy := cluster.WorkloadRef{Kind: cluster.KindVM, ID: "big"}
	s.Placements[busy] = &cluster.Placement{Workload: busy, Owner: "c1", Requested: cluster.RequestRunning}
	sc := &Scheduler{Requirements: func(r cluster.WorkloadRef) *cluster.Requirements {
		if r == busy {
			return &cluster.Requirements{MemoryMB: 20000}
		}
		return nil
	}}
	got, _, err := sc.Place(s, h, w, cluster.Requirements{MemoryMB: 4096, CPUs: 2}, nil)
	if err != nil || got == "c1" {
		t.Fatalf("got %s %v", got, err)
	}
}

func TestPlaceFiltersWithReasons(t *testing.T) {
	s, h := world()
	s.Nodes["c1"].State = cluster.NodeMaintenance
	h[1].StorageOK = false
	s.Nodes["c3"].Compute.CPUModel = "Zen3"
	sc := &Scheduler{}
	_, skipped, err := sc.Place(s, h, w, cluster.Requirements{MemoryMB: 1024, CPUModel: "Skylake"}, nil)
	if !errors.Is(err, cluster.ErrNoFit) {
		t.Fatalf("expected no fit: %v", err)
	}
	if !strings.Contains(skipped["c1"], "maintenance") || !strings.Contains(skipped["c2"], "storage") || !strings.Contains(skipped["c3"], "CPU") {
		t.Fatalf("reasons: %v", skipped)
	}
	if _, ok := skipped["nas"]; ok {
		t.Fatal("the storage node was considered")
	}
}

func TestPlaceMemoryAndVLANs(t *testing.T) {
	s, h := world()
	sc := &Scheduler{}
	if _, sk, err := sc.Place(s, h, w, cluster.Requirements{MemoryMB: 40000}, nil); err == nil || !strings.Contains(sk["c1"], "memory") {
		t.Fatalf("memory isn't overcommitted: %v %v", err, sk)
	}
	if _, sk, err := sc.Place(s, h, w, cluster.Requirements{Bridges: map[string][]int{"br0": {30}}}, nil); err == nil || !strings.Contains(sk["c2"], "VLAN 30") {
		t.Fatalf("VLAN check: %v %v", err, sk)
	}
	if _, sk, err := sc.Place(s, h, w, cluster.Requirements{Bridges: map[string][]int{"br9": nil}}, nil); err == nil || !strings.Contains(sk["c3"], "br9") {
		t.Fatalf("bridge check: %v %v", err, sk)
	}
}

func TestPreferredAntiAffinityAndExclude(t *testing.T) {
	s, h := world()
	s.Placements[w] = &cluster.Placement{Workload: w, HA: cluster.HAPolicy{Enabled: true, Preferred: []cluster.NodeID{"c3"}, AntiAffinity: "web"}}
	sc := &Scheduler{}
	if got, _, _ := sc.Place(s, h, w, cluster.Requirements{}, nil); got != "c3" {
		t.Fatalf("preferred: %s", got)
	}
	if got, _, _ := sc.Place(s, h, w, cluster.Requirements{}, []cluster.NodeID{"c3"}); got == "c3" {
		t.Fatal("an excluded node was chosen")
	}
	other := cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web2"}
	s.Placements[other] = &cluster.Placement{Workload: other, Owner: "c1", HA: cluster.HAPolicy{Enabled: true, AntiAffinity: "web"}}
	s.Placements[w].HA.Preferred = nil
	if got, _, _ := sc.Place(s, h, w, cluster.Requirements{}, nil); got == "c1" {
		t.Fatal("anti-affinity ignored")
	}
	s.Placements[w].HA.Preferred, s.Placements[w].HA.Restricted = []cluster.NodeID{"c2"}, true
	if _, sk, _ := sc.Place(s, h, w, cluster.Requirements{}, []cluster.NodeID{"c2"}); !strings.Contains(sk["c1"], "preferred") {
		t.Fatalf("restricted: %v", sk)
	}
}

func TestHAOnlyOnWatchdogNodes(t *testing.T) {
	s, h := world()
	s.Nodes["c1"].Compute.Watchdog = "softdog"
	s.Nodes["c2"].Compute.Watchdog = ""
	s.Placements[w] = &cluster.Placement{Workload: w, HA: cluster.HAPolicy{Enabled: true}}
	sc := &Scheduler{}
	got, sk, err := sc.Place(s, h, w, cluster.Requirements{}, nil)
	if err != nil || got != "c3" || !strings.Contains(sk["c1"], "softdog") || !strings.Contains(sk["c2"], "no watchdog") {
		t.Fatalf("%s %v %v", got, sk, err)
	}
	s.HAOverrides["c1"] = &cluster.WatchdogOverride{Node: "c1", Kind: "softdog"}
	if why := sc.Fits(s, h, w, cluster.Requirements{}, "c1"); why != "" {
		t.Fatalf("an allowed softdog node: %s", why)
	}
}

func TestPassthroughNeverAutoPlaced(t *testing.T) {
	s, h := world()
	sc := &Scheduler{}
	if _, _, err := sc.Place(s, h, w, cluster.Requirements{Devices: []string{"gpu:0000:01:00.0"}}, nil); err == nil {
		t.Fatal("a VM with passthrough devices was placed automatically")
	}
	if why := sc.Fits(s, h, w, cluster.Requirements{Devices: []string{"gpu:0000:01:00.0"}}, "c2"); why != "" {
		t.Fatalf("a chosen node is checked by the node itself, not here: %s", why)
	}
}

func TestPendingFenceAndSuspect(t *testing.T) {
	s, h := world()
	s.Nodes["c1"].FenceEpoch = 1
	s.Fences["c1"] = &cluster.Fence{Node: "c1", Epoch: 1}
	h[1].Suspect = true
	h[2].Quorate = false
	if _, sk, err := (&Scheduler{}).Place(s, h, w, cluster.Requirements{}, nil); err == nil || sk["c1"] == "" || sk["c2"] == "" || sk["c3"] == "" {
		t.Fatalf("%v %v", sk, err)
	}
}
