package runtime_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha/clustertest"
	"github.com/hardyos/hardyos/daemon/internal/cluster/runtime"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
)

// Nothing starts on a node until the state records its current boot: a
// fence declared before that would remember the previous boot and let
// this one rejoin as if it had restarted (decision 389).
func TestNothingStartsBeforeTheBootIsRecorded(t *testing.T) {
	w := clustertest.New(t, "c1", "c2")
	w.Mutate(func(s *cluster.Snapshot) { s.Nodes["c1"].BootID = "an-older-boot" })
	vm := w.AddVM("web", "c1", false, 0)
	w.Run(3 * time.Second)
	if _, ok := w.Nodes["c1"].RunningGen(vm); ok {
		t.Fatal("started before this boot was recorded")
	}
	w.Mutate(func(s *cluster.Snapshot) { s.Nodes["c1"].BootID = w.Nodes["c1"].BootID })
	w.Run(3 * time.Second)
	if _, ok := w.Nodes["c1"].RunningGen(vm); !ok {
		t.Fatal("didn't start once the boot was recorded")
	}
}

// An HA workload starts only once the fence agent armed the watchdog.
func TestHAStartWaitsForTheFenceAgent(t *testing.T) {
	w := clustertest.New(t, "c1", "c2")
	ready := false
	w.Nodes["c1"].Rec.FenceReady = func() bool { return ready }
	vm := w.AddVM("web", "c1", true, 50)
	w.Run(3 * time.Second)
	if _, ok := w.Nodes["c1"].RunningGen(vm); ok {
		t.Fatal("an HA workload started before the watchdog was armed")
	}
	ready = true
	w.Run(3 * time.Second)
	if _, ok := w.Nodes["c1"].RunningGen(vm); !ok {
		t.Fatal("never started")
	}
}

func TestPrepullBoundsTheOwnersList(t *testing.T) {
	w := clustertest.New(t, "c1", "c2")
	app := cluster.WorkloadRef{Kind: cluster.KindApp, ID: "notes"}
	if err := w.Propose("c1", cluster.CmdWorkloadAdd, state.WorkloadAdd{SpecHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Workload: app, Name: "notes", Owner: "c1",
		Requested: cluster.RequestRunning, HA: cluster.HAPolicy{Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	var list []string
	for i := 0; i < 100; i++ {
		list = append(list, fmt.Sprintf("ghcr.io/x/img%d:1", i))
	}
	list = append([]string{"Not An Image!", "ghcr.io/x/img0:1"}, list...)
	st := &store{}
	p := &runtime.Prepuller{Cluster: w.Nodes["c2"], Source: &source{imgs: map[string][]string{"notes": list}}, Images: st}
	p.Step(context.Background(), true)
	n := 0
	for _, l := range st.pulls {
		n += len(l)
		for _, img := range l {
			if img == "Not An Image!" {
				t.Fatal("an invalid reference was pulled")
			}
		}
	}
	if n != runtime.MaxImagesPerApp {
		t.Fatalf("pulled %d images for one app", n)
	}
}
