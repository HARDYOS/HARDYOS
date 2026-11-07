package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha/clustertest"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
)

// Changing a cluster workload's settings goes through its owner, which
// records the approved hash (decision 386): a VM placed here gets the
// actor for the approval, one placed elsewhere and every cluster app are
// refused with a clear error; other VMs and apps are untouched.
func TestClusterWorkloadSettings(t *testing.T) {
	w := clustertest.New(t, "c1", "c2")
	svc := &ha.Service{}
	svc.Parts.Membership = w.Nodes["c1"]
	svc.Init()
	s := New(Config{ClusterHA: svc, Insecure: true})
	if clusterSpecs.Load() != svc {
		t.Fatal("the VM update job can't reach part C")
	}
	w.AddVM("here", "c1", false, 0)
	w.AddVM("there", "c2", false, 0)
	app := cluster.WorkloadRef{Kind: cluster.KindApp, ID: "notes"}
	if err := w.Propose("c1", cluster.CmdWorkloadAdd, state.WorkloadAdd{SpecHash: "sha256:" + strings.Repeat("b", 64), Workload: app, Name: "Notes", Owner: "c1",
		Storage: cluster.WorkloadStorage{Pool: "tank"}}); err != nil {
		t.Fatal(err)
	}
	u := &auth.User{Principal: "cade"}
	vm := func(id string) cluster.WorkloadRef { return cluster.WorkloadRef{Kind: cluster.KindVM, ID: id} }

	rec := httptest.NewRecorder()
	if a, ok := s.clusterSettings(rec, u, vm("local")); !ok || a != nil {
		t.Fatalf("a local VM: %v %v", a, ok)
	}
	if a, ok := s.clusterSettings(rec, u, vm("here")); !ok || a == nil || a.Name == "" {
		t.Fatalf("a cluster VM placed here: %+v %v", a, ok)
	}
	rec = httptest.NewRecorder()
	if _, ok := s.clusterSettings(rec, u, vm("there")); ok || rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "c2") {
		t.Fatalf("a cluster VM placed elsewhere: %v %d %s", ok, rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	if !s.refuseClusterApp(rec, "notes") || rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "cluster_workload") {
		t.Fatalf("a cluster app's settings: %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	if s.refuseClusterApp(rec, "photos") {
		t.Fatal("a local app was refused")
	}
}
