package state

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

func storageCmd(t cluster.CommandType, body any) cluster.Command {
	b, _ := json.Marshal(body)
	return cluster.Command{Type: t, Body: b, Time: time.Date(2026, 11, 7, 1, 0, 0, 0, time.UTC)}
}

func snapWith() *cluster.Snapshot {
	web := cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web"}
	return &cluster.Snapshot{
		Nodes: map[cluster.NodeID]*cluster.Node{
			"c1":  {ID: "c1", Role: cluster.RoleCompute, State: cluster.NodeDead},
			"nas": {ID: "nas", Role: cluster.RoleStorage, State: cluster.NodeActive},
		},
		Placements: map[cluster.WorkloadRef]*cluster.Placement{web: {Workload: web, Owner: "c1", Generation: 4, State: cluster.PlacementRunning,
			Requested: cluster.RequestRunning, Storage: cluster.WorkloadStorage{Pool: "tank"}}},
		Grants: map[cluster.WorkloadRef]*cluster.Grant{web: {Workload: web, Nodes: []cluster.NodeID{"c1"}, Mode: cluster.GrantExclusive, Generation: 4}},
		Fences: map[cluster.NodeID]*cluster.Fence{"c1": {Node: "c1", Epoch: 2, Reason: "dead"}},
	}
}

func TestStorageSigners(t *testing.T) {
	st := Storage{}
	for _, ty := range []cluster.CommandType{cluster.CmdStorageApplied, cluster.CmdStorageFenced, cluster.CmdStorageUnfence, cluster.CmdStorageLayout, cluster.CmdShareCluster} {
		if r := st.Signers(ty); len(r) != 1 || r[0] != cluster.RoleStorage {
			t.Errorf("%s may be signed by %v", ty, r)
		}
	}
	for _, r := range st.Signers(cluster.CmdAppUID) {
		if r == cluster.RoleWitness {
			t.Error("the witness may sign storage.appuid")
		}
	}
}

func TestAppliedAndFenced(t *testing.T) {
	st := Storage{}
	s := snapWith()
	web := cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web"}
	if err := st.Apply(s, storageCmd(cluster.CmdStorageApplied, StorageAppliedBody{Grants: []GrantAck{{Workload: web, Generation: 3}}})); err == nil {
		t.Fatal("a stale acknowledgement was applied")
	}
	if err := st.Apply(s, storageCmd(cluster.CmdStorageApplied, StorageAppliedBody{Grants: []GrantAck{{Workload: web, Generation: 4}}})); err != nil || !s.Grants[web].Applied {
		t.Fatal(err)
	}
	if err := st.Apply(s, storageCmd(cluster.CmdStorageFenced, StorageFencedBody{Node: "c1", Epoch: 1})); err == nil {
		t.Fatal("wrong epoch confirmed")
	}
	if err := st.Apply(s, storageCmd(cluster.CmdStorageFenced, StorageFencedBody{Node: "c1", Epoch: 2})); err != nil {
		t.Fatal(err)
	}
	if !s.Fences["c1"].Confirmed || s.Nodes["c1"].State != cluster.NodeFenced || s.Grants[web].Applied {
		t.Fatalf("after fence: %+v %s %v", s.Fences["c1"], s.Nodes["c1"].State, s.Grants[web].Applied)
	}
	if err := st.Apply(s, storageCmd(cluster.CmdStorageFenced, StorageFencedBody{Node: "c1", Epoch: 2})); err == nil {
		t.Fatal("confirmed twice")
	}
	// Unfence only once rejoining.
	if err := st.Apply(s, storageCmd(cluster.CmdStorageUnfence, StorageUnfencedBody{Node: "c1", Epoch: 2})); err == nil {
		t.Fatal("unfenced a node that isn't rejoining")
	}
	s.Nodes["c1"].State = cluster.NodeRejoining
	if err := st.Apply(s, storageCmd(cluster.CmdStorageUnfence, StorageUnfencedBody{Node: "c1", Epoch: 2})); err != nil {
		t.Fatal(err)
	}
	if s.Nodes["c1"].State != cluster.NodeActive || s.Fences["c1"] != nil {
		t.Fatal("unfence didn't take")
	}
}

func TestAppUIDsAndShares(t *testing.T) {
	st := Storage{}
	s := snapWith()
	if err := st.Apply(s, storageCmd(cluster.CmdAppUID, AppUIDBody{App: "notes", UID: FreeAppUID(s)})); err != nil {
		t.Fatal(err)
	}
	if s.AppUIDs["notes"] != 30000 || FreeAppUID(s) != 30001 {
		t.Fatalf("%v", s.AppUIDs)
	}
	for _, b := range []AppUIDBody{{App: "other", UID: 30000}, {App: "notes", UID: 30001}, {App: "x1", UID: 29999}, {App: "../x", UID: 30002}} {
		if err := st.Apply(s, storageCmd(cluster.CmdAppUID, b)); err == nil {
			t.Errorf("accepted %+v", b)
		}
	}
	sh := cluster.ClusterShare{ID: "media", Pool: "tank", Dataset: "tank/shares/media", Path: "/mnt/tank/shares/media", MountPath: "/mnt/hc/tank/shares/media", FSID: "77"}
	if err := st.Apply(s, storageCmd(cluster.CmdShareCluster, ShareClusterBody{Share: sh, In: true})); err != nil {
		t.Fatal(err)
	}
	bad := sh
	bad.MountPath = "/etc"
	if err := st.Apply(s, storageCmd(cluster.CmdShareCluster, ShareClusterBody{Share: bad, In: true})); err == nil {
		t.Fatal("a share mounted outside /mnt/hc passed")
	}
	bad = sh
	bad.Dataset = "tank/vms/web"
	if err := st.Apply(s, storageCmd(cluster.CmdShareCluster, ShareClusterBody{Share: bad, In: true})); err == nil {
		t.Fatal("a VM's dataset passed as a share")
	}
	if err := st.Apply(s, storageCmd(cluster.CmdShareCluster, ShareClusterBody{Share: sh})); err != nil || len(s.ClusterShares) != 0 {
		t.Fatal(err)
	}
}

func TestLayout(t *testing.T) {
	st := Storage{}
	app := cluster.WorkloadRef{Kind: cluster.KindApp, ID: "notes"}
	s := &cluster.Snapshot{
		Placements: map[cluster.WorkloadRef]*cluster.Placement{app: {Workload: app, Owner: "c1", Generation: 2, State: cluster.PlacementRunning,
			Requested: cluster.RequestRunning, Storage: cluster.WorkloadStorage{Pool: "tank", Mode: cluster.StorageNFS}}},
		Grants: map[cluster.WorkloadRef]*cluster.Grant{app: {Workload: app, Nodes: []cluster.NodeID{"c1"}, Generation: 2, Applied: true}},
	}
	block := cluster.WorkloadStorage{Pool: "tank", Mode: cluster.StorageBlock, BlockFS: "ext4",
		Volumes: []cluster.Volume{{Dataset: "tank/apps/notes/block", Disk: "block", WWN: "6001405aaaaaaaaaaaaaaaaaaaaaaaaa"}}}
	if err := st.Apply(s, storageCmd(cluster.CmdStorageLayout, StorageLayoutBody{Workload: app, Generation: 2, Storage: block})); err == nil {
		t.Fatal("changed a running app's layout")
	}
	s.Placements[app].State, s.Placements[app].Requested = cluster.PlacementStopped, cluster.RequestStopped
	if err := st.Apply(s, storageCmd(cluster.CmdStorageLayout, StorageLayoutBody{Workload: app, Generation: 1, Storage: block})); !errors.Is(err, cluster.ErrStaleGeneration) {
		t.Fatalf("stale generation: %v", err)
	}
	other := block
	other.Volumes = []cluster.Volume{{Dataset: "tank/vms/web/disk0", Disk: "block"}}
	if err := st.Apply(s, storageCmd(cluster.CmdStorageLayout, StorageLayoutBody{Workload: app, Generation: 2, Storage: other})); err == nil {
		t.Fatal("an app took a VM's disk")
	}
	if err := st.Apply(s, storageCmd(cluster.CmdStorageLayout, StorageLayoutBody{Workload: app, Generation: 2, Storage: block})); err != nil {
		t.Fatal(err)
	}
	if s.Placements[app].Generation != 3 || s.Grants[app].Generation != 3 || s.Grants[app].Applied || s.Placements[app].Storage.Mode != cluster.StorageBlock {
		t.Fatalf("after layout: %+v %+v", s.Placements[app], s.Grants[app])
	}
}
