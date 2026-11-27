package vms

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// A local VM's conversion check: what keeps it on this server, and the
// hash of its settings as they will be on cluster storage (the storage
// server's pool, the cluster's CPU model) - the hash ClusterAdopt then
// has to meet once it is attached (decisions 480, 486).
func TestHACheckAndClusterAdopt(t *testing.T) {
	e := haEnv(t)
	ctx := context.Background()
	if _, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	v, err := e.m.Get(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.m.HACheck(ctx, HACheckArgs{ID: "web", Pool: "nas", SetCPU: true, CPUModel: "x86-64-v2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) != 0 || res.LocalPool != v.Pool || res.CPUModel != "x86-64-v2" || len(res.Disks) == 0 {
		t.Fatalf("check %+v", res)
	}
	// The same VM attached from cluster storage (as after workload.add,
	// its vm.json as it was sent): ClusterAdopt writes the converted spec
	// only for the recorded hash.
	stored, err := os.ReadFile(filepath.Join(e.root, e.sim.datasets[v.Dataset]["mountpoint"], specFile))
	if err != nil {
		t.Fatal(err)
	}
	var want Spec
	_ = json.Unmarshal(stored, &want)
	want.Normalize()
	want.Pool, want.CPUModel = "nas", "x86-64-v2"
	if h, _ := SpecHash(&want); h != res.Hash {
		t.Fatal("the check's hash isn't the converted spec's")
	}
	dir := "/mnt/hc/nas/vms/web"
	write(t, filepath.Join(e.root, dir, specFile), string(stored))
	e.m.Backend = &fakeBackend{att: map[string]*AttachedStorage{
		"web": {Backend: BackendCluster, StateDir: dir, Disks: map[string]string{"disk0": testWWN}, Generation: 1},
	}}
	// Parked here first: no local VM of that name.
	delete(e.sim.datasets, v.Dataset)
	if _, err := e.m.ClusterAdopt(ctx, ClusterAdoptArgs{HACheckArgs: HACheckArgs{ID: "web", Pool: "nas"}, Hash: res.Hash}); err == nil {
		t.Fatal("adopted a spec that doesn't hash as recorded (the CPU model left out)")
	}
	if _, err := e.m.ClusterAdopt(ctx, ClusterAdoptArgs{HACheckArgs: HACheckArgs{ID: "web", Pool: "nas", SetCPU: true, CPUModel: "x86-64-v2"}, Hash: res.Hash}); err != nil {
		t.Fatal(err)
	}
	h, err := e.m.ClusterHash(ctx, "web")
	if err != nil || h != res.Hash {
		t.Fatalf("the cluster VM's hash after adopting: %s %v", h, err)
	}
}

// What keeps a VM on its server: passthrough devices, ISOs from this
// server's library, an unfinished Windows install.
func TestHACheckProblems(t *testing.T) {
	e := haEnv(t)
	ctx := context.Background()
	s := linuxSpec(t)
	s.Media = append(s.Media, Media{Kind: MediaISO, ISO: "debian.iso"})
	e.addISO(t, "debian.iso", 1024)
	if _, err := e.m.Create(ctx, CreateArgs{Spec: s, Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	res, err := e.m.HACheck(ctx, HACheckArgs{ID: "web", Pool: "nas"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(res.Problems, func(p string) bool { return strings.Contains(p, "ISO library") }) {
		t.Fatalf("problems %v", res.Problems)
	}
	if _, err := e.m.HACheck(ctx, HACheckArgs{ID: "web", Pool: "bad/pool"}); err == nil {
		t.Fatal("a bad pool name was accepted")
	}
}

// On the storage server a cluster VM's datasets are never one of its own
// VMs (decision 488): the engine leaves org.hardyos:role=cluster alone.
func TestClusterDatasetsAreNotLocalVMs(t *testing.T) {
	e := haEnv(t)
	ctx := context.Background()
	if _, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	v, _ := e.m.Get(ctx, "web")
	e.sim.datasets[v.Dataset]["org.hardyos:role"] = "cluster"
	if _, err := e.m.Get(ctx, "web"); err == nil {
		t.Fatal("the storage server listed a cluster VM as its own")
	}
}

// The storage server's scheduler for HA VMs follows the same rules.
func TestScheduleStep(t *testing.T) {
	now := time.Date(2026, 11, 27, 10, 30, 0, 0, time.UTC)
	sc := &Schedule{Hourly: 2}
	have := []string{"vm-auto-hourly-20261127-0800", "vm-auto-hourly-20261127-0900", "manual"}
	due, prune := ScheduleStep(sc, have, now)
	if !slices.Equal(due, []string{"vm-auto-hourly-20261127-1000"}) || !slices.Equal(prune, []string{"vm-auto-hourly-20261127-0800"}) {
		t.Fatalf("due %v prune %v", due, prune)
	}
	if d, p := ScheduleStep(nil, have, now); d != nil || p != nil {
		t.Fatal("no schedule took snapshots")
	}
}

// Root's own change at the end of an unattended install of a cluster VM
// is recorded (before and after) for hardyd to approve, once.
func TestClusterInstalledRecords(t *testing.T) {
	e := newEnv(t)
	e.m.recordInstallDone("web", "sha256:a", "sha256:b")
	l := e.m.ClusterInstalled(InstalledArgs{})
	if len(l) != 1 || l[0].Before != "sha256:a" || l[0].After != "sha256:b" {
		t.Fatalf("records %+v", l)
	}
	// A restart of hardyd-priv (a new manager) still has it.
	again := &Manager{Root: e.root}
	if l := again.ClusterInstalled(InstalledArgs{}); len(l) != 1 || l[0].ID != "web" {
		t.Fatalf("after a restart: %+v", l)
	}
	if l := again.ClusterInstalled(InstalledArgs{Ack: []string{"web"}}); len(l) != 0 {
		t.Fatalf("acknowledged records stay: %+v", l)
	}
	if l := (&Manager{Root: e.root}).ClusterInstalled(InstalledArgs{}); len(l) != 0 {
		t.Fatalf("an acknowledged record came back after a restart: %+v", l)
	}
}

func haEnv(t *testing.T) *testEnv {
	t.Helper()
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 1024)
	return e
}
