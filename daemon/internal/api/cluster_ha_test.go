package api

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha/clustertest"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/updates"
)

func newClusterEnv(t *testing.T, member bool) (*testEnv, *clustertest.World) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	broker := events.NewBroker()
	m := &jobs.Manager{DB: db, Events: broker}
	var w *clustertest.World
	svc := &ha.Service{Jobs: m, DB: db}
	if member {
		w = clustertest.New(t, "c1", "c2")
		svc.Parts.Membership = w.Nodes["c1"]
	}
	svc.Init()
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	upd := &updates.Service{Jobs: m, DB: db, Dir: t.TempDir()}
	srv := httptest.NewServer(New(Config{DB: db, Jobs: m, Events: broker, Updates: upd, ClusterHA: svc, Insecure: true}))
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	return &testEnv{srv: srv, db: db, broker: broker}, w
}

func TestClusterHAOutsideACluster(t *testing.T) {
	env, _ := newClusterEnv(t, false)
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	var v ha.StatusView
	if code := admin.do("GET", "/api/v1/cluster/ha", nil, &v); code != 200 || v.Member {
		t.Fatalf("%d %+v", code, v)
	}
	if code := admin.do("POST", "/api/v1/cluster/moves", map[string]any{"kind": "vm", "id": "web", "mode": "offline"}, nil); code != 409 {
		t.Fatalf("a move outside a cluster: %d", code)
	}
}

func TestClusterHAAPI(t *testing.T) {
	env, w := newClusterEnv(t, true)
	vm := w.AddVM("web", "c1", false, 0)
	gpu := cluster.WorkloadRef{Kind: cluster.KindVM, ID: "gpu"}
	if err := w.Propose("c1", cluster.CmdWorkloadAdd, state.WorkloadAdd{SpecHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Workload: gpu, Name: "Gaming", Owner: "c1", Pinned: true}); err != nil {
		t.Fatal(err)
	}
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	kid := env.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	if code := kid.do("GET", "/api/v1/cluster/ha", nil, nil); code != 403 {
		t.Fatalf("a non-admin read HA: %d", code)
	}

	var v ha.StatusView
	if code := admin.do("GET", "/api/v1/cluster/ha", nil, &v); code != 200 || !v.Member || len(v.Placements) != 2 || len(v.Nodes) != 2 {
		t.Fatalf("%d %+v", code, v)
	}
	if code := admin.do("PUT", "/api/v1/cluster/workloads/vm/web/ha", map[string]any{"policy": map[string]any{"enabled": true, "priority": 500}}, nil); code != 400 {
		t.Fatalf("a priority of 500: %d", code)
	}
	if code := admin.do("PUT", "/api/v1/cluster/workloads/vm/gpu/ha", map[string]any{"policy": map[string]any{"enabled": true}}, nil); code != 400 {
		t.Fatalf("HA for a pinned VM: %d", code)
	}
	if code := admin.do("PUT", "/api/v1/cluster/workloads/vm/web/ha", map[string]any{"policy": map[string]any{"enabled": true, "priority": 70}}, nil); code != 202 {
		t.Fatalf("a valid policy: %d", code)
	}
	if code := admin.do("PUT", "/api/v1/cluster/workloads/vm/nope/ha", map[string]any{"policy": map[string]any{}}, nil); code != 404 {
		t.Fatalf("an unknown workload: %d", code)
	}
	if code := admin.do("PUT", "/api/v1/cluster/ha/watchdog/c2", map[string]any{"allow": true, "confirm": "c1"}, nil); code != 400 {
		t.Fatalf("an override without its confirmation: %d", code)
	}
	if code := admin.do("PUT", "/api/v1/cluster/ha/timings", map[string]any{"heartbeatMs": 1000, "suspectMs": 10000, "quorumLeaseMs": 15000,
		"selfStopMs": 5000, "watchdogMs": 10000, "deadMs": 20000, "storageIsolatedMs": 15000, "lanIsolatedMs": 60000, "fenceAckMs": 30000}, nil); code != 400 {
		t.Fatalf("unsafe timings: %d", code)
	}
	if code := admin.do("POST", "/api/v1/cluster/moves", map[string]any{"kind": "vm", "id": "gpu", "to": "c2", "mode": "offline"}, nil); code != 400 {
		t.Fatalf("a passthrough VM moved without confirmation: %d", code)
	}
	if code := admin.do("POST", "/api/v1/cluster/moves", map[string]any{"kind": "app", "id": "web", "mode": "live"}, nil); code != 400 {
		t.Fatalf("an app moving live: %d", code)
	}
	if code := admin.do("POST", "/api/v1/cluster/moves", map[string]any{"kind": "vm", "id": "web", "mode": "offline", "generation": 9}, nil); code != 409 {
		t.Fatalf("a stale generation: %d", code)
	}
	if code := admin.do("POST", "/api/v1/cluster/moves", map[string]any{"kind": "vm", "id": "web", "to": "c2", "mode": "offline"}, nil); code != 202 {
		t.Fatalf("a valid move: %d", code)
	}
	if code := admin.do("POST", "/api/v1/cluster/moves/drain", map[string]any{"node": "c1", "stopOthers": true}, nil); code != 400 {
		t.Fatalf("a drain that stops workloads without confirmation: %d", code)
	}
	var c ha.CandidatesView
	if code := admin.do("GET", "/api/v1/cluster/moves/candidates?kind=vm&id=gpu", nil, &c); code != 200 || !c.Pinned || c.Live {
		t.Fatalf("%d %+v", code, c)
	}
	_ = vm
}
