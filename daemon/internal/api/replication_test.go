package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/replica"
	"github.com/hardyos/hardyos/daemon/internal/replication"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/updates"
)

func newReplicationEnv(t *testing.T) (*testEnv, *replication.Service) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	broker := events.NewBroker()
	m := &jobs.Manager{DB: db, Events: broker}
	fake := &sysexec.Fake{}
	fake.On("zpool list -H -o name", "tank\n")
	fake.On("zfs get -H -p -o value org.hardyos:role tank/replicas", "-\n")
	svc := &replication.Service{DB: db, Root: &replication.LocalRoot{M: &replica.Manager{Runner: fake}}, Jobs: m,
		Sealer: &replication.Sealer{Source: secretbox.NewStaticSource()}, Hostname: func() string { return "nas" }}
	svc.RegisterJobs(m)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	upd := &updates.Service{Jobs: m, DB: db, Dir: t.TempDir()}
	srv := httptest.NewServer(New(Config{DB: db, Jobs: m, Events: broker, Updates: upd, Replication: svc, Insecure: true}))
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	return &testEnv{srv: srv, db: db, broker: broker}, svc
}

func TestReplicationAPI(t *testing.T) {
	env, svc := newReplicationEnv(t)
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)

	// Administrators only.
	admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	kid := env.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	for _, p := range []string{"/api/v1/replication", "/api/v1/replication/receive", "/api/v1/replication/items"} {
		if code := kid.do("GET", p, nil, nil); code != 403 {
			t.Errorf("%s as a family member: %d", p, code)
		}
	}

	var ov ReplicationOverview
	if code := admin.do("GET", "/api/v1/replication", nil, &ov); code != 200 || len(ov.Pin) != 64 || ov.Port != replication.DefaultPort || len(ov.Tasks) != 0 {
		t.Fatalf("overview %d %+v", code, ov)
	}

	// Receiving side: a pairing code, shown once, stored sealed.
	var e ErrorResponse
	if code := admin.do("POST", "/api/v1/replication/receive/pairing", map[string]any{"pool": "rpool"}, &e); code != 400 {
		t.Fatalf("boot pool: %d", code)
	}
	var pc ReplicationPairingCode
	if code := admin.do("POST", "/api/v1/replication/receive/pairing", map[string]any{"pool": "tank", "quotaBytes": 1 << 40, "minKeep": 5}, &pc); code != 202 || len(pc.Code) != 30 {
		t.Fatalf("pairing %d %+v", code, pc)
	}
	if j := waitJobDone(t, admin, pc.Job.(map[string]any)["id"].(string)); j["state"] != "succeeded" {
		t.Fatalf("pairing job %v", j)
	}
	var rcv ReplicationReceive
	if code := admin.do("GET", "/api/v1/replication/receive", nil, &rcv); code != 200 || !rcv.Receiving || rcv.Pairing == nil || rcv.Pairing.Pool != "tank" || rcv.Pairing.MinKeep != 5 {
		t.Fatalf("receive %d %+v", code, rcv)
	}
	var jobsList []map[string]any
	admin.do("GET", "/api/v1/jobs", nil, &jobsList)
	for _, j := range jobsList {
		if b, _ := json.Marshal(j); strings.Contains(string(b), pc.Code) {
			t.Fatal("the pairing code is in a job's parameters")
		}
	}
	var stored string
	_ = env.db.QueryRow(`SELECT hex(code_sealed) FROM repl_pairing`).Scan(&stored)
	if stored == "" || strings.Contains(strings.ToLower(stored), strings.ToLower(strings.ReplaceAll(pc.Code, "-", ""))) {
		t.Fatal("pairing code not sealed")
	}
	if code := admin.do("DELETE", "/api/v1/replication/receive/pairing", nil, nil); code != 202 {
		t.Fatalf("cancel pairing %d", code)
	}

	// Sending side: bad addresses and codes never reach a job.
	if code := admin.do("POST", "/api/v1/replication/targets", map[string]string{"address": "nas 2", "code": pc.Code}, &e); code != 400 {
		t.Fatalf("bad address %d", code)
	}
	if code := admin.do("POST", "/api/v1/replication/targets", map[string]string{"address": "nas2", "code": "nope"}, &e); code != 400 {
		t.Fatalf("bad code %d", code)
	}
	// A task needs a paired server.
	task := map[string]any{"name": "Nightly", "targetId": "nope", "intervalMinutes": 60, "keepLocal": 3, "keepRemote": 14, "enabled": true,
		"items": []map[string]string{{"kind": "share", "id": "media"}}}
	if code := admin.do("POST", "/api/v1/replication/tasks", task, &e); code != 400 {
		t.Fatalf("task without a server %d", code)
	}
	tgt := &replication.Target{Name: "bravo", Address: "bravo:44400", SourceID: "abcdef123456", Pin: strings.Repeat("ab", 32)}
	if err := svc.Store().AddTarget(context.Background(), tgt); err != nil {
		t.Fatal(err)
	}
	task["targetId"] = tgt.ID
	task["intervalMinutes"] = 1
	if code := admin.do("POST", "/api/v1/replication/tasks", task, &e); code != 400 || !strings.Contains(e.Message, "minutes") {
		t.Fatalf("1-minute task %d %s", code, e.Message)
	}
	task["intervalMinutes"] = 30
	var acc struct {
		Job map[string]any `json:"job"`
	}
	if code := admin.do("POST", "/api/v1/replication/tasks", task, &acc); code != 202 {
		t.Fatalf("task %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job["id"].(string)); j["state"] != "succeeded" {
		t.Fatalf("task job %v", j)
	}
	admin.do("GET", "/api/v1/replication", nil, &ov)
	if len(ov.Tasks) != 1 || ov.Tasks[0].TargetName != "bravo" || ov.Tasks[0].NextRunAt == nil || len(ov.Targets[0].Pin) != 16 {
		t.Fatalf("overview %+v", ov)
	}
	id := ov.Tasks[0].ID
	// Deleting needs the name; the target can't go while a task uses it.
	if code := admin.do("DELETE", "/api/v1/replication/tasks/"+id, map[string]string{"confirm": "nightly"}, &e); code != 400 {
		t.Fatalf("delete without the name %d", code)
	}
	if code := admin.do("DELETE", "/api/v1/replication/targets/"+tgt.ID, map[string]string{"confirm": "bravo"}, &acc); code != 202 {
		t.Fatalf("delete target %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job["id"].(string)); j["state"] != "failed" || !strings.Contains(j["error"].(string), "still sends") {
		t.Fatalf("target with a task %v", j)
	}
	var hist map[string][]any
	if code := admin.do("GET", "/api/v1/replication/tasks/"+id+"/history", nil, &hist); code != 200 || len(hist["runs"]) != 0 {
		t.Fatalf("history %d %v", code, hist)
	}
	if code := admin.do("POST", "/api/v1/replication/tasks/"+id+"/cancel", nil, &e); code != 409 {
		t.Fatalf("cancel when idle %d", code)
	}
	// Restores need a confirmation and valid names.
	restore := map[string]any{"kind": "share", "id": "media", "snapshot": "hardyos-repl-abcdef1234-20261027T101500Z", "pool": "tank", "newId": "media-old", "name": "Media (old)"}
	if code := admin.do("POST", "/api/v1/replication/targets/"+tgt.ID+"/restore", restore, &e); code != 400 || e.Code != "confirm_required" {
		t.Fatalf("restore without confirm %d %+v", code, e)
	}
	restore["confirm"], restore["snapshot"] = true, "manual-1"
	if code := admin.do("POST", "/api/v1/replication/targets/"+tgt.ID+"/restore", restore, &e); code != 400 {
		t.Fatalf("restore of a user snapshot %d", code)
	}
	if code := admin.do("GET", "/api/v1/replication/targets/"+tgt.ID+"/replicas/pool/x/snapshots", nil, &e); code != 400 {
		t.Fatalf("bad kind %d", code)
	}
	// Sources: unknown ones 404; deleting one needs its name.
	if code := admin.do("DELETE", "/api/v1/replication/receive/sources/nope", map[string]any{"confirm": "x", "deleteReplicas": true}, &e); code != 404 {
		t.Fatalf("unknown source %d", code)
	}
}
