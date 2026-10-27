package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/nfs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/snapshots"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/updates"
)

func TestSnapshotsAPI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stub := &stubShares{shares: []shares.Share{
		{ID: "media", Name: "Media", Pool: "tank", Dataset: "tank/shares/media", Path: "/mnt/tank/shares/media", Mounted: true,
			Access: []shares.Rule{{Kind: shares.KindEveryone, Level: shares.LevelRead}}, Apps: []shares.AppGrant{}, Services: shares.DefaultServices()},
		{ID: "backups", Name: "Backups", Pool: "tank", Dataset: "tank/shares/backups", Path: "/mnt/tank/shares/backups", Mounted: true,
			Access: []shares.Rule{}, Apps: []shares.AppGrant{}, Services: shares.DefaultServices()},
		{ID: "secret", Name: "Secret", Pool: "tank", Dataset: "tank/shares/secret", Mounted: true,
			Access: []shares.Rule{{Kind: shares.KindEveryone, Level: shares.LevelRead}, {Kind: shares.KindUser, Name: "kid", Level: shares.LevelNone}},
			Apps:   []shares.AppGrant{}, Services: shares.DefaultServices()},
	}}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	stub.register(ps)
	var mu sync.Mutex
	var calls []string
	rec := func(op string, raw json.RawMessage) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, op+" "+string(raw))
	}
	ps.Handle(priv.OpSnapshotsList, func(_ context.Context, raw json.RawMessage) (any, error) {
		rec("list", raw)
		return priv.SnapshotsResult{Snapshots: []snapshots.Snapshot{{Name: "hardyos-auto-hourly_2026-10-26-1300", Kind: "hourly", CreatedAt: time.Now()}}}, nil
	})
	ps.Handle(priv.OpSnapshotsCreate, func(_ context.Context, raw json.RawMessage) (any, error) {
		rec("create", raw)
		var a priv.SnapshotsCreateArgs
		_ = json.Unmarshal(raw, &a)
		return snapshots.Snapshot{Name: a.Name, Kind: "manual"}, nil
	})
	ps.Handle(priv.OpSnapshotsDelete, func(_ context.Context, raw json.RawMessage) (any, error) {
		rec("delete", raw)
		return map[string]bool{"deleted": true}, nil
	})
	ps.Handle(priv.OpNFSStatus, func(context.Context, json.RawMessage) (any, error) {
		return nfs.Status{Running: true, UIDs: map[string]int{"media": 31000}, Exports: []nfs.Export{}}, nil
	})
	go func() { _ = ps.Serve(ctx, ln) }()
	pc := priv.NewClient(sock)
	broker := events.NewBroker()
	m := &jobs.Manager{DB: db, Events: broker}
	RegisterJobKinds(m, pc)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	upd := &updates.Service{Priv: pc, Jobs: m, DB: db, Dir: t.TempDir(), Notify: &notify.Center{DB: db, Events: broker}}
	srv := httptest.NewServer(New(Config{DB: db, Jobs: m, Events: broker, Priv: pc, Updates: upd, Insecure: true}))
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	env := &testEnv{srv: srv, db: db, broker: broker}
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	kid := env.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	called := func(prefix string) []string {
		mu.Lock()
		defer mu.Unlock()
		var out []string
		for _, c := range calls {
			if strings.HasPrefix(c, prefix) {
				out = append(out, c)
			}
		}
		return out
	}

	// Listing: anyone who may use the folder.
	var res priv.SnapshotsResult
	if code := admin.do("GET", "/api/v1/shares/backups/snapshots", nil, &res); code != 200 || len(res.Snapshots) != 1 {
		t.Fatalf("admin list = %d %+v", code, res)
	}
	if code := kid.do("GET", "/api/v1/shares/media/snapshots", nil, &res); code != 200 || res.Snapshots[0].Kind != "hourly" {
		t.Fatalf("kid list = %d %+v", code, res)
	}
	for _, id := range []string{"backups", "secret", "ghost"} {
		if code := kid.do("GET", "/api/v1/shares/"+id+"/snapshots", nil, nil); code != 404 {
			t.Errorf("kid listed %s: %d", id, code)
		}
	}
	if c := called("list"); len(c) != 2 || !strings.Contains(c[0], `"share":"backups"`) {
		t.Errorf("list calls = %v", c)
	}

	// Taking and deleting: administrators, as jobs, audited.
	if code := kid.do("POST", "/api/v1/shares/media/snapshots", map[string]string{}, nil); code != 403 {
		t.Errorf("kid took a snapshot: %d", code)
	}
	var e ErrorResponse
	if code := admin.do("POST", "/api/v1/shares/media/snapshots", map[string]string{"name": "hardyos-auto-hourly_2026-10-26-1300"}, &e); code != 400 {
		t.Errorf("reserved name = %d %+v", code, e)
	}
	var acc struct {
		Job struct {
			ID string `json:"id"`
		} `json:"job"`
	}
	if code := admin.do("POST", "/api/v1/shares/media/snapshots", map[string]string{"name": "before-cleanup"}, &acc); code != 202 {
		t.Fatalf("create = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job.ID); j["state"] != "succeeded" || j["kind"] != JobKindSnapshotsCreate {
		t.Fatalf("create job: %v", j)
	}
	if c := called("create"); len(c) != 1 || !strings.Contains(c[0], `"name":"before-cleanup"`) || !strings.Contains(c[0], `"share":"media"`) {
		t.Errorf("create calls = %v", c)
	}
	if code := admin.do("POST", "/api/v1/shares/ghost/snapshots", map[string]string{}, nil); code != 404 {
		t.Errorf("snapshot of a missing folder = %d", code)
	}

	if code := kid.do("DELETE", "/api/v1/shares/media/snapshots/before-cleanup", map[string]string{"confirm": "before-cleanup"}, nil); code != 403 {
		t.Errorf("kid deleted: %d", code)
	}
	if code := admin.do("DELETE", "/api/v1/shares/media/snapshots/before-cleanup", map[string]string{"confirm": "before"}, &e); code != 400 || e.Code != "confirm_required" {
		t.Errorf("delete without confirm = %d %+v", code, e)
	}
	if code := admin.do("DELETE", "/api/v1/shares/media/snapshots/before-cleanup", map[string]string{"confirm": "before-cleanup"}, &acc); code != 202 {
		t.Fatalf("delete = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job.ID); j["state"] != "succeeded" {
		t.Fatalf("delete job: %v", j)
	}
	if c := called("delete"); len(c) != 1 || !strings.Contains(c[0], `"confirm":"before-cleanup"`) || !strings.Contains(c[0], `"snapshot":"before-cleanup"`) {
		t.Errorf("delete calls = %v", c)
	}

	// NFS details for the dialog.
	var sn ShareNFS
	if code := admin.do("GET", "/api/v1/shares/media/nfs", nil, &sn); code != 200 || sn.UID != 31000 || !sn.Running || sn.Path != "/mnt/tank/shares/media" {
		t.Errorf("nfs = %d %+v", code, sn)
	}
	if code := kid.do("GET", "/api/v1/shares/media/nfs", nil, nil); code != 403 {
		t.Errorf("kid read NFS details: %d", code)
	}

	var audit []struct {
		Action string `json:"action"`
		Target string `json:"target"`
	}
	admin.do("GET", "/api/v1/audit?action=shares.snapshot", nil, &audit)
	got := map[string]string{}
	for _, a := range audit {
		got[a.Action] = a.Target
	}
	if got["shares.snapshot.create"] != "media@before-cleanup" || got["shares.snapshot.delete"] != "media@before-cleanup" {
		t.Errorf("audit = %+v", audit)
	}
}
