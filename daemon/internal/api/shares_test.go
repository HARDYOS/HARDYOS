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

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/updates"
)

// stubShares is a root helper that keeps shared folders in memory.
type stubShares struct {
	mu     sync.Mutex
	shares []shares.Share
	calls  []string
}

func (d *stubShares) register(ps *priv.Server) {
	rec := func(op string, raw json.RawMessage) {
		d.calls = append(d.calls, op+" "+string(raw))
	}
	ps.Handle(priv.OpSharesList, func(context.Context, json.RawMessage) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		return priv.SharesResult{Shares: append([]shares.Share{}, d.shares...)}, nil
	})
	ps.Handle(priv.OpSharesCreate, func(_ context.Context, raw json.RawMessage) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		rec("create", raw)
		var a shares.NewShare
		_ = json.Unmarshal(raw, &a)
		sh := shares.Share{ID: a.ID, Name: a.Name, Pool: a.Pool, Dataset: a.Pool + "/shares/" + a.ID, Path: "/mnt/" + a.Pool + "/shares/" + a.ID,
			Mounted: true, QuotaBytes: a.QuotaBytes, Recycle: a.Recycle, Guest: a.Guest, Access: a.Access, Apps: []shares.AppGrant{}}
		d.shares = append(d.shares, sh)
		return sh, nil
	})
	ps.Handle(priv.OpSharesUpdate, func(_ context.Context, raw json.RawMessage) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		rec("update", raw)
		var a shares.ShareUpdate
		_ = json.Unmarshal(raw, &a)
		for i := range d.shares {
			if d.shares[i].ID == a.ID {
				if a.Name != nil {
					d.shares[i].Name = *a.Name
				}
				return d.shares[i], nil
			}
		}
		return nil, priv.Errorf(priv.CodeBadArgs, "%v", shares.ErrNotFound)
	})
	ps.Handle(priv.OpSharesDelete, func(_ context.Context, raw json.RawMessage) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		rec("delete", raw)
		var a priv.ShareDeleteArgs
		_ = json.Unmarshal(raw, &a)
		for i := range d.shares {
			if d.shares[i].ID == a.ID {
				d.shares = append(d.shares[:i], d.shares[i+1:]...)
				return map[string]bool{"deleted": true}, nil
			}
		}
		return nil, priv.Errorf(priv.CodeBadArgs, "%v", shares.ErrNotFound)
	})
	ps.Handle(priv.OpSharesStarter, func(_ context.Context, raw json.RawMessage) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		rec("starter", raw)
		sh := shares.Share{ID: "media", Name: "Media", Pool: "tank", Mounted: true, Access: []shares.Rule{}, Apps: []shares.AppGrant{}}
		d.shares = append(d.shares, sh)
		return priv.SharesResult{Shares: []shares.Share{sh}}, nil
	})
	ps.Handle(priv.OpSharesFolders, func(_ context.Context, raw json.RawMessage) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		rec("folders", raw)
		var a priv.ShareFoldersArgs
		_ = json.Unmarshal(raw, &a)
		if a.ID != "media" {
			return nil, priv.Errorf(priv.CodeBadArgs, "%v", shares.ErrNotFound)
		}
		if a.Path == "../etc" {
			return nil, priv.Errorf(priv.CodeBadArgs, "the folder path isn't valid")
		}
		return priv.ShareFoldersResult{Folders: []string{"Movies", "TV"}}, nil
	})
}

func (d *stubShares) called(prefix string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for _, c := range d.calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

func TestSharesAPI(t *testing.T) {
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
	stub := &stubShares{}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	stub.register(ps)
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

	var list priv.SharesResult
	if code := admin.do("GET", "/api/v1/shares", nil, &list); code != 200 || list.Shares == nil || len(list.Shares) != 0 {
		t.Fatalf("empty list = %d %+v", code, list)
	}

	// Quick mistakes are caught before the job.
	var e ErrorResponse
	for _, bad := range []map[string]any{
		{"pool": "tank", "name": ""},
		{"pool": "", "name": "Media"},
		{"pool": "tank", "name": "Media", "id": "Media!"},
		{"pool": "tank", "name": "Media", "access": []map[string]string{{"kind": "robot", "level": "read"}}},
	} {
		if code := admin.do("POST", "/api/v1/shares", bad, &e); code != 400 {
			t.Errorf("POST %v = %d %+v", bad, code, e)
		}
	}
	if code := kid.do("POST", "/api/v1/shares", map[string]any{"pool": "tank", "name": "Kid Stuff"}, nil); code != 403 {
		t.Fatalf("a family member created a share: %d", code)
	}

	// Create runs as a job and is audited.
	var acc struct {
		Job struct {
			ID string `json:"id"`
		} `json:"job"`
	}
	req := map[string]any{"pool": "tank", "name": "  Family Photos ", "quotaBytes": 5 << 30, "recycle": true,
		"access": []map[string]string{{"kind": "group", "name": `HOME\Family`, "level": "write"}, {"kind": "everyone", "level": "read"}}}
	if code := admin.do("POST", "/api/v1/shares", req, &acc); code != 202 {
		t.Fatalf("create = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job.ID); j["state"] != "succeeded" || j["kind"] != JobKindSharesCreate {
		t.Fatalf("create job: %v", j)
	}
	if c := stub.called("create"); len(c) != 1 || !strings.Contains(c[0], `"id":"family-photos"`) || !strings.Contains(c[0], `"name":"Family Photos"`) {
		t.Fatalf("create sent %v", c)
	}
	var sh shares.Share
	if code := admin.do("GET", "/api/v1/shares/family-photos", nil, &sh); code != 200 || sh.Name != "Family Photos" || len(sh.Access) != 2 {
		t.Fatalf("get = %d %+v", code, sh)
	}
	if code := admin.do("POST", "/api/v1/shares", map[string]any{"pool": "tank", "name": "family photos", "id": "other"}, &e); code != 409 {
		t.Errorf("duplicate name = %d", code)
	}

	// Family members see the folders, not who may use them.
	if code := kid.do("GET", "/api/v1/shares", nil, &list); code != 200 || len(list.Shares) != 1 || len(list.Shares[0].Access) != 0 || list.Shares[0].Dataset != "" {
		t.Fatalf("family view = %d %+v", code, list)
	}
	if code := kid.do("GET", "/api/v1/shares/family-photos/folders", nil, nil); code != 403 {
		t.Errorf("family member browsed folders: %d", code)
	}

	// Update.
	if code := admin.do("PATCH", "/api/v1/shares/family-photos", map[string]any{"name": "Photos", "guest": true}, &acc); code != 202 {
		t.Fatalf("update = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job.ID); j["state"] != "succeeded" {
		t.Fatalf("update job: %v", j)
	}
	if c := stub.called("update"); len(c) != 1 || !strings.Contains(c[0], `"id":"family-photos"`) || !strings.Contains(c[0], `"guest":true`) {
		t.Fatalf("update sent %v", c)
	}
	if code := admin.do("PATCH", "/api/v1/shares/ghost", map[string]any{"guest": true}, nil); code != 404 {
		t.Errorf("update a missing share = %d", code)
	}
	if code := admin.do("PATCH", "/api/v1/shares/family-photos", map[string]any{"name": "a/b"}, nil); code != 400 {
		t.Errorf("bad name = %d", code)
	}

	// Delete needs the name, and not while an app uses it.
	if code := admin.do("DELETE", "/api/v1/shares/family-photos", map[string]string{"confirm": "Family Photos"}, &e); code != 400 || e.Code != "confirm_required" {
		t.Fatalf("delete with the old name = %d %+v", code, e)
	}
	stub.mu.Lock()
	stub.shares[0].Apps = []shares.AppGrant{{App: "immich", UID: 30001, Level: "write"}}
	stub.mu.Unlock()
	if code := admin.do("DELETE", "/api/v1/shares/family-photos", map[string]string{"confirm": "photos"}, &e); code != 409 || !strings.Contains(e.Message, "immich") {
		t.Fatalf("delete while used = %d %+v", code, e)
	}
	stub.mu.Lock()
	stub.shares[0].Apps = []shares.AppGrant{}
	stub.mu.Unlock()
	if code := admin.do("DELETE", "/api/v1/shares/family-photos", map[string]string{"confirm": "photos"}, &acc); code != 202 {
		t.Fatalf("delete = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job.ID); j["state"] != "succeeded" {
		t.Fatalf("delete job: %v", j)
	}
	if c := stub.called("delete"); len(c) != 1 || !strings.Contains(c[0], `"confirm":"Photos"`) {
		t.Fatalf("delete sent %v", c)
	}

	// Starter set.
	if code := admin.do("POST", "/api/v1/shares/starter", map[string]any{"pool": "tank"}, &e); code != 400 {
		t.Errorf("starter with nothing chosen = %d", code)
	}
	if code := admin.do("POST", "/api/v1/shares/starter", map[string]any{"pool": "tank", "media": true, "backups": true}, &acc); code != 202 {
		t.Fatalf("starter = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job.ID); j["state"] != "succeeded" {
		t.Fatalf("starter job: %v", j)
	}

	// Folders for pickers.
	var folders priv.ShareFoldersResult
	if code := admin.do("GET", "/api/v1/shares/media/folders?path=", nil, &folders); code != 200 || len(folders.Folders) != 2 {
		t.Fatalf("folders = %d %+v", code, folders)
	}
	if code := admin.do("GET", "/api/v1/shares/ghost/folders", nil, nil); code != 404 {
		t.Errorf("folders of a missing share = %d", code)
	}
	if code := admin.do("GET", "/api/v1/shares/media/folders?path=../etc", nil, nil); code != 400 {
		t.Errorf("folders outside = %d", code)
	}

	var audit []struct {
		Action string `json:"action"`
		Target string `json:"target"`
	}
	admin.do("GET", "/api/v1/audit?action=shares.", nil, &audit)
	got := map[string]bool{}
	for _, a := range audit {
		got[a.Action] = true
	}
	for _, want := range []string{"shares.create", "shares.update", "shares.delete", "shares.starter"} {
		if !got[want] {
			t.Errorf("no audit entry for %s: %+v", want, audit)
		}
	}
}
