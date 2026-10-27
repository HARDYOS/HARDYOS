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

	"github.com/hardyos/hardyos/daemon/internal/domain"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/smb"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/updates"
)

func TestFileServicesAPI(t *testing.T) {
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
	var mu sync.Mutex
	st := smb.Status{Available: true, ServerName: "HARDYOS", Settings: smb.Settings{SMBEnabled: true}, Shares: []smb.ShareStatus{}, Addresses: []string{}}
	var joins []smb.JoinArgs
	var leaves []smb.LeaveArgs
	var dcCfg *domain.Config
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	ps.Handle(priv.OpFilesStatus, func(context.Context, json.RawMessage) (any, error) {
		mu.Lock()
		defer mu.Unlock()
		return st, nil
	})
	ps.Handle(priv.OpFilesJoin, func(_ context.Context, raw json.RawMessage) (any, error) {
		var a smb.JoinArgs
		_ = json.Unmarshal(raw, &a)
		mu.Lock()
		defer mu.Unlock()
		joins = append(joins, a)
		d := a.Domain
		if d == "" {
			d = st.LocalDomain
		}
		st.Joined, st.Domain = true, &smb.Domain{Domain: d, NetBIOS: "HOME", DCs: []string{"192.168.1.20"}, AdminsGroupSID: "S-1-5-21-1-2-3-4"}
		return st, nil
	})
	ps.Handle(priv.OpFilesLeave, func(_ context.Context, raw json.RawMessage) (any, error) {
		var a smb.LeaveArgs
		_ = json.Unmarshal(raw, &a)
		mu.Lock()
		defer mu.Unlock()
		leaves = append(leaves, a)
		st.Joined, st.Domain = false, nil
		return st, nil
	})
	ps.Handle(priv.OpFilesSettings, func(_ context.Context, raw json.RawMessage) (any, error) {
		var a smb.SettingsArgs
		_ = json.Unmarshal(raw, &a)
		mu.Lock()
		defer mu.Unlock()
		if a.SMBEnabled != nil {
			st.Settings.SMBEnabled = *a.SMBEnabled
		}
		if a.Homes != nil {
			st.Settings.Homes = *a.Homes
		}
		return st, nil
	})
	ps.Handle(priv.OpDomainStatus, func(context.Context, json.RawMessage) (any, error) {
		return domain.Status{Available: true, Provisioned: dcCfg != nil, Config: dcCfg}, nil
	})
	ps.Handle(priv.OpDomainProvision, func(_ context.Context, raw json.RawMessage) (any, error) {
		var a domain.ProvisionArgs
		_ = json.Unmarshal(raw, &a)
		dcCfg = &domain.Config{Domain: a.Domain, NetBIOS: "HOME"}
		mu.Lock()
		st.LocalDomain = a.Domain
		mu.Unlock()
		return dcCfg, nil
	})
	ps.Handle(priv.OpDomainDestroy, func(context.Context, json.RawMessage) (any, error) {
		dcCfg = nil
		return map[string]bool{"deleted": true}, nil
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
	var acc struct {
		Job struct {
			ID string `json:"id"`
		} `json:"job"`
	}
	var e ErrorResponse

	// Creating the domain on this server joins the file server with the
	// same password, inside the provision job.
	const pw = "Ci-Adm1n-Passw0rd!"
	if code := admin.do("POST", "/api/v1/domain", map[string]any{"domain": "home.example.net", "adminPassword": pw, "address": "192.168.1.20"}, &acc); code != 202 {
		t.Fatalf("provision = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job.ID); j["state"] != "succeeded" {
		t.Fatalf("provision job %v", j)
	}
	if len(joins) != 1 || joins[0].AdminPassword != pw || joins[0].Domain != "" {
		t.Fatalf("auto join: %+v", joins)
	}
	var got smb.Status
	admin.do("GET", "/api/v1/files", nil, &got)
	if !got.Joined || got.Domain.Domain != "home.example.net" {
		t.Fatalf("status %+v", got)
	}
	// Joining again is refused; leaving needs confirming.
	if code := admin.do("POST", "/api/v1/files/join", map[string]string{"adminPassword": pw}, &e); code != 409 {
		t.Errorf("second join = %d", code)
	}
	if code := admin.do("POST", "/api/v1/files/leave", map[string]any{}, &e); code != 400 || e.Code != "confirm_required" {
		t.Errorf("unconfirmed leave = %d %+v", code, e)
	}
	if code := admin.do("POST", "/api/v1/files/leave", map[string]any{"confirm": true, "adminPassword": pw}, &acc); code != 202 {
		t.Fatalf("leave = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job.ID); j["state"] != "succeeded" || leaves[0].AdminPassword != pw || !leaves[0].Confirm {
		t.Fatalf("leave job %v %+v", j, leaves)
	}
	// Join through File Services, by name.
	if code := admin.do("POST", "/api/v1/files/join", map[string]string{"domain": "bad domain"}, &e); code != 400 {
		t.Errorf("join without a password = %d", code)
	}
	if code := admin.do("POST", "/api/v1/files/join", map[string]string{"domain": "Home.Example.NET", "adminPassword": pw}, &acc); code != 202 {
		t.Fatalf("join = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job.ID); j["state"] != "succeeded" || joins[1].Domain != "home.example.net" {
		t.Fatalf("join job %v %+v", j, joins)
	}
	// Settings.
	if code := admin.do("PATCH", "/api/v1/files/settings", map[string]any{"homes": map[string]any{"enabled": true, "pool": ""}}, &e); code != 400 {
		t.Errorf("homes without a pool = %d", code)
	}
	if code := admin.do("PATCH", "/api/v1/files/settings", map[string]any{"smbEnabled": false, "homes": map[string]any{"enabled": true, "pool": "tank", "quotaBytes": 1 << 30}}, &acc); code != 202 {
		t.Fatalf("settings = %d", code)
	}
	waitJobDone(t, admin, acc.Job.ID)
	admin.do("GET", "/api/v1/files", nil, &got)
	if got.Settings.SMBEnabled || got.Settings.Homes.Pool != "tank" {
		t.Errorf("settings %+v", got.Settings)
	}
	// Family members see how to connect, not the settings.
	admin.do("POST", "/api/v1/users", map[string]any{"username": "kid", "password": "kidpassword1", "role": "user"}, nil)
	kid := env.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	var ks smb.Status
	if code := kid.do("GET", "/api/v1/files", nil, &ks); code != 200 || ks.Settings.Homes.Pool != "" || ks.Domain.AdminsGroupSID != "" || len(ks.Domain.DCs) != 0 {
		t.Errorf("family view %d %+v", code, ks)
	}
	if code := kid.do("PATCH", "/api/v1/files/settings", map[string]any{"smbEnabled": true}, &e); code != 403 {
		t.Errorf("family settings = %d", code)
	}
	// Deleting the domain makes the file server forget it.
	if code := admin.do("DELETE", "/api/v1/domain", map[string]string{"confirm": "home.example.net"}, &acc); code != 202 {
		t.Fatalf("destroy = %d", code)
	}
	waitJobDone(t, admin, acc.Job.ID)
	if len(leaves) != 2 || leaves[1].AdminPassword != "" || !leaves[1].Confirm {
		t.Errorf("leave after destroy: %+v", leaves)
	}
	// Never a password in job history or the audit log.
	var list []map[string]any
	admin.do("GET", "/api/v1/jobs?limit=50", nil, &list)
	var audit []map[string]any
	admin.do("GET", "/api/v1/audit?limit=100", nil, &audit)
	all, _ := json.Marshal([]any{list, audit})
	if strings.Contains(string(all), pw) {
		t.Fatal("a password reached job history or the audit log")
	}
	for _, want := range []string{"files.join", "files.leave", "files.settings"} {
		if !strings.Contains(string(all), want) {
			t.Errorf("audit lacks %s", want)
		}
	}
}
