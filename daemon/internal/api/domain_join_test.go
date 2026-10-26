package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/domain"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/updates"
)

func TestDomainJoinLeaveAPI(t *testing.T) {
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
	var cfg *domain.Config
	var gotJoinPW, gotLeavePW string
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	ps.Handle(priv.OpDomainStatus, func(context.Context, json.RawMessage) (any, error) {
		return domain.Status{Available: true, Provisioned: cfg != nil, Config: cfg, Running: cfg != nil, Responding: cfg != nil}, nil
	})
	ps.Handle(priv.OpDomainJoin, func(_ context.Context, raw json.RawMessage) (any, error) {
		var a domain.JoinArgs
		_ = json.Unmarshal(raw, &a)
		gotJoinPW = a.AdminPassword
		cfg = &domain.Config{Domain: a.Domain, DCName: "dc2." + a.Domain, Host: "dc2", Address: a.Address, Joined: true,
			Others: []domain.DC{{Name: "dc1." + a.Domain, Address: a.Existing}}}
		return cfg, nil
	})
	ps.Handle(priv.OpDomainLeave, func(_ context.Context, raw json.RawMessage) (any, error) {
		var a priv.DomainLeaveArgs
		_ = json.Unmarshal(raw, &a)
		gotLeavePW = a.AdminPassword
		cfg = nil
		return map[string]bool{"left": true}, nil
	})
	ps.Handle(priv.OpDomainForwarders, func(_ context.Context, raw json.RawMessage) (any, error) {
		var a priv.DomainForwardersArgs
		_ = json.Unmarshal(raw, &a)
		cfg.Forwarders = a.Forwarders
		return domain.Status{Available: true, Provisioned: true, Config: cfg}, nil
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

	const pw = "Join-Adm1n-Secret"
	var acc struct {
		Job struct {
			ID string `json:"id"`
		} `json:"job"`
	}
	var e ErrorResponse
	if code := admin.do("POST", "/api/v1/domain/join", map[string]string{"domain": "home.example.net", "existing": "192.168.1.20", "address": "192.168.1.21"}, &e); code != 400 {
		t.Fatalf("join without a password = %d", code)
	}
	if code := admin.do("POST", "/api/v1/domain/join", map[string]string{"domain": "Home.Example.net", "existing": "192.168.1.20", "address": "192.168.1.21", "adminPassword": pw}, &acc); code != 202 {
		t.Fatalf("join = %d", code)
	}
	j := waitJobDone(t, admin, acc.Job.ID)
	if j["state"] != "succeeded" || gotJoinPW != pw {
		t.Fatalf("join job %v, password %q", j, gotJoinPW)
	}
	var st domain.Status
	admin.do("GET", "/api/v1/domain", nil, &st)
	if st.Config == nil || st.Config.Host != "dc2" || len(st.Config.Others) != 1 {
		t.Fatalf("status = %+v", st)
	}
	if code := admin.do("PUT", "/api/v1/domain/forwarders", map[string]any{"forwarders": []string{"9.9.9.9"}}, &st); code != 200 || st.Config.Forwarders[0] != "9.9.9.9" {
		t.Fatalf("forwarders = %d %+v", code, st.Config)
	}
	// Removing a DC that isn't listed, or without typing its name, is refused.
	if code := admin.do("POST", "/api/v1/domain/controllers/remove", map[string]string{"name": "dc9.home.example.net", "confirm": "dc9.home.example.net"}, &e); code != 400 {
		t.Errorf("unknown DC = %d", code)
	}
	if code := admin.do("POST", "/api/v1/domain/controllers/remove", map[string]string{"name": "dc1.home.example.net", "confirm": "dc1"}, &e); code != 400 || e.Code != "confirm_required" {
		t.Errorf("unconfirmed = %d %+v", code, e)
	}
	if code := admin.do("POST", "/api/v1/domain/leave", map[string]string{"adminPassword": pw}, &acc); code != 202 {
		t.Fatalf("leave = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job.ID); j["state"] != "succeeded" || gotLeavePW != pw {
		t.Fatalf("leave job %v, password %q", j, gotLeavePW)
	}
	// No password anywhere it's kept.
	var list []map[string]any
	admin.do("GET", "/api/v1/jobs?limit=20", nil, &list)
	var audit []map[string]any
	admin.do("GET", "/api/v1/audit?limit=50", nil, &audit)
	all, _ := json.Marshal([]any{list, audit})
	if strings.Contains(string(all), pw) {
		t.Fatal("a domain password reached job history or the audit log")
	}
	for _, want := range []string{"domain.join", "domain.forwarders", "domain.leave"} {
		if !strings.Contains(string(all), want) {
			t.Errorf("audit lacks %s", want)
		}
	}
}
