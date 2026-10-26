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
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/updates"
)

// stubDC is a root helper that pretends to be the domain controller.
type stubDC struct {
	mu     sync.Mutex
	cfg    *domain.Config
	calls  []string
	lastPW string
}

func (d *stubDC) register(ps *priv.Server) {
	rec := func(op string, raw json.RawMessage) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.calls = append(d.calls, op+" "+string(raw))
	}
	ps.Handle(priv.OpDomainStatus, func(ctx context.Context, raw json.RawMessage) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		return domain.Status{Available: true, Provisioned: d.cfg != nil, Config: d.cfg, Running: d.cfg != nil, Responding: d.cfg != nil}, nil
	})
	ps.Handle(priv.OpDomainProvision, func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a domain.ProvisionArgs
		_ = json.Unmarshal(raw, &a)
		d.mu.Lock()
		defer d.mu.Unlock()
		d.lastPW = a.AdminPassword
		d.cfg = &domain.Config{Domain: a.Domain, Realm: strings.ToUpper(a.Domain), NetBIOS: "HOME", Address: a.Address, Enabled: true}
		return d.cfg, nil
	})
	ps.Handle(priv.OpDomainDestroy, func(ctx context.Context, raw json.RawMessage) (any, error) {
		rec("destroy", raw)
		d.mu.Lock()
		defer d.mu.Unlock()
		d.cfg = nil
		return map[string]bool{"deleted": true}, nil
	})
	ps.Handle(priv.OpDomainUserCreate, func(ctx context.Context, raw json.RawMessage) (any, error) {
		rec("user.create", raw)
		var u domain.NewUser
		_ = json.Unmarshal(raw, &u)
		if u.Username == "taken" {
			return nil, priv.Errorf(priv.CodeBadArgs, "a user called taken already exists")
		}
		return domain.User{Username: u.Username, Enabled: true, Groups: []string{}}, nil
	})
	ps.Handle(priv.OpDomainUserPassword, func(ctx context.Context, raw json.RawMessage) (any, error) {
		rec("user.password", raw)
		var p domain.PasswordReset
		_ = json.Unmarshal(raw, &p)
		return domain.User{Username: p.Username, Enabled: true, Groups: []string{}}, nil
	})
	ps.Handle(priv.OpDomainUserDelete, func(ctx context.Context, raw json.RawMessage) (any, error) {
		rec("user.delete", raw)
		return map[string]bool{"deleted": true}, nil
	})
	ps.Handle(priv.OpDomainGroupUpdate, func(ctx context.Context, raw json.RawMessage) (any, error) {
		rec("group.update", raw)
		var g domain.GroupUpdate
		_ = json.Unmarshal(raw, &g)
		return domain.Group{Name: g.Name, Members: g.Add}, nil
	})
}

func TestDomainAPI(t *testing.T) {
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
	dc := &stubDC{}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	dc.register(ps)
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

	const pw = "Domain-Adm1n-Secret"
	var e ErrorResponse
	// Quick mistakes are caught before the job.
	if code := admin.do("POST", "/api/v1/domain", map[string]string{"domain": "hardy.local", "adminPassword": pw, "address": "192.168.1.20"}, &e); code != 400 {
		t.Fatalf(".local accepted: %d", code)
	}
	if code := admin.do("POST", "/api/v1/domain", map[string]string{"domain": "home.example.net", "adminPassword": "weak", "address": "192.168.1.20"}, &e); code != 400 {
		t.Fatalf("weak password accepted: %d", code)
	}

	var acc struct {
		Job struct {
			ID string `json:"id"`
		} `json:"job"`
	}
	if code := admin.do("POST", "/api/v1/domain", map[string]string{"domain": "Home.Example.net", "adminPassword": pw, "address": "192.168.1.20"}, &acc); code != 202 {
		t.Fatalf("provision = %d", code)
	}
	j := waitJobDone(t, admin, acc.Job.ID)
	if j["state"] != "succeeded" {
		t.Fatalf("provision job: %v", j)
	}
	if dc.lastPW != pw {
		t.Errorf("the root helper got password %q", dc.lastPW)
	}
	// The password is nowhere in the job history or the audit log.
	raw, _ := json.Marshal(j)
	var audit []map[string]any
	admin.do("GET", "/api/v1/audit?limit=50", nil, &audit)
	rawAudit, _ := json.Marshal(audit)
	if strings.Contains(string(raw), pw) || strings.Contains(string(rawAudit), pw) {
		t.Fatalf("password leaked: job %s audit %s", raw, rawAudit)
	}
	if !strings.Contains(string(raw), "home.example.net") {
		t.Errorf("job lacks the normalized domain: %s", raw)
	}

	// A second domain is refused.
	if code := admin.do("POST", "/api/v1/domain", map[string]string{"domain": "other.example.net", "adminPassword": pw, "address": "192.168.1.21"}, &e); code != 409 {
		t.Fatalf("second domain = %d", code)
	}

	// Users: created, errors passed through, passwords never recorded.
	var u domain.User
	if code := admin.do("POST", "/api/v1/domain/users", map[string]any{"username": "alice", "password": "Al1ce-Passw0rd!"}, &u); code != 201 || u.Username != "alice" {
		t.Fatalf("create user = %d %+v", code, u)
	}
	if code := admin.do("POST", "/api/v1/domain/users", map[string]any{"username": "taken", "password": "Al1ce-Passw0rd!"}, &e); code != 400 || !strings.Contains(e.Message, "already exists") {
		t.Fatalf("duplicate user = %d %+v", code, e)
	}
	if code := admin.do("POST", "/api/v1/domain/users/alice/password", map[string]any{"password": "N3w-Passw0rd!", "mustChangePassword": true}, &u); code != 200 {
		t.Fatalf("reset = %d", code)
	}
	if code := admin.do("PATCH", "/api/v1/domain/groups/Family", map[string]any{"add": []string{"alice"}}, nil); code != 200 {
		t.Fatalf("group update = %d", code)
	}
	if code := admin.do("DELETE", "/api/v1/domain/users/alice", nil, nil); code != 204 {
		t.Fatalf("delete user = %d", code)
	}
	admin.do("GET", "/api/v1/audit?limit=50", nil, &audit)
	rawAudit, _ = json.Marshal(audit)
	for _, want := range []string{"domain.provision", "domain.user.create", "domain.user.password", "domain.group.update", "domain.user.delete"} {
		if !strings.Contains(string(rawAudit), want) {
			t.Errorf("audit lacks %s", want)
		}
	}
	if strings.Contains(string(rawAudit), "Al1ce-Passw0rd!") || strings.Contains(string(rawAudit), "N3w-Passw0rd!") {
		t.Error("a user's password reached the audit log")
	}
	// The path names the user, whatever the body says.
	if !strings.Contains(strings.Join(dc.calls, "\n"), `user.password {"username":"alice"`) {
		t.Errorf("calls: %v", dc.calls)
	}

	// Deleting needs the domain's name.
	if code := admin.do("DELETE", "/api/v1/domain", map[string]string{"confirm": "home.example.org"}, &e); code != 400 || e.Code != "confirm_required" {
		t.Fatalf("delete without the name = %d %+v", code, e)
	}
	if code := admin.do("DELETE", "/api/v1/domain", map[string]string{"confirm": "HOME.example.net"}, &acc); code != 202 {
		t.Fatalf("delete = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job.ID); j["state"] != "succeeded" {
		t.Fatalf("delete job: %v", j)
	}

	// Regular users can't touch the domain.
	admin.do("POST", "/api/v1/users", map[string]any{"username": "kid", "password": "kidpassword1", "role": "user"}, nil)
	kid := env.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	if code := kid.do("GET", "/api/v1/domain", nil, nil); code != 403 {
		t.Errorf("regular user GET /domain = %d", code)
	}
}

func TestSecretBox(t *testing.T) {
	ref := jobSecrets.put("s3cret")
	if v, ok := jobSecrets.take(ref); !ok || v != "s3cret" {
		t.Fatal("take failed")
	}
	if _, ok := jobSecrets.take(ref); ok {
		t.Fatal("a secret could be read twice")
	}
	if _, ok := jobSecrets.take("nope"); ok {
		t.Fatal("unknown ref returned a secret")
	}
}
