package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

type testEnv struct {
	srv    *httptest.Server
	db     *store.DB
	broker *events.Broker
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	broker := events.NewBroker()

	// A real root helper on a temp socket, so the self-test job exercises the whole path.
	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	priv.RegisterBuiltins(ps)
	go func() { _ = ps.Serve(ctx, ln) }()
	pc := priv.NewClient(sock)

	m := &jobs.Manager{DB: db, Events: broker}
	RegisterJobKinds(m, pc)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(New(Config{DB: db, Jobs: m, Events: broker, Priv: pc, Insecure: true}))
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	return &testEnv{srv: srv, db: db, broker: broker}
}

// client is a browser-like client with its own cookie jar.
type client struct {
	t    *testing.T
	base string
	http *http.Client
}

func (e *testEnv) client(t *testing.T) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: e.srv.URL, http: &http.Client{Jar: jar, Timeout: 10 * time.Second}}
}

func (c *client) do(method, path string, body any, out any) int {
	c.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, r)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-HardyOS-Request", "1")
	res, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	if out != nil {
		_ = json.NewDecoder(res.Body).Decode(out)
	}
	return res.StatusCode
}

func TestSetupLoginAndUsers(t *testing.T) {
	env := newEnv(t)
	admin := env.client(t)

	var setup map[string]bool
	if code := admin.do("GET", "/api/v1/setup", nil, &setup); code != 200 || !setup["needsAdmin"] {
		t.Fatalf("setup status %d %v", code, setup)
	}
	// Signed-in endpoints need a session.
	if code := admin.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Fatalf("me before setup = %d", code)
	}
	var me map[string]any
	if code := admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, &me); code != 201 {
		t.Fatalf("setup admin = %d %v", code, me)
	}
	if me["breakGlass"] != true || me["role"] != "admin" {
		t.Fatalf("first admin = %v", me)
	}
	// Setup only works once.
	other := env.client(t)
	if code := other.do("POST", "/api/v1/setup/admin", map[string]string{"username": "evil", "password": "supersecret1"}, nil); code != 409 {
		t.Fatalf("second setup = %d", code)
	}
	// The setup call signed the admin in.
	if code := admin.do("GET", "/api/v1/auth/me", nil, &me); code != 200 || me["username"] != "cade" {
		t.Fatalf("me after setup = %d %v", code, me)
	}

	// Admin creates a regular user.
	var created map[string]any
	if code := admin.do("POST", "/api/v1/users", map[string]string{"username": "Kid", "password": "kidpassword1"}, &created); code != 201 {
		t.Fatalf("create user = %d %v", code, created)
	}
	if created["role"] != "user" || created["username"] != "kid" {
		t.Fatalf("created = %v", created)
	}
	if code := admin.do("POST", "/api/v1/users", map[string]string{"username": "x", "password": "short"}, nil); code != 400 {
		t.Fatalf("invalid user = %d", code)
	}

	// The regular user can sign in but can't use admin endpoints.
	kid := env.client(t)
	if code := kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil); code != 200 {
		t.Fatalf("kid login = %d", code)
	}
	if code := kid.do("GET", "/api/v1/users", nil, nil); code != 403 {
		t.Fatalf("kid list users = %d", code)
	}

	// Disabling the user ends their session.
	id := int(created["id"].(float64))
	if code := admin.do("PATCH", "/api/v1/users/"+itoa(id), map[string]bool{"disabled": true}, nil); code != 200 {
		t.Fatalf("disable = %d", code)
	}
	if code := kid.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Fatalf("disabled user still signed in: %d", code)
	}

	// The last admin can't delete themselves.
	if code := admin.do("DELETE", "/api/v1/users/"+itoa(int(me["id"].(float64))), nil, nil); code != 409 {
		t.Fatalf("delete last admin = %d", code)
	}

	// Logout ends the session.
	if code := admin.do("POST", "/api/v1/auth/logout", nil, nil); code != 204 {
		t.Fatalf("logout = %d", code)
	}
	if code := admin.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Fatalf("me after logout = %d", code)
	}
}

func TestCSRFProtection(t *testing.T) {
	env := newEnv(t)
	// No custom header.
	res, err := http.Post(env.srv.URL+"/api/v1/auth/login", "application/json", strings.NewReader(`{"username":"a","password":"b"}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("no header = %d, want 403", res.StatusCode)
	}
	// Header present but cross-site origin.
	req, _ := http.NewRequest("POST", env.srv.URL+"/api/v1/auth/login", strings.NewReader(`{"username":"a","password":"b"}`))
	req.Header.Set("X-HardyOS-Request", "1")
	req.Header.Set("Origin", "https://evil.example")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("cross-origin = %d, want 403", res.StatusCode)
	}
}

func TestLoginRateLimit(t *testing.T) {
	env := newEnv(t)
	c := env.client(t)
	c.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)

	attacker := env.client(t)
	for i := 0; i < 5; i++ {
		if code := attacker.do("POST", "/api/v1/auth/login", map[string]string{"username": "cade", "password": "wrong-password"}, nil); code != 401 {
			t.Fatalf("attempt %d = %d", i, code)
		}
	}
	if code := attacker.do("POST", "/api/v1/auth/login", map[string]string{"username": "cade", "password": "supersecret1"}, nil); code != 429 {
		t.Fatalf("after 5 failures = %d, want 429 even with the right password", code)
	}
}

func TestSelfTestJobAndEvents(t *testing.T) {
	env := newEnv(t)
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)

	// Open the event stream with the session cookie.
	u := strings.Replace(env.srv.URL, "http", "ws", 1) + "/api/v1/events"
	hdr := http.Header{}
	for _, ck := range admin.http.Jar.Cookies(mustURL(env.srv.URL)) {
		hdr.Add("Cookie", ck.Name+"="+ck.Value)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: hdr})
	if err != nil {
		t.Fatalf("dial events: %v", err)
	}
	defer ws.CloseNow()
	if _, msg, err := ws.Read(ctx); err != nil || !strings.Contains(string(msg), "hello") {
		t.Fatalf("hello: %s %v", msg, err)
	}

	var job map[string]any
	if code := admin.do("POST", "/api/v1/system/self-test", nil, &job); code != 202 {
		t.Fatalf("self-test = %d %v", code, job)
	}
	for {
		_, msg, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("waiting for job events: %v", err)
		}
		var e struct {
			Type string `json:"type"`
			Data struct {
				ID    string `json:"id"`
				State string `json:"state"`
				Error string `json:"error"`
			} `json:"data"`
		}
		_ = json.Unmarshal(msg, &e)
		if e.Type != "job.updated" || e.Data.ID != job["id"] {
			continue
		}
		if e.Data.State == "failed" {
			t.Fatalf("self-test failed: %s", e.Data.Error)
		}
		if e.Data.State == "succeeded" {
			break
		}
	}

	var entries []map[string]any
	if code := admin.do("GET", "/api/v1/audit?action=system.", nil, &entries); code != 200 || len(entries) != 1 {
		t.Fatalf("audit = %d %v", code, entries)
	}
}

func TestEventsRequireSignIn(t *testing.T) {
	env := newEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, res, err := websocket.Dial(ctx, strings.Replace(env.srv.URL, "http", "ws", 1)+"/api/v1/events", nil)
	if err == nil {
		t.Fatal("anonymous websocket accepted")
	}
	if res != nil && res.StatusCode != 401 {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}
}
