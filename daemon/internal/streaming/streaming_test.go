package streaming

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/ports"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// fakeSunshine answers like Sunshine's API (confighttp.cpp): Basic auth,
// JSON bodies, status fields.
type fakeSunshine struct {
	mu       sync.Mutex
	user     string
	pass     string
	pin      string
	devices  []map[string]any
	waiting  []map[string]string
	authSeen int
	paired   []string
	// config is sunshine.conf (key by key); restarts counts /api/restart.
	config   map[string]string
	restarts int
}

func (f *fakeSunshine) handler() http.Handler {
	mux := http.NewServeMux()
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			defer f.mu.Unlock()
			u, p, ok := r.BasicAuth()
			if ok {
				f.authSeen++
			}
			if !ok || u != f.user || p != f.pass {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.Header.Get("Origin") != "" || r.Header.Get("Referer") != "" {
				http.Error(w, `{"error":"Missing CSRF token"}`, http.StatusBadRequest)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /api/clients/list", auth(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"named_certs": f.devices, "status": true})
	}))
	mux.HandleFunc("GET /api/pin", auth(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"pairings": f.waiting})
	}))
	mux.HandleFunc("POST /api/pin", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "content type", http.StatusBadRequest)
			return
		}
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		ok := in["pin"] == f.pin && len(f.waiting) > 0 && in["pairing_id"] == f.waiting[0]["id"]
		if ok {
			f.paired = append(f.paired, in["name"])
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": ok})
	}))
	// Sunshine's settings: GET answers the file's keys with its own
	// fields; POST writes the file from exactly what it is given.
	mux.HandleFunc("GET /api/config", auth(func(w http.ResponseWriter, _ *http.Request) {
		out := map[string]any{"status": true, "platform": "windows", "version": "2026.914", "restart_supported": true}
		for k, v := range f.config {
			out[k] = v
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	mux.HandleFunc("POST /api/config", auth(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, `{"error":"not strings"}`, http.StatusBadRequest)
			return
		}
		f.config = in
		_ = json.NewEncoder(w).Encode(map[string]any{"status": true})
	}))
	mux.HandleFunc("POST /api/restart", auth(func(w http.ResponseWriter, _ *http.Request) {
		f.restarts++
		_ = json.NewEncoder(w).Encode(map[string]any{"status": true})
	}))
	mux.HandleFunc("POST /api/clients/unpair", auth(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		ok := false
		for i, d := range f.devices {
			if d["uuid"] == in["uuid"] {
				f.devices = append(f.devices[:i], f.devices[i+1:]...)
				ok = true
				break
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": ok})
	}))
	return mux
}

func newFake(t *testing.T) (*fakeSunshine, *httptest.Server, Target, *Client) {
	t.Helper()
	f := &fakeSunshine{user: "hardyos", pass: "Abcdefghijkmnopqrstuvw23", pin: "1234",
		devices: []map[string]any{{"name": "Living room TV", "uuid": "0123ABCD-0000-1111-2222-333344445555", "enabled": true}},
		waiting: []map[string]string{{"id": strings.Repeat("ab", 16), "name": "Steam Deck", "address": "192.168.1.30"}}}
	srv := httptest.NewTLSServer(f.handler())
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	return f, srv, Target{Address: "127.0.0.1", CertSHA256: hex.EncodeToString(sum[:]), User: f.user, Password: f.pass},
		&Client{AllowLoopback: true, Port: p}
}

func TestClient(t *testing.T) {
	f, _, tgt, c := newFake(t)
	ctx := context.Background()
	devs, err := c.Devices(ctx, tgt)
	if err != nil || len(devs) != 1 || devs[0].Name != "Living room TV" || !devs[0].Enabled {
		t.Fatalf("devices %+v %v", devs, err)
	}
	w, err := c.Waiting(ctx, tgt)
	if err != nil || len(w) != 1 || w[0].Name != "Steam Deck" {
		t.Fatalf("waiting %+v %v", w, err)
	}
	if err := c.Pair(ctx, tgt, w[0].ID, "9999", "Deck"); err == nil {
		t.Fatal("a wrong PIN paired")
	}
	if err := c.Pair(ctx, tgt, w[0].ID, "1234", "Deck"); err != nil {
		t.Fatal(err)
	}
	if len(f.paired) != 1 || f.paired[0] != "Deck" {
		t.Fatalf("paired %v", f.paired)
	}
	if err := c.Unpair(ctx, tgt, devs[0].UUID); err != nil {
		t.Fatal(err)
	}
	if err := c.Unpair(ctx, tgt, devs[0].UUID); err == nil {
		t.Fatal("unpaired twice")
	}
	bad := tgt
	bad.Password = "wrong"
	if _, err := c.Devices(ctx, bad); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong password: %v", err)
	}
	// Input never reaches Sunshine unchecked.
	for _, in := range [][3]string{{"xyz", "1234", "a"}, {w[0].ID, "12345", "a"}, {w[0].ID, "12a4", "a"}, {w[0].ID, "1234", ""}, {w[0].ID, "1234", "a\nb"}, {w[0].ID, "1234", strings.Repeat("a", 65)}} {
		if err := c.Pair(ctx, tgt, in[0], in[1], in[2]); err == nil {
			t.Errorf("pair %q accepted", in)
		}
	}
	if err := c.Unpair(ctx, tgt, "../../x"); err == nil {
		t.Error("bad uuid accepted")
	}
}

// A VM's Sunshine moves to its port set (decision 506): only `port`
// changes, every other setting is written back as it was (Sunshine writes
// its file from what it is given), its own answer fields aren't, and it
// restarts. Only HardyOS's port sets are accepted.
func TestClientBasePort(t *testing.T) {
	f, _, tg, c := newFake(t)
	ctx := context.Background()
	f.config = map[string]string{"sunshine_name": "game", "origin_web_ui_allowed": "lan", "pkey": "C:/x/hardyos-key.pem", "upnp": "disabled"}
	if b, err := c.BasePort(ctx, tg); err != nil || b != ports.SunshineHTTP {
		t.Fatalf("base %d %v", b, err)
	}
	if err := c.SetBasePort(ctx, tg, ports.StreamingSlot(3).Base); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"sunshine_name": "game", "origin_web_ui_allowed": "lan", "pkey": "C:/x/hardyos-key.pem", "upnp": "disabled",
		"port": strconv.Itoa(ports.StreamingSlot(3).Base)}
	if !reflect.DeepEqual(f.config, want) || f.restarts != 1 {
		t.Fatalf("settings %v restarts %d", f.config, f.restarts)
	}
	if b, _ := c.BasePort(ctx, tg); b != ports.StreamingSlot(3).Base {
		t.Fatalf("base after %d", b)
	}
	// Back to the standard set: the setting goes.
	if err := c.SetBasePort(ctx, tg, ports.SunshineHTTP); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.config["port"]; ok || f.config["upnp"] != "disabled" {
		t.Fatalf("settings %v", f.config)
	}
	for _, bad := range []int{ports.SunshineHTTP + 1, 22, ports.StreamingSlot(ports.StreamingSlots-1).Base + ports.StreamingSlotStride} {
		if err := c.SetBasePort(ctx, tg, bad); err == nil {
			t.Errorf("moved to %d", bad)
		}
	}
	// A setting with a line break would rewrite the file: refused.
	f.config = map[string]string{"sunshine_name": "a\nport = 22"}
	if err := c.SetBasePort(ctx, tg, ports.StreamingSlot(1).Base); err == nil {
		t.Fatal("a line break was written back")
	}
}

func TestClientPinsTheCertificate(t *testing.T) {
	f, _, tgt, c := newFake(t)
	ctx := context.Background()
	wrong := tgt
	wrong.CertSHA256 = strings.Repeat("00", 32)
	f.mu.Lock()
	f.authSeen = 0
	f.mu.Unlock()
	if _, err := c.Devices(ctx, wrong); !errors.Is(err, ErrPin) {
		t.Fatalf("wrong certificate: %v", err)
	}
	if err := c.Pair(ctx, wrong, strings.Repeat("ab", 16), "1234", "Deck"); !errors.Is(err, ErrPin) {
		t.Fatalf("pair with a wrong certificate: %v", err)
	}
	f.mu.Lock()
	seen := f.authSeen
	f.mu.Unlock()
	if seen != 0 {
		t.Fatal("the password was sent to a server with the wrong certificate")
	}
	// No pin, no call.
	none := tgt
	none.CertSHA256 = ""
	if _, err := c.Devices(ctx, none); err == nil {
		t.Fatal("called without a pin")
	}
	// Only home network addresses; loopback only in tests.
	for _, a := range []string{"8.8.8.8", "::1", "0.0.0.0", "100.64.1.1", "not-an-ip", "169.254.1.1"} {
		x := tgt
		x.Address = a
		if _, err := c.Devices(ctx, x); err == nil || errors.Is(err, ErrUnreachable) {
			t.Errorf("%s: %v", a, err)
		}
	}
	strict := &Client{Port: c.Port}
	if _, err := strict.Devices(ctx, tgt); err == nil {
		t.Fatal("loopback allowed outside tests")
	}
}

func TestStore(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Store{DB: db, Keys: secretbox.NewStaticSource()}
	if _, err := s.Get(ctx, "game"); !errors.Is(err, ErrNoAccount) {
		t.Fatal(err)
	}
	pw, err := NewPassword()
	if err != nil || len(pw) != 24 || strings.ContainsAny(pw, "'\" ;&") {
		t.Fatalf("password %q", pw)
	}
	if err := s.Save(ctx, "game", "hardyos", pw); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := db.QueryRowContext(ctx, `SELECT password_sealed FROM vm_streaming WHERE vm_id = 'game'`).Scan(&raw); err != nil || strings.Contains(string(raw), pw) {
		t.Fatal("the password is stored in the clear")
	}
	a, err := s.Get(ctx, "game")
	if err != nil || a.Password != pw || a.User != "hardyos" {
		t.Fatalf("%+v %v", a, err)
	}
	// Bound to its VM: moved to another row it doesn't open.
	if _, err := db.ExecContext(ctx, `INSERT INTO vm_streaming (vm_id, sunshine_user, password_sealed, created_at) VALUES ('other', 'hardyos', ?, '')`, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "other"); err == nil {
		t.Fatal("a sealed password opened in another row")
	}
	if ok, at := s.Has(ctx, "game"); !ok || at != "" {
		t.Fatal("has")
	}
	_ = s.Revealed(ctx, "game")
	if _, at := s.Has(ctx, "game"); at == "" {
		t.Fatal("revealed not recorded")
	}
	_ = s.Delete(ctx, "game")
	if ok, _ := s.Has(ctx, "game"); ok {
		t.Fatal("not deleted")
	}
}
