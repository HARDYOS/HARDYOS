package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/streaming"
	"github.com/hardyos/hardyos/daemon/internal/updates"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// apiSunshine is a fake Sunshine for the API tests.
type apiSunshine struct {
	mu     sync.Mutex
	pass   string // learned from the create call
	pins   []string
	unpair []string
}

func (f *apiSunshine) serve(t *testing.T) (*httptest.Server, string, int) {
	mux := http.NewServeMux()
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			defer f.mu.Unlock()
			u, p, ok := r.BasicAuth()
			if !ok || u != vms.SunshineUser || p == "" || p != f.pass {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /api/clients/list", auth(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"named_certs":[{"name":"TV","uuid":"0123ABCD-0000-1111-2222-333344445555"}],"status":true}`))
	}))
	mux.HandleFunc("GET /api/pin", auth(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"pairings":[{"id":"` + strings.Repeat("cd", 16) + `","name":"Deck","address":"192.168.1.30"}]}`))
	}))
	mux.HandleFunc("POST /api/pin", auth(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.pins = append(f.pins, in["pairing_id"]+"/"+in["pin"]+"/"+in["name"])
		_, _ = w.Write([]byte(`{"status":true}`))
	}))
	mux.HandleFunc("POST /api/clients/unpair", auth(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.unpair = append(f.unpair, in["uuid"])
		_, _ = w.Write([]byte(`{"status":true}`))
	}))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	return srv, hex.EncodeToString(sum[:]), p
}

func newStreamEnv(t *testing.T) (*testEnv, *stubVMs, *apiSunshine) {
	t.Helper()
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
	sun := &apiSunshine{}
	_, pin, port := sun.serve(t)
	stub := &stubVMs{vms: map[string]*vms.VM{}, tokens: map[string]string{}}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	stub.register(ps)
	ps.Handle(priv.OpVMsStreamingInfo, func(_ context.Context, raw json.RawMessage) (any, error) {
		stub.rec(priv.OpVMsStreamingInfo, raw)
		return vms.StreamingInfo{Address: "127.0.0.1", User: vms.SunshineUser, CertSHA256: pin, NetBirdAddress: "100.92.1.2"}, nil
	})
	ps.Handle(priv.OpVMsStreamingPublish, func(_ context.Context, raw json.RawMessage) (any, error) {
		stub.rec(priv.OpVMsStreamingPublish, raw)
		var a vms.StreamingPublishArgs
		_ = json.Unmarshal(raw, &a)
		stub.mu.Lock()
		defer stub.mu.Unlock()
		v := stub.vms[a.ID]
		v.Streaming.Remote = a.Enabled
		c := *v
		return &c, nil
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
	srv := httptest.NewServer(New(Config{DB: db, Jobs: m, Events: broker, Priv: pc, Insecure: true, Updates: upd,
		StreamingClient: &streaming.Client{AllowLoopback: true, Port: port}}))
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	return &testEnv{srv: srv, db: db, broker: broker}, stub, sun
}

func gamingRequest() VMCreateRequest {
	return VMCreateRequest{Spec: vms.Spec{ID: "game", Name: "Game", Template: "gaming", OS: "windows", Pool: "tank",
		CPU: vms.CPU{Cores: 8, Threads: 2}, Memory: vms.Memory{MB: 16384}, Disks: []vms.Disk{{Name: "disk0", SizeGB: 256}},
		Media:     []vms.Media{{Kind: vms.MediaISO, ISO: "Win11.iso"}, {Kind: vms.MediaVirtio}, {Kind: vms.MediaUnattend}, {Kind: vms.MediaStreaming}},
		NICs:      []vms.NIC{{Mode: vms.NICBridge}},
		Unattend:  &vms.Unattend{User: "cade", Locale: "en-US"},
		Streaming: &vms.Streaming{Sunshine: true}},
		Password: "Windows pass 1"}
}

type jobAccepted struct {
	Job struct {
		ID     string          `json:"id"`
		Params json.RawMessage `json:"params"`
	} `json:"job"`
}

func TestVMStreamingAPI(t *testing.T) {
	env, stub, sun := newStreamEnv(t)
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	kid := env.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)

	// Create: the downloads are fetched by name, the Sunshine password is
	// made in the job and reaches root only in the create call.
	var acc jobAccepted
	if code := admin.do("POST", "/api/v1/vms", gamingRequest(), &acc); code != 202 {
		t.Fatalf("create = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job.ID); j["state"] != "succeeded" {
		t.Fatalf("create job: %v", j)
	}
	fetches := strings.Join(stub.called(priv.OpVMsCatalogFetch), "\n")
	if !strings.Contains(fetches, `"image":"sunshine"`) || !strings.Contains(fetches, `"image":"virtual-display"`) {
		t.Fatalf("fetches: %s", fetches)
	}
	creates := stub.called(priv.OpVMsCreate)
	if len(creates) != 1 {
		t.Fatalf("creates %v", creates)
	}
	var ca vms.CreateArgs
	_ = json.Unmarshal([]byte(strings.TrimPrefix(creates[0], priv.OpVMsCreate+" ")), &ca)
	if len(ca.StreamingPassword) != 24 {
		t.Fatalf("streaming password %q", ca.StreamingPassword)
	}
	pw := ca.StreamingPassword
	sun.mu.Lock()
	sun.pass = pw
	sun.mu.Unlock()
	// Root sets the streaming settings it keeps; the stub keeps them as sent.
	stub.mu.Lock()
	stub.vms["game"].Streaming = &vms.Streaming{Sunshine: true, User: vms.SunshineUser, CertSHA256: strings.Repeat("a", 64)}
	stub.vms["game"].State = "running"
	stub.mu.Unlock()
	var params string
	_ = env.db.QueryRow(`SELECT params FROM jobs WHERE id = ?`, acc.Job.ID).Scan(&params)
	var sealed []byte
	_ = env.db.QueryRow(`SELECT password_sealed FROM vm_streaming WHERE vm_id = 'game'`).Scan(&sealed)
	if strings.Contains(params, pw) || len(sealed) == 0 || strings.Contains(string(sealed), pw) {
		t.Fatalf("password stored badly: params %s sealed %d", params, len(sealed))
	}

	// Family members can't see or change any of it.
	for _, c := range []struct{ m, p string }{
		{"GET", "/api/v1/vms/game/streaming"}, {"POST", "/api/v1/vms/game/streaming/reveal"},
		{"POST", "/api/v1/vms/game/streaming/pair"}, {"POST", "/api/v1/vms/game/streaming/unpair"}, {"PUT", "/api/v1/vms/game/streaming/remote"},
	} {
		if code := kid.do(c.m, c.p, map[string]any{"password": "kidpassword1", "pairingId": strings.Repeat("cd", 16), "pin": "1234", "name": "x", "uuid": "0123ABCD-0000-1111-2222-333344445555", "enabled": true}, nil); code != 403 {
			t.Errorf("kid %s %s = %d", c.m, c.p, code)
		}
	}

	// Status: reached through the pinned certificate with the account.
	var st VMStreamingStatus
	if code := admin.do("GET", "/api/v1/vms/game/streaming", nil, &st); code != 200 {
		t.Fatalf("status = %d", code)
	}
	if !st.SetUp || !st.Reachable || len(st.Devices) != 1 || len(st.Waiting) != 1 || st.Address != "127.0.0.1" || !st.AccountKept || st.NetBird != "100.92.1.2" {
		t.Fatalf("status = %+v", st)
	}
	if strings.Contains(stub.called(priv.OpVMsStreamingInfo)[0], pw) {
		t.Fatal("the password went to root")
	}

	// Reveal: the admin's own password first; audited either way.
	if code := admin.do("POST", "/api/v1/vms/game/streaming/reveal", VMStreamingRevealRequest{Password: "wrong"}, nil); code != 401 {
		t.Fatalf("reveal with a wrong password = %d", code)
	}
	var shown VMStreamingAccount
	if code := admin.do("POST", "/api/v1/vms/game/streaming/reveal", VMStreamingRevealRequest{Password: "supersecret1"}, &shown); code != 200 || shown.Password != pw || shown.User != vms.SunshineUser {
		t.Fatalf("reveal = %d %+v", code, shown)
	}
	var n int
	_ = env.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'vms.streaming.reveal'`).Scan(&n)
	if n != 2 {
		t.Fatalf("reveal audit rows = %d", n)
	}
	_ = env.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE detail LIKE ?`, "%"+pw+"%").Scan(&n)
	if n != 0 {
		t.Fatal("the password is in the audit log")
	}

	// Pair: checked here, the PIN kept out of the job's parameters.
	if code := admin.do("POST", "/api/v1/vms/game/streaming/pair", VMStreamingPairRequest{PairingID: "x", PIN: "1234", Name: "Deck"}, nil); code != 400 {
		t.Fatalf("bad pairing id = %d", code)
	}
	if code := admin.do("POST", "/api/v1/vms/game/streaming/pair", VMStreamingPairRequest{PairingID: strings.Repeat("cd", 16), PIN: "12345", Name: "Deck"}, nil); code != 400 {
		t.Fatalf("bad pin = %d", code)
	}
	if code := admin.do("POST", "/api/v1/vms/game/streaming/pair", VMStreamingPairRequest{PairingID: strings.Repeat("cd", 16), PIN: "4821", Name: "Steam Deck"}, &acc); code != 202 {
		t.Fatalf("pair = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job.ID); j["state"] != "succeeded" {
		t.Fatalf("pair job: %v", j)
	}
	_ = env.db.QueryRow(`SELECT params FROM jobs WHERE id = ?`, acc.Job.ID).Scan(&params)
	if strings.Contains(params, "4821") || strings.Contains(string(acc.Job.Params), "4821") {
		t.Fatalf("the PIN is in the job: %s", params)
	}
	sun.mu.Lock()
	pins := strings.Join(sun.pins, ",")
	sun.mu.Unlock()
	if pins != strings.Repeat("cd", 16)+"/4821/Steam Deck" {
		t.Fatalf("Sunshine got %s", pins)
	}
	_ = env.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'vms.streaming.pair' AND target LIKE 'game%'`).Scan(&n)
	if n == 0 {
		t.Fatal("pairing isn't audited")
	}

	// Unpair.
	if code := admin.do("POST", "/api/v1/vms/game/streaming/unpair", VMStreamingUnpairRequest{UUID: "../x"}, nil); code != 400 {
		t.Fatalf("bad uuid = %d", code)
	}
	if code := admin.do("POST", "/api/v1/vms/game/streaming/unpair", VMStreamingUnpairRequest{UUID: "0123ABCD-0000-1111-2222-333344445555"}, &acc); code != 202 {
		t.Fatalf("unpair = %d", code)
	}
	waitJobDone(t, admin, acc.Job.ID)
	sun.mu.Lock()
	if len(sun.unpair) != 1 {
		t.Fatalf("unpaired %v", sun.unpair)
	}
	sun.mu.Unlock()

	// NetBird publishing goes to root's op.
	if code := admin.do("PUT", "/api/v1/vms/game/streaming/remote", VMStreamingRemoteRequest{Enabled: true}, &acc); code != 202 {
		t.Fatalf("remote = %d", code)
	}
	waitJobDone(t, admin, acc.Job.ID)
	if c := stub.called(priv.OpVMsStreamingPublish); len(c) != 1 || !strings.Contains(c[0], `"enabled":true`) {
		t.Fatalf("publish calls %v", c)
	}

	// A VM without HardyOS's streaming has only the manual guidance.
	stub.mu.Lock()
	stub.vms["plain"] = &vms.VM{Spec: vms.Spec{ID: "plain", Name: "Plain", OS: "windows"}, State: "running"}
	stub.mu.Unlock()
	if code := admin.do("GET", "/api/v1/vms/plain/streaming", nil, &st); code != 200 || st.SetUp {
		t.Fatalf("plain = %d %+v", code, st)
	}
	if code := admin.do("POST", "/api/v1/vms/plain/streaming/pair", VMStreamingPairRequest{PairingID: strings.Repeat("cd", 16), PIN: "1234", Name: "x"}, nil); code != 409 {
		t.Fatalf("pair on plain = %d", code)
	}

	// Deleting the VM forgets the account.
	stub.mu.Lock()
	stub.vms["game"].State = "stopped"
	stub.mu.Unlock()
	if code := admin.do("DELETE", "/api/v1/vms/game", VMDeleteRequest{Confirm: "game"}, &acc); code != 202 {
		t.Fatalf("delete = %d", code)
	}
	waitJobDone(t, admin, acc.Job.ID)
	_ = env.db.QueryRow(`SELECT COUNT(*) FROM vm_streaming`).Scan(&n)
	if n != 0 {
		t.Fatal("the account outlived its VM")
	}
}
