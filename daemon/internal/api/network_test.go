package api

import (
	"context"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/network"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/updates"
)

// newNetworkEnv runs the real network manager (on a temp root with a fake
// command runner) behind a real hardyd-priv socket.
func newNetworkEnv(t *testing.T) (*testEnv, string, *sysexec.Fake) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for path, content := range map[string]string{
		"etc/network/interfaces":            "auto lo\niface lo inet loopback\n\nallow-hotplug ens33\niface ens33 inet dhcp\n",
		"etc/hostname":                      "hardyos\n",
		"etc/resolv.conf":                   "nameserver 192.168.252.2\n",
		"usr/share/zoneinfo/America/Denver": "TZif",
		"usr/share/zoneinfo/Etc/UTC":        "TZif",
	} {
		p := filepath.Join(root, path)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fake := &sysexec.Fake{}
	for _, p := range []string{"ifdown ", "ifup ", "ifquery ", "hostname ", "systemctl ", "chronyc "} {
		fake.OnPrefix(p, sysexec.Result{})
	}
	fake.OnPrefix("ip -j -d addr", sysexec.Result{Stdout: []byte(`[{"ifname":"ens33","flags":["BROADCAST","UP","LOWER_UP"],"address":"00:0c:29:aa:bb:cc","addr_info":[{"local":"192.168.252.128","prefixlen":24,"scope":"global"}]}]`)})
	fake.OnPrefix("ip -j route", sysexec.Result{Stdout: []byte(`[{"gateway":"192.168.252.2"}]`)})
	mgr := &network.Manager{Runner: fake, Root: root, Ports: func() []string { return []string{"ens33"} }}

	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	priv.RegisterNetwork(ps, mgr)
	go func() { _ = ps.Serve(ctx, ln) }()
	pc := priv.NewClient(sock)
	broker := events.NewBroker()
	m := &jobs.Manager{DB: db, Events: broker}
	RegisterJobKinds(m, pc)
	upd := &updates.Service{Priv: pc, Jobs: m, DB: db, Dir: t.TempDir(), Notify: &notify.Center{DB: db, Events: broker}}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Config{DB: db, Jobs: m, Events: broker, Priv: pc, Updates: upd, Insecure: true}))
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	return &testEnv{srv: srv, db: db, broker: broker}, root, fake
}

func TestNetworkAPI(t *testing.T) {
	env, root, _ := newNetworkEnv(t)
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)

	var st network.Status
	if code := admin.do("GET", "/api/v1/network", nil, &st); code != 200 {
		t.Fatalf("status = %d", code)
	}
	if st.Config.Hostname != "hardyos" || len(st.Config.Interfaces) != 1 || st.Config.Interfaces[0].Mode != network.ModeDHCP {
		t.Fatalf("imported config = %+v", st.Config)
	}
	if len(st.Live) != 1 || st.Live[0].Addresses[0] != "192.168.252.128/24" || st.Gateway != "192.168.252.2" {
		t.Fatalf("live = %+v gw %q", st.Live, st.Gateway)
	}

	// Every problem comes back at once.
	bad := st.Config
	bad.Hostname = "Bad Name"
	bad.Interfaces = []network.Interface{{Name: "ens33", Addressing: network.Addressing{Mode: network.ModeStatic, Address: "192.168.252.0/24"}}}
	var e ErrorResponse
	if code := admin.do("PUT", "/api/v1/network", bad, &e); code != 400 || len(e.Details) < 2 {
		t.Fatalf("bad settings = %d %+v", code, e)
	}

	good := st.Config
	good.Hostname = "nas"
	good.Interfaces = []network.Interface{{Name: "ens33", Addressing: network.Addressing{Mode: network.ModeStatic, Address: "192.168.252.50/24", Gateway: "192.168.252.2"}}}
	good.DNS = []string{"192.168.252.2"}
	var acc struct {
		Job map[string]any `json:"job"`
	}
	if code := admin.do("PUT", "/api/v1/network", good, &acc); code != 202 {
		t.Fatalf("apply = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job["id"].(string)); j["state"] != "succeeded" {
		t.Fatalf("apply job = %v", j)
	}
	b, _ := os.ReadFile(filepath.Join(root, "etc/network/interfaces"))
	if !strings.Contains(string(b), "address 192.168.252.50/24") {
		t.Fatalf("interfaces:\n%s", b)
	}
	admin.do("GET", "/api/v1/network", nil, &st)
	if st.Pending == nil || st.Pending.Addresses[0] != "192.168.252.50" {
		t.Fatalf("pending = %+v", st.Pending)
	}
	// Another change has to wait.
	if code := admin.do("PUT", "/api/v1/network", good, &e); code != 409 {
		t.Fatalf("second apply = %d", code)
	}
	if code := admin.do("POST", "/api/v1/network/confirm", nil, nil); code != 200 {
		t.Fatalf("confirm = %d", code)
	}
	admin.do("GET", "/api/v1/network", nil, &st)
	if st.Pending != nil || st.Config.Hostname != "nas" {
		t.Fatalf("after confirm = %+v", st)
	}
	if code := admin.do("POST", "/api/v1/network/revert", nil, &e); code != 400 {
		t.Fatalf("revert with nothing pending = %d", code)
	}

	// Date and time.
	var ts network.TimeStatus
	if code := admin.do("PUT", "/api/v1/system/time", network.TimeConfig{Timezone: "America/Denver", NTP: true, NTPServers: []string{"time.cloudflare.com"}}, &ts); code != 200 || ts.Timezone != "America/Denver" {
		t.Fatalf("set time = %d %+v", code, ts)
	}
	if code := admin.do("PUT", "/api/v1/system/time", network.TimeConfig{Timezone: "Nowhere/Land", NTP: true}, &e); code != 400 {
		t.Fatalf("bad zone = %d", code)
	}
	if code := admin.do("POST", "/api/v1/system/time/clock", map[string]string{"time": "2026-10-25T20:00:00Z"}, &e); code != 400 || !strings.Contains(e.Message, "automatic time") {
		t.Fatalf("manual clock with NTP on = %d %+v", code, e)
	}

	// Regular users can read the time but not change the network.
	admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "supersecret2", "role": "user"}, nil)
	kid := env.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "supersecret2"}, nil)
	if code := kid.do("GET", "/api/v1/system/time", nil, nil); code != 200 {
		t.Fatalf("user time = %d", code)
	}
	if code := kid.do("GET", "/api/v1/network", nil, nil); code != 403 {
		t.Fatalf("user network = %d", code)
	}
}
