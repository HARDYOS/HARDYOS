package api

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/cfdns"
	"github.com/hardyos/hardyos/daemon/internal/cfdns/cftest"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/nbstandby"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/ports"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/updates"
)

const nbsHost = "vpn.example.net"

// nbsVPS is the VPS's forced command (no network).
type nbsVPS struct {
	mu       sync.Mutex
	snap     []byte
	restored []byte
	down     bool
	fences   []string
}

func (v *nbsVPS) Run(_ context.Context, verb string, stdin io.Reader, stdout io.Writer) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.down {
		return &nbstandby.VPSError{Msg: "connection refused"}
	}
	switch verb {
	case nbstandby.VerbStatus:
		_, err := io.WriteString(stdout, `{"running":true,"version":"0.83.1","hostname":"`+nbsHost+`","restoreAllowed":true,"handbackInstalled":true}`)
		return err
	case nbstandby.VerbFence, nbstandby.VerbUnfence:
		v.fences = append(v.fences, verb)
		return nil
	case nbstandby.VerbSnapshot:
		_, err := stdout.Write(v.snap)
		return err
	case nbstandby.VerbRestore:
		b, err := io.ReadAll(stdin)
		v.restored = b
		if err == nil {
			_, err = io.WriteString(stdout, "restored")
		}
		return err
	}
	return fmt.Errorf("refused")
}

// nbsApps is the installed app (data folder, running) for root and the
// apps ops stub.
type nbsApps struct {
	mu        sync.Mutex
	dir       string
	installed bool
	running   bool
}

func (a *nbsApps) StandbyApp(context.Context) (string, bool, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.installed {
		return "", false, false, nbstandby.ErrNoApp
	}
	return a.dir, a.running, true, nil
}

type nbsNet struct {
	mu   sync.Mutex
	open bool
}

func (n *nbsNet) Apply(_ context.Context, open bool, _ string) error {
	n.mu.Lock()
	n.open = open
	n.mu.Unlock()
	return nil
}
func (n *nbsNet) Remove(context.Context) error { return nil }

func nbsSnapshot(t *testing.T) []byte {
	t.Helper()
	cfg := "server:\n  listenAddress: \":80\"\n  exposedAddress: \"https://" + nbsHost + ":443\"\n  authSecret: \"s\"\n  dataDir: \"/var/lib/netbird\"\n  store:\n    engine: \"sqlite\"\n    encryptionKey: \"k\"\n"
	files := map[string][]byte{nbstandby.EntryConfig: []byte(cfg), nbstandby.EntryStore: append([]byte("SQLite format 3\x00"), "db"...)}
	sums := map[string]string{}
	for n, b := range files {
		s := sha256.Sum256(b)
		sums[n] = hex.EncodeToString(s[:])
	}
	man, _ := json.Marshal(nbstandby.Manifest{Format: 1, Hostname: nbsHost, Engine: "sqlite", Version: "0.83.1", Peers: 3, Generation: "00112233445566778899aabbccddeeff", Files: sums})
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range []struct {
		n string
		b []byte
	}{{nbstandby.EntryManifest, man}, {nbstandby.EntryConfig, files[nbstandby.EntryConfig]}, {nbstandby.EntryStore, files[nbstandby.EntryStore]}} {
		tw.WriteHeader(&tar.Header{Name: e.n, Mode: 0o600, Size: int64(len(e.b)), Typeflag: tar.TypeReg})
		tw.Write(e.b)
	}
	tw.Close()
	return buf.Bytes()
}

type nbsEnv struct {
	*testEnv
	cf   *cftest.Server
	vps  *nbsVPS
	apps *nbsApps
	net  *nbsNet
	pc   *priv.Client
}

func newNBSEnv(t *testing.T) *nbsEnv {
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
	e := &nbsEnv{cf: cftest.New("abcdefghijklmnopqrstuvwxyz0123456789ABCD", "example.net"), vps: &nbsVPS{snap: nbsSnapshot(t)},
		apps: &nbsApps{dir: filepath.Join(t.TempDir(), "app")}, net: &nbsNet{}}
	t.Cleanup(e.cf.Close)
	for _, d := range []string{"data", "config", "traefik", "letsencrypt"} {
		os.MkdirAll(filepath.Join(e.apps.dir, d), 0o700)
	}
	keys := filepath.Join(t.TempDir(), "keys")
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	nbsDir := filepath.Join(keys, "netbird-standby")
	priv.RegisterDNS(ps, priv.DNSEnv{KeyDir: keys, Client: e.cf.Client, StandbyTakenOver: func() (nbstandby.TakeOverInfo, bool) { return nbstandby.TakenOver(nbsDir) }})
	key := bytes.Repeat([]byte{9}, 32)
	priv.RegisterNetBirdStandby(ps, &nbstandby.Root{Dir: nbsDir, Key: func() ([]byte, error) { return key, nil },
		Remote: func(nbstandby.SSHTarget) nbstandby.Remote { return e.vps }, Apps: e.apps, Net: e.net})
	// The apps engine, as far as the standby uses it.
	ps.Handle(priv.OpAppsStatus, func(context.Context, json.RawMessage) (any, error) {
		e.apps.mu.Lock()
		defer e.apps.mu.Unlock()
		o := apps.Overview{Available: true, Pool: "tank", Apps: []apps.App{}}
		if e.apps.installed {
			state := "stopped"
			if e.apps.running {
				state = "running"
			}
			o.Apps = append(o.Apps, apps.App{ID: ports.NetBirdStandbyApp, Name: "NetBird Standby", Version: "0.83.1", State: state})
		}
		return o, nil
	})
	setRunning := func(v bool) priv.HandlerFunc {
		return func(context.Context, json.RawMessage) (any, error) {
			e.apps.mu.Lock()
			e.apps.running = v
			e.apps.mu.Unlock()
			return struct{}{}, nil
		}
	}
	ps.Handle(priv.OpAppsUp, setRunning(true))
	ps.Handle(priv.OpAppsStop, setRunning(false))
	ps.Handle(priv.OpNetBirdStatus, func(context.Context, json.RawMessage) (any, error) {
		return map[string]any{"state": "connected", "connected": true, "ip": "100.64.0.5", "managementUrl": "https://" + nbsHost}, nil
	})
	go func() { _ = ps.Serve(ctx, ln) }()
	e.pc = priv.NewClient(sock)
	broker := events.NewBroker()
	m := &jobs.Manager{DB: db, Events: broker}
	RegisterJobKinds(m, e.pc)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	center := &notify.Center{DB: db, Events: broker}
	upd := &updates.Service{Priv: e.pc, Jobs: m, DB: db, Dir: t.TempDir(), Notify: center}
	srv := httptest.NewServer(New(Config{DB: db, Jobs: m, Events: broker, Priv: e.pc, Updates: upd, Notify: center, Insecure: true}))
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	e.testEnv = &testEnv{srv: srv, db: db, broker: broker}
	return e
}

func jobOK(t *testing.T, c *client, code int, acc map[string]any, what string) map[string]any {
	t.Helper()
	if code != 202 {
		t.Fatalf("%s = %d", what, code)
	}
	j := waitJobDone(t, c, acc["job"].(map[string]any)["id"].(string))
	if j["state"] != "succeeded" {
		t.Fatalf("%s job = %+v", what, j)
	}
	return j
}

func TestNBStandbyAPI(t *testing.T) {
	e := newNBSEnv(t)
	admin := e.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	kid := e.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	for _, r := range [][2]string{{"GET", "/api/v1/netbird-standby"}, {"GET", "/api/v1/netbird-standby/script"}, {"POST", "/api/v1/netbird-standby/takeover"},
		{"POST", "/api/v1/netbird-standby/handback"}, {"PUT", "/api/v1/netbird-standby/settings"}, {"POST", "/api/v1/netbird-standby/sync"},
		{"DELETE", "/api/v1/netbird-standby"}, {"GET", "/api/v1/netbird-standby/dns?name=" + nbsHost}} {
		if code := kid.do(r[0], r[1], map[string]any{}, nil); code != 403 {
			t.Errorf("a family member: %s %s = %d", r[0], r[1], code)
		}
	}
	var st NBStandbyStatus
	if code := admin.do("GET", "/api/v1/netbird-standby", nil, &st); code != 200 || st.Health.State != "unconfigured" || len(st.PortForwards) != 3 {
		t.Fatalf("%d %+v", code, st)
	}

	// Settings: checked here (and again by root).
	_, hostKey, _ := nbstandby.NewKey()
	good := NBStandbySettingsRequest{VPSHost: "vps.example.net", HostKey: hostKey, Hostname: nbsHost,
		Settings: nbstandby.Settings{IntervalMinutes: 15, AutoSync: true, PublicIPv4: "93.184.215.14", ConnectFrom: []string{"100.64.0.5"}}}
	for _, mut := range []func(*NBStandbySettingsRequest){
		func(r *NBStandbySettingsRequest) { r.Hostname = "nope" },
		func(r *NBStandbySettingsRequest) { r.VPSHost = "vps; rm -rf /" },
		func(r *NBStandbySettingsRequest) { r.HostKey = "not a key" },
		func(r *NBStandbySettingsRequest) { r.VPSUser = "-oProxyCommand=sh" },
		func(r *NBStandbySettingsRequest) { r.Settings.PublicIPv4 = "192.168.1.10" },
	} {
		bad := good
		mut(&bad)
		if code := admin.do("PUT", "/api/v1/netbird-standby/settings", bad, nil); code != 400 {
			t.Errorf("bad settings %+v = %d", bad, code)
		}
	}
	var acc map[string]any
	// A new public address needs the name typed.
	if code := admin.do("PUT", "/api/v1/netbird-standby/settings", good, nil); code != 400 {
		t.Fatalf("address without confirmation = %d", code)
	}
	vpsIsName := good
	vpsIsName.VPSHost = nbsHost
	vpsIsName.AddressConfirm = nbsHost
	if code := admin.do("PUT", "/api/v1/netbird-standby/settings", vpsIsName, nil); code != 400 {
		t.Fatalf("VPS = NetBird name = %d", code)
	}
	good.AddressConfirm = nbsHost
	jobOK(t, admin, admin.do("PUT", "/api/v1/netbird-standby/settings", good, &acc), acc, "settings")
	admin.do("GET", "/api/v1/netbird-standby", nil, &st)
	if st.Connection == nil || !st.Connection.Configured || !strings.HasPrefix(st.Connection.PublicKey, "ssh-ed25519 ") ||
		st.Connection.PublicIPv4 != "93.184.215.14" || st.Settings.PublicIPv4 != "93.184.215.14" {
		t.Fatalf("%+v", st.Connection)
	}
	var script NBStandbyScript
	if code := admin.do("GET", "/api/v1/netbird-standby/script", nil, &script); code != 200 || !strings.HasPrefix(script.Fingerprint, "SHA256:") ||
		!strings.Contains(script.Script, `restrict,command="/usr/local/sbin/hardyos-netbird-standby",from="100.64.0.5" `+st.Connection.PublicKey) {
		t.Fatalf("%d %s", code, script.Script)
	}

	// Sync (by hand; the schedule is tested in the service).
	jobOK(t, admin, admin.do("POST", "/api/v1/netbird-standby/sync", nil, &acc), acc, "sync")
	admin.do("GET", "/api/v1/netbird-standby", nil, &st)
	if len(st.Connection.Snapshots) != 1 || len(st.History) != 1 || !st.History[0].OK || st.Health.State != "ok" {
		t.Fatalf("%+v %+v %+v", st.Connection.Snapshots, st.History, st.Health)
	}

	// DNS: the Cloudflare token (Control Panel › Hostnames) and the name's adoption.
	if err := e.pc.Call(t.Context(), priv.OpDNSTokenSet, priv.DNSTokenSetArgs{Token: "abcdefghijklmnopqrstuvwxyz0123456789ABCD", Base: "home.example.net"}, nil); err != nil {
		t.Fatal(err)
	}
	e.cf.Add("example.net", cfdns.Record{Type: "A", Name: nbsHost, Content: "198.51.100.10", TTL: 300})
	var pv priv.DNSStandbyPreview
	if code := admin.do("GET", "/api/v1/netbird-standby/dns?name="+nbsHost, nil, &pv); code != 200 || len(pv.Records) != 1 || !pv.Adoptable {
		t.Fatalf("%d %+v", code, pv)
	}
	cfTok := "abcdefghijklmnopqrstuvwxyz0123456789ABCD"
	if code := admin.do("POST", "/api/v1/netbird-standby/dns", NBStandbyDNSRequest{Name: nbsHost, Confirm: nbsHost, IDs: []string{pv.Records[0].ID}}, nil); code != 400 {
		t.Fatalf("adopt without the token = %d", code)
	}
	var accWrong map[string]any
	j0 := waitJobDone(t, admin, func() string {
		admin.do("POST", "/api/v1/netbird-standby/dns", NBStandbyDNSRequest{Name: nbsHost, Confirm: nbsHost, IDs: []string{pv.Records[0].ID}, Token: strings.Repeat("y", 40)}, &accWrong)
		return accWrong["job"].(map[string]any)["id"].(string)
	}())
	if j0["state"] != "failed" {
		t.Fatalf("adopt with another token: %+v", j0)
	}
	if code := admin.do("POST", "/api/v1/netbird-standby/dns", NBStandbyDNSRequest{Name: nbsHost, Confirm: "vpn", IDs: []string{pv.Records[0].ID}, Token: cfTok}, nil); code != 400 {
		t.Fatalf("adopt without the typed name = %d", code)
	}
	if code := admin.do("POST", "/api/v1/netbird-standby/dns", NBStandbyDNSRequest{Name: "other.example.net", Confirm: "other.example.net", IDs: []string{pv.Records[0].ID}, Token: cfTok}, nil); code != 400 {
		t.Fatalf("adopt another name = %d", code)
	}
	jobOK(t, admin, admin.do("POST", "/api/v1/netbird-standby/dns", NBStandbyDNSRequest{Name: nbsHost, Confirm: nbsHost, IDs: []string{pv.Records[0].ID}, Token: cfTok}, &acc), acc, "adopt")

	// Take over: typed name, the app installed.
	if code := admin.do("POST", "/api/v1/netbird-standby/takeover", nbstandby.TakeOverArgs{Confirm: "vpn.example"}, nil); code != 400 {
		t.Fatalf("take over without the name = %d", code)
	}
	if code := admin.do("POST", "/api/v1/netbird-standby/takeover", nbstandby.TakeOverArgs{Confirm: nbsHost}, nil); code != 400 {
		t.Fatalf("take over without the app = %d", code)
	}
	e.apps.mu.Lock()
	e.apps.installed = true
	e.apps.mu.Unlock()
	e.vps.mu.Lock()
	e.vps.down = true // the VPS died: the saved copy is used
	e.vps.mu.Unlock()
	j := jobOK(t, admin, admin.do("POST", "/api/v1/netbird-standby/takeover", nbstandby.TakeOverArgs{Confirm: nbsHost}, &acc), acc, "take over")
	res, _ := json.Marshal(j["result"])
	var rec nbstandby.TakeoverRecord
	json.Unmarshal(res, &rec)
	if !rec.DNSChanged || rec.FinalSync || rec.Fenced || rec.By != "cade" {
		t.Fatalf("%+v", rec)
	}
	if got := e.cf.Find(nbsHost, "A"); len(got) != 1 || got[0].Content != "93.184.215.14" || got[0].TTL != 60 {
		t.Fatalf("DNS: %+v", got)
	}
	if !e.net.open || !e.apps.running {
		t.Fatal("the standby isn't open and running")
	}
	if b, err := os.ReadFile(filepath.Join(e.apps.dir, "data", "store.db")); err != nil || !bytes.HasPrefix(b, []byte("SQLite format 3")) {
		t.Fatal("store not staged")
	}
	admin.do("GET", "/api/v1/netbird-standby", nil, &st)
	if st.Health.State != "takenover" || st.Takeover == nil {
		t.Fatalf("%+v", st.Health)
	}
	// While taken over: no syncing, no forgetting, no forgetting the token.
	if code := admin.do("POST", "/api/v1/netbird-standby/sync", nil, nil); code != 409 {
		t.Fatalf("sync while taken over = %d", code)
	}
	if code := admin.do("DELETE", "/api/v1/netbird-standby", NBStandbyConfirm{Confirm: nbsHost}, nil); code != 409 {
		t.Fatalf("forget while taken over = %d", code)
	}

	// Hand back: the VPS is back; the typed name and the split-brain tick.
	e.vps.mu.Lock()
	e.vps.down = false
	e.vps.mu.Unlock()
	if code := admin.do("POST", "/api/v1/netbird-standby/handback", nbstandby.HandBackArgs{Confirm: nbsHost}, nil); code != 400 {
		t.Fatalf("hand back without the acknowledgement = %d", code)
	}
	jobOK(t, admin, admin.do("POST", "/api/v1/netbird-standby/handback", nbstandby.HandBackArgs{Confirm: nbsHost, AcceptSplitBrain: true}, &acc), acc, "hand back")
	if got := e.cf.Find(nbsHost, "A"); len(got) != 1 || got[0].Content != "198.51.100.10" || got[0].TTL != 300 {
		t.Fatalf("DNS not restored: %+v", got)
	}
	if e.net.open || e.apps.running || len(e.vps.restored) == 0 {
		t.Fatal("hand-back didn't finish")
	}
	admin.do("GET", "/api/v1/netbird-standby", nil, &st)
	if st.Connection.Mode != nbstandby.ModeStandby || st.Takeover != nil {
		t.Fatalf("%+v", st.Connection)
	}
	// Every step is audited.
	var audit []map[string]any
	admin.do("GET", "/api/v1/audit", nil, &audit)
	seen := map[string]bool{}
	for _, a := range audit {
		seen[fmt.Sprint(a["action"])] = true
	}
	for _, want := range []string{"netbird.standby.settings", "netbird.standby.sync", "netbird.standby.dns.adopt", "netbird.standby.takeover",
		"netbird.standby.takenover", "netbird.standby.handback", "netbird.standby.handedback"} {
		if !seen[want] {
			t.Errorf("no audit entry %s", want)
		}
	}
	if code := admin.do("DELETE", "/api/v1/netbird-standby", NBStandbyConfirm{Confirm: "x"}, nil); code != 400 {
		t.Fatalf("forget without the name = %d", code)
	}
	jobOK(t, admin, admin.do("DELETE", "/api/v1/netbird-standby", NBStandbyConfirm{Confirm: nbsHost}, &acc), acc, "forget")
}
