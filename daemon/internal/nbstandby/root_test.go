package nbstandby

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// sshVPS is an in-process SSH server standing in for the VPS (no network:
// connections are net.Pipe ends). It accepts only the authorized key and
// behaves like the forced command: the client's command is a request, and
// only the three verbs do anything.
type sshVPS struct {
	hostKey   ssh.Signer
	allowed   ssh.PublicKey
	vps       *fakeVPS
	mu        sync.Mutex
	requested []string
}

func newSSHVPS(t *testing.T, vps *fakeVPS) *sshVPS {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	hk, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return &sshVPS{hostKey: hk, vps: vps}
}

// dial connects through a Unix socket pair (buffered both ways, no network).
func (s *sshVPS) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	conn := func(fd int) net.Conn {
		f := os.NewFile(uintptr(fd), "sshpair")
		defer f.Close()
		c, err := net.FileConn(f)
		if err != nil {
			panic(err)
		}
		return c
	}
	client, server := conn(fds[0]), conn(fds[1])
	go s.serve(server)
	return client, nil
}

func (s *sshVPS) serve(c net.Conn) {
	defer c.Close()
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if s.allowed != nil && bytes.Equal(key.Marshal(), s.allowed.Marshal()) {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("not authorized")
	}}
	cfg.AddHostKey(s.hostKey)
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			defer ch.Close()
			for req := range creqs {
				if req.Type != "exec" {
					req.Reply(false, nil)
					continue
				}
				var p struct{ Cmd string }
				ssh.Unmarshal(req.Payload, &p)
				req.Reply(true, nil)
				s.mu.Lock()
				s.requested = append(s.requested, p.Cmd)
				s.mu.Unlock()
				code := uint32(0)
				switch p.Cmd {
				case VerbStatus, VerbSnapshot, VerbRestore:
					var in io.Reader
					if p.Cmd == VerbRestore {
						in = ch
					}
					if err := s.vps.Run(context.Background(), p.Cmd, in, ch); err != nil {
						io.WriteString(ch.Stderr(), err.Error())
						code = 1
					}
				default:
					io.WriteString(ch.Stderr(), "hardyos-standby: refused")
					code = 2
				}
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{code}))
				return
			}
		}()
	}
}

func testKey() func() ([]byte, error) {
	k := bytes.Repeat([]byte{7}, 32)
	return func() ([]byte, error) { return k, nil }
}

func TestSSHRemote(t *testing.T) {
	vps := &fakeVPS{status: `{"running":true}`, snapshot: []byte("SNAP")}
	srv := newSSHVPS(t, vps)
	seed, pub, _ := NewKey()
	signer, _ := SignerFromSeed(seed)
	srv.allowed = signer.PublicKey()
	tgt := SSHTarget{Host: "vps.example.net", Port: 22, User: VPSUser, HostKey: srv.hostKey.PublicKey(), Signer: signer, Dial: srv.dial}
	var out bytes.Buffer
	if err := tgt.Run(t.Context(), VerbSnapshot, nil, &out); err != nil || out.String() != "SNAP" {
		t.Fatalf("%q %v", out.String(), err)
	}
	out.Reset()
	if err := tgt.Run(t.Context(), VerbRestore, strings.NewReader("UPLOAD"), &out); err != nil || string(vps.restored) != "UPLOAD" {
		t.Fatalf("%q %v", vps.restored, err)
	}
	if err := tgt.Run(t.Context(), "id", nil, &out); err == nil {
		t.Fatal("a verb outside the list was sent")
	}
	// The VPS's own refusal comes back as its message.
	vps.fail = map[string]string{VerbStatus: "hand-back isn't allowed on this VPS"}
	err := tgt.Run(t.Context(), VerbStatus, nil, &out)
	var ve *VPSError
	if !errors.As(err, &ve) || !strings.Contains(ve.Msg, "isn't allowed") {
		t.Fatalf("%v", err)
	}
	// Another host key (someone in between) is refused before anything runs.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	os, _ := ssh.NewSignerFromKey(other)
	bad := tgt
	bad.HostKey = os.PublicKey()
	n := len(srv.requested)
	if err := bad.Run(t.Context(), VerbSnapshot, nil, &out); err == nil || !strings.Contains(err.Error(), "host key") {
		t.Fatalf("%v", err)
	}
	// A key the VPS doesn't know.
	seed2, _, _ := NewKey()
	s2, _ := SignerFromSeed(seed2)
	bad = tgt
	bad.Signer = s2
	if err := bad.Run(t.Context(), VerbSnapshot, nil, &out); err == nil {
		t.Fatal("unknown key accepted")
	}
	if len(srv.requested) != n {
		t.Fatal("a command reached the VPS without the right keys")
	}
	_ = pub
	// Host keys are read in both usual forms.
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(srv.hostKey.PublicKey())))
	for _, s := range []string{line, line + " root@vps", "vps.example.net " + line} {
		if _, err := ParseHostKey(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "ssh-ed25519", "hello world", line + "\n" + line} {
		if _, err := ParseHostKey(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

type rootFixture struct {
	root *Root
	vps  *fakeVPS
	apps *fakeApps
	net  *fakeNet
	now  *time.Time
}

func newRoot(t *testing.T) *rootFixture {
	t.Helper()
	dir := t.TempDir()
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	f := &rootFixture{vps: &fakeVPS{status: `{"running":true,"version":"0.83.1","hostname":"vpn.example.net","restoreAllowed":true}`},
		apps: &fakeApps{dir: filepath.Join(dir, "app"), catalog: true, installed: true}, net: &fakeNet{}, now: &now}
	f.vps.snapshot = makeSnapshot(t, defaultFiles(t), nil)
	for _, d := range []string{"data", "config", "traefik", "letsencrypt"} {
		os.MkdirAll(filepath.Join(f.apps.dir, d), 0o700)
	}
	f.root = &Root{Dir: filepath.Join(dir, "keys", "netbird-standby"), Key: testKey(), Apps: f.apps, Net: f.net,
		Remote: func(SSHTarget) Remote { return f.vps }, Now: func() time.Time { return *f.now }}
	return f
}

func (f *rootFixture) configure(t *testing.T) *Status {
	t.Helper()
	_, hk, _ := NewKey()
	st, err := f.root.Configure(t.Context(), ConfigureArgs{VPSHost: "vps.example.net", HostKey: hk, Hostname: "VPN.example.net."})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestRootConfigure(t *testing.T) {
	f := newRoot(t)
	_, hk, _ := NewKey()
	for _, bad := range []ConfigureArgs{
		{VPSHost: "vps;rm", HostKey: hk, Hostname: testHost},
		{VPSHost: "vps.example.net", HostKey: "nope", Hostname: testHost},
		{VPSHost: "vps.example.net", HostKey: hk, Hostname: "localhost"},
		{VPSHost: "vps.example.net", HostKey: hk, Hostname: testHost, VPSUser: "root -oProxyCommand=x"},
		{VPSHost: "vps.example.net", HostKey: hk, Hostname: testHost, VPSPort: 70000},
	} {
		if _, err := f.root.Configure(t.Context(), bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	st := f.configure(t)
	if !st.Configured || st.Hostname != testHost || st.VPSUser != VPSUser || st.VPSPort != 22 || !strings.HasPrefix(st.PublicKey, "ssh-ed25519 ") ||
		!strings.HasPrefix(st.HostKeyFP, "SHA256:") || st.Mode != ModeStandby {
		t.Fatalf("%+v", st)
	}
	// The private key never leaves root: it isn't in the status, and the
	// state file holds it sealed only.
	b, _ := os.ReadFile(filepath.Join(f.root.Dir, stateFile))
	if bytes.Contains(b, []byte("PRIVATE KEY")) {
		t.Fatal("plain key in the state")
	}
	if fi, _ := os.Stat(filepath.Join(f.root.Dir, stateFile)); fi.Mode().Perm() != 0o600 {
		t.Fatal("state file mode")
	}
	// Saving again keeps the key; NewKey replaces it.
	pub := st.PublicKey
	st, _ = f.root.Configure(t.Context(), ConfigureArgs{VPSHost: "vps.example.net", HostKey: hk, Hostname: testHost})
	if st.PublicKey != pub {
		t.Fatal("key changed without NewKey")
	}
	st, _ = f.root.Configure(t.Context(), ConfigureArgs{VPSHost: "vps.example.net", HostKey: hk, Hostname: testHost, NewKey: true})
	if st.PublicKey == pub {
		t.Fatal("NewKey kept the key")
	}
	if f.net.last() != "apply open=false vpn.example.net" {
		t.Fatalf("firewall: %q", f.net.last())
	}
}

func TestRootSyncKeepsSealedSnapshots(t *testing.T) {
	f := newRoot(t)
	f.configure(t)
	for i := 0; i < 5; i++ {
		*f.now = f.now.Add(15 * time.Minute)
		rec, err := f.root.Sync(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if rec.Info.Peers != 7 || rec.Sealed <= rec.Info.Bytes {
			t.Fatalf("%+v", rec)
		}
	}
	st, _ := f.root.Status(t.Context())
	if len(st.Snapshots) != KeepSnapshots || st.LastError != "" || !st.LastOK.Equal(*f.now) {
		t.Fatalf("%+v", st)
	}
	entries, _ := os.ReadDir(f.root.Dir)
	sealed := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sealed") {
			sealed++
			b, _ := os.ReadFile(filepath.Join(f.root.Dir, e.Name()))
			if bytes.Contains(b, []byte("relaysecret")) || bytes.Contains(b, sqliteMagic) {
				t.Fatal("snapshot stored in the clear")
			}
		}
	}
	if sealed != KeepSnapshots {
		t.Fatalf("%d sealed files", sealed)
	}
	// A bad snapshot: error recorded, nothing kept, the good ones stay.
	f.vps.snapshot = makeSnapshot(t, defaultFiles(t), func(m *Manifest) { m.Hostname = "evil.example.net" })
	if _, err := f.root.Sync(t.Context()); err == nil {
		t.Fatal("bad snapshot accepted")
	}
	st, _ = f.root.Status(t.Context())
	if st.LastError == "" || len(st.Snapshots) != KeepSnapshots {
		t.Fatalf("%+v", st)
	}
	entries, _ = os.ReadDir(f.root.Dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".incoming") {
			t.Fatal("partial snapshot left behind")
		}
	}
	// The VPS's own error is reported.
	f.vps.fail = map[string]string{VerbSnapshot: "the NetBird store is PostgreSQL"}
	if _, err := f.root.Sync(t.Context()); err == nil || !strings.Contains(err.Error(), "PostgreSQL") {
		t.Fatalf("%v", err)
	}
	// A VPS that never ends is cut off by the context.
	f.vps.fail = nil
	f.vps.hang = true
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if _, err := f.root.Sync(ctx); err == nil {
		t.Fatal("hanging VPS")
	}
}

func TestRootTakeOverAndHandBack(t *testing.T) {
	f := newRoot(t)
	f.configure(t)
	if _, err := f.root.Stage(t.Context(), ConfirmArgs{Confirm: testHost}); err == nil {
		t.Fatal("staged without a snapshot")
	}
	files := defaultFiles(t)
	files[EntryServerEnv] = []byte("NB_STORE_ENCRYPTION_KEY=ZW52a2V5\n")
	f.vps.snapshot = makeSnapshot(t, files, nil)
	if _, err := f.root.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.root.Network(t.Context(), NetworkArgs{Open: true}); err == nil {
		t.Fatal("ports opened without a take-over")
	}
	if _, err := f.root.Stage(t.Context(), ConfirmArgs{Confirm: "vpn.example.org"}); err == nil {
		t.Fatal("wrong confirmation")
	}
	f.apps.catalog = false
	if _, err := f.root.Stage(t.Context(), ConfirmArgs{Confirm: testHost}); err == nil || !strings.Contains(err.Error(), "package") {
		t.Fatalf("non-catalog app: %v", err)
	}
	f.apps.catalog, f.apps.running = true, true
	if _, err := f.root.Stage(t.Context(), ConfirmArgs{Confirm: testHost}); err == nil {
		t.Fatal("staged into a running app")
	}
	f.apps.running = false
	// Leftovers from earlier runs are replaced.
	os.WriteFile(filepath.Join(f.apps.dir, "data", "store.db-wal"), []byte("old wal"), 0o600)
	res, err := f.root.Stage(t.Context(), ConfirmArgs{Confirm: " VPN.example.net "})
	if err != nil {
		t.Fatal(err)
	}
	if res.Snapshot.Info.Peers != 7 {
		t.Fatalf("%+v", res)
	}
	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join(f.apps.dir, p))
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		return string(b)
	}
	if read("data/store.db") != string(sqliteFile("store")) || read("data/idp.db") != string(sqliteFile("idp")) {
		t.Fatal("databases")
	}
	if _, err := os.Stat(filepath.Join(f.apps.dir, "data", "store.db-wal")); err == nil {
		t.Fatal("old WAL kept")
	}
	cfg := read("config/config.yaml")
	if v, _ := configValue([]byte(cfg), "server.store.encryptionKey"); v != "ZW52a2V5" {
		t.Fatalf("secret not folded:\n%s", cfg)
	}
	if !strings.Contains(read("traefik/dynamic.yaml"), "Host(`vpn.example.net`)") || !strings.Contains(read("letsencrypt/acme.json"), "letsencrypt") {
		t.Fatal("routes or certificate")
	}
	for _, p := range []string{"config/config.yaml", "data/store.db", "letsencrypt/acme.json"} {
		if fi, _ := os.Stat(filepath.Join(f.apps.dir, p)); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", p, fi.Mode())
		}
	}
	st, _ := f.root.Status(t.Context())
	if st.Mode != ModeTakenOver || st.Staged != res.Snapshot.ID {
		t.Fatalf("%+v", st)
	}
	// While taken over: no syncing, no reconfiguring, no second stage.
	if _, err := f.root.Sync(t.Context()); err == nil {
		t.Fatal("synced while taken over")
	}
	_, hk, _ := NewKey()
	if _, err := f.root.Configure(t.Context(), ConfigureArgs{VPSHost: "x.example.net", HostKey: hk, Hostname: testHost}); err == nil {
		t.Fatal("reconfigured while taken over")
	}
	if _, err := f.root.Forget(t.Context(), ConfirmArgs{Confirm: testHost}); err == nil {
		t.Fatal("forgot while taken over")
	}
	if _, err := f.root.Network(t.Context(), NetworkArgs{Open: true}); err != nil || f.net.last() != "apply open=true vpn.example.net" {
		t.Fatalf("%v %q", err, f.net.last())
	}
	// After a restart the table comes back open.
	f.root.OnStart(t.Context())
	if f.net.last() != "apply open=true vpn.example.net" {
		t.Fatalf("%q", f.net.last())
	}

	// The standby wrote to its store meanwhile; hand-back sends it.
	os.WriteFile(filepath.Join(f.apps.dir, "data", "store.db"), sqliteFile("newer"), 0o600)
	os.WriteFile(filepath.Join(f.apps.dir, "data", "store.db-wal"), []byte("wal"), 0o600)
	f.apps.running = true
	if _, err := f.root.Handback(t.Context(), ConfirmArgs{Confirm: testHost}); err == nil {
		t.Fatal("handed back from a running standby")
	}
	f.apps.running = false
	hb, err := f.root.Handback(t.Context(), ConfirmArgs{Confirm: testHost})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hb.Message, "restored") {
		t.Fatalf("%+v", hb)
	}
	sent := readTar(t, f.vps.restored)
	if string(sent["data/store.db"]) != string(sqliteFile("newer")) || string(sent["data/store.db-wal"]) != "wal" || sent["config/config.yaml"] != nil {
		t.Fatalf("sent %v", keys(sent))
	}
	if !strings.Contains(string(sent["SHA256SUMS"]), "  data/store.db\n") {
		t.Fatalf("%s", sent["SHA256SUMS"])
	}
	if _, err := f.root.Unstage(t.Context(), ConfirmArgs{Confirm: testHost}); err != nil {
		t.Fatal(err)
	}
	for _, p := range stagedFiles {
		if _, err := os.Stat(filepath.Join(f.apps.dir, p)); err == nil {
			t.Errorf("%s left after hand-back", p)
		}
	}
	st, _ = f.root.Status(t.Context())
	if st.Mode != ModeStandby || st.NetworkOpen || f.net.last() != "apply open=false vpn.example.net" {
		t.Fatalf("%+v %q", st, f.net.last())
	}
	if _, err := f.root.Sync(t.Context()); err != nil {
		t.Fatal("sync after hand-back:", err)
	}
	// Forget removes everything.
	if _, err := f.root.Forget(t.Context(), ConfirmArgs{Confirm: "nope"}); err == nil {
		t.Fatal("forgot without the name")
	}
	if _, err := f.root.Forget(t.Context(), ConfirmArgs{Confirm: testHost}); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(f.root.Dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sealed") {
			t.Fatal("snapshot left after forget")
		}
	}
	f.apps.installed = false
	f.root.SyncApp(t.Context())
	if f.net.last() != "remove" {
		t.Fatalf("%q", f.net.last())
	}
}

func TestRootVPSStatus(t *testing.T) {
	f := newRoot(t)
	if _, err := f.root.VPS(t.Context()); err == nil {
		t.Fatal("status without a connection")
	}
	f.configure(t)
	vs, err := f.root.VPS(t.Context())
	if err != nil || !vs.Running || !vs.RestoreAllowed || vs.Version != "0.83.1" {
		t.Fatalf("%+v %v", vs, err)
	}
	f.vps.status = "garbage"
	if _, err := f.root.VPS(t.Context()); err == nil {
		t.Fatal("garbage accepted")
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Security review fixes (H1, L1, L4, M1, M2): what root refuses and keeps.
func TestRootGuards(t *testing.T) {
	f := newRoot(t)
	adopted := ""
	f.root.DNSName = func() string { return adopted }
	_, hk, _ := NewKey()
	// The VPS can't be reached by the NetBird name (it points here when taken over).
	if _, err := f.root.Configure(t.Context(), ConfigureArgs{VPSHost: testHost, HostKey: hk, Hostname: testHost}); err == nil {
		t.Fatal("VPS host = NetBird name accepted")
	}
	if _, err := f.root.Configure(t.Context(), ConfigureArgs{VPSHost: "vps.example.net", HostKey: hk, Hostname: testHost, From: []string{"x"}}); err == nil {
		t.Fatal("bad from= accepted")
	}
	st, err := f.root.Configure(t.Context(), ConfigureArgs{VPSHost: "vps.example.net", HostKey: hk, Hostname: testHost, From: []string{"100.64.0.5"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.From) != 1 {
		t.Fatalf("%+v", st.From)
	}
	// The script comes from root's own state.
	sc, err := f.root.Script(t.Context())
	if err != nil || !strings.Contains(sc.Script, `from="100.64.0.5"`) || !strings.Contains(sc.Script, st.PublicKey) || !strings.HasPrefix(sc.Fingerprint, "SHA256:") {
		t.Fatalf("%v %+v", err, sc.Fingerprint)
	}
	// Public addresses: the name typed, internet addresses only.
	for _, bad := range []AddressArgs{{IPv4: "93.184.215.14", Confirm: "x"}, {IPv4: "192.168.1.2", Confirm: testHost},
		{IPv4: "203.0.113.5", Confirm: testHost}, {IPv6: "2001:db8::1", Confirm: testHost}} {
		if _, err := f.root.Address(t.Context(), bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if st, err = f.root.Address(t.Context(), AddressArgs{IPv4: "93.184.215.14", IPv6: "2606:4700:4700:0::1111", Confirm: testHost}); err != nil || st.PublicIPv6 != "2606:4700:4700::1111" {
		t.Fatalf("%+v %v", st, err)
	}
	if _, ok := TakenOver(f.root.Dir); ok {
		t.Fatal("taken over before staging")
	}
	if _, err := f.root.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	// While a name is adopted, the hostname can't move.
	adopted = testHost
	if _, err := f.root.Configure(t.Context(), ConfigureArgs{VPSHost: "vps.example.net", HostKey: hk, Hostname: "nb.example.net"}); err == nil {
		t.Fatal("hostname moved away from the adopted name")
	}
	// Another host key (or VPS) drops the copies: they came from elsewhere.
	_, hk2, _ := NewKey()
	if st, err = f.root.Configure(t.Context(), ConfigureArgs{VPSHost: "vps.example.net", HostKey: hk2, Hostname: testHost}); err != nil || len(st.Snapshots) != 0 {
		t.Fatalf("%v %d", err, len(st.Snapshots))
	}
	if _, err := f.root.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	// A fenced VPS's snapshot isn't kept.
	f.vps.snapshot = makeSnapshot(t, defaultFiles(t), func(m *Manifest) { m.Fenced = true })
	if _, err := f.root.Sync(t.Context()); err == nil || !strings.Contains(err.Error(), "fenced") {
		t.Fatalf("%v", err)
	}
	f.vps.snapshot = makeSnapshot(t, defaultFiles(t), nil)
	if _, err := f.root.Stage(t.Context(), ConfirmArgs{Confirm: testHost}); err != nil {
		t.Fatal(err)
	}
	info, ok := TakenOver(f.root.Dir)
	if !ok || info.Host != testHost || info.IPv4 != "93.184.215.14" || info.IPv6 != "2606:4700:4700::1111" {
		t.Fatalf("%+v %v", info, ok)
	}
	// Nothing about the addresses changes while taken over.
	if _, err := f.root.Address(t.Context(), AddressArgs{IPv4: "8.8.8.8", Confirm: testHost}); err == nil {
		t.Fatal("address changed while taken over")
	}
	// Only the hostname's certificate was staged, without the ACME account.
	b, _ := os.ReadFile(filepath.Join(f.apps.dir, "letsencrypt", "acme.json"))
	if bytes.Contains(b, []byte("Account")) || !bytes.Contains(b, []byte("Certificates")) {
		t.Fatalf("%s", b)
	}
	// Hand-back names the generation and the standby's version, and a
	// sealed copy stays here until the next good sync.
	if _, err := f.root.Handback(t.Context(), ConfirmArgs{Confirm: testHost}); err != nil {
		t.Fatal(err)
	}
	sent := readTar(t, f.vps.restored)
	if string(sent["GENERATION"]) != testGeneration+"\n" || string(sent["VERSION"]) != StandbyVersion+"\n" {
		t.Fatalf("%q %q", sent["GENERATION"], sent["VERSION"])
	}
	st, _ = f.root.Status(t.Context())
	if !st.HandbackCopy {
		t.Fatal("no hand-back copy")
	}
	if _, err := f.root.Unstage(t.Context(), ConfirmArgs{Confirm: testHost}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.root.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	st, _ = f.root.Status(t.Context())
	entries, _ := os.ReadDir(f.root.Dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "handback-") {
			t.Fatal("hand-back copy kept after a good sync")
		}
	}
	if st.HandbackCopy {
		t.Fatal("status still says there's a hand-back copy")
	}
	// Fence and unfence go to the VPS's verbs.
	if err := f.root.Fence(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if err := f.root.Fence(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	calls := f.vps.calls()
	if calls[len(calls)-2] != VerbFence || calls[len(calls)-1] != VerbUnfence {
		t.Fatalf("%v", calls)
	}
}

func TestStageWithoutGenerationRefusesHandback(t *testing.T) {
	f := newRoot(t)
	f.configure(t)
	f.vps.snapshot = makeSnapshot(t, defaultFiles(t), func(m *Manifest) { m.Generation = "" })
	if _, err := f.root.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.root.Stage(t.Context(), ConfirmArgs{Confirm: testHost}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.root.Handback(t.Context(), ConfirmArgs{Confirm: testHost}); err == nil || !strings.Contains(err.Error(), "generation") {
		t.Fatalf("%v", err)
	}
}
