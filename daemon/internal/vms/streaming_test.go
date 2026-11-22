package vms

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/ports"
)

const streamPW = "Abcdefghijkmnopqrstuvw23"

// seedStreaming puts the two pinned downloads in the catalog store, as a
// finished catalog fetch leaves them (sealed against their pinned SHA-256).
func (e *testEnv) seedStreaming(t *testing.T) {
	t.Helper()
	c, err := e.m.store(context.Background(), "tank", true)
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.m.openStore(c)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, id := range []string{CatalogSunshine, CatalogVDD} {
		_, cf, err := e.m.catalogFile(id)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.WriteFile(cf.File, []byte(id), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := seal(r, cf.File, digest{Algo: "sha256", Hex: cf.SHA256}); err != nil {
			t.Fatal(err)
		}
	}
}

func gamingStreamSpec(t *testing.T) Spec {
	s := winSpec(t, "gaming")
	s.ID, s.Name = "game", "Game"
	s.NICs[0].MAC = "52:54:00:12:34:56" // the sim's ARP table knows it
	s.Streaming = &Streaming{Sunshine: true, Remote: true, User: "evil", CertSHA256: strings.Repeat("a", 64)}
	return s
}

func streamEnv(t *testing.T) *testEnv {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "Win11_24H2_English_x64.iso", 10)
	e.seedVirtio(t)
	return e
}

func TestStreamingCatalogPinned(t *testing.T) {
	for _, id := range []string{CatalogSunshine, CatalogVDD} {
		found := false
		for _, c := range Catalog {
			if c.ID != id {
				continue
			}
			found = true
			if c.Kind != "file" || len(c.Files) == 0 {
				t.Fatalf("%s: %+v", id, c)
			}
			for arch, f := range c.Files {
				if !hex64RE.MatchString(f.SHA256) || f.SumsURL != "" {
					t.Errorf("%s/%s isn't pinned by SHA-256", id, arch)
				}
				if !strings.Contains(f.URL, "/releases/download/"+SunshineVersion+"/") && !strings.Contains(f.URL, "/releases/download/"+VDDVersion+"/") {
					t.Errorf("%s/%s isn't pinned to a release: %s", id, arch, f.URL)
				}
				if _, err := allowedURL(f.URL, c.Hosts); err != nil {
					t.Error(err)
				}
			}
		}
		if !found {
			t.Fatalf("%s isn't in the catalog", id)
		}
	}
	// The wizard's catalog list leaves them out (they're never a VM disk).
	e := newEnv(t)
	for _, v := range e.m.CatalogList() {
		if v.Kind == "file" {
			t.Fatalf("%s offered in the wizard", v.ID)
		}
	}
}

func TestSetupScript(t *testing.T) {
	e := newEnv(t)
	s := gamingStreamSpec(t)
	s.Streaming = &Streaming{Sunshine: true, User: SunshineUser}
	files, err := e.m.streamingFiles(&s, &streamKit{certPEM: []byte("CERT"), keyPEM: []byte("KEY"), password: streamPW})
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for k := range files {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if strings.Join(keys, ",") != "setup.ps1,sunshine-account.json,sunshine-cert.pem,sunshine-key.pem" {
		t.Fatalf("disc files: %v", keys)
	}
	var acct map[string]string
	if err := json.Unmarshal(files["sunshine-account.json"], &acct); err != nil || acct["user"] != SunshineUser || acct["password"] != streamPW {
		t.Fatalf("account file: %s", files["sunshine-account.json"])
	}
	script := string(files["setup.ps1"])
	for _, want := range []string{
		"FileSystemLabel -eq '" + StreamingLabel + "'",
		"Checked 'sunshine-" + SunshineVersion + "-amd64.msi' '" + sunshineAMD64SHA256 + "'",
		"Checked 'vdd-" + VDDVersion + "-x64.zip' '" + vddX64SHA256 + "'",
		"'/qn', '/norestart'",
		"--creds",
		"origin_web_ui_allowed = lan",
		"upnp = disabled",
		"sunshine_name = game",
		"'Root\\MttVDD'",
		"TrustedPublisher",
		"$store.Remove($signer)",
		"\r\n",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("setup script lacks %q", want)
		}
	}
	// Nothing is downloaded in the guest, and the password never reaches
	// the script or its log.
	for _, bad := range []string{"Invoke-WebRequest", "http://", "https://", "DownloadFile", "Start-BitsTransfer", streamPW, "Say $creds", "Transcript"} {
		if strings.Contains(script, bad) {
			t.Errorf("setup script has %q", bad)
		}
	}
	// Only values that passed patterns go in.
	if _, err := SetupScript(SetupScriptVars{Name: "x'; rm", SunshineFile: "a.msi", VDDFile: "b.zip", SunshineSHA256: sunshineAMD64SHA256, VDDSHA256: vddX64SHA256}); err == nil {
		t.Fatal("a quote went into the script")
	}
	// The hook only runs the script from the labelled disc.
	h, ok := firstLogonHook(StreamingHook)
	if !ok {
		t.Fatal("no sunshine hook")
	}
	cmds := h(HookVM{ID: "game", User: "cade", Arch: "amd64"})
	if len(cmds) != 1 || cmds[0].CommandLine != StreamingCommand || len(StreamingCommand) > 1024 || !strings.Contains(StreamingCommand, "'"+StreamingLabel+"'") {
		t.Fatalf("hook: %+v", cmds)
	}
}

func TestCreateWithStreaming(t *testing.T) {
	e := streamEnv(t)
	ctx := context.Background()
	s := gamingStreamSpec(t)

	// The downloads must be in the catalog store first.
	if _, err := e.m.Create(ctx, CreateArgs{Spec: s, Password: "Windows pass 1", StreamingPassword: streamPW}); err == nil || !strings.Contains(err.Error(), "isn't downloaded") {
		t.Fatalf("without the downloads: %v", err)
	}
	e.seedStreaming(t)
	// The password is hardyd's generator's kind only.
	if _, err := e.m.Create(ctx, CreateArgs{Spec: s, Password: "Windows pass 1", StreamingPassword: "short pw'"}); err == nil || !strings.Contains(err.Error(), "Sunshine password") {
		t.Fatalf("bad streaming password: %v", err)
	}
	// It needs the home network with the anti-spoofing filter.
	nat := gamingStreamSpec(t)
	nat.NICs[0].Mode = NICNAT
	if _, err := e.m.Create(ctx, CreateArgs{Spec: nat, Password: "Windows pass 1", StreamingPassword: streamPW}); err == nil || !strings.Contains(err.Error(), "home network") {
		t.Fatalf("NAT: %v", err)
	}
	// And an unattended install (the step runs at its first sign-in).
	manual := gamingStreamSpec(t)
	manual.Unattend = nil
	manual.Media = withoutMedia(manual.Media, MediaUnattend)
	if _, err := e.m.Create(ctx, CreateArgs{Spec: manual, Password: "Windows pass 1", StreamingPassword: streamPW}); err == nil || !strings.Contains(err.Error(), "unattended") {
		t.Fatalf("without unattend: %v", err)
	}

	res, err := e.m.Create(ctx, CreateArgs{Spec: s, Password: "Windows pass 1", StreamingPassword: streamPW})
	if err != nil {
		t.Fatal(err)
	}
	v := res.VM
	st := v.Streaming
	// Root sets the account, the pin and Remote (off), whatever hardyd sent.
	if st == nil || !st.Sunshine || st.User != SunshineUser || st.Remote || !hex64RE.MatchString(st.CertSHA256) || st.CertSHA256 == strings.Repeat("a", 64) {
		t.Fatalf("streaming = %+v", st)
	}
	if !v.HasStreamingMedia() || !slices.Contains(v.Unattend.Hooks, StreamingHook) {
		t.Fatalf("media %v hooks %v", v.Media, v.Unattend.Hooks)
	}
	disc := filepath.Join(e.root, UnattendRunDir, v.UUID+"-stream.iso")
	if fi, err := os.Stat(disc); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("streaming disc: %v %v", fi, err)
	}
	if left, _ := filepath.Glob(filepath.Join(e.root, UnattendRunDir, ".stage-*")); len(left) != 0 {
		t.Fatalf("staging left: %v", left)
	}
	var mk string
	for _, l := range e.sim.Lines() {
		if strings.Contains(l, "-volid "+StreamingLabel) {
			mk = l
		}
		if strings.Contains(l, streamPW) {
			t.Fatalf("the Sunshine password was on a command line: %s", l)
		}
	}
	if mk == "" || !strings.Contains(mk, "-graft-points") ||
		!strings.Contains(mk, "/sunshine-"+SunshineVersion+"-amd64.msi=/mnt/tank/vm-catalog/sunshine-"+SunshineVersion+"-amd64.msi") ||
		!strings.Contains(mk, "/vdd-"+VDDVersion+"-x64.zip=/mnt/tank/vm-catalog/vdd-"+VDDVersion+"-x64.zip") {
		t.Fatalf("streaming disc command: %s", mk)
	}
	spec, _ := os.ReadFile(filepath.Join(e.root, "mnt/tank/vms/game", specFile))
	if strings.Contains(string(spec), streamPW) || strings.Contains(string(spec), "PRIVATE KEY") {
		t.Fatal("the Sunshine password or key is in vm.json")
	}
	x := e.sim.defined["game"]
	if !strings.Contains(x, UnattendRunDir+"/"+v.UUID+"-stream.iso") {
		t.Fatalf("the streaming disc isn't in a drive:\n%s", x)
	}
	// The answer file runs the step after the guest tools.
	b, err := AnswerFile(&v.Spec, "x86_64", "Windows pass 1")
	if err != nil {
		t.Fatal(err)
	}
	ax := string(b)
	gi, si := strings.Index(ax, esc(GuestToolsCommand)), strings.Index(ax, esc(StreamingCommand))
	if gi < 0 || si < gi {
		t.Fatalf("first-logon order: tools %d, sunshine %d", gi, si)
	}

	// Updates keep root's streaming settings and can't add the disc again.
	up := v.Spec
	up.Streaming = &Streaming{Sunshine: true, Remote: true, User: "x", CertSHA256: strings.Repeat("b", 64)}
	r2, err := e.m.Update(ctx, UpdateArgs{Spec: up})
	if err != nil {
		t.Fatal(err)
	}
	if *r2.VM.Streaming != *st {
		t.Fatalf("update changed streaming: %+v", r2.VM.Streaming)
	}

	// Starting checks the disc; the install's end deletes it with the
	// answer disc.
	BootKeyPresses, BootKeyEvery = 1, time.Millisecond
	if _, err := e.m.Start(ctx, "game"); err != nil {
		t.Fatal(err)
	}
	e.sim.agent = true
	e.m.checkInstalled(ctx, "game")
	v2, _ := e.m.Get(ctx, "game")
	if v2.HasStreamingMedia() || v2.Unattend != nil || !v2.StreamingSetUp() {
		t.Fatalf("after the install: %v %+v %+v", v2.Media, v2.Unattend, v2.Streaming)
	}
	if _, err := os.Stat(disc); !os.IsNotExist(err) {
		t.Fatalf("the streaming disc is still there: %v", err)
	}
	// It can't come back.
	up = v2.Spec
	up.Media = append(up.Media, Media{Kind: MediaStreaming})
	if _, err := e.m.Update(ctx, UpdateArgs{Spec: up}); err == nil {
		t.Fatal("the streaming disc came back")
	}
}

func TestStreamingCert(t *testing.T) {
	c, k, fp, err := newSunshineCert(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(c)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(blk.Bytes)
	if hex.EncodeToString(sum[:]) != fp || cert.Subject.CommonName != "Sunshine Gamestream Host" {
		t.Fatalf("fingerprint %s", fp)
	}
	kb, _ := pem.Decode(k)
	if kb == nil || kb.Type != "PRIVATE KEY" {
		t.Fatal("no key")
	}
	if _, err := x509.ParsePKCS8PrivateKey(kb.Bytes); err != nil {
		t.Fatal(err)
	}
}

func TestStreamingValidation(t *testing.T) {
	h := Host{Arch: x86, TPM: true, SecureBoot: true}
	bad := map[string]func(*Spec){
		"disc without streaming": func(s *Spec) { s.Streaming = nil },
		"hook without disc":      func(s *Spec) { s.Media = withoutMedia(s.Media, MediaStreaming) },
		"two discs":              func(s *Spec) { s.Media = append(s.Media, Media{Kind: MediaStreaming}) },
		"bad user":               func(s *Spec) { s.Streaming.User = "Bad User" },
		"bad pin":                func(s *Spec) { s.Streaming.CertSHA256 = "zz" },
		"linux":                  func(s *Spec) { s.OS = "linux" },
		"disc with a file":       func(s *Spec) { s.Media[len(s.Media)-1].ISO = "x.iso" },
	}
	for name, f := range bad {
		s := gamingStreamSpec(t)
		s.Streaming = &Streaming{Sunshine: true, User: SunshineUser, CertSHA256: strings.Repeat("a", 64)}
		s.Media = []Media{{Kind: MediaISO, ISO: "w.iso"}, {Kind: MediaUnattend}, {Kind: MediaStreaming}}
		s.Unattend.Hooks = []string{StreamingHook}
		f(&s)
		s.Normalize()
		if err := s.Validate(h); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A spec without HardyOS's streaming can't smuggle in the disc or the hook.
	e := streamEnv(t)
	e.seedStreaming(t)
	s := winSpec(t, "windows11")
	s.Unattend.Hooks = []string{StreamingHook}
	if _, err := e.m.Create(context.Background(), CreateArgs{Spec: s, Password: "Windows pass 1"}); err == nil || !strings.Contains(err.Error(), "Sunshine first-logon step") {
		t.Fatalf("hook without streaming: %v", err)
	}
}

func TestRenderStreamingNFT(t *testing.T) {
	f := StreamForward{VM: "game", Iface: "wt0", PeerNet: "100.92.0.0/16", HostIP: "100.92.1.2", Bridge: "br0", VMIP: "192.168.1.77"}
	text, err := RenderStreamingNFT(&f)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table ip hardyos_streaming {",
		"delete table ip hardyos_streaming",
		`iifname "wt0" ip saddr 100.92.0.0/16 ip daddr 100.92.1.2 tcp dport { 47984, 47989, 48010 } dnat to 192.168.1.77`,
		`iifname "wt0" ip saddr 100.92.0.0/16 ip daddr 100.92.1.2 udp dport { 47998-48000, 48002, 48010 } dnat to 192.168.1.77`,
		`iifname "wt0" oifname "br0" ip saddr 100.92.0.0/16 ip daddr 192.168.1.77 ct status dnat masquerade`,
		"type nat hook prerouting priority dstnat - 5;",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	// Sunshine's web UI is never forwarded, and nothing but NetBird.
	if strings.Contains(text, "47990") || strings.Count(text, `iifname "wt0" ip saddr`) != 2 {
		t.Fatalf("ruleset:\n%s", text)
	}
	rules, err := StreamingIPTables(f)
	if err != nil || len(rules) != 3 || !slices.Contains(rules[0], "47984,47989,48010") || !slices.Contains(rules[1], "47998:48000,48002,48010") || !slices.Contains(rules[0], "100.92.0.0/16") {
		t.Fatalf("iptables %v %v", rules, err)
	}
	for _, r := range rules {
		if slices.Contains(r, "47990") {
			t.Fatal("the web UI port is forwarded")
		}
	}
	// Bad values never reach a rule.
	bad := map[string]func(*StreamForward){
		"public peers":     func(f *StreamForward) { f.PeerNet = "0.0.0.0/0" },
		"public net":       func(f *StreamForward) { f.PeerNet = "8.8.0.0/16"; f.HostIP = "8.8.1.1" },
		"host outside":     func(f *StreamForward) { f.HostIP = "100.93.1.2" },
		"public VM":        func(f *StreamForward) { f.VMIP = "8.8.8.8" },
		"VM in NetBird":    func(f *StreamForward) { f.VMIP = "100.92.3.4" },
		"iface injection":  func(f *StreamForward) { f.Iface = `wt0" accept;` },
		"bridge = netbird": func(f *StreamForward) { f.Bridge = "wt0" },
		"ipv6":             func(f *StreamForward) { f.VMIP = "fd00::1" },
		"unmasked":         func(f *StreamForward) { f.PeerNet = "100.92.1.2/16" },
		"bad vm":           func(f *StreamForward) { f.VM = "x y" },
	}
	for name, mut := range bad {
		g := f
		mut(&g)
		if _, err := RenderStreamingNFT(&g); err == nil {
			t.Errorf("%s: rendered", name)
		}
		if _, err := StreamingIPTables(g); err == nil {
			t.Errorf("%s: iptables rules", name)
		}
	}
	if text, err := RenderStreamingNFT(nil); err != nil || text != "" {
		t.Fatal("nil forward")
	}
	if portList(ports.SunshineUDP, "-") != "47998-48000,48002,48010" {
		t.Fatal(portList(ports.SunshineUDP, "-"))
	}
}

func TestStreamingForwarding(t *testing.T) {
	e := streamEnv(t)
	e.seedStreaming(t)
	ctx := context.Background()
	if _, err := e.m.Create(ctx, CreateArgs{Spec: gamingStreamSpec(t), Password: "Windows pass 1", StreamingPassword: streamPW}); err != nil {
		t.Fatal(err)
	}
	nb := NetBirdInfo{Connected: true, Interface: "wt0", IP: "100.92.1.2", Network: "100.92.0.0/16"}
	e.m.NetBird = func(context.Context) NetBirdInfo { return nb }
	var dialled []string
	e.m.streamDial = func(_ context.Context, a string) error { dialled = append(dialled, a); return nil }

	if _, err := e.m.SetStreamingRemote(ctx, StreamingPublishArgs{ID: "game", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	info, err := e.m.StreamingInfo(ctx, "game")
	if err != nil || info.Forwarding || info.Problem != "the VM is off" || !info.Remote {
		t.Fatalf("off: %+v %v", info, err)
	}
	if e.sim.has("nft -f") {
		t.Fatal("rules for a VM that's off")
	}
	// Running: root finds the VM's address in its ARP table (by MAC, on
	// the bridge's subnet) and forwards.
	BootKeyPresses = 0
	if _, err := e.m.Start(ctx, "game"); err != nil {
		t.Fatal(err)
	}
	if err := e.m.syncStreaming(ctx); err != nil {
		t.Fatal(err)
	}
	info, _ = e.m.StreamingInfo(ctx, "game")
	if info.Address != "192.168.1.77" || !info.Forwarding || info.NetBirdAddress != "100.92.1.2" {
		t.Fatalf("running: %+v", info)
	}
	rules, err := os.ReadFile(filepath.Join(e.root, StreamRunDir, "streaming.nft"))
	if err != nil || !strings.Contains(string(rules), "dnat to 192.168.1.77") {
		t.Fatalf("rules: %s %v", rules, err)
	}
	if fi, _ := os.Stat(filepath.Join(e.root, StreamRunDir)); fi.Mode().Perm() != 0o700 {
		t.Fatalf("rules folder %v", fi.Mode())
	}
	if !e.sim.has("nft -f "+StreamRunDir+"/streaming.nft") || !e.sim.has("iptables -w -A HARDYOS-STREAM -i wt0 -o br0") || !e.sim.has("iptables -w -C FORWARD -j HARDYOS-STREAM") {
		t.Fatalf("commands:\n%s", strings.Join(e.sim.Lines(), "\n"))
	}
	// Nothing changes: nothing is reloaded.
	n := len(e.sim.Lines())
	_ = e.m.syncStreaming(ctx)
	for _, l := range e.sim.Lines()[n:] {
		if strings.HasPrefix(l, "nft") || strings.HasPrefix(l, "iptables") {
			t.Fatalf("reloaded: %s", l)
		}
	}
	// A second VM can't take the same ports.
	other := gamingStreamSpec(t)
	other.ID, other.Name, other.NICs[0].MAC = "game2", "Game 2", ""
	if _, err := e.m.Create(ctx, CreateArgs{Spec: other, Password: "Windows pass 1", StreamingPassword: streamPW}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.SetStreamingRemote(ctx, StreamingPublishArgs{ID: "game2", Enabled: true}); err == nil || !strings.Contains(err.Error(), "only one VM") {
		t.Fatalf("second VM: %v", err)
	}
	// NetBird disconnects: the rules go.
	nb.Connected = false
	_ = e.m.syncStreaming(ctx)
	if !e.sim.has("nft delete table ip hardyos_streaming") {
		t.Fatal("rules kept without NetBird")
	}
	nb.Connected = true
	_ = e.m.syncStreaming(ctx)
	// Turned off: gone.
	if _, err := e.m.SetStreamingRemote(ctx, StreamingPublishArgs{ID: "game", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	info, _ = e.m.StreamingInfo(ctx, "game")
	if info.Forwarding || info.Remote {
		t.Fatalf("after turning off: %+v", info)
	}
	if _, err := e.m.SetStreamingRemote(ctx, StreamingPublishArgs{ID: "nope", Enabled: true}); err == nil {
		t.Fatal("unknown VM published")
	}
	_ = dialled
}

func TestStreamingAddressNeverTheGuestsWord(t *testing.T) {
	e := streamEnv(t)
	e.seedStreaming(t)
	ctx := context.Background()
	s := gamingStreamSpec(t)
	s.NICs[0].MAC = "52:54:00:aa:bb:cc" // not in the sim's ARP table
	if _, err := e.m.Create(ctx, CreateArgs{Spec: s, Password: "Windows pass 1", StreamingPassword: streamPW}); err != nil {
		t.Fatal(err)
	}
	BootKeyPresses = 0
	if _, err := e.m.Start(ctx, "game"); err != nil {
		t.Fatal(err)
	}
	// The guest claims an address: root only knocks on it, and without
	// the ARP table agreeing nothing is used.
	e.m.statsMu.Lock()
	if e.m.addrs == nil {
		e.m.addrs = map[string][]string{}
	}
	e.m.addrs["game"] = []string{"192.168.1.1", "8.8.8.8"}
	e.m.statsMu.Unlock()
	var dialled []string
	e.m.streamDial = func(_ context.Context, a string) error { dialled = append(dialled, a); return nil }
	info, err := e.m.StreamingInfo(ctx, "game")
	if err != nil || info.Address != "" || info.Problem == "" {
		t.Fatalf("info %+v %v", info, err)
	}
	if len(dialled) != 1 || dialled[0] != "192.168.1.1:47990" {
		t.Fatalf("knocked on %v", dialled)
	}
}
