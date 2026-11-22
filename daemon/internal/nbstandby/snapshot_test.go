package nbstandby

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func TestSealRoundTripAndTamper(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	for _, size := range []int{0, 1, chunkSize - 1, chunkSize, chunkSize + 1, 3*chunkSize + 17} {
		plain := make([]byte, size)
		rand.Read(plain)
		var sealed bytes.Buffer
		w, err := NewSealWriter(&sealed, key)
		if err != nil {
			t.Fatal(err)
		}
		// Uneven writes.
		for p := plain; len(p) > 0; {
			n := min(len(p), 70000)
			w.Write(p[:n])
			p = p[n:]
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		r, err := OpenReader(bytes.NewReader(sealed.Bytes()), key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("size %d: %v", size, err)
		}
		if bytes.Contains(sealed.Bytes(), plain[:min(size, 64)]) && size >= 64 {
			t.Fatal("plain text in the sealed file")
		}
		b := sealed.Bytes()
		// Truncated (the final chunk dropped), trailing data, a flipped
		// bit, another key: all refused.
		bad := map[string][]byte{
			"trailing": append(append([]byte{}, b...), 0),
			"flipped":  flip(b, len(b)-5),
		}
		if size > chunkSize {
			bad["truncated"] = b[:len(sealMagic)+fileIDLen+4+chunkSize+16]
		}
		for what, c := range bad {
			r, err := OpenReader(bytes.NewReader(c), key)
			if err == nil {
				_, err = io.ReadAll(r)
			}
			if err == nil {
				t.Errorf("size %d: %s accepted", size, what)
			}
		}
		other := make([]byte, 32)
		rand.Read(other)
		if r, err := OpenReader(bytes.NewReader(b), other); err == nil {
			if _, err := io.ReadAll(r); err == nil {
				t.Fatal("opened with another key")
			}
		}
	}
}

func flip(b []byte, i int) []byte {
	c := append([]byte{}, b...)
	c[i] ^= 1
	return c
}

func TestCheckSnapshot(t *testing.T) {
	snap := makeSnapshot(t, defaultFiles(t), nil)
	info, err := Check(bytes.NewReader(snap), testHost, nil)
	if err != nil {
		t.Fatal(err)
	}
	if info.Peers != 7 || info.Version != "0.83.1" || info.Bytes != int64(len(snap)) || len(info.SHA256) != 64 ||
		info.CertNotAfter.Year() != 2027 || len(info.Files) != 5 {
		t.Fatalf("%+v", info)
	}
	// Each of these must be refused.
	cases := map[string][]byte{}
	f := defaultFiles(t)
	f["config/../etc/passwd"] = []byte("x")
	cases["traversal"] = makeSnapshot(t, f, nil)
	f = defaultFiles(t)
	f["data/other.db"] = sqliteFile("x")
	cases["unknown entry"] = makeSnapshot(t, f, nil)
	f = defaultFiles(t)
	f[EntryStore] = []byte("not sqlite at all")
	cases["not sqlite"] = makeSnapshot(t, f, nil)
	f = defaultFiles(t)
	delete(f, EntryStore)
	cases["no store"] = makeSnapshot(t, f, nil)
	cases["hash mismatch"] = makeSnapshot(t, defaultFiles(t), func(m *Manifest) { m.Files[EntryStore] = strings.Repeat("0", 64) })
	cases["unlisted file"] = makeSnapshot(t, defaultFiles(t), func(m *Manifest) { delete(m.Files, EntryIDP) })
	cases["other host"] = makeSnapshot(t, defaultFiles(t), func(m *Manifest) { m.Hostname = "evil.example.net" })
	cases["postgres"] = makeSnapshot(t, defaultFiles(t), func(m *Manifest) { m.Engine = "postgres" })
	cases["format"] = makeSnapshot(t, defaultFiles(t), func(m *Manifest) { m.Format = 2 })
	f = defaultFiles(t)
	f[EntryConfig] = []byte(strings.Replace(testConfig, "vpn.example.net:443", "evil.example.net:443", 1))
	cases["config host"] = makeSnapshot(t, f, nil)
	f = defaultFiles(t)
	f[EntryConfig] = []byte(strings.Replace(testConfig, `engine: "sqlite"`, `engine: "postgres"`, 1))
	cases["config postgres"] = makeSnapshot(t, f, nil)
	f = defaultFiles(t)
	f[EntryServerEnv] = []byte("LD_PRELOAD=/x\n")
	cases["other env"] = makeSnapshot(t, f, nil)
	good := defaultFiles(t)
	cases["symlink"] = buildTar(t, []tarEntry{{name: EntryManifest, body: []byte(`{"format":1}`)}, {name: EntryStore, typ: tar.TypeSymlink, link: "/etc/shadow"}})
	cases["manifest not first"] = buildTar(t, []tarEntry{{name: EntryConfig, body: good[EntryConfig]}, {name: EntryManifest, body: []byte(`{}`)}})
	cases["dir first then file"] = buildTar(t, []tarEntry{{name: "config/", typ: tar.TypeDir}, {name: EntryConfig, body: good[EntryConfig]}})
	cases["twice"] = buildTar(t, []tarEntry{{name: EntryManifest, body: []byte(`{}`)}, {name: EntryConfig, body: good[EntryConfig]}, {name: "./" + EntryConfig, body: good[EntryConfig]}})
	cases["not a tar"] = []byte("hello")
	big := make([]byte, entryLimits[EntryConfig]+1)
	cases["too big"] = buildTar(t, []tarEntry{{name: EntryManifest, body: []byte(`{}`)}, {name: EntryConfig, body: big}})
	for name, b := range cases {
		if _, err := Check(bytes.NewReader(b), testHost, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Check(bytes.NewReader(snap), "", nil); err == nil {
		t.Fatal("no hostname accepted")
	}
}

func TestFilterACME(t *testing.T) {
	b := testACME(t, testHost, time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC))
	var store map[string]map[string]any
	json.Unmarshal(b, &store)
	first := store["letsencrypt"]["Certificates"].([]any)[0].(map[string]any)
	other := map[string]any{"domain": map[string]any{"main": "other.example.net"}, "certificate": first["certificate"], "key": "OTHERKEY"}
	store["letsencrypt"]["Certificates"] = append(store["letsencrypt"]["Certificates"].([]any), other)
	b, _ = json.Marshal(store)
	out, err := FilterACME(b, testHost)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("Account")) || bytes.Contains(out, []byte("OTHERKEY")) {
		t.Fatalf("%s", out)
	}
	if _, ok := acmeNotAfter(out, testHost); !ok {
		t.Fatal("certificate lost")
	}
	if _, err := FilterACME([]byte("nope"), testHost); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestCheckConfigAndFold(t *testing.T) {
	host, warn, err := CheckConfig([]byte(testConfig))
	if err != nil || host != testHost || len(warn) != 0 {
		t.Fatal(host, warn, err)
	}
	for _, bad := range []string{
		"server:\n  listenAddress: \":80\"\n",
		strings.Replace(testConfig, `dataDir: "/var/lib/netbird"`, `dataDir: "/srv/nb"`, 1),
		strings.Replace(testConfig, "  store:\n", "  store:\n    dsn: \"host=db\"\n", 1),
		strings.Replace(testConfig, "  store:\n", "  store:\n    file: \"/tmp/x.db\"\n", 1),
		strings.Replace(testConfig, "https://vpn", "http://vpn", 1),
	} {
		if _, _, err := CheckConfig([]byte(bad)); err == nil {
			t.Errorf("accepted:\n%s", bad)
		}
	}
	out, err := FoldSecrets([]byte(testConfig), map[string]string{"NB_STORE_ENCRYPTION_KEY": "bmV3a2V5", "NB_AUTH_SECRET": "newsecret"})
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := configValue(out, "server.store.encryptionKey"); v != "bmV3a2V5" {
		t.Fatalf("%s", out)
	}
	if v, _ := configValue(out, "server.authSecret"); v != "newsecret" {
		t.Fatalf("%s", out)
	}
	if v, _ := configValue(out, "server.auth.issuer"); v != "https://vpn.example.net/oauth2" {
		t.Fatal("other lines changed")
	}
	if _, err := FoldSecrets([]byte(testConfig), map[string]string{"NB_AUTH_SECRET": `x"; rm -rf /`}); err == nil {
		t.Fatal("quote accepted")
	}
	if _, err := FoldSecrets([]byte("server:\n  x: 1\n"), map[string]string{"NB_AUTH_SECRET": "abc"}); err == nil {
		t.Fatal("missing line accepted")
	}
	// The VPS setting a secret in the environment without a line for it in
	// config.yaml is refused at sync (it couldn't be carried).
	f := defaultFiles(t)
	f[EntryConfig] = []byte(strings.Replace(testConfig, `  authSecret: "relaysecret"`+"\n", "", 1))
	f[EntryServerEnv] = []byte("NB_AUTH_SECRET=abc\n")
	if _, err := Check(bytes.NewReader(makeSnapshot(t, f, nil)), testHost, nil); err == nil {
		t.Fatal("uncarried env accepted")
	}
}

func TestScript(t *testing.T) {
	_, pub, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := Script(ScriptSetup{Hostname: testHost, PublicKey: pub, From: []string{"100.64.0.5", "203.0.113.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	keyLine := `restrict,command="/usr/local/sbin/hardyos-netbird-standby",from="100.64.0.5,203.0.113.0/24" ` + pub
	if !strings.Contains(s, keyLine) {
		t.Fatal("authorized_keys line missing")
	}
	// The forced command takes exactly three verbs; restore needs the
	// opt-in twice (sudoers and the root script).
	for _, want := range []string{
		`status|snapshot|restore|fence|unfence) exec sudo -n /usr/local/sbin/hardyos-netbird-standby-root "$SSH_ORIGINAL_COMMAND" ;;`,
		`[ -f "$ARM" ] || fail "hand-back isn't armed`,
		`rm -f "$ARM" # one use`,
		`[ "${SUDO_USER:-}" != hardyos-standby ] || fail "refused"`,
		`rule="$rule, /usr/local/sbin/hardyos-netbird-standby-root restore, /usr/local/sbin/hardyos-netbird-standby-root fence, /usr/local/sbin/hardyos-netbird-standby-root unfence"`,
		`runuser -u nobody -- sqlite3 -safe -batch -noheader "$1" "PRAGMA trusted_schema=OFF; $2"`,
		`trap cleanup EXIT`,
		`visudo -cf "$tmp_sudo"`,
		`ssh-keygen -lf /var/lib/hardyos-standby/.ssh/authorized_keys`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	if strings.Contains(s, "@@") || strings.Contains(s, "allow-restore ]") {
		t.Fatal("unfilled placeholder or the old marker in the script")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "s.sh")
	os.WriteFile(p, []byte(s), 0o600)
	if out, err := exec.Command("bash", "-n", p).CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, out)
	}
	// The embedded scripts too.
	for _, part := range []string{"FORCED", "ROOT"} {
		i := strings.Index(s, "<<'"+part+"'\n")
		j := strings.Index(s, "\n"+part+"\n")
		if i < 0 || j < i {
			t.Fatalf("no %s part", part)
		}
		body := s[i+len("<<'"+part+"'\n") : j]
		pp := filepath.Join(dir, part)
		os.WriteFile(pp, []byte(body), 0o600)
		shell := "bash"
		if part == "FORCED" {
			shell = "sh"
		}
		if out, err := exec.Command(shell, "-n", pp).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", part, err, out)
		}
		if sc, err := exec.LookPath("shellcheck"); err == nil {
			if out, err := exec.Command(sc, "-S", "warning", pp).CombinedOutput(); err != nil {
				t.Errorf("shellcheck %s:\n%s", part, out)
			}
		}
	}
	if sc, err := exec.LookPath("shellcheck"); err == nil {
		if out, err := exec.Command(sc, "-S", "warning", p).CombinedOutput(); err != nil {
			t.Errorf("shellcheck:\n%s", out)
		}
	}
	for _, bad := range []ScriptSetup{
		{Hostname: "x", PublicKey: pub},
		{Hostname: testHost, PublicKey: "ssh-rsa AAAA"},
		{Hostname: testHost, PublicKey: pub, From: []string{`1.2.3.4" ssh-rsa`}},
		{Hostname: testHost, PublicKey: pub + "\nssh-ed25519 AAAA other"},
	} {
		if _, err := Script(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

// TestForcedCommand runs the forced command with a stub sudo: only the
// three verbs reach the root script, as one argument.
func TestForcedCommand(t *testing.T) {
	_, pub, _ := NewKey()
	s, _ := Script(ScriptSetup{Hostname: testHost, PublicKey: pub})
	i := strings.Index(s, "<<'FORCED'\n")
	j := strings.Index(s, "\nFORCED\n")
	body := s[i+len("<<'FORCED'\n") : j]
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "forced"), []byte(body), 0o700)
	os.WriteFile(filepath.Join(dir, "sudo"), []byte("#!/bin/sh\necho \"sudo:$#:$*\"\n"), 0o700)
	run := func(cmd string) (string, error) {
		c := exec.Command("sh", filepath.Join(dir, "forced"))
		c.Env = []string{"PATH=" + dir + ":/usr/bin:/bin", "SSH_ORIGINAL_COMMAND=" + cmd}
		out, err := c.CombinedOutput()
		return string(out), err
	}
	for _, v := range []string{"status", "snapshot", "restore", "fence", "unfence"} {
		out, err := run(v)
		if err != nil || strings.TrimSpace(out) != "sudo:3:-n /usr/local/sbin/hardyos-netbird-standby-root "+v {
			t.Fatalf("%s: %q %v", v, out, err)
		}
	}
	for _, bad := range []string{"", "bash", "status; id", "snapshot x", "status\nid", "$(id)", "restore --all", "arm-restore 24h", "arm-restore"} {
		out, err := run(bad)
		if err == nil || strings.Contains(out, "sudo:") {
			t.Errorf("%q ran: %q", bad, out)
		}
	}
}

func TestNetRules(t *testing.T) {
	closed := NFTRules(false)
	if !strings.Contains(closed, "tcp dport { 44620, 44621 } drop") || !strings.Contains(closed, "udp dport 44622 drop") ||
		!strings.Contains(closed, `iifname "lo" accept`) || strings.Contains(closed, "dnat") ||
		!strings.Contains(closed, "ip saddr != 172.16.253.16/28 ip daddr 172.16.253.16/28 drop") || !strings.Contains(closed, "ip daddr 172.16.253.16/28 drop") {
		t.Fatal(closed)
	}
	open := NFTRules(true)
	for _, want := range []string{"ip daddr 127.0.77.1 tcp dport 443 dnat ip to 127.0.0.1:44621", "ip daddr 127.0.77.1 tcp dport 80 dnat ip to 127.0.0.1:44620",
		"ip daddr 127.0.77.1 udp dport 3478 dnat ip to 127.0.0.1:44622"} {
		if !strings.Contains(open, want) {
			t.Errorf("open lacks %q", want)
		}
	}
	if strings.Contains(open, "drop") {
		t.Fatal("open still drops")
	}
	// nft's own syntax check, where nft can run (root with netlink).
	if nft, err := exec.LookPath("nft"); err == nil && os.Geteuid() == 0 {
		probe := exec.Command(nft, "-c", "-f", "-")
		probe.Stdin = strings.NewReader("table inet hardyos_probe {\n}\n")
		if probe.Run() == nil {
			for _, r := range []string{closed, open, NFTRemove()} {
				c := exec.Command(nft, "-c", "-f", "-")
				c.Stdin = strings.NewReader(r)
				if out, err := c.CombinedOutput(); err != nil {
					t.Errorf("nft -c: %v\n%s\n%s", err, out, r)
				}
			}
		}
	}
	old := []byte("127.0.0.1\tlocalhost\n::1\tlocalhost\n")
	on, err := UpdateHosts(old, testHost)
	if err != nil || !hasLine(string(on), "127.0.77.1\tvpn.example.net") || !strings.HasPrefix(string(on), string(old)) {
		t.Fatalf("%q %v", on, err)
	}
	again, _ := UpdateHosts(on, testHost)
	if !bytes.Equal(again, on) {
		t.Fatal("not idempotent")
	}
	off, _ := UpdateHosts(on, "")
	if !bytes.Equal(off, old) {
		t.Fatalf("%q", off)
	}
	if _, err := UpdateHosts(old, "evil host\n1.2.3.4 bank.com"); err == nil {
		t.Fatal("bad hostname accepted")
	}
	// The take-over needs Docker's userland proxy.
	dockerDir := t.TempDir()
	os.MkdirAll(filepath.Join(dockerDir, "etc", "docker"), 0o755)
	os.WriteFile(filepath.Join(dockerDir, "etc", "hosts"), old, 0o644)
	os.WriteFile(filepath.Join(dockerDir, "etc", "docker", "daemon.json"), []byte(`{"userland-proxy": false}`), 0o644)
	if err := (&System{Runner: okRunner{}, Root: dockerDir}).Apply(t.Context(), true, testHost); err == nil || !strings.Contains(err.Error(), "userland") {
		t.Fatalf("userland proxy off: %v", err)
	}
	// The System applier writes /etc/hosts under its root.
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc", "hosts"), old, 0o644)
	sys := &System{Runner: okRunner{}, Root: root}
	if err := sys.Apply(t.Context(), true, testHost); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(root, "etc", "hosts"))
	if !hasLine(string(b), "127.0.77.1\tvpn.example.net") {
		t.Fatalf("%s", b)
	}
	if err := sys.Apply(t.Context(), false, testHost); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(root, "etc", "hosts"))
	if !bytes.Equal(b, old) {
		t.Fatalf("%s", b)
	}
}

type okRunner struct{}

func (okRunner) Run(context.Context, []byte, string, ...string) (sysexec.Result, error) {
	return sysexec.Result{}, nil
}
