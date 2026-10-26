package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/network"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func sample() Contents {
	return Contents{
		Manifest: Manifest{CreatedAt: time.Date(2026, 10, 25, 3, 15, 0, 0, time.UTC), Version: "0.2.0", Hostname: "nas", Schema: 7, Users: 2},
		DB:       []byte("SQLite format 3\x00 pretend"),
		Files: []File{
			{Path: "var/lib/hardyos/network/settings.json", Mode: 0o644, Data: []byte(`{"hostname":"nas"}`)},
			{Path: "var/lib/hardyos/tls/server.key", Mode: 0o600, Data: []byte("KEY")},
		},
	}
}

func TestPackUnpack(t *testing.T) {
	b, err := Pack(sample(), "")
	if err != nil {
		t.Fatal(err)
	}
	if enc, _ := Encrypted(b); enc {
		t.Fatal("no password should mean not encrypted")
	}
	c, err := Unpack(b, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(c.DB) != string(sample().DB) || len(c.Files) != 2 || c.Manifest.Hostname != "nas" || c.Manifest.Users != 2 || c.Manifest.Secrets {
		t.Fatalf("round trip = %+v", c)
	}
	if c.Files[1].Mode != 0o600 {
		t.Fatalf("mode = %o", c.Files[1].Mode)
	}
}

func TestEncrypted(t *testing.T) {
	c := sample()
	c.Files = append(c.Files, File{Path: "var/lib/hardyos/keys/tank.key", Mode: 0o600, Data: []byte("0123456789abcdef0123456789abcdef"), Secret: true})
	if _, err := Pack(c, ""); err == nil {
		t.Fatal("keys without a password must be refused")
	}
	b, err := Pack(c, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("0123456789abcdef")) || bytes.Contains(b, []byte("nas")) {
		t.Fatal("contents visible in an encrypted backup")
	}
	if _, err := Unpack(b, ""); !errors.Is(err, ErrNeedPassword) {
		t.Fatalf("no password: %v", err)
	}
	if _, err := Unpack(b, "wrong"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	got, err := Unpack(b, "correct horse")
	if err != nil || !got.Manifest.Secrets || len(got.Files) != 3 {
		t.Fatalf("unpack = %+v %v", got, err)
	}
	// Flipping one byte breaks it.
	b[len(b)-5] ^= 1
	if _, err := Unpack(b, "correct horse"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("tampered: %v", err)
	}
}

func TestRejectsCraftedBackups(t *testing.T) {
	if _, err := Unpack([]byte("PK\x03\x04 a zip"), ""); !errors.Is(err, ErrNotBackup) {
		t.Fatalf("zip: %v", err)
	}
	for _, p := range []string{"etc/shadow", "../etc/passwd", "var/lib/hardyos/keys/../../../etc/cron.d/x", "/etc/passwd", "var/lib/hardyos/keys/sub/x.key", "var/lib/hardyos/keys/x.txt"} {
		if AllowedPath(p) {
			t.Errorf("%q allowed", p)
		}
	}
	for _, p := range []string{"var/lib/hardyos/keys/tank.key", "etc/ssh/ssh_host_ed25519_key", "var/lib/hardyos/tls/server.crt"} {
		if !AllowedPath(p) {
			t.Errorf("%q refused", p)
		}
	}
	// A hand-made archive that sneaks a file in, with a matching manifest.
	evil := func(name string) []byte {
		var tgz bytes.Buffer
		gz := gzip.NewWriter(&tgz)
		tw := tar.NewWriter(gz)
		data := []byte("* * * * * root sh -c 'evil'")
		m := Manifest{Format: FormatVersion, Entries: []EntryInfo{{Path: DBName, Size: 1, SHA256: sha(t, []byte("x"))}, {Path: name, Size: int64(len(data)), SHA256: sha(t, data)}}}
		mb, _ := json.Marshal(m)
		for _, e := range []struct {
			n string
			b []byte
		}{{ManifestName, mb}, {DBName, []byte("x")}, {name, data}} {
			_ = tw.WriteHeader(&tar.Header{Name: e.n, Mode: 0o644, Size: int64(len(e.b)), Typeflag: tar.TypeReg})
			_, _ = tw.Write(e.b)
		}
		_ = tw.Close()
		_ = gz.Close()
		return append([]byte(magic+"\x00"), tgz.Bytes()...)
	}
	for _, name := range []string{"files/etc/cron.d/evil", "files/../../etc/cron.d/evil", "etc/cron.d/evil"} {
		if _, err := Unpack(evil(name), ""); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func sha(t *testing.T, b []byte) string {
	t.Helper()
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// --- root side ---

func newRoot(t *testing.T) (*Root, *sysexec.Fake, string) {
	t.Helper()
	root := t.TempDir()
	write := func(rel, s string, mode os.FileMode) {
		p := filepath.Join(root, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(s), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("var/lib/hardyos/network/settings.json", `{"hostname":"nas","dns":["192.168.1.1"],"search":[],"interfaces":[{"name":"eno1","mode":"static","address":"192.168.1.20/24","gateway":"192.168.1.1"}],"bonds":[],"vlans":[]}`, 0o644)
	write("var/lib/hardyos/network/time.json", `{"timezone":"America/Denver","ntp":true,"ntpServers":[]}`, 0o644)
	write("var/lib/hardyos/tls/server.crt", "CERT", 0o644)
	write("var/lib/hardyos/tls/server.key", "TLSKEY", 0o600)
	write("var/lib/hardyos/keys/tank.key", "POOLKEY", 0o600)
	write("etc/ssh/ssh_host_ed25519_key", "SSHKEY", 0o600)
	write("etc/ssh/ssh_host_ed25519_key.pub", "SSHPUB", 0o644)
	write("usr/share/zoneinfo/America/Denver", "TZif", 0o644)
	write("etc/network/interfaces", "auto lo\n", 0o644)
	write("etc/hostname", "hardyos\n", 0o644)
	_ = os.MkdirAll(filepath.Join(root, WorkDir), 0o750)
	_ = os.MkdirAll(filepath.Join(root, "tank/hardyos-backups"), 0o755)
	fake := &sysexec.Fake{}
	fake.On("zpool list -H -o name", "rpool\ntank\n")
	fake.On("zfs get -H -o value mountpoint tank/hardyos-backups", "/tank/hardyos-backups\n")
	for _, p := range []string{"hostname ", "systemctl ", "ifdown ", "ifup ", "ifquery "} {
		fake.OnPrefix(p, sysexec.Result{})
	}
	netm := &network.Manager{Runner: fake, Root: root, Ports: func() []string { return []string{"eno1"} }}
	return &Root{Runner: fake, Root: root, UID: -1, GID: -1, Network: netm, Now: func() time.Time { return time.Date(2026, 10, 25, 3, 15, 0, 0, time.UTC) }}, fake, root
}

func TestCollect(t *testing.T) {
	r, _, _ := newRoot(t)
	files, err := r.Collect(false)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, f.Path)
		if f.Secret {
			t.Errorf("%s is secret in a plain backup", f.Path)
		}
	}
	if len(files) != 4 {
		t.Fatalf("plain backup = %v", names)
	}
	files, _ = r.Collect(true)
	secrets := 0
	for _, f := range files {
		if f.Secret {
			secrets++
		}
	}
	if len(files) != 7 || secrets != 2 { // pool key + ssh private key; the .pub isn't secret
		t.Fatalf("with secrets: %d files, %d secret", len(files), secrets)
	}
}

func TestStoreListFetchStageApply(t *testing.T) {
	r, _, root := newRoot(t)
	ctx := context.Background()
	files, _ := r.Collect(false)
	c := sample()
	c.Files = files
	b, _ := Pack(c, "")
	src := filepath.Join(root, WorkDir, "made-1.hbak")
	_ = os.WriteFile(src, b, 0o640)

	if _, err := r.Store(ctx, "rpool", src, 3); err == nil {
		t.Fatal("boot pool accepted")
	}
	if _, err := r.Store(ctx, "tank", filepath.Join(root, "etc/hostname"), 3); err == nil {
		t.Fatal("file outside the work directory accepted")
	}
	// Keep 3 of 5.
	for i := 0; i < 5; i++ {
		c.Manifest.CreatedAt = c.Manifest.CreatedAt.Add(24 * time.Hour)
		b, _ := Pack(c, "")
		_ = os.WriteFile(src, b, 0o640)
		if _, err := r.Store(ctx, "tank", src, 3); err != nil {
			t.Fatal(err)
		}
	}
	list, err := r.List(ctx)
	if err != nil || len(list) != 3 || list[0].Manifest.CreatedAt.Day() != 30 || list[0].Pool != "tank" {
		t.Fatalf("list = %+v %v", list, err)
	}
	// Secrets never go on a pool.
	enc, _ := Pack(Contents{Manifest: c.Manifest, DB: c.DB, Files: []File{{Path: "var/lib/hardyos/keys/tank.key", Mode: 0o600, Data: []byte("k"), Secret: true}}}, "pw123456")
	_ = os.WriteFile(src, enc, 0o640)
	if _, err := r.Store(ctx, "tank", src, 3); err == nil {
		t.Fatal("encrypted backup with keys stored on a pool")
	}

	path, err := r.Fetch(ctx, "tank", list[0].Name)
	if err != nil || !strings.HasPrefix(path, filepath.Join(root, WorkDir)+"/") {
		t.Fatalf("fetch = %q %v", path, err)
	}
	if _, err := r.Fetch(ctx, "tank", "../../etc/hostname"); err == nil {
		t.Fatal("traversal fetched")
	}

	// Change things, then restore.
	_ = os.WriteFile(filepath.Join(root, "var/lib/hardyos/tls/server.crt"), []byte("NEWCERT"), 0o644)
	_ = os.WriteFile(filepath.Join(root, StateDir, DBName), []byte("current db"), 0o600)
	_ = os.WriteFile(filepath.Join(root, StateDir, DBName+"-wal"), []byte("wal"), 0o600)
	st, err := r.Stage(path, "")
	if err != nil || st.Manifest.Hostname != "nas" {
		t.Fatalf("stage = %+v %v", st, err)
	}
	if r.PendingRestore() == nil {
		t.Fatal("nothing pending")
	}
	res := r.ApplyPending(ctx)
	if res == nil || !res.OK || len(res.Notes) != 0 {
		t.Fatalf("apply = %+v", res)
	}
	if b, _ := os.ReadFile(filepath.Join(root, StateDir, DBName)); string(b) != string(sample().DB) {
		t.Fatalf("db = %q", b)
	}
	if _, err := os.Stat(filepath.Join(root, StateDir, DBName+"-wal")); err == nil {
		t.Fatal("stale WAL left next to the restored database")
	}
	if b, _ := os.ReadFile(filepath.Join(root, "var/lib/hardyos/tls/server.crt")); string(b) != "CERT" {
		t.Fatalf("cert = %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "etc/network/interfaces")); !strings.Contains(string(b), "address 192.168.1.20/24") {
		t.Fatalf("network not restored:\n%s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "etc/hostname")); string(b) != "nas\n" {
		t.Fatalf("hostname = %q", b)
	}
	if r.PendingRestore() != nil {
		t.Fatal("still pending after apply")
	}
	if lr := r.LastResult(); lr == nil || !lr.OK {
		t.Fatalf("last result = %+v", lr)
	}
	if r.ApplyPending(ctx) != nil {
		t.Fatal("applied twice")
	}
}

func TestApplySkipsNetworkForOtherHardware(t *testing.T) {
	r, _, root := newRoot(t)
	r.Network.Ports = func() []string { return []string{"enp7s0"} } // new machine
	files, _ := r.Collect(false)
	c := sample()
	c.Files = files
	b, _ := Pack(c, "")
	src := filepath.Join(root, WorkDir, "upload-1.hbak")
	_ = os.WriteFile(src, b, 0o640)
	before, _ := os.ReadFile(filepath.Join(root, "etc/network/interfaces"))
	if _, err := r.Stage(src, ""); err != nil {
		t.Fatal(err)
	}
	res := r.ApplyPending(context.Background())
	if !res.OK || len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "don't work on this server") {
		t.Fatalf("result = %+v", res)
	}
	if after, _ := os.ReadFile(filepath.Join(root, "etc/network/interfaces")); string(after) != string(before) {
		t.Fatal("network files changed for hardware they don't fit")
	}
}
