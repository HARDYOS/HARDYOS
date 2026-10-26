package domain

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func tarOf(t *testing.T, entries []*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range entries {
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(h.Name))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			_, _ = tw.Write([]byte(h.Name))
		}
	}
	_ = tw.Close()
	return buf.Bytes()
}

func TestUntarRefusesTricks(t *testing.T) {
	allow := func(top string) bool { return archiveTop[top] }
	good := []*tar.Header{
		{Name: "private/", Typeflag: tar.TypeDir, Mode: 0o700},
		{Name: "private/sam.ldb", Typeflag: tar.TypeReg, Mode: 0o600},
		{Name: "./state/share_info.tdb", Typeflag: tar.TypeReg, Mode: 0o644},
	}
	dest := t.TempDir()
	if err := untar(bytes.NewReader(tarOf(t, good)), dest, allow); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "private/sam.ldb")); string(b) != "private/sam.ldb" {
		t.Fatalf("content = %q", b)
	}
	for name, bad := range map[string][]*tar.Header{
		"escape":    {{Name: "../etc/shadow", Typeflag: tar.TypeReg, Mode: 0o644}},
		"absolute":  {{Name: "/etc/shadow", Typeflag: tar.TypeReg, Mode: 0o644}},
		"symlink":   {{Name: "private/x", Typeflag: tar.TypeSymlink, Linkname: "/etc"}},
		"hardlink":  {{Name: "private/y", Typeflag: tar.TypeLink, Linkname: "/etc/shadow"}},
		"device":    {{Name: "private/z", Typeflag: tar.TypeChar}},
		"elsewhere": {{Name: "root/.ssh/authorized_keys", Typeflag: tar.TypeReg, Mode: 0o600}},
		"deep":      {{Name: "private/../../outside", Typeflag: tar.TypeReg, Mode: 0o600}},
	} {
		d := t.TempDir()
		if err := untar(bytes.NewReader(tarOf(t, bad)), d, allow); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A link planted in the destination is never followed.
	d := t.TempDir()
	_ = os.MkdirAll(filepath.Join(d, "private"), 0o700)
	outside := filepath.Join(t.TempDir(), "victim")
	_ = os.WriteFile(outside, []byte("safe"), 0o644)
	_ = os.Symlink(outside, filepath.Join(d, "private", "sam.ldb"))
	if err := untar(bytes.NewReader(tarOf(t, good[1:2])), d, allow); err == nil {
		t.Error("wrote through a symlink")
	}
	if b, _ := os.ReadFile(outside); string(b) != "safe" {
		t.Error("the file behind the symlink changed")
	}
}

func TestJoinPicksTheNextName(t *testing.T) {
	f := &sysexec.Fake{}
	m := testManager(t, f)
	f.OnPrefix("arping -D", sysexec.Result{})
	f.On("dig +short +time=2 +tries=2 @192.168.1.20 SRV _ldap._tcp.dc._msdcs.home.example.net", "0 100 389 dc1.home.example.net.\n0 100 389 dc2.home.example.net.\n")
	f.On("dig +short +time=2 +tries=2 @192.168.1.20 A dc2.home.example.net", "192.168.1.21\n")
	f.On("dig +short +time=2 +tries=2 @192.168.1.20 A dc3.home.example.net", "")
	// Stop right after the name is chosen: making the dataset fails.
	f.OnResult("findmnt -n -o FSTYPE,SOURCE --target /", sysexec.Result{ExitCode: 1})
	m.DataDir = "/nonexistent-root-only/dc"
	_, err := m.Join(context.Background(), JoinArgs{Domain: "home.example.net", Existing: "192.168.1.20", AdminPassword: "x", Address: "192.168.1.22"})
	if err == nil {
		t.Fatal("join went ahead")
	}
	lines := strings.Join(f.Lines(), "\n")
	if !strings.Contains(lines, "A dc3.home.example.net") {
		t.Errorf("didn't look for dc3:\n%s", lines)
	}

	// No domain there: a clear message.
	f2 := &sysexec.Fake{}
	m2 := testManager(t, f2)
	f2.OnPrefix("arping -D", sysexec.Result{})
	f2.OnPrefix("dig ", sysexec.Result{ExitCode: 9})
	_, err = m2.Join(context.Background(), JoinArgs{Domain: "home.example.net", Existing: "192.168.1.30", AdminPassword: "x", Address: "192.168.1.22"})
	if err == nil || !strings.Contains(err.Error(), "no domain controller for home.example.net answered at 192.168.1.30") {
		t.Errorf("err = %v", err)
	}
	// Its own address can't be the other DC's.
	_, err = m2.Join(context.Background(), JoinArgs{Domain: "home.example.net", Existing: "192.168.1.22", AdminPassword: "x", Address: "192.168.1.22"})
	if err == nil || !strings.Contains(err.Error(), "needs its own") {
		t.Errorf("err = %v", err)
	}
}

func TestLeaveAndDestroyRules(t *testing.T) {
	f := &sysexec.Fake{}
	m := testManager(t, f)
	_ = os.MkdirAll(m.dataPath(), 0o700)
	_ = m.save(&Config{Domain: "home.example.net", Realm: "HOME.EXAMPLE.NET", Address: "192.168.1.21/24", Enabled: true,
		Others: []DC{{Name: "dc1.home.example.net", Address: "192.168.1.20"}}})
	if err := m.Destroy(context.Background(), "home.example.net"); err == nil || !strings.Contains(err.Error(), "remove this one") {
		t.Errorf("destroying a shared domain: %v", err)
	}
	f.OnResult("ip netns exec hardyos-dc samba-tool domain demote -A "+filepath.Join(m.Dir(), ".join-auth")+" --server=dc1.home.example.net -s "+m.SmbConf(),
		sysexec.Result{ExitCode: 255, Stderr: []byte("ERROR: LDAP error 49 LDAP_INVALID_CREDENTIALS -  <8009030C: LdapErr: DSID-0C0904DC, comment: AcceptSecurityContext error, data 52e, v1db1> Logon failure")})
	err := m.Leave(context.Background(), "wrong")
	if err == nil || !strings.Contains(err.Error(), "password isn't right") {
		t.Errorf("leave with a wrong password: %v", err)
	}
	if _, err := os.Stat(m.dataPath(".join-auth")); err == nil {
		t.Error("the credentials file was left behind")
	}
	// A dead DC that still answers isn't removed.
	f.On("dig +short +time=2 +tries=2 @192.168.1.20 SRV _ldap._tcp.home.example.net", "0 100 389 dc1.home.example.net.\n")
	if err := m.RemoveDead(context.Background(), "dc1.home.example.net", "dc1.home.example.net"); err == nil || !strings.Contains(err.Error(), "still answers") {
		t.Errorf("removing a live DC: %v", err)
	}
	if err := m.RemoveDead(context.Background(), "dc1.home.example.net", "nope"); err == nil {
		t.Error("removed without confirmation")
	}
}

func TestSetForwarders(t *testing.T) {
	f := &sysexec.Fake{}
	m := testManager(t, f)
	_ = os.MkdirAll(m.dataPath(), 0o700)
	_ = m.save(&Config{Domain: "home.example.net", Realm: "HOME.EXAMPLE.NET", NetBIOS: "HOME", Address: "192.168.1.20/24", Enabled: false})
	for _, bad := range [][]string{{}, {"nonsense"}, {"127.0.0.1"}, {"192.168.1.20"}, {"1.1.1.1", "8.8.8.8", "9.9.9.9"}} {
		if _, err := m.SetForwarders(context.Background(), bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if _, err := m.SetForwarders(context.Background(), []string{" 9.9.9.9", "1.1.1.1", "9.9.9.9"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(m.dataPath("etc", "smb.conf"))
	if !strings.Contains(string(b), "dns forwarder = 9.9.9.9 1.1.1.1") || !strings.Contains(string(b), "samba_dnsupdate --use-samba-tool") {
		t.Errorf("smb.conf:\n%s", b)
	}
}

func TestConfigDNSServers(t *testing.T) {
	c := Config{Address: "192.168.1.21/24", Others: []DC{{Name: "dc1.x.net", Address: "192.168.1.20"}, {Name: "dc3.x.net"}}}
	if got := strings.Join(c.DNSServers(), ","); got != "192.168.1.21,192.168.1.20" {
		t.Errorf("DNSServers = %s", got)
	}
	if c.HostName() != "dc1" {
		t.Errorf("HostName = %s", c.HostName())
	}
}
