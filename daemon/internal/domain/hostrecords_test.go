package domain

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func hostRecordsManager(t *testing.T, taken string) (*Manager, *sysexec.Fake, string) {
	t.Helper()
	f := &sysexec.Fake{}
	m := testManager(t, f)
	if err := os.MkdirAll(m.dataPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := m.save(&Config{Domain: "home.example.net", Realm: "HOME.EXAMPLE.NET", NetBIOS: "HOME", Address: "192.168.1.20/24", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	f.On("systemctl is-active --quiet hardyos-dc.service", "")
	f.On(AdminTool+" "+m.SmbConf()+" names.taken", `{"taken":[`+taken+`]}`)
	return m, f, "ip netns exec hardyos-dc samba-tool dns "
}

func countPrefix(lines []string, p string) int {
	n := 0
	for _, l := range lines {
		if strings.HasPrefix(l, p) {
			n++
		}
	}
	return n
}

var allowedLabels = []string{"nas", "sso", "files", "photos", "wpad", "fileserver"}

func TestHostRecordsOwnZone(t *testing.T) {
	m, f, st := hostRecordsManager(t, `"fileserver"`)
	ctx := context.Background()
	for _, bad := range []HostRecordsArgs{
		{Base: "lan.example.org", Address: "192.168.1.20", Labels: []string{"nas"}}, // the DC's own address
		{Base: "lan.example.org", Address: "127.0.0.1", Labels: []string{"nas"}},
		{Base: "lan.example.org", Address: "fe80::1", Labels: []string{"nas"}},
		{Base: "lan.example.org", Address: "192.168.1.105", Labels: []string{"a b"}},
		{Base: "lan.example.org", Address: "192.168.1.105", Labels: []string{"x.y"}},
		{Base: "org", Address: "192.168.1.105", Labels: []string{"nas"}},
		{Base: "lan.example.org; rm", Address: "192.168.1.105", Labels: []string{"nas"}},
		{Base: "example.org", Address: "192.168.1.105", Labels: []string{"nas"}, Allowed: allowedLabels, PublicApex: true},
	} {
		if bad.Allowed == nil {
			bad.Allowed = allowedLabels
		}
		if _, err := m.SetHostRecords(ctx, bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if n := countPrefix(f.Lines(), st); n != 0 {
		t.Fatalf("bad input ran samba-tool %d times", n)
	}
	f.OnPrefix(st+"zonecreate 127.0.0.1 lan.example.org ", sysexec.Result{})
	f.OnPrefix(st+"add 127.0.0.1 lan.example.org ", sysexec.Result{})
	f.OnPrefix(st+"query 127.0.0.1 lan.example.org photos ", sysexec.Result{Stdout: []byte("  Name=, Records=1, Children=0\n    A: 192.168.1.50\n")})
	f.OnPrefix(st+"query 127.0.0.1 lan.example.org ", sysexec.Result{ExitCode: 255, Stderr: []byte("WERR_DNS_ERROR_NAME_DOES_NOT_EXIST")})
	// "board" isn't one root knows; wpad never; fileserver is a computer.
	res, err := m.SetHostRecords(ctx, HostRecordsArgs{Base: "lan.example.org", Address: "192.168.1.105",
		Labels: []string{"nas", "sso", "photos", "board", "wpad", "fileserver"}, Allowed: allowedLabels})
	if err != nil {
		t.Fatal(err)
	}
	if res.Zone != "lan.example.org" || strings.Join(res.Added, ",") != "nas.lan.example.org,sso.lan.example.org" {
		t.Fatalf("%+v", res)
	}
	for _, s := range []string{"photos", "board", "wpad", "fileserver"} {
		if !strings.Contains(strings.Join(res.Skipped, ","), s+".lan.example.org") {
			t.Errorf("%s not skipped: %+v", s, res.Skipped)
		}
	}
	if countPrefix(f.Lines(), st+"zonecreate") != 1 || countPrefix(f.Lines(), st+"add 127.0.0.1 lan.example.org wpad") != 0 {
		t.Fatalf("%v", f.Lines())
	}
	for _, l := range f.Lines() {
		if strings.HasPrefix(l, st) && !strings.HasSuffix(l, "-P -s "+m.SmbConf()) {
			t.Errorf("not the machine account: %s", l)
		}
	}
	// Fewer names: only HardyOS's own record is removed, never photos.
	f.On(st+"zoneinfo 127.0.0.1 lan.example.org -P -s "+m.SmbConf(), "zone")
	f.OnPrefix(st+"delete 127.0.0.1 lan.example.org sso A 192.168.1.105 ", sysexec.Result{})
	res, err = m.SetHostRecords(ctx, HostRecordsArgs{Base: "lan.example.org", Address: "192.168.1.105", Labels: []string{"nas"}, Allowed: allowedLabels})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Kept, ",") != "nas.lan.example.org" || strings.Join(res.Removed, ",") != "sso.lan.example.org" {
		t.Fatalf("%+v", res)
	}
	if countPrefix(f.Lines(), st+"delete 127.0.0.1 lan.example.org photos") != 0 {
		t.Fatalf("%v", f.Lines())
	}
	// Removing: no base, address or allowed list needed; the zone HardyOS
	// made goes too.
	f.OnPrefix(st+"delete 127.0.0.1 lan.example.org nas A 192.168.1.105 ", sysexec.Result{})
	f.OnPrefix(st+"zonedelete 127.0.0.1 lan.example.org ", sysexec.Result{})
	res, err = m.RemoveHostRecords(ctx)
	if err != nil || strings.Join(res.Removed, ",") != "nas.lan.example.org" {
		t.Fatalf("%+v %v", res, err)
	}
	if countPrefix(f.Lines(), st+"zonedelete") != 1 {
		t.Fatal("zone kept")
	}
	if s, _ := m.loadHostRecords(); len(s.Records) != 0 || len(s.Zones) != 0 {
		t.Fatalf("%+v", s)
	}
}

func TestHostRecordsDirectoryCheckFailsClosed(t *testing.T) {
	f := &sysexec.Fake{}
	m := testManager(t, f)
	_ = os.MkdirAll(m.dataPath(), 0o700)
	_ = m.save(&Config{Domain: "home.example.net", Address: "192.168.1.20/24", Enabled: true})
	f.On("systemctl is-active --quiet hardyos-dc.service", "")
	// The directory helper isn't answering: no records.
	if _, err := m.SetHostRecords(context.Background(), HostRecordsArgs{Base: "home.example.net", Address: "192.168.1.105",
		Labels: []string{"nas"}, Allowed: allowedLabels}); err == nil {
		t.Fatal("published without checking the directory")
	}
	for _, l := range f.Lines() {
		if strings.Contains(l, "dns add") {
			t.Fatal(l)
		}
	}
}

func TestHostRecordsInsideTheADZone(t *testing.T) {
	m, f, st := hostRecordsManager(t, "")
	f.OnPrefix(st+"query ", sysexec.Result{ExitCode: 255})
	f.OnPrefix(st+"add 127.0.0.1 home.example.net ", sysexec.Result{})
	// The base is the AD domain: names go straight into its zone, no zone
	// is made, even when it's a Cloudflare zone apex (nothing is hidden).
	res, err := m.SetHostRecords(context.Background(), HostRecordsArgs{Base: "home.example.net", Address: "192.168.1.105",
		Labels: []string{"photos"}, Allowed: allowedLabels, PublicApex: true})
	if err != nil || res.Zone != "home.example.net" || strings.Join(res.Added, ",") != "photos.home.example.net" {
		t.Fatalf("%+v %v", res, err)
	}
	// A base inside the AD domain: relative names in its zone.
	res, err = m.SetHostRecords(context.Background(), HostRecordsArgs{Base: "apps.home.example.net", Address: "192.168.1.105",
		Labels: []string{"photos"}, Allowed: allowedLabels})
	if err != nil || res.Zone != "home.example.net" || strings.Join(res.Added, ",") != "photos.apps.home.example.net" {
		t.Fatalf("%+v %v", res, err)
	}
	if countPrefix(f.Lines(), st+"zone") != 0 {
		t.Fatalf("made a zone: %v", f.Lines())
	}
}
