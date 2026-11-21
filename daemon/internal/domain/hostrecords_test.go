package domain

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func hostRecordsManager(t *testing.T) (*Manager, *sysexec.Fake, string) {
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

func TestHostRecordsOwnZone(t *testing.T) {
	m, f, st := hostRecordsManager(t)
	ctx := context.Background()
	for _, bad := range []HostRecordsArgs{
		{Base: "lan.example.org", Address: "192.168.1.20", Labels: []string{"nas"}}, // the DC's own address
		{Base: "lan.example.org", Address: "127.0.0.1", Labels: []string{"nas"}},
		{Base: "lan.example.org", Address: "fe80::1", Labels: []string{"nas"}},
		{Base: "lan.example.org", Address: "192.168.1.105", Labels: []string{"a b"}},
		{Base: "lan.example.org", Address: "192.168.1.105", Labels: []string{"x.y"}},
		{Base: "org", Address: "192.168.1.105", Labels: []string{"nas"}},
		{Base: "lan.example.org; rm", Address: "192.168.1.105", Labels: []string{"nas"}},
	} {
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
	res, err := m.SetHostRecords(ctx, HostRecordsArgs{Base: "lan.example.org", Address: "192.168.1.105", Labels: []string{"nas", "sso", "photos"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Zone != "lan.example.org" || strings.Join(res.Added, ",") != "nas.lan.example.org,sso.lan.example.org" ||
		strings.Join(res.Skipped, ",") != "photos.lan.example.org" {
		t.Fatalf("%+v", res)
	}
	if countPrefix(f.Lines(), st+"zonecreate") != 1 {
		t.Fatal("zone not made")
	}
	for _, l := range f.Lines() {
		if strings.HasPrefix(l, st) && !strings.HasSuffix(l, "-P -s "+m.SmbConf()) {
			t.Errorf("not the machine account: %s", l)
		}
	}
	// Fewer names: only HardyOS's own record is removed, never photos.
	f.On(st+"zoneinfo 127.0.0.1 lan.example.org -P -s "+m.SmbConf(), "zone")
	f.OnPrefix(st+"delete 127.0.0.1 lan.example.org sso A 192.168.1.105 ", sysexec.Result{})
	res, err = m.SetHostRecords(ctx, HostRecordsArgs{Base: "lan.example.org", Address: "192.168.1.105", Labels: []string{"nas"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Kept, ",") != "nas.lan.example.org" || strings.Join(res.Removed, ",") != "sso.lan.example.org" {
		t.Fatalf("%+v", res)
	}
	if countPrefix(f.Lines(), st+"delete") != 1 || countPrefix(f.Lines(), st+"delete 127.0.0.1 lan.example.org photos") != 0 {
		t.Fatalf("%v", f.Lines())
	}
	// None: everything HardyOS added goes.
	f.OnPrefix(st+"delete 127.0.0.1 lan.example.org nas A 192.168.1.105 ", sysexec.Result{})
	res, err = m.SetHostRecords(ctx, HostRecordsArgs{Base: "lan.example.org", Address: "192.168.1.105"})
	if err != nil || strings.Join(res.Removed, ",") != "nas.lan.example.org" {
		t.Fatalf("%+v %v", res, err)
	}
	if s, _ := m.loadHostRecords(); len(s.Records) != 0 {
		t.Fatalf("%+v", s)
	}
}

func TestHostRecordsInsideTheADZone(t *testing.T) {
	m, f, st := hostRecordsManager(t)
	f.OnPrefix(st+"query ", sysexec.Result{ExitCode: 255})
	f.OnPrefix(st+"add 127.0.0.1 example.net ", sysexec.Result{})
	f.OnPrefix(st+"add 127.0.0.1 home.example.net ", sysexec.Result{})
	// The base is the AD domain: names go straight into its zone, no zone
	// is made.
	res, err := m.SetHostRecords(context.Background(), HostRecordsArgs{Base: "home.example.net", Address: "192.168.1.105", Labels: []string{"photos"}})
	if err != nil || res.Zone != "home.example.net" || strings.Join(res.Added, ",") != "photos.home.example.net" {
		t.Fatalf("%+v %v", res, err)
	}
	// A base inside the AD domain: relative names in its zone.
	res, err = m.SetHostRecords(context.Background(), HostRecordsArgs{Base: "apps.home.example.net", Address: "192.168.1.105", Labels: []string{"photos"}})
	if err != nil || res.Zone != "home.example.net" || strings.Join(res.Added, ",") != "photos.apps.home.example.net" {
		t.Fatalf("%+v %v", res, err)
	}
	if countPrefix(f.Lines(), st+"zone") != 0 {
		t.Fatalf("made a zone: %v", f.Lines())
	}
	// The earlier record (another base now) was removed.
	if strings.Join(res.Removed, ",") != "photos.home.example.net" {
		// The delete wasn't stubbed: it stays to be tried again.
		if s, _ := m.loadHostRecords(); len(s.Records) != 2 {
			t.Fatalf("%+v %+v", res, s)
		}
	}
}
