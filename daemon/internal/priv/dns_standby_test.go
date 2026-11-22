package priv

import (
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/cfdns"
)

// The NetBird standby's name (decision 424): one name in the token's zone,
// adopted after the administrator saw its records and typed it; only then
// may dns.record.set point it at a public address, and restore puts it back.
func TestStandbyNameAdoption(t *testing.T) {
	const name = "vpn.example.net" // outside the base home.example.net
	takenOver := false
	s, cf, _, _ := dnsServerWith(t, func() (string, bool) { return name, takenOver })
	if err := dnsCall(t, s, OpDNSStandbyPreview, DNSStandbyNameArgs{Name: name}, nil); err == nil {
		t.Fatal("preview without a token")
	}
	if err := dnsCall(t, s, OpDNSTokenSet, DNSTokenSetArgs{Token: testCFToken, Base: "home.example.net"}, nil); err != nil {
		t.Fatal(err)
	}
	vpsA := cf.Add("example.net", cfdns.Record{Type: "A", Name: name, Content: "198.51.100.10", TTL: 300})
	vpsAAAA := cf.Add("example.net", cfdns.Record{Type: "AAAA", Name: name, Content: "2001:db8::10", TTL: 300, Comment: "vps"})
	cf.Add("example.net", cfdns.Record{Type: "A", Name: "www.example.net", Content: "198.51.100.20", TTL: 300})

	// Before adoption the name is out of reach.
	if err := dnsCall(t, s, OpDNSRecordSet, DNSRecordSetArgs{Name: name, Type: "A", Content: "203.0.113.5"}, nil); err == nil {
		t.Fatal("set a name outside the base before adoption")
	}
	// Names outside the zone, the zone itself, the base, odd names.
	for _, bad := range []string{"example.net", "vpn.example.org", "home.example.net", "_x.example.net", "*.example.net", "vpn.example.net.evil.com"} {
		if err := dnsCall(t, s, OpDNSStandbyPreview, DNSStandbyNameArgs{Name: bad}, nil); err == nil {
			t.Errorf("preview of %s accepted", bad)
		}
	}
	var pv DNSStandbyPreview
	if err := dnsCall(t, s, OpDNSStandbyPreview, DNSStandbyNameArgs{Name: "VPN.example.net."}, &pv); err != nil {
		t.Fatal(err)
	}
	if pv.Name != name || len(pv.Records) != 2 || !pv.Adoptable {
		t.Fatalf("%+v", pv)
	}
	ids := []string{pv.Records[0].ID, pv.Records[1].ID}
	// The typed name must match, and the ids must be exactly what's there.
	if err := dnsCall(t, s, OpDNSStandbyAdopt, DNSStandbyAdoptArgs{Name: name, Confirm: "vpn", IDs: ids}, nil); err == nil {
		t.Fatal("adopted without the typed name")
	}
	if err := dnsCall(t, s, OpDNSStandbyAdopt, DNSStandbyAdoptArgs{Name: name, Confirm: name, IDs: ids[:1]}, nil); err == nil {
		t.Fatal("adopted with a stale preview")
	}
	if err := dnsCall(t, s, OpDNSStandbyAdopt, DNSStandbyAdoptArgs{Name: name, Confirm: name, IDs: ids}, nil); err != nil {
		t.Fatal(err)
	}
	if err := dnsCall(t, s, OpDNSStandbyAdopt, DNSStandbyAdoptArgs{Name: name, Confirm: name, IDs: ids}, nil); err == nil {
		t.Fatal("adopted twice")
	}
	var st DNSStatus
	_ = dnsCall(t, s, OpDNSStatus, struct{}{}, &st)
	if st.Standby == nil || st.Standby.Name != name || len(st.Standby.Adopted) != 2 {
		t.Fatalf("%+v", st.Standby)
	}

	// Only while root's standby has taken over that name.
	if err := dnsCall(t, s, OpDNSRecordSet, DNSRecordSetArgs{Name: name, Type: "A", Content: "203.0.113.5", TTL: 60}, nil); err == nil {
		t.Fatal("pointed the name here without a take-over")
	}
	takenOver = true
	// Take-over: only public addresses, A/AAAA only, TTL 60.
	for _, bad := range []DNSRecordSetArgs{
		{Name: name, Type: "A", Content: "192.168.1.20", TTL: 60},
		{Name: name, Type: "A", Content: "100.64.1.2", TTL: 60},
		{Name: name, Type: "AAAA", Content: "fd00::1", TTL: 60},
		{Name: name, Type: "CNAME", Content: "home.example.net", TTL: 60},
		{Name: "www.example.net", Type: "A", Content: "203.0.113.5", TTL: 60}, // another name in the zone
	} {
		if err := dnsCall(t, s, OpDNSRecordSet, bad, nil); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	var r DNSRecordSetResult
	if err := dnsCall(t, s, OpDNSRecordSet, DNSRecordSetArgs{Name: name, Type: "A", Content: "203.0.113.5", TTL: 60}, &r); err != nil || r.Action != "updated" || r.ID != vpsA {
		t.Fatalf("%+v %v", r, err)
	}
	if err := dnsCall(t, s, OpDNSRecordSet, DNSRecordSetArgs{Name: name, Type: "AAAA", Content: "2001:db8:1::5", TTL: 60}, &r); err != nil || r.ID != vpsAAAA {
		t.Fatalf("%+v %v", r, err)
	}
	if got := cf.Find(name, "A"); len(got) != 1 || got[0].Content != "203.0.113.5" || got[0].TTL != 60 {
		t.Fatalf("%+v", got)
	}
	if got := cf.Find("www.example.net", "A"); got[0].Content != "198.51.100.20" {
		t.Fatal("another record changed")
	}

	// Hand-back: the originals come back exactly (content, TTL, comment).
	if err := dnsCall(t, s, OpDNSStandbyRestore, struct{}{}, nil); err != nil {
		t.Fatal(err)
	}
	if got := cf.Find(name, "A"); len(got) != 1 || got[0].Content != "198.51.100.10" || got[0].TTL != 300 {
		t.Fatalf("%+v", got)
	}
	if got := cf.Find(name, "AAAA"); len(got) != 1 || got[0].Content != "2001:db8::10" || got[0].Comment != "vps" {
		t.Fatalf("%+v", got)
	}
	// Forgetting needs the name typed; afterwards the name is out of reach again.
	if err := dnsCall(t, s, OpDNSStandbyForget, DNSTokenClearArgs{Confirm: "x"}, nil); err == nil {
		t.Fatal("forgot without the name")
	}
	if err := dnsCall(t, s, OpDNSStandbyForget, DNSTokenClearArgs{Confirm: name}, nil); err != nil {
		t.Fatal(err)
	}
	if err := dnsCall(t, s, OpDNSRecordSet, DNSRecordSetArgs{Name: name, Type: "A", Content: "203.0.113.5"}, nil); err == nil {
		t.Fatal("set after forgetting")
	}
}

func TestStandbyNameRefusesOddRecords(t *testing.T) {
	s, cf, _, _ := dnsServer(t)
	if err := dnsCall(t, s, OpDNSTokenSet, DNSTokenSetArgs{Token: testCFToken, Base: "home.example.net"}, nil); err != nil {
		t.Fatal(err)
	}
	cf.Add("example.net", cfdns.Record{Type: "CNAME", Name: "vpn.example.net", Content: "vps.hoster.example", TTL: 1})
	var pv DNSStandbyPreview
	if err := dnsCall(t, s, OpDNSStandbyPreview, DNSStandbyNameArgs{Name: "vpn.example.net"}, &pv); err != nil {
		t.Fatal(err)
	}
	if pv.Adoptable || !strings.Contains(pv.Problem, "CNAME") {
		t.Fatalf("%+v", pv)
	}
	if err := dnsCall(t, s, OpDNSStandbyAdopt, DNSStandbyAdoptArgs{Name: "vpn.example.net", Confirm: "vpn.example.net", IDs: []string{pv.Records[0].ID}}, nil); err == nil {
		t.Fatal("adopted a CNAME")
	}
	// A name with nothing yet has no VPS address to come back to.
	if err := dnsCall(t, s, OpDNSStandbyAdopt, DNSStandbyAdoptArgs{Name: "new.example.net", Confirm: "new.example.net"}, nil); err == nil {
		t.Fatal("adopted an empty name")
	}
	// A new token for another base forgets the adoption.
	cf.Add("example.net", cfdns.Record{Type: "A", Name: "nb.example.net", Content: "198.51.100.10", TTL: 1})
	_ = dnsCall(t, s, OpDNSStandbyPreview, DNSStandbyNameArgs{Name: "nb.example.net"}, &pv)
	if err := dnsCall(t, s, OpDNSStandbyAdopt, DNSStandbyAdoptArgs{Name: "nb.example.net", Confirm: "nb.example.net", IDs: []string{pv.Records[0].ID}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := dnsCall(t, s, OpDNSTokenSet, DNSTokenSetArgs{Token: testCFToken, Base: "other.example.net"}, nil); err != nil {
		t.Fatal(err)
	}
	var st DNSStatus
	_ = dnsCall(t, s, OpDNSStatus, struct{}{}, &st)
	if st.Standby != nil {
		t.Fatal("adoption kept across bases")
	}
}

func TestPublicAddress(t *testing.T) {
	for a, want := range map[string]bool{"203.0.113.5": true, "8.8.8.8": true, "2001:4860::1": true,
		"10.0.0.1": false, "192.168.1.1": false, "100.100.1.1": false, "127.0.0.1": false, "fe80::1": false, "fd00::1": false, "::ffff:10.0.0.1": false, "x": false} {
		if publicAddress(a) != want {
			t.Errorf("%s: %v", a, !want)
		}
	}
}
