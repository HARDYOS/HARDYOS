package priv

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cfdns"
	"github.com/hardyos/hardyos/daemon/internal/cfdns/cftest"
	"github.com/hardyos/hardyos/daemon/internal/nbstandby"
)

const (
	standbyName = "vpn.example.net" // outside the base home.example.net
	homeV4      = "93.184.215.14"
	homeV6      = "2606:4700:4700::1111"
)

// takeover is the standby's state as root's DNS operations see it.
type takeover struct {
	on   bool
	info nbstandby.TakeOverInfo
	keys string
}

func (t *takeover) get() (nbstandby.TakeOverInfo, bool) { return t.info, t.on }

// binding is the standby's current binding, taken over or not.
func (t *takeover) binding() (nbstandby.Binding, bool) { return t.info, t.info.Host != "" }

func standbyDNS(t *testing.T) (*Server, *cftest.Server, *takeover) {
	t.Helper()
	to := &takeover{info: nbstandby.TakeOverInfo{Host: standbyName, IPv4: homeV4, IPv6: homeV6,
		VPSHost: "198.51.100.10", VPSPort: 22, HostKeyFP: "SHA256:vps"}}
	s, cf, dir, _ := dnsServerWith(t, to.get, to.binding)
	if err := dnsCall(t, s, OpDNSTokenSet, DNSTokenSetArgs{Token: testCFToken, Base: "home.example.net"}, nil); err != nil {
		t.Fatal(err)
	}
	to.keys = dir
	return s, cf, to
}

// The NetBird standby's name (decision 424): one name in the token's zone,
// adopted with the name typed and the Cloudflare token pasted again; only
// during a take-over may dns.record.set point it here, and only at the
// address root keeps; restore puts back what HardyOS changed, nothing else.
func TestStandbyNameAdoption(t *testing.T) {
	s, cf, to := standbyDNS(t)
	vpsA := cf.Add("example.net", cfdns.Record{Type: "A", Name: standbyName, Content: "198.51.100.10", TTL: 300})
	vpsA2 := cf.Add("example.net", cfdns.Record{Type: "A", Name: standbyName, Content: "198.51.100.11", TTL: 300})
	vpsAAAA := cf.Add("example.net", cfdns.Record{Type: "AAAA", Name: standbyName, Content: "2001:db8::10", TTL: 300, Comment: "vps"})
	cf.Add("example.net", cfdns.Record{Type: "A", Name: "www.example.net", Content: "198.51.100.20", TTL: 300})

	if err := dnsCall(t, s, OpDNSRecordSet, DNSRecordSetArgs{Name: standbyName, Type: "A", Content: homeV4}, nil); err == nil {
		t.Fatal("set a name outside the base before adoption")
	}
	for _, bad := range []string{"example.net", "vpn.example.org", "home.example.net", "_x.example.net", "*.example.net", "vpn.example.net.evil.com"} {
		if err := dnsCall(t, s, OpDNSStandbyPreview, DNSStandbyNameArgs{Name: bad}, nil); err == nil {
			t.Errorf("preview of %s accepted", bad)
		}
	}
	var pv DNSStandbyPreview
	if err := dnsCall(t, s, OpDNSStandbyPreview, DNSStandbyNameArgs{Name: "VPN.example.net."}, &pv); err != nil {
		t.Fatal(err)
	}
	if pv.Name != standbyName || len(pv.Records) != 3 || !pv.Adoptable {
		t.Fatalf("%+v", pv)
	}
	ids := []string{pv.Records[0].ID, pv.Records[1].ID, pv.Records[2].ID}
	for what, a := range map[string]DNSStandbyAdoptArgs{
		"no typed name": {Name: standbyName, Confirm: "vpn", IDs: ids, Token: testCFToken},
		"stale preview": {Name: standbyName, Confirm: standbyName, IDs: ids[:1], Token: testCFToken},
		"no token":      {Name: standbyName, Confirm: standbyName, IDs: ids},
		"another token": {Name: standbyName, Confirm: standbyName, IDs: ids, Token: strings.Repeat("z", 40)},
	} {
		if err := dnsCall(t, s, OpDNSStandbyAdopt, a, nil); err == nil {
			t.Errorf("%s: adopted", what)
		}
	}
	to.on = true
	if err := dnsCall(t, s, OpDNSStandbyAdopt, DNSStandbyAdoptArgs{Name: standbyName, Confirm: standbyName, IDs: ids, Token: testCFToken}, nil); err == nil {
		t.Fatal("adopted while taken over")
	}
	to.on = false
	if err := dnsCall(t, s, OpDNSStandbyAdopt, DNSStandbyAdoptArgs{Name: standbyName, Confirm: standbyName, IDs: ids, Token: testCFToken}, nil); err != nil {
		t.Fatal(err)
	}
	if err := dnsCall(t, s, OpDNSStandbyAdopt, DNSStandbyAdoptArgs{Name: standbyName, Confirm: standbyName, IDs: ids, Token: testCFToken}, nil); err == nil {
		t.Fatal("adopted twice")
	}

	// Not taken over: nothing may point the name here, and nothing restores.
	if err := dnsCall(t, s, OpDNSRecordSet, DNSRecordSetArgs{Name: standbyName, Type: "A", Content: homeV4, TTL: 60}, nil); err == nil {
		t.Fatal("pointed the name here without a take-over")
	}
	if err := dnsCall(t, s, OpDNSStandbyRestore, struct{}{}, nil); err == nil {
		t.Fatal("restored without a take-over")
	}
	to.on = true
	// Only root's own address for the name, A/AAAA only.
	for _, bad := range []DNSRecordSetArgs{
		{Name: standbyName, Type: "A", Content: "8.8.8.8", TTL: 60}, // a public address, but not this server's
		{Name: standbyName, Type: "A", Content: "192.168.1.20", TTL: 60},
		{Name: standbyName, Type: "AAAA", Content: "2606:4700::2", TTL: 60},
		{Name: standbyName, Type: "CNAME", Content: "home.example.net", TTL: 60},
		{Name: "www.example.net", Type: "A", Content: homeV4, TTL: 60},
	} {
		if err := dnsCall(t, s, OpDNSRecordSet, bad, nil); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	// Every adopted A record changes; the AAAA is never deleted by setting A.
	var r DNSRecordSetResult
	if err := dnsCall(t, s, OpDNSRecordSet, DNSRecordSetArgs{Name: standbyName, Type: "A", Content: homeV4, TTL: 60}, &r); err != nil || r.Action != "updated" {
		t.Fatalf("%+v %v", r, err)
	}
	if got := cf.Find(standbyName, "A"); len(got) != 2 || got[0].Content != homeV4 || got[1].Content != homeV4 {
		t.Fatalf("%+v", got)
	}
	if got := cf.Find(standbyName, "AAAA"); len(got) != 1 || got[0].ID != vpsAAAA {
		t.Fatalf("AAAA touched: %+v", got)
	}
	if err := dnsCall(t, s, OpDNSRecordSet, DNSRecordSetArgs{Name: standbyName, Type: "AAAA", Content: homeV6, TTL: 60}, &r); err != nil || r.ID != vpsAAAA {
		t.Fatalf("%+v %v", r, err)
	}
	// Someone changes one A record by hand meanwhile: restore leaves it.
	cf.Set(vpsA2, "151.101.1.1")
	var res DNSStandbyRestoreResult
	if err := dnsCall(t, s, OpDNSStandbyRestore, struct{}{}, &res); err != nil {
		t.Fatal(err)
	}
	if res.Restored != 2 || len(res.Skipped) != 1 {
		t.Fatalf("%+v", res)
	}
	for id, want := range map[string]string{vpsA: "198.51.100.10", vpsA2: "151.101.1.1", vpsAAAA: "2001:db8::10"} {
		if got := cf.Get(id); got.Content != want {
			t.Errorf("%s: %+v", id, got)
		}
	}
	if got := cf.Get(vpsAAAA); got.Comment != "vps" || got.TTL != 300 {
		t.Fatalf("%+v", got)
	}
	if got := cf.Find("www.example.net", "A"); got[0].Content != "198.51.100.20" {
		t.Fatal("another record changed")
	}
	// Forgetting: not while taken over, the name typed, the token again.
	if err := dnsCall(t, s, OpDNSStandbyForget, DNSStandbyForgetArgs{Confirm: standbyName, Token: testCFToken}, nil); err == nil {
		t.Fatal("forgot while taken over")
	}
	to.on = false
	if err := dnsCall(t, s, OpDNSStandbyForget, DNSStandbyForgetArgs{Confirm: "x", Token: testCFToken}, nil); err == nil {
		t.Fatal("forgot without the name")
	}
	if err := dnsCall(t, s, OpDNSStandbyForget, DNSStandbyForgetArgs{Confirm: standbyName}, nil); err == nil {
		t.Fatal("forgot without the token")
	}
	if err := dnsCall(t, s, OpDNSStandbyForget, DNSStandbyForgetArgs{Confirm: standbyName, Token: testCFToken}, nil); err != nil {
		t.Fatal(err)
	}
	if StandbyDNSName(to.keys) != "" {
		t.Fatal("name still adopted")
	}
}

// A name with only an A record gets an AAAA made by HardyOS when root has
// an IPv6 address; restore deletes exactly that one.
func TestStandbyNameCreatedRecord(t *testing.T) {
	s, cf, to := standbyDNS(t)
	cf.Add("example.net", cfdns.Record{Type: "A", Name: standbyName, Content: "198.51.100.10", TTL: 300})
	var pv DNSStandbyPreview
	_ = dnsCall(t, s, OpDNSStandbyPreview, DNSStandbyNameArgs{Name: standbyName}, &pv)
	if err := dnsCall(t, s, OpDNSStandbyAdopt, DNSStandbyAdoptArgs{Name: standbyName, Confirm: standbyName, IDs: []string{pv.Records[0].ID}, Token: testCFToken}, nil); err != nil {
		t.Fatal(err)
	}
	to.on = true
	var r DNSRecordSetResult
	if err := dnsCall(t, s, OpDNSRecordSet, DNSRecordSetArgs{Name: standbyName, Type: "AAAA", Content: homeV6, TTL: 60}, &r); err != nil || r.Action != "created" {
		t.Fatalf("%+v %v", r, err)
	}
	if err := dnsCall(t, s, OpDNSStandbyRestore, struct{}{}, nil); err != nil {
		t.Fatal(err)
	}
	if got := cf.Find(standbyName, "AAAA"); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestStandbyNameRefusesOddRecords(t *testing.T) {
	s, cf, to := standbyDNS(t)
	cf.Add("example.net", cfdns.Record{Type: "CNAME", Name: standbyName, Content: "vps.hoster.example", TTL: 1})
	var pv DNSStandbyPreview
	if err := dnsCall(t, s, OpDNSStandbyPreview, DNSStandbyNameArgs{Name: standbyName}, &pv); err != nil {
		t.Fatal(err)
	}
	if pv.Adoptable || !strings.Contains(pv.Problem, "CNAME") {
		t.Fatalf("%+v", pv)
	}
	if err := dnsCall(t, s, OpDNSStandbyAdopt, DNSStandbyAdoptArgs{Name: standbyName, Confirm: standbyName, IDs: []string{pv.Records[0].ID}, Token: testCFToken}, nil); err == nil {
		t.Fatal("adopted a CNAME")
	}
	if err := dnsCall(t, s, OpDNSStandbyAdopt, DNSStandbyAdoptArgs{Name: "new.example.net", Confirm: "new.example.net", Token: testCFToken}, nil); err == nil {
		t.Fatal("adopted an empty name")
	}
	to.info.Host = "nb.example.net"
	cf.Add("example.net", cfdns.Record{Type: "A", Name: "nb.example.net", Content: "198.51.100.10", TTL: 1})
	_ = dnsCall(t, s, OpDNSStandbyPreview, DNSStandbyNameArgs{Name: "nb.example.net"}, &pv)
	if err := dnsCall(t, s, OpDNSStandbyAdopt, DNSStandbyAdoptArgs{Name: "nb.example.net", Confirm: "nb.example.net", IDs: []string{pv.Records[0].ID}, Token: testCFToken}, nil); err != nil {
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
	for a, want := range map[string]bool{homeV4: true, "8.8.8.8": true, "2001:4860::1": true, homeV6: true,
		"10.0.0.1": false, "192.168.1.1": false, "100.100.1.1": false, "127.0.0.1": false, "fe80::1": false, "fd00::1": false, "::ffff:10.0.0.1": false, "x": false,
		"203.0.113.5": false, "198.51.100.1": false, "192.0.2.1": false, "240.0.0.1": false, "2001:db8::1": false, "2002::1": false, "64:ff9b::1.2.3.4": false} {
		if publicAddress(a) != want {
			t.Errorf("%s: %v", a, !want)
		}
	}
}

// The adopted name is bound to this server's addresses and the VPS (security
// review N2): when any of them changes afterwards, a take-over can't move the
// name until the token is pasted again (rebind) or the console rebinds.
func TestStandbyNameBinding(t *testing.T) {
	s, cf, to := standbyDNS(t)
	cf.Add("example.net", cfdns.Record{Type: "A", Name: standbyName, Content: "198.51.100.10", TTL: 300})
	var pv DNSStandbyPreview
	if err := dnsCall(t, s, OpDNSStandbyPreview, DNSStandbyNameArgs{Name: standbyName}, &pv); err != nil {
		t.Fatal(err)
	}
	adopt := DNSStandbyAdoptArgs{Name: standbyName, Confirm: standbyName, IDs: []string{pv.Records[0].ID}, Token: testCFToken}
	saved := to.info
	to.info.IPv4 = ""
	if err := dnsCall(t, s, OpDNSStandbyAdopt, adopt, nil); err == nil {
		t.Fatal("adopted without a public address")
	}
	to.info = saved
	to.info.Host = "other.example.net"
	if err := dnsCall(t, s, OpDNSStandbyAdopt, adopt, nil); err == nil {
		t.Fatal("adopted for a standby with another name")
	}
	to.info = saved
	if err := dnsCall(t, s, OpDNSStandbyAdopt, adopt, nil); err != nil {
		t.Fatal(err)
	}
	if b, ok := StandbyDNSBound(to.keys); !ok || b != saved {
		t.Fatalf("bound %+v %v", b, ok)
	}

	// A compromised hardyd changes the address (or the VPS, or its host key)
	// and takes over: the name doesn't move.
	for what, change := range map[string]func(*nbstandby.Binding){
		"address":  func(b *nbstandby.Binding) { b.IPv4 = "8.8.8.8" },
		"ipv6":     func(b *nbstandby.Binding) { b.IPv6 = "2606:4700::2" },
		"vps":      func(b *nbstandby.Binding) { b.VPSHost = "203.0.113.9" },
		"vps port": func(b *nbstandby.Binding) { b.VPSPort = 2222 },
		"host key": func(b *nbstandby.Binding) { b.HostKeyFP = "SHA256:evil" },
	} {
		to.info = saved
		change(&to.info)
		to.on = true
		if err := dnsCall(t, s, OpDNSRecordSet, DNSRecordSetArgs{Name: standbyName, Type: "A", Content: to.info.IPv4, TTL: 60}, nil); err == nil {
			t.Errorf("%s changed: the name moved", what)
		}
		// Rebinding: never while taken over, only with the token.
		if err := dnsCall(t, s, OpDNSStandbyRebind, DNSStandbyRebindArgs{Token: testCFToken}, nil); err == nil {
			t.Errorf("%s: rebound while taken over", what)
		}
		to.on = false
		if err := dnsCall(t, s, OpDNSStandbyRebind, DNSStandbyRebindArgs{}, nil); err == nil {
			t.Errorf("%s: rebound without the token", what)
		}
		if err := dnsCall(t, s, OpDNSStandbyRebind, DNSStandbyRebindArgs{Token: strings.Repeat("z", 40)}, nil); err == nil {
			t.Errorf("%s: rebound with another token", what)
		}
	}
	if got := cf.Find(standbyName, "A"); got[0].Content != "198.51.100.10" {
		t.Fatalf("%+v", got)
	}

	// The administrator confirms the new address with the token.
	to.info = saved
	to.info.IPv4 = "93.184.215.15"
	if err := dnsCall(t, s, OpDNSStandbyRebind, DNSStandbyRebindArgs{Token: testCFToken}, nil); err != nil {
		t.Fatal(err)
	}
	to.on = true
	if err := dnsCall(t, s, OpDNSRecordSet, DNSRecordSetArgs{Name: standbyName, Type: "A", Content: "93.184.215.15", TTL: 60}, nil); err != nil {
		t.Fatal(err)
	}
	// Restore puts back the VPS's record even if the address changed again
	// after the name moved (it matches the bound address, not the current).
	to.info.IPv4 = "93.184.215.16"
	var res DNSStandbyRestoreResult
	if err := dnsCall(t, s, OpDNSStandbyRestore, struct{}{}, &res); err != nil || res.Restored != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	to.on = false

	// The console rebinds and forgets without the token.
	env := DNSEnv{KeyDir: to.keys, Client: cf.Client, Now: time.Now, StandbyTakenOver: to.get, StandbyBinding: to.binding}
	if err := ConsoleRebind(env); err != nil {
		t.Fatal(err)
	}
	if b, _ := StandbyDNSBound(to.keys); b.IPv4 != "93.184.215.16" {
		t.Fatalf("%+v", b)
	}
	to.on = true
	if err := ConsoleForget(env); err == nil {
		t.Fatal("console forgot while taken over")
	}
	to.on = false
	if err := ConsoleForget(env); err != nil {
		t.Fatal(err)
	}
	if StandbyDNSName(to.keys) != "" {
		t.Fatal("still adopted")
	}
	pvc, err := ConsolePreview(context.Background(), env, standbyName)
	if err != nil {
		t.Fatal(err)
	}
	if err := ConsoleAdopt(context.Background(), env, standbyName, []string{pvc.Records[0].ID}); err != nil {
		t.Fatal(err)
	}
	if StandbyDNSName(to.keys) != standbyName {
		t.Fatal("console adopt")
	}
}
