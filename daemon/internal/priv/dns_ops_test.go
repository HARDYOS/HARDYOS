package priv

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cfdns"
	"github.com/hardyos/hardyos/daemon/internal/cfdns/cftest"
	"github.com/hardyos/hardyos/daemon/internal/domain"
	"github.com/hardyos/hardyos/daemon/internal/nbstandby"
)

const testCFToken = "abcdefghijklmnopqrstuvwxyz0123456789ABCD"

func dnsServer(t *testing.T) (*Server, *cftest.Server, string, *time.Time) {
	t.Helper()
	return dnsServerWith(t, nil)
}

// dnsServerWith is dnsServer with the standby's take-over state.
func dnsServerWith(t *testing.T, takenOver func() (nbstandby.TakeOverInfo, bool)) (*Server, *cftest.Server, string, *time.Time) {
	t.Helper()
	cf := cftest.New(testCFToken, "example.net")
	t.Cleanup(cf.Close)
	dir := filepath.Join(t.TempDir(), "keys")
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	s := &Server{}
	d := registerDNS(s, DNSEnv{KeyDir: dir, Client: cf.Client, Now: func() time.Time { return now }, StandbyTakenOver: takenOver})
	registerRecordSet(s, d)
	registerStandbyDNS(s, d)
	return s, cf, dir, &now
}

func dnsCall(t *testing.T, s *Server, op string, args, out any) error {
	t.Helper()
	raw, _ := json.Marshal(args)
	res, err := s.ops[op](context.Background(), raw)
	if err != nil {
		return err
	}
	if out != nil {
		b, _ := json.Marshal(res)
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatal(err)
		}
	}
	return nil
}

func TestDNSTokenIsRootsOnly(t *testing.T) {
	s, cf, dir, _ := dnsServer(t)
	var st DNSStatus
	if err := dnsCall(t, s, OpDNSStatus, struct{}{}, &st); err != nil || st.Set {
		t.Fatalf("%+v %v", st, err)
	}
	// Bad input never reaches Cloudflare.
	for _, a := range []DNSTokenSetArgs{
		{Token: "short", Base: "home.example.net"},
		{Token: testCFToken + " x", Base: "home.example.net"},
		{Token: testCFToken, Base: "localhost"},
		{Token: testCFToken, Base: "*.example.net"},
		{Token: testCFToken, Base: "_x.example.net"},
	} {
		if err := dnsCall(t, s, OpDNSTokenSet, a, nil); err == nil {
			t.Errorf("accepted %+v", a)
		}
	}
	if len(cf.Seen) != 0 {
		t.Fatal("bad arguments reached Cloudflare")
	}
	// A token Cloudflare doesn't know, or a base outside its zones.
	if err := dnsCall(t, s, OpDNSTokenSet, DNSTokenSetArgs{Token: strings.Repeat("z", 40), Base: "home.example.net"}, nil); err == nil {
		t.Fatal("unknown token accepted")
	}
	if err := dnsCall(t, s, OpDNSTokenSet, DNSTokenSetArgs{Token: testCFToken, Base: "home.other.org"}, nil); err == nil {
		t.Fatal("base outside the token's zones accepted")
	}
	if err := dnsCall(t, s, OpDNSTokenSet, DNSTokenSetArgs{Token: testCFToken, Base: "Home.Example.NET."}, &st); err != nil {
		t.Fatal(err)
	}
	if !st.Set || st.Base != "home.example.net" || st.Zone != "example.net" || st.VerifiedAt.IsZero() {
		t.Fatalf("%+v", st)
	}
	// The token appears in no result and isn't stored in the clear.
	b, _ := json.Marshal(st)
	if bytes.Contains(b, []byte(testCFToken)) {
		t.Fatal("token in status")
	}
	file, err := os.ReadFile(filepath.Join(dir, DNSStateFile))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(file, []byte(testCFToken)) {
		t.Fatal("token stored in the clear")
	}
	if fi, _ := os.Stat(filepath.Join(dir, DNSStateFile)); fi.Mode().Perm() != 0o600 {
		t.Fatalf("state mode %v", fi.Mode())
	}
	// hardyd's secrets.key can't give out the key the token is sealed with.
	RegisterSecrets(s, dir)
	raw, _ := json.Marshal(SecretsKeyArgs{Purpose: dnsKeyPurpose})
	res, err := s.ops[OpSecretsKey](context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := RootKeyFor(dir, dnsKeyPurpose)
	if bytes.Equal(res.(SecretsKeyResult).Key, root) {
		t.Fatal("secrets.key hands out the DNS token's key")
	}
	// A state file moved to another base doesn't open.
	var raw2 dnsState
	_ = json.Unmarshal(file, &raw2)
	raw2.Base = "evil.example.net"
	bad, _ := json.Marshal(raw2)
	_ = os.WriteFile(filepath.Join(dir, DNSStateFile), bad, 0o600)
	if err := dnsCall(t, s, OpDNSTokenVerify, struct{}{}, nil); err == nil {
		t.Fatal("token opened for another base")
	}
	_ = os.WriteFile(filepath.Join(dir, DNSStateFile), file, 0o600)
	if err := dnsCall(t, s, OpDNSTokenVerify, struct{}{}, &st); err != nil || st.Problem != "" {
		t.Fatalf("%+v %v", st, err)
	}
	// A disabled token is reported, not hidden.
	cf.Tokens[testCFToken] = "disabled"
	if err := dnsCall(t, s, OpDNSTokenVerify, struct{}{}, &st); err != nil || st.Problem == "" {
		t.Fatalf("%+v %v", st, err)
	}
	cf.Tokens[testCFToken] = "active"
	// Clearing needs the base typed.
	if err := dnsCall(t, s, OpDNSTokenClear, DNSTokenClearArgs{Confirm: "example.net"}, nil); err == nil {
		t.Fatal("cleared without confirmation")
	}
	if err := dnsCall(t, s, OpDNSTokenClear, DNSTokenClearArgs{Confirm: "home.example.net"}, &st); err != nil || st.Set {
		t.Fatalf("%+v %v", st, err)
	}
	if err := dnsCall(t, s, OpDNSACMEPresent, DNSACMEPresentArgs{Name: "_acme-challenge.home.example.net", Value: strings.Repeat("a", 43)}, nil); err == nil {
		t.Fatal("present without a token")
	}
}

func TestDNSACMEChallenges(t *testing.T) {
	s, cf, _, now := dnsServer(t)
	if err := dnsCall(t, s, OpDNSTokenSet, DNSTokenSetArgs{Token: testCFToken, Base: "home.example.net"}, nil); err != nil {
		t.Fatal(err)
	}
	val := strings.Repeat("A", 42) + "_"
	for _, bad := range []DNSACMEPresentArgs{
		{Name: "_acme-challenge.example.net", Value: val},             // outside the base
		{Name: "_acme-challenge.home.example.org", Value: val},        // another domain
		{Name: "home.example.net", Value: val},                        // not a challenge name
		{Name: "_acme-challenge.*.home.example.net", Value: val},      // wildcard label
		{Name: "_acme-challenge.photos.home.example.net", Value: val}, // only the base's own
		{Name: "_acme-challenge.home.example.net", Value: "v=spf1 -all"},
		{Name: "_acme-challenge.home.example.net", Value: strings.Repeat("a", 44)},
	} {
		if err := dnsCall(t, s, OpDNSACMEPresent, bad, nil); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	var r DNSACMEPresentResult
	if err := dnsCall(t, s, OpDNSACMEPresent, DNSACMEPresentArgs{Name: "_acme-challenge.home.example.net", Value: val}, &r); err != nil {
		t.Fatal(err)
	}
	if got := cf.TXT("_acme-challenge.home.example.net"); len(got) != 1 || got[0] != val {
		t.Fatalf("%v", got)
	}
	var stale DNSACMEPresentResult
	if err := dnsCall(t, s, OpDNSACMEPresent, DNSACMEPresentArgs{Name: "_acme-challenge.home.example.net", Value: val}, &stale); err != nil {
		t.Fatal(err)
	}
	// Someone else's TXT record can't be deleted through cleanup.
	foreign := cf.Add("example.net", cfdns.Record{Type: "TXT", Name: "_acme-challenge.home.example.net", Content: "other", TTL: 60})
	if err := dnsCall(t, s, OpDNSACMECleanup, DNSACMECleanupArgs{ID: foreign}, nil); err == nil {
		t.Fatal("deleted a record HardyOS didn't make")
	}
	if err := dnsCall(t, s, OpDNSACMECleanup, DNSACMECleanupArgs{ID: "../x"}, nil); err == nil {
		t.Fatal("bad id accepted")
	}
	if err := dnsCall(t, s, OpDNSACMECleanup, DNSACMECleanupArgs{ID: r.ID}, nil); err != nil {
		t.Fatal(err)
	}
	if got := cf.TXT("_acme-challenge.home.example.net"); len(got) != 2 {
		t.Fatalf("after cleanup: %v", got)
	}
	// Old challenges are removed by themselves; the bound holds.
	*now = now.Add(2 * time.Hour)
	for i := 0; i < MaxACMEChallenges; i++ {
		if err := dnsCall(t, s, OpDNSACMEPresent, DNSACMEPresentArgs{Name: "_acme-challenge.home.example.net", Value: val}, nil); err != nil {
			t.Fatal(i, err)
		}
	}
	for _, r := range cf.Find("_acme-challenge.home.example.net", "TXT") {
		if r.ID == stale.ID {
			t.Fatal("stale challenge kept")
		}
	}
	if err := dnsCall(t, s, OpDNSACMEPresent, DNSACMEPresentArgs{Name: "_acme-challenge.home.example.net", Value: val}, nil); err == nil {
		t.Fatal("more than the limit")
	}
	var st DNSStatus
	if err := dnsCall(t, s, OpDNSACMECleanup, DNSACMECleanupArgs{}, &st); err != nil || st.Challenges != 0 {
		t.Fatalf("%+v %v", st, err)
	}
	if got := cf.TXT("_acme-challenge.home.example.net"); len(got) != 1 {
		t.Fatalf("cleanup all removed others: %v", got)
	}
}

func TestDNSRecordSet(t *testing.T) {
	s, cf, _, _ := dnsServer(t)
	if err := dnsCall(t, s, OpDNSRecordSet, DNSRecordSetArgs{Name: "nas.home.example.net", Type: "A", Content: "192.168.1.20"}, nil); err == nil {
		t.Fatal("set without a token")
	}
	if err := dnsCall(t, s, OpDNSTokenSet, DNSTokenSetArgs{Token: testCFToken, Base: "home.example.net"}, nil); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []DNSRecordSetArgs{
		{Name: "home.example.net", Type: "A", Content: "192.168.1.20"},          // the base itself
		{Name: "example.net", Type: "A", Content: "192.168.1.20"},               // above the base
		{Name: "www.example.net", Type: "A", Content: "192.168.1.20"},           // beside it
		{Name: "evilhome.example.net", Type: "A", Content: "192.168.1.20"},      // suffix trick
		{Name: "_dmarc.home.example.net", Type: "TXT", Content: "v=DMARC1"},     // type
		{Name: "_x.home.example.net", Type: "A", Content: "192.168.1.20"},       // underscore
		{Name: "a.*.home.example.net", Type: "A", Content: "192.168.1.20"},      // inner wildcard
		{Name: "nas.home.example.net", Type: "MX", Content: "mail.example.net"}, // type
		{Name: "nas.home.example.net", Type: "A", Content: "fe80::1"},           // family
		{Name: "nas.home.example.net", Type: "AAAA", Content: "192.168.1.20"},   // family
		{Name: "nas.home.example.net", Type: "A", Content: "0.0.0.0"},           // unspecified
		{Name: "nas.home.example.net", Type: "A", Content: "127.0.0.1"},         // loopback
		{Name: "nas.home.example.net", Type: "CNAME", Content: "nas.home.example.net"},
		{Name: "nas.home.example.net", Type: "CNAME", Content: "not a host"},
		{Name: "nas.home.example.net", Type: "A", Content: "192.168.1.20", TTL: 30},
	} {
		if err := dnsCall(t, s, OpDNSRecordSet, bad, nil); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	var r DNSRecordSetResult
	if err := dnsCall(t, s, OpDNSRecordSet, DNSRecordSetArgs{Name: "nas.home.example.net", Type: "A", Content: "192.168.1.20"}, &r); err != nil || r.Action != "created" {
		t.Fatalf("%+v %v", r, err)
	}
	if err := dnsCall(t, s, OpDNSRecordSet, DNSRecordSetArgs{Name: "nas.home.example.net", Type: "A", Content: "192.168.1.20"}, &r); err != nil || r.Action != "unchanged" {
		t.Fatalf("%+v %v", r, err)
	}
	if err := dnsCall(t, s, OpDNSRecordSet, DNSRecordSetArgs{Name: "nas.home.example.net", Type: "A", Content: "100.64.0.7"}, &r); err != nil || r.Action != "updated" {
		t.Fatalf("%+v %v", r, err)
	}
	// Changing type replaces HardyOS's own record.
	if err := dnsCall(t, s, OpDNSRecordSet, DNSRecordSetArgs{Name: "nas.home.example.net", Type: "CNAME", Content: "proxy.netbird.example"}, &r); err != nil || r.Action != "created" {
		t.Fatalf("%+v %v", r, err)
	}
	if got := cf.Find("nas.home.example.net", ""); len(got) != 1 || got[0].Type != "CNAME" || got[0].Proxied == nil || *got[0].Proxied {
		t.Fatalf("%+v", got)
	}
	// The wildcard is allowed.
	if err := dnsCall(t, s, OpDNSRecordSet, DNSRecordSetArgs{Name: "*.home.example.net", Type: "CNAME", Content: "proxy.netbird.example"}, &r); err != nil {
		t.Fatal(err)
	}
	// Records of someone else's are never touched, even ones that claim
	// to be HardyOS's (mail's records carry the same comment).
	cf.Add("example.net", cfdns.Record{Type: "A", Name: "photos.home.example.net", Content: "203.0.113.9", TTL: 1})
	cf.Add("example.net", cfdns.Record{Type: "A", Name: "office.home.example.net", Content: "203.0.113.9", TTL: 1, Comment: cfdns.Comment})
	for _, n := range []string{"photos.home.example.net", "office.home.example.net"} {
		if err := dnsCall(t, s, OpDNSRecordSet, DNSRecordSetArgs{Name: n, Type: "A", Content: "192.168.1.20"}, nil); err == nil {
			t.Errorf("changed %s", n)
		}
		if got := cf.Find(n, ""); len(got) != 1 || got[0].Content != "203.0.113.9" {
			t.Errorf("%s: %+v", n, got)
		}
	}
	var st DNSStatus
	_ = dnsCall(t, s, OpDNSStatus, struct{}{}, &st)
	if len(st.Records) != 2 {
		t.Fatalf("%+v", st.Records)
	}
}

func TestHostRecordsBaseIsRoots(t *testing.T) {
	s, _, dir, _ := dnsServer(t)
	RegisterHostRecords(s, &domain.Manager{}, dir, func(context.Context) ([]string, error) { return []string{"board"}, nil })
	call := func(a domain.HostRecordsArgs) error { return dnsCall(t, s, OpDomainHostRecords, a, nil) }
	ok := domain.HostRecordsArgs{Base: "home.example.net", Address: "127.0.0.1", Labels: []string{"nas"}}
	if err := call(ok); err == nil || !strings.Contains(err.Error(), "base domain") {
		t.Fatalf("without a token: %v", err)
	}
	if err := dnsCall(t, s, OpDNSTokenSet, DNSTokenSetArgs{Token: testCFToken, Base: "home.example.net"}, nil); err != nil {
		t.Fatal(err)
	}
	// hardyd can't name another domain (a zone for it on the DC would take
	// it over for the LAN).
	for _, b := range []string{"google.com", "example.net", "x.home.example.net"} {
		a := ok
		a.Base = b
		if err := call(a); err == nil || !strings.Contains(err.Error(), "base domain") {
			t.Errorf("base %s: %v", b, err)
		}
	}
	// Nor an address that isn't this server's.
	a := ok
	a.Address = "203.0.113.77"
	if err := call(a); err == nil || !strings.Contains(err.Error(), "address of this server") {
		t.Fatalf("%v", err)
	}
	a.Address = "127.0.0.1"
	if err := call(a); err == nil || !strings.Contains(err.Error(), "address of this server") {
		t.Fatalf("loopback: %v", err)
	}
}

func TestDNSAccountTokensAndPendingZones(t *testing.T) {
	s, cf, _, _ := dnsServer(t)
	// An account-owned token: /user/tokens/verify doesn't know it, its
	// account's endpoint does.
	cf.AccountTokens[testCFToken] = true
	var st DNSStatus
	if err := dnsCall(t, s, OpDNSTokenSet, DNSTokenSetArgs{Token: testCFToken, Base: "home.example.net"}, &st); err != nil || !st.Set {
		t.Fatalf("%+v %v", st, err)
	}
	if cf.Calls["GET /accounts/"+cf.Account+"/tokens/verify"] != 1 {
		t.Fatalf("%v", cf.Calls)
	}
	if err := dnsCall(t, s, OpDNSTokenVerify, struct{}{}, &st); err != nil || st.Problem != "" {
		t.Fatalf("%+v %v", st, err)
	}
	// A zone that isn't active yet (nameservers not moved) is refused.
	cf.ZoneStatus["example.net"] = "pending"
	if err := dnsCall(t, s, OpDNSTokenSet, DNSTokenSetArgs{Token: testCFToken, Base: "home.example.net"}, nil); err == nil ||
		!strings.Contains(err.Error(), "isn't active") {
		t.Fatalf("pending zone: %v", err)
	}
}

// dns.record.set ships registered with the NetBird standby (decision 424),
// with the standby's own name operations.
func TestRecordSetIsRegistered(t *testing.T) {
	s := &Server{}
	RegisterDNS(s, DNSEnv{KeyDir: t.TempDir()})
	want := map[string]bool{OpDNSRecordSet: true, OpDNSStandbyPreview: true, OpDNSStandbyAdopt: true, OpDNSStandbyRestore: true, OpDNSStandbyForget: true}
	for _, op := range s.Ops() {
		delete(want, op)
	}
	if len(want) != 0 {
		t.Fatalf("not registered: %v", want)
	}
}
