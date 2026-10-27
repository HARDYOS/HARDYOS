package manage

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/mail"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

type fakePriv struct {
	mu    sync.Mutex
	calls []string
	args  []any
}

func (f *fakePriv) Call(_ context.Context, op string, args, out any) error {
	f.mu.Lock()
	f.calls = append(f.calls, op)
	f.args = append(f.args, args)
	f.mu.Unlock()
	switch op {
	case mail.OpApply:
		a := args.(*mail.ApplyArgs)
		res := mail.ApplyResult{DKIM: map[string]string{}}
		for _, d := range a.Config.Domains {
			res.DKIM[d.Name] = "PUB-" + d.Name + "-" + d.Selector
		}
		b, _ := json.Marshal(res)
		return json.Unmarshal(b, out)
	case mail.OpStatus:
		return json.Unmarshal([]byte(`{"services":{},"queue":[]}`), out)
	}
	return nil
}

func (f *fakePriv) count(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == op {
			n++
		}
	}
	return n
}

type fakeDir []DirUser

func (d fakeDir) Users(context.Context) ([]DirUser, error) { return d, nil }

type fakePasswords map[string]string

func (p fakePasswords) CheckDomainPassword(_ context.Context, account, pw string) error {
	if p[account] == pw && pw != "" {
		return nil
	}
	return errors.New("bad password")
}

func newSvc(t *testing.T) (*Service, *fakePriv) {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	fp := &fakePriv{}
	return &Service{Store: &Store{DB: db, Keys: secretbox.NewStaticSource()}, Priv: fp, Throttle: mail.NewThrottle()}, fp
}

func enable(t *testing.T, s *Service) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.Store.AddDomain(ctx, "example.net", "", false); err != nil {
		t.Fatal(err)
	}
	doms, _ := s.Store.Domains(ctx)
	st := DefaultSettings()
	st.Enabled, st.Pool, st.Hostname, st.VPSPeer, st.DefaultDomain = true, "tank", "mail.example.net", "100.90.1.2", "example.net"
	st, err := ValidateSettings(st, doms)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Store.SaveSettings(ctx, st); err != nil {
		t.Fatal(err)
	}
}

func TestSettingsAndSecrets(t *testing.T) {
	s, _ := newSvc(t)
	ctx := context.Background()
	st, err := s.Store.LoadSettings(ctx)
	if err != nil || st.Enabled || st.JunkScore != 6 {
		t.Fatalf("defaults %+v %v", st, err)
	}
	st.Enabled = true
	if _, err := ValidateSettings(st, nil); err == nil {
		t.Error("enabled without pool, name, VPS or domain")
	}
	bad := DefaultSettings()
	bad.VPSIPv4 = "2001:db8::1"
	if _, err := ValidateSettings(bad, nil); err == nil {
		t.Error("IPv6 accepted as the VPS's IPv4 address")
	}
	if err := s.Store.SetSecret(ctx, SecretSES, "very-secret"); err != nil {
		t.Fatal(err)
	}
	raw, _ := s.Store.DB.GetSetting(ctx, SecretSES)
	if strings.Contains(raw, "very-secret") {
		t.Fatal("secret stored in clear")
	}
	if v, err := s.Store.Secret(ctx, SecretSES); err != nil || v != "very-secret" {
		t.Fatalf("%q %v", v, err)
	}
	// Bound to its name: copying it to another key doesn't open it.
	_ = s.Store.DB.SetSetting(ctx, SecretCloudflare, raw)
	if _, err := s.Store.Secret(ctx, SecretCloudflare); err == nil {
		t.Error("a secret opened under another name")
	}
}

func TestDomains(t *testing.T) {
	s, _ := newSvc(t)
	ctx := context.Background()
	d, err := s.Store.AddDomain(ctx, "example.net", "reject", true)
	if err != nil || d.DMARCPolicy != "reject" || !d.Cloudflare || !strings.HasPrefix(d.Selector, "hardyos") {
		t.Fatalf("%+v %v", d, err)
	}
	if _, err := s.Store.AddDomain(ctx, "example.net", "", false); err == nil {
		t.Error("duplicate domain")
	}
	if _, err := s.Store.AddDomain(ctx, "Bad_Domain", "", false); err == nil {
		t.Error("invalid domain")
	}
	sts := "enforce"
	d2, err := s.Store.UpdateDomain(ctx, "example.net", DomainUpdate{MTASTS: &sts, RotateDKIM: true})
	if err != nil || d2.MTASTS != "enforce" || d2.MTASTSID == "" || d2.Selector == d.Selector {
		t.Fatalf("%+v %v", d2, err)
	}
	if _, err := s.Store.CreateMailbox(ctx, Mailbox{Account: "alice", Address: "alice@example.net", AccountState: "active", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.Store.DeleteDomain(ctx, "example.net"); err == nil {
		t.Error("deleted a domain mailboxes use")
	}
}

func TestSyncAccounts(t *testing.T) {
	s, fp := newSvc(t)
	enable(t, s)
	ctx := context.Background()
	s.Dir = fakeDir{
		{Username: "Administrator", Enabled: true, Builtin: true},
		{Username: "alice", GivenName: "Alice", Enabled: true},
		{Username: "zoe2", GivenName: "Zoë", Enabled: true},
		{Username: "alice.b", GivenName: "Alice", Enabled: true},
		{Username: "kid", GivenName: "", Enabled: false},
	}
	res, err := s.SyncAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Created, " ") != "alice@example.net zoe@example.net alice2@example.net kid@example.net" {
		t.Fatalf("created %v", res.Created)
	}
	mbs, _ := s.Store.Mailboxes(ctx)
	if len(mbs) != 4 {
		t.Fatalf("%d mailboxes", len(mbs))
	}
	kid, _ := s.Store.MailboxByAccount(ctx, "kid")
	if kid.CanSignIn() || kid.AccountState != "disabled" {
		t.Errorf("kid %+v", kid)
	}
	// alice is turned off, zoe2 deleted.
	s.Dir = fakeDir{{Username: "alice", GivenName: "Alice", Enabled: false}, {Username: "alice.b", Enabled: true}, {Username: "kid", Enabled: false}}
	res, err = s.SyncAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Disabled) != 1 || res.Disabled[0] != "alice@example.net" || len(res.Deleted) != 1 || res.Deleted[0] != "zoe@example.net" || res.Changed() {
		t.Fatalf("%+v", res)
	}
	if fp.count(mail.OpKick) != 2 {
		t.Errorf("kicks: %d", fp.count(mail.OpKick))
	}
}

func TestCheckLogin(t *testing.T) {
	s, _ := newSvc(t)
	enable(t, s)
	ctx := context.Background()
	alice, _ := s.Store.CreateMailbox(ctx, Mailbox{Account: "alice", Address: "alice@example.net", AccountState: "active", Enabled: true})
	_, _ = s.Store.CreateMailbox(ctx, Mailbox{Account: "kid", Address: "kid@example.net", AccountState: "disabled", Enabled: true})
	s.Passwords = fakePasswords{"alice": "pw-alice", "kid": "pw-kid"}
	if err := s.CheckLogin(ctx, "alice@example.net", "pw-alice"); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{"alice@example.net", "wrong"}, {"kid@example.net", "pw-kid"}, {"nobody@example.net", "x"}, {mail.NotifyLogin, "x"}} {
		if err := s.CheckLogin(ctx, c[0], c[1]); !errors.Is(err, mail.ErrBadLogin) {
			t.Errorf("%s: %v", c[0], err)
		}
	}
	// Turned off by an administrator.
	off := false
	if _, err := s.Store.UpdateMailbox(ctx, alice.ID, MailboxUpdate{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckLogin(ctx, "alice@example.net", "pw-alice"); err == nil {
		t.Error("a turned-off mailbox signed in")
	}
	on := true
	_, _ = s.Store.UpdateMailbox(ctx, alice.ID, MailboxUpdate{Enabled: &on})
	// Webmail tokens last as long as their window session.
	alive := map[string]bool{"sess1": true}
	s.SessionAlive = func(k string) bool { return alive[k] }
	addr, tok, err := s.WebmailLogin(ctx, "alice", "sess1")
	if err != nil || addr != "alice@example.net" || !strings.HasPrefix(tok, WebmailPrefix) {
		t.Fatalf("%s %s %v", addr, tok, err)
	}
	if err := s.CheckLogin(ctx, "alice@example.net", tok); err != nil {
		t.Fatalf("webmail token: %v", err)
	}
	if err := s.CheckLogin(ctx, "kid@example.net", tok); err == nil {
		t.Error("alice's token opened another mailbox")
	}
	alive["sess1"] = false
	if err := s.CheckLogin(ctx, "alice@example.net", tok); err == nil {
		t.Error("a token outlived its session")
	}
	if _, _, err := s.WebmailLogin(ctx, "kid", "sess2"); err == nil {
		t.Error("a turned-off account got webmail")
	}
	// Notifications.
	st, _ := s.Store.LoadSettings(ctx)
	st.NotifyFrom = "hardyos@example.net"
	_ = s.Store.SaveSettings(ctx, st)
	pw, _ := s.NotifyPassword(ctx)
	if err := s.CheckLogin(ctx, mail.NotifyLogin, pw); err != nil {
		t.Fatalf("notify login: %v", err)
	}
}

func TestRootArgs(t *testing.T) {
	s, _ := newSvc(t)
	enable(t, s)
	ctx := context.Background()
	_, _ = s.Store.CreateMailbox(ctx, Mailbox{Account: "alice", Address: "alice@example.net", Aliases: []string{"mom@example.net"}, AccountState: "active", Enabled: true, QuotaMB: 100})
	_, _ = s.Store.CreateMailbox(ctx, Mailbox{Account: "kid", Address: "kid@example.net", AccountState: "disabled", Enabled: true})
	if _, err := s.Store.SetGroup(ctx, Group{Address: "family@example.net", Targets: []string{"alice@example.net", "kid@example.net"}}); err != nil {
		t.Fatal(err)
	}
	st, _ := s.Store.LoadSettings(ctx)
	st.SESRegion, st.SESAccessID = "eu-west-1", "AKIAEXAMPLEEXAMPLE12"
	_ = s.Store.SaveSettings(ctx, st)
	_ = s.Store.SetSecret(ctx, SecretSES, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	a, err := s.RootArgs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Config.Normalize(a.Secrets); err != nil {
		t.Fatalf("root would refuse: %v", err)
	}
	if a.Config.SES == nil || a.Config.SES.Host != "email-smtp.eu-west-1.amazonaws.com" || a.Secrets.SESPassword == "" {
		t.Fatalf("SES %+v", a.Config.SES)
	}
	if _, ok := a.Secrets.DAV["kid@example.net"]; ok {
		t.Error("a turned-off mailbox has a calendar password")
	}
	if _, ok := a.Secrets.DAV["alice@example.net"]; !ok {
		t.Error("alice has no calendar password")
	}
	// Apply stores the DKIM keys root made.
	if _, err := s.Apply(ctx, func(float64, string) {}); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Store.GetDomain(ctx, "example.net")
	if !strings.HasPrefix(d.DKIMPublic, "PUB-example.net-") {
		t.Fatalf("DKIM %q", d.DKIMPublic)
	}
}

func TestSESPassword(t *testing.T) {
	p := SESSMTPPassword("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1")
	if len(p) != 44 || p != SESSMTPPassword("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1") || p == SESSMTPPassword("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "eu-west-1") {
		t.Fatalf("%q", p)
	}
	if p[0] != 'B' { // base64 of 0x04...
		t.Errorf("version byte: %q", p)
	}
}

func TestSESClient(t *testing.T) {
	var sawAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE")
		switch {
		case r.Method == "GET" && r.URL.Path == "/v2/email/identities/example.net":
			w.Header().Set("x-amzn-ErrorType", "NotFoundException")
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"not found"}`)
		case r.Method == "POST" && r.URL.Path == "/v2/email/identities":
			io.WriteString(w, `{"VerifiedForSendingStatus":false,"DkimAttributes":{"Status":"PENDING","Tokens":["a","b","c"]}}`)
		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	cl := &SESClient{Region: "us-east-1", AccessKey: "AKIAEXAMPLE", SecretKey: "x", HTTP: srv.Client(), Endpoint: srv.URL}
	id, err := cl.Identity(context.Background(), "example.net")
	if err != nil || id.Exists {
		t.Fatalf("%+v %v", id, err)
	}
	id, err = cl.CreateIdentity(context.Background(), "example.net")
	if err != nil || len(id.DKIMTokens) != 3 || !sawAuth {
		t.Fatalf("%+v %v signed=%v", id, err, sawAuth)
	}
}

func TestCloudflarePublish(t *testing.T) {
	var mu sync.Mutex
	created, updated := []CFRecord{}, []CFRecord{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		ok := func(v any) {
			b, _ := json.Marshal(map[string]any{"success": true, "errors": []any{}, "result": v})
			w.Write(b)
		}
		switch {
		case r.URL.Path == "/zones":
			if r.URL.Query().Get("name") == "example.net" {
				ok([]map[string]string{{"id": "Z1", "name": "example.net"}})
			} else {
				ok([]any{})
			}
		case r.Method == "GET" && r.URL.Path == "/zones/Z1/dns_records":
			q := r.URL.Query()
			switch q.Get("type") + " " + q.Get("name") {
			case "TXT example.net":
				ok([]CFRecord{{ID: "spf", Type: "TXT", Name: "example.net", Content: `"v=spf1 include:_spf.google.com ~all"`}})
			case "CNAME autoconfig.example.net":
				ok([]CFRecord{{ID: "other", Type: "CNAME", Name: "autoconfig.example.net", Content: "elsewhere.test"}})
			case "MX example.net":
				ok([]CFRecord{{ID: "mx", Type: "MX", Name: "example.net", Content: "mail.example.net"}})
			default:
				ok([]CFRecord{})
			}
		case r.Method == "POST":
			var rec CFRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			created = append(created, rec)
			ok(rec)
		case r.Method == "PUT":
			var rec CFRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			rec.ID = r.URL.Path
			updated = append(updated, rec)
			ok(rec)
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	cf := &Cloudflare{Token: "t", HTTP: srv.Client(), Base: srv.URL}
	recs := mail.Records(mail.DomainDNS{Domain: "example.net", Hostname: "mail.example.net", DKIMSelector: "s1", DKIMPublicKey: "KEY", SES: true})
	recs = append(recs, mail.Record{Type: "CNAME", Name: "autoconfig.example.net", Value: "mail.example.net", Purpose: "autoconfig"})
	res := cf.Publish(context.Background(), recs)
	actions := map[string]string{}
	for _, r := range res {
		actions[r.Type+" "+r.Name] = r.Action
	}
	if actions["MX example.net"] != "unchanged" || actions["TXT example.net"] != "updated" || actions["TXT s1._domainkey.example.net"] != "created" ||
		actions["CNAME autoconfig.example.net"] != "skipped" {
		t.Fatalf("%v", actions)
	}
	for _, u := range updated {
		if u.Name == "example.net" && u.Content != "v=spf1 include:_spf.google.com mx include:amazonses.com ~all" {
			t.Errorf("SPF merged as %q", u.Content)
		}
	}
	for _, c := range created {
		if c.Comment != CFComment {
			t.Errorf("created without the hardyos comment: %+v", c)
		}
	}
}

func TestMergeSPF(t *testing.T) {
	for _, c := range [][3]string{
		{"v=spf1 include:_spf.google.com ~all", "v=spf1 mx include:amazonses.com -all", "v=spf1 include:_spf.google.com mx include:amazonses.com ~all"},
		{"v=spf1 mx include:amazonses.com -all", "v=spf1 mx include:amazonses.com -all", "v=spf1 mx include:amazonses.com -all"},
		{"", "v=spf1 mx -all", "v=spf1 mx -all"},
	} {
		if got := MergeSPF(c[0], c[1]); got != c[2] {
			t.Errorf("MergeSPF(%q) = %q, want %q", c[0], got, c[2])
		}
	}
}

func TestLocalFrom(t *testing.T) {
	for in, want := range map[string]string{"Zoë": "zoe", "Jean Luc": "jean.luc", "  ": "", "Ünal-Öz": "unal.oz", "李": ""} {
		if got := localFrom(in); got != want {
			t.Errorf("localFrom(%q) = %q, want %q", in, got, want)
		}
	}
}
