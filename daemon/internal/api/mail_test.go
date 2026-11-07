package api

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/mail"
	"github.com/hardyos/hardyos/daemon/internal/mail/manage"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// newMailEnv is a hardyd with the mail server and a root helper whose mail
// operations write into a temporary folder and start nothing.
func newMailEnv(t *testing.T) (*testEnv, *manage.Service, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	broker := events.NewBroker()
	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	etc := t.TempDir()
	pool := t.TempDir()
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	priv.RegisterBuiltins(ps)
	fake := (&sysexec.Fake{}).OnPrefix("systemctl", sysexec.Result{}).OnPrefix("nft", sysexec.Result{}).
		OnPrefix("postqueue", sysexec.Result{}).OnPrefix("doveadm", sysexec.Result{}).OnPrefix("zfs", sysexec.Result{Stdout: []byte("1048576\n")})
	priv.RegisterMail(ps, &mail.Root{
		Runner: fake,
		Write: func(p string, b []byte, m os.FileMode) error {
			if !strings.HasPrefix(p, pool) {
				p = filepath.Join(etc, p)
			}
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return err
			}
			return os.WriteFile(p, b, m)
		},
		Chown:         func(string, int, int) error { return nil },
		LookupUser:    func(string) (int, int, error) { return 29990, 29990, nil },
		LookupGrp:     func(string) (int, error) { return 0, nil },
		Dataset:       func(context.Context, string) (string, error) { return pool, nil },
		SkipChecks:    true,
		StateFile:     filepath.Join(etc, "mail.json"),
		StartServices: func(context.Context, mail.RootConfig, *mail.ApplyResult) error { return nil },
	})
	go func() { _ = ps.Serve(ctx, ln) }()
	pc := priv.NewClient(sock)
	svc := &manage.Service{Store: &manage.Store{DB: db, Keys: secretbox.NewStaticSource()}, Priv: pc}
	m := &jobs.Manager{DB: db, Events: broker}
	RegisterJobKinds(m, pc)
	RegisterMailJobs(m, svc, pc)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Config{DB: db, Jobs: m, Events: broker, Priv: pc, Insecure: true, Mail: svc}))
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	return &testEnv{srv: srv, db: db, broker: broker}, svc, etc
}

func TestMailAPI(t *testing.T) {
	env, svc, etc := newMailEnv(t)
	admin := adminClient(t, env)
	admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	kid := env.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	if code := kid.do("GET", "/api/v1/mail", nil, nil); code != 403 {
		t.Fatalf("a non-administrator saw the mail settings: %d", code)
	}
	if code := admin.do("POST", "/api/v1/mail/domains", map[string]any{"name": "Example.NET"}, nil); code != 200 {
		t.Fatalf("add domain %d", code)
	}
	if code := admin.do("POST", "/api/v1/mail/domains", map[string]any{"name": "bad domain"}, nil); code != 400 {
		t.Fatalf("bad domain %d", code)
	}
	// Turning it on needs a pool, a name and the VPS.
	var e ErrorResponse
	if code := admin.do("PUT", "/api/v1/mail/settings", map[string]any{"settings": map[string]any{"enabled": true}}, &e); code != 400 {
		t.Fatalf("enabled without settings: %d %v", code, e)
	}
	st := manage.DefaultSettings()
	st.Enabled, st.Pool, st.Hostname, st.VPSPeer, st.DefaultDomain = true, "tank", "mail.example.net", "100.90.1.2", "example.net"
	var acc JobAccepted
	if code := admin.do("PUT", "/api/v1/mail/settings", map[string]any{"settings": st}, &acc); code != 202 {
		t.Fatalf("enable %d", code)
	}
	j := waitJob(t, admin, acc.Job.(map[string]any)["id"].(string))
	if j["state"] != "succeeded" {
		t.Fatalf("apply job %v", j)
	}
	d, _ := svc.Store.GetDomain(context.Background(), "example.net")
	if d.DKIMPublic == "" {
		t.Fatal("the DKIM key wasn't stored")
	}
	if b, err := os.ReadFile(filepath.Join(etc, "etc/postfix/main.cf")); err != nil || !strings.Contains(string(b), "myhostname = mail.example.net") {
		t.Fatalf("main.cf: %v", err)
	}
	var dns MailDNS
	if code := admin.do("GET", "/api/v1/mail/domains/example.net/dns", nil, &dns); code != 200 || len(dns.Records) < 5 || dns.Records[0].Type != "MX" {
		t.Fatalf("dns %d %+v", code, dns)
	}
	var vps MailVPS
	if code := admin.do("GET", "/api/v1/mail/vps", nil, &vps); code != 200 || vps.Problem == "" {
		t.Fatalf("vps without NetBird %d %+v", code, vps)
	}
	// The kid is a local account: no mailbox, a reason.
	var me MailMe
	if code := kid.do("GET", "/api/v1/mail/me", nil, &me); code != 200 || !me.Enabled || me.Mailbox != nil || me.Reason == "" {
		t.Fatalf("me %d %+v", code, me)
	}
	// Mailbox deletion needs the address typed and a gone account.
	mb, _ := svc.Store.CreateMailbox(context.Background(), manage.Mailbox{Account: "alice", Address: "alice@example.net", Enabled: true, AccountState: "active"})
	if code := admin.do("DELETE", "/api/v1/mail/mailboxes/"+itoa(int(mb.ID)), map[string]string{"confirm": "alice"}, nil); code != 400 {
		t.Fatalf("delete without confirmation: %d", code)
	}
	if code := admin.do("DELETE", "/api/v1/mail/mailboxes/"+itoa(int(mb.ID)), map[string]string{"confirm": "alice@example.net"}, nil); code != 409 {
		t.Fatalf("delete of an active account's mailbox: %d", code)
	}
	// Mail app settings, without a sign-in.
	resp, err := http.Get(env.srv.URL + "/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress=alice@example.net")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), "<hostname>mail.example.net</hostname>") {
		t.Fatalf("autoconfig %d %s", resp.StatusCode, b)
	}
	resp, _ = http.Post(env.srv.URL+"/autodiscover/autodiscover.xml", "text/xml", strings.NewReader(
		`<Autodiscover><Request><EMailAddress>alice@example.net</EMailAddress></Request></Autodiscover>`))
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), "<LoginName>alice@example.net</LoginName>") {
		t.Fatalf("autodiscover %d %s", resp.StatusCode, b)
	}
	// Calendars need a sign-in.
	resp, _ = http.Get(env.srv.URL + "/dav-mail/")
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("calendars without a sign-in: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("PROPFIND", env.srv.URL+"/dav-mail/alice@example.net/", nil)
	req.SetBasicAuth("alice@example.net", "wrong")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("calendars with a wrong password: %d", resp.StatusCode)
	}
	// Turning it off is a job too.
	st.Enabled = false
	if code := admin.do("PUT", "/api/v1/mail/settings", map[string]any{"settings": st}, &acc); code != 202 {
		t.Fatalf("disable %d", code)
	}
	if j := waitJob(t, admin, acc.Job.(map[string]any)["id"].(string)); j["state"] != "succeeded" || j["kind"] != JobKindMailDisable {
		t.Fatalf("disable job %v", j)
	}
}

func TestMailPublicPaths(t *testing.T) {
	for p, want := range map[string]bool{"/dav-mail/x/": true, "/autodiscover/autodiscover.xml": true, "/": false,
		"/api/v1/mail": false, "/s/abc": false, "/.well-known/caldav": true, "/oidc/authorize": false} {
		if mailPublicPath(p) != want {
			t.Errorf("%s: %v", p, !want)
		}
	}
}
