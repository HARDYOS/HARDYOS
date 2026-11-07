package mail

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func files(t *testing.T) map[string]File {
	t.Helper()
	cfg, err := sampleConfig().Normalize(sampleSecrets())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]File{}
	for _, f := range Render(cfg, sampleSecrets(), sampleEnv()) {
		out[f.Path] = f
	}
	return out
}

func TestNormalizeRefuses(t *testing.T) {
	sec := sampleSecrets()
	cases := map[string]func(c *RootConfig, s *RootSecrets){
		"no pool":           func(c *RootConfig, _ *RootSecrets) { c.Pool = "" },
		"bad hostname":      func(c *RootConfig, _ *RootSecrets) { c.Hostname = "mail" },
		"loopback vps":      func(c *RootConfig, _ *RootSecrets) { c.VPSPeer = "127.0.0.1" },
		"no domains":        func(c *RootConfig, _ *RootSecrets) { c.Domains = nil },
		"bad selector":      func(c *RootConfig, _ *RootSecrets) { c.Domains[0].Selector = "a b" },
		"foreign mailbox":   func(c *RootConfig, _ *RootSecrets) { c.Mailboxes[0].Address = "alice@elsewhere.test" },
		"duplicate address": func(c *RootConfig, _ *RootSecrets) { c.Mailboxes[1].Aliases = []string{"mom@example.net"} },
		"postmaster alias":  func(c *RootConfig, _ *RootSecrets) { c.Mailboxes[1].Aliases = []string{"postmaster@example.net"} },
		"group to nowhere":  func(c *RootConfig, _ *RootSecrets) { c.GroupAliases[0].Targets = []string{"zed@example.net"} },
		"ses elsewhere":     func(c *RootConfig, _ *RootSecrets) { c.SES.Host = "smtp.evil.test" },
		"ses no password":   func(_ *RootConfig, s *RootSecrets) { s.SESPassword = "" },
		"no auth secret":    func(_ *RootConfig, s *RootSecrets) { s.AuthSecret = "short" },
		"upper case":        func(c *RootConfig, _ *RootSecrets) { c.Mailboxes[0].Address = "Alice@example.net" },
		"newline in alias": func(c *RootConfig, _ *RootSecrets) {
			c.Mailboxes[0].Aliases = []string{"x\nrelayhost=evil@example.net"}
		},
		"space in host": func(c *RootConfig, _ *RootSecrets) { c.Hostname = "mail.example.net\nmynetworks = 0.0.0.0/0" },
		"dav for stranger": func(_ *RootConfig, s *RootSecrets) {
			s.DAV = map[string]string{"zed@example.net": strings.Repeat("a", 40)}
		},
		"notify elsewhere": func(c *RootConfig, _ *RootSecrets) { c.NotifyFrom = "x@other.test" },
		"quota too big":    func(c *RootConfig, _ *RootSecrets) { c.Mailboxes[0].QuotaMB = MaxQuotaMB + 1 },
	}
	for name, mut := range cases {
		c, s := sampleConfig(), sec
		c.SES = &RootSES{Host: c.SES.Host, Port: c.SES.Port, Username: c.SES.Username}
		c.Mailboxes = append([]RootMailbox(nil), c.Mailboxes...)
		c.Domains = append([]RootDomain(nil), c.Domains...)
		c.GroupAliases = []RootGroupAlias{{Address: "family@example.net", Targets: []string{"alice@example.net"}}}
		mut(&c, &s)
		if _, err := c.Normalize(s); err == nil {
			t.Errorf("%s: accepted", name)
		} else {
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Errorf("%s: %T %v isn't a ValidationError", name, err, err)
			}
		}
	}
	if _, err := sampleConfig().Normalize(sec); err != nil {
		t.Fatalf("sample refused: %v", err)
	}
}

func TestPostfixIsNoOpenRelay(t *testing.T) {
	fs := files(t)
	main := fs["/etc/postfix/main.cf"].Content
	master := fs["/etc/postfix/master.cf"].Content
	for _, want := range []string{
		"mynetworks = 127.0.0.0/8 [::1]/128\n",
		"smtpd_relay_restrictions = permit_sasl_authenticated, reject_unauth_destination\n",
		"smtpd_recipient_restrictions = reject_non_fqdn_recipient, reject_unlisted_recipient, reject_unauth_destination\n",
		"smtpd_tls_auth_only = yes\n",
		"smtpd_client_restrictions = reject\n",
		"authorized_submit_users = root\n",
		"relayhost = [email-smtp.us-east-1.amazonaws.com]:587\n",
		"smtp_tls_security_level = secure\n",
		"milter_default_action = tempfail\n",
		"smtpd_client_event_limit_exceptions = 100.90.1.2/32 127.0.0.0/8 [::1]/128\n",
	} {
		if !strings.Contains(main, want) {
			t.Errorf("main.cf lacks %q", want)
		}
	}
	for _, bad := range []string{"relay_domains", "permit_mynetworks", "0.0.0.0/0", "smtpd_sasl_auth_enable = yes"} {
		if strings.Contains(main, bad) {
			t.Errorf("main.cf has %q", bad)
		}
	}
	// No port 25 at home; every submission port encrypts, signs in and
	// checks the sender.
	for _, l := range strings.Split(master, "\n") {
		if strings.HasPrefix(l, "smtp ") && strings.Contains(l, " inet ") {
			t.Errorf("master.cf listens on port 25: %q", l)
		}
	}
	for _, svc := range []string{"submission", "submissions", "10587", "10465"} {
		i := strings.Index(master, "\n"+svc+" ")
		if i < 0 {
			t.Fatalf("no %s service", svc)
		}
		block := master[i+1:]
		if j := strings.Index(block[1:], "\n"+strings.Fields(block[1:])[0]); j > 0 {
			_ = j
		}
		end := strings.Index(block, "milter_macro_daemon_name=ORIGINATING")
		block = block[:end]
		for _, want := range []string{"smtpd_tls_security_level=encrypt", "smtpd_sasl_auth_enable=yes",
			"smtpd_client_restrictions=permit_sasl_authenticated,reject", "reject_sender_login_mismatch",
			"smtpd_relay_restrictions=permit_sasl_authenticated,reject"} {
			if !strings.Contains(block, want) {
				t.Errorf("%s lacks %s", svc, want)
			}
		}
		proxied := strings.HasPrefix(svc, "10")
		if strings.Contains(block, "smtpd_upstream_proxy_protocol=haproxy") != proxied {
			t.Errorf("%s: PROXY protocol should be %v", svc, proxied)
		}
	}
	if !strings.Contains(master, "smtpd_client_restrictions=check_client_access,cidr:/etc/postfix/hardyos/vps.cidr,reject") {
		t.Error("the relay port isn't limited to the VPS")
	}
	if got := fs["/etc/postfix/hardyos/vps.cidr"].Content; !strings.Contains(got, "\n100.90.1.2/32 OK\n") {
		t.Errorf("vps.cidr = %q", got)
	}
	senders := fs["/etc/postfix/hardyos/senders"].Content
	for _, want := range []string{"mom@example.net alice@example.net\n", "family@example.net alice@example.net,bob@example.net\n",
		"hardyos@example.net " + NotifyLogin + "\n"} {
		if !strings.Contains(senders, want) {
			t.Errorf("senders lacks %q", want)
		}
	}
	aliases := fs["/etc/postfix/hardyos/aliases"].Content
	for _, want := range []string{"postmaster@example.net alice@example.net\n", "abuse@family.example alice@example.net\n"} {
		if !strings.Contains(aliases, want) {
			t.Errorf("aliases lacks %q", want)
		}
	}
}

func TestSecretsStayPrivate(t *testing.T) {
	fs := files(t)
	sec := sampleSecrets()
	for p, f := range fs {
		world := f.Mode&0o004 != 0
		if strings.Contains(f.Content, sec.AuthSecret) && (world || p != DovecotConf) {
			t.Errorf("%s (%o) holds the auth secret", p, f.Mode)
		}
		if strings.Contains(f.Content, sec.SESPassword) && (f.Mode != 0o600 || f.Group != "") {
			t.Errorf("%s (%o %s) holds the SES password", p, f.Mode, f.Group)
		}
		if strings.Contains(f.Content, sec.DAV["alice@example.net"]) && (world || p != RadicaleUsers) {
			t.Errorf("%s holds a calendar password", p)
		}
	}
	if f := fs[DovecotConf]; f.Mode != 0o640 || f.Group != "dovecot" {
		t.Errorf("dovecot.conf %o %s", f.Mode, f.Group)
	}
}

func TestDovecotConfig(t *testing.T) {
	c := files(t)[DovecotConf].Content
	for _, want := range []string{
		"ssl = required\n", "auth_allow_cleartext = no\n", "haproxy_trusted_networks = 100.90.1.2\n",
		"auth_policy_reject_on_fail = yes\n", "grant_url = http://127.0.0.1:44250/token\n",
		"auth_policy_server_url = http://127.0.0.1:44250/policy\n", "mechanisms_filter = plain login\n",
		"port = 10993\n    ssl = yes\n    haproxy = yes\n", "inet_listener imap {\n    port = 0\n",
		"mail_home = /tank/mail/vmail/%{user | domain}/%{user | username}\n",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("dovecot.conf lacks %q", want)
		}
	}
	users := files(t)[DovecotDir+"/users"].Content
	if !strings.Contains(users, "alice@example.net::29990:29990::/tank/mail/vmail/example.net/alice::userdb_quota_storage_size=2048M\n") {
		t.Errorf("users file: %s", users)
	}
	if !strings.Contains(users, "bob@example.net::29990:29990::/tank/mail/vmail/example.net/bob::\n") {
		t.Errorf("bob (no quota): %s", users)
	}
	noV6 := sampleEnv()
	noV6.NoIPv6 = true
	cfg, _ := sampleConfig().Normalize(sampleSecrets())
	for _, f := range Render(cfg, sampleSecrets(), noV6) {
		if f.Path == DovecotConf && !strings.Contains(f.Content, "\nlisten = *\n") {
			t.Error("IPv6 listen without IPv6")
		}
		if f.Path == "/etc/postfix/main.cf" && !strings.Contains(f.Content, "inet_protocols = ipv4\n") {
			t.Error("Postfix uses IPv6 without IPv6")
		}
	}
}

func TestRspamdAndRadicale(t *testing.T) {
	fs := files(t)
	dk := fs[RspamdLocalDir+"/dkim_signing.conf"].Content
	if !strings.Contains(dk, `"example.net" {`) || !strings.Contains(dk, `path = "/tank/mail/keys/dkim/example.net.hardyos1.key";`) {
		t.Errorf("dkim_signing: %s", dk)
	}
	if !strings.Contains(fs[RspamdLocalDir+"/actions.conf"].Content, "reject = null;") {
		t.Error("Rspamd may reject (the VPS would bounce)")
	}
	if strings.Contains(fs[RspamdLocalDir+"/options.inc"].Content, "100.90.1.2") {
		t.Error("the VPS counts as local: its mail would skip the checks")
	}
	if !strings.Contains(fs[RspamdLocalDir+"/external_relay.conf"].Content, `ip_map = ["100.90.1.2"];`) {
		t.Error("external_relay doesn't name the VPS")
	}
	if !strings.Contains(fs[RspamdLocalDir+"/antivirus.conf"].Content, ClamdSocket) {
		t.Error("ClamAV on but not configured")
	}
	if !strings.Contains(fs[RadicaleConf].Content, "hosts = 127.0.0.1:5232\n") {
		t.Error("Radicale listens beyond localhost")
	}
	if !strings.Contains(fs[RadicaleRights].Content, "[family-collections]") {
		t.Error("no family calendar rights")
	}
	nft := fs[NFTFile].Content
	if !strings.Contains(nft, "ip saddr 100.90.1.2 accept") || !strings.Contains(nft, "tcp dport { 2525, 10587, 10465, 10993 } drop") {
		t.Errorf("nft: %s", nft)
	}
}

func TestRootApplyWritesAndRestores(t *testing.T) {
	dir := t.TempDir()
	written := map[string][]byte{}
	r := &Root{
		Write: func(p string, b []byte, _ os.FileMode) error {
			written[p] = append([]byte(nil), b...)
			return nil
		},
		Chown:      func(string, int, int) error { return nil },
		LookupUser: func(string) (int, int, error) { return 29990, 29990, nil },
		LookupGrp:  func(string) (int, error) { return 0, nil },
		Dataset:    func(context.Context, string) (string, error) { return dir, nil },
		SkipChecks: true,
		StateFile:  filepath.Join(dir, "state.json"),
		StartServices: func(context.Context, RootConfig, *ApplyResult) error {
			return nil
		},
	}
	// The TLS key is read back from disk: let writes under dir land.
	r.Write = func(p string, b []byte, m os.FileMode) error {
		written[p] = append([]byte(nil), b...)
		if strings.HasPrefix(p, dir) {
			return os.WriteFile(p, b, m)
		}
		return nil
	}
	res, err := r.Apply(context.Background(), ApplyArgs{Config: sampleConfig(), Secrets: sampleSecrets()})
	if err != nil {
		t.Fatal(err)
	}
	if res.DKIM["example.net"] == "" || res.DKIM["family.example"] == "" {
		t.Fatalf("DKIM keys: %v", res.DKIM)
	}
	key, err := os.ReadFile(filepath.Join(dir, "keys", "dkim", "example.net.hardyos1.key"))
	if err != nil || !strings.Contains(string(key), "PRIVATE KEY") {
		t.Fatalf("DKIM key: %v", err)
	}
	st, _ := os.Stat(filepath.Join(dir, "keys", "dkim", "example.net.hardyos1.key"))
	if st.Mode().Perm() != 0o640 {
		t.Errorf("DKIM key mode %o", st.Mode().Perm())
	}
	// Applying again keeps the same key.
	res2, err := r.Apply(context.Background(), ApplyArgs{Config: sampleConfig(), Secrets: sampleSecrets()})
	if err != nil || res2.DKIM["example.net"] != res.DKIM["example.net"] {
		t.Fatalf("the DKIM key changed: %v", err)
	}
	if _, ok := written["/etc/postfix/main.cf"]; !ok {
		t.Error("main.cf not written")
	}
	if _, ok := written[filepath.Join(RunTLSDir, "key.pem")]; !ok {
		t.Error("TLS key not installed for the services")
	}
	if _, err := os.Stat(r.StateFile); err != nil {
		t.Error("setup not remembered")
	}
}

func TestDeleteMailboxNeedsConfirmation(t *testing.T) {
	r := &Root{Dataset: func(context.Context, string) (string, error) { return t.TempDir(), nil }}
	err := r.DeleteMailbox(context.Background(), DeleteArgs{Pool: "tank", Address: "alice@example.net", Confirm: "alice"})
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("deleted without the typed address: %v", err)
	}
	if err := r.DeleteMailbox(context.Background(), DeleteArgs{Pool: "tank", Address: "../x@example.net", Confirm: "../x@example.net"}); err == nil {
		t.Fatal("a path in the address was accepted")
	}
}

func TestMatchKey(t *testing.T) {
	dir := t.TempDir()
	e := Env{MailRoot: dir}
	r := &Root{Write: func(p string, b []byte, m os.FileMode) error {
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		return os.WriteFile(p, b, m)
	}}
	if err := r.ensureTLS(e, "mail.example.net"); err != nil {
		t.Fatal(err)
	}
	key, _ := os.ReadFile(e.TLSKey())
	chain, _ := os.ReadFile(e.TLSChain())
	certs, err := matchKey(key, chain)
	if err != nil || certs[0].DNSNames[0] != "mail.example.net" {
		t.Fatalf("%v %v", certs, err)
	}
	other := t.TempDir()
	_ = r.ensureTLS(Env{MailRoot: other}, "mail.example.net")
	otherKey, _ := os.ReadFile(Env{MailRoot: other}.TLSKey())
	if _, err := matchKey(otherKey, chain); err == nil {
		t.Fatal("a certificate for another key was accepted")
	}
	if !certInfo(certs).SelfSigned {
		t.Error("self-signed not noticed")
	}
}

func TestParseQueueAndQuota(t *testing.T) {
	q := ParseQueue([]byte(`{"queue_name":"deferred","queue_id":"4F2A1","arrival_time":1700000000,"message_size":1234,"sender":"a@example.net","recipients":[{"address":"b@x.test","delay_reason":"connect to email-smtp.us-east-1.amazonaws.com: Connection timed out"}]}
not json
{"queue_name":"active","queue_id":"5B","arrival_time":1700000100,"message_size":1,"sender":"","recipients":[]}
`), 10)
	if len(q) != 2 || q[0].Reason == "" || q[0].Recipients[0] != "b@x.test" || q[1].Queue != "active" {
		t.Fatalf("%+v", q)
	}
	u := ParseQuota("a@example.net", []byte("quota name\ttype\tvalue\tlimit\t%\nUser quota\tSTORAGE\t2048\t10240\t20\nUser quota\tMESSAGE\t12\t-\t0\n"))
	if u.UsedKB != 2048 || u.LimitKB != 10240 {
		t.Fatalf("%+v", u)
	}
}

// ---- DNS ----

type fakeResolver struct {
	mx    map[string][]*net.MX
	txt   map[string][]string
	cname map[string]string
	ip    map[string][]netip.Addr
	srv   map[string][]*net.SRV
}

func nf(name string) error { return &net.DNSError{Name: name, IsNotFound: true} }

func (f *fakeResolver) LookupMX(_ context.Context, n string) ([]*net.MX, error) {
	if v, ok := f.mx[n]; ok {
		return v, nil
	}
	return nil, nf(n)
}
func (f *fakeResolver) LookupTXT(_ context.Context, n string) ([]string, error) {
	if v, ok := f.txt[n]; ok {
		return v, nil
	}
	return nil, nf(n)
}
func (f *fakeResolver) LookupCNAME(_ context.Context, n string) (string, error) {
	if v, ok := f.cname[n]; ok {
		return v + ".", nil
	}
	return n + ".", nil
}
func (f *fakeResolver) LookupNetIP(_ context.Context, _, n string) ([]netip.Addr, error) {
	if v, ok := f.ip[n]; ok {
		return v, nil
	}
	return nil, nf(n)
}
func (f *fakeResolver) LookupSRV(_ context.Context, _, _, n string) (string, []*net.SRV, error) {
	if v, ok := f.srv[n]; ok {
		return n, v, nil
	}
	return "", nil, nf(n)
}

func TestDNSRecordsAndChecks(t *testing.T) {
	d := DomainDNS{Domain: "example.net", Hostname: "mail.example.net", DKIMSelector: "hardyos1", DKIMPublicKey: "MIIBKEY",
		DMARCPolicy: "quarantine", DMARCReports: "postmaster@example.net", SES: true, SESRegion: "eu-west-1",
		SESDKIM: []string{"tok1", "tok2", "tok3"}, SESMailFrom: true}
	recs := append(ServerRecords("mail.example.net", "203.0.113.5", ""), Records(d)...)
	byName := map[string]Record{}
	for _, r := range recs {
		byName[r.Type+" "+r.Name] = r
	}
	if r := byName["MX example.net"]; r.Value != "mail.example.net" || !r.Required {
		t.Errorf("MX %+v", r)
	}
	if r := byName["TXT example.net"]; r.Value != "v=spf1 mx include:amazonses.com -all" {
		t.Errorf("SPF %+v", r)
	}
	if r := byName["TXT hardyos1._domainkey.example.net"]; r.Value != "v=DKIM1; k=rsa; p=MIIBKEY" {
		t.Errorf("DKIM %+v", r)
	}
	if r := byName["CNAME tok2._domainkey.example.net"]; r.Value != "tok2.dkim.amazonses.com" {
		t.Errorf("SES %+v", r)
	}
	if r := byName["MX bounce.example.net"]; r.Value != "feedback-smtp.eu-west-1.amazonses.com" {
		t.Errorf("MAIL FROM %+v", r)
	}
	if _, ok := byName["TXT _mta-sts.example.net"]; ok {
		t.Error("MTA-STS listed while off")
	}

	res := &fakeResolver{
		mx:    map[string][]*net.MX{"example.net": {{Host: "mail.example.net.", Pref: 10}}},
		txt:   map[string][]string{"example.net": {"v=spf1 include:_spf.google.com mx include:amazonses.com ~all", "google-site-verification=x"}, "hardyos1._domainkey.example.net": {"v=DKIM1; k=rsa; p=MIIB", "KEY"}, "_dmarc.example.net": {"v=DMARC1; p=none"}},
		cname: map[string]string{"tok1._domainkey.example.net": "tok1.dkim.amazonses.com"},
		ip:    map[string][]netip.Addr{"mail.example.net": {netip.MustParseAddr("198.51.100.9")}},
		srv:   map[string][]*net.SRV{"_imaps._tcp.example.net": {{Target: "mail.example.net.", Port: 993, Weight: 1}}, "_imap._tcp.example.net": {{Target: ".", Port: 0}}},
	}
	// The DKIM record is split in two strings by DNS: net joins them.
	res.txt["hardyos1._domainkey.example.net"] = []string{"v=DKIM1; k=rsa; p=MIIBKEY"}
	checks := CheckRecords(context.Background(), res, recs)
	got := map[string]string{}
	for _, c := range checks {
		got[c.Type+" "+c.Name] = c.Status
	}
	want := map[string]string{
		"MX example.net": "ok", "TXT example.net": "ok", "TXT hardyos1._domainkey.example.net": "ok",
		"TXT _dmarc.example.net": "ok", "CNAME tok1._domainkey.example.net": "ok", "CNAME tok2._domainkey.example.net": "missing",
		"A mail.example.net": "wrong", "SRV _imaps._tcp.example.net": "ok", "SRV _imap._tcp.example.net": "ok",
		"SRV _submissions._tcp.example.net": "missing",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %s, want %s", k, got[k], v)
		}
	}
	s := Summarize(checks)
	if s.Ready || s.Problems == 0 {
		t.Errorf("summary %+v", s)
	}
	// Two SPF records are an error.
	st, why := matchTXT(Record{Match: "spf", Value: "v=spf1 mx -all"}, []string{"v=spf1 mx -all", "v=spf1 a -all"})
	if st != "wrong" || !strings.Contains(why, "several") {
		t.Errorf("two SPF: %s %s", st, why)
	}
	if st, _ := matchTXT(Record{Match: "spf", Value: "v=spf1 mx include:amazonses.com -all"}, []string{"v=spf1 mx -all"}); st != "wrong" {
		t.Error("SPF without SES accepted")
	}
}

// ---- client settings ----

func TestClientSettings(t *testing.T) {
	c := ClientSettings{Domain: "example.net", Hostname: "mail.example.net", Address: "alice@example.net", Name: "Alice <&>", DAV: true}
	var ac struct {
		Provider struct {
			Incoming struct {
				Host string `xml:"hostname"`
				Port int    `xml:"port"`
				Sock string `xml:"socketType"`
			} `xml:"incomingServer"`
		} `xml:"emailProvider"`
	}
	if err := xml.Unmarshal([]byte(AutoconfigXML(c)), &ac); err != nil || ac.Provider.Incoming.Host != "mail.example.net" || ac.Provider.Incoming.Port != 993 || ac.Provider.Incoming.Sock != "SSL" {
		t.Fatalf("autoconfig %+v %v", ac, err)
	}
	var ad struct {
		Resp struct {
			Acct struct {
				Protos []struct {
					Type  string `xml:"Type"`
					Port  int    `xml:"Port"`
					Login string `xml:"LoginName"`
				} `xml:"Protocol"`
			} `xml:"Account"`
		} `xml:"Response"`
	}
	if err := xml.Unmarshal([]byte(AutodiscoverXML(c)), &ad); err != nil || len(ad.Resp.Acct.Protos) != 2 || ad.Resp.Acct.Protos[0].Login != "alice@example.net" {
		t.Fatalf("autodiscover %+v %v", ad, err)
	}
	mc := string(MobileConfig(c))
	if err := xml.Unmarshal([]byte(mc), new(any)); err != nil {
		// plist isn't a generic tree xml.Unmarshal accepts into any; check well-formedness by a decoder.
		dec := xml.NewDecoder(strings.NewReader(mc))
		for {
			if _, err := dec.Token(); err != nil {
				if err != io.EOF {
					t.Fatalf("mobileconfig isn't well-formed: %v", err)
				}
				break
			}
		}
	}
	for _, want := range []string{"com.apple.mail.managed", "com.apple.caldav.account", "Alice &lt;&amp;&gt;", "<integer>993</integer>",
		"https://mail.example.net/dav-mail/alice@example.net/"} {
		if !strings.Contains(mc, want) {
			t.Errorf("mobileconfig lacks %q", want)
		}
	}
	if strings.Contains(mc, "<key>IncomingPassword</key>") || strings.Contains(mc, "<key>OutgoingPassword</key>") {
		t.Error("the profile carries a password")
	}
	if uuidFrom("a") != uuidFrom("a") || uuidFrom("a") == uuidFrom("b") {
		t.Error("profile identifiers aren't stable")
	}
}

// ---- VPS ----

func TestVPSScript(t *testing.T) {
	s, err := VPSScript(VPSSetup{Hostname: "mail.example.net", HomePeer: "100.90.1.7", Domains: []string{"family.example", "example.net"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"relay_domains = example.net family.example\n", "example.net smtp:[100.90.1.7]:2525\n",
		"smtpd_relay_restrictions = reject_unauth_destination\n", "reject_unverified_recipient\n",
		"mynetworks = 127.0.0.0/8 [::1]/128\n", "maximal_queue_lifetime = 14d\n",
		"server home 100.90.1.7:10993 send-proxy-v2", "server home 100.90.1.7:10465 send-proxy-v2", "server home 100.90.1.7:10587 send-proxy-v2",
		"set -euo pipefail", "postfix check", "haproxy -c -f",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	if strings.Contains(s, "permit_mynetworks") || strings.Contains(s, "smtpd_sasl_auth_enable = yes") {
		t.Error("the VPS could relay")
	}
	if _, err := VPSScript(VPSSetup{Hostname: "mail.example.net", HomePeer: "", Domains: []string{"example.net"}}); err == nil {
		t.Error("no NetBird address accepted")
	}
	if _, err := VPSScript(VPSSetup{Hostname: "mail.example.net", HomePeer: "100.90.1.7", Domains: []string{"ex$ample.net"}}); err == nil {
		t.Error("bad domain accepted")
	}
}

// portDialer sends each port to a local listener.
type portDialer map[string]string

func (p portDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	_, port, _ := net.SplitHostPort(addr)
	var d net.Dialer
	return d.DialContext(ctx, network, p[port])
}

func fakeSMTP(t *testing.T, rcptReply string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.WriteString(c, "220 mail.example.net ESMTP\r\n")
				buf := make([]byte, 512)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					line := strings.ToUpper(string(buf[:n]))
					switch {
					case strings.HasPrefix(line, "EHLO"):
						io.WriteString(c, "250-mail.example.net\r\n250 PIPELINING\r\n")
					case strings.HasPrefix(line, "MAIL"):
						io.WriteString(c, "250 2.1.0 Ok\r\n")
					case strings.HasPrefix(line, "RCPT"):
						io.WriteString(c, rcptReply+"\r\n")
					case strings.HasPrefix(line, "QUIT"):
						io.WriteString(c, "221 Bye\r\n")
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestCheckVPS(t *testing.T) {
	ok := fakeSMTP(t, "550 5.1.1 <x@example.net>: Recipient address rejected: undeliverable address: host 100.90.1.7[100.90.1.7] said: 550 5.1.1 User unknown in virtual mailbox table")
	down := fakeSMTP(t, "450 4.1.1 <x@example.net>: Recipient address rejected: unverified address: connect to 100.90.1.7[100.90.1.7]:2525: Connection refused")
	ctx := context.Background()
	got := CheckVPS(ctx, portDialer{"25": ok, "993": "127.0.0.1:1", "465": "127.0.0.1:1"}, "203.0.113.5", "mail.example.net", "example.net", "")
	if !got[0].OK {
		t.Fatalf("working relay not recognised: %+v", got[0])
	}
	if got[1].OK || got[2].OK {
		t.Error("closed ports reported working")
	}
	got = CheckVPS(ctx, portDialer{"25": down, "993": "127.0.0.1:1", "465": "127.0.0.1:1"}, "203.0.113.5", "mail.example.net", "example.net", "")
	if got[0].OK || !strings.Contains(got[0].Detail, "couldn't reach HardyOS") {
		t.Fatalf("broken path not recognised: %+v", got[0])
	}
}

// ---- sign-in ----

func TestThrottleNeverLocksOutTheLAN(t *testing.T) {
	th := NewThrottle()
	attacker := netip.MustParseAddr("198.51.100.66")
	lan := netip.MustParseAddr("192.168.1.20")
	for i := 0; i < 10; i++ {
		th.Result("admin@example.net", attacker, false)
	}
	if v := th.Check("admin@example.net", attacker); !v.Block {
		t.Fatal("the attacker isn't blocked")
	}
	if v := th.Check("admin@example.net", lan); v.Block || v.Wait > 0 {
		t.Fatalf("the LAN is held back by an internet attack: %+v", v)
	}
	// Mistakes on the LAN slow down, never block.
	for i := 0; i < 50; i++ {
		th.Result("admin@example.net", lan, false)
	}
	if v := th.Check("admin@example.net", lan); v.Block {
		t.Fatal("the LAN was blocked")
	} else if v.Wait > 31*time.Second {
		t.Fatalf("LAN wait %s", v.Wait)
	}
	for _, a := range []string{"10.0.0.1", "172.17.0.2", "100.90.1.2", "fd00::1", "127.0.0.1"} {
		if !Inside(netip.MustParseAddr(a)) {
			t.Errorf("%s isn't inside", a)
		}
	}
	if Inside(attacker) {
		t.Error("an internet address counts as inside")
	}
}

type checker map[string]string

func (c checker) CheckLogin(_ context.Context, l, s string) error {
	if c[l] == s && s != "" {
		return nil
	}
	return ErrBadLogin
}

func TestAuthServer(t *testing.T) {
	secret := strings.Repeat("s", 40)
	as := &AuthServer{Secret: func() string { return secret }, Checker: checker{"alice@example.net": "pw1"}, Limits: NewThrottle()}
	srv := httptest.NewServer(as)
	defer srv.Close()
	post := func(path string, form url.Values, hdr map[string]string) (int, string) {
		req, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	grant := url.Values{"grant_type": {"password"}, "username": {"Alice@example.net"}, "password": {"pw1"}, "client_id": {"dovecot"}, "client_secret": {secret}}
	if code, body := post("/token", grant, nil); code != 200 || !strings.Contains(body, `"username":"alice@example.net"`) || !strings.Contains(body, `"active":"true"`) {
		t.Fatalf("grant %d %s", code, body)
	}
	bad := url.Values{"grant_type": {"password"}, "username": {"alice@example.net"}, "password": {"nope"}, "client_secret": {secret}}
	if code, _ := post("/token", bad, nil); code != 400 {
		t.Fatalf("wrong password: %d", code)
	}
	noClient := url.Values{"grant_type": {"password"}, "username": {"alice@example.net"}, "password": {"pw1"}, "client_secret": {"guess"}}
	if code, _ := post("/token", noClient, nil); code != 401 {
		t.Fatalf("without the client secret: %d", code)
	}
	// Policy needs the bearer secret.
	req, _ := http.NewRequest("POST", srv.URL+"/policy?command=allow", strings.NewReader(`{"login":"a@example.net","remote":"198.51.100.66"}`))
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("policy without the secret: %d", resp.StatusCode)
	}
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("POST", srv.URL+"/policy?command=report", strings.NewReader(`{"login":"a@example.net","remote":"198.51.100.66","success":false,"fail_type":"credentials"}`))
		req.Header.Set("Authorization", "Bearer "+secret)
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
	}
	req, _ = http.NewRequest("POST", srv.URL+"/policy?command=allow", strings.NewReader(`{"login":"a@example.net","remote":"198.51.100.66"}`))
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, _ = http.DefaultClient.Do(req)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), `"status":-1`) {
		t.Fatalf("blocked address allowed: %s", b)
	}
	// Mail off: everything refused.
	as.Secret = func() string { return "" }
	if code, _ := post("/token", grant, nil); code != 401 {
		t.Fatalf("grant while off: %d", code)
	}
}

func TestAuthServerLoopbackOnly(t *testing.T) {
	as := &AuthServer{Secret: func() string { return "x" }, Checker: checker{}, Limits: NewThrottle()}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/token", nil)
	req.RemoteAddr = "192.168.1.5:4000"
	as.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("a LAN client reached the sign-in listener: %d", rec.Code)
	}
}

func TestLocalPartAndAddresses(t *testing.T) {
	for _, a := range []string{"alice@example.net", "a.b+c_d-e@sub.example.co"} {
		if _, err := NormalizeAddress(a); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
	for _, a := range []string{"a..b@example.net", ".a@example.net", "a@example", "a@-x.net", "a b@x.net", "a@x.123"} {
		if _, err := NormalizeAddress(a); err == nil {
			t.Errorf("%s accepted", a)
		}
	}
}
