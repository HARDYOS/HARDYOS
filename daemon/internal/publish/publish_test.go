package publish

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/netbird"
	"github.com/hardyos/hardyos/daemon/internal/netbird/nbtest"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

type env struct {
	ctx context.Context
	db  *store.DB
	st  *Store
	nb  *nbtest.Server
	pub *Publisher
	in  Inputs
	// issuer is the sign-in provider's (pub.Issuer).
	issuer string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	nb := nbtest.New("nbp_token123")
	t.Cleanup(nb.Close)
	for i := range nb.Domains {
		nb.Domains[i].SupportsPrivate = true // a private proxy: the desktop is NetBird-only by default
	}
	st := &Store{DB: db, Sealer: &Sealer{KeyFile: filepath.Join(t.TempDir(), "secrets", "hardyd.key")}}
	pub := &Publisher{Store: st}
	e := &env{ctx: ctx, db: db, st: st, nb: nb, pub: pub, issuer: "https://sso.home.example.net",
		in: Inputs{NetBirdIP: "100.83.40.2", ManagementURL: nb.URL, Known: true,
			Apps: []App{{ID: "jellyfin", Name: "Jellyfin"}, {ID: "notes", Name: "Notes"}}}}
	if err := st.SetToken(ctx, "nbp_token123"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Save(ctx, Settings{Enabled: true, BaseDomain: "home.example.net", DefaultMode: ModePublic}); err != nil {
		t.Fatal(err)
	}
	pub.Issuer = func(context.Context) string { return e.issuer }
	return e
}

func (e *env) sync(t *testing.T) *Result {
	t.Helper()
	res, err := e.pub.Sync(e.ctx, e.in)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func item(res *Result, key string) Item {
	for _, it := range res.Items {
		if it.Key == key {
			return it
		}
	}
	return Item{}
}

func byDomain(nb *nbtest.Server, d string) *netbird.Service {
	for _, v := range nb.ServiceList() {
		if v.Domain == d {
			return &v
		}
	}
	return nil
}

func TestSealer(t *testing.T) {
	dir := t.TempDir()
	s := &Sealer{KeyFile: filepath.Join(dir, "k", "key")}
	v, err := s.Seal("remote.token", "nbp_secret")
	if err != nil || !strings.HasPrefix(v, "v1:") || strings.Contains(v, "nbp_secret") {
		t.Fatalf("seal = %q %v", v, err)
	}
	if got, err := s.Open("remote.token", v); err != nil || got != "nbp_secret" {
		t.Fatalf("open = %q %v", got, err)
	}
	if _, err := s.Open("remote.secret", v); !errors.Is(err, ErrSealed) {
		t.Fatalf("moved to another name: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, "k", "key"))
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Size() != 32 {
		t.Fatalf("key file %v %v", fi, err)
	}
	other := &Sealer{KeyFile: filepath.Join(t.TempDir(), "key")}
	if _, err := other.Open("remote.token", v); !errors.Is(err, ErrSealed) {
		t.Fatalf("another server's key: %v", err)
	}
	if _, err := s.Open("remote.token", "plain"); !errors.Is(err, ErrSealed) {
		t.Fatalf("unsealed value: %v", err)
	}
}

type fakeSource struct{ key []byte }

func (f fakeSource) Key(_ context.Context, purpose string) ([]byte, error) {
	if purpose != KeyPurpose {
		return nil, errors.New("wrong purpose " + purpose)
	}
	return f.key, nil
}

func TestSealerWithAKeySource(t *testing.T) {
	src := fakeSource{key: []byte("0123456789abcdef0123456789abcdef")}
	s := &Sealer{Source: src, KeyFile: filepath.Join(t.TempDir(), "unused")}
	v, err := s.Seal("remote.token", "nbp_secret")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := (&Sealer{Source: src}).Open("remote.token", v); err != nil || got != "nbp_secret" {
		t.Fatalf("open = %q %v", got, err)
	}
	if _, err := os.Stat(s.KeyFile); !os.IsNotExist(err) {
		t.Fatal("made a key file despite the source")
	}
	other := fakeSource{key: []byte("fedcba9876543210fedcba9876543210")}
	if _, err := (&Sealer{Source: other}).Open("remote.token", v); !errors.Is(err, ErrSealed) {
		t.Fatalf("another key: %v", err)
	}
}

func TestTokenIsSealedInTheDatabase(t *testing.T) {
	e := newEnv(t)
	raw, _ := e.db.GetSetting(e.ctx, "remote.token")
	if raw == "" || strings.Contains(raw, "nbp_token123") {
		t.Fatalf("raw token setting = %q", raw)
	}
	if tok, _ := e.st.Token(e.ctx); tok != "nbp_token123" {
		t.Fatalf("token = %q", tok)
	}
	s, _ := e.st.Load(e.ctx)
	if len(s.Instance) != 6 || s.DesktopName != "nas" {
		t.Fatalf("settings = %+v", s)
	}
	// Saving again keeps the instance tag.
	s2, _ := e.st.Save(e.ctx, Settings{Enabled: true, BaseDomain: "home.example.net", DefaultMode: ModePublic})
	if s2.Instance != s.Instance {
		t.Fatal("instance changed")
	}
	for _, bad := range []Settings{{BaseDomain: "Home.Example.net"}, {Enabled: true}, {BaseDomain: "x.example.net", DesktopName: "my nas"},
		{BaseDomain: "x.example.net", DefaultMode: "everyone"}, {BaseDomain: "x.example.net", APIURL: "http://vpn.example.net"}} {
		if _, err := e.st.Save(e.ctx, bad); err == nil {
			t.Errorf("%+v saved", bad)
		}
	}
}

func TestSyncCreatesKeepsAndRepairs(t *testing.T) {
	e := newEnv(t)
	res := e.sync(t)
	if res.Problem != "" || res.Created != 4 {
		t.Fatalf("first sync = %+v", res)
	}
	s, _ := e.st.Load(e.ctx)
	secret, _ := e.st.GatewaySecret(e.ctx)
	desk := byDomain(e.nb, "nas.home.example.net")
	jf := byDomain(e.nb, "jellyfin.home.example.net")
	if desk == nil || jf == nil || byDomain(e.nb, "notes.home.example.net") == nil {
		t.Fatalf("services = %+v", e.nb.ServiceList())
	}
	if jf.Name != "hardyos-"+s.Instance+"-app-jellyfin" || desk.Name != "hardyos-"+s.Instance+"-desktop" {
		t.Fatalf("names %q %q", jf.Name, desk.Name)
	}
	tg := jf.Targets[0]
	if len(jf.Targets) != 1 || tg.TargetType != "peer" || tg.TargetID != "peer-nas" || tg.Protocol != "https" || tg.Port != DefaultGatewayPort ||
		tg.Host != "100.83.40.2" || !tg.Options.SkipTLSVerify || tg.Options.CustomHeaders[GatewayHeader] != GatewayValue(secret, "jellyfin.home.example.net") || len(secret) != 64 {
		t.Fatalf("target = %+v %+v", tg, tg.Options)
	}
	// Each service carries its own value: the shared secret itself is in
	// no service, and one service's value is no other's.
	for _, v := range e.nb.ServiceList() {
		for _, x := range v.Targets {
			if got := x.Options.CustomHeaders[GatewayHeader]; got == secret || got != GatewayValue(secret, v.Domain) {
				t.Fatalf("%s carries %q", v.Domain, got)
			}
		}
	}
	if GatewayValue(secret, "jellyfin.home.example.net") == GatewayValue(secret, "notes.home.example.net") ||
		GatewayValue(secret, "Jellyfin.Home.Example.net") != GatewayValue(secret, "jellyfin.home.example.net") {
		t.Fatal("per-host values")
	}
	if !jf.PassHostHeader || jf.RewriteRedirect || jf.Private || jf.Auth.BearerAuth == nil || !jf.Auth.BearerAuth.Enabled {
		t.Fatalf("jellyfin = %+v", jf)
	}
	// The desktop is NetBird-only by default (All), nothing else in front.
	if !desk.Private || len(desk.AccessGroups) != 1 || desk.AccessGroups[0] != "group-all" || desk.Auth.BearerAuth != nil || len(desk.Targets) != 1 {
		t.Fatalf("desktop = %+v", desk)
	}
	// No share link yet: no files.<base>.
	if byDomain(e.nb, "files.home.example.net") != nil {
		t.Fatal("files published without a share link")
	}
	// HardyOS's sign-in provider: public, nothing in front, always.
	sso := byDomain(e.nb, "sso.home.example.net")
	if sso == nil || sso.Private || sso.Auth.BearerAuth != nil || sso.Name != "hardyos-"+s.Instance+"-sso" {
		t.Fatalf("sso = %+v", sso)
	}
	if b, _ := e.db.GetSetting(e.ctx, SettingBaseDomain); b != "home.example.net" {
		t.Fatalf("base domain for the sign-in provider = %q", b)
	}
	it := item(res, AppKey("jellyfin"))
	if !it.Published || it.URL != "https://jellyfin.home.example.net" || it.Status != "active" || it.Error != "" || !it.Config.Default {
		t.Fatalf("item = %+v", it)
	}

	// Nothing changed: nothing sent.
	puts := e.nb.Count("PUT ")
	if res := e.sync(t); res.Created+res.Updated+res.Deleted != 0 || e.nb.Count("PUT ") != puts {
		t.Fatalf("second sync = %+v", res)
	}

	// Someone changed HardyOS's service in NetBird's dashboard: put back,
	// keeping their IP rules.
	e.nb.Lock()
	for _, v := range e.nb.Services {
		if v.Domain == "jellyfin.home.example.net" {
			v.PassHostHeader = false
			v.AccessRestrictions = json.RawMessage(`{"allowed_countries":["US"]}`)
		}
	}
	e.nb.Unlock()
	if res := e.sync(t); res.Updated != 1 {
		t.Fatalf("repair = %+v", res)
	}
	jf = byDomain(e.nb, "jellyfin.home.example.net")
	if !jf.PassHostHeader || string(jf.AccessRestrictions) != `{"allowed_countries":["US"]}` {
		t.Fatalf("after repair = %+v %s", jf, jf.AccessRestrictions)
	}
}

func TestSyncOnlyTouchesItsOwnServices(t *testing.T) {
	e := newEnv(t)
	e.nb.Lock()
	e.nb.Services["foreign"] = &netbird.Service{ID: "foreign", Name: "grafana", Domain: "notes.home.example.net", Enabled: true}
	e.nb.Services["other-nas"] = &netbird.Service{ID: "other-nas", Name: "hardyos-ffffff-app-old", Domain: "old.home.example.net", Enabled: true}
	e.nb.Unlock()
	res := e.sync(t)
	if it := item(res, AppKey("notes")); it.Published || !strings.Contains(it.Error, "another NetBird service (grafana)") {
		t.Fatalf("notes = %+v", it)
	}
	if e.nb.Services["foreign"] == nil || e.nb.Services["other-nas"] == nil {
		t.Fatal("touched a service HardyOS doesn't own")
	}
	if e.nb.Count("DELETE ") != 0 || e.nb.Count("PUT ") != 0 {
		t.Fatalf("requests = %v", e.nb.Requests)
	}
}

func TestAppLifecycle(t *testing.T) {
	e := newEnv(t)
	e.sync(t)
	// An app the root helper didn't list (it didn't answer): left alone.
	e.in.Known, e.in.Apps = false, nil
	if res := e.sync(t); res.Deleted != 0 || byDomain(e.nb, "notes.home.example.net") == nil {
		t.Fatalf("unknown app list = %+v", res)
	}
	// Notes removed.
	e.in.Known, e.in.Apps = true, []App{{ID: "jellyfin", Name: "Jellyfin"}}
	if err := e.st.SetConfig(e.ctx, AppKey("notes"), ServiceConfig{Mode: ModeOff}, nil); err != nil {
		t.Fatal(err)
	}
	if res := e.sync(t); res.Deleted != 1 || byDomain(e.nb, "notes.home.example.net") != nil {
		t.Fatalf("removed app = %+v", res)
	}
	if e.st.exists(e.ctx, AppKey("notes")) {
		t.Fatal("a removed app's choice stays")
	}
	// Turned off for one app.
	_ = e.st.SetConfig(e.ctx, AppKey("jellyfin"), ServiceConfig{Mode: ModeOff, HardyOSSignIn: true}, nil)
	if res := e.sync(t); res.Deleted != 1 || byDomain(e.nb, "jellyfin.home.example.net") != nil {
		t.Fatalf("off = %+v", res)
	}
	// Publishing off removes the rest.
	s, _ := e.st.Load(e.ctx)
	s.Enabled = false
	_, _ = e.st.Save(e.ctx, s)
	if res := e.sync(t); res.Deleted != 2 || len(e.nb.ServiceList()) != 0 {
		t.Fatalf("disabled = %+v %v", res, e.nb.ServiceList())
	}
}

func TestPasswordPINAndSSOGroups(t *testing.T) {
	e := newEnv(t)
	pw := "family-secret-1"
	if err := e.st.SetConfig(e.ctx, AppKey("jellyfin"), ServiceConfig{Mode: ModePublic, Auth: AuthPassword, HardyOSSignIn: true}, &pw); err != nil {
		t.Fatal(err)
	}
	pin := "4821"
	if err := e.st.SetConfig(e.ctx, AppKey("notes"), ServiceConfig{Mode: ModePublic, Auth: AuthPIN}, &pin); err != nil {
		t.Fatal(err)
	}
	e.sync(t)
	// NetBird got the password once; it isn't in hardyd's database in the clear.
	sent := ""
	for _, b := range e.nb.Bodies {
		sent += string(b)
	}
	if !strings.Contains(sent, `"password":"family-secret-1"`) || !strings.Contains(sent, `"pin":"4821"`) {
		t.Fatalf("sent = %s", sent)
	}
	rows, _ := e.db.QueryContext(e.ctx, `SELECT secret || applied FROM remote_services`)
	for rows.Next() {
		var v string
		_ = rows.Scan(&v)
		if strings.Contains(v, pw) || strings.Contains(v, pin) {
			t.Fatalf("secret in the clear: %q", v)
		}
	}
	rows.Close()
	// Changing the password sends it again; keeping it doesn't.
	puts := e.nb.Count("PUT ")
	e.sync(t)
	if e.nb.Count("PUT ") != puts {
		t.Fatal("unchanged password sent again")
	}
	pw2 := "another-secret-2"
	_ = e.st.SetConfig(e.ctx, AppKey("jellyfin"), ServiceConfig{Mode: ModePublic, Auth: AuthPassword, HardyOSSignIn: true}, &pw2)
	if res := e.sync(t); res.Updated != 1 {
		t.Fatalf("new password = %+v", res)
	}
	// Password needed when switching to it.
	if err := e.st.SetConfig(e.ctx, AppKey("notes"), ServiceConfig{Mode: ModePublic, Auth: AuthPassword}, nil); err == nil {
		t.Fatal("switched to password without one")
	}
	short := "1234567"
	if err := e.st.SetConfig(e.ctx, AppKey("notes"), ServiceConfig{Mode: ModePublic, Auth: AuthPassword}, &short); err == nil {
		t.Fatal("short password")
	}
	bad := "12a4"
	if err := e.st.SetConfig(e.ctx, AppKey("notes"), ServiceConfig{Mode: ModePublic, Auth: AuthPIN}, &bad); err == nil {
		t.Fatal("PIN with a letter")
	}
	// SSO limited to a group.
	_ = e.st.SetConfig(e.ctx, AppKey("notes"), ServiceConfig{Mode: ModePublic, Auth: AuthSSO, Groups: []string{"group-family"}}, nil)
	e.sync(t)
	nt := byDomain(e.nb, "notes.home.example.net")
	if nt.Auth.BearerAuth == nil || len(nt.Auth.BearerAuth.DistributionGroups) != 1 || nt.Auth.PINAuth != nil {
		t.Fatalf("notes = %+v", nt.Auth)
	}
	// A group that went away.
	_ = e.st.SetConfig(e.ctx, AppKey("notes"), ServiceConfig{Mode: ModePublic, Auth: AuthSSO, Groups: []string{"group-gone"}}, nil)
	if it := item(e.sync(t), AppKey("notes")); !strings.Contains(it.Error, "doesn't exist") {
		t.Fatalf("gone group = %+v", it)
	}
	// Desktop with a password: share links and OIDC bypass it.
	dpw := "desktop-secret-9"
	_ = e.st.SetConfig(e.ctx, DesktopKey, ServiceConfig{Mode: ModePublic, Auth: AuthPassword}, &dpw)
	e.sync(t)
	d := byDomain(e.nb, "nas.home.example.net")
	if len(d.Targets) != 3 || *d.Targets[1].Path != "/s/" || d.Targets[1].AccessAction != "bypass" || *d.Targets[2].Path != "/oidc" {
		t.Fatalf("desktop targets = %+v", d.Targets)
	}
}

func TestNetBirdOnly(t *testing.T) {
	e := newEnv(t)
	e.nb.Lock()
	for i := range e.nb.Domains {
		e.nb.Domains[i].SupportsPrivate = false
	}
	e.nb.Unlock()
	_ = e.st.SetConfig(e.ctx, AppKey("jellyfin"), ServiceConfig{Mode: ModeNetBird, HardyOSSignIn: true}, nil)
	res := e.sync(t)
	// The desktop never goes public on its own when NetBird-only can't be had.
	if it := item(res, DesktopKey); it.Published || !strings.Contains(it.Error, "Private capability") {
		t.Fatalf("desktop without a private cluster = %+v", it)
	}
	if it := item(res, AppKey("jellyfin")); it.Published || !strings.Contains(it.Error, "Private capability") {
		t.Fatalf("no private cluster = %+v", it)
	}
	e.nb.Lock()
	for i := range e.nb.Domains {
		e.nb.Domains[i].SupportsPrivate = true
	}
	e.nb.Unlock()
	e.sync(t)
	jf := byDomain(e.nb, "jellyfin.home.example.net")
	if jf == nil || !jf.Private || len(jf.AccessGroups) != 1 || jf.AccessGroups[0] != "group-all" || jf.Auth.BearerAuth != nil {
		t.Fatalf("netbird-only = %+v", jf)
	}
	// Switching to NetBird-only on a cluster that loses Private takes it
	// off rather than leaving it public.
	e.nb.Lock()
	for i := range e.nb.Domains {
		e.nb.Domains[i].SupportsPrivate = false
	}
	e.nb.Unlock()
	if e.sync(t); byDomain(e.nb, "jellyfin.home.example.net") != nil {
		t.Fatal("kept a service that can't be what was asked")
	}
}

func TestSyncProblemsLeaveServicesAlone(t *testing.T) {
	e := newEnv(t)
	e.sync(t)
	n := len(e.nb.ServiceList())
	for name, change := range map[string]func(){
		"not connected": func() { e.in.NetBirdIP = "" },
		"domain gone": func() {
			e.nb.Lock()
			e.nb.Domains = e.nb.Domains[:1]
			e.nb.Unlock()
		},
	} {
		saved := e.in
		change()
		res := e.sync(t)
		if res.Problem == "" || len(e.nb.ServiceList()) != n || e.nb.Count("DELETE ") != 0 {
			t.Fatalf("%s: %+v", name, res)
		}
		e.in = saved
	}
	_ = e.st.SetToken(e.ctx, "nbp_wrong")
	if res := e.sync(t); !strings.Contains(res.Problem, "refused the access token") {
		t.Fatalf("bad token = %+v", res)
	}
	_ = e.st.SetToken(e.ctx, "")
	if res := e.sync(t); !strings.Contains(res.Problem, "access token") {
		t.Fatalf("no token = %+v", res)
	}
}

func TestShareLinksHost(t *testing.T) {
	e := newEnv(t)
	e.in.ShareLinks = true
	e.sync(t)
	f := byDomain(e.nb, "files.home.example.net")
	if f == nil || f.Private || f.Auth.BearerAuth != nil || len(f.Targets) != 2 || *f.Targets[0].Path != "/s/" ||
		*f.Targets[1].Path != "/" || f.Targets[1].AccessAction != "block" {
		t.Fatalf("files = %+v", f)
	}
	// The last link gone: so is the host, unless public share links are on.
	e.in.ShareLinks = false
	if res := e.sync(t); res.Deleted != 1 || byDomain(e.nb, "files.home.example.net") != nil {
		t.Fatalf("no links = %+v", res)
	}
	s, _ := e.st.Load(e.ctx)
	s.PublicShareLinks = true
	_, _ = e.st.Save(e.ctx, s)
	if e.sync(t); byDomain(e.nb, "files.home.example.net") == nil {
		t.Fatal("public share links on, no host")
	}
}

func TestRemoveAll(t *testing.T) {
	e := newEnv(t)
	e.sync(t)
	e.nb.Lock()
	e.nb.Services["foreign"] = &netbird.Service{ID: "foreign", Name: "grafana", Domain: "grafana.home.example.net"}
	e.nb.Unlock()
	n, err := e.pub.RemoveAll(e.ctx, e.in)
	if err != nil || n != 4 || len(e.nb.ServiceList()) != 1 {
		t.Fatalf("remove all = %d %v %v", n, err, e.nb.ServiceList())
	}
}

type fakeDNS map[string]string

func (f fakeDNS) LookupCNAME(_ context.Context, host string) (string, error) {
	for k, v := range f {
		if k == host || (strings.HasPrefix(k, "*.") && strings.HasSuffix(host, k[1:])) {
			return v, nil
		}
	}
	return "", errors.New("no such host")
}

func stepState(c *CheckResult, id string) string {
	for _, s := range c.Steps {
		if s.ID == id {
			return s.State + ": " + s.Detail
		}
	}
	return ""
}

func TestCheck(t *testing.T) {
	e := newEnv(t)
	sso := func(context.Context) string { return "https://nas.home.example.net/oidc" }
	c, err := e.pub.Check(e.ctx, e.in, fakeDNS{"*.home.example.net": "proxy.example.net."}, sso)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Ready || !strings.HasPrefix(stepState(c, "dns"), "ok") || !strings.HasPrefix(stepState(c, "token"), "ok") ||
		!strings.HasPrefix(stepState(c, "private"), "ok") || !strings.HasPrefix(stepState(c, "sso"), "warn") || !strings.HasPrefix(stepState(c, "peer"), "ok") {
		t.Fatalf("check = %+v", c.Steps)
	}
	if c.Record == nil || c.Record.Name != "*.home.example.net" || c.Record.Target != "proxy.example.net" || c.Record.Type != "CNAME" || c.Record.Proxy != "DNS only" {
		t.Fatalf("record = %+v", c.Record)
	}
	if len(c.Groups) != 2 || len(c.Clusters) != 1 {
		t.Fatalf("lists = %+v %+v", c.Groups, c.Clusters)
	}
	// NetBird signs in with HardyOS.
	e.nb.Lock()
	e.nb.IdPs = []netbird.IdentityProvider{{ID: "i1", Type: "oidc", Name: "HardyOS", Issuer: "https://nas.home.example.net/oidc/"}}
	e.nb.Unlock()
	c, _ = e.pub.Check(e.ctx, e.in, fakeDNS{"*.home.example.net": "edge.example.net", "proxy.example.net": "edge.example.net"}, sso)
	if !strings.HasPrefix(stepState(c, "sso"), "ok") || !strings.HasPrefix(stepState(c, "dns"), "ok") {
		t.Fatalf("sso / chained cname = %+v", c.Steps)
	}
	// The record is missing or wrong.
	c, _ = e.pub.Check(e.ctx, e.in, fakeDNS{}, nil)
	if !strings.Contains(stepState(c, "dns"), "No CNAME") || !c.Ready {
		t.Fatalf("no dns = %+v", c.Steps)
	}
	c, _ = e.pub.Check(e.ctx, e.in, fakeDNS{"*.home.example.net": "elsewhere.example.org"}, nil)
	if !strings.Contains(stepState(c, "dns"), "points at elsewhere.example.org") {
		t.Fatalf("wrong dns = %+v", c.Steps)
	}
	// A domain NetBird doesn't have yet: add it with the cluster, then verify.
	s, _ := e.st.Load(e.ctx)
	s.BaseDomain = "apps.example.net"
	_, _ = e.st.Save(e.ctx, s)
	c, _ = e.pub.Check(e.ctx, e.in, fakeDNS{}, nil)
	if c.Ready || !strings.HasPrefix(stepState(c, "domain"), "bad") || c.Record == nil || c.Record.Target != "proxy.example.net" {
		t.Fatalf("new domain = %+v %+v", c.Steps, c.Record)
	}
	if err := e.pub.AddDomain(e.ctx, e.in, ""); err != nil {
		t.Fatal(err)
	}
	c, _ = e.pub.Check(e.ctx, e.in, fakeDNS{}, nil)
	if !strings.HasPrefix(stepState(c, "domain"), "warn") {
		t.Fatalf("added domain = %+v", c.Steps)
	}
	if err := e.pub.VerifyDomain(e.ctx, e.in); err != nil {
		t.Fatal(err)
	}
	// Without a token nothing else can be checked.
	_ = e.st.SetToken(e.ctx, "")
	c, _ = e.pub.Check(e.ctx, e.in, fakeDNS{}, nil)
	if !strings.HasPrefix(stepState(c, "token"), "bad") || c.Ready {
		t.Fatalf("no token = %+v", c.Steps)
	}
}

// sso.<base> is published only while the sign-in provider's issuer is
// exactly https://sso.<base>: with any other issuer the provider doesn't
// answer there, and the host would be public with nothing behind it.
func TestSSOPublishedOnlyForItsOwnIssuer(t *testing.T) {
	for _, tc := range []struct {
		issuer string
		want   bool
	}{
		{"https://sso.home.example.net", true},
		{"https://sso.home.example.net/oidc", false},
		{"https://sso.home.example.net/", false},
		{"https://sso.home.example.net:8443", false},
		{"http://sso.home.example.net", false},
		{"https://nas.home.example.net/oidc", false},
		{"https://login.example.org", false},
		{"https://sso.other.example.net", false},
		{"", false},
	} {
		e := newEnv(t)
		e.issuer = tc.issuer
		res := e.sync(t)
		it := item(res, SSOKey)
		got := byDomain(e.nb, "sso.home.example.net") != nil
		if got != tc.want || it.Published != tc.want || (!tc.want && (it.Config.Mode != ModeOff || !strings.Contains(it.Error, "issuer"))) {
			t.Errorf("issuer %q: published %v (%+v)", tc.issuer, got, it)
		}
		// Nothing else depends on it.
		if byDomain(e.nb, "jellyfin.home.example.net") == nil {
			t.Errorf("issuer %q: apps not published", tc.issuer)
		}
	}
	// No provider at all.
	e := newEnv(t)
	e.pub.Issuer = nil
	if e.sync(t); byDomain(e.nb, "sso.home.example.net") != nil {
		t.Fatal("sso published without a provider")
	}
	// The issuer moving away takes the published host down.
	e = newEnv(t)
	e.sync(t)
	e.issuer = "https://sso.home.example.net/oidc"
	if res := e.sync(t); res.Deleted != 1 || byDomain(e.nb, "sso.home.example.net") != nil {
		t.Fatalf("issuer changed: %+v", res)
	}
	items, _ := e.pub.Items(e.ctx, e.in)
	for _, it := range items {
		if it.Key == SSOKey && it.Config.Mode != ModeOff {
			t.Fatalf("Items shows sso as %+v", it)
		}
	}
}

func TestRotatingTheGatewaySecretUpdatesEveryService(t *testing.T) {
	e := newEnv(t)
	e.sync(t)
	old, _ := e.st.GatewaySecret(e.ctx)
	if err := e.st.RotateGatewaySecret(e.ctx); err != nil {
		t.Fatal(err)
	}
	now, _ := e.st.GatewaySecret(e.ctx)
	if now == old || len(now) != 64 {
		t.Fatalf("secret %q -> %q", old, now)
	}
	if res := e.sync(t); res.Updated != 4 {
		t.Fatalf("after rotation = %+v", res)
	}
	for _, v := range e.nb.ServiceList() {
		if v.Targets[0].Options.CustomHeaders[GatewayHeader] != GatewayValue(now, v.Domain) {
			t.Fatalf("%s still has the old value", v.Domain)
		}
	}
}

// The desktop's name is never an app's address, even while the desktop
// isn't published.
func TestDesktopNameIsAlwaysReserved(t *testing.T) {
	e := newEnv(t)
	if err := e.st.SetConfig(e.ctx, DesktopKey, ServiceConfig{Mode: ModeOff}, nil); err != nil {
		t.Fatal(err)
	}
	e.in.Apps = append(e.in.Apps, App{ID: "nas", Name: "An app called nas"})
	res := e.sync(t)
	if it := item(res, AppKey("nas")); it.Published || !strings.Contains(it.Error, "desktop") {
		t.Fatalf("app nas = %+v", it)
	}
	if byDomain(e.nb, "nas.home.example.net") != nil {
		t.Fatal("an app took the desktop's address")
	}
}
