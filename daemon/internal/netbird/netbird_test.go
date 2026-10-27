package netbird

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// recorded serves the recorded answers by method and path and remembers
// what it was sent.
type recorded struct {
	mu      sync.Mutex
	answers map[string]struct {
		status int
		body   []byte
	}
	got []string
	// bodies are the request bodies by "METHOD path".
	bodies map[string][]byte
	auth   []string
}

func newRecorded() *recorded {
	return &recorded{answers: map[string]struct {
		status int
		body   []byte
	}{}, bodies: map[string][]byte{}}
}

func (r *recorded) on(method, path string, status int, body []byte) {
	r.answers[method+" "+path] = struct {
		status int
		body   []byte
	}{status, body}
}

func (r *recorded) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := req.Method + " " + req.URL.RequestURI()
	r.got = append(r.got, key)
	r.auth = append(r.auth, req.Header.Get("Authorization"))
	b, _ := io.ReadAll(req.Body)
	r.bodies[key] = b
	a, ok := r.answers[key]
	if !ok {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"message":"not found","code":404}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(a.status)
	_, _ = w.Write(a.body)
}

func TestAPIAgainstRecordedAnswers(t *testing.T) {
	rec := newRecorded()
	rec.on("GET", "/api/peers?ip=100.83.40.2", 200, fixture(t, "peers.json"))
	rec.on("GET", "/api/groups", 200, fixture(t, "groups.json"))
	rec.on("GET", "/api/reverse-proxies/clusters", 200, fixture(t, "clusters.json"))
	rec.on("GET", "/api/reverse-proxies/domains", 200, fixture(t, "domains.json"))
	rec.on("GET", "/api/reverse-proxies/services", 200, fixture(t, "services.json"))
	rec.on("POST", "/api/reverse-proxies/services", 200, fixture(t, "service-created.json"))
	rec.on("PUT", "/api/reverse-proxies/services/cs9newservice00000001", 200, fixture(t, "service-created.json"))
	rec.on("DELETE", "/api/reverse-proxies/services/cs9newservice00000001", 200, nil)
	rec.on("POST", "/api/reverse-proxies/domains", 200, []byte(`{}`))
	rec.on("GET", "/api/reverse-proxies/domains/ds8i4ug6lnn4g9hqv7m2/validate", 200, nil)
	srv := httptest.NewServer(rec)
	defer srv.Close()
	ctx := context.Background()
	a := &API{BaseURL: srv.URL + "/api/", Token: "nbp_secret"}

	peers, err := a.Peers(ctx, "100.83.40.2")
	if err != nil || len(peers) != 1 || peers[0].ID != "chacbco6lnnbn6cg5s90" || peers[0].IP != "100.83.40.2" || peers[0].Groups[0].Name != "All" {
		t.Fatalf("peers = %+v, %v", peers, err)
	}
	groups, err := a.Groups(ctx)
	if err != nil || len(groups) != 2 || groups[1].Name != "Family" {
		t.Fatalf("groups = %+v, %v", groups, err)
	}
	cl, err := a.Clusters(ctx)
	if err != nil || len(cl) != 1 || cl[0].Address != "proxy.hardynetworks.net" || cl[0].Private {
		t.Fatalf("clusters = %+v, %v", cl, err)
	}
	doms, err := a.Domains(ctx)
	if err != nil || len(doms) != 2 || !doms[1].Validated || doms[1].Type != "custom" || doms[1].TargetCluster != "proxy.hardynetworks.net" {
		t.Fatalf("domains = %+v, %v", doms, err)
	}
	svcs, err := a.Services(ctx)
	if err != nil || len(svcs) != 1 || svcs[0].Meta.Status != "active" || svcs[0].Auth.PasswordAuth == nil || !svcs[0].Auth.PasswordAuth.Enabled {
		t.Fatalf("services = %+v, %v", svcs, err)
	}
	if !strings.Contains(string(svcs[0].AccessRestrictions), `"allowed_countries": ["US"]`) {
		t.Fatalf("access restrictions kept as sent: %s", svcs[0].AccessRestrictions)
	}
	req := ServiceRequest{Name: "hardyos-a1b2c3-jellyfin", Domain: "jellyfin.home.hardynetworks.net", Mode: "http", Enabled: true, PassHostHeader: true,
		Targets: []Target{{TargetID: "chacbco6lnnbn6cg5s90", TargetType: "peer", Protocol: "https", Host: "100.83.40.2", Port: 44200, Enabled: true,
			Options: &TargetOptions{SkipTLSVerify: true, CustomHeaders: map[string]string{"X-Hardyos-Gateway": "secret"}}}},
		Auth: &Auth{BearerAuth: &BearerAuth{Enabled: true}}}
	created, err := a.CreateService(ctx, req)
	if err != nil || created.ID != "cs9newservice00000001" || created.Meta.Status != "certificate_pending" {
		t.Fatalf("create = %+v, %v", created, err)
	}
	var sent map[string]any
	_ = json.Unmarshal(rec.bodies["POST /api/reverse-proxies/services"], &sent)
	tg := sent["targets"].([]any)[0].(map[string]any)
	if sent["pass_host_header"] != true || sent["private"] != false || tg["target_type"] != "peer" || tg["protocol"] != "https" ||
		tg["options"].(map[string]any)["skip_tls_verify"] != true || sent["auth"].(map[string]any)["bearer_auth"].(map[string]any)["enabled"] != true {
		t.Fatalf("create body = %s", rec.bodies["POST /api/reverse-proxies/services"])
	}
	if _, ok := tg["path"]; ok {
		t.Fatalf("no path means every path: %v", tg)
	}
	if _, err := a.UpdateService(ctx, created.ID, req); err != nil {
		t.Fatal(err)
	}
	if err := a.DeleteService(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if err := a.AddDomain(ctx, DomainRequest{Domain: "home.hardynetworks.net", TargetCluster: "proxy.hardynetworks.net"}); err != nil {
		t.Fatal(err)
	}
	if err := a.ValidateDomain(ctx, "ds8i4ug6lnn4g9hqv7m2"); err != nil {
		t.Fatal(err)
	}
	for _, h := range rec.auth {
		if h != "Token nbp_secret" {
			t.Fatalf("Authorization = %q", h)
		}
	}
	// A missing service is a 404 HardyOS can tell apart.
	if _, err := a.Service(ctx, "gone"); !IsNotFound(err) {
		t.Fatalf("missing service: %v", err)
	}
}

func TestAPIErrorsNeverShowTheToken(t *testing.T) {
	rec := newRecorded()
	rec.on("GET", "/api/reverse-proxies/domains", 403, []byte(`{"message":"permission denied","code":403}`))
	rec.on("GET", "/api/groups", 401, []byte(`{"message":"token invalid","code":401}`))
	rec.on("GET", "/api/reverse-proxies/services", 200, []byte(`{"not":"a list"}`))
	srv := httptest.NewServer(rec)
	defer srv.Close()
	a := &API{BaseURL: srv.URL, Token: "nbp_supersecret"}
	ctx := context.Background()
	_, err := a.Domains(ctx)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 403 || !strings.Contains(err.Error(), "Network Admin") {
		t.Fatalf("403: %v", err)
	}
	if _, err := a.Groups(ctx); err == nil || !strings.Contains(err.Error(), "refused the access token") {
		t.Fatalf("401: %v", err)
	}
	if _, err := a.Services(ctx); err == nil {
		t.Fatal("a wrong shape must fail")
	}
	bad := &API{BaseURL: "http://127.0.0.1:1", Token: "nbp_supersecret"}
	for _, err := range []error{err, func() error { _, e := bad.Groups(ctx); return e }()} {
		if err != nil && strings.Contains(err.Error(), "supersecret") {
			t.Fatalf("token in error: %v", err)
		}
	}
	if _, err := (&API{BaseURL: "ftp://x", Token: "t"}).Groups(ctx); err == nil {
		t.Fatal("non-https base must fail")
	}
	if _, err := (&API{BaseURL: srv.URL}).Groups(ctx); err == nil {
		t.Fatal("no token must fail")
	}
}

func TestNormalizeBaseURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://vpn.hardynetworks.net":      "https://vpn.hardynetworks.net",
		"https://vpn.hardynetworks.net/":     "https://vpn.hardynetworks.net",
		"https://vpn.hardynetworks.net/api/": "https://vpn.hardynetworks.net",
		"https://vpn.example.net:33073/api":  "https://vpn.example.net:33073",
		"http://127.0.0.1:8080":              "http://127.0.0.1:8080",
	} {
		if got, err := NormalizeBaseURL(in); err != nil || got != want {
			t.Errorf("%s = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"http://vpn.example.net", "vpn.example.net", "https://u:p@vpn.example.net", "https://vpn.example.net/?x=1", ""} {
		if _, err := NormalizeBaseURL(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestParseStatus(t *testing.T) {
	var st ClientStatus
	if err := ParseStatus(fixture(t, "status-connected.json"), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Connected || st.State != "connected" || st.IP != "100.83.40.2" || st.Network != "100.83.0.0/16" || st.FQDN != "nas.netbird.selfhosted" ||
		st.PeersTotal != 4 || st.PeersConnected != 3 || st.ManagementURL != "https://vpn.hardynetworks.net" || st.Version != "0.81.5" || st.Problem != "" {
		t.Fatalf("connected = %+v", st)
	}
	st = ClientStatus{}
	if err := ParseStatus(fixture(t, "status-needslogin.json"), &st); err != nil {
		t.Fatal(err)
	}
	if st.Connected || st.State != "needs_login" || !strings.Contains(st.Problem, "setup key") {
		t.Fatalf("needs login = %+v", st)
	}
	st = ClientStatus{}
	_ = ParseStatus([]byte(`{"daemonStatus":"Connected","management":{"connected":false,"error":"context deadline exceeded"},"netbirdIp":"100.83.40.2/16"}`), &st)
	if st.Connected || !strings.Contains(st.Problem, "Can't reach the NetBird server") {
		t.Fatalf("management down = %+v", st)
	}
}

func TestValidation(t *testing.T) {
	if u, err := ValidManagementURL(" https://vpn.hardynetworks.net/ "); err != nil || u != "https://vpn.hardynetworks.net" {
		t.Fatalf("%q %v", u, err)
	}
	if u, err := ValidManagementURL("https://vpn.example.net:33073"); err != nil || u != "https://vpn.example.net:33073" {
		t.Fatalf("%q %v", u, err)
	}
	for _, bad := range []string{"http://vpn.example.net", "https://vpn.example.net/path", "https://-x.example.net", "https://a;b", "https://"} {
		if _, err := ValidManagementURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, k := range []string{"A1B2C3D4-0000-1111-2222-333344445555", "abcdefgh"} {
		if !ValidSetupKey(k) {
			t.Errorf("%q refused", k)
		}
	}
	for _, k := range []string{"short", "has space in it", "--management-url=x", "a\nb-cdefgh", strings.Repeat("a", 129)} {
		if ValidSetupKey(k) {
			t.Errorf("%q accepted", k)
		}
	}
	if !ValidDomain("home.hardynetworks.net") || ValidDomain("Home.example.net") || ValidDomain("localhost") || ValidDomain("*.example.net") {
		t.Fatal("ValidDomain")
	}
}

// root makes a fake root with the netbird binary.
func root(t *testing.T, installed bool) string {
	t.Helper()
	dir := t.TempDir()
	if installed {
		p := filepath.Join(dir, binary)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte("#!/bin/true\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// upLine is how HardyOS runs `netbird up`: routes and DNS that NetBird's
// management server would push are refused (flag names of NetBird 0.81.5).
const upLine = "netbird up --management-url https://vpn.hardynetworks.net --hostname nas --disable-client-routes --disable-server-routes --disable-dns"

func TestUpRefusesPushedRoutesAndDNS(t *testing.T) {
	args := strings.Join(UpArgs("https://vpn.hardynetworks.net", "nas"), " ")
	for _, flag := range []string{"--disable-client-routes", "--disable-server-routes", "--disable-dns"} {
		if !strings.Contains(args, flag) {
			t.Errorf("netbird up without %s: %s", flag, args)
		}
	}
	// The proxy must still reach the gateway.
	if strings.Contains(args, "--block-inbound") {
		t.Errorf("netbird up blocks inbound connections: %s", args)
	}
}

func TestClipKeepsNetBirdsWordsPrintable(t *testing.T) {
	for in, want := range map[string]string{
		"  plain  ":                     "plain",
		"line\nbreak\r\tand\x1b[31mred": "line break and [31mred",
		"a b\u0085c":                    "a b c",
		strings.Repeat("é", 200):        strings.Repeat("é", 50) + "…",
	} {
		if got := Clip(in, 100); got != want {
			t.Errorf("Clip(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestJoinStatusLeave(t *testing.T) {
	dir := root(t, true)
	f := &sysexec.Fake{}
	f.On("systemctl enable --now netbird.service", "")
	f.OnResult("netbird status --json", sysexec.Result{Stdout: fixture(t, "status-idle.json")})
	f.On(upLine, "Connected")
	m := &Manager{Runner: f, Root: dir, Sleep: 1}
	ctx := context.Background()
	key := "A1B2C3D4-0000-1111-2222-333344445555"

	// Not joined yet: the service is off.
	f.OnResult("systemctl is-active --quiet netbird.service", sysexec.Result{ExitCode: 3})
	st, err := m.Status(ctx)
	if err != nil || st.State != "off" || st.Joined || st.Problem != "" {
		t.Fatalf("before = %+v, %v", st, err)
	}

	if _, err := m.Join(ctx, JoinArgs{ManagementURL: "https://vpn.hardynetworks.net", SetupKey: key, Hostname: "NAS"}); err != nil {
		t.Fatal(err)
	}
	// The key went in the environment only.
	for _, c := range f.Calls {
		if strings.Contains(c.Line, key) || strings.Contains(string(c.Stdin), key) {
			t.Fatalf("setup key on a command line: %q", c.Line)
		}
		if strings.HasPrefix(c.Line, "netbird up") && (len(c.Env) != 1 || c.Env[0] != "NB_SETUP_KEY="+key) {
			t.Fatalf("netbird up env = %v", c.Env)
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, MarkerFile))
	if err != nil || !strings.Contains(string(b), `"hostname": "nas"`) || strings.Contains(string(b), key) {
		t.Fatalf("marker = %s %v", b, err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, MarkerFile)); fi.Mode().Perm() != 0o600 {
		t.Fatalf("marker mode %v", fi.Mode())
	}

	// Joined and connected.
	f.OnResult("systemctl is-active --quiet netbird.service", sysexec.Result{})
	f.OnResult("netbird status --json", sysexec.Result{Stdout: fixture(t, "status-connected.json")})
	st, err = m.Status(ctx)
	if err != nil || !st.Joined || !st.Connected || st.IP != "100.83.40.2" || st.Hostname != "nas" {
		t.Fatalf("after = %+v, %v", st, err)
	}
	// Joining twice is refused.
	if _, err := m.Join(ctx, JoinArgs{ManagementURL: "https://vpn.hardynetworks.net", SetupKey: key, Hostname: "nas"}); !errors.Is(err, ErrAlreadyJoined) {
		t.Fatalf("second join: %v", err)
	}
	// Leaving needs the server's name.
	if _, err := m.Leave(ctx, LeaveArgs{Confirm: "yes"}); err == nil {
		t.Fatal("leave without confirmation")
	}
	f.On("netbird down", "")
	f.OnResult("netbird logout", sysexec.Result{ExitCode: 1, Stderr: []byte("management unreachable")})
	f.On("systemctl disable --now netbird.service", "")
	res, err := m.Leave(ctx, LeaveArgs{Confirm: "VPN.hardynetworks.net"})
	if err != nil || res.Left != "https://vpn.hardynetworks.net" || !strings.Contains(res.Notes, "dashboard") {
		t.Fatalf("leave = %+v, %v", res, err)
	}
	if _, err := os.Stat(filepath.Join(dir, MarkerFile)); !os.IsNotExist(err) {
		t.Fatal("marker kept after leaving")
	}
}

func TestJoinFailureHidesTheKeyAndTurnsOff(t *testing.T) {
	dir := root(t, true)
	key := "A1B2C3D4-0000-1111-2222-333344445555"
	f := &sysexec.Fake{}
	f.On("systemctl enable --now netbird.service", "")
	f.OnResult("netbird status --json", sysexec.Result{Stdout: fixture(t, "status-idle.json")})
	f.OnResult(upLine, sysexec.Result{ExitCode: 1, Stderr: []byte("login failed: invalid setup key " + key)})
	f.On("netbird down", "")
	f.On("systemctl disable --now netbird.service", "")
	m := &Manager{Runner: f, Root: dir, Sleep: 1}
	_, err := m.Join(context.Background(), JoinArgs{ManagementURL: "https://vpn.hardynetworks.net", SetupKey: key, Hostname: "nas"})
	if err == nil || strings.Contains(err.Error(), key) || !strings.Contains(err.Error(), "invalid setup key") {
		t.Fatalf("err = %v", err)
	}
	lines := strings.Join(f.Lines(), "\n")
	if !strings.Contains(lines, "systemctl disable --now netbird.service") {
		t.Fatalf("service left on: %s", lines)
	}
	if _, err := os.Stat(filepath.Join(dir, MarkerFile)); !os.IsNotExist(err) {
		t.Fatal("marker written after a failed join")
	}
}

func TestJoinRefusesBadArgsAndMissingClient(t *testing.T) {
	m := &Manager{Runner: &sysexec.Fake{}, Root: root(t, false)}
	ctx := context.Background()
	good := JoinArgs{ManagementURL: "https://vpn.hardynetworks.net", SetupKey: "A1B2C3D4-0000-1111-2222-333344445555", Hostname: "nas"}
	for _, a := range []JoinArgs{
		{ManagementURL: "http://vpn.hardynetworks.net", SetupKey: good.SetupKey, Hostname: "nas"},
		{ManagementURL: good.ManagementURL, SetupKey: "--setup-key=x", Hostname: "nas"},
		{ManagementURL: good.ManagementURL, SetupKey: good.SetupKey, Hostname: "nas; reboot"},
		{ManagementURL: good.ManagementURL, SetupKey: good.SetupKey, Hostname: "-n"},
	} {
		var ve *ValidationError
		if _, err := m.Join(ctx, a); !errors.As(err, &ve) {
			t.Errorf("%+v: %v", a, err)
		}
	}
	if _, err := m.Join(ctx, good); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("not installed: %v", err)
	}
	st, _ := m.Status(ctx)
	if st.Installed || st.State != "not_installed" {
		t.Fatalf("status = %+v", st)
	}
}

func TestOnStartRestartsAJoinedServer(t *testing.T) {
	dir := root(t, true)
	f := &sysexec.Fake{}
	m := &Manager{Runner: f, Root: dir}
	if err := m.OnStart(context.Background()); err != nil || len(f.Calls) != 0 {
		t.Fatalf("not joined: %v %v", err, f.Lines())
	}
	_ = m.writeMarker(marker{ManagementURL: "https://vpn.hardynetworks.net", Hostname: "nas"})
	f.OnResult("systemctl is-active --quiet netbird.service", sysexec.Result{ExitCode: 3})
	f.On("systemctl enable --now netbird.service", "")
	if err := m.OnStart(context.Background()); err != nil {
		t.Fatal(err)
	}
	if l := f.Lines(); l[len(l)-1] != "systemctl enable --now netbird.service" {
		t.Fatalf("lines = %v", l)
	}
}
