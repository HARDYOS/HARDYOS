package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// Administrators of other members reach only the cluster desktop's areas
// (decision 368).
func TestClusterAdminMay(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{"GET", "/api/v1/vms", true},
		{"POST", "/api/v1/vms/web/start", true},
		{"GET", "/api/v1/vms/web/console/ws", true},
		{"POST", "/api/v1/apps/install", true},
		{"GET", "/api/v1/apps/catalogs", true},
		{"POST", "/api/v1/storage/pools/tank/scrub", true},
		{"GET", "/api/v1/system/info", true},
		{"GET", "/api/v1/cluster", true},
		{"PUT", "/api/v1/cluster/workloads/vm/web/ha", true},
		{"GET", "/api/v1/users", false},
		{"POST", "/api/v1/users/3/password", false},
		{"GET", "/api/v1/terminal/ws", false},
		{"POST", "/api/v1/terminal/session", false},
		{"PATCH", "/api/v1/oidc", false},
		{"POST", "/api/v1/domain/join", false},
		{"PUT", "/api/v1/network", false},
		{"POST", "/api/v1/vms/bridge", false},
		{"PUT", "/api/v1/remote/desktop", false},
		{"PUT", "/api/v1/apps/notes/publish", false},
		{"POST", "/api/v1/apps/custom", false},
		{"POST", "/api/v1/apps/packages", false},
		{"POST", "/api/v1/apps/catalogs", false},
		{"POST", "/api/v1/devices/vgpu-driver/upload", false},
		{"POST", "/api/v1/system/updates/install-available", false},
		{"GET", "/api/v1/system/updates", false},
		{"POST", "/api/v1/system/versions/x/activate", false},
		{"POST", "/api/v1/system/backups/restore", false},
		{"POST", "/api/v1/cluster/join-codes", false},
		{"DELETE", "/api/v1/cluster/join-codes/x", false},
		{"POST", "/api/v1/cluster/witness/script", false},
		{"POST", "/api/v1/cluster/leave", false},
		{"POST", "/api/v1/cluster/dissolve", false},
		{"POST", "/api/v1/cluster", false},
		{"DELETE", "/api/v1/cluster/nodes/c2", false},
		{"PUT", "/api/v1/cluster/admin-trust", false},
		{"GET", "/api/v1/auth/me", false},
		{"GET", "/somewhere", false},
	} {
		if got := clusterAdminMay(tc.method, tc.path); got != tc.want {
			t.Errorf("%s %s = %v", tc.method, tc.path, got)
		}
	}
}

// Only allowed headers of a member's answer reach the browser, this node's
// security headers stay, and anything but JSON is sandboxed (decision 369).
func TestRelayResponseHeaderAllowlist(t *testing.T) {
	src := http.Header{}
	src.Set("Content-Type", "text/html; charset=utf-8")
	src.Set("Content-Length", "12")
	src.Set("Set-Cookie", "__Host-hardyos_session=evil")
	src.Set("Content-Security-Policy", "default-src *")
	src.Set("X-Frame-Options", "ALLOWALL")
	src.Set("Access-Control-Allow-Origin", "*")
	src.Set("Location", "https://evil.example/")
	src.Set("Refresh", "0; url=https://evil.example/")
	src.Set("Content-Disposition", "inline")
	dst := http.Header{}
	dst.Set("Content-Security-Policy", "default-src 'self'")
	relayResponseHeaders(dst, src)
	for _, k := range []string{"Set-Cookie", "Access-Control-Allow-Origin", "Location", "Refresh"} {
		if dst.Get(k) != "" {
			t.Errorf("%s crossed: %q", k, dst.Get(k))
		}
	}
	if dst.Get("Content-Security-Policy") != sandboxCSP || dst.Get("X-Frame-Options") != "SAMEORIGIN" ||
		dst.Get("X-Content-Type-Options") != "nosniff" || dst.Get("Content-Type") != "text/html; charset=utf-8" ||
		dst.Get("Content-Disposition") != "inline" {
		t.Fatalf("headers %v", dst)
	}
	// JSON keeps this node's own policy.
	src.Set("Content-Type", "application/json")
	dst = http.Header{}
	dst.Set("Content-Security-Policy", "default-src 'self'")
	relayResponseHeaders(dst, src)
	if dst.Get("Content-Security-Policy") != "default-src 'self'" {
		t.Fatalf("json csp %q", dst.Get("Content-Security-Policy"))
	}
}

// Relayed requests are capped per person and in all (decision 371).
func TestRelayLimits(t *testing.T) {
	var l relayLimits
	var rel []func()
	for i := 0; i < maxRelayPerUser; i++ {
		r, ok := l.take("cade", false)
		if !ok {
			t.Fatalf("refused at %d", i)
		}
		rel = append(rel, r)
	}
	if _, ok := l.take("cade", false); ok {
		t.Fatal("over the per-person cap")
	}
	// WebSockets count apart.
	if r, ok := l.take("cade", true); !ok {
		t.Fatal("upgrade refused")
	} else {
		r()
	}
	rel[0]()
	rel[0]() // twice is harmless
	if r, ok := l.take("cade", false); !ok {
		t.Fatal("not released")
	} else {
		rel[0] = r
	}
	// The global cap.
	for i := 0; ; i++ {
		r, ok := l.take("user"+string(rune('a'+i%26))+strings.Repeat("x", i/26), false)
		if !ok {
			if l.total != maxRelayTotal {
				t.Fatalf("refused at total %d", l.total)
			}
			break
		}
		rel = append(rel, r)
	}
	for _, r := range rel {
		r()
	}
	if l.total != 0 || len(l.perUser) != 0 {
		t.Fatalf("left %d %v", l.total, l.perUser)
	}
}

// A relayed request is served with the browser's Host and scheme, and the
// member's answer reaches the browser with only the allowed headers
// (decisions 369, 373).
func TestRelayHostAndHeaders(t *testing.T) {
	nas, c1 := twoNodeCluster(t)
	c1.s.mux.HandleFunc("GET /api/v1/version/echo", func(w http.ResponseWriter, r *http.Request) {
		still := false
		if rr := relayedFrom(r); rr != nil {
			_, still = rr.still(r.Context())
		}
		writeJSON(w, http.StatusOK, map[string]any{"host": r.Host, "scheme": requestScheme(r), "relayed": relayedFrom(r) != nil,
			"base": apiBase(r), "still": still})
	})
	c1.s.mux.HandleFunc("GET /api/v1/version/page", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Set-Cookie", "x=1")
		w.Header().Set("X-Evil", "1")
		w.Header().Set("Content-Security-Policy", "default-src *")
		_, _ = w.Write([]byte("<script>alert(1)</script>"))
	})
	cade := nas.env.client(t)
	if code := cade.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil); code != 201 {
		t.Fatalf("setup = %d", code)
	}
	var echo struct {
		Host    string `json:"host"`
		Scheme  string `json:"scheme"`
		Relayed bool   `json:"relayed"`
		Base    string `json:"base"`
		Still   bool   `json:"still"`
	}
	if code := cade.do("GET", "/api/v1/nodes/c1/version/echo", nil, &echo); code != 200 {
		t.Fatalf("echo = %d", code)
	}
	// Paths handed back (a VM console's WebSocket) name the node; a long
	// request (the console) can check the person again (decision 373).
	if want := strings.TrimPrefix(nas.env.srv.URL, "http://"); echo.Host != want || echo.Scheme != "http" || !echo.Relayed ||
		echo.Base != "/api/v1/nodes/c1" || !echo.Still {
		t.Fatalf("echo %+v, want host %s", echo, want)
	}

	req, _ := http.NewRequest("GET", nas.env.srv.URL+"/api/v1/nodes/c1/version/page", nil)
	resp, err := cade.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("Set-Cookie") != "" || resp.Header.Get("X-Evil") != "" || resp.Header.Get("Content-Security-Policy") != sandboxCSP {
		t.Fatalf("relayed headers %v", resp.Header)
	}
	// An assertion naming a host that isn't one is refused by the target.
	core := nas.svc.Core()
	r2, sb, err := core.RelayRequest(t.Context(), &cluster.Forward{Node: "c1", Principal: cluster.Principal{Kind: "local", Name: "cade", Admin: true},
		Method: "GET", Path: "/api/v1/version/echo", Host: "evil\r\nx: y"})
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	resp2, err := core.RoundTripRelay(r2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("bad host = %d", resp2.StatusCode)
	}
}
