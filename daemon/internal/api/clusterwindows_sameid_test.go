package api

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/apps"
)

// The same app id on the entry and on the owner (review M1): a window for
// c1's board opens c1's, and nas's own board opens nas's; the hostname is
// never used for c1's (board.<base> here is nas's own).
func TestAppWindowSameIDOnEntry(t *testing.T) {
	own := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "nas-board:"+r.URL.Path)
	}))
	t.Cleanup(own.Close)
	port := own.Listener.Addr().(*net.TCPAddr).Port
	nas, _, admin, _ := windowClusterWith(t, map[string]apps.App{
		"board": {ID: "board", Name: "Board", State: "running", Web: &apps.AppWeb{Port: port, Path: "/", Scheme: "http"}},
	})
	var open AppOpen
	if code := admin.do("POST", "/api/v1/nodes/c1/apps/board/open", nil, &open); code != 200 || open.Hostname {
		t.Fatalf("c1's board = %d %+v", code, open)
	}
	if _, page := signInWindow(t, admin, open); !strings.HasPrefix(page, "board:/start ") {
		t.Fatalf("c1's board window landed on %q", page)
	}
	var mine AppOpen
	if code := admin.do("POST", "/api/v1/apps/board/open", nil, &mine); code != 200 {
		t.Fatalf("nas's board = %d", code)
	}
	if _, page := signInWindow(t, admin, mine); !strings.HasPrefix(page, "nas-board:") {
		t.Fatalf("nas's board window landed on %q", page)
	}
	// Both nas and c1 have board: the name is nas's own, never c1's.
	nas.s.hosts.mu.Lock()
	nas.s.hosts.apps, nas.s.hosts.appsKnow = map[string]apps.App{"board": {ID: "board"}}, true
	nas.s.hosts.mu.Unlock()
	if nas.s.hostRoutesTo(context.Background(), "board", "c1") {
		t.Fatal("board.<base> on nas would open c1's board")
	}
}
