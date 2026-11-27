package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// fakeWindows is a cluster where "c1" runs the app "remoteapp" and "dup"
// is on two other members; the relay is a plain HTTP hop to a backend.
type fakeWindows struct {
	backend string
	deny    atomic.Bool
	checks  atomic.Int32
}

func (f *fakeWindows) self() cluster.NodeID                 { return "nas" }
func (f *fakeWindows) placed(string) (cluster.NodeID, bool) { return "", false }

func (f *fakeWindows) route(_ context.Context, id string) (cluster.NodeID, []cluster.NodeID) {
	switch id {
	case "remoteapp":
		return "c1", nil
	case "dup":
		return "", []cluster.NodeID{"c1", "c2"}
	}
	return "", nil
}

func (f *fakeWindows) check(_ context.Context, _ *http.Request, u *auth.User, tok string, node cluster.NodeID, app string) (string, error) {
	f.checks.Add(1)
	if f.deny.Load() || node != "c1" || app != "remoteapp" || u == nil || tok == "" {
		return "", errWindowForbidden
	}
	return "/start", nil
}

func (f *fakeWindows) transport(node cluster.NodeID, app string) http.RoundTripper {
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if node != "c1" || app != "remoteapp" {
			return nil, errors.New("wrong owner")
		}
		if uid, _ := r.Context().Value(windowUserKey{}).(int64); uid == 0 {
			return nil, errors.New("no window person")
		}
		if f.deny.Load() {
			// The owner refuses (its access list).
			return &http.Response{StatusCode: http.StatusForbidden, Body: http.NoBody, Header: http.Header{}, Request: r}, nil
		}
		r2 := r.Clone(r.Context())
		r2.URL.Scheme, r2.URL.Host = "http", f.backend
		return http.DefaultTransport.RoundTrip(r2)
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// <app>.<base> for an app another member runs (decision 494): the same
// bounce through this desktop host, the owner's access check before the
// code, every request relayed (HTTP and WebSocket), several owners refused.
func TestHostnamesRemoteApp(t *testing.T) {
	e := newHostsEnv(t)
	port, seen := windowBackend(t)
	fw := &fakeWindows{backend: "127.0.0.1:" + strconv.Itoa(port)}
	e.server.windows = fw
	e.activate()
	admin := e.browser(true)
	admin.req("POST", desk+"/api/v1/auth/login", map[string]string{"username": "cade", "password": "supersecret1"})

	r, body := admin.req("GET", "https://remoteapp.home.example.net/x?y=1", nil)
	if r.StatusCode != 200 || !strings.HasPrefix(body, "board:/x host=remoteapp.home.example.net") {
		t.Fatalf("%d %q", r.StatusCode, body)
	}
	if fw.checks.Load() != 1 {
		t.Fatalf("the owner was asked %d times before the code", fw.checks.Load())
	}
	for len(seen) > 1 {
		<-seen
	}
	if r, _ := admin.req("GET", "https://remoteapp.home.example.net/again", nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	got := <-seen
	if c := got.Header.Get("Cookie"); strings.Contains(c, "hardyos") {
		t.Fatalf("HardyOS cookies reached the app: %q", c)
	}

	// A WebSocket.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "wss://remoteapp.home.example.net/ws", &websocket.DialOptions{HTTPClient: admin.hc})
	if err != nil {
		t.Fatalf("websocket: %v", err)
	}
	if err := ws.Write(ctx, websocket.MessageText, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	if _, msg, err := ws.Read(ctx); err != nil || string(msg) != "echo:hi" {
		t.Fatalf("echo = %q %v", msg, err)
	}
	ws.CloseNow()

	// The session is for the app on c1 only: the same cookie isn't good for
	// a local app.
	if r, _ := admin.browserNoFollow().req("GET", "https://board.home.example.net/", nil); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("a remote app's session opened a local app: %d", r.StatusCode)
	}

	// The owner refuses the person: no code, and relayed requests answer 403.
	fw.deny.Store(true)
	other := e.browser(true)
	other.req("POST", desk+"/api/v1/auth/login", map[string]string{"username": "cade", "password": "supersecret1"})
	if r, body := other.req("GET", "https://remoteapp.home.example.net/", nil); r.StatusCode != http.StatusForbidden || !strings.Contains(body, "can&#39;t use this app") {
		t.Fatalf("refused by the owner: %d %s", r.StatusCode, body)
	}
	if r, _ := admin.req("GET", "https://remoteapp.home.example.net/again", nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("an open session after the owner refused: %d", r.StatusCode)
	}
	fw.deny.Store(false)

	// Windows opened on the desktop's hostname use the app's name only when
	// that name reaches the very member running it (review M1): never when
	// this server has an app with the same id, nor for another member, nor
	// when several have it.
	ctx2 := context.Background()
	for _, x := range []struct {
		app  string
		node cluster.NodeID
		want bool
	}{
		{"remoteapp", "c1", true},
		{"remoteapp", "c2", false},
		{"board", "c1", false}, // this server's own board wins on board.<base>
		{"dup", "c1", false},   // on c1 and c2
		{"roundcube", "c1", false},
		{"nope", "c1", false},
	} {
		if got := e.server.hostRoutesTo(ctx2, x.app, x.node); got != x.want {
			t.Errorf("hostRoutesTo(%s, %s) = %v, want %v", x.app, x.node, got, x.want)
		}
	}

	// On several other members: refused with their names.
	if r, body := admin.req("GET", "https://dup.home.example.net/", nil); r.StatusCode != http.StatusConflict || !strings.Contains(body, "c1, c2") {
		t.Fatalf("dup = %d %s", r.StatusCode, body)
	}
	// Webmail is each server's own: never routed elsewhere.
	if r, _ := admin.req("GET", "https://roundcube.home.example.net/", nil); r.StatusCode != http.StatusNotFound {
		t.Fatalf("roundcube = %d", r.StatusCode)
	}
	// Unknown everywhere: 404 as before.
	if r, _ := admin.req("GET", "https://nope.home.example.net/", nil); r.StatusCode != http.StatusNotFound {
		t.Fatalf("nope = %d", r.StatusCode)
	}
}
