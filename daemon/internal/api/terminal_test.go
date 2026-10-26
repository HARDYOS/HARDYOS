package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/updates"
)

func TestTerminalAPI(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("terminals need Linux")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	priv.RegisterTerminalWith(ps, func(user string) *exec.Cmd {
		// Echo every line back, upper-cased, and report the size on request.
		return exec.Command("/bin/sh", "-c", `echo "ready for `+user+`"; while read l; do if [ "$l" = size ]; then stty size; else echo "$l" | tr a-z A-Z; fi; done`)
	})
	go func() { _ = ps.Serve(ctx, ln) }()
	pc := priv.NewClient(sock)
	broker := events.NewBroker()
	srv := httptest.NewServer(New(Config{DB: db, Events: broker, Priv: pc, Updates: &updates.Service{DB: db, Notify: &notify.Center{DB: db, Events: broker}}, Insecure: true}))
	defer srv.Close()
	env := &testEnv{srv: srv, db: db, broker: broker}
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)

	dial := func(ticket string) (*websocket.Conn, *http.Response, error) {
		u := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/terminal/ws?cols=90&rows=20&ticket=" + ticket
		return websocket.Dial(ctx, u, &websocket.DialOptions{HTTPClient: admin.http, HTTPHeader: http.Header{"Origin": {srv.URL}}})
	}

	// No ticket, no terminal.
	if _, res, err := dial("made-up"); err == nil || res == nil || res.StatusCode != 403 {
		t.Fatalf("without a ticket: %v %v", res, err)
	}
	var e ErrorResponse
	if code := admin.do("POST", "/api/v1/terminal/session", map[string]string{"password": "wrong"}, &e); code != 401 {
		t.Fatalf("wrong password = %d", code)
	}
	var tk map[string]string
	if code := admin.do("POST", "/api/v1/terminal/session", map[string]string{"password": "supersecret1"}, &tk); code != 200 || tk["ticket"] == "" {
		t.Fatalf("session = %d %v", code, tk)
	}
	conn, _, err := dial(tk["ticket"])
	if err != nil {
		t.Fatal(err)
	}
	read := func(want string) {
		t.Helper()
		rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
		defer rcancel()
		var seen strings.Builder
		for !strings.Contains(seen.String(), want) {
			_, b, err := conn.Read(rctx)
			if err != nil {
				t.Fatalf("waiting for %q, got %q: %v", want, seen.String(), err)
			}
			seen.Write(b)
		}
	}
	read("ready for cade")
	_ = conn.Write(ctx, websocket.MessageBinary, []byte("hello\n"))
	read("HELLO")
	msg, _ := json.Marshal(map[string]any{"type": "resize", "cols": 120, "rows": 33})
	_ = conn.Write(ctx, websocket.MessageText, msg)
	_ = conn.Write(ctx, websocket.MessageBinary, []byte("size\n"))
	read("33 120")
	conn.Close(websocket.StatusNormalClosure, "")

	// A ticket works once.
	if _, res, err := dial(tk["ticket"]); err == nil || res == nil || res.StatusCode != 403 {
		t.Fatalf("ticket reused: res=%v err=%v", res, err)
	}

	// Opening and closing are in the audit log.
	time.Sleep(200 * time.Millisecond)
	var entries []map[string]any
	admin.do("GET", "/api/v1/audit", nil, &entries)
	got := map[string]bool{}
	for _, en := range entries {
		got[fmt.Sprint(en["action"])+"/"+fmt.Sprint(en["outcome"])] = true
	}
	for _, want := range []string{"terminal.unlock/failure", "terminal.open/success", "terminal.close/success"} {
		if !got[want] {
			t.Errorf("audit lacks %s: %v", want, got)
		}
	}

	// Switched off, nobody gets one.
	admin.do("PUT", "/api/v1/terminal/settings", map[string]bool{"enabled": false}, nil)
	if code := admin.do("POST", "/api/v1/terminal/session", map[string]string{"password": "supersecret1"}, &e); code != 403 {
		t.Fatalf("disabled = %d", code)
	}
	// Regular users can't ask.
	admin.do("PUT", "/api/v1/terminal/settings", map[string]bool{"enabled": true}, nil)
	admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "supersecret2", "role": "user"}, nil)
	kid := env.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "supersecret2"}, nil)
	if code := kid.do("POST", "/api/v1/terminal/session", map[string]string{"password": "supersecret2"}, &e); code != 403 {
		t.Fatalf("user = %d", code)
	}
}
