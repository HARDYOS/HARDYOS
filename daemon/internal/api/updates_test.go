package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/update"
	"github.com/hardyos/hardyos/daemon/internal/updates"
)

// stubUpdater answers the update operations and records what it was asked.
type stubUpdater struct {
	mu      sync.Mutex
	staged  []byte
	calls   []string
	status  update.Status
	reboots int
}

func (u *stubUpdater) register(s *priv.Server, dir string) {
	rec := func(op string, raw json.RawMessage) {
		u.mu.Lock()
		u.calls = append(u.calls, op+" "+string(raw))
		u.mu.Unlock()
	}
	s.Handle(priv.OpUpdateStatus, func(_ context.Context, raw json.RawMessage) (any, error) {
		u.mu.Lock()
		defer u.mu.Unlock()
		return u.status, nil
	})
	s.Handle(priv.OpUpdateStage, func(_ context.Context, raw json.RawMessage) (any, error) {
		rec(priv.OpUpdateStage, raw)
		var a priv.UpdateStageArgs
		_ = json.Unmarshal(raw, &a)
		if !strings.HasPrefix(a.Path, dir+"/") {
			return nil, priv.Errorf(priv.CodeBadArgs, "outside the updates directory")
		}
		b, _ := os.ReadFile(a.Path)
		u.mu.Lock()
		u.staged = b
		u.status.Pending = &update.Pending{BE: "hardyos-0.2.0", Version: "0.2.0"}
		u.mu.Unlock()
		if bytes.Contains(b, []byte("unsigned")) {
			return nil, priv.Errorf(priv.CodeFailed, "%v", update.ErrUntrusted)
		}
		return update.StageResult{Version: "0.2.0", BE: "hardyos-0.2.0"}, nil
	})
	for _, op := range []string{priv.OpUpdateActivate, priv.OpUpdateDelete, priv.OpUpdateConfirm} {
		op := op
		s.Handle(op, func(_ context.Context, raw json.RawMessage) (any, error) {
			rec(op, raw)
			return map[string]bool{"ok": true}, nil
		})
	}
	s.Handle(priv.OpSystemReboot, func(context.Context, json.RawMessage) (any, error) {
		u.mu.Lock()
		u.reboots++
		u.mu.Unlock()
		return map[string]bool{"rebooting": true}, nil
	})
	s.Handle(priv.OpPing, func(context.Context, json.RawMessage) (any, error) { return priv.PingResult{}, nil })
}

func newUpdatesEnv(t *testing.T, stub *stubUpdater) (*testEnv, *updates.Service, *store.DB) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "u.db"))
	if err != nil {
		t.Fatal(err)
	}
	broker := events.NewBroker()
	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "updates")
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	stub.register(ps, dir)
	go func() { _ = ps.Serve(ctx, ln) }()
	pc := priv.NewClient(sock)
	m := &jobs.Manager{DB: db, Events: broker}
	svc := &updates.Service{Priv: pc, Jobs: m, DB: db, Dir: dir, Notify: &notify.Center{DB: db, Events: broker}}
	svc.RegisterJobs(m)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Config{DB: db, Jobs: m, Events: broker, Priv: pc, Updates: svc, Insecure: true}))
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	return &testEnv{srv: srv, db: db, broker: broker}, svc, db
}

func (c *client) upload(path string, body []byte, out any) int {
	c.t.Helper()
	req, _ := http.NewRequest("POST", c.base+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-HardyOS-Request", "1")
	res, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	if out != nil {
		_ = json.NewDecoder(res.Body).Decode(out)
	}
	return res.StatusCode
}

func waitJobDone(t *testing.T, c *client, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var j map[string]any
		c.do("GET", "/api/v1/jobs/"+id, nil, &j)
		switch j["state"] {
		case "succeeded", "failed", "cancelled":
			return j
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatal("job did not finish")
	return nil
}

func TestUpdateUploadAndVersions(t *testing.T) {
	stub := &stubUpdater{status: update.Status{Managed: true, Running: "hardyos-0.1.0", Versions: []update.Version{}}}
	env, svc, _ := newUpdatesEnv(t, stub)
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)

	var st map[string]any
	if code := admin.do("GET", "/api/v1/system/updates", nil, &st); code != 200 || st["running"] != "hardyos-0.1.0" {
		t.Fatalf("status %d %v", code, st)
	}

	var acc struct {
		Job map[string]any `json:"job"`
	}
	if code := admin.upload("/api/v1/system/updates/upload", []byte("bundle-bytes"), &acc); code != 202 {
		t.Fatalf("upload = %d", code)
	}
	j := waitJobDone(t, admin, acc.Job["id"].(string))
	if j["state"] != "succeeded" || !strings.Contains(j["message"].(string), "Restart") {
		t.Fatalf("install job %v", j)
	}
	if string(stub.staged) != "bundle-bytes" {
		t.Fatalf("staged %q", stub.staged)
	}

	// An untrusted file fails the job, and the upload is cleaned up.
	if code := admin.upload("/api/v1/system/updates/upload", []byte("unsigned"), &acc); code != 202 {
		t.Fatalf("upload = %d", code)
	}
	failed := waitJobDone(t, admin, acc.Job["id"].(string))
	if failed["state"] != "failed" || !strings.Contains(failed["error"].(string), "trusted") {
		t.Fatalf("untrusted job %v", failed)
	}
	failedPath := failed["params"].(map[string]any)["path"].(string)
	if !strings.HasPrefix(failedPath, svc.Dir+"/upload-") {
		t.Fatalf("upload saved at %s", failedPath)
	}
	if _, err := os.Stat(failedPath); err == nil {
		t.Fatal("the rejected upload was left on disk")
	}

	var e map[string]any
	if code := admin.do("POST", "/api/v1/system/updates/download", map[string]string{"url": "ftp://example.com/x.hupd"}, &e); code != 400 {
		t.Fatalf("ftp url = %d %v", code, e)
	}
	if code := admin.do("POST", "/api/v1/system/versions/hardyos-0.1.0/activate", map[string]bool{"restoreSettings": true}, &acc); code != 202 {
		t.Fatalf("activate = %d", code)
	}
	waitJobDone(t, admin, acc.Job["id"].(string))
	if code := admin.do("POST", "/api/v1/system/versions/..%2F..%2Fetc/activate", map[string]bool{}, nil); code != 400 && code != 404 {
		t.Fatalf("bad name = %d", code)
	}
	if code := admin.do("POST", "/api/v1/system/versions/hardyos-0.1.0/delete", map[string]string{"confirmName": "nope"}, nil); code != 400 {
		t.Fatalf("delete without confirm = %d", code)
	}
	if code := admin.do("POST", "/api/v1/system/versions/hardyos-0.1.0/delete", map[string]string{"confirmName": "hardyos-0.1.0"}, &acc); code != 202 {
		t.Fatalf("delete = %d", code)
	}
	waitJobDone(t, admin, acc.Job["id"].(string))
	if code := admin.do("POST", "/api/v1/system/reboot", nil, nil); code != 202 || stub.reboots != 1 {
		t.Fatalf("reboot = %d (%d)", code, stub.reboots)
	}

	calls := strings.Join(stub.calls, "\n")
	if !strings.Contains(calls, `update.activate {"name":"hardyos-0.1.0","restoreSettings":true}`) ||
		!strings.Contains(calls, `update.delete {"name":"hardyos-0.1.0","confirmName":"hardyos-0.1.0"}`) {
		t.Fatalf("calls:\n%s", calls)
	}

	// Regular users can't touch updates.
	admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1", "role": "user"}, nil)
	kid := env.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	if code := kid.upload("/api/v1/system/updates/upload", []byte("x"), nil); code != 403 {
		t.Fatalf("user upload = %d", code)
	}
	if code := kid.do("POST", "/api/v1/system/reboot", nil, nil); code != 403 {
		t.Fatalf("user reboot = %d", code)
	}
}

func TestConfirmWhenHealthy(t *testing.T) {
	stub := &stubUpdater{status: update.Status{Managed: true, Running: "hardyos-0.2.0",
		Pending: &update.Pending{BE: "hardyos-0.2.0", Version: "0.2.0"}}}
	_, svc, db := newUpdatesEnv(t, stub)
	ctx := context.Background()
	svc.ConfirmWhenHealthy(ctx, 0)
	if !strings.Contains(strings.Join(stub.calls, "\n"), priv.OpUpdateConfirm) {
		t.Fatal("pending update was not confirmed")
	}

	// A result is reported once.
	stub.status.Pending = nil
	stub.status.Last = &update.Result{OK: false, Version: "0.3.0", Message: "HardyOS 0.3.0 didn't start correctly", At: time.Now()}
	svc.ConfirmWhenHealthy(ctx, 0)
	svc.ConfirmWhenHealthy(ctx, 0)
	center := &notify.Center{DB: db}
	list, err := center.List(ctx, true, 10)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, x := range list {
		if x.Title == "Update rolled back" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("rollback notifications = %d (%+v)", n, list)
	}
}
