package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/backup"
	"github.com/hardyos/hardyos/daemon/internal/backups"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/network"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func newBackupEnv(t *testing.T) (*testEnv, *backup.Root, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	root := t.TempDir()
	for path, content := range map[string]string{
		"var/lib/hardyos/tls/server.crt": "CERT",
		"var/lib/hardyos/tls/server.key": "TLSKEY",
		"var/lib/hardyos/keys/tank.key":  "POOLKEY",
		"etc/hostname":                   "nas\n",
		"etc/network/interfaces":         "auto lo\n",
	} {
		p := filepath.Join(root, path)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.MkdirAll(filepath.Join(root, "tank/hardyos-backups"), 0o755)
	db, err := store.Open(ctx, filepath.Join(root, "live.db"))
	if err != nil {
		t.Fatal(err)
	}
	fake := &sysexec.Fake{}
	fake.On("zpool list -H -o name", "rpool\ntank\n")
	fake.On("zfs get -H -o value mountpoint tank/hardyos-backups", "/tank/hardyos-backups\n")
	fake.OnPrefix("hostname ", sysexec.Result{})
	r := &backup.Root{Runner: fake, Root: root, UID: -1, GID: -1, Network: &network.Manager{Runner: fake, Root: root, Ports: func() []string { return []string{"eno1"} }}}

	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	priv.RegisterBackup(ps, r)
	go func() { _ = ps.Serve(ctx, ln) }()
	pc := priv.NewClient(sock)
	broker := events.NewBroker()
	m := &jobs.Manager{DB: db, Events: broker}
	svc := &backups.Service{DB: db, Priv: pc, Jobs: m, Notify: &notify.Center{DB: db, Events: broker}, Current: "0.2.0",
		Dir: filepath.Join(root, backup.WorkDir), Hostname: func() string { return "nas" }}
	svc.RegisterJobs(m)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Config{DB: db, Jobs: m, Events: broker, Priv: pc, Backups: svc, Insecure: true}))
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	return &testEnv{srv: srv, db: db, broker: broker}, r, root
}

func (c *client) raw(method, path string, body []byte) (int, []byte, http.Header) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	req.Header.Set("X-HardyOS-Request", "1")
	req.Header.Set("Content-Type", "application/octet-stream")
	res, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b, res.Header
}

func TestBackupsAPI(t *testing.T) {
	env, root, rootDir := newBackupEnv(t)
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)

	var st backups.Status
	if code := admin.do("GET", "/api/v1/system/backups", nil, &st); code != 200 || len(st.Pools) != 1 || st.Pools[0] != "tank" || !st.Settings.Nightly {
		t.Fatalf("status = %d %+v", code, st)
	}

	// Back up onto the pool.
	var acc struct {
		Job map[string]any `json:"job"`
	}
	if code := admin.do("POST", "/api/v1/system/backups/run", map[string]string{}, &acc); code != 202 {
		t.Fatalf("run = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job["id"].(string)); j["state"] != "succeeded" {
		t.Fatalf("backup job = %v", j)
	}
	admin.do("GET", "/api/v1/system/backups", nil, &st)
	if len(st.Backups) != 1 || st.Backups[0].Manifest.Users != 1 || st.Backups[0].Manifest.Secrets || st.LastError != "" || st.LastRun == nil {
		t.Fatalf("after run = %+v", st)
	}

	// Download with keys: needs a real password.
	var e ErrorResponse
	if code := admin.do("POST", "/api/v1/system/backups/download", map[string]any{"password": "short", "secrets": true}, &e); code != 400 {
		t.Fatalf("short password = %d", code)
	}
	var d backups.Download
	if code := admin.do("POST", "/api/v1/system/backups/download", map[string]any{"password": "long enough pw", "secrets": true}, &d); code != 200 || !strings.HasPrefix(d.File, "hardyos-settings-nas-") {
		t.Fatalf("download = %d %+v", code, d)
	}
	code, file, hdr := admin.raw("GET", "/api/v1/system/backups/files/"+d.Name+"?as="+d.File, nil)
	if code != 200 || !strings.Contains(hdr.Get("Content-Disposition"), d.File) {
		t.Fatalf("file = %d %v", code, hdr)
	}
	if enc, _ := backup.Encrypted(file); !enc || bytes.Contains(file, []byte("POOLKEY")) {
		t.Fatal("download isn't encrypted")
	}
	if code, _, _ := admin.raw("GET", "/api/v1/system/backups/files/..%2Flive.db", nil); code != 404 {
		t.Fatalf("traversal = %d", code)
	}
	// Job history never holds the password.
	var list []map[string]any
	admin.do("GET", "/api/v1/jobs", nil, &list)
	for _, j := range list {
		if strings.Contains(strings.ToLower(jsonString(j)), "long enough pw") {
			t.Fatal("password in job history")
		}
	}

	// Someone is added after the backup...
	admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "supersecret2", "role": "user"}, nil)

	// ...then the backup is restored.
	var up map[string]string
	if code := admin.uploadTo("/api/v1/system/backups/upload", file, &up); code != 200 || up["upload"] == "" {
		t.Fatalf("upload = %d %v", code, up)
	}
	if code := admin.do("POST", "/api/v1/system/backups/restore", map[string]string{"upload": up["upload"], "password": "nope"}, &e); code != 400 || !strings.Contains(e.Message, "password is wrong") {
		t.Fatalf("wrong password = %d %+v", code, e)
	}
	// The upload is kept, so the right password works without uploading again.
	var staged backup.Staged
	if code := admin.do("POST", "/api/v1/system/backups/restore", map[string]string{"upload": up["upload"], "password": "long enough pw"}, &staged); code != 200 || !staged.Manifest.Secrets {
		t.Fatalf("restore = %d %+v", code, staged)
	}
	admin.do("GET", "/api/v1/system/backups", nil, &st)
	if st.Pending == nil {
		t.Fatal("restore not pending")
	}
	if code := admin.do("POST", "/api/v1/system/backups/restore/cancel", nil, nil); code != 204 {
		t.Fatalf("cancel = %d", code)
	}
	admin.do("GET", "/api/v1/system/backups", nil, &st)
	if st.Pending != nil {
		t.Fatal("still pending after cancel")
	}
	// From the pool this time, then "restart".
	if code := admin.do("POST", "/api/v1/system/backups/restore", map[string]string{"pool": "tank", "name": st.Backups[0].Name}, &staged); code != 200 {
		t.Fatalf("restore from pool = %d", code)
	}
	if res := root.ApplyPending(context.Background()); res == nil || !res.OK {
		t.Fatalf("apply = %+v", res)
	}
	info, err := store.Inspect(context.Background(), filepath.Join(rootDir, "var/lib/hardyos/hardyd.db"))
	if err != nil || info.Users != 1 {
		t.Fatalf("restored database: %+v %v (kid should be gone)", info, err)
	}
}

func TestRestoreRefusesNewerDatabase(t *testing.T) {
	env, _, rootDir := newBackupEnv(t)
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	// A database from a future version.
	dbPath := filepath.Join(rootDir, "future.db")
	fut, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fut.Exec(`INSERT INTO users (username, display_name, password_hash, role, created_at, updated_at) VALUES ('x','x','x','admin',?,?)`, store.Now(), store.Now())
	_, _ = fut.Exec(`INSERT INTO schema_migrations (version, name, applied_at) VALUES (9999, 'future.sql', ?)`, time.Now().String())
	fut.Close()
	raw, _ := os.ReadFile(dbPath)
	b, _ := backup.Pack(backup.Contents{Manifest: backup.Manifest{CreatedAt: time.Now(), Version: "9.0.0", Hostname: "nas"}, DB: raw}, "")
	var up map[string]string
	admin.uploadTo("/api/v1/system/backups/upload", b, &up)
	var e ErrorResponse
	if code := admin.do("POST", "/api/v1/system/backups/restore", map[string]string{"upload": up["upload"]}, &e); code != 400 || !strings.Contains(e.Message, "newer HardyOS") {
		t.Fatalf("future backup = %d %+v", code, e)
	}
	// Not a backup at all.
	if code, _, _ := admin.raw("POST", "/api/v1/system/backups/upload", []byte("hello")); code != 400 {
		t.Fatalf("junk upload = %d", code)
	}
	_ = sql.ErrNoRows
}

func (c *client) uploadTo(path string, body []byte, out any) int {
	return c.upload(path, body, out)
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
