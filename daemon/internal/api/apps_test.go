package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/updates"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// stubApps is a root helper that pretends to run Docker apps.
type stubApps struct {
	mu       sync.Mutex
	pool     string
	apps     map[string]apps.App
	prepared []apps.PrepareArgs
	calls    []string
}

func (d *stubApps) register(ps *priv.Server) {
	rec := func(op string, raw json.RawMessage) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.calls = append(d.calls, op+" "+string(raw))
	}
	ps.Handle(priv.OpPools, func(context.Context, json.RawMessage) (any, error) {
		return []zfs.Pool{{Name: "tank", Health: "ONLINE"}, {Name: "broken", Health: "FAULTED"}}, nil
	})
	ps.Handle(priv.OpAppsStatus, func(context.Context, json.RawMessage) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		o := apps.Overview{Available: true, Configured: d.pool != "", Pool: d.pool, EngineRunning: d.pool != ""}
		for _, a := range d.apps {
			o.Apps = append(o.Apps, a)
		}
		return o, nil
	})
	ps.Handle(priv.OpAppsPorts, func(_ context.Context, raw json.RawMessage) (any, error) {
		var a priv.AppPortsArgs
		_ = json.Unmarshal(raw, &a)
		out := map[string]int{}
		for _, p := range a.Ports {
			out[p.Name] = p.Default + 1 // pretend the default is taken
		}
		return out, nil
	})
	ps.Handle(priv.OpAppsPrepare, func(_ context.Context, raw json.RawMessage) (any, error) {
		var a apps.PrepareArgs
		_ = json.Unmarshal(raw, &a)
		pkg, err := apps.ReadPackage(a.Package)
		if err != nil {
			return nil, priv.Errorf(priv.CodeBadArgs, "%v", err)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		d.prepared = append(d.prepared, a)
		if d.pool == "" {
			d.pool = a.Pool
		}
		_, upgrade := d.apps[pkg.Manifest.ID]
		d.apps[pkg.Manifest.ID] = apps.App{ID: pkg.Manifest.ID, Name: pkg.Manifest.Name, Version: pkg.Manifest.Version,
			State: "stopped", Dataset: d.pool + "/apps/" + pkg.Manifest.ID, Containers: []apps.Container{{Service: "app", State: "exited"}}}
		return apps.PrepareResult{ID: pkg.Manifest.ID, Name: pkg.Manifest.Name, Upgrade: upgrade, Warnings: []string{},
			Services: []apps.ServiceImage{{Service: "db", Image: "postgres:16-alpine"}, {Service: "app", Image: "ghcr.io/x/app:latest"}}}, nil
	})
	ps.Handle(priv.OpAppsPull, func(_ context.Context, raw json.RawMessage) (any, error) {
		rec("pull", raw)
		var a priv.AppPullArgs
		_ = json.Unmarshal(raw, &a)
		if a.Service == "db" {
			return apps.PullResult{Cached: true, Message: "Docker Hub couldn't be reached; using the copy of postgres already here"}, nil
		}
		return apps.PullResult{}, nil
	})
	setState := func(state string) func(context.Context, json.RawMessage) (any, error) {
		return func(_ context.Context, raw json.RawMessage) (any, error) {
			var a priv.AppRef
			_ = json.Unmarshal(raw, &a)
			d.mu.Lock()
			defer d.mu.Unlock()
			d.calls = append(d.calls, state+" "+a.ID)
			app := d.apps[a.ID]
			app.State = state
			d.apps[a.ID] = app
			return map[string]bool{"ok": true}, nil
		}
	}
	ps.Handle(priv.OpAppsUp, setState("running"))
	ps.Handle(priv.OpAppsStart, setState("running"))
	ps.Handle(priv.OpAppsStop, setState("stopped"))
	ps.Handle(priv.OpAppsLogs, func(_ context.Context, raw json.RawMessage) (any, error) {
		rec("logs", raw)
		return priv.AppLogsResult{Logs: "app-1  | listening on :3000\n"}, nil
	})
	ps.Handle(priv.OpAppsRemove, func(_ context.Context, raw json.RawMessage) (any, error) {
		rec("remove", raw)
		var a apps.RemoveArgs
		_ = json.Unmarshal(raw, &a)
		d.mu.Lock()
		defer d.mu.Unlock()
		delete(d.apps, a.ID)
		return map[string]bool{"ok": true}, nil
	})
}

func (d *stubApps) called(prefix string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for _, c := range d.calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// writeTestApp packs a small app with a password setting.
func writeTestApp(t *testing.T, dir, version string) []byte {
	t.Helper()
	src := t.TempDir()
	mf := `{"format":1,"id":"notes","name":"Family Notes","version":"` + version + `","summary":"Shared notes.",
	  "publisher":"Test","icon":"icon.svg","web":{"port":"WEB"},
	  "ports":[{"name":"WEB","label":"Website","default":8100}],
	  "settings":[{"env":"SECRET","generate":"secret"},{"env":"ADMIN_PASSWORD","label":"Admin password","type":"password","required":true},
	    {"env":"TITLE","label":"Title","default":"Notes"}]}`
	compose := "services:\n  app:\n    image: ghcr.io/x/app:latest\n    ports: [\"${HARDY_PORT_WEB}:80\"]\n    environment:\n      PASSWORD: ${ADMIN_PASSWORD}\n"
	for name, body := range map[string]string{
		"hardyapp.json": mf, "compose.yaml": compose,
		"icon.svg": `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"/>`,
	} {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := apps.Pack(src)
	if err != nil {
		t.Fatal(err)
	}
	if dir != "" {
		if err := os.WriteFile(filepath.Join(dir, "notes.hardyapp"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return b
}

func TestAppsAPI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stub := &stubApps{apps: map[string]apps.App{}}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	stub.register(ps)
	go func() { _ = ps.Serve(ctx, ln) }()
	pc := priv.NewClient(sock)
	broker := events.NewBroker()
	m := &jobs.Manager{DB: db, Events: broker}
	RegisterJobKinds(m, pc)
	catalog := t.TempDir()
	writeTestApp(t, catalog, "1.0.0")
	appStore := &appstore.Store{CatalogDir: catalog, UploadDir: filepath.Join(t.TempDir(), "uploads")}
	RegisterAppJobs(m, pc, appStore)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	upd := &updates.Service{Priv: pc, Jobs: m, DB: db, Dir: t.TempDir(), Notify: &notify.Center{DB: db, Events: broker}}
	srv := httptest.NewServer(New(Config{DB: db, Jobs: m, Events: broker, Priv: pc, Updates: upd, Apps: appStore, Insecure: true}))
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	env := &testEnv{srv: srv, db: db, broker: broker}
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	kid := env.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)

	// The catalog lists the app with what the install form needs.
	var cat []appstore.Entry
	if code := admin.do("GET", "/api/v1/apps/catalog", nil, &cat); code != 200 || len(cat) != 1 {
		t.Fatalf("catalog = %d %+v", code, cat)
	}
	if e := cat[0]; e.ID != "notes" || len(e.Settings) != 2 || !e.Ports[0].Web || len(e.Images) != 1 || !strings.HasPrefix(e.Icon, "data:image/svg+xml") {
		t.Fatalf("catalog entry: %+v", e)
	}
	if code := kid.do("GET", "/api/v1/apps/catalog", nil, nil); code != 403 {
		t.Fatalf("family member saw the catalog: %d", code)
	}

	// The plan suggests free ports and, the first time, the healthy pools.
	var plan AppPlan
	if code := admin.do("POST", "/api/v1/apps/plan", AppPackageRef{Source: "catalog", Ref: "notes"}, &plan); code != 200 {
		t.Fatalf("plan = %d", code)
	}
	if plan.Ports["WEB"] != 8101 || len(plan.Pools) != 1 || plan.Pools[0] != "tank" || plan.EnginePool != "" || plan.Installed {
		t.Fatalf("plan: %+v", plan)
	}
	var e ErrorResponse
	if code := admin.do("POST", "/api/v1/apps/plan", AppPackageRef{Source: "catalog", Ref: "nope"}, &e); code != 404 {
		t.Fatalf("plan for a missing app = %d", code)
	}

	// Quick mistakes are caught before the job.
	bad := AppInstallRequest{AppPackageRef: AppPackageRef{Source: "catalog", Ref: "notes"}, Pool: "tank",
		Ports: map[string]int{"WEB": 80, "SSH": 2222}, Settings: map[string]string{"SECRET": "mine", "OTHER": "x"}}
	if code := admin.do("POST", "/api/v1/apps/install", bad, &e); code != 400 || len(e.Details) != 4 {
		t.Fatalf("bad install = %d %+v", code, e)
	}

	// Install: the password goes to the job in memory, never into its parameters.
	const pw = "correct-horse-battery"
	req := AppInstallRequest{AppPackageRef: AppPackageRef{Source: "catalog", Ref: "notes"}, Pool: "tank",
		Ports: map[string]int{"WEB": 8101}, Settings: map[string]string{"ADMIN_PASSWORD": pw, "TITLE": "Hardy notes"}}
	var acc struct {
		Job struct {
			ID string `json:"id"`
		} `json:"job"`
	}
	if code := admin.do("POST", "/api/v1/apps/install", req, &acc); code != 202 {
		t.Fatalf("install = %d", code)
	}
	j := waitJobDone(t, admin, acc.Job.ID)
	if j["state"] != "succeeded" {
		t.Fatalf("install job: %v", j)
	}
	if b, _ := json.Marshal(j); strings.Contains(string(b), pw) {
		t.Fatal("the password is in the job")
	}
	if res, _ := j["result"].(map[string]any); res == nil || !strings.Contains(strings.Join(toStrings(res["notes"]), " "), "postgres") {
		t.Errorf("install result should mention the cached image: %v", j["result"])
	}
	stub.mu.Lock()
	got := stub.prepared[0]
	stub.mu.Unlock()
	if got.Settings["ADMIN_PASSWORD"] != pw || got.Settings["TITLE"] != "Hardy notes" || got.Pool != "tank" || got.Host != "127.0.0.1" || got.Ports["WEB"] != 8101 {
		t.Fatalf("prepare got %+v", got)
	}
	if n := len(stub.called("pull")); n != 2 {
		t.Fatalf("pulled %d images", n)
	}
	var audit []struct {
		Action string `json:"action"`
		Target string `json:"target"`
	}
	admin.do("GET", "/api/v1/audit?action=apps.", nil, &audit)
	if len(audit) != 1 || audit[0].Action != "apps.install" || audit[0].Target != "notes 1.0.0" {
		t.Errorf("audit for the install: %+v", audit)
	}

	// Family members see installed apps, without the details.
	var ov AppsOverview
	if code := kid.do("GET", "/api/v1/apps", nil, &ov); code != 200 || len(ov.Apps) != 1 || ov.Apps[0].State != "running" ||
		ov.Pool != "" || ov.Apps[0].Dataset != "" || len(ov.Apps[0].Containers) != 0 {
		t.Fatalf("family view = %d %+v", code, ov)
	}
	if code := kid.do("POST", "/api/v1/apps/notes/stop", nil, nil); code != 403 {
		t.Fatalf("family member stopped an app: %d", code)
	}

	// Stop and start answer with the app.
	var app apps.App
	if code := admin.do("POST", "/api/v1/apps/notes/stop", nil, &app); code != 200 || app.State != "stopped" {
		t.Fatalf("stop = %d %+v", code, app)
	}
	if code := admin.do("POST", "/api/v1/apps/notes/start", nil, &app); code != 200 || app.State != "running" {
		t.Fatalf("start = %d %+v", code, app)
	}
	if code := admin.do("POST", "/api/v1/apps/notes/explode", nil, nil); code != 404 {
		t.Fatalf("unknown action = %d", code)
	}
	if code := admin.do("POST", "/api/v1/apps/ghost/stop", nil, nil); code != 404 {
		t.Fatalf("stop a missing app = %d", code)
	}

	// Logs.
	var logs AppLogs
	if code := admin.do("GET", "/api/v1/apps/notes/logs?lines=50", nil, &logs); code != 200 || !strings.Contains(logs.Logs, "listening") {
		t.Fatalf("logs = %d %+v", code, logs)
	}
	if code := admin.do("GET", "/api/v1/apps/notes/logs?lines=99999", nil, nil); code != 400 {
		t.Fatalf("too many lines = %d", code)
	}

	// A newer version in the catalog shows as an update; updating keeps the
	// app's own host, ports and settings.
	writeTestApp(t, catalog, "1.1.0")
	admin.do("GET", "/api/v1/apps", nil, &ov)
	if ov.Updates["notes"] != "1.1.0" {
		t.Fatalf("updates: %+v", ov.Updates)
	}
	if code := admin.do("POST", "/api/v1/apps/notes/update", nil, &acc); code != 202 {
		t.Fatalf("update = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job.ID); j["state"] != "succeeded" {
		t.Fatalf("update job: %v", j)
	}
	stub.mu.Lock()
	got = stub.prepared[1]
	stub.mu.Unlock()
	if got.Host != "" || got.Pool != "" || len(got.Ports) != 0 || len(got.Settings) != 0 {
		t.Fatalf("update sent %+v", got)
	}

	// Uploads are checked and kept by their hash.
	if code := admin.do("POST", "/api/v1/apps/packages", []byte("not a package"), &e); code != 400 {
		t.Fatalf("junk upload = %d", code)
	}
	if code := admin.do("POST", "/api/v1/apps/packages", make([]byte, apps.MaxPackageBytes+10), &e); code != 413 {
		t.Fatalf("huge upload = %d", code)
	}
	var up appstore.Entry
	if code := admin.do("POST", "/api/v1/apps/packages", writeTestApp(t, "", "2.0.0"), &up); code != 200 || up.Source != "upload" || len(up.Ref) != 64 || up.Version != "2.0.0" {
		t.Fatalf("upload = %d %+v", code, up)
	}
	if code := admin.do("POST", "/api/v1/apps/plan", AppPackageRef{Source: "upload", Ref: up.Ref}, &plan); code != 200 || !plan.Installed || plan.InstalledVersion != "1.1.0" || plan.EnginePool != "tank" || len(plan.Pools) != 0 {
		t.Fatalf("plan for the upload = %d %+v", code, plan)
	}
	if code := admin.do("POST", "/api/v1/apps/plan", AppPackageRef{Source: "upload", Ref: "../../etc/passwd"}, &e); code != 404 {
		t.Fatalf("path in ref = %d", code)
	}

	// Removing needs the app's name.
	if code := admin.do("DELETE", "/api/v1/apps/notes", AppRemoveRequest{Confirm: "nope"}, &e); code != 400 || e.Code != "confirm_required" {
		t.Fatalf("remove without confirming = %d %+v", code, e)
	}
	if code := admin.do("DELETE", "/api/v1/apps/notes", AppRemoveRequest{Confirm: "family notes", DeleteData: true}, &acc); code != 202 {
		t.Fatalf("remove = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job.ID); j["state"] != "succeeded" {
		t.Fatalf("remove job: %v", j)
	}
	if rm := stub.called("remove"); len(rm) != 1 || !strings.Contains(rm[0], `"deleteData":true`) {
		t.Fatalf("remove calls: %v", rm)
	}
}

func toStrings(v any) []string {
	var out []string
	if xs, ok := v.([]any); ok {
		for _, x := range xs {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func TestNewerVersion(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"1.10.0", "1.9.2", true}, {"1.0.0", "1.0.0", false}, {"1.0.0", "1.0.0-rc1", true},
		{"1.0.0-rc1", "1.0.0", false}, {"2", "1.9.9", true}, {"v1.2.0", "1.1.9", true}, {"1.0.1", "1.0", true},
	} {
		if got := apps.NewerVersion(c.a, c.b); got != c.want {
			t.Errorf("NewerVersion(%q, %q) = %v", c.a, c.b, got)
		}
	}
}
