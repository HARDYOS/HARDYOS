package api

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/tlscert"
	"github.com/hardyos/hardyos/daemon/internal/updates"
)

type appsEnv struct {
	*testEnv
	ctx     context.Context
	server  *Server
	stub    *stubApps
	store   *appstore.Store
	catalog string
	admin   *client
	kid     *client
}

func newAppsEnv(t *testing.T) *appsEnv {
	t.Helper()
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
	st := &appstore.Store{CatalogDir: catalog, UploadDir: filepath.Join(t.TempDir(), "uploads"),
		ImportDir: filepath.Join(t.TempDir(), "imports"), DB: db}
	RegisterAppJobs(m, pc, st)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	upd := &updates.Service{Priv: pc, Jobs: m, DB: db, Dir: t.TempDir(), Notify: &notify.Center{DB: db, Events: broker}}
	server := New(Config{DB: db, Jobs: m, Events: broker, Priv: pc, Updates: upd, Apps: st, Insecure: true})
	srv := httptest.NewServer(server)
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	e := &appsEnv{testEnv: &testEnv{srv: srv, db: db, broker: broker}, ctx: ctx, server: server, stub: stub, store: st, catalog: catalog}
	e.admin = e.client(t)
	e.admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	e.admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	e.kid = e.client(t)
	e.kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	return e
}

type jobRef struct {
	Job struct {
		ID string `json:"id"`
	} `json:"job"`
}

// runJob posts and waits for the job it starts.
func (e *appsEnv) runJob(t *testing.T, method, path string, body any) map[string]any {
	t.Helper()
	var acc jobRef
	var er ErrorResponse
	code := e.admin.do(method, path, body, &acc)
	if code != 202 {
		e.admin.do(method, path, body, &er)
		t.Fatalf("%s %s = %d %+v", method, path, code, er)
	}
	return waitJobDone(t, e.admin, acc.Job.ID)
}

func (e *appsEnv) installNotes(t *testing.T, access []appstore.Principal) {
	t.Helper()
	req := AppInstallRequest{AppPackageRef: AppPackageRef{Source: "catalog", Ref: "notes"}, Pool: "tank",
		Settings: map[string]string{"ADMIN_PASSWORD": "pw-123456"}, Access: access}
	if j := e.runJob(t, "POST", "/api/v1/apps/install", req); j["state"] != "succeeded" {
		t.Fatalf("install: %v", j)
	}
}

func auditActions(c *client, prefix string) []string {
	var list []struct {
		Action string `json:"action"`
		Target string `json:"target"`
	}
	c.do("GET", "/api/v1/audit?action="+prefix, nil, &list)
	var out []string
	for _, a := range list {
		out = append(out, a.Action+" "+a.Target)
	}
	return out
}

func TestAppAccess(t *testing.T) {
	e := newAppsEnv(t)
	var er ErrorResponse
	bad := AppInstallRequest{AppPackageRef: AppPackageRef{Source: "catalog", Ref: "notes"}, Pool: "tank",
		Access: []appstore.Principal{{Kind: "user", Name: "ghost"}, {Kind: "group", Name: "Family"}}}
	if code := e.admin.do("POST", "/api/v1/apps/install", bad, &er); code != 400 || len(er.Details) != 1 {
		t.Fatalf("bad access = %d %+v", code, er) // the bad group stops before the missing user is looked up
	}
	e.installNotes(t, []appstore.Principal{{Kind: "user", Name: "Cade"}})

	// Only cade (and administrators) may use it: the kid doesn't see it.
	var ov AppsOverview
	if code := e.kid.do("GET", "/api/v1/apps", nil, &ov); code != 200 || len(ov.Apps) != 0 {
		t.Fatalf("kid sees %d %+v", code, ov.Apps)
	}
	if code := e.kid.do("POST", "/api/v1/apps/notes/open", nil, &er); code != 403 {
		t.Fatalf("kid opened it: %d", code)
	}
	var acc AppAccess
	if code := e.admin.do("GET", "/api/v1/apps/notes/access", nil, &acc); code != 200 || len(acc.Principals) != 1 || acc.Principals[0].Name != "cade" {
		t.Fatalf("access = %d %+v", code, acc)
	}
	if code := e.kid.do("GET", "/api/v1/apps/notes/access", nil, nil); code != 403 {
		t.Fatalf("kid read access: %d", code)
	}

	// Domain users and groups are stored as written; HardyOS users must exist.
	put := AppAccess{Principals: []appstore.Principal{{Kind: "user", Name: "kid"}, {Kind: "group", Name: `HOME\Family`}, {Kind: "user", Name: `HOME\alice`}, {Kind: "user", Name: "kid"}}}
	if code := e.admin.do("PUT", "/api/v1/apps/notes/access", put, &acc); code != 200 || len(acc.Principals) != 3 {
		t.Fatalf("put access = %d %+v", code, acc)
	}
	if code := e.kid.do("GET", "/api/v1/apps", nil, &ov); code != 200 || len(ov.Apps) != 1 || ov.Apps[0].Dataset != "" {
		t.Fatalf("kid view = %d %+v", code, ov.Apps)
	}
	if code := e.admin.do("PUT", "/api/v1/apps/notes/access", AppAccess{Principals: []appstore.Principal{{Kind: "user", Name: "nobody"}}}, &er); code != 400 {
		t.Fatalf("unknown user = %d", code)
	}
	if code := e.admin.do("PUT", "/api/v1/apps/ghost/access", put, &er); code != 404 {
		t.Fatalf("access for a missing app = %d", code)
	}
	// Everyone is stored as no list.
	if code := e.admin.do("PUT", "/api/v1/apps/notes/access", AppAccess{Principals: []appstore.Principal{{Kind: "everyone"}, {Kind: "user", Name: "kid"}}}, &acc); code != 200 || len(acc.Principals) != 0 {
		t.Fatalf("everyone = %d %+v", code, acc)
	}
	if got := auditActions(e.admin, "apps.access"); len(got) != 3 {
		t.Errorf("access audit: %v", got)
	}

	// Removing with the data forgets who could use it.
	e.admin.do("PUT", "/api/v1/apps/notes/access", put, nil)
	if j := e.runJob(t, "DELETE", "/api/v1/apps/notes", AppRemoveRequest{Confirm: "Family Notes", DeleteData: true}); j["state"] != "succeeded" {
		t.Fatalf("remove: %v", j)
	}
	if l, _ := e.store.Access(e.ctx, "notes"); len(l) != 0 {
		t.Fatalf("access kept after deleting the data: %+v", l)
	}
}

func TestAppConfigUpdateRollback(t *testing.T) {
	e := newAppsEnv(t)
	e.installNotes(t, nil)

	var cfg AppConfigView
	if code := e.admin.do("GET", "/api/v1/apps/notes/config", nil, &cfg); code != 200 || cfg.UID != 30000 || len(cfg.Package.Settings) != 2 || cfg.Source != "catalog" {
		t.Fatalf("config = %d %+v", code, cfg)
	}
	if code := e.kid.do("GET", "/api/v1/apps/notes/config", nil, nil); code != 403 {
		t.Fatalf("kid read config: %d", code)
	}
	var er ErrorResponse
	if code := e.admin.do("PATCH", "/api/v1/apps/notes/config", AppConfigUpdate{}, &er); code != 400 {
		t.Fatalf("empty change = %d", code)
	}
	grants := []string{"hostNetwork"}
	if code := e.admin.do("PATCH", "/api/v1/apps/notes/config", AppConfigUpdate{Grants: &grants, Limits: &apps.Limits{MemoryMB: 10}}, &er); code != 400 || len(er.Details) != 2 {
		t.Fatalf("grants on a catalog app = %d %+v", code, er)
	}
	const pw = "a-new-password-1"
	j := e.runJob(t, "PATCH", "/api/v1/apps/notes/config", AppConfigUpdate{
		Settings: map[string]string{"TITLE": "Our notes", "ADMIN_PASSWORD": pw},
		Limits:   &apps.Limits{MemoryMB: 512, CPUs: 1.5},
	})
	if j["state"] != "succeeded" {
		t.Fatalf("reconfigure: %v", j)
	}
	if b, _ := json.Marshal(j); strings.Contains(string(b), pw) {
		t.Fatal("the password is in the job")
	}
	e.stub.mu.Lock()
	rc := e.stub.reconfigs[0]
	e.stub.mu.Unlock()
	if rc.Settings["ADMIN_PASSWORD"] != pw || rc.Settings["TITLE"] != "Our notes" || rc.Limits == nil || rc.Limits.MemoryMB != 512 || rc.Grants != nil {
		t.Fatalf("reconfigure got %+v", rc)
	}
	// An empty password keeps the current one.
	e.runJob(t, "PATCH", "/api/v1/apps/notes/config", AppConfigUpdate{Settings: map[string]string{"ADMIN_PASSWORD": ""}, Ports: map[string]int{"WEB": 8200}})
	e.stub.mu.Lock()
	rc = e.stub.reconfigs[1]
	e.stub.mu.Unlock()
	if _, ok := rc.Settings["ADMIN_PASSWORD"]; ok || rc.Ports["WEB"] != 8200 {
		t.Fatalf("second reconfigure got %+v", rc)
	}

	// An update takes a snapshot first; when it fails, the job says which.
	writeTestApp(t, e.catalog, "1.1.0")
	e.stub.mu.Lock()
	e.stub.failUp = true
	e.stub.mu.Unlock()
	j = e.runJob(t, "POST", "/api/v1/apps/notes/update", nil)
	res, _ := j["result"].(map[string]any)
	if j["state"] != "failed" || res["snapshot"] != "hardyos-update-20261026-120000" || !strings.Contains(j["error"].(string), "roll back") {
		t.Fatalf("failed update: %v", j)
	}
	var snaps priv.AppSnapshotsResult
	if code := e.admin.do("GET", "/api/v1/apps/notes/snapshots", nil, &snaps); code != 200 || len(snaps.Snapshots) != 1 {
		t.Fatalf("snapshots = %d %+v", code, snaps)
	}
	if code := e.admin.do("POST", "/api/v1/apps/notes/rollback", AppRollbackRequest{Snapshot: snaps.Snapshots[0].Name, Confirm: "nope"}, &er); code != 400 || er.Code != "confirm_required" {
		t.Fatalf("rollback without confirming = %d", code)
	}
	if code := e.admin.do("POST", "/api/v1/apps/notes/rollback", AppRollbackRequest{Snapshot: "hardyos-update-19990101-000000", Confirm: "family notes"}, &er); code != 404 {
		t.Fatalf("rollback to a missing snapshot = %d", code)
	}
	if code := e.admin.do("POST", "/api/v1/apps/notes/rollback", AppRollbackRequest{Snapshot: "../x", Confirm: "family notes"}, &er); code != 400 {
		t.Fatalf("rollback to a bad name = %d", code)
	}
	if j := e.runJob(t, "POST", "/api/v1/apps/notes/rollback", AppRollbackRequest{Snapshot: snaps.Snapshots[0].Name, Confirm: "family notes"}); j["state"] != "succeeded" {
		t.Fatalf("rollback: %v", j)
	}
	e.stub.mu.Lock()
	rb := e.stub.rolledBack[0]
	e.stub.failUp = false
	e.stub.mu.Unlock()
	if rb.Snapshot != snaps.Snapshots[0].Name || rb.Confirm != "Family Notes" {
		t.Fatalf("rollback got %+v", rb)
	}
	j = e.runJob(t, "POST", "/api/v1/apps/notes/update", nil)
	if res, _ := j["result"].(map[string]any); j["state"] != "succeeded" || res["snapshot"] == "" {
		t.Fatalf("update: %v", j)
	}
	if n := len(e.stub.called("snapshot")); n != 2 {
		t.Fatalf("%d snapshots", n)
	}
}

// packApp builds a package from a manifest and compose file.
func packApp(t *testing.T, manifest, compose string) []byte {
	t.Helper()
	src := t.TempDir()
	for name, body := range map[string]string{"hardyapp.json": manifest, "compose.yaml": compose,
		"icon.svg": `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"/>`} {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := apps.Pack(src)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func labApp(t *testing.T, version string) []byte {
	gpu := ""
	if version == "1.1.0" {
		gpu = `,"gpu":true` // the new version asks for the graphics card too
	}
	return packApp(t, `{"format":1,"id":"labnotes","name":"Lab Notes","version":"`+version+`","summary":"Notes from a lab.","icon":"icon.svg",
	  "web":{"port":"WEB"},"ports":[{"name":"WEB","label":"Website","default":8300}],
	  "shares":[{"name":"DOCS","label":"Documents","access":"write","suggest":"documents","required":true}],
	  "permissions":{"hostNetwork":true,"devices":["/dev/dri"]`+gpu+`}}`,
		"services:\n  app:\n    image: ghcr.io/lab/notes:"+version+"\n    ports: [\"${HARDY_PORT_WEB}:80\"]\n")
}

func shaHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestImportedCatalogsAndCustomApps(t *testing.T) {
	e := newAppsEnv(t)
	var mu sync.Mutex
	pkgs := map[string][]byte{"/pkgs/lab-1.hardyapp": labApp(t, "1.0.0"), "/pkgs/evil.hardyapp": labApp(t, "6.6.6")}
	index := func() string {
		mu.Lock()
		defer mu.Unlock()
		return `{"name":"Hardy Labs","apps":[
		  {"id":"labnotes","name":"Lab Notes","version":"1.0.0","summary":"Notes.","url":"../pkgs/lab-1.hardyapp","sha256":"` + shaHex(pkgs["/pkgs/lab-1.hardyapp"]) + `","icon":"https://tracker.example/i.png"},
		  {"id":"plain","name":"Plain","version":"1.0","summary":"Over http","url":"http://example.com/p.hardyapp","sha256":"` + strings.Repeat("a", 64) + `"},
		  {"id":"evil","name":"Evil","version":"6.6.6","summary":"Wrong hash","url":"/pkgs/evil.hardyapp","sha256":"` + strings.Repeat("b", 64) + `"}]}`
	}
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hardyos/index.json" {
			_, _ = io.WriteString(w, index())
			return
		}
		mu.Lock()
		b, ok := pkgs[r.URL.Path]
		mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	defer remote.Close()
	e.store.Client = remote.Client()
	indexURL := remote.URL + "/hardyos/index.json"

	var er ErrorResponse
	if code := e.admin.do("POST", "/api/v1/apps/catalogs", AppCatalogRequest{URL: strings.Replace(indexURL, "https", "http", 1)}, &er); code != 400 {
		t.Fatalf("http catalog = %d", code)
	}
	if code := e.kid.do("POST", "/api/v1/apps/catalogs", AppCatalogRequest{URL: indexURL}, nil); code != 403 {
		t.Fatalf("kid added a catalog: %d", code)
	}
	var cat appstore.Catalog
	if code := e.admin.do("POST", "/api/v1/apps/catalogs", AppCatalogRequest{URL: indexURL}, &cat); code != 200 || cat.Name != "Hardy Labs" || len(cat.Apps) != 2 ||
		!strings.Contains(cat.LastError, "plain") || cat.Apps[0].Icon != "" {
		t.Fatalf("add catalog = %d %+v %+v", code, cat, er)
	}
	var list []appstore.Catalog
	if code := e.admin.do("GET", "/api/v1/apps/catalogs", nil, &list); code != 200 || len(list) != 1 {
		t.Fatalf("catalogs = %d %+v", code, list)
	}

	// The package is fetched, checked against the index's hash and labelled.
	lab := cat.Apps[0]
	var plan AppPlan
	if code := e.admin.do("POST", "/api/v1/apps/plan", AppPackageRef{Source: "imported", Ref: lab.SHA256}, &plan); code != 200 ||
		plan.Package.SourceName != "Hardy Labs" || len(plan.Package.Grants) != 2 || len(plan.Package.Shares) != 1 {
		er = ErrorResponse{}
		e.admin.do("POST", "/api/v1/apps/plan", AppPackageRef{Source: "imported", Ref: lab.SHA256}, &er)
		t.Fatalf("plan = %d %+v %+v", code, plan, er)
	}
	if code := e.admin.do("POST", "/api/v1/apps/plan", AppPackageRef{Source: "imported", Ref: cat.Apps[1].SHA256}, &er); code != 400 || !strings.Contains(er.Message, "checksum") {
		t.Fatalf("tampered package = %d %+v", code, er)
	}

	// Extra permissions must be asked for, and each one is audited.
	req := AppInstallRequest{AppPackageRef: AppPackageRef{Source: "imported", Ref: lab.SHA256}, Pool: "tank",
		Grants: []string{"gpu"}, Limits: &apps.Limits{MemoryMB: 1}}
	if code := e.admin.do("POST", "/api/v1/apps/install", req, &er); code != 400 || len(er.Details) != 5 {
		t.Fatalf("bad grants = %d %+v", code, er) // gpu not asked, two not allowed, the share is required, memory too small
	}
	req.Grants, req.Limits = []string{"hostNetwork", "device:/dev/dri"}, &apps.Limits{MemoryMB: 1024, CPUs: 2}
	req.Shares = map[string]apps.ShareChoice{"DOCS": {Share: "documents", Path: "Lab", Access: "read"}}
	if code := e.admin.do("POST", "/api/v1/apps/install", req, &er); code != 400 || !strings.Contains(er.Message, "whole shared folder") {
		t.Fatalf("subfolder = %d %+v", code, er)
	}
	req.Shares = map[string]apps.ShareChoice{"DOCS": {Share: "documents", Access: "read"}}
	if j := e.runJob(t, "POST", "/api/v1/apps/install", req); j["state"] != "succeeded" {
		t.Fatalf("install: %v", j)
	}
	e.stub.mu.Lock()
	got := e.stub.prepared[len(e.stub.prepared)-1]
	e.stub.mu.Unlock()
	if got.Source != apps.SourceImported || got.SourceName != "Hardy Labs" || len(got.Grants) != 2 || got.Shares["DOCS"].Share != "documents" || got.Limits.CPUs != 2 {
		t.Fatalf("prepare got %+v", got)
	}
	if a := auditActions(e.admin, "apps.grant"); len(a) != 2 || a[1] != "apps.grant labnotes hostNetwork" {
		t.Fatalf("grant audit: %v", a)
	}

	// A newer version in the catalog shows as an update once refreshed.
	var ov AppsOverview
	e.admin.do("GET", "/api/v1/apps", nil, &ov)
	if len(ov.Updates) != 0 {
		t.Fatalf("updates before refresh: %v", ov.Updates)
	}
	mu.Lock()
	pkgs["/pkgs/lab-2.hardyapp"] = labApp(t, "1.1.0")
	mu.Unlock()
	newIndex := `{"name":"Renamed","apps":[{"id":"labnotes","name":"Lab Notes","version":"1.1.0","summary":"Notes.","url":"/pkgs/lab-2.hardyapp","sha256":"` + shaHex(labApp(t, "1.1.0")) + `"}]}`
	remote.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hardyos/index.json" {
			_, _ = io.WriteString(w, newIndex)
			return
		}
		mu.Lock()
		b := pkgs[r.URL.Path]
		mu.Unlock()
		_, _ = w.Write(b)
	})
	if code := e.admin.do("POST", "/api/v1/apps/catalogs", AppCatalogRequest{URL: indexURL}, &cat); code != 200 || cat.Name != "Hardy Labs" || cat.Apps[0].Version != "1.1.0" {
		t.Fatalf("refresh = %d %+v", code, cat)
	}
	e.admin.do("GET", "/api/v1/apps", nil, &ov)
	if ov.Updates["labnotes"] != "1.1.0" {
		t.Fatalf("updates: %v", ov.Updates)
	}
	// 1.1.0 asks for the GPU too: the update says so before taking a snapshot.
	var need GrantsNeeded
	if code := e.admin.do("POST", "/api/v1/apps/labnotes/update", nil, &need); code != 400 || need.Code != "grants_required" ||
		len(need.Grants) != 1 || need.Grants[0].Grant != "gpu" {
		t.Fatalf("update needing a grant = %d %+v", code, need)
	}
	all := []string{"hostNetwork", "device:/dev/dri", "gpu"}
	if j := e.runJob(t, "POST", "/api/v1/apps/labnotes/update", AppUpdateRequest{Grants: &all}); j["state"] != "succeeded" {
		t.Fatalf("update: %v", j)
	}
	e.stub.mu.Lock()
	got = e.stub.prepared[len(e.stub.prepared)-1]
	e.stub.mu.Unlock()
	if got.Source != apps.SourceImported || len(got.Grants) != 3 {
		t.Fatalf("update prepared %+v", got)
	}

	if code := e.admin.do("DELETE", "/api/v1/apps/catalogs", AppCatalogRemoveRequest{ID: cat.ID}, nil); code != 204 {
		t.Fatalf("remove catalog = %d", code)
	}
	if code := e.admin.do("DELETE", "/api/v1/apps/catalogs", AppCatalogRemoveRequest{ID: cat.ID}, nil); code != 404 {
		t.Fatalf("remove again = %d", code)
	}
	if a := auditActions(e.admin, "apps.catalog"); len(a) != 3 {
		t.Fatalf("catalog audit: %v", a) // add, refresh, remove
	}

	// Create an app from a Compose file.
	custom := appstore.CustomApp{ID: "whoami", Name: "Who am I", Compose: "services:\n  web:\n    image: traefik/whoami\n    ports: [\"8080:80\"]\n",
		Ports: []apps.Port{{Name: "WEB", Label: "Website", Default: 8400}}, WebPort: "WEB",
		Folders: []apps.Folder{{Path: "config", Owner: "1000:1000"}}}
	if code := e.admin.do("POST", "/api/v1/apps/custom", custom, &er); code != 400 || !strings.Contains(er.Message, "${HARDY_PORT_WEB}") {
		t.Fatalf("custom without the port variable = %d %+v", code, er)
	}
	custom.Compose = strings.Replace(custom.Compose, "8080:80", "${HARDY_PORT_WEB}:80", 1)
	if code := e.admin.do("POST", "/api/v1/apps/custom", custom, &plan); code != 200 || plan.Package.Source != "custom" ||
		!strings.HasPrefix(plan.Package.Icon, "data:image/svg+xml") || plan.Ports["WEB"] != 8401 || len(plan.Package.Ref) != 64 {
		t.Fatalf("custom = %d %+v", code, plan)
	}
	if j := e.runJob(t, "POST", "/api/v1/apps/install", AppInstallRequest{AppPackageRef: AppPackageRef{Source: "custom", Ref: plan.Package.Ref}}); j["state"] != "succeeded" {
		t.Fatalf("install custom: %v", j)
	}
	if code := e.admin.do("POST", "/api/v1/apps/whoami/update", nil, &er); code != 400 {
		t.Fatalf("update custom without a package = %d", code)
	}
}

func TestAppWindowProxy(t *testing.T) {
	old := proxyRecheck
	proxyRecheck = 0
	defer func() { proxyRecheck = old }()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ws":
			c, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer c.CloseNow()
			typ, b, err := c.Read(r.Context())
			if err == nil {
				_ = c.Write(r.Context(), typ, append([]byte("echo: "), b...))
			}
			return
		case "/go":
			http.Redirect(w, r, "http://"+r.Host+"/there", http.StatusFound)
			return
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		_, _ = io.WriteString(w, "host="+r.Host+" proto="+r.Header.Get("X-Forwarded-Proto")+" cookies="+r.Header.Get("Cookie"))
	}))
	defer backend.Close()
	bport := backend.Listener.Addr().(*net.TCPAddr).Port

	e := newAppsEnv(t)
	e.stub.webPortFrom = bport
	e.installNotes(t, []appstore.Principal{{Kind: "user", Name: "cade"}})

	// Without the proxy running, open gives the app's own address.
	var open AppOpen
	if code := e.admin.do("POST", "/api/v1/apps/notes/open", nil, &open); code != 200 || open.Proxied || !strings.HasSuffix(open.URL, ":"+itoa(bport)+"/") {
		t.Fatalf("open without proxy = %d %+v", code, open)
	}

	certPEM, keyPEM, err := tlscert.Generate([]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	probe, _ := net.Listen("tcp", "127.0.0.1:0")
	base := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	go e.server.RunAppProxy(ctx, AppProxyOptions{TLS: &tls.Config{Certificates: []tls.Certificate{cert}}, BasePort: base,
		ListenHost: "127.0.0.1", DesktopPort: 443, Interval: 50 * time.Millisecond})
	deadline := time.Now().Add(5 * time.Second)
	for !e.server.proxy.isRunning() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	if code := e.kid.do("POST", "/api/v1/apps/notes/open", nil, nil); code != 403 {
		t.Fatalf("kid opened it: %d", code)
	}
	if code := e.admin.do("POST", "/api/v1/apps/notes/open", nil, &open); code != 200 || !open.Proxied || !strings.HasPrefix(open.URL, "https://127.0.0.1:") {
		t.Fatalf("open = %d %+v", code, open)
	}
	u, _ := url.Parse(open.URL)
	if p, _ := e.store.ProxyPorts(e.ctx); p["notes"] != base || u.Port() != itoa(base) {
		t.Fatalf("proxy ports %v, url %s", p, open.URL)
	}

	// The admin's browser: the same cookie jar holds the desktop session,
	// which must never reach the app.
	insecure := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	browser := &http.Client{Jar: e.admin.http.Jar, Transport: insecure, Timeout: 10 * time.Second}
	res, err := browser.Get(open.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || res.Request.URL.Path != "/" || strings.Contains(string(body), "hardyos_") || !strings.Contains(string(body), "proto=https") ||
		!strings.Contains(string(body), "host=127.0.0.1:"+itoa(base)) {
		t.Fatalf("through the proxy: %d %s", res.StatusCode, body)
	}
	if res.Header.Get("X-Frame-Options") != "" {
		t.Error("X-Frame-Options kept")
	}
	csp := strings.Join(res.Header.Values("Content-Security-Policy"), " | ")
	if strings.Contains(csp, "'none'") || !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'self' https://127.0.0.1") {
		t.Errorf("CSP: %s", csp)
	}
	jarURL, _ := url.Parse("https://127.0.0.1:" + itoa(base))
	var proxyCookieSeen bool
	for _, c := range e.admin.http.Jar.Cookies(jarURL) {
		proxyCookieSeen = proxyCookieSeen || c.Name == "hardyos_app_notes"
	}
	if !proxyCookieSeen {
		t.Error("no proxy cookie")
	}

	// The token works once.
	if res, err := browser.Get(open.URL); err != nil || res.StatusCode != 403 {
		t.Fatalf("token reused: %v %v", err, res.StatusCode)
	}
	// Someone without the cookie gets the sign-in page.
	stranger := &http.Client{Transport: insecure}
	if res, err := stranger.Get("https://127.0.0.1:" + itoa(base) + "/"); err != nil || res.StatusCode != 401 {
		t.Fatalf("stranger: %v %v", err, res.StatusCode)
	}
	// Redirects to the app's own address stay on the proxy.
	noFollow := &http.Client{Jar: e.admin.http.Jar, Transport: insecure, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if res, err := noFollow.Get("https://127.0.0.1:" + itoa(base) + "/go"); err != nil || res.Header.Get("Location") != "https://127.0.0.1:"+itoa(base)+"/there" {
		t.Fatalf("redirect: %v %v", err, res.Header.Get("Location"))
	}

	// WebSockets go through.
	c, _, err := websocket.Dial(e.ctx, "wss://127.0.0.1:"+itoa(base)+"/ws", &websocket.DialOptions{HTTPClient: browser})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Write(e.ctx, websocket.MessageText, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	if _, b, err := c.Read(e.ctx); err != nil || string(b) != "echo: hi" {
		t.Fatalf("websocket: %v %q", err, b)
	}
	c.CloseNow()

	// The desktop may frame the proxies on its own host.
	res, _ = http.Get(e.srv.URL + "/api/v1/health")
	if !strings.Contains(res.Header.Get("Content-Security-Policy"), "frame-src 'self' http://127.0.0.1:*") {
		t.Errorf("desktop CSP: %s", res.Header.Get("Content-Security-Policy"))
	}

	// Signing out of the desktop ends the app session too.
	e.admin.do("POST", "/api/v1/auth/logout", nil, nil)
	if res, err := browser.Get("https://127.0.0.1:" + itoa(base) + "/"); err != nil || res.StatusCode != 403 {
		t.Fatalf("after sign-out: %v %v", err, res.StatusCode)
	}

	// Removing the app stops its proxy.
	admin2 := e.client(t)
	admin2.do("POST", "/api/v1/auth/login", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	e.admin = admin2
	e.runJob(t, "DELETE", "/api/v1/apps/notes", AppRemoveRequest{Confirm: "notes"})
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := net.DialTimeout("tcp", "127.0.0.1:"+itoa(base), 200*time.Millisecond); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the proxy still listens after the app was removed")
}

type fakeDomainUser struct{}

func (fakeDomainUser) IdentitySource() string    { return "domain" }
func (fakeDomainUser) IdentityPrincipal() string { return `HOME\alice` }
func (fakeDomainUser) IdentityGroups() []string  { return []string{`HOME\Family`} }
func (fakeDomainUser) IsAdmin() bool             { return false }

func TestDomainIdentityForAppAccess(t *testing.T) {
	who := whoOf(fakeDomainUser{})
	rules := []appstore.Principal{{Kind: "group", Name: `home\family`}}
	if who.Username != `HOME\alice` || !appstore.MayUse(rules, who) || appstore.MayUse([]appstore.Principal{{Kind: "user", Name: "alice"}}, who) {
		t.Fatalf("domain who: %+v", who)
	}
}

func TestStripHelpers(t *testing.T) {
	h := http.Header{}
	h.Add("Cookie", "a=1; hardyos_session=x; b=2")
	h.Add("Cookie", "hardyos_app_notes=y")
	stripHardyCookies(h)
	if got := h.Values("Cookie"); len(got) != 1 || got[0] != "a=1; b=2" {
		t.Fatalf("cookies: %v", got)
	}
	for in, want := range map[string]string{
		"default-src 'self'; frame-ancestors 'none'":          "default-src 'self'",
		"frame-ancestors 'none'":                              "",
		"Frame-Ancestors x, script-src 'self'; img-src data:": "script-src 'self'; img-src data:",
	} {
		if got := stripFrameAncestors(in); got != want {
			t.Errorf("stripFrameAncestors(%q) = %q", in, got)
		}
	}
}
