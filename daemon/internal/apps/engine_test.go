package apps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// fakeShares is a ShareResolver over folders in a temp directory.
type fakeShares struct {
	root string
	mu   sync.Mutex
	log  []string
	fail map[string]error
}

func (f *fakeShares) Resolve(_ context.Context, share, sub string) (string, error) {
	if err := f.fail[share]; err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(f.root, share)); err != nil {
		return "", fmt.Errorf("there's no shared folder with that id")
	}
	return filepath.Join(f.root, share, sub), nil
}

func (f *fakeShares) GrantApp(_ context.Context, share, app string, uid int, write bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, fmt.Sprintf("grant %s %s %d %v", share, app, uid, write))
	return nil
}

func (f *fakeShares) RevokeApp(_ context.Context, app string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, "revoke "+app)
	return nil
}

func (f *fakeShares) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	l := f.log
	f.log = nil
	return l
}

const engineManifest = `{"format":1,"id":"notes","name":"Family Notes","version":"1.0.0","summary":"Shared notes.",
  "web":{"port":"WEB"},
  "ports":[{"name":"WEB","label":"Website","default":8100}],
  "settings":[{"env":"SECRET","generate":"secret"},{"env":"ADMIN_PASSWORD","label":"Admin password","type":"password"},
    {"env":"TITLE","label":"Title","default":"Notes"}],
  "folders":[{"path":"db"},{"path":"cache","owner":"999:999"}],
  "shares":[{"name":"MEDIA","label":"Media library","access":"read","suggest":"media"},
    {"name":"DOWNLOADS","label":"Downloads","access":"write"}]PERMS}`

// testEnv is a Manager on a temp root with ZFS, Docker and systemd faked.
type testEnv struct {
	t      *testing.T
	m      *Manager
	fake   *sysexec.Fake
	shares *fakeShares
	root   string
	mnt    string // where datasets are "mounted"
	// compose is what `docker compose config` prints; DATA, MEDIA and DL
	// are replaced by the real folders.
	compose string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	e := &testEnv{t: t, fake: &sysexec.Fake{}, root: t.TempDir(), mnt: t.TempDir()}
	e.shares = &fakeShares{root: t.TempDir()}
	for _, d := range []string{"media/Movies", "downloads"} {
		if err := os.MkdirAll(filepath.Join(e.shares.root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	must(t, os.MkdirAll(filepath.Join(e.root, "usr/bin"), 0o755))
	must(t, os.WriteFile(filepath.Join(e.root, "usr/bin/docker"), nil, 0o755))
	must(t, os.MkdirAll(filepath.Join(e.root, "usr/sbin"), 0o755))
	must(t, os.WriteFile(filepath.Join(e.root, "usr/sbin/dockerd"), nil, 0o755))
	e.m = &Manager{Runner: e.fake, Root: e.root, Shares: e.shares, MemTotal: func() uint64 { return 8 << 30 },
		clock: func() time.Time { return time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC) }}
	must(t, os.MkdirAll(e.m.stateDir(), 0o700))
	eng := EngineConfig{Pool: "tank", Dataset: "tank/docker", DataRoot: "/mnt/tank/docker"}
	must(t, os.WriteFile(filepath.Join(e.m.stateDir(), engineFile), mustJSON(eng), 0o600))

	ok := sysexec.Result{}
	e.fake.OnPrefix("systemctl ", ok)
	e.fake.On("docker info --format {{.ServerVersion}}", "29.0.0")
	e.fake.On("docker info --format {{.ServerVersion}}|{{.DockerRootDir}}", "29.0.0|/mnt/tank/docker")
	e.fake.On("docker compose version", "Docker Compose version v2")
	e.fake.On("ss -Hlntu", "")
	e.fake.OnPrefix("docker ps ", ok)
	e.fake.OnPrefix("docker image inspect", sysexec.Result{Stdout: []byte("sha256:" + strings.Repeat("a", 64) + "\n")})
	e.fake.OnPrefix("zfs create tank/apps/", ok)
	e.dataset("old")
	e.compose = `{"name":"hardyos-notes","services":{"app":{"image":"ghcr.io/x/app:1",
	  "ports":[{"target":80,"published":"8100","protocol":"tcp"}],
	  "volumes":[{"type":"bind","source":"DATA/db","target":"/db"},{"type":"bind","source":"MEDIA","target":"/media"},
	    {"type":"bind","source":"DL","target":"/downloads"}]}}}`
	// Another app whose data was kept: it keeps user ID 30000.
	oldDir := e.dir("old")
	must(t, os.MkdirAll(filepath.Join(oldDir, metaDir), 0o700))
	oldMF := strings.Replace(strings.Replace(engineManifest, `"id":"notes"`, `"id":"old"`, 1), "PERMS", "", 1)
	must(t, os.WriteFile(filepath.Join(oldDir, metaDir, ManifestFile), []byte(oldMF), 0o600))
	must(t, os.WriteFile(filepath.Join(oldDir, metaDir, stateFile), mustJSON(appState{ID: "old", UID: 30000, Removed: true}), 0o600))
	e.listApps("old")
	return e
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (e *testEnv) dir(id string) string { return filepath.Join(e.mnt, id) }

// dataset makes tank/apps/<id> exist.
func (e *testEnv) dataset(id string) {
	ds := "tank/apps/" + id
	e.fake.On("zfs list -H -o name "+ds, ds+"\n")
	e.fake.On("zfs get -Hp -o value mountpoint,mounted "+ds, e.dir(id)+"\nyes\n")
	must(e.t, os.MkdirAll(e.dir(id), 0o755))
}

func (e *testEnv) listApps(ids ...string) {
	out := "tank/apps\n"
	for _, id := range ids {
		out += "tank/apps/" + id + "\n"
	}
	e.fake.On("zfs list -H -o name -d 1 -t filesystem tank/apps", out)
}

// scriptCompose makes `docker compose config` print e.compose for notes.
func (e *testEnv) scriptCompose() {
	data := filepath.Join(e.dir("notes"), dataDirName)
	out := strings.NewReplacer("DATA", data, "MEDIA", filepath.Join(e.shares.root, "media"),
		"DL", filepath.Join(data, unsharedDir, "DOWNLOADS")).Replace(e.compose)
	meta := filepath.Join(e.dir("notes"), metaDir)
	e.fake.On(fmt.Sprintf("docker compose -p hardyos-notes --project-directory %s -f %s --env-file %s config --format json",
		data, filepath.Join(meta, ComposeFile), filepath.Join(meta, envFile)), out)
	e.fake.OnPrefix("docker compose -p hardyos-notes --project-directory "+data+" -f "+filepath.Join(meta, resolvedFile), sysexec.Result{})
}

func enginePackage(t *testing.T, perms string) []byte {
	t.Helper()
	return tarGz(t, map[string]string{
		"hardyapp.json": strings.Replace(engineManifest, "PERMS", perms, 1),
		"compose.yaml":  "services: {}\n",
	}, nil)
}

// install prepares notes for the first time.
func (e *testEnv) install(a PrepareArgs) (*PrepareResult, error) {
	e.t.Helper()
	e.fake.OnResult("zfs list -H -o name tank/apps/notes", sysexec.Result{ExitCode: 1, Stderr: []byte("does not exist")})
	e.fake.On("zfs get -Hp -o value mountpoint,mounted tank/apps/notes", e.dir("notes")+"\nyes\n")
	must(e.t, os.MkdirAll(e.dir("notes"), 0o755))
	e.scriptCompose()
	if a.Package == nil {
		a.Package = enginePackage(e.t, "")
	}
	if a.Host == "" {
		a.Host = "nas.local"
	}
	res, err := e.m.Prepare(context.Background(), a)
	if err == nil {
		e.dataset("notes")
		e.listApps("old", "notes")
	}
	return res, err
}

// shipInCatalog puts a package in the test's catalog folder.
func (e *testEnv) shipInCatalog(pkg []byte) {
	e.t.Helper()
	if e.m.CatalogDir == "" {
		e.m.CatalogDir = e.t.TempDir()
	}
	must(e.t, os.WriteFile(filepath.Join(e.m.CatalogDir, fmt.Sprintf("app%d.hardyapp", len(pkg))), pkg, 0o644))
}

func (e *testEnv) state(id string) appState {
	e.t.Helper()
	var st appState
	b, err := os.ReadFile(filepath.Join(e.dir(id), metaDir, stateFile))
	must(e.t, err)
	must(e.t, json.Unmarshal(b, &st))
	return st
}

func (e *testEnv) env(id string) map[string]string {
	e.t.Helper()
	b, err := os.ReadFile(filepath.Join(e.dir(id), metaDir, envFile))
	must(e.t, err)
	return parseEnv(b)
}

func (e *testEnv) resolvedFile(id string) Resolved {
	e.t.Helper()
	r, err := readResolvedFile(filepath.Join(e.dir(id), metaDir, resolvedFile))
	must(e.t, err)
	return r
}

func problemText(err error) string {
	var p Problems
	if errors.As(err, &p) {
		return strings.Join(p, "\n")
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestInstallWithSharesUIDAndLimits(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	res, err := e.install(PrepareArgs{
		Settings: map[string]string{"ADMIN_PASSWORD": "hunter2"},
		Shares:   map[string]ShareChoice{"MEDIA": {Share: "media"}},
		Limits:   &Limits{MemoryMB: 512, CPUs: 1.5},
		Source:   SourceUpload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Upgrade {
		t.Error("first install reported as an upgrade")
	}
	data := filepath.Join(e.dir("notes"), dataDirName)
	st := e.state("notes")
	// The lowest free ID: 30000 still belongs to the removed app's data.
	if st.UID != 30001 || st.Source != SourceUpload || st.Limits != (Limits{512, 1.5}) {
		t.Errorf("state: %+v", st)
	}
	if ch := st.Shares["MEDIA"]; ch.Share != "media" || ch.Path != "" || ch.Access != "read" || len(st.Shares) != 1 {
		t.Errorf("shares in state: %+v", st.Shares)
	}
	env := e.env("notes")
	if env["HARDY_UID"] != "30001" || env["HARDY_GID"] != "30001" ||
		env["HARDY_SHARE_MEDIA"] != filepath.Join(e.shares.root, "media") ||
		env["HARDY_SHARE_DOWNLOADS"] != filepath.Join(data, ".unshared", "DOWNLOADS") {
		t.Errorf("env: %v", env)
	}
	if fi, err := os.Stat(filepath.Join(data, ".unshared", "DOWNLOADS")); err != nil || !fi.IsDir() {
		t.Errorf("unshared folder: %v", err)
	}
	// Folders without an owner belong to the app's user; explicit owners stay
	// (only root can set owners).
	if os.Geteuid() == 0 {
		if uid := ownerOf(t, filepath.Join(data, "db")); uid != 30001 {
			t.Errorf("db owner %d", uid)
		}
		if uid := ownerOf(t, filepath.Join(data, "cache")); uid != 999 {
			t.Errorf("cache owner %d", uid)
		}
	}
	if g := e.shares.take(); len(g) != 1 || g[0] != "grant media notes 30001 false" {
		t.Errorf("grants: %v", g)
	}
	// The read-only share is mounted read-only; every service is in the slice.
	r := e.resolvedFile("notes")
	svc := r["services"].(map[string]any)["app"].(map[string]any)
	if svc["cgroup_parent"] != "hardyos-app-notes.slice" {
		t.Errorf("cgroup_parent: %v", svc["cgroup_parent"])
	}
	for _, v := range r.bindMounts() {
		ro, _ := v["read_only"].(bool)
		if want := strings.HasSuffix(v["source"].(string), "/media"); ro != want {
			t.Errorf("%v: read_only %v", v["source"], ro)
		}
	}
	if strings.Contains(string(mustRead(t, filepath.Join(e.dir("notes"), metaDir, stateFile))), "hunter2") {
		t.Error("a password went into state.json")
	}

	// Up writes the slice with the limits.
	if err := e.m.Up(ctx, "notes"); err != nil {
		t.Fatal(err)
	}
	slice := string(mustRead(t, filepath.Join(e.root, "run/systemd/system/hardyos-app-notes.slice")))
	if !strings.Contains(slice, "MemoryMax=512M\n") || !strings.Contains(slice, "CPUQuota=150%\n") {
		t.Errorf("slice:\n%s", slice)
	}
	if !hasLine(e.fake.Lines(), "systemctl daemon-reload") {
		t.Error("no daemon-reload after writing the slice")
	}

	// Status shows what the app has.
	o, err := e.m.Status(ctx)
	if err != nil || len(o.Apps) != 1 {
		t.Fatalf("status: %v %+v", err, o)
	}
	a := o.Apps[0]
	if a.Source != SourceUpload || a.UID != 30001 || a.Limits.MemoryMB != 512 || len(a.Grants) != 0 ||
		len(a.Shares) != 2 || a.Shares[0] != (AppShare{Name: "MEDIA", Label: "Media library", Share: "media", Path: "", Access: "read"}) ||
		a.Shares[1].Share != "" || a.Shares[1].Access != "write" || len(a.Permissions) != 2 {
		t.Errorf("app view: %+v", a)
	}
	b, _ := json.Marshal(a)
	for _, k := range []string{`"source":"upload"`, `"sourceName":""`, `"uid":30001`, `"grants":[]`, `"limits":{"memoryMB":512,"cpus":1.5}`, `"permissions":[`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("app JSON lacks %s: %s", k, b)
		}
	}

	// Config never returns secrets.
	cfg, err := e.m.Config(ctx, "notes")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range cfg.Settings {
		switch s.Env {
		case "ADMIN_PASSWORD":
			if s.Value != "" || !s.Set {
				t.Errorf("password setting: %+v", s)
			}
		case "TITLE":
			if s.Value != "Notes" || !s.Set {
				t.Errorf("title: %+v", s)
			}
		case "SECRET":
			t.Error("a generated secret is listed")
		}
	}
	if cfg.UID != 30001 || cfg.Ports["WEB"] != 8100 || cfg.Source != SourceUpload || len(cfg.Shares) != 2 {
		t.Errorf("config: %+v", cfg)
	}

	// Removing revokes the share grants and the slice; the ID stays with the data.
	e.fake.OnPrefix("docker compose -p hardyos-notes", sysexec.Result{})
	if err := e.m.Remove(ctx, RemoveArgs{ID: "notes", Confirm: "Family Notes"}); err != nil {
		t.Fatal(err)
	}
	if g := e.shares.take(); len(g) != 1 || g[0] != "revoke notes" {
		t.Errorf("remove: %v", g)
	}
	if _, err := os.Stat(filepath.Join(e.root, "run/systemd/system/hardyos-app-notes.slice")); !os.IsNotExist(err) {
		t.Error("slice left after remove")
	}
	if st := e.state("notes"); !st.Removed || st.UID != 30001 {
		t.Errorf("after remove: %+v", st)
	}
}

func ownerOf(t *testing.T, p string) int {
	t.Helper()
	fi, err := os.Stat(p)
	must(t, err)
	return statUID(fi)
}

func statUID(fi os.FileInfo) int {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	must(t, err)
	return b
}

func hasLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

func TestInstallRefusals(t *testing.T) {
	cases := map[string]struct {
		perms   string
		args    PrepareArgs
		compose string
		noRes   bool
		want    string
	}{
		"write to a read share": {args: PrepareArgs{Shares: map[string]ShareChoice{"MEDIA": {Share: "media", Access: "write"}}}, want: "may only read"},
		"unknown share":         {args: PrepareArgs{Shares: map[string]ShareChoice{"PHOTOS": {Share: "media"}}}, want: "no shared folder called PHOTOS"},
		"missing share":         {args: PrepareArgs{Shares: map[string]ShareChoice{"MEDIA": {Share: "nope"}}}, want: "no shared folder with that id"},
		"climbing out of share": {args: PrepareArgs{Shares: map[string]ShareChoice{"MEDIA": {Share: "media", Path: "../../etc"}}}, want: "not a subfolder"},
		"share subfolder":       {args: PrepareArgs{Shares: map[string]ShareChoice{"MEDIA": {Share: "media", Path: "Movies"}}}, want: "whole shared folder"},
		"bind in a share": {args: PrepareArgs{Shares: map[string]ShareChoice{"MEDIA": {Share: "media"}}},
			compose: `{"services":{"app":{"image":"x","volumes":[{"type":"bind","source":"MEDIA/Movies","target":"/m"}]}}}`, want: "mount the shared folder itself"},
		"bind in a stand-in": {compose: `{"services":{"app":{"image":"x","volumes":[{"type":"bind","source":"DL/x","target":"/m"}]}}}`,
			want: "${HARDY_SHARE_DOWNLOADS}"},
		"nested data binds": {compose: `{"services":{"app":{"image":"x","volumes":[{"type":"bind","source":"DATA","target":"/all"}]},
			"db":{"image":"y","volumes":[{"type":"bind","source":"DATA/db","target":"/db"}]}}}`, want: "inside "},
		"data root and stand-in": {compose: `{"services":{"app":{"image":"x","volumes":[{"type":"bind","source":"DATA","target":"/all"},{"type":"bind","source":"DL","target":"/dl"}]}}}`,
			want: "a container could replace it"},
		"bad share id": {args: PrepareArgs{Shares: map[string]ShareChoice{"MEDIA": {Share: "Media!"}}}, want: "isn't a shared folder id"},
		"bind outside shares": {args: PrepareArgs{Shares: map[string]ShareChoice{"MEDIA": {Share: "media"}}},
			compose: `{"services":{"app":{"image":"x","volumes":[{"type":"bind","source":"/srv","target":"/srv"}]}}}`, want: "/srv is outside"},
		"host network undeclared": {compose: `{"services":{"app":{"image":"x","network_mode":"host"}}}`, want: "network_mode: host"},
		"untrusted without grants": {perms: `,"permissions":{"hostNetwork":true,"gpu":true,"capabilities":["NET_ADMIN","CHOWN"],"devices":["/dev/net/tun"]}`,
			args: PrepareArgs{Source: SourceImported, SourceName: "Friends"}, want: "host network"},
		"bad grant":        {args: PrepareArgs{Source: SourceUpload, Grants: []string{"cap:SYS_ADMIN"}}, want: "cap:SYS_ADMIN"},
		"bad source":       {args: PrepareArgs{Source: "internet"}, want: "source"},
		"imported no name": {args: PrepareArgs{Source: SourceImported}, want: "catalog's name"},
		"huge limit":       {args: PrepareArgs{Limits: &Limits{MemoryMB: 1 << 20}}, want: "memory limit"},
		"tiny cpu":         {args: PrepareArgs{Limits: &Limits{CPUs: 0.001}}, want: "processor limit"},
		"host network moved port": {perms: `,"permissions":{"hostNetwork":true}`, args: PrepareArgs{Ports: map[string]int{"WEB": 8200}, Grants: []string{"hostNetwork"}},
			want: "fixed at 8100"},
		"no shares here": {noRes: true, perms: "REQ", args: PrepareArgs{Shares: map[string]ShareChoice{"MEDIA": {Share: "media"}}}, want: "aren't available"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newTestEnv(t)
			if c.compose != "" {
				e.compose = c.compose
			}
			if c.noRes {
				e.m.Shares = nil
			}
			perms := c.perms
			if perms == "REQ" {
				perms = ""
				c.args.Package = tarGz(t, map[string]string{
					"hardyapp.json": strings.Replace(strings.Replace(engineManifest, "PERMS", "", 1), `"suggest":"media"`, `"required":true`, 1),
					"compose.yaml":  "services: {}\n",
				}, nil)
			} else {
				c.args.Package = enginePackage(t, perms)
			}
			_, err := e.install(c.args)
			if err == nil || !strings.Contains(problemText(err), c.want) {
				t.Fatalf("got %v, want a problem mentioning %q", err, c.want)
			}
		})
	}
}

func TestRequiredShareAndGrants(t *testing.T) {
	// A required share must be chosen.
	e := newTestEnv(t)
	req := tarGz(t, map[string]string{
		"hardyapp.json": strings.Replace(strings.Replace(engineManifest, "PERMS", "", 1), `"suggest":"media"`, `"required":true`, 1),
		"compose.yaml":  "services: {}\n",
	}, nil)
	if _, err := e.install(PrepareArgs{Package: req}); !strings.Contains(problemText(err), "choose a shared folder") {
		t.Errorf("required share: %v", err)
	}

	// An untrusted app gets exactly what was granted (basic capabilities need nothing).
	perms := `,"permissions":{"hostNetwork":true,"capabilities":["NET_ADMIN","CHOWN"]}`
	e = newTestEnv(t)
	e.compose = `{"services":{"app":{"image":"x","network_mode":"host","cap_add":["NET_ADMIN","CHOWN"]}}}`
	_, err := e.install(PrepareArgs{Package: enginePackage(t, perms), Source: SourceUpload, Grants: []string{"hostNetwork"}})
	if t2 := problemText(err); !strings.Contains(t2, "NET_ADMIN") || strings.Contains(t2, "CHOWN") || strings.Contains(t2, "(host network)") ||
		!strings.Contains(t2, "server's own network settings") {
		t.Errorf("partial grants: %v", err)
	}
	if _, err := e.install(PrepareArgs{Package: enginePackage(t, perms), Source: SourceUpload,
		Grants: []string{"hostNetwork", "cap:NET_ADMIN", "gpu"}}); err != nil {
		t.Fatal(err)
	}
	if st := e.state("notes"); strings.Join(st.Grants, ",") != "cap:NET_ADMIN,hostNetwork" {
		t.Errorf("stored grants: %v", st.Grants)
	}
	o, _ := e.m.Status(context.Background())
	if a := o.Apps[0]; len(a.Grants) != 2 || !strings.Contains(strings.Join(a.Permissions, "\n"), "host network") {
		t.Errorf("view: %+v", a)
	}

	// A catalog app with the same permissions needs no grants: hardyd-priv
	// finds its bytes in the shipped catalog, whatever hardyd says.
	e = newTestEnv(t)
	e.compose = `{"services":{"app":{"image":"x","network_mode":"host","cap_add":["NET_ADMIN"]}}}`
	pkg := enginePackage(t, perms)
	e.shipInCatalog(pkg)
	if _, err := e.install(PrepareArgs{Package: pkg}); err != nil {
		t.Fatal(err)
	}
	if st := e.state("notes"); len(st.Grants) != 0 || st.Source != SourceCatalog || st.CatalogSHA256 != packageSum(pkg) {
		t.Errorf("catalog state: %+v", st)
	}
}

func TestReconfigure(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.install(PrepareArgs{Settings: map[string]string{"ADMIN_PASSWORD": "hunter2", "TITLE": "Ours"},
		Shares: map[string]ShareChoice{"MEDIA": {Share: "media"}}, Source: SourceUpload}); err != nil {
		t.Fatal(err)
	}
	e.shares.take()
	secret := e.env("notes")["SECRET"]

	// Only the limits: everything else stays, no grants touched.
	res, err := e.m.Reconfigure(ctx, ReconfigureArgs{ID: "notes", Limits: &Limits{MemoryMB: 256},
		Settings: map[string]string{"ADMIN_PASSWORD": ""}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Upgrade {
		t.Error("reconfigure isn't an upgrade of the installed app")
	}
	env := e.env("notes")
	if env["ADMIN_PASSWORD"] != "hunter2" || env["TITLE"] != "Ours" || env["SECRET"] != secret {
		t.Errorf("env after reconfigure: %v", env)
	}
	st := e.state("notes")
	if st.Limits.MemoryMB != 256 || st.Shares["MEDIA"].Share != "media" || st.Source != SourceUpload || st.UID != 30001 {
		t.Errorf("state after reconfigure: %+v", st)
	}
	if g := e.shares.take(); len(g) != 0 {
		t.Errorf("unchanged shares were granted again: %v", g)
	}

	// Changing a share revokes the old grants and gives the new ones.
	e.compose = `{"services":{"app":{"image":"x","volumes":[{"type":"bind","source":"DATA/db","target":"/db"}]}}}`
	e.scriptCompose()
	if _, err := e.m.Reconfigure(ctx, ReconfigureArgs{ID: "notes", Shares: map[string]ShareChoice{
		"MEDIA": {Share: ""}, "DOWNLOADS": {Share: "downloads"}}}); err != nil {
		t.Fatal(err)
	}
	if g := e.shares.take(); strings.Join(g, ";") != "revoke notes;grant downloads notes 30001 true" {
		t.Errorf("grants after a share change: %v", g)
	}
	if env := e.env("notes"); env["HARDY_SHARE_DOWNLOADS"] != filepath.Join(e.shares.root, "downloads") ||
		!strings.HasSuffix(env["HARDY_SHARE_MEDIA"], "/.unshared/MEDIA") {
		t.Errorf("env after share change: %v", env)
	}
	if _, err := e.m.Reconfigure(ctx, ReconfigureArgs{ID: "nope"}); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("reconfigure of an app that isn't installed: %v", err)
	}
}

func TestStartRechecksShares(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.install(PrepareArgs{Shares: map[string]ShareChoice{"MEDIA": {Share: "media"}}}); err != nil {
		t.Fatal(err)
	}
	if err := e.m.Up(ctx, "notes"); err != nil {
		t.Fatal(err)
	}
	// The share now resolves elsewhere (moved to another pool): the old
	// mount isn't covered, so the app doesn't start.
	must(t, os.MkdirAll(filepath.Join(e.shares.root, "media2", "Movies"), 0o755))
	e.m.Shares = &movedShares{fakeShares: e.shares}
	if err := e.m.Up(ctx, "notes"); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Errorf("start after the share moved: %v", err)
	}
	// Someone made the read-only mount writable in the resolved file.
	e.m.Shares = e.shares
	path := filepath.Join(e.dir("notes"), metaDir, resolvedFile)
	b := strings.ReplaceAll(string(mustRead(t, path)), `"read_only": true`, `"read_only": false`)
	must(t, os.WriteFile(path, []byte(b), 0o600))
	if err := e.m.Up(ctx, "notes"); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("start with a writable read share: %v", err)
	}
	// Without shared folders at all, an app that has one doesn't start.
	e.m.Shares = nil
	if err := e.m.Up(ctx, "notes"); err == nil || !strings.Contains(err.Error(), "aren't available") {
		t.Errorf("start without shares: %v", err)
	}
}

type movedShares struct{ *fakeShares }

func (s *movedShares) Resolve(ctx context.Context, share, sub string) (string, error) {
	return s.fakeShares.Resolve(ctx, share+"2", sub)
}

func TestSnapshotsAndRollback(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.install(PrepareArgs{Shares: map[string]ShareChoice{"MEDIA": {Share: "media"}}}); err != nil {
		t.Fatal(err)
	}
	ds := "tank/apps/notes"
	e.fake.OnPrefix("zfs snapshot ", sysexec.Result{})
	e.fake.OnPrefix("zfs destroy "+ds+"@", sysexec.Result{})
	e.fake.On("zfs list -H -p -t snapshot -o name,creation,org.hardyos:app-version -s creation -d 1 "+ds, strings.Join([]string{
		ds + "@hardyos-update-20260101-000000\t1767225600\t0.9.0",
		ds + "@auto-daily\t1767312000\t-",
		ds + "@hardyos-update-20260201-000000\t1769904000\t0.9.5",
		ds + "@hardyos-update-20260301-000000\t1772323200\t1.0.0",
		ds + "@hardyos-update-20261026-120000\t1793016000\t1.0.0",
	}, "\n")+"\n")

	if _, err := e.m.Snapshot(ctx, SnapshotArgs{ID: "notes", Reason: "whim"}); err == nil {
		t.Error("snapshot with a made-up reason")
	}
	name, err := e.m.Snapshot(ctx, SnapshotArgs{ID: "notes", Reason: "update"})
	if err != nil || name != "hardyos-update-20261026-120000" {
		t.Fatalf("snapshot: %q %v", name, err)
	}
	lines := e.fake.Lines()
	if !hasLine(lines, "zfs snapshot -o org.hardyos:app-version=1.0.0 "+ds+"@"+name) {
		t.Errorf("snapshot command missing: %v", lines)
	}
	// Only the oldest update snapshot beyond three goes; others' snapshots stay.
	var destroyed []string
	for _, l := range lines {
		if strings.HasPrefix(l, "zfs destroy") {
			destroyed = append(destroyed, l)
		}
	}
	if len(destroyed) != 1 || destroyed[0] != "zfs destroy "+ds+"@hardyos-update-20260101-000000" {
		t.Errorf("pruned: %v", destroyed)
	}
	if _, err := os.Stat(filepath.Join(e.dir("notes"), metaDir, imagesFile)); err != nil {
		t.Errorf("images not recorded: %v", err)
	}

	snaps, err := e.m.Snapshots(ctx, "notes")
	if err != nil || len(snaps) != 5 || snaps[0].Name != name || snaps[0].Version != "1.0.0" || snaps[3].Version != "" ||
		!snaps[0].Created.Equal(time.Unix(1793016000, 0)) {
		t.Fatalf("snapshots: %v %+v", err, snaps)
	}

	if err := e.m.Rollback(ctx, RollbackArgs{ID: "notes", Snapshot: snaps[1].Name, Confirm: "wrong"}); err == nil {
		t.Error("rollback without the name")
	}
	if err := e.m.Rollback(ctx, RollbackArgs{ID: "notes", Snapshot: "hardyos-update-nope", Confirm: "Family Notes"}); err == nil {
		t.Error("rollback to a snapshot that doesn't exist")
	}
	e.fake.OnPrefix("zfs rollback ", sysexec.Result{})
	before := len(e.fake.Lines())
	if err := e.m.Rollback(ctx, RollbackArgs{ID: "notes", Snapshot: "hardyos-update-20260301-000000", Confirm: "family notes"}); err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, l := range e.fake.Lines()[before:] {
		switch {
		case strings.HasSuffix(l, " stop"):
			order = append(order, "stop")
		case strings.HasPrefix(l, "zfs rollback -r "+ds+"@hardyos-update-20260301-000000"):
			order = append(order, "rollback")
		case strings.HasSuffix(l, "up -d --remove-orphans"):
			order = append(order, "up")
		}
	}
	if strings.Join(order, ",") != "stop,rollback,up" {
		t.Errorf("rollback steps: %v", order)
	}
}

func TestPolicyPermissionsV2(t *testing.T) {
	m := testMF(t, `"permissions":{"hostNetwork":true,"gpu":true},`)
	plain := testMF(t, "")
	ok := map[string]string{
		"host network": `"network_mode":"host"`,
		"dri":          `"devices":[{"source":"/dev/dri","target":"/dev/dri"},"/dev/dri/renderD128:/dev/dri/renderD128"]`,
		"nvidia":       `"deploy":{"resources":{"reservations":{"devices":[{"driver":"nvidia","count":"all","capabilities":["gpu","video"]}]}}}`,
	}
	for name, svc := range ok {
		if err := resolved(t, svc, "").Check(m, "hardyos-notes", dataDir, ports); err != nil {
			t.Errorf("%s with the permission: %v", name, err)
		}
		if err := resolved(t, svc, "").Check(plain, "hardyos-notes", dataDir, ports); err == nil {
			t.Errorf("%s without the permission was allowed", name)
		}
	}
	for name, c := range map[string]struct{ svc, want string }{
		"amd reservation": {`"deploy":{"resources":{"reservations":{"devices":[{"driver":"amd","capabilities":["gpu"]}]}}}`, "NVIDIA"},
		"no gpu cap":      {`"deploy":{"resources":{"reservations":{"devices":[{"driver":"nvidia","capabilities":["compute"]}]}}}`, "capabilities [gpu]"},
		"options":         {`"deploy":{"resources":{"reservations":{"devices":[{"driver":"nvidia","capabilities":["gpu"],"options":{"x":"y"}}]}}}`, "options"},
		"other device":    {`"devices":["/dev/sda:/dev/sda"]`, "/dev/sda"},
		"cgroup_parent":   {`"cgroup_parent":"system.slice"`, "cgroup options"},
		"host pid":        {`"pid":"host"`, "pid: host"},
	} {
		err := resolved(t, c.svc, "").Check(m, "hardyos-notes", dataDir, ports)
		if !strings.Contains(problemText(err), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}

	// Binds of shares: write grants as they are, read grants made read-only.
	shares := []shareBind{{Name: "MEDIA", Path: "/mnt/tank/shares/media", Write: false},
		{Name: "DL", Path: "/mnt/tank/shares/downloads", Write: true}}
	r := resolved(t, `"volumes":[{"type":"bind","source":"/mnt/tank/shares/media","target":"/media"},
		{"type":"bind","source":"/mnt/tank/shares/downloads/","target":"/dl"}]`, "")
	if err := r.check(plain, "hardyos-notes", dataDir, ports, shares); err != nil {
		t.Fatal(err)
	}
	bm := r.bindMounts()
	if bm[0]["read_only"] != true || bm[1]["read_only"] != nil {
		t.Errorf("read-only forcing: %v", bm)
	}
	// Only the share itself: a folder in it could be swapped for a link by
	// anything else that writes in the share.
	r = resolved(t, `"volumes":[{"type":"bind","source":"/mnt/tank/shares/media/TV","target":"/tv"}]`, "")
	if err := r.check(plain, "hardyos-notes", dataDir, ports, shares); !strings.Contains(problemText(err), "${HARDY_SHARE_MEDIA}") {
		t.Errorf("a folder in a share: %v", err)
	}
	r = resolved(t, `"volumes":[{"type":"bind","source":"/mnt/tank/shares/mediax","target":"/x"}]`, "")
	if err := r.check(plain, "hardyos-notes", dataDir, ports, shares); err == nil {
		t.Error("a sibling of a share was allowed")
	}
}

func TestAdaptGPU(t *testing.T) {
	svc := `"devices":["/dev/dri:/dev/dri"],"deploy":{"resources":{"reservations":{"devices":[{"driver":"nvidia","capabilities":["gpu"]}]}}}`
	root := t.TempDir()
	sys := func(p string) string { return filepath.Join(root, p) }

	// No GPU at all: both go, with warnings, and the install goes on.
	r := resolved(t, svc, "")
	warn := r.adaptGPU(gpuHardware{}, sys, "Notes")
	app := r["services"].(map[string]any)["app"].(map[string]any)
	if _, ok := app["devices"]; ok || app["deploy"] != nil || len(warn) != 2 {
		t.Errorf("without a GPU: %v %v", app, warn)
	}

	// A render node: the device stays and the service joins its group.
	must(t, os.MkdirAll(filepath.Join(root, "dev/dri"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "dev/dri/renderD128"), nil, 0o660))
	if os.Geteuid() == 0 {
		must(t, os.Chown(filepath.Join(root, "dev/dri/renderD128"), 0, 993))
	}
	r = resolved(t, svc, "")
	m := &Manager{Root: root}
	hw := m.detectGPU()
	if !hw.DRI || hw.NVIDIA {
		t.Fatalf("detected: %+v", hw)
	}
	warn = r.adaptGPU(hw, sys, "Notes")
	app = r["services"].(map[string]any)["app"].(map[string]any)
	if len(anyList(app["devices"])) != 1 || len(warn) != 1 || !strings.Contains(warn[0], "NVIDIA") {
		t.Errorf("with a render node: %v %v", app, warn)
	}
	if os.Geteuid() == 0 && fmt.Sprint(app["group_add"]) != "[993]" {
		t.Errorf("group_add: %v", app["group_add"])
	}

	// An NVIDIA card without the toolkit is reported as such.
	must(t, os.WriteFile(filepath.Join(root, "dev/nvidia0"), nil, 0o666))
	if hw := m.detectGPU(); hw.NVIDIA || !hw.NVIDIANoToolkit {
		t.Errorf("card without toolkit: %+v", hw)
	}
	must(t, os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "usr/bin/nvidia-ctk"), nil, 0o755))
	r = resolved(t, svc, "")
	if warn := r.adaptGPU(m.detectGPU(), sys, "Notes"); len(warn) != 0 {
		t.Errorf("with everything: %v", warn)
	}
}

func TestManifestSharesAndDescribe(t *testing.T) {
	base := strings.Replace(engineManifest, "PERMS", `,"permissions":{"hostNetwork":true,"gpu":true}`, 1)
	var m Manifest
	must(t, json.Unmarshal([]byte(base), &m))
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	d := strings.Join(DescribePermissions(m), "\n")
	for _, want := range []string{"host network", "GPU", `Read files in the shared folder you choose for "Media library" (optional)`,
		`Read and change files in the shared folder you choose for "Downloads"`} {
		if !strings.Contains(d, want) {
			t.Errorf("describe lacks %q:\n%s", want, d)
		}
	}
	for name, c := range map[string]struct{ from, to, want string }{
		"lower name":  {`"name":"MEDIA"`, `"name":"media"`, "share name"},
		"dup":         {`"name":"DOWNLOADS"`, `"name":"MEDIA"`, "twice"},
		"no label":    {`"label":"Media library"`, `"label":""`, "label"},
		"bad access":  {`"access":"read"`, `"access":"all"`, "access"},
		"bad suggest": {`"suggest":"media"`, `"suggest":"Media Folder"`, "suggest"},
	} {
		var mm Manifest
		must(t, json.Unmarshal([]byte(strings.Replace(base, c.from, c.to, 1)), &mm))
		if err := mm.Validate(); !strings.Contains(problemText(err), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Host-network apps may use ports below 1024; others may not.
	low := strings.Replace(base, `"default":8100`, `"default":53`, 1)
	var hn, plain Manifest
	must(t, json.Unmarshal([]byte(low), &hn))
	if err := hn.Validate(); err != nil {
		t.Errorf("host network on port 53: %v", err)
	}
	must(t, json.Unmarshal([]byte(strings.Replace(low, `"hostNetwork":true`, `"hostNetwork":false`, 1)), &plain))
	if err := plain.Validate(); err == nil {
		t.Error("port 53 without host network")
	}
}

func TestSlices(t *testing.T) {
	if got := SliceName("apex-rmm"); got != `hardyos-app-apex\x2drmm.slice` {
		t.Errorf("slice name: %s", got)
	}
	u := string(sliceUnit("notes", Limits{}))
	if !strings.Contains(u, "MemoryMax=infinity\n") || !strings.Contains(u, "CPUQuota=\n") {
		t.Errorf("unlimited slice:\n%s", u)
	}
	// Written only when it changes.
	f := &sysexec.Fake{}
	f.OnPrefix("systemctl", sysexec.Result{})
	m := &Manager{Runner: f, Root: t.TempDir()}
	for i := 0; i < 2; i++ {
		must(t, m.writeSlice(context.Background(), "notes", Limits{CPUs: 2}))
	}
	if n := len(f.Lines()); n != 1 {
		t.Errorf("daemon-reloads: %d", n)
	}
}

func TestSuggestFixedPorts(t *testing.T) {
	f := &sysexec.Fake{}
	f.On("ss -Hlntu", "tcp LISTEN 0 4096 0.0.0.0:53 0.0.0.0:*\n")
	m := &Manager{Runner: f, Root: t.TempDir()}
	got, err := m.SuggestPorts(context.Background(), []PortCheck{{Name: "DNS", Default: 53, Fixed: true}, {Name: "WEB", Default: 8100}}, "")
	if err != nil || got["DNS"] != 53 || got["WEB"] != 8100 {
		t.Errorf("suggest: %v %v", got, err)
	}
}

func TestAllocUIDSkipsTaken(t *testing.T) {
	e := newTestEnv(t)
	// Fill 30000-30002 with kept apps.
	ids := []string{"old"}
	for i, id := range []string{"aa", "bb"} {
		e.dataset(id)
		must(t, os.MkdirAll(filepath.Join(e.dir(id), metaDir), 0o700))
		mf := strings.Replace(strings.Replace(engineManifest, `"id":"notes"`, `"id":"`+id+`"`, 1), "PERMS", "", 1)
		must(t, os.WriteFile(filepath.Join(e.dir(id), metaDir, ManifestFile), []byte(mf), 0o600))
		must(t, os.WriteFile(filepath.Join(e.dir(id), metaDir, stateFile), mustJSON(appState{ID: id, UID: 30001 + i}), 0o600))
		ids = append(ids, id)
	}
	sort.Strings(ids)
	e.listApps(ids...)
	if _, err := e.install(PrepareArgs{Shares: map[string]ShareChoice{"MEDIA": {Share: "media"}}}); err != nil {
		t.Fatal(err)
	}
	if uid := e.state("notes").UID; uid != 30003 {
		t.Errorf("uid %d", uid)
	}
}
