package apps

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// The Immich package Photos sets up (docs/photos.md): every image pinned
// by digest, its own user everywhere, existing photos and the family
// folder read-only, and the accelerated machine learning services off
// (and not downloaded) until Photos turns one on.

func immichDir() string { return filepath.Join("..", "..", "..", "apps", "catalog", "immich") }

func immichPackage(t *testing.T) *Package {
	t.Helper()
	files := map[string]string{}
	for _, n := range []string{ManifestFile, ComposeFile, "icon.svg"} {
		b, err := os.ReadFile(filepath.Join(immichDir(), n))
		if err != nil {
			t.Fatal(err)
		}
		files[n] = string(b)
	}
	pkg, err := ReadPackage(tarGz(t, files, nil))
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}

func TestImmichManifest(t *testing.T) {
	mf := immichPackage(t).Manifest
	if mf.ID != "immich" || !contains(mf.Arch, "amd64") || !contains(mf.Arch, "arm64") || !mf.Permissions.GPU || mf.Permissions.HostNetwork {
		t.Fatalf("manifest %+v", mf)
	}
	managed := 0
	for _, s := range mf.Settings {
		if s.Managed {
			managed++
			if !s.Hidden() || s.Default != "0" || strings.Join(s.Options, ",") != "0,1" {
				t.Errorf("managed setting %+v", s)
			}
		}
	}
	if managed != 3 {
		t.Fatalf("%d managed settings", managed)
	}
	want := map[string]string{"PHOTOS": "write", "EXISTING": "read", "EXISTING_2": "read", "EXISTING_3": "read", "FAMILY": "read"}
	for _, s := range mf.Shares {
		if want[s.Name] != s.Access {
			t.Errorf("share %s is %s", s.Name, s.Access)
		}
		delete(want, s.Name)
	}
	if len(want) != 0 {
		t.Errorf("missing shares %v", want)
	}
}

func TestManagedSettingRules(t *testing.T) {
	base := `{"format":1,"id":"abc","name":"X","version":"1","summary":"x","icon":"icon.svg","ports":[],"settings":[SETTING]}`
	for name, s := range map[string]string{
		"managed password": `{"env":"A","label":"A","type":"password","managed":true}`,
		"managed secret":   `{"env":"A","generate":"secret","managed":true}`,
	} {
		files := map[string]string{ManifestFile: strings.Replace(base, "SETTING", s, 1), ComposeFile: "services: {}\n", "icon.svg": "<svg/>"}
		if _, err := ReadPackage(tarGz(t, files, nil)); err == nil || !strings.Contains(err.Error(), "managed") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// rocm is its own permission: gpu alone doesn't allow /dev/kfd.
func TestROCmPermission(t *testing.T) {
	svc := `"devices":["/dev/kfd:/dev/kfd","/dev/dri:/dev/dri"]`
	r := resolved(t, svc, "")
	err := r.Check(testMF(t, `"permissions":{"gpu":true},`), "hardyos-notes", dataDir, ports)
	if err == nil || !strings.Contains(problemText(err), "/dev/kfd") {
		t.Fatalf("gpu alone allowed /dev/kfd: %v", err)
	}
	if err := r.Check(testMF(t, `"permissions":{"gpu":true,"rocm":true},`), "hardyos-notes", dataDir, ports); err != nil && strings.Contains(problemText(err), "/dev/") {
		t.Fatalf("gpu+rocm refused: %v", err)
	}
	mf := Manifest{Permissions: Permissions{ROCm: true}}
	if g := neededGrants(mf); !contains(g, GrantROCm) || !validGrant(GrantROCm) {
		t.Fatalf("grants %v", g)
	}
	base := `{"format":1,"id":"abc","name":"X","version":"1","summary":"x","icon":"icon.svg","ports":[],"permissions":{"rocm":true}}`
	if _, err := ReadPackage(tarGz(t, map[string]string{ManifestFile: base, ComposeFile: "services: {}\n", "icon.svg": "<svg/>"}, nil)); err == nil || !strings.Contains(err.Error(), "rocm") {
		t.Fatalf("rocm without gpu: %v", err)
	}
}

func TestBackupDumpRules(t *testing.T) {
	base := `{"format":1,"id":"abc","name":"X","version":"1","summary":"x","icon":"icon.svg","ports":[],"backup":{"dump":DUMP}}`
	for name, d := range map[string]string{
		"no service":  `{"command":["pg_dump"]}`,
		"no command":  `{"service":"db","command":[]}`,
		"line break":  `{"service":"db","command":["a\nb"]}`,
		"bad timeout": `{"service":"db","command":["x"],"timeoutSeconds":5}`,
	} {
		files := map[string]string{ManifestFile: strings.Replace(base, "DUMP", d, 1), ComposeFile: "services: {}\n", "icon.svg": "<svg/>"}
		if _, err := ReadPackage(tarGz(t, files, nil)); err == nil || !strings.Contains(err.Error(), "backup.dump") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// PreBackup execs the manifest's argv in the running service as the
// app's user, and does nothing while the service isn't running.
func TestPreBackup(t *testing.T) {
	e := newTestEnv(t)
	mf := strings.Replace(strings.Replace(engineManifest, "PERMS", "", 1), `"folders":`,
		`"backup":{"dump":{"service":"app","command":["pg_dump","--file=/db/x.dump"]}},"folders":`, 1)
	pkg := tarGz(t, map[string]string{"hardyapp.json": mf, "compose.yaml": "services: {}\n"}, nil)
	if _, err := e.install(PrepareArgs{Package: pkg, Settings: map[string]string{"ADMIN_PASSWORD": "pw"},
		Shares: map[string]ShareChoice{"MEDIA": {Share: "media"}}, Source: SourceUpload}); err != nil {
		t.Fatal(problemText(err))
	}
	data := filepath.Join(e.dir("notes"), dataDirName)
	pre := "docker compose -p hardyos-notes --project-directory " + data + " -f " + filepath.Join(e.dir("notes"), metaDir, resolvedFile)
	ctx := context.Background()
	if ran, err := e.m.PreBackup(ctx, "notes"); ran || err != nil {
		t.Fatalf("stopped app: %v %v", ran, err)
	}
	e.fake.On(pre+" ps --status running --services", "app\n")
	ran, err := e.m.PreBackup(ctx, "notes")
	if !ran || err != nil {
		t.Fatalf("running app: %v %v", ran, err)
	}
	want := pre + " exec -T --user 30001:30001 app pg_dump --file=/db/x.dump"
	if !contains(e.fake.Lines(), want) {
		t.Fatalf("no %q in %v", want, e.fake.Lines())
	}
	e.fake.OnResult(want, sysexec.Result{ExitCode: 1, Stderr: []byte("boom")})
	if _, err := e.m.PreBackup(ctx, "notes"); err == nil {
		t.Fatal("a failing dump reported success")
	}
}

// resolveImmich runs `docker compose config` on the package as HardyOS
// would, with these setting values.
func resolveImmich(t *testing.T, settings map[string]string) Resolved {
	t.Helper()
	if exec.Command("docker", "compose", "version").Run() != nil {
		t.Skip("docker compose isn't installed")
	}
	mf := immichPackage(t).Manifest
	tmp := t.TempDir()
	data := filepath.Join(tmp, "data")
	must(t, os.MkdirAll(data, 0o755))
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + tmp, "HARDY_APP_ID=immich", "HARDY_APP_DATA=" + data, "HARDY_HOST=nas.local",
		"HARDY_TZ=UTC", "HARDY_UID=30001", "HARDY_GID=30001", "HARDY_PORT_WEB=2283"}
	for _, s := range mf.Shares {
		p := filepath.Join(tmp, "share-"+s.Name)
		must(t, os.MkdirAll(p, 0o755))
		env = append(env, ShareEnv(s.Name)+"="+p)
	}
	for _, s := range mf.Settings {
		v := s.Default
		if x, ok := settings[s.Env]; ok {
			v = x
		}
		if v == "" {
			v = "x"
		}
		env = append(env, s.Env+"="+v)
	}
	cmd := exec.Command("docker", "compose", "-p", "hardyos-immich", "-f", filepath.Join(immichDir(), ComposeFile), "config", "--format", "json")
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("compose config: %v", err)
	}
	r, err := ParseResolved(out)
	must(t, err)
	return r
}

func TestImmichCompose(t *testing.T) {
	r := resolveImmich(t, nil)
	services, _ := r["services"].(map[string]any)
	idle := map[string]bool{}
	for _, s := range r.Services() {
		if !strings.Contains(s.Image, "@sha256:") {
			t.Errorf("%s isn't pinned by digest: %s", s.Service, s.Image)
		}
		idle[s.Service] = s.Idle
	}
	for _, sv := range []string{"immich-machine-learning-cuda", "immich-machine-learning-openvino", "immich-machine-learning-rocm"} {
		svc, _ := services[sv].(map[string]any)
		if !idle[sv] || svc["pull_policy"] != "never" {
			t.Errorf("%s: idle=%v pull_policy=%v", sv, idle[sv], svc["pull_policy"])
		}
	}
	for _, sv := range []string{"immich-server", "immich-machine-learning", "database", "redis"} {
		if idle[sv] {
			t.Errorf("%s is idle", sv)
		}
	}
	for name, raw := range services {
		svc, _ := raw.(map[string]any)
		if svc["user"] != "30001:30001" {
			t.Errorf("%s runs as %v", name, svc["user"])
		}
		if svc["privileged"] == true || svc["network_mode"] != nil {
			t.Errorf("%s: privileged or another network", name)
		}
	}
	// Existing photos and the family folder are mounted read-only.
	srv, _ := services["immich-server"].(map[string]any)
	// Immich is reached only through HardyOS's proxies (docs/photos.md).
	for _, raw := range anyList(srv["ports"]) {
		if pm, _ := raw.(map[string]any); pm["host_ip"] != "127.0.0.1" {
			t.Errorf("immich-server publishes %v beyond 127.0.0.1", pm)
		}
	}
	ro := map[string]bool{}
	for _, v := range anyList(srv["volumes"]) {
		m, _ := v.(map[string]any)
		target, _ := m["target"].(string)
		r, _ := m["read_only"].(bool)
		ro[target] = r
	}
	for target, want := range map[string]bool{"/data": false, "/mnt/existing": true, "/mnt/existing-2": true, "/mnt/existing-3": true, "/mnt/family": true} {
		if got, ok := ro[target]; !ok || got != want {
			t.Errorf("%s: read-only %v (mounted %v), want %v", target, got, ok, want)
		}
	}

	// Photos turning NVIDIA on: that service runs (and is downloaded).
	r = resolveImmich(t, map[string]string{"ML_CUDA_REPLICAS": "1"})
	for _, s := range r.Services() {
		if s.Service == "immich-machine-learning-cuda" && s.Idle {
			t.Error("cuda still idle with 1 replica")
		}
	}

	// Without a GPU, the devices go with a warning; /dev/kfd's says ROCm.
	root := t.TempDir()
	warn := r.adaptGPU(gpuHardware{}, func(p string) string { return filepath.Join(root, p) }, "Immich")
	if !strings.Contains(strings.Join(warn, "\n"), "ROCm") {
		t.Errorf("warnings %v", warn)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "/dev/kfd") || strings.Contains(string(b), "/dev/dri") || strings.Contains(string(b), `"nvidia"`) {
		t.Errorf("GPU devices left on a server without one: %s", b)
	}
}

// A managed value the new package no longer offers falls back to its
// default on an update instead of failing it.
func TestManagedValueFallsBack(t *testing.T) {
	e := newTestEnv(t)
	mf := strings.Replace(strings.Replace(engineManifest, "PERMS", "", 1),
		`{"env":"TITLE","label":"Title","default":"Notes"}`,
		`{"env":"TITLE","label":"Title","default":"Notes"},{"env":"ACCEL","label":"Accel","type":"select","options":["0","1"],"default":"0","managed":true}`, 1)
	pkg := tarGz(t, map[string]string{"hardyapp.json": mf, "compose.yaml": "services: {}\n"}, nil)
	if _, err := e.install(PrepareArgs{Package: pkg, Settings: map[string]string{"ADMIN_PASSWORD": "pw", "ACCEL": "1"},
		Shares: map[string]ShareChoice{"MEDIA": {Share: "media"}}, Source: SourceUpload}); err != nil {
		t.Fatal(problemText(err))
	}
	if e.env("notes")["ACCEL"] != "1" {
		t.Fatalf("env %v", e.env("notes"))
	}
	// An older value that isn't an option any more (as if the options changed).
	envPath := filepath.Join(e.dir("notes"), metaDir, envFile)
	env := e.env("notes")
	env["ACCEL"] = "2"
	must(t, os.WriteFile(envPath, renderEnv(env), 0o600))
	if _, err := e.m.Reconfigure(context.Background(), ReconfigureArgs{ID: "notes"}); err != nil {
		t.Fatalf("update with a stale managed value: %s", problemText(err))
	}
	if e.env("notes")["ACCEL"] != "0" {
		t.Fatalf("env after update %v", e.env("notes"))
	}
	// Config (the settings screen) leaves managed settings out.
	cfg, err := e.m.Config(context.Background(), "notes")
	must(t, err)
	for _, s := range cfg.Settings {
		if s.Env == "ACCEL" {
			t.Fatal("managed setting on the settings screen")
		}
	}
}
