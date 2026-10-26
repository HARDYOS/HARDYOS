package apps

import (
	"context"

	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// zfsSim stands in for ZFS (datasets are plain folders, snapshots are
// copies) and systemctl, and passes every other command to the real
// system. With it, the integration test runs real Docker Compose against
// real packages on any machine with Docker.
type zfsSim struct {
	base  string
	mu    sync.Mutex
	ds    map[string]bool
	snaps []simSnap
	real  sysexec.Runner
}

type simSnap struct {
	full    string // ds@name
	created int64
	version string
}

func (z *zfsSim) mountpoint(ds string) string {
	pool, rest, _ := strings.Cut(ds, "/")
	return filepath.Join(z.base, "mnt", pool, rest)
}

func (z *zfsSim) snapDir(full string) string {
	return filepath.Join(z.base, "snap", strings.ReplaceAll(full, "/", "_"))
}

// copyTree copies a folder with owners and modes (cp -a).
func copyTree(ctx context.Context, src, dst string) error {
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	_, err := sysexec.Output(ctx, sysexec.Exec{}, "cp", "-a", src, dst)
	return err
}

func (z *zfsSim) Run(ctx context.Context, stdin []byte, name string, args ...string) (sysexec.Result, error) {
	switch name {
	case "systemctl":
		return sysexec.Result{}, nil
	case "zfs":
	default:
		return z.real.Run(ctx, stdin, name, args...)
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	last := args[len(args)-1]
	fail := func(msg string) (sysexec.Result, error) {
		return sysexec.Result{ExitCode: 1, Stderr: []byte(msg)}, nil
	}
	line := strings.Join(args, " ")
	switch args[0] {
	case "list":
		if strings.Contains(line, "-t snapshot") {
			var out []string
			for _, s := range z.snaps {
				if strings.HasPrefix(s.full, last+"@") {
					v := s.version
					if v == "" {
						v = "-"
					}
					out = append(out, fmt.Sprintf("%s\t%d\t%s", s.full, s.created, v))
				}
			}
			return sysexec.Result{Stdout: []byte(strings.Join(out, "\n") + "\n")}, nil
		}
		if strings.Contains(line, "-d 1") {
			var out []string
			for d := range z.ds {
				if d == last || strings.HasPrefix(d, last+"/") && !strings.Contains(strings.TrimPrefix(d, last+"/"), "/") {
					out = append(out, d)
				}
			}
			return sysexec.Result{Stdout: []byte(strings.Join(out, "\n") + "\n")}, nil
		}
		if !z.ds[last] {
			return fail("dataset does not exist")
		}
		return sysexec.Result{Stdout: []byte(last + "\n")}, nil
	case "create":
		z.ds[last] = true
		return sysexec.Result{}, os.MkdirAll(z.mountpoint(last), 0o755)
	case "get":
		if !z.ds[last] {
			return fail("dataset does not exist")
		}
		return sysexec.Result{Stdout: []byte(z.mountpoint(last) + "\nyes\n")}, nil
	case "snapshot":
		ds, _, _ := strings.Cut(last, "@")
		if !z.ds[ds] {
			return fail("dataset does not exist")
		}
		for _, s := range z.snaps {
			if s.full == last {
				return fail("dataset already exists")
			}
		}
		s := simSnap{full: last, created: time.Now().Unix() + int64(len(z.snaps))}
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				if k, v, _ := strings.Cut(args[i+1], "="); k == "org.hardyos:app-version" {
					s.version = v
				}
			}
		}
		if err := copyTree(ctx, z.mountpoint(ds), z.snapDir(last)); err != nil {
			return sysexec.Result{}, err
		}
		z.snaps = append(z.snaps, s)
		return sysexec.Result{}, nil
	case "rollback":
		ds, _, _ := strings.Cut(last, "@")
		idx := -1
		for i, s := range z.snaps {
			if s.full == last {
				idx = i
			}
		}
		if idx < 0 {
			return fail("could not find any snapshots to destroy; check snapshot names")
		}
		if err := copyTree(ctx, z.snapDir(last), z.mountpoint(ds)); err != nil {
			return sysexec.Result{}, err
		}
		// -r: later snapshots go.
		var keep []simSnap
		for i, s := range z.snaps {
			if !strings.HasPrefix(s.full, ds+"@") || i <= idx {
				keep = append(keep, s)
			}
		}
		z.snaps = keep
		return sysexec.Result{}, nil
	case "destroy":
		if strings.Contains(last, "@") {
			var keep []simSnap
			for _, s := range z.snaps {
				if s.full != last {
					keep = append(keep, s)
				}
			}
			z.snaps = keep
			return sysexec.Result{}, os.RemoveAll(z.snapDir(last))
		}
		for d := range z.ds {
			if d == last || strings.HasPrefix(d, last+"/") {
				delete(z.ds, d)
			}
		}
		return sysexec.Result{}, os.RemoveAll(z.mountpoint(last))
	}
	return fail("zfsSim: unexpected " + line)
}

func catalogPackage(t *testing.T, name string) []byte {
	t.Helper()
	b, err := Pack(filepath.Join("..", "..", "..", "apps", "catalog", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDockerIntegration installs KinCast for real: pulls its images, starts
// Postgres, the app and the streaming server, and checks the site answers.
// Needs Docker and root (folder owners): HARDYOS_DOCKER_INTEGRATION=1.
func TestDockerIntegration(t *testing.T) {
	if os.Getenv("HARDYOS_DOCKER_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_DOCKER_INTEGRATION=1 to run against a real Docker engine")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(root, "usr/bin/docker"), nil, 0o755)
	sim := &zfsSim{base: t.TempDir(), ds: map[string]bool{"tank": true}, real: sysexec.Exec{}}
	m := &Manager{Runner: sim, Root: root}
	pkg := catalogPackage(t, "kincast")

	ports, err := m.SuggestPorts(ctx, []PortCheck{{Name: "WEB", Default: 18095}, {Name: "RTMP", Default: 11935}}, "")
	if err != nil {
		t.Fatal(err)
	}
	prep, err := m.Prepare(ctx, PrepareArgs{Package: pkg, Pool: "tank", Host: "127.0.0.1", Ports: ports,
		Settings: map[string]string{"TRANSCODE_RENDITIONS": "720,360"}})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	t.Cleanup(func() {
		_ = m.Remove(context.Background(), RemoveArgs{ID: "kincast", Confirm: "KinCast", DeleteData: true})
	})
	if prep.Upgrade || len(prep.Services) != 3 {
		t.Fatalf("prepare result: %+v", prep)
	}
	for _, s := range prep.Services {
		r, err := m.Pull(ctx, "kincast", s.Service)
		if err != nil {
			t.Fatalf("pull %s: %v", s.Service, err)
		}
		if r.Cached {
			t.Logf("pull %s: %s", s.Service, r.Message)
		}
	}
	if err := m.Up(ctx, "kincast"); err != nil {
		t.Fatalf("up: %v", err)
	}

	web := fmt.Sprintf("http://127.0.0.1:%d/api/health", ports["WEB"])
	waitFor(t, ctx, "KinCast answering at "+web, func() bool {
		resp, err := http.Get(web)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode == 200 && strings.Contains(string(b), `"ok":true`)
	})
	waitFor(t, ctx, "every container running", func() bool {
		o, err := m.Status(ctx)
		return err == nil && len(o.Apps) == 1 && o.Apps[0].State == "running" && len(o.Apps[0].Containers) == 3
	})
	o, _ := m.Status(ctx)
	app := o.Apps[0]
	if app.Web == nil || app.Web.Port != ports["WEB"] || !strings.HasPrefix(app.Icon, "data:image/svg+xml;base64,") {
		t.Errorf("status: %+v", app)
	}

	// The app got its settings and HardyOS's variables; secrets were generated.
	env := readEnv(t, sim, "kincast")
	if env["TRANSCODE_RENDITIONS"] != "720,360" || env["HARDY_HOST"] != "127.0.0.1" || len(env["SESSION_SECRET"]) != 64 {
		t.Errorf("env: %v", env)
	}
	st, _ := os.ReadFile(filepath.Join(sim.mountpoint("tank/apps/kincast"), ".hardyos", "state.json"))
	if strings.Contains(string(st), env["SESSION_SECRET"]) {
		t.Error("a secret was written to state.json")
	}
	// Folders were made with the owners the containers need.
	if fi, err := os.Stat(filepath.Join(sim.mountpoint("tank/apps/kincast"), "data", "media")); err != nil || fi.Sys() == nil {
		t.Fatalf("media folder: %v", err)
	}

	logs, err := m.Logs(ctx, "kincast", 200)
	if err != nil || !strings.Contains(logs, "listening") {
		t.Errorf("logs (%v): %.400s", err, logs)
	}

	// Stop and start.
	if err := m.Stop(ctx, "kincast"); err != nil {
		t.Fatal(err)
	}
	if o, _ := m.Status(ctx); o.Apps[0].State != "stopped" {
		t.Errorf("after stop: %s", o.Apps[0].State)
	}
	if err := m.Start(ctx, "kincast"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ctx, "KinCast back after start", func() bool {
		resp, err := http.Get(web)
		if err == nil {
			resp.Body.Close()
		}
		return err == nil && resp.StatusCode == 200
	})

	// Reinstalling (an update) keeps the generated secrets and the ports.
	prep, err = m.Prepare(ctx, PrepareArgs{Package: pkg, Host: "127.0.0.1"})
	if err != nil || !prep.Upgrade {
		t.Fatalf("reinstall: %v %+v", err, prep)
	}
	if env2 := readEnv(t, sim, "kincast"); env2["SESSION_SECRET"] != env["SESSION_SECRET"] || env2[PortEnv("WEB")] != env[PortEnv("WEB")] {
		t.Error("reinstall changed the secrets or ports")
	}

	// A container that swaps one of its folders for a link out of the data
	// folder can't get it mounted.
	media := filepath.Join(sim.mountpoint("tank/apps/kincast"), "data", "hls")
	if err := m.Stop(ctx, "kincast"); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(media); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", media); err != nil {
		t.Fatal(err)
	}
	if err := m.Up(ctx, "kincast"); err == nil || !strings.Contains(err.Error(), "outside the app's data folder") {
		t.Fatalf("up with a planted symlink: %v", err)
	}
	_ = os.Remove(media)

	// Removing without deleting data keeps it for next time.
	if err := m.Remove(ctx, RemoveArgs{ID: "kincast", Confirm: "wrong"}); err == nil {
		t.Fatal("remove without the right name succeeded")
	}
	if err := m.Remove(ctx, RemoveArgs{ID: "kincast", Confirm: "kincast"}); err != nil {
		t.Fatal(err)
	}
	o, _ = m.Status(ctx)
	if len(o.Apps) != 0 || len(o.KeptData) != 1 {
		t.Fatalf("after remove: %+v", o)
	}
	if out, _ := sysexec.Output(ctx, sysexec.Exec{}, "docker", "ps", "-a", "-q", "--filter", "label=org.hardyos.app=kincast"); len(strings.TrimSpace(string(out))) != 0 {
		t.Error("containers left after remove")
	}
}

func readEnv(t *testing.T, sim *zfsSim, id string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(sim.mountpoint("tank/apps/"+id), ".hardyos", "app.env"))
	if err != nil {
		t.Fatal(err)
	}
	return parseEnv(b)
}

func waitFor(t *testing.T, ctx context.Context, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Minute)
	for !ok() {
		if time.Now().After(deadline) || ctx.Err() != nil {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Second)
	}
}

// engineTestImage is small and served by a mirror without Docker Hub's
// pull limits.
const engineTestImage = "mirror.gcr.io/library/busybox:1.36"

// TestDockerIntegrationEngine runs a small app with real Docker through
// the App Store v2 engine: shared folders (read-only and writable binds,
// the app's own user), the limits slice, reconfiguring, and a snapshot and
// rollback (snapshots simulated as copies). Same switch as above.
func TestDockerIntegrationEngine(t *testing.T) {
	if os.Getenv("HARDYOS_DOCKER_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_DOCKER_INTEGRATION=1 to run against a real Docker engine")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	const id, name = "aetest-shares", "Engine Test"

	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "usr/bin/docker"), nil, 0o755))
	sim := &zfsSim{base: t.TempDir(), ds: map[string]bool{"tank": true}, real: sysexec.Exec{}}
	shares := &fakeShares{root: t.TempDir()}
	for _, d := range []string{"media", "dl"} {
		must(t, os.MkdirAll(filepath.Join(shares.root, d), 0o777))
		must(t, os.Chmod(filepath.Join(shares.root, d), 0o777))
	}
	must(t, os.WriteFile(filepath.Join(shares.root, "media", "hello.txt"), []byte("hello"), 0o644))
	m := &Manager{Runner: sim, Root: root, Shares: shares}

	pkgDir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(pkgDir, ManifestFile), []byte(`{"format":1,"id":"`+id+`","name":"`+name+`","version":"1.0.0",
	  "summary":"Checks the apps engine.","web":{"port":"WEB"},
	  "ports":[{"name":"WEB","label":"Website","default":18180}],
	  "folders":[{"path":"state"}],
	  "shares":[{"name":"MEDIA","label":"Media","access":"read"},{"name":"DL","label":"Downloads","access":"write"}]}`), 0o644))
	must(t, os.WriteFile(filepath.Join(pkgDir, ComposeFile), []byte(`services:
  web:
    image: `+engineTestImage+`
    user: "${HARDY_UID}:${HARDY_GID}"
    command: ["httpd", "-f", "-p", "8080", "-h", "/media"]
    ports: ["${HARDY_PORT_WEB}:8080"]
    volumes:
      - ${HARDY_SHARE_MEDIA}:/media
      - ${HARDY_SHARE_DL}:/dl
      - ${HARDY_APP_DATA}/state:/state
`), 0o644))
	pkg, err := Pack(pkgDir)
	must(t, err)

	ports, err := m.SuggestPorts(ctx, []PortCheck{{Name: "WEB", Default: 18180}}, "")
	must(t, err)
	if _, err := m.Prepare(ctx, PrepareArgs{Package: pkg, Pool: "tank", Host: "127.0.0.1", Ports: ports, Source: SourceUpload,
		Shares: map[string]ShareChoice{"MEDIA": {Share: "media"}, "DL": {Share: "dl"}},
		Limits: &Limits{MemoryMB: 128, CPUs: 0.5}}); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	t.Cleanup(func() {
		_ = m.Remove(context.Background(), RemoveArgs{ID: id, Confirm: id, DeleteData: true})
	})
	if g := shares.take(); strings.Join(g, ";") != "grant dl "+id+" 30000 true;grant media "+id+" 30000 false" {
		t.Errorf("grants: %v", g)
	}
	if _, err := m.Pull(ctx, id, "web"); err != nil {
		t.Fatalf("pull: %v", err)
	}
	must(t, m.Up(ctx, id))

	hello := fmt.Sprintf("http://127.0.0.1:%d/hello.txt", ports["WEB"])
	get := func() int {
		resp, err := http.Get(hello)
		if err != nil {
			return 0
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	waitFor(t, ctx, "the app serving the media share", func() bool { return get() == 200 })

	ctr := strings.TrimSpace(string(dockerOut(t, ctx, "ps", "-q", "--filter", "label=org.hardyos.app="+id)))
	if ctr == "" {
		t.Fatal("no container")
	}
	// The read share is read-only, the write share writable, as the app's user.
	if _, err := sysexec.Output(ctx, sysexec.Exec{}, "docker", "exec", ctr, "touch", "/media/x"); err == nil {
		t.Error("the app could write in a read-only share")
	}
	if _, err := sysexec.Output(ctx, sysexec.Exec{}, "docker", "exec", ctr, "touch", "/dl/y"); err != nil {
		t.Errorf("writing in the write share: %v", err)
	} else if uid := ownerOf(t, filepath.Join(shares.root, "dl", "y")); uid != 30000 {
		t.Errorf("file written as uid %d, want 30000", uid)
	}
	if uid := ownerOf(t, filepath.Join(sim.mountpoint("tank/apps/"+id), "data", "state")); uid != 30000 {
		t.Errorf("state folder owner %d", uid)
	}
	// Limits: the container runs in the app's slice, written with the limits.
	if cp := strings.TrimSpace(string(dockerOut(t, ctx, "inspect", "--format", "{{.HostConfig.CgroupParent}}", ctr))); cp != SliceName(id) {
		t.Errorf("cgroup parent %q, want %q", cp, SliceName(id))
	}
	slice := string(mustRead(t, filepath.Join(root, "run/systemd/system", SliceName(id))))
	if !strings.Contains(slice, "MemoryMax=128M") || !strings.Contains(slice, "CPUQuota=50%") {
		t.Errorf("slice:\n%s", slice)
	}

	// Snapshot before a change.
	state := filepath.Join(sim.mountpoint("tank/apps/"+id), "data", "state")
	must(t, os.WriteFile(filepath.Join(state, "v1"), nil, 0o644))
	snap, err := m.Snapshot(ctx, SnapshotArgs{ID: id, Reason: "update"})
	must(t, err)
	if snaps, err := m.Snapshots(ctx, id); err != nil || len(snaps) != 1 || snaps[0].Name != snap || snaps[0].Version != "1.0.0" {
		t.Fatalf("snapshots: %v %+v", err, snaps)
	}

	// Reconfigure: take the media share away and change the limits.
	if _, err := m.Reconfigure(ctx, ReconfigureArgs{ID: id, Shares: map[string]ShareChoice{"MEDIA": {}},
		Limits: &Limits{MemoryMB: 256}}); err != nil {
		t.Fatalf("reconfigure: %v", err)
	}
	if g := shares.take(); strings.Join(g, ";") != "revoke "+id+";grant dl "+id+" 30000 true" {
		t.Errorf("grants after reconfigure: %v", g)
	}
	must(t, m.Up(ctx, id))
	waitFor(t, ctx, "the app without the media share", func() bool { return get() == 404 })
	if s := string(mustRead(t, filepath.Join(root, "run/systemd/system", SliceName(id)))); !strings.Contains(s, "MemoryMax=256M") {
		t.Errorf("slice after reconfigure:\n%s", s)
	}
	must(t, os.WriteFile(filepath.Join(state, "v2"), nil, 0o644))

	// Roll back: the snapshot's files, shares and limits return.
	if err := m.Rollback(ctx, RollbackArgs{ID: id, Snapshot: snap, Confirm: "wrong"}); err == nil {
		t.Fatal("rollback without the name")
	}
	if err := m.Rollback(ctx, RollbackArgs{ID: id, Snapshot: snap, Confirm: name}); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	waitFor(t, ctx, "the app serving the media share again", func() bool { return get() == 200 })
	if _, err := os.Stat(filepath.Join(state, "v1")); err != nil {
		t.Error("v1 lost in the rollback")
	}
	if _, err := os.Stat(filepath.Join(state, "v2")); err == nil {
		t.Error("v2 survived the rollback")
	}
	if g := shares.take(); strings.Join(g, ";") != "revoke "+id+";grant dl "+id+" 30000 true;grant media "+id+" 30000 false" {
		t.Errorf("grants after rollback: %v", g)
	}
	o, err := m.Status(ctx)
	if err != nil || len(o.Apps) != 1 || o.Apps[0].Limits.MemoryMB != 128 || o.Apps[0].Shares[0].Share != "media" || o.Apps[0].Source != SourceUpload {
		t.Errorf("status after rollback: %v %+v", err, o)
	}

	if err := m.Remove(ctx, RemoveArgs{ID: id, Confirm: name, DeleteData: true}); err != nil {
		t.Fatal(err)
	}
	if out := dockerOut(t, ctx, "ps", "-a", "-q", "--filter", "label=org.hardyos.app="+id); len(strings.TrimSpace(string(out))) != 0 {
		t.Error("containers left after remove")
	}
	if g := shares.take(); len(g) != 1 || g[0] != "revoke "+id {
		t.Errorf("grants after remove: %v", g)
	}
}

func dockerOut(t *testing.T, ctx context.Context, args ...string) []byte {
	t.Helper()
	out, err := sysexec.Output(ctx, sysexec.Exec{}, "docker", args...)
	if err != nil {
		t.Fatalf("docker %v: %v", args, err)
	}
	return out
}
