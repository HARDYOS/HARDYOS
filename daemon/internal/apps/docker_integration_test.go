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

// zfsSim stands in for ZFS (datasets are plain folders) and systemctl, and
// passes every other command to the real system. With it, the integration
// test runs real Docker Compose against the real KinCast package on any
// machine with Docker.
type zfsSim struct {
	base string
	mu   sync.Mutex
	ds   map[string]bool
	real sysexec.Runner
}

func (z *zfsSim) mountpoint(ds string) string {
	pool, rest, _ := strings.Cut(ds, "/")
	return filepath.Join(z.base, "mnt", pool, rest)
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
	switch args[0] {
	case "list":
		if strings.Contains(strings.Join(args, " "), "-d 1") {
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
	case "destroy":
		for d := range z.ds {
			if d == last || strings.HasPrefix(d, last+"/") {
				delete(z.ds, d)
			}
		}
		return sysexec.Result{}, os.RemoveAll(z.mountpoint(last))
	}
	return fail("zfsSim: unexpected " + strings.Join(args, " "))
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
