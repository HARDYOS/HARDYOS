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
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/install"
	"github.com/hardyos/hardyos/daemon/internal/installer"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

const testDisk = "/dev/disk/by-id/ata-Samsung_SSD_870_A"

// stubInstallHelper answers the install steps without touching anything and
// records which ones ran, with their arguments.
type stubInstallHelper struct {
	mu    sync.Mutex
	calls []string
	args  map[string]json.RawMessage
	fail  string // op that fails
}

func (h *stubInstallHelper) register(s *priv.Server) {
	h.args = map[string]json.RawMessage{}
	ok := func(op string) priv.HandlerFunc {
		return func(ctx context.Context, raw json.RawMessage) (any, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.calls = append(h.calls, op)
			h.args[op] = raw
			if op == h.fail {
				return nil, priv.Errorf(priv.CodeFailed, "simulated failure in %s", op)
			}
			if op == priv.OpInstallCheck {
				var a priv.InstallArgs
				_ = json.Unmarshal(raw, &a)
				if a.Plan.Disks[0] != testDisk {
					return nil, priv.Errorf(priv.CodeBadArgs, "disk %s not found (was it removed?)", a.Plan.Disks[0])
				}
				return priv.InstallInfo{Version: "0.1.0", BE: "hardyos-0.1.0", Disks: []install.DiskCheck{{Disk: hw.Disk{ByID: testDisk}, Warnings: []string{}}}}, nil
			}
			return map[string]bool{"ok": true}, nil
		}
	}
	for _, op := range []string{priv.OpInstallCheck, priv.OpInstallPartition, priv.OpInstallPool, priv.OpInstallSystem,
		priv.OpInstallConfigure, priv.OpInstallBoot, priv.OpInstallFinish, priv.OpInstallReset, priv.OpSystemReboot} {
		s.Handle(op, ok(op))
	}
	s.Handle(priv.OpHWDisks, func(context.Context, json.RawMessage) (any, error) {
		return []hw.Disk{{Name: "sda", ByID: testDisk, SizeBytes: 250e9, Usage: hw.UsageFree}}, nil
	})
	s.Handle(priv.OpHWSystem, func(context.Context, json.RawMessage) (any, error) {
		return hw.System{NICs: []hw.NIC{{Name: "lo"}}, Memory: hw.Memory{TotalBytes: 8 << 30}}, nil
	})
}

func (h *stubInstallHelper) ops() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string{}, h.calls...)
}

func newInstallerEnv(t *testing.T, helper *stubInstallHelper) *testEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "live.db"))
	if err != nil {
		t.Fatal(err)
	}
	broker := events.NewBroker()
	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	helper.register(ps)
	go func() { _ = ps.Serve(ctx, ln) }()
	pc := priv.NewClient(sock)

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "run/hardyos"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, install.CodeFile), []byte("K7QM-4TXP\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	m := &jobs.Manager{DB: db, Events: broker}
	inst := &installer.Service{Priv: pc, Jobs: m, Limiter: auth.NewLoginLimiter(), Root: root}
	inst.RegisterJobs(m)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Config{DB: db, Jobs: m, Events: broker, Priv: pc, Installer: inst, Insecure: true}))
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	return &testEnv{srv: srv, db: db, broker: broker}
}

func validInstall() map[string]any {
	return map[string]any{
		"plan": map[string]any{
			"disks": []string{testDisk}, "hostname": "nas", "timezone": "America/Chicago",
			"network": map[string]any{"mode": "dhcp"},
		},
		"admin":       map[string]string{"username": "cade", "password": "supersecret1", "displayName": "Cade"},
		"confirmWipe": true,
	}
}

func waitInstall(t *testing.T, c *client) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var st map[string]any
		c.do("GET", "/api/v1/installer", nil, &st)
		if j, ok := st["job"].(map[string]any); ok {
			switch j["state"] {
			case "succeeded", "failed", "cancelled":
				return j
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("install job did not finish")
	return nil
}

func TestInstallerFlow(t *testing.T) {
	helper := &stubInstallHelper{}
	env := newInstallerEnv(t, helper)
	c := env.client(t)

	var st map[string]any
	if code := c.do("GET", "/api/v1/installer", nil, &st); code != 200 || st["active"] != true || st["unlocked"] != false {
		t.Fatalf("status = %d %v", code, st)
	}
	// The normal API is not served on the live installer.
	if code := c.do("POST", "/api/v1/auth/login", map[string]string{"username": "x", "password": "y"}, nil); code != 404 {
		t.Fatalf("login on the installer = %d", code)
	}
	if code := c.do("GET", "/api/v1/installer/hardware", nil, nil); code != 401 {
		t.Fatalf("hardware while locked = %d", code)
	}
	if code := c.do("POST", "/api/v1/installer/unlock", map[string]string{"code": "AAAA-AAAA"}, nil); code != 401 {
		t.Fatalf("wrong code = %d", code)
	}
	// Codes are case- and dash-insensitive.
	if code := c.do("POST", "/api/v1/installer/unlock", map[string]string{"code": "k7qm 4txp"}, &st); code != 200 || st["unlocked"] != true {
		t.Fatalf("unlock = %d %v", code, st)
	}

	var hwOut map[string]any
	if code := c.do("GET", "/api/v1/installer/hardware", nil, &hwOut); code != 200 || len(hwOut["disks"].([]any)) != 1 {
		t.Fatalf("hardware = %d %v", code, hwOut)
	}

	var info map[string]any
	if code := c.do("POST", "/api/v1/installer/check", map[string]any{"plan": validInstall()["plan"]}, &info); code != 200 || info["bootEnvironment"] != "hardyos-0.1.0" {
		t.Fatalf("check = %d %v", code, info)
	}
	bad := validInstall()
	bad["plan"].(map[string]any)["disks"] = []string{"/dev/disk/by-id/ata-gone"}
	var e map[string]any
	if code := c.do("POST", "/api/v1/installer/check", map[string]any{"plan": bad["plan"]}, &e); code != 400 {
		t.Fatalf("check missing disk = %d %v", code, e)
	}

	noConfirm := validInstall()
	noConfirm["confirmWipe"] = false
	if code := c.do("POST", "/api/v1/installer/install", noConfirm, nil); code != 400 {
		t.Fatalf("install without confirm = %d", code)
	}
	weak := validInstall()
	weak["admin"] = map[string]string{"username": "cade", "password": "short"}
	if code := c.do("POST", "/api/v1/installer/install", weak, &e); code != 400 || e["code"] != "invalid_admin" {
		t.Fatalf("weak password = %d %v", code, e)
	}

	var job map[string]any
	if code := c.do("POST", "/api/v1/installer/install", validInstall(), &job); code != 202 {
		t.Fatalf("install = %d %v", code, job)
	}
	done := waitInstall(t, c)
	if done["state"] != "succeeded" {
		t.Fatalf("job = %v", done)
	}
	// Two checks from the API calls above, one before submitting, one in the job, then the steps.
	want := []string{priv.OpInstallCheck, priv.OpInstallCheck, priv.OpInstallCheck, priv.OpInstallCheck, priv.OpInstallPartition,
		priv.OpInstallPool, priv.OpInstallSystem, priv.OpInstallConfigure, priv.OpInstallBoot, priv.OpInstallFinish}
	if got := helper.ops(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ops = %v", got)
	}
	// The password reaches root only as a hash.
	var cfgArgs priv.InstallArgs
	_ = json.Unmarshal(helper.args[priv.OpInstallConfigure], &cfgArgs)
	if cfgArgs.Seed == nil || cfgArgs.Seed.Username != "cade" || !auth.VerifyPassword("supersecret1", cfgArgs.Seed.PasswordHash) {
		t.Fatalf("seed = %+v", cfgArgs.Seed)
	}
	if string(helper.args[priv.OpInstallConfigure]) == "" || strings.Contains(string(helper.args[priv.OpInstallConfigure]), "supersecret1") {
		t.Fatal("plain password sent to the root helper")
	}
	var partArgs priv.InstallArgs
	_ = json.Unmarshal(helper.args[priv.OpInstallPartition], &partArgs)
	if !partArgs.ConfirmWipe {
		t.Fatal("partition step without confirmWipe")
	}

	if code := c.do("POST", "/api/v1/installer/install", validInstall(), &e); code != 409 {
		t.Fatalf("second install = %d %v", code, e)
	}
	if code := c.do("POST", "/api/v1/installer/reboot", nil, nil); code != 202 {
		t.Fatalf("reboot = %d", code)
	}

	// Another browser without the code sees nothing.
	other := env.client(t)
	if code := other.do("POST", "/api/v1/installer/install", validInstall(), nil); code != 401 {
		t.Fatalf("install without unlock = %d", code)
	}
}

func TestInstallerFailureResets(t *testing.T) {
	helper := &stubInstallHelper{fail: priv.OpInstallSystem}
	env := newInstallerEnv(t, helper)
	c := env.client(t)
	c.do("POST", "/api/v1/installer/unlock", map[string]string{"code": "K7QM-4TXP"}, nil)
	if code := c.do("POST", "/api/v1/installer/install", validInstall(), nil); code != 202 {
		t.Fatalf("install = %d", code)
	}
	j := waitInstall(t, c)
	if j["state"] != "failed" {
		t.Fatalf("job = %v", j)
	}
	ops := helper.ops()
	if ops[len(ops)-1] != priv.OpInstallReset {
		t.Fatalf("no reset after failure: %v", ops)
	}
	// A failed install can be retried.
	helper.fail = ""
	if code := c.do("POST", "/api/v1/installer/install", validInstall(), nil); code != 202 {
		t.Fatalf("retry = %d", code)
	}
	if j := waitInstall(t, c); j["state"] != "succeeded" {
		t.Fatalf("retry job = %v", j)
	}
}

func TestInstallerUnlockRateLimit(t *testing.T) {
	env := newInstallerEnv(t, &stubInstallHelper{})
	c := env.client(t)
	limited := false
	for i := 0; i < 30; i++ {
		if code := c.do("POST", "/api/v1/installer/unlock", map[string]string{"code": "AAAA-AAAA"}, nil); code == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("guessing codes was never rate limited")
	}
	// Even the right code is refused while limited.
	if code := c.do("POST", "/api/v1/installer/unlock", map[string]string{"code": "K7QM-4TXP"}, nil); code != 429 {
		t.Fatalf("right code while limited = %d", code)
	}
}

func TestInstallerStatusOnInstalledSystem(t *testing.T) {
	env := newEnv(t)
	var st map[string]any
	if code := env.client(t).do("GET", "/api/v1/installer", nil, &st); code != 200 || st["active"] != false {
		t.Fatalf("status = %d %v", code, st)
	}
}
