package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/devices"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/gpu"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/updates"
)

// devRunner is a fake command runner that also does what apt and dpkg-deb
// would do to the files.
type devRunner struct {
	*sysexec.Fake
	mu    sync.Mutex
	hooks map[string]func([]string)
}

func (r *devRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) (sysexec.Result, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	r.mu.Lock()
	var fns []func([]string)
	for p, fn := range r.hooks {
		if strings.HasPrefix(line, p) {
			fns = append(fns, fn)
		}
	}
	r.mu.Unlock()
	for _, fn := range fns {
		fn(args)
	}
	return r.Fake.Run(ctx, stdin, name, args...)
}

func (r *devRunner) RunEnv(ctx context.Context, env []string, stdin []byte, name string, args ...string) (sysexec.Result, error) {
	return r.Run(ctx, stdin, name, args...)
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

const testLicence = "NVIDIA Software License\nThis license is a legal agreement...\n"

func newDevicesEnv(t *testing.T) (*testEnv, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	link := func(p, target string) {
		_ = os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755)
		rel, _ := filepath.Rel(filepath.Dir(p), target)
		if err := os.Symlink(rel, filepath.Join(root, p)); err != nil {
			t.Fatal(err)
		}
	}
	dev := func(addr, vendor, device, class, driver string, group string) {
		d := "/sys/devices/pci0000:00/" + addr
		put(t, root, d+"/vendor", "0x"+vendor+"\n")
		put(t, root, d+"/device", "0x"+device+"\n")
		put(t, root, d+"/class", class+"\n")
		put(t, root, d+"/reset_method", "flr\n")
		_ = os.MkdirAll(filepath.Join(root, "sys/bus/pci/drivers", driver), 0o755)
		link(d+"/driver", "/sys/bus/pci/drivers/"+driver)
		link("/sys/bus/pci/devices/"+addr, d)
		_ = os.MkdirAll(filepath.Join(root, "sys/kernel/iommu_groups", group, "devices"), 0o755)
		link("/sys/kernel/iommu_groups/"+group+"/devices/"+addr, d)
		link(d+"/iommu_group", "/sys/kernel/iommu_groups/"+group)
	}
	dev("0000:00:02.0", "8086", "3e92", "0x030000", "i915", "2")
	dev("0000:01:00.0", "10de", "1eb1", "0x030000", "nouveau", "12")
	put(t, root, "/proc/cpuinfo", "vendor_id\t: GenuineIntel\n")
	put(t, root, "/proc/cmdline", "quiet\n")
	put(t, root, "/proc/sys/kernel/random/boot_id", "b1\n")
	put(t, root, "/proc/sys/kernel/osrelease", "6.12.48+deb13-amd64\n")
	put(t, root, "/proc/net/route", "Iface\tDestination\n")
	put(t, root, "/etc/os-release", "VERSION_CODENAME=trixie\n")
	put(t, root, "/lib/modules/6.12.48+deb13-amd64/build/Makefile", "")
	// Boot disks, for "Turn on IOMMU".
	put(t, root, "/var/lib/hardyos/boot.json", `{"pool":"rpool","disks":[{"byId":"/dev/disk/by-id/a","espPartUUID":"aaaaaaaa-0000-0000-0000-000000000001"}]}`)
	put(t, root, "/dev/disk/by-partuuid/aaaaaaaa-0000-0000-0000-000000000001", "")
	put(t, root, "/run/hardyos/boot/be/hardyos-0.1.0/boot/vmlinuz-6.12.1", "k")
	put(t, root, "/run/hardyos/boot/be/hardyos-0.1.0/boot/initrd.img-6.12.1", "i")

	r := &devRunner{Fake: &sysexec.Fake{}, hooks: map[string]func([]string){}}
	r.hooks["apt-get -y --no-install-recommends --download-only"] = func([]string) {
		put(t, root, "/var/cache/apt/archives/nvidia-kernel-support_550.163.01-2_amd64.deb", "deb")
	}
	r.hooks["dpkg-deb -x "] = func(args []string) {
		put(t, root, filepath.Join(args[2], "usr/share/doc/nvidia-kernel-support/copyright"), testLicence)
	}
	r.hooks["apt-get -y --no-install-recommends -o"] = func([]string) {
		put(t, root, "/lib/modules/6.12.48+deb13-amd64/updates/dkms/nvidia.ko", "ko")
	}
	r.On("zfs list -H -p -o name,creation,org.hardyos:version -d 1 -r rpool/ROOT", "rpool/ROOT\t1\t-\nrpool/ROOT/hardyos-0.1.0\t2\t0.1.0\n")
	r.On("zpool get -H -o value bootfs rpool", "rpool/ROOT/hardyos-0.1.0\n")
	r.OnPrefix("dpkg-query ", sysexec.Result{ExitCode: 1})
	r.OnPrefix("nvidia-smi", sysexec.Result{ExitCode: 127})
	r.OnPrefix("", sysexec.Result{})

	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	priv.RegisterDevices(ps, &devices.Host{Runner: r, Root: root, Arch: "amd64"}, &gpu.Manager{Runner: r, Root: root, Arch: "amd64"})
	go func() { _ = ps.Serve(ctx, ln) }()
	pc := priv.NewClient(sock)
	broker := events.NewBroker()
	m := &jobs.Manager{DB: db, Events: broker}
	RegisterJobKinds(m, pc)
	old := gpuPollInterval
	gpuPollInterval = 20 * time.Millisecond
	upd := &updates.Service{Priv: pc, Jobs: m, DB: db, Dir: t.TempDir(), Notify: &notify.Center{DB: db, Events: broker}}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Config{DB: db, Jobs: m, Events: broker, Priv: pc, Updates: upd, Insecure: true,
		GPUUploadDir: filepath.Join(root, gpu.UploadDir)}))
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
		gpuPollInterval = old
	})
	return &testEnv{srv: srv, db: db, broker: broker}, root
}

func TestDevicesAPI(t *testing.T) {
	env, root := newDevicesEnv(t)
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	kid := env.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	if code := kid.do("GET", "/api/v1/devices", nil, nil); code != 403 {
		t.Fatalf("non-admin inventory = %d", code)
	}

	var inv devices.Inventory
	if code := admin.do("GET", "/api/v1/devices", nil, &inv); code != 200 || len(inv.GPUs) != 2 || !inv.IOMMU.CanTurnOn {
		t.Fatalf("inventory %d %+v", code, inv)
	}
	var chk priv.DevicesCheckResult
	if code := admin.do("POST", "/api/v1/devices/check", map[string]any{"vm": "win11", "devices": []devices.Device{{Kind: "gpu", ID: "0000:09:00.0"}}}, &chk); code != 200 || chk.OK || len(chk.Problems) != 1 {
		t.Fatalf("check %d %+v", code, chk)
	}
	if code := admin.do("POST", "/api/v1/devices/check", map[string]any{"vm": "win11", "devices": []devices.Device{{Kind: "gpu", ID: "0000:01:00.0"}}}, &chk); code != 200 || !chk.OK {
		t.Fatalf("check ok %d %+v", code, chk)
	}

	// Turn on IOMMU: a job; the flags land on the boot disk.
	var acc struct {
		Job map[string]any `json:"job"`
	}
	if code := admin.do("POST", "/api/v1/devices/iommu/enable", nil, &acc); code != 202 {
		t.Fatalf("iommu = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job["id"].(string)); j["state"] != "succeeded" {
		t.Fatalf("iommu job %v", j)
	}
	cfg, _ := os.ReadFile(filepath.Join(root, "run/hardyos/boot/esp0/grub/grub.cfg"))
	if !strings.Contains(string(cfg), "quiet intel_iommu=on iommu=pt") {
		t.Fatalf("grub.cfg:\n%s", cfg)
	}

	// NVIDIA: fetch the licence, refuse without agreement, then install.
	if code := admin.do("POST", "/api/v1/devices/nvidia/prepare", nil, &acc); code != 202 {
		t.Fatalf("prepare = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job["id"].(string)); j["state"] != "succeeded" {
		t.Fatalf("prepare job %v", j)
	}
	var lic priv.LicenceResult
	if code := admin.do("GET", "/api/v1/devices/nvidia/licence", nil, &lic); code != 200 || lic.Text != testLicence {
		t.Fatalf("licence %d %+v", code, lic)
	}
	sum := sha256.Sum256([]byte(testLicence))
	sha := hex.EncodeToString(sum[:])
	if code := admin.do("POST", "/api/v1/devices/nvidia/install", map[string]any{"licenceSha256": sha}, nil); code != 400 {
		t.Fatalf("install without accept = %d", code)
	}
	if code := admin.do("POST", "/api/v1/devices/nvidia/install", map[string]any{"licenceSha256": sha, "accept": true}, &acc); code != 202 {
		t.Fatalf("install = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job["id"].(string)); j["state"] != "succeeded" {
		t.Fatalf("install job %v", j)
	}
	var st gpu.Status
	admin.do("GET", "/api/v1/devices/nvidia", nil, &st)
	if st.NVIDIAGPUs != 1 || st.Consent == nil || st.Consent.By != "cade" || !st.Consent.Installed || st.Task == nil || st.Task.Kind != gpu.TaskNvidiaInstall {
		t.Fatalf("status %+v", st)
	}
	var task priv.TaskResult
	if admin.do("GET", "/api/v1/devices/gpu-task", nil, &task); task.Task == nil || !strings.Contains(task.Task.Log, "agreed to by cade") {
		t.Fatalf("task %+v", task.Task)
	}
	var audit []map[string]any
	admin.do("GET", "/api/v1/audit", nil, &audit)
	found := map[string]bool{}
	for _, e := range audit {
		found[e["action"].(string)] = true
	}
	for _, a := range []string{"devices.iommu.enable", "devices.nvidia.prepare", "devices.nvidia.licence.accept", "devices.nvidia.install"} {
		if !found[a] {
			t.Errorf("audit missing %s (%v)", a, found)
		}
	}

	// vGPU driver upload: name checked, file hashed, then installed by a job.
	if code := admin.upload("/api/v1/devices/vgpu-driver/upload", []byte("x"), nil); code != 400 {
		t.Fatalf("nameless upload = %d", code)
	}
	payload := []byte("#!/bin/sh\nlabel=\"NVIDIA Accelerated Graphics Driver for Linux-x86_64 550.90.05\"\n")
	res, body := admin.send("POST", "/api/v1/devices/vgpu-driver/upload", payload, map[string]string{"X-HardyOS-Filename": "NVIDIA-Linux-x86_64-550.90.05-vgpu-kvm.run"})
	if res.StatusCode != 200 {
		t.Fatalf("upload = %d %s", res.StatusCode, body)
	}
	vsum := sha256.Sum256(payload)
	if !strings.Contains(string(body), hex.EncodeToString(vsum[:])) || !strings.Contains(string(body), `"version":"550.90.05"`) {
		t.Fatalf("upload result %s", body)
	}
	if code := admin.do("POST", "/api/v1/devices/vgpu-driver/install", map[string]any{"upload": "../x", "sha256": sha, "accept": true}, nil); code != 400 {
		t.Fatalf("bad upload id = %d", code)
	}
	var up VGPUUpload
	_ = jsonUnmarshal(body, &up)
	inst := map[string]any{"upload": up.Upload, "sha256": up.SHA256, "fileName": up.FileName}
	if code := admin.do("POST", "/api/v1/devices/vgpu-driver/install", inst, nil); code != 400 {
		t.Fatalf("install without accept = %d", code)
	}
	inst["accept"] = true
	if code := admin.do("POST", "/api/v1/devices/vgpu-driver/install", inst, &acc); code != 202 {
		t.Fatalf("vgpu install = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job["id"].(string)); j["state"] != "succeeded" {
		t.Fatalf("vgpu install job %v", j)
	}
	if _, err := os.Stat(filepath.Join(root, gpu.UploadDir, up.Upload)); err == nil {
		t.Error("upload left behind")
	}
	if code := admin.do("POST", "/api/v1/devices/slices/..%2f/remove", nil, nil); code != 400 && code != 404 {
		t.Fatalf("bad slice = %d", code)
	}
	if code := admin.do("POST", "/api/v1/devices/gpus/zz/sriov", map[string]int{"vfs": 1}, nil); code != 400 {
		t.Fatalf("bad sriov address = %d", code)
	}
	if code := kid.do("POST", "/api/v1/devices/nvidia/prepare", nil, nil); code != 403 {
		t.Fatalf("non-admin prepare = %d", code)
	}
}
