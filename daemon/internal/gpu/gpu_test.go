package gpu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// runner is a sysexec.Fake that also does what some commands would do to
// the files (download packages, unpack one, build the module).
type runner struct {
	*sysexec.Fake
	mu    sync.Mutex
	hooks map[string]func(args []string)
}

func (r *runner) Run(ctx context.Context, stdin []byte, name string, args ...string) (sysexec.Result, error) {
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

func (r *runner) RunEnv(ctx context.Context, env []string, stdin []byte, name string, args ...string) (sysexec.Result, error) {
	res, err := r.Run(ctx, stdin, name, args...)
	return res, err
}

func (r *runner) on(prefix string, fn func([]string)) {
	r.mu.Lock()
	r.hooks[prefix] = fn
	r.mu.Unlock()
}

func (r *runner) has(sub string) bool {
	for _, l := range r.Fake.Lines() {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

type world struct {
	t    *testing.T
	root string
	r    *runner
	m    *Manager
}

func (w *world) write(p, data string) {
	w.t.Helper()
	full := filepath.Join(w.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
		w.t.Fatal(err)
	}
}

const licenceText = "NVIDIA Software License\n\nThis license is a legal agreement between you and NVIDIA Corporation...\n"

func newWorld(t *testing.T) *world {
	w := &world{t: t, root: t.TempDir(), r: &runner{Fake: &sysexec.Fake{}, hooks: map[string]func([]string){}}}
	w.write("/sys/bus/pci/devices/0000:01:00.0/vendor", "0x10de\n")
	w.write("/sys/bus/pci/devices/0000:01:00.0/class", "0x030000\n")
	w.write("/etc/os-release", "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nVERSION_CODENAME=trixie\n")
	w.write("/etc/apt/sources.list", "deb http://deb.debian.org/debian trixie main contrib non-free-firmware\n")
	w.write("/proc/sys/kernel/osrelease", "6.12.48+deb13-amd64\n")
	w.write("/lib/modules/6.12.48+deb13-amd64/build/Makefile", "")
	w.r.on("apt-get -y --no-install-recommends --download-only install", func([]string) {
		w.write("/var/cache/apt/archives/nvidia-kernel-support_550.163.01-2_amd64.deb", "deb")
		w.write("/var/cache/apt/archives/nvidia-driver_550.163.01-2_amd64.deb", "deb")
	})
	w.r.on("dpkg-deb -x ", func(args []string) {
		w.write(filepath.Join(args[2], "usr/share/doc/nvidia-kernel-support/copyright"), licenceText)
		w.write(filepath.Join(args[2], "usr/share/doc/nvidia-kernel-support/changelog.gz"), "x")
	})
	w.r.on("apt-get -y --no-install-recommends -o Dpkg::Options::=--force-confdef", func([]string) {
		w.write("/lib/modules/6.12.48+deb13-amd64/updates/dkms/nvidia.ko.xz", "ko")
	})
	w.r.OnPrefix("dpkg-query ", sysexec.Result{ExitCode: 1})
	w.r.OnPrefix("", sysexec.Result{})
	w.m = &Manager{Runner: w.r, Root: w.root, Arch: "amd64"}
	return w
}

func waitTask(t *testing.T, m *Manager) *Task {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tk := m.Wait(ctx)
	if tk == nil || tk.State == TaskRunning {
		t.Fatalf("task didn't finish: %+v", tk)
	}
	return tk
}

func TestToolkitKeyIsPinned(t *testing.T) {
	fp, err := keyFingerprint(toolkitKey)
	if err != nil {
		t.Fatal(err)
	}
	// Checked against `gpg --show-keys` of NVIDIA's published key (2026-10-26).
	if ToolkitKeyFingerprint != "C95B321B61E88C1809C4F759DDCAE044F796ECB0" || fp != ToolkitKeyFingerprint {
		t.Fatalf("fingerprint %s", fp)
	}
	// A changed key isn't the pinned one.
	bad := strings.Replace(string(toolkitKey), "mQINBFnNWDEBEACiX68rxIWvqH3h2GykO25oK9BAqV8fDtb6lXEbw3eKx4g87BRz", "mQINBFnNWDEBEACiX68rxIWvqH3h2GykO25oK9BAqV8fDtb6lXEbw3eKx4g87BRy", 1)
	if fp2, _ := keyFingerprint([]byte(bad)); fp2 == ToolkitKeyFingerprint {
		t.Fatal("tampered key has the pinned fingerprint")
	}
	if _, err := keyFingerprint([]byte("not a key")); err == nil {
		t.Fatal("garbage parsed")
	}
}

func TestWriteSources(t *testing.T) {
	w := newWorld(t)
	if hasNonFree(w.root) {
		t.Fatal("non-free-firmware counted as non-free")
	}
	if err := writeSources(w.root, "amd64"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(w.root, nonFreeSourcesPath))
	if !strings.Contains(string(b), "Suites: trixie trixie-updates\nComponents: non-free\n") || !strings.Contains(string(b), "trixie-security") {
		t.Fatalf("non-free sources:\n%s", b)
	}
	list, _ := os.ReadFile(filepath.Join(w.root, toolkitListPath))
	if string(list) != "# Added by HardyOS: NVIDIA's container toolkit (key C95B321B61E88C1809C4F759DDCAE044F796ECB0).\ndeb [signed-by=/etc/apt/keyrings/hardyos-nvidia-container-toolkit.asc] https://nvidia.github.io/libnvidia-container/stable/deb/amd64 /\n" {
		t.Fatalf("toolkit list:\n%s", list)
	}
	if !hasNonFree(w.root) {
		t.Fatal("our own file not recognised")
	}
	// A system that already has non-free (deb822) gets no extra file.
	w2 := newWorld(t)
	w2.write("/etc/apt/sources.list", "")
	w2.write("/etc/apt/sources.list.d/debian.sources", "Types: deb\nURIs: http://deb.debian.org/debian\nSuites: trixie\nComponents: main contrib non-free non-free-firmware\n")
	if err := writeSources(w2.root, "amd64"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(w2.root, nonFreeSourcesPath)); err == nil {
		t.Fatal("non-free added twice")
	}
}

func TestNvidiaPrepareAgreeInstall(t *testing.T) {
	w := newWorld(t)
	m := w.m
	if _, err := m.InstallNvidia(InstallArgs{LicenceSHA256: strings.Repeat("a", 64), By: "cade"}); err == nil {
		t.Fatal("installed before the licence was shown")
	}
	if _, err := m.PrepareNvidia(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.PrepareNvidia(); err != ErrBusy && m.Task().State == TaskRunning {
		t.Fatalf("second task: %v", err)
	}
	tk := waitTask(t, m)
	if tk.State != TaskSucceeded {
		t.Fatalf("prepare: %+v", tk)
	}
	text, lic, err := m.LicenceText()
	if err != nil || text != licenceText || lic.Version != "550.163.01-2" || !strings.HasPrefix(lic.Source, "nvidia-kernel-support_") {
		t.Fatalf("licence %q %+v %v", text, lic, err)
	}
	sum := sha256.Sum256([]byte(licenceText))
	if lic.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("hash")
	}
	if !w.r.has("apt-get update") || !w.r.has("--download-only install nvidia-driver nvidia-kernel-dkms") {
		t.Fatalf("commands:\n%s", strings.Join(w.r.Lines(), "\n"))
	}
	// Agreeing to a different text is refused.
	if _, err := m.InstallNvidia(InstallArgs{LicenceSHA256: strings.Repeat("b", 64), By: "cade"}); err == nil {
		t.Fatal("wrong licence hash accepted")
	}
	if _, err := m.InstallNvidia(InstallArgs{LicenceSHA256: lic.SHA256}); err == nil {
		t.Fatal("no name accepted")
	}
	if _, err := m.InstallNvidia(InstallArgs{LicenceSHA256: lic.SHA256, By: "cade"}); err != nil {
		t.Fatal(err)
	}
	tk = waitTask(t, m)
	if tk.State != TaskSucceeded {
		t.Fatalf("install: %+v\n%s", tk, tk.Log)
	}
	if r, _ := tk.Result.(map[string]bool); r["restartNeeded"] {
		t.Fatalf("result %+v", tk.Result)
	}
	rec, _ := m.load()
	if rec.Driver == nil || !rec.Driver.Installed || rec.Driver.By != "cade" || rec.Driver.LicenceSHA256 != lic.SHA256 {
		t.Fatalf("consent %+v", rec.Driver)
	}
	lines := strings.Join(w.r.Lines(), "\n")
	order := []string{"dpkg --configure -a", "apt-get update", "Dpkg::Options::=--force-confold install nvidia-driver", "modprobe nvidia"}
	last := -1
	for _, o := range order {
		i := strings.Index(lines[last+1:], o)
		if i < 0 {
			t.Fatalf("%q missing or out of order in:\n%s", o, lines)
		}
		last += i + 1
	}
	if !strings.Contains(tk.Log, "agreed to by cade") {
		t.Errorf("log:\n%s", tk.Log)
	}
	// A new Manager (hardyd-priv restarted) still knows the last task.
	m2 := &Manager{Runner: w.r, Root: w.root}
	if lt := m2.Task(); lt == nil || lt.Kind != TaskNvidiaInstall || lt.State != TaskSucceeded {
		t.Fatalf("last task = %+v", lt)
	}
}

func TestNvidiaInstallFailsWhenNotBuilt(t *testing.T) {
	w := newWorld(t)
	w.r.on("apt-get -y --no-install-recommends -o Dpkg::Options::=--force-confdef", func([]string) {})
	if _, err := w.m.PrepareNvidia(); err != nil {
		t.Fatal(err)
	}
	waitTask(t, w.m)
	_, lic, _ := w.m.LicenceText()
	if _, err := w.m.InstallNvidia(InstallArgs{LicenceSHA256: lic.SHA256, By: "cade"}); err != nil {
		t.Fatal(err)
	}
	tk := waitTask(t, w.m)
	if tk.State != TaskFailed || !strings.Contains(tk.Error, "couldn't be built for this server's kernel (6.12.48+deb13-amd64)") {
		t.Fatalf("task %+v", tk)
	}
	if !w.r.has("dkms autoinstall -k 6.12.48+deb13-amd64") {
		t.Error("no rebuild attempt")
	}
}

func TestNoNVIDIACard(t *testing.T) {
	w := newWorld(t)
	_ = os.RemoveAll(filepath.Join(w.root, "sys"))
	if _, err := w.m.PrepareNvidia(); err != ErrNoNVIDIA {
		t.Fatalf("err = %v", err)
	}
}

func TestInterruptedTask(t *testing.T) {
	w := newWorld(t)
	w.m.saveTask(Task{ID: "x", Kind: TaskNvidiaInstall, State: TaskRunning})
	if tk := w.m.Task(); tk.State != TaskFailed || !strings.Contains(tk.Error, "interrupted") {
		t.Fatalf("task = %+v", tk)
	}
}

func TestVGPUFileNames(t *testing.T) {
	for name, want := range map[string]string{
		"NVIDIA-Linux-x86_64-550.90.05-vgpu-kvm.run": "550.90.05",
		"NVIDIA-Linux-x86_64-570.124-vgpu-kvm.run":   "570.124",
	} {
		if v, err := CheckVGPUFileName(name, "amd64"); err != nil || v != want {
			t.Errorf("%s: %q %v", name, v, err)
		}
	}
	for name, msg := range map[string]string{
		"NVIDIA-Linux-x86_64-550.90.07-grid.run":       "guest (GRID) driver",
		"NVIDIA-Linux-x86_64-470.82-vgpu-kvm.run":      "too old",
		"NVIDIA-Linux-aarch64-550.90.05-vgpu-kvm.run":  "this server is amd64",
		"../NVIDIA-Linux-x86_64-550.90.05-vgpu-kvm.run": "choose NVIDIA's vGPU host driver",
		"NVIDIA-Linux-x86_64-550.90.05.run":            "choose NVIDIA's vGPU host driver",
	} {
		if _, err := CheckVGPUFileName(name, "amd64"); err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestVGPUInstall(t *testing.T) {
	w := newWorld(t)
	m := w.m
	const name = "NVIDIA-Linux-x86_64-550.90.05-vgpu-kvm.run"
	payload := "#!/bin/sh\n# This script was generated using Makeself 2.1.5\nlabel=\"NVIDIA Accelerated Graphics Driver for Linux-x86_64 550.90.05\"\n\x00binary"
	sum := sha256.Sum256([]byte(payload))
	sha := hex.EncodeToString(sum[:])
	upload := UploadDir + "/upload-0123456789abcdef.run"
	w.write(upload, payload)
	w.r.on("sh /var/lib/hardyos-gpu/vgpu/"+name+" --silent --dkms", func([]string) {
		w.write("/lib/modules/6.12.48+deb13-amd64/updates/dkms/nvidia.ko", "ko")
	})
	args := VGPUArgs{Upload: upload, SHA256: sha, FileName: name, By: "cade"}

	bad := args
	bad.Upload = "/etc/shadow"
	if _, err := m.InstallVGPU(bad); err == nil {
		t.Fatal("file outside the upload folder accepted")
	}
	bad = args
	bad.SHA256 = strings.Repeat("0", 64)
	if _, err := m.InstallVGPU(bad); err != nil {
		t.Fatal(err)
	}
	if tk := waitTask(t, m); tk.State != TaskFailed || !strings.Contains(tk.Error, "checksum doesn't match") {
		t.Fatalf("bad hash: %+v", tk)
	}
	if _, err := os.Stat(filepath.Join(w.root, Dir, "vgpu", name)); err == nil {
		t.Fatal("unverified file kept")
	}
	if _, err := m.InstallVGPU(args); err != nil {
		t.Fatal(err)
	}
	tk := waitTask(t, m)
	if tk.State != TaskSucceeded {
		t.Fatalf("install: %+v\n%s", tk, tk.Log)
	}
	if _, err := os.Stat(filepath.Join(w.root, upload)); err == nil {
		t.Error("upload not removed")
	}
	fi, err := os.Stat(filepath.Join(w.root, Dir, "vgpu", name))
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("driver copy: %v %v", fi, err)
	}
	rec, _ := m.load()
	if rec.VGPU == nil || rec.VGPU.Version != "550.90.05" || !rec.VGPU.Installed || rec.VGPU.SHA256 != sha {
		t.Fatalf("record %+v", rec.VGPU)
	}

	// A file that isn't NVIDIA's installer, or doesn't match its name.
	for _, p := range []string{"#!/bin/sh\necho hi\n", "#!/bin/sh\nlabel=\"NVIDIA Accelerated Graphics Driver for Linux-x86_64 535.1\"\n", "\x7fELF"} {
		s := sha256.Sum256([]byte(p))
		w.write(upload, p)
		a := args
		a.SHA256 = hex.EncodeToString(s[:])
		if _, err := m.InstallVGPU(a); err != nil {
			t.Fatal(err)
		}
		if tk := waitTask(t, m); tk.State != TaskFailed || !strings.Contains(tk.Error, "NVIDIA") && !strings.Contains(tk.Error, "match") {
			t.Fatalf("%q: %+v", p, tk)
		}
	}

	// Debian's driver must be replaced knowingly.
	w.r.OnResult("dpkg-query -W -f=${db:Status-Status} nvidia-kernel-dkms", sysexec.Result{Stdout: []byte("installed")})
	w.write(upload, payload)
	if _, err := m.InstallVGPU(args); err == nil || !strings.Contains(err.Error(), "confirm") {
		t.Fatalf("replace not confirmed: %v", err)
	}
}

func TestUpdateHook(t *testing.T) {
	w := newWorld(t)
	m := w.m
	newRoot := "/run/hardyos/update/root"
	w.write(newRoot+"/boot/vmlinuz-6.12.50+deb13-amd64", "k")
	w.write(newRoot+"/lib/modules/6.12.50+deb13-amd64/modules.dep", "")
	w.write(newRoot+"/etc/os-release", "VERSION_CODENAME=trixie\n")

	// Nothing installed: nothing to do (and no chroot).
	if err := m.PrepareNewRoot(context.Background(), newRoot); err != nil {
		t.Fatal(err)
	}
	if w.r.has("chroot") {
		t.Fatal("chroot without a driver")
	}

	rec := &Record{Driver: &Consent{By: "cade", Installed: true, Packages: DriverPackages, LicenceSHA256: strings.Repeat("a", 64)}}
	if err := m.save(rec); err != nil {
		t.Fatal(err)
	}
	built := false
	w.r.on("chroot "+newRoot+" env DEBIAN_FRONTEND=noninteractive apt-get -y", func([]string) {
		if built {
			w.write(newRoot+"/lib/modules/6.12.50+deb13-amd64/updates/dkms/nvidia.ko.xz", "ko")
		}
	})
	err := m.PrepareNewRoot(context.Background(), newRoot)
	if err == nil || !strings.Contains(err.Error(), "couldn't be built for the new version's kernel 6.12.50+deb13-amd64") {
		t.Fatalf("hook: %v", err)
	}
	if !w.r.has("chroot " + newRoot + " dkms autoinstall -k 6.12.50+deb13-amd64") {
		t.Error("no rebuild attempt")
	}
	built = true
	if err := m.PrepareNewRoot(context.Background(), newRoot); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"mount --rbind /dev " + newRoot + "/dev",
		"chroot " + newRoot + " env DEBIAN_FRONTEND=noninteractive apt-get update",
		"chroot " + newRoot + " env DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install nvidia-driver",
		"chroot " + newRoot + " update-initramfs -u -k 6.12.50+deb13-amd64",
		"umount -R -l " + newRoot + "/dev",
	} {
		if !w.r.has(want) {
			t.Errorf("missing %q", want)
		}
	}
	// The agreement and apt sources went into the new system.
	if _, err := os.Stat(filepath.Join(w.root, newRoot, Dir, "state.json")); err != nil {
		t.Error("GPU state not copied")
	}
	if _, err := os.Stat(filepath.Join(w.root, newRoot, toolkitListPath)); err != nil {
		t.Error("toolkit source not written into the new system")
	}
	if err := m.PrepareNewRoot(context.Background(), "relative"); err == nil {
		t.Error("relative root accepted")
	}
}

func TestUpdateHookVGPU(t *testing.T) {
	w := newWorld(t)
	m := w.m
	newRoot := "/run/hardyos/update/root"
	w.write(newRoot+"/boot/vmlinuz-6.12.50+deb13-amd64", "k")
	w.write(newRoot+"/lib/modules/6.12.50+deb13-amd64/modules.dep", "")
	const name = "NVIDIA-Linux-x86_64-550.90.05-vgpu-kvm.run"
	w.write(Dir+"/vgpu/"+name, "#!/bin/sh\n")
	if err := m.save(&Record{VGPU: &VGPUDriver{File: name, Installed: true, Version: "550.90.05"}}); err != nil {
		t.Fatal(err)
	}
	w.r.on("chroot "+newRoot+" sh "+Dir+"/vgpu/"+name, func([]string) {
		w.write(newRoot+"/lib/modules/6.12.50+deb13-amd64/updates/dkms/nvidia.ko", "ko")
	})
	if err := m.PrepareNewRoot(context.Background(), newRoot); err != nil {
		t.Fatal(err)
	}
	if !w.r.has("chroot " + newRoot + " sh /var/lib/hardyos-gpu/vgpu/" + name + " --silent --dkms --kernel-name=6.12.50+deb13-amd64 --skip-module-load") {
		t.Fatalf("commands:\n%s", strings.Join(w.r.Lines(), "\n"))
	}
	if _, err := os.Stat(filepath.Join(w.root, newRoot, Dir, "vgpu", name)); err != nil {
		t.Fatal("driver file not copied into the new system")
	}
}
