package gpu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/syslock"
)

func TestParseSimulationAndPinning(t *testing.T) {
	v := parseSimulation(simulation + "Inst libcuda1:amd64 (1:550.163.01-2 Debian:13/stable [amd64])\nInst bad (x;rm Debian)\n")
	if v["nvidia-driver"] != "550.163.01-2" || v["nvidia-container-toolkit"] != "1.17.8-1" || v["libcuda1"] != "1:550.163.01-2" || v["bad"] != "" {
		t.Fatalf("versions = %v", v)
	}
	got := strings.Join(pinned([]string{"nvidia-driver", "firmware-misc-nonfree"}, v), " ")
	if got != "nvidia-driver=550.163.01-2 firmware-misc-nonfree" {
		t.Fatalf("pinned = %s", got)
	}
}

// The newest downloaded package is chosen by dpkg's order, not by name.
func TestNewestDebUsesDpkg(t *testing.T) {
	w := newWorld(t)
	w.write("/var/cache/apt/archives/nvidia-kernel-support_550.90.07-1_amd64.deb", "old")
	w.write("/var/cache/apt/archives/nvidia-kernel-support_550.163.01-2_amd64.deb", "new")
	// A string sort puts 550.90 after 550.163; dpkg knows better.
	w.r.OnResult("dpkg --compare-versions 550.90.07-1 gt 550.163.01-2", sysexec.Result{ExitCode: 1})
	w.r.OnResult("dpkg --compare-versions 550.163.01-2 gt 550.90.07-1", sysexec.Result{ExitCode: 0})
	p, v, err := newestDeb(context.Background(), w.r, w.root, "nvidia-kernel-support")
	if err != nil || v != "550.163.01-2" || !strings.HasSuffix(p, "550.163.01-2_amd64.deb") {
		t.Fatalf("newest = %s %s %v", p, v, err)
	}
	if !w.r.has("dpkg --compare-versions") {
		t.Fatal("dpkg not asked")
	}
	w.r.OnResult("dpkg --compare-versions 1 eq 2", sysexec.Result{ExitCode: 2})
	if _, err := compareVersions(context.Background(), w.r, "1", "eq", "2"); err == nil {
		t.Fatal("dpkg failure ignored")
	}
	if _, err := compareVersions(context.Background(), w.r, "1;x", "eq", "2"); err == nil {
		t.Fatal("bad version accepted")
	}
}

func installedDriver(t *testing.T, w *world) {
	t.Helper()
	rec := &Record{Driver: &Consent{By: "cade", Installed: true, Packages: DriverPackages, Version: "550.163.01-2",
		Versions: map[string]string{"nvidia-driver": "550.163.01-2"}, LicenceSHA256: strings.Repeat("a", 64)}}
	if err := w.m.save(rec); err != nil {
		t.Fatal(err)
	}
}

func newRootWorld(t *testing.T) (*world, string) {
	w := newWorld(t)
	newRoot := "/run/hardyos/update/root"
	w.write(newRoot+"/boot/vmlinuz-6.12.50+deb13-amd64", "k")
	w.write(newRoot+"/lib/modules/6.12.50+deb13-amd64/modules.dep", "")
	w.write(newRoot+"/etc/os-release", "VERSION_CODENAME=trixie\n")
	return w, newRoot
}

// An update whose packages bring another driver version stops and asks
// for the licence again.
func TestUpdateHookAsksAgainForAnotherVersion(t *testing.T) {
	w, newRoot := newRootWorld(t)
	installedDriver(t, w)
	sim := "chroot " + newRoot + " env DEBIAN_FRONTEND=noninteractive apt-get -s --no-install-recommends install " + strings.Join(DriverPackages, " ")
	w.r.OnResult(sim, sysexec.Result{Stdout: []byte("Inst nvidia-kernel-support (550.180.01-1 Debian:13/stable [amd64])\nInst nvidia-driver (550.180.01-1 Debian [amd64])\n")})
	w.r.OnResult("dpkg --compare-versions 550.180.01-1 eq 550.163.01-2", sysexec.Result{ExitCode: 1})
	err := w.m.PrepareNewRoot(context.Background(), newRoot)
	var ce *ConsentError
	if !errors.As(err, &ce) || !errors.Is(err, ErrConsent) || ce.Offered != "550.180.01-1" || ce.Agreed != "550.163.01-2" {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "agree to its licence") || !strings.Contains(err.Error(), "without the NVIDIA driver this time") {
		t.Fatalf("message: %v", err)
	}
	if w.r.has("apt-get -y --no-install-recommends -o Dpkg::Options::=--force-confdef") {
		t.Fatal("installed a driver version nobody agreed to")
	}

	// The same version: installed pinned.
	w.r.OnResult(sim, sysexec.Result{Stdout: []byte("Inst nvidia-kernel-support (550.163.01-2 Debian [amd64])\nInst nvidia-driver (550.163.01-2 Debian [amd64])\n")})
	w.r.on("chroot "+newRoot+" env DEBIAN_FRONTEND=noninteractive apt-get -y", func([]string) {
		w.write(newRoot+"/lib/modules/6.12.50+deb13-amd64/updates/dkms/nvidia.ko.xz", "ko")
	})
	if err := w.m.PrepareNewRoot(context.Background(), newRoot); err != nil {
		t.Fatal(err)
	}
	if !w.r.has("install nvidia-driver=550.163.01-2 nvidia-kernel-dkms ") {
		t.Fatalf("not pinned:\n%s", strings.Join(w.r.Lines(), "\n"))
	}
}

// A driver that can't be built for the new version doesn't block updates
// for ever: the admin can choose to update without it once.
func TestUpdateWithoutTheDriverThisTime(t *testing.T) {
	w, newRoot := newRootWorld(t)
	installedDriver(t, w)
	err := w.m.PrepareNewRoot(context.Background(), newRoot)
	if err == nil || !strings.Contains(err.Error(), "Update without the NVIDIA driver this time") {
		t.Fatalf("build failure: %v", err)
	}
	if _, err := w.m.SetSkipNextUpdate(true, ""); err == nil {
		t.Fatal("no name accepted")
	}
	if _, err := w.m.SetSkipNextUpdate(true, "cade"); err != nil {
		t.Fatal(err)
	}
	st, _ := w.m.Status(context.Background())
	if st.SkipNextUpdate == nil || st.SkipNextUpdate.By != "cade" {
		t.Fatalf("status %+v", st.SkipNextUpdate)
	}
	before := len(w.r.Lines())
	if err := w.m.PrepareNewRoot(context.Background(), newRoot); err != nil {
		t.Fatal(err)
	}
	for _, l := range w.r.Lines()[before:] {
		if strings.HasPrefix(l, "chroot ") {
			t.Fatalf("built anyway: %s", l)
		}
	}
	// The new version knows its driver needs installing again.
	nm := &Manager{Runner: w.r, Root: filepath.Join(w.root, newRoot)}
	nrec, err := nm.load()
	if err != nil || nrec.ReinstallNeeded == nil || !nrec.ReinstallNeeded.Driver || nrec.Driver.Installed || nrec.SkipNextUpdate != nil {
		t.Fatalf("new record %+v %v", nrec, err)
	}
	// The choice is used up here.
	if rec, _ := w.m.load(); rec.SkipNextUpdate != nil || !rec.Driver.Installed {
		t.Fatalf("host record %+v", rec)
	}
	if err := w.m.PrepareNewRoot(context.Background(), newRoot); err == nil {
		t.Fatal("the skip applied twice")
	}
	// Nothing to skip without a driver.
	w2 := newWorld(t)
	if _, err := w2.m.SetSkipNextUpdate(true, "cade"); err == nil {
		t.Fatal("skip without a driver")
	}
}

func TestToolkitRepoIsPinned(t *testing.T) {
	w := newWorld(t)
	if err := writeSources(w.root, "amd64"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(w.root, toolkitPinPath))
	if err != nil {
		t.Fatal(err)
	}
	pin := string(b)
	specific := strings.Index(pin, "Package: nvidia-container-toolkit nvidia-container-toolkit-base libnvidia-container1 libnvidia-container-tools\nPin: origin \"nvidia.github.io\"\nPin-Priority: 500\n")
	general := strings.Index(pin, "Package: *\nPin: origin \"nvidia.github.io\"\nPin-Priority: -1\n")
	if specific < 0 || general < 0 || specific > general {
		t.Fatalf("pin:\n%s", pin)
	}
	removeSources(w.root)
	if _, err := os.Stat(filepath.Join(w.root, toolkitPinPath)); err == nil {
		t.Fatal("pin left after removing the repository")
	}
}

func vgpuWorld(t *testing.T) (*world, VGPUArgs) {
	w := newWorld(t)
	const name = "NVIDIA-Linux-x86_64-550.90.05-vgpu-kvm.run"
	payload := "#!/bin/sh\nlabel=\"NVIDIA Accelerated Graphics Driver for Linux-x86_64 550.90.05\"\n"
	sum := sha256.Sum256([]byte(payload))
	upload := UploadDir + "/upload-0123456789abcdef.run"
	w.write(upload, payload)
	w.r.on("sh /var/lib/hardyos-gpu/vgpu/"+name+" --silent --dkms", func([]string) {
		w.write("/lib/modules/6.12.48+deb13-amd64/updates/dkms/nvidia.ko", "ko")
	})
	return w, VGPUArgs{Upload: upload, SHA256: hex.EncodeToString(sum[:]), FileName: name, By: "cade", ConfirmVersion: "550.90.05"}
}

func TestVGPUInstallNeedsTypedVersionAndIsLogged(t *testing.T) {
	w, args := vgpuWorld(t)
	for _, v := range []string{"", "550.90", "550.90.06"} {
		a := args
		a.ConfirmVersion = v
		if _, err := w.m.InstallVGPU(a); err == nil || !strings.Contains(err.Error(), "type the driver's version (550.90.05)") {
			t.Fatalf("version %q: %v", v, err)
		}
	}
	if _, ok := KnownVGPU(args.SHA256); ok {
		t.Fatal("the list of known drivers isn't empty by default")
	}
	attested := ""
	AttestVGPU = func(_ context.Context, path, sha string) error { attested = sha; return nil }
	defer func() { AttestVGPU = nil }()
	if _, err := w.m.InstallVGPU(args); err != nil {
		t.Fatal(err)
	}
	tk := waitTask(t, w.m)
	if tk.State != TaskSucceeded || !strings.Contains(tk.Log, "isn't in HardyOS's list of checked NVIDIA vGPU drivers") {
		t.Fatalf("task %+v\n%s", tk, tk.Log)
	}
	if attested != args.SHA256 {
		t.Fatal("attestation hook not called")
	}
	// A second install appends; nothing is rewritten.
	w.write(args.Upload, "#!/bin/sh\nnot it\n")
	bad := args
	if _, err := w.m.InstallVGPU(bad); err != nil {
		t.Fatal(err)
	}
	waitTask(t, w.m)
	b, err := os.ReadFile(filepath.Join(w.root, Dir, InstallLog))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 4 {
		t.Fatalf("log:\n%s", b)
	}
	var e installLogEntry
	_ = json.Unmarshal([]byte(lines[0]), &e)
	if e.Event != "start" || e.By != "cade" || e.SHA256 != args.SHA256 || e.Version != "550.90.05" || e.Known {
		t.Fatalf("first entry %+v", e)
	}
	_ = json.Unmarshal([]byte(lines[3]), &e)
	if e.Event != "failed" || !strings.Contains(e.Error, "checksum doesn't match") {
		t.Fatalf("last entry %+v", e)
	}
	// An attestation that says no stops the install.
	w2, args2 := vgpuWorld(t)
	AttestVGPU = func(context.Context, string, string) error { return errors.New("not confirmed on the console") }
	if _, err := w2.m.InstallVGPU(args2); err != nil {
		t.Fatal(err)
	}
	if tk := waitTask(t, w2.m); tk.State != TaskFailed || !strings.Contains(tk.Error, "wasn't approved") {
		t.Fatalf("attest refused: %+v", tk)
	}
	if w2.r.has("--silent --dkms") {
		t.Fatal("ran an unapproved installer")
	}
}

// GPU tasks never overlap an update or a boot menu change, and a task that
// panics still ends (the busy flag is always cleared).
func TestTasksTakeTheSystemLock(t *testing.T) {
	w := newWorld(t)
	release, err := syslock.TryAcquire("Installing an update")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.m.PrepareNvidia(); !errors.Is(err, syslock.ErrBusy) || !strings.Contains(err.Error(), "Installing an update is in progress") {
		t.Fatalf("during an update: %v", err)
	}
	release()
	tk, err := w.m.start(TaskNvidiaRemove, func(context.Context, *tc) (any, error) { panic("boom") })
	if err != nil {
		t.Fatal(err)
	}
	_ = tk
	if got := waitTask(t, w.m); got.State != TaskFailed || !strings.Contains(got.Error, "internal error: boom") {
		t.Fatalf("panicking task: %+v", got)
	}
	// And it gave the lock back.
	r2, err := syslock.TryAcquire("Installing an update")
	if err != nil {
		t.Fatalf("lock kept: %v", err)
	}
	r2()
}
