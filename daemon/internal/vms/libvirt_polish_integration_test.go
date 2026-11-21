package vms

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// VM polish against the real thing (decisions 410-419), in the CI job
// "Virtual machines (KVM)":
//
//	sudo HARDYOS_VM_INTEGRATION=1 ./vms.test -test.run TestLibvirtPolishIntegration -test.v
//
// It fetches Debian 13's real cloud image through the verified catalog,
// makes a cloud-init VM with sound and the clipboard channel (libvirt
// validates both), boots it, takes a scheduled snapshot, saves it as a
// template, makes and boots a second VM from the template, and builds a
// Windows answer disc.
func TestLibvirtPolishIntegration(t *testing.T) {
	if os.Getenv("HARDYOS_VM_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_VM_INTEGRATION=1 (as root, with ZFS, libvirt and /dev/kvm) to run")
	}
	ctx := context.Background()
	pool := fmt.Sprintf("hvp%d", os.Getpid()%10000)
	img := filepath.Join(t.TempDir(), "pool.img")
	must(t, "truncate", "-s", "16G", img)
	must(t, "zpool", "create", "-f", "-m", "/mnt/"+pool, pool, img)
	t.Cleanup(func() {
		for _, d := range []string{"deb", "deb-copy", "win"} {
			_ = exec.Command("virsh", "-c", "qemu:///system", "destroy", d).Run()
			_ = exec.Command("virsh", "-c", "qemu:///system", "undefine", d, "--nvram", "--tpm").Run()
		}
		_ = exec.Command("zpool", "destroy", "-f", pool).Run()
	})
	must(t, "zfs", "create", pool+"/isos")
	must(t, "chmod", "755", "/mnt/"+pool, "/mnt/"+pool+"/isos")
	if _, err := user.Lookup(ImportUser); err != nil {
		must(t, "useradd", "--system", "--user-group", "--no-create-home", "--shell", "/usr/sbin/nologin", ImportUser)
		t.Cleanup(func() { _ = exec.Command("userdel", ImportUser).Run() })
	}
	m := &Manager{Runner: sysexec.Exec{}, Root: "/", Library: datasetLibrary{ds: pool + "/isos", mp: "/mnt/" + pool + "/isos"}}

	// 1. The verified catalog, against Debian's real SHA512SUMS.
	task, err := m.FetchCatalog(ctx, FetchArgs{Image: CatalogDebian13})
	if err != nil {
		t.Fatal(err)
	}
	waitTask(t, m, task.ID, 10*time.Minute)
	fetched, _ := m.TaskStatus(TaskArgs{ID: task.ID})
	if !strings.HasPrefix(fetched.Digest, "sha512:") || fetched.File != "debian-13-genericcloud-amd64.qcow2" {
		t.Fatalf("fetch = %+v", fetched)
	}
	// Again: reused from the library after hashing it.
	again, err := m.FetchCatalog(ctx, FetchArgs{Image: CatalogDebian13})
	if err != nil {
		t.Fatal(err)
	}
	waitTask(t, m, again.ID, 5*time.Minute)

	// 2. A one-click Debian VM with sound and the clipboard.
	spec := Spec{
		ID: "deb", Name: "Debian", Template: "debian13", OS: "linux", Pool: pool,
		CPU: CPU{Cores: 1, Threads: 1}, Memory: Memory{MB: 1024},
		Firmware: Firmware{Type: FirmwareUEFI},
		Disks:    []Disk{{Name: "disk0", SizeGB: 4, Bus: BusVirtioSCSI, Import: &Import{File: fetched.File, Digest: fetched.Digest}}},
		Media:    []Media{{Kind: MediaCloudInit}},
		NICs:     []NIC{{Mode: NICNAT, Model: "virtio"}},
		Video:    "virtio", Boot: []string{"disk"}, GuestAgent: true, Sound: true, Clipboard: true,
		CloudInit: &CloudInit{User: "cade", Hostname: "deb1", InstallAgent: true},
	}
	if _, err := m.Create(ctx, CreateArgs{Spec: spec, Password: "integration-test"}); err != nil {
		t.Fatal(err)
	}
	imp, err := m.StartImport(ctx, ImportArgs{ID: "deb", Disk: "disk0"})
	if err != nil {
		t.Fatal(err)
	}
	waitTask(t, m, imp.ID, 10*time.Minute)
	xml := must(t, "virsh", "-c", "qemu:///system", "dumpxml", "deb")
	for _, want := range []string{"qemu-vdagent", "<sound model='ich9'>", "<audio id='1' type='none'/>"} {
		if !strings.Contains(xml, want) {
			t.Errorf("libvirt's definition lacks %s:\n%s", want, xml)
		}
	}
	if _, err := m.Start(ctx, "deb"); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "deb", "running")

	// 3. A scheduled snapshot of the running VM.
	if _, err := m.SetSchedule(ctx, SetScheduleArgs{ID: "deb", Schedule: &Schedule{Hourly: 1}}); err != nil {
		t.Fatal(err)
	}
	m.TickSchedules(ctx)
	snaps, _ := m.Snapshots(ctx, "deb")
	if len(snaps) != 1 || snaps[0].Kind != "hourly" {
		t.Fatalf("snapshots = %+v", snaps)
	}
	time.Sleep(20 * time.Second) // let it boot a little
	if _, err := m.Stop(ctx, StopArgs{ID: "deb", Force: true}); err != nil {
		t.Fatal(err)
	}

	// 4. Make a template, then a VM from it, and boot that.
	tt, err := m.MakeTemplate(ctx, MakeTemplateArgs{VM: "deb", ID: "deb-base", Name: "Debian base"})
	if err != nil {
		t.Fatal(err)
	}
	waitTask(t, m, tt.ID, 10*time.Minute)
	tpls, err := m.UserTemplates(ctx)
	if err != nil || len(tpls) != 1 || tpls[0].Spec.UUID != "" {
		t.Fatalf("templates = %+v %v", tpls, err)
	}
	cp := tpls[0].Spec
	cp.ID, cp.Name, cp.Pool, cp.FromTemplate = "deb-copy", "Debian copy", pool, "deb-base"
	cp.Disks[0].Clone = &Clone{Template: "deb-base"}
	cp.Disks[0].SizeGB = 5
	if _, err := m.Create(ctx, CreateArgs{Spec: cp, Password: "integration-test"}); err != nil {
		t.Fatal(err)
	}
	ct, err := m.StartClone(ctx, ImportArgs{ID: "deb-copy", Disk: "disk0"})
	if err != nil {
		t.Fatal(err)
	}
	waitTask(t, m, ct.ID, 10*time.Minute)
	if out := must(t, "zfs", "get", "-H", "-p", "-o", "value", "volsize", pool+"/vms/deb-copy/disk0"); strings.TrimSpace(out) != fmt.Sprint(5<<30) {
		t.Fatalf("the copy's size = %s", out)
	}
	if _, err := m.Start(ctx, "deb-copy"); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "deb-copy", "running")
	if _, err := m.Stop(ctx, StopArgs{ID: "deb-copy", Force: true}); err != nil {
		t.Fatal(err)
	}
	// The template goes first; the VMs keep their disks.
	if err := m.DeleteTemplate(ctx, DeleteTemplateArgs{ID: "deb-base", Confirm: "deb-base"}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"deb-copy", "deb"} {
		if err := m.Delete(ctx, DeleteArgs{ID: id, Confirm: id}); err != nil {
			t.Fatal(err)
		}
	}

	// 5. A Windows answer disc (no Windows needed to make one).
	if err := os.WriteFile("/mnt/"+pool+"/isos/Win11-test.iso", []byte("not really windows"), 0o644); err != nil {
		t.Fatal(err)
	}
	win := Spec{
		ID: "win", Name: "Windows", Template: "windows11", OS: "windows", Pool: pool,
		CPU: CPU{Cores: 2, Threads: 1}, Memory: Memory{MB: 4096},
		Firmware: Firmware{Type: FirmwareUEFI}, // the answer disc doesn't depend on Secure Boot or the TPM
		Disks:    []Disk{{Name: "disk0", SizeGB: 64, Bus: BusVirtioSCSI}},
		Media:    []Media{{Kind: MediaISO, ISO: "Win11-test.iso"}, {Kind: MediaUnattend}},
		NICs:     []NIC{{Mode: NICNAT, Model: "virtio"}},
		Video:    "vga", Boot: []string{"cdrom", "disk"}, GuestAgent: true,
		Unattend: &Unattend{User: "cade", Locale: "en-US", Edition: "Windows 11 Pro"},
	}
	if _, err := m.Create(ctx, CreateArgs{Spec: win, Password: "Windows pass 1", AllowOvercommit: true}); err != nil {
		t.Fatal(err)
	}
	disc := "/mnt/" + pool + "/vms/win/" + unattendFile
	out := filepath.Join(t.TempDir(), "autounattend.xml")
	must(t, "xorriso", "-osirrox", "on", "-indev", disc, "-extract", "/autounattend.xml", out)
	b, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(b), "<Value>Windows 11 Pro</Value>") || strings.Contains(string(b), "Windows pass 1") {
		t.Fatalf("answer file: %v\n%s", err, b)
	}
	if err := m.Delete(ctx, DeleteArgs{ID: "win", Confirm: "win"}); err != nil {
		t.Fatal(err)
	}
}

func waitState(t *testing.T, m *Manager, id, want string) {
	t.Helper()
	for i := 0; i < 60; i++ {
		if m.state(context.Background(), id) == want {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("%s isn't %s (it's %s)", id, want, m.state(context.Background(), id))
}
