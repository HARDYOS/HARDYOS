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

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// The real thing: ZFS, libvirt and KVM. Runs in CI (.github/workflows/
// ci.yml, "Virtual machines (KVM)") as root on a runner with /dev/kvm:
//
//	sudo HARDYOS_VM_INTEGRATION=1 ./vms.test -test.run TestLibvirtIntegration -test.v
//
// It downloads CirrOS (a 20 MB Linux) into an ISO library on a file-backed
// pool, imports it into a VM's zvol, boots it, reads its screen through
// the console handover, snapshots it, rolls it back and deletes it.

const (
	cirrosURL    = "https://github.com/cirros-dev/cirros/releases/download/0.6.2/cirros-0.6.2-x86_64-disk.img"
	cirrosSHA256 = "07e44a73e54c94d988028515403c1ed762055e01b83a767edf3c2b387f78ce00"
)

// datasetLibrary is an ISO library on a plain dataset (the shares code
// isn't under test here).
type datasetLibrary struct {
	ds, mp string
}

func (l datasetLibrary) Folder(context.Context, string, bool) (*Folder, error) {
	t, err := shares.ReadMountTable()
	if err != nil {
		return nil, err
	}
	dev, err := t.VerifyMount(l.mp, l.ds)
	if err != nil {
		return nil, err
	}
	return &Folder{Pool: strings.Split(l.ds, "/")[0], Path: l.mp, Dev: dev}, nil
}

func must(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func waitTask(t *testing.T, m *Manager, id string, limit time.Duration) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		st, err := m.TaskStatus(TaskArgs{ID: id})
		if err != nil {
			t.Fatal(err)
		}
		if st.Done {
			if st.Error != "" {
				t.Fatalf("%s %s: %s", st.Kind, st.File, st.Error)
			}
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("task %s didn't finish in %s", id, limit)
}

func TestLibvirtIntegration(t *testing.T) {
	if os.Getenv("HARDYOS_VM_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_VM_INTEGRATION=1 (as root, with ZFS, libvirt and /dev/kvm) to run")
	}
	ctx := context.Background()
	pool := fmt.Sprintf("hvm%d", os.Getpid()%10000)
	img := filepath.Join(t.TempDir(), "pool.img")
	must(t, "truncate", "-s", "3G", img)
	must(t, "zpool", "create", "-f", "-m", "/mnt/"+pool, pool, img)
	t.Cleanup(func() {
		_ = exec.Command("virsh", "-c", "qemu:///system", "destroy", "cirros").Run()
		_ = exec.Command("virsh", "-c", "qemu:///system", "undefine", "cirros", "--nvram").Run()
		_ = exec.Command("zpool", "destroy", "-f", pool).Run()
	})
	must(t, "zfs", "create", pool+"/isos")
	must(t, "chmod", "755", "/mnt/"+pool, "/mnt/"+pool+"/isos")

	// Imports run qemu-img sandboxed as this user (packaging makes it).
	if _, err := user.Lookup(ImportUser); err != nil {
		must(t, "useradd", "--system", "--user-group", "--no-create-home", "--shell", "/usr/sbin/nologin", ImportUser)
		t.Cleanup(func() { _ = exec.Command("userdel", ImportUser).Run() })
	}

	m := &Manager{Runner: sysexec.Exec{}, Root: "/", Library: datasetLibrary{ds: pool + "/isos", mp: "/mnt/" + pool + "/isos"}}

	caps := m.Capabilities(ctx)
	t.Logf("capabilities: %+v", caps)
	if !caps.KVM || caps.Libvirt == "" {
		t.Fatalf("KVM or libvirt missing: %+v", caps)
	}
	// QEMU is confined by AppArmor, or VMs don't run.
	if !caps.Supported || caps.Security != SecurityModel {
		t.Fatalf("VMs aren't confined: %+v", caps)
	}

	// The ISO library: a download by link, checked by hash.
	task, err := m.StartDownload(ctx, DownloadArgs{URL: cirrosURL, SHA256: cirrosSHA256})
	if err != nil {
		t.Fatal(err)
	}
	waitTask(t, m, task.ID, 5*time.Minute)
	lib, err := m.ListLibrary(ctx)
	if err != nil || len(lib.Files) != 1 || lib.Files[0].Kind != "disk" {
		t.Fatalf("library = %+v %v", lib, err)
	}

	spec := Spec{
		ID: "cirros", Name: "CirrOS", Template: "import", OS: "linux", Pool: pool,
		CPU: CPU{Cores: 1, Threads: 1}, Memory: Memory{MB: 256},
		Firmware: Firmware{Type: FirmwareBIOS},
		Disks:    []Disk{{Name: "disk0", SizeGB: 1, Bus: BusVirtioBlk, Import: &Import{File: lib.Files[0].Name}}},
		NICs:     []NIC{{Mode: NICNAT, Model: "virtio"}},
		Video:    "vga", Boot: []string{"disk"},
	}
	res, err := m.Create(ctx, CreateArgs{Spec: spec})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("created %s (%s)", res.VM.ID, res.VM.UUID)
	imp, err := m.StartImport(ctx, ImportArgs{ID: "cirros", Disk: "disk0"})
	if err != nil {
		t.Fatal(err)
	}
	waitTask(t, m, imp.ID, 5*time.Minute)

	if _, err := m.Start(ctx, "cirros"); err != nil {
		t.Fatal(err)
	}
	// It runs and uses CPU.
	var cpu uint64
	for i := 0; i < 30; i++ {
		if s := m.stats(ctx)["cirros"]; s.State == "running" && s.CPUTime > 0 {
			cpu = s.CPUTime
			break
		}
		time.Sleep(time.Second)
	}
	if cpu == 0 {
		t.Fatalf("the VM isn't running: %+v", m.stats(ctx))
	}

	// Its screen, handed over by root after a one-time token.
	tok, err := m.Console(ctx, ConsoleArgs{ID: "cirros"})
	if err != nil {
		t.Fatal(err)
	}
	f, err := m.ConsoleOpen(ctx, ConsoleOpenArgs{ID: "cirros", Token: tok.Token})
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 12)
	_ = f.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := f.Read(buf); err != nil || !strings.HasPrefix(string(buf), "RFB 003.") {
		t.Fatalf("console said %q (%v)", buf, err)
	}
	f.Close()
	if _, err := m.ConsoleOpen(ctx, ConsoleOpenArgs{ID: "cirros", Token: tok.Token}); err == nil {
		t.Fatal("a console token worked twice")
	}

	// Let it boot a little, snapshot it running (no agent: crash-consistent).
	time.Sleep(15 * time.Second)
	snap, err := m.TakeSnapshot(ctx, SnapshotArgs{ID: "cirros", Label: "booted"})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Consistent {
		t.Error("a snapshot without the guest agent claims to be consistent")
	}
	if _, err := m.Stop(ctx, StopArgs{ID: "cirros", Force: true}); err != nil {
		t.Fatal(err)
	}
	if s := m.state(ctx, "cirros"); s != "stopped" {
		t.Fatalf("state after turning off = %s", s)
	}

	// Grow the disk and add one, then go back to the snapshot: both undone.
	cur, _ := m.Get(ctx, "cirros")
	s2 := cur.Spec
	s2.Disks[0].SizeGB = 2
	s2.Disks = append(s2.Disks, Disk{Name: "disk1", SizeGB: 1, Bus: BusVirtioSCSI})
	if _, err := m.Update(ctx, UpdateArgs{Spec: s2, AllowOvercommit: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Rollback(ctx, RollbackArgs{ID: "cirros", Snapshot: snap.Name, Confirm: "cirros"}); err != nil {
		t.Fatal(err)
	}
	back, _ := m.Get(ctx, "cirros")
	if len(back.Disks) != 1 || back.Disks[0].SizeGB != 1 {
		t.Fatalf("after the rollback: %+v", back.Disks)
	}
	if out := must(t, "zfs", "list", "-H", "-o", "name", "-r", pool+"/vms/cirros"); strings.Contains(out, "disk1") {
		t.Fatalf("disk1 survived the rollback:\n%s", out)
	}
	// And it starts again from the snapshot.
	if _, err := m.Start(ctx, "cirros"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Stop(ctx, StopArgs{ID: "cirros", Force: true}); err != nil {
		t.Fatal(err)
	}
	logs, _ := m.Logs(ctx, "cirros", 20)
	t.Logf("QEMU log:\n%s", logs)

	if err := m.Delete(ctx, DeleteArgs{ID: "cirros", Confirm: "cirros"}); err != nil {
		t.Fatal(err)
	}
	if out := must(t, "zfs", "list", "-H", "-o", "name", "-r", pool); strings.Contains(out, "vms/cirros") {
		t.Fatalf("the VM's datasets are still there:\n%s", out)
	}
	if err := exec.Command("virsh", "-c", "qemu:///system", "dominfo", "cirros").Run(); err == nil {
		t.Fatal("libvirt still knows the VM")
	}
}
