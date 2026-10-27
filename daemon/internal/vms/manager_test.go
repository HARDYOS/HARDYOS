package vms

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/devices"
)

func linuxSpec(t *testing.T) Spec {
	s := fromTemplate(t, "web", "linux")
	s.UUID = ""
	s.NICs[0].MAC = ""
	s.Disks[0].Import = &Import{File: "noble-server-cloudimg-amd64.img"}
	return *s
}

func TestCreateLinuxVM(t *testing.T) {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 1024)
	ctx := context.Background()
	res, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "correct horse battery"})
	if err != nil {
		t.Fatal(err)
	}
	v := res.VM
	if v.ID != "web" || v.State != "stopped" || v.UUID == "" || v.NICs[0].MAC == "" || !strings.HasPrefix(v.NICs[0].MAC, "52:54:00:") {
		t.Fatalf("vm = %+v", v)
	}
	// The password's hash stays with root.
	if !v.PasswordSet || v.CloudInit.PasswordHash != "" {
		t.Fatalf("cloud-init in the view = %+v (set %v)", v.CloudInit, v.PasswordSet)
	}
	for _, l := range e.sim.Lines() {
		if strings.Contains(l, "correct horse") {
			t.Fatalf("the password was on a command line: %s", l)
		}
	}
	for _, want := range []string{
		"zfs create -o org.hardyos:vm=web -o canmount=on -o devices=off -o setuid=off -o exec=off -o quota=45097156608 tank/vms/web",
		"zfs create -s -V 32G -o volblocksize=16K -o org.hardyos:vm=web tank/vms/web/disk0",
		"xorriso -as mkisofs -quiet -volid cidata -joliet -rock -output /mnt/tank/vms/web/cloud-init.iso.new /mnt/tank/vms/web/cloud-init",
		"virsh -c qemu:///system -q define --validate /run/hardyos/vms/web.xml",
		"virsh -c qemu:///system -q autostart --disable web",
	} {
		if !e.sim.has(want) {
			t.Errorf("missing %q in:\n%s", want, strings.Join(e.sim.Lines(), "\n"))
		}
	}
	// The spec on the pool is root's only, and has the hash.
	path := filepath.Join(e.root, "mnt/tank/vms/web", specFile)
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("vm.json: %v %v", fi, err)
	}
	b, _ := os.ReadFile(path)
	var saved Spec
	_ = json.Unmarshal(b, &saved)
	if !strings.HasPrefix(saved.CloudInit.PasswordHash, "$6$") || bytes.Contains(b, []byte("correct horse")) {
		t.Fatalf("saved spec: %s", b)
	}
	x := e.sim.defined["web"]
	if !strings.Contains(x, `<source bridge="br0">`) || !strings.Contains(x, "/mnt/tank/vms/web/cloud-init.iso") {
		t.Fatalf("domain:\n%s", x)
	}
	// The XML file handed to libvirt is gone.
	if _, err := os.Stat(filepath.Join(e.root, "run/hardyos/vms/web.xml")); err == nil {
		t.Error("the domain XML was left behind")
	}

	l, err := e.m.List(ctx)
	if err != nil || len(l.VMs) != 1 || l.VMs[0].ID != "web" {
		t.Fatalf("list = %+v %v", l, err)
	}
}

func TestCreateRefuses(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)

	// No bridge yet: hardyd sets it up first.
	if _, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err == nil || !strings.Contains(err.Error(), "bridge") {
		t.Fatalf("without a bridge: %v", err)
	}
	e.bridge.name = "br0"
	s := linuxSpec(t)
	s.CPU.Cores = 64
	s.Memory.MB = 1 << 20
	_, err := e.m.Create(ctx, CreateArgs{Spec: s, Password: "longenough"})
	var p Problems
	if !errors.As(err, &p) || len(p) < 2 {
		t.Fatalf("too big: %v", err)
	}
	s = linuxSpec(t)
	s.Disks[0].Import.File = "missing.qcow2"
	if _, err := e.m.Create(ctx, CreateArgs{Spec: s, Password: "longenough"}); err == nil || !strings.Contains(err.Error(), "missing.qcow2") {
		t.Fatalf("missing image: %v", err)
	}
	if _, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "short"}); err == nil {
		t.Fatal("a short password was accepted")
	}
	// A hash can't be smuggled in.
	s = linuxSpec(t)
	s.CloudInit.PasswordHash = "$6$x$" + strings.Repeat("b", 86)
	s.CloudInit.SSHKeys = nil
	if _, err := e.m.Create(ctx, CreateArgs{Spec: s}); err == nil || !strings.Contains(err.Error(), "SSH key or a password") {
		t.Fatalf("hash from hardyd: %v", err)
	}
	if _, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err == nil || !strings.Contains(err.Error(), "already a VM") {
		t.Fatalf("duplicate: %v", err)
	}
	// Devices need part D's manager.
	e.m.Devices = nil
	g := fromTemplate(t, "game", "gaming")
	g.UUID = ""
	g.Devices = []devices.Device{{Kind: devices.KindGPU, ID: "0000:01:00.0"}}
	g.Media = nil
	if _, err := e.m.Create(ctx, CreateArgs{Spec: *g}); err == nil || !strings.Contains(err.Error(), "passing devices through") {
		t.Fatalf("devices without part D: %v", err)
	}
}

func gamingVM(t *testing.T, e *testEnv) {
	t.Helper()
	e.bridge.name = "br0"
	e.addISO(t, "Win11_24H2_English_x64.iso", 10)
	if err := os.MkdirAll(e.isoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(e.isoDir, VirtioFile))
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Truncate(VirtioSize)
	f.Close()
	g := fromTemplate(t, "game", "gaming")
	g.UUID = ""
	g.Media = []Media{{Kind: MediaISO, ISO: "Win11_24H2_English_x64.iso"}, {Kind: MediaVirtio}}
	g.Devices = []devices.Device{{Kind: devices.KindGPU, ID: "0000:01:00.0", Primary: true}}
	if _, err := e.m.Create(context.Background(), CreateArgs{Spec: *g}); err != nil {
		t.Fatal(err)
	}
}

func TestStartStopWithDevices(t *testing.T) {
	e := newEnv(t)
	gamingVM(t, e)
	ctx := context.Background()
	if got := e.devs.log(); got != "check game 1" {
		t.Fatalf("create asked part D: %s", got)
	}
	if strings.Contains(e.sim.defined["game"], "<hostdev") {
		t.Fatal("a stopped VM's definition holds its devices")
	}
	res, err := e.m.Start(ctx, "game")
	if err != nil {
		t.Fatal(err)
	}
	if res.VM.State != "running" {
		t.Fatalf("state = %s", res.VM.State)
	}
	if got := e.devs.log(); got != "check game 1,check game 1,prepare game" {
		t.Fatalf("start asked part D: %s", got)
	}
	// The discs are opened up for QEMU, and libvirt is told not to take them.
	if strings.Join(e.granted, ",") != "Win11_24H2_English_x64.iso,"+VirtioFile {
		t.Fatalf("granted = %v", e.granted)
	}
	// It started with the device and was then redefined without it.
	lines := e.sim.Lines()
	var defines, start int
	for i, l := range lines {
		if strings.Contains(l, " define ") {
			defines++
		}
		if strings.HasSuffix(l, " start game") {
			start = i
		}
	}
	if defines < 3 || start == 0 {
		t.Fatalf("commands:\n%s", strings.Join(lines, "\n"))
	}
	if strings.Contains(e.sim.defined["game"], "<hostdev") {
		t.Fatal("the definition kept for later holds the device")
	}

	// A graceful stop asks the guest; devices go back once it's off.
	if _, err := e.m.Stop(ctx, StopArgs{ID: "game"}); err != nil {
		t.Fatal(err)
	}
	if !e.sim.has("virsh -c qemu:///system -q shutdown game --mode agent,acpi") {
		t.Fatal("no shutdown")
	}
	if strings.Contains(e.devs.log(), "release") {
		t.Fatal("devices released before the VM was off")
	}
	e.sim.mu.Lock()
	e.sim.domains["game"].state = "shut off"
	e.sim.mu.Unlock()
	e.m.check(ctx, false)
	if !strings.HasSuffix(e.devs.log(), "release game") {
		t.Fatalf("after the guest shut down: %s", e.devs.log())
	}

	// Force stop releases at once.
	if _, err := e.m.Start(ctx, "game"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Stop(ctx, StopArgs{ID: "game", Force: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(e.devs.log(), "release game") || e.m.state(ctx, "game") != "stopped" {
		t.Fatalf("force stop: %s", e.devs.log())
	}
	if e.bridge.ensured != 0 {
		t.Fatal("the engine created the bridge itself")
	}
}

func TestStartRefusedByDevices(t *testing.T) {
	e := newEnv(t)
	gamingVM(t, e)
	e.devs.checkErr = errors.New("the GPU is in use by Plex")
	if _, err := e.m.Start(context.Background(), "game"); err == nil || !strings.Contains(err.Error(), "Plex") {
		t.Fatalf("start = %v", err)
	}
	if e.sim.has("virsh -c qemu:///system -q start game") {
		t.Fatal("started anyway")
	}
}

func TestUpdate(t *testing.T) {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	ctx := context.Background()
	res, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"})
	if err != nil {
		t.Fatal(err)
	}
	s := res.VM.Spec
	s.Disks[0].SizeGB = 64
	s.Disks = append(s.Disks, Disk{Name: "disk1", SizeGB: 100, Bus: BusVirtioBlk})
	s.Memory.MB = 8192
	up, err := e.m.Update(ctx, UpdateArgs{Spec: s})
	if err != nil {
		t.Fatal(err)
	}
	if !e.sim.has("zfs set volsize=64G tank/vms/web/disk0") || !e.sim.has("zfs create -s -V 100G -o volblocksize=16K -o org.hardyos:vm=web tank/vms/web/disk1") {
		t.Fatalf("commands:\n%s", strings.Join(e.sim.Lines(), "\n"))
	}
	if up.VM.Memory.MB != 8192 || up.VM.Disks[0].Import == nil || up.VM.CloudInit == nil || !up.VM.PasswordSet {
		t.Fatalf("updated = %+v", up.VM)
	}

	// Shrinking, dropping a disk without saying so, and a new pool are refused.
	fresh := func() Spec {
		v, err := e.m.Get(ctx, "web")
		if err != nil {
			t.Fatal(err)
		}
		return v.Spec
	}
	s2 := fresh()
	s2.Disks[0].SizeGB = 10
	s2.Disks = s2.Disks[:1]
	s2.Pool = "fast"
	_, err = e.m.Update(ctx, UpdateArgs{Spec: s2})
	var p Problems
	if !errors.As(err, &p) || !strings.Contains(err.Error(), "can't shrink") || !strings.Contains(err.Error(), "disk1 is missing") || !strings.Contains(err.Error(), "another pool") {
		t.Fatalf("bad update: %v", err)
	}

	// Removing a disk: confirmed, and only while off.
	if _, err := e.m.Start(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	s3 := fresh()
	s3.Disks = s3.Disks[:1]
	if _, err := e.m.Update(ctx, UpdateArgs{Spec: s3, RemoveDisks: []string{"disk1"}}); err == nil || !strings.Contains(err.Error(), "stop the VM") {
		t.Fatalf("remove while running: %v", err)
	}
	// Changing hardware while it runs says to restart.
	s4 := fresh()
	s4.CPU.Cores = 4
	r4, err := e.m.Update(ctx, UpdateArgs{Spec: s4})
	if err != nil || !r4.VM.RestartNeeded || len(r4.Warnings) == 0 {
		t.Fatalf("while running: %+v %v", r4, err)
	}
	if _, err := e.m.Stop(ctx, StopArgs{ID: "web", Force: true}); err != nil {
		t.Fatal(err)
	}
	// Deleting a disk needs the VM's name typed.
	if _, err := e.m.Update(ctx, UpdateArgs{Spec: s3, RemoveDisks: []string{"disk1"}}); err == nil || !strings.Contains(err.Error(), "type the VM's name") {
		t.Fatalf("remove without confirming: %v", err)
	}
	if _, err := e.m.Update(ctx, UpdateArgs{Spec: s3, RemoveDisks: []string{"disk1"}, Confirm: "web"}); err != nil {
		t.Fatal(err)
	}
	if !e.sim.has("zfs destroy -r tank/vms/web/disk1") {
		t.Fatal("disk1 wasn't deleted")
	}
}

func TestSnapshotsAndRollback(t *testing.T) {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	ctx := context.Background()
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	e.m.Now = func() time.Time { return now }
	if _, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Start(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	snap, err := e.m.TakeSnapshot(ctx, SnapshotArgs{ID: "web", Label: "before upgrading"})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Name != "vm-20261026-120000" || !snap.Consistent {
		t.Fatalf("snapshot = %+v", snap)
	}
	lines := strings.Join(e.sim.Lines(), "\n")
	fi, si, ti := strings.Index(lines, "domfsfreeze web"), strings.Index(lines, "zfs snapshot -r"), strings.Index(lines, "domfsthaw web")
	if fi < 0 || si < fi || ti < si {
		t.Fatalf("freeze, snapshot, thaw order:\n%s", lines)
	}
	// Same second: a new name.
	snap2, err := e.m.TakeSnapshot(ctx, SnapshotArgs{ID: "web"})
	if err != nil || snap2.Name != "vm-20261026-120000-1" {
		t.Fatalf("second = %+v %v", snap2, err)
	}
	l, err := e.m.Snapshots(ctx, "web")
	if err != nil || len(l) != 2 || l[1].Label != "before upgrading" && l[0].Label != "before upgrading" {
		t.Fatalf("snapshots = %+v %v", l, err)
	}

	// A disk added after the snapshot goes when rolling back.
	cur, _ := e.m.Get(ctx, "web")
	s := cur.Spec
	s.Disks = append(s.Disks, Disk{Name: "disk1", SizeGB: 10, Bus: BusVirtioSCSI})
	if _, err := e.m.Update(ctx, UpdateArgs{Spec: s}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Rollback(ctx, RollbackArgs{ID: "web", Snapshot: snap.Name, Confirm: "web"}); err == nil || !strings.Contains(err.Error(), "stop the VM") {
		t.Fatalf("rollback while running: %v", err)
	}
	if _, err := e.m.Stop(ctx, StopArgs{ID: "web", Force: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Rollback(ctx, RollbackArgs{ID: "web", Snapshot: snap.Name, Confirm: "nope"}); err == nil {
		t.Fatal("rollback without the name")
	}
	if _, err := e.m.Rollback(ctx, RollbackArgs{ID: "web", Snapshot: "../etc", Confirm: "web"}); err == nil {
		t.Fatal("rollback to a made-up snapshot")
	}
	if _, err := e.m.Rollback(ctx, RollbackArgs{ID: "web", Snapshot: snap.Name, Confirm: "Linux server"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"zfs rollback -r tank/vms/web@" + snap.Name, "zfs rollback -r tank/vms/web/disk0@" + snap.Name, "zfs destroy -r tank/vms/web/disk1"} {
		if !e.sim.has(want) {
			t.Errorf("missing %q", want)
		}
	}
	if err := e.m.DeleteSnapshot(ctx, DeleteSnapshotArgs{ID: "web", Snapshot: snap2.Name}); err == nil || !strings.Contains(err.Error(), "to confirm") {
		t.Fatalf("snapshot deleted without confirming: %v", err)
	}
	if err := e.m.DeleteSnapshot(ctx, DeleteSnapshotArgs{ID: "web", Snapshot: snap2.Name, Confirm: "web"}); err != nil {
		t.Fatal(err)
	}
}

func TestDelete(t *testing.T) {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	ctx := context.Background()
	e.m.Now = func() time.Time { return time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC) }
	for _, keep := range []bool{true, false} {
		if _, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.m.Start(ctx, "web"); err != nil {
			t.Fatal(err)
		}
		if err := e.m.Delete(ctx, DeleteArgs{ID: "web", Confirm: "web", KeepDisks: keep}); err == nil {
			t.Fatal("deleted a running VM")
		}
		if _, err := e.m.Stop(ctx, StopArgs{ID: "web", Force: true}); err != nil {
			t.Fatal(err)
		}
		if err := e.m.Delete(ctx, DeleteArgs{ID: "web", Confirm: "", KeepDisks: keep}); err == nil {
			t.Fatal("deleted without confirmation")
		}
		if err := e.m.Delete(ctx, DeleteArgs{ID: "web", Confirm: "web", KeepDisks: keep}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.m.Get(ctx, "web"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("still there: %v", err)
		}
	}
	if !e.sim.has("zfs rename tank/vms/web tank/vms/web-kept-20261026-120000") || !e.sim.has("zfs destroy -r tank/vms/web") {
		t.Fatalf("commands:\n%s", strings.Join(e.sim.Lines(), "\n"))
	}
}

func TestConsoleTokens(t *testing.T) {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	ctx := context.Background()
	if _, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Console(ctx, ConsoleArgs{ID: "web"}); err == nil {
		t.Fatal("a token for a stopped VM")
	}
	if _, err := e.m.Start(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	// The VM's VNC server, on its socket.
	dir := filepath.Join(e.root, "var/lib/libvirt/qemu/domain-1-web")
	_ = os.MkdirAll(dir, 0o700)
	ln, err := net.Listen("unix", filepath.Join(dir, "vnc.sock"))
	if err != nil {
		t.Skipf("socket path too long here: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("RFB 003.008\n"))
			c.Close()
		}
	}()
	now := time.Now()
	e.m.Now = func() time.Time { return now }
	tok, err := e.m.Console(ctx, ConsoleArgs{ID: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.ConsoleOpen(ctx, ConsoleOpenArgs{ID: "other", Token: tok.Token}); err == nil {
		t.Fatal("a token opened another VM")
	}
	// That used it up.
	if _, err := e.m.ConsoleOpen(ctx, ConsoleOpenArgs{ID: "web", Token: tok.Token}); err == nil {
		t.Fatal("a token worked twice")
	}
	tok, _ = e.m.Console(ctx, ConsoleArgs{ID: "web"})
	f, err := e.m.ConsoleOpen(ctx, ConsoleOpenArgs{ID: "web", Token: tok.Token})
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 12)
	_, _ = f.Read(buf)
	f.Close()
	if string(buf) != "RFB 003.008\n" {
		t.Fatalf("read %q", buf)
	}
	tok, _ = e.m.Console(ctx, ConsoleArgs{ID: "web"})
	now = now.Add(TokenTTL + time.Second)
	if _, err := e.m.ConsoleOpen(ctx, ConsoleOpenArgs{ID: "web", Token: tok.Token}); err == nil {
		t.Fatal("an expired token worked")
	}
	if okSocket("/tmp/evil.sock") || okSocket("/var/lib/libvirt/qemu/../../../etc/x") || !okSocket("/var/lib/libvirt/qemu/domain-1-web/vnc.sock") {
		t.Fatal("socket path check")
	}
}

func TestImportDisk(t *testing.T) {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	ctx := context.Background()
	if _, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	e.stream.info = `{"format":"qcow2","virtual-size":42949672960,"format-specific":{"type":"qcow2","data":{}}}`
	task, err := e.m.StartImport(ctx, ImportArgs{ID: "web", Disk: "disk0"})
	if err != nil {
		t.Fatal(err)
	}
	var st *Task
	for i := 0; i < 200; i++ {
		st, _ = e.m.TaskStatus(TaskArgs{ID: task.ID})
		if st.Done {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !st.Done || st.Error != "" || st.Progress != 100 {
		t.Fatalf("task = %+v", st)
	}
	// qemu-img only saw the private copy (not the share), and wrote the
	// zvol's real device; the copy is gone afterwards.
	if len(e.stream.jobs) != 2 {
		t.Fatalf("jobs = %+v", e.stream.jobs)
	}
	info, conv := e.stream.jobs[0], e.stream.jobs[1]
	if !strings.HasPrefix(info.Image, "/mnt/tank/vms/web/import-") || info.Target != "" || conv.Image != info.Image {
		t.Fatalf("jobs = %+v", e.stream.jobs)
	}
	if strings.Join(info.Args, " ") != "info --output=json "+imageSpec("", info.Image) {
		t.Fatalf("info = %v", info.Args)
	}
	if strings.Join(conv.Args, " ") != `convert -p -n -W -O raw json:{"backing":null,"driver":"qcow2","file":{"driver":"file","filename":"`+info.Image+`"}} /dev/zvol/tank/vms/web/disk0` {
		t.Fatalf("convert = %v", conv.Args)
	}
	if _, err := os.Stat(filepath.Join(e.root, info.Image)); !os.IsNotExist(err) {
		t.Fatalf("the private copy is still there: %v", err)
	}
	// The 40 GB image grew the 32 GB disk.
	if !e.sim.has("zfs set volsize=40G tank/vms/web/disk0") {
		t.Fatal("the disk didn't grow")
	}
	if v, _ := e.m.Get(ctx, "web"); v.Disks[0].SizeGB != 40 {
		t.Fatalf("size = %d", v.Disks[0].SizeGB)
	}

	for _, info := range []string{
		`{"format":"qcow2","virtual-size":1,"backing-filename":"/etc/shadow"}`,
		`{"format":"qcow2","virtual-size":1,"format-specific":{"data":{"data-file":"/dev/sda"}}}`,
		`{"format":"vmdk","virtual-size":1,"format-specific":{"data":{"create-type":"twoGbMaxExtentSparse"}}}`,
		`{"format":"luks","virtual-size":1}`,
	} {
		var ii imageInfo
		_ = json.Unmarshal([]byte(info), &ii)
		if err := checkImage(ii, "/dev/fd/3"); err == nil {
			t.Errorf("accepted %s", info)
		}
	}
}

func TestDownloadToLibrary(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	payload := bytes.Repeat([]byte("hardyos"), 10000)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(payload)
	_ = zw.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/alpine.iso":
			_, _ = w.Write(payload)
		case "/disk.qcow2.gz":
			_, _ = w.Write(gz.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	e.m.HTTP = srv.Client()
	sum := sha256.Sum256(payload)

	wait := func(id string) *Task {
		for i := 0; i < 300; i++ {
			st, _ := e.m.TaskStatus(TaskArgs{ID: id})
			if st.Done {
				return st
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("the download didn't finish")
		return nil
	}
	if _, err := e.m.StartDownload(ctx, DownloadArgs{URL: "http://example.com/a.iso", Pool: "tank"}); err == nil {
		t.Fatal("plain http accepted")
	}
	if _, err := e.m.StartDownload(ctx, DownloadArgs{URL: srv.URL + "/alpine.iso"}); err == nil {
		t.Fatal("no pool and no library: accepted")
	}
	if _, err := e.m.StartDownload(ctx, DownloadArgs{URL: srv.URL + "/notes.txt", Pool: "tank"}); err == nil {
		t.Fatal("a text file accepted")
	}
	// Wrong checksum: deleted.
	task, err := e.m.StartDownload(ctx, DownloadArgs{URL: srv.URL + "/alpine.iso", Pool: "tank", SHA256: strings.Repeat("0", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if st := wait(task.ID); !strings.Contains(st.Error, "checksum") {
		t.Fatalf("wrong checksum: %+v", st)
	}
	if e.lib.created != "tank" {
		t.Fatalf("the library wasn't made on tank: %q", e.lib.created)
	}
	if entries, _ := os.ReadDir(e.isoDir); len(entries) != 0 {
		t.Fatalf("left behind: %v", entries)
	}
	task, err = e.m.StartDownload(ctx, DownloadArgs{URL: srv.URL + "/alpine.iso", Pool: "tank", SHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatal(err)
	}
	if st := wait(task.ID); st.Error != "" {
		t.Fatal(st.Error)
	}
	task, err = e.m.StartDownload(ctx, DownloadArgs{URL: srv.URL + "/disk.qcow2.gz"})
	if err != nil {
		t.Fatal(err)
	}
	if st := wait(task.ID); st.Error != "" {
		t.Fatal(st.Error)
	}
	lib, err := e.m.ListLibrary(ctx)
	if err != nil || len(lib.Files) != 2 || lib.Files[0].Name != "alpine.iso" || lib.Files[1].Name != "disk.qcow2" || lib.Files[1].Size != int64(len(payload)) {
		t.Fatalf("library = %+v %v", lib, err)
	}
	if _, err := e.m.StartDownload(ctx, DownloadArgs{URL: srv.URL + "/alpine.iso"}); err == nil {
		t.Fatal("downloaded over an existing file")
	}
	if err := e.m.DeleteFile(ctx, DeleteFileArgs{Name: "alpine.iso"}); err != nil {
		t.Fatal(err)
	}

	// Without the test client, the server itself is off limits.
	e.m.HTTP = nil
	task, _ = e.m.StartDownload(ctx, DownloadArgs{URL: srv.URL + "/alpine.iso"})
	if st := wait(task.ID); !strings.Contains(st.Error, "only come from the internet") {
		t.Fatalf("local download: %+v", st)
	}
}

func TestLibraryIgnoresLinksAndFolders(t *testing.T) {
	e := newEnv(t)
	e.addISO(t, "real.iso", 4)
	_ = os.Symlink("/etc/passwd", filepath.Join(e.isoDir, "link.iso"))
	_ = os.Mkdir(filepath.Join(e.isoDir, "folder.iso"), 0o755)
	f, _ := e.lib.Folder(context.Background(), "", false)
	l, err := listFolder(f)
	if err != nil || len(l) != 1 || l[0].Name != "real.iso" {
		t.Fatalf("list = %+v %v", l, err)
	}
	if _, err := openFile(f, "link.iso"); err == nil {
		t.Fatal("opened a link")
	}
	if _, err := openFile(f, "../real.iso"); err == nil {
		t.Fatal("opened a path")
	}
}

func TestParsers(t *testing.T) {
	st := parseDomStats("Domain: 'web'\n  state.state=1\n  cpu.time=5000\n  vcpu.current=2\n  balloon.available=4000000\n  balloon.unused=1000000\n\nDomain: 'off'\n  state.state=5\n")
	if st["web"].State != "running" || st["web"].MemoryUsedMB != 2929 || st["off"].State != "stopped" {
		t.Fatalf("stats = %+v", st)
	}
	a := parseDomIfAddr(" Name MAC Protocol Address\n----\n vnet0 52:54:00:00:00:01 ipv4 192.168.1.50/24\n vnet0 52:54:00:00:00:01 ipv6 fe80::1/64\n vnet0 52:54:00:00:00:01 ipv6 2001:db8::5/64\n")
	if strings.Join(a, ",") != "192.168.1.50,2001:db8::5" {
		t.Fatalf("addresses = %v", a)
	}
}

func TestCPUPercent(t *testing.T) {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	ctx := context.Background()
	now := time.Now()
	e.m.Now = func() time.Time { return now }
	if _, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Start(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	e.m.stats(ctx)
	now = now.Add(2 * time.Second)
	// The simulator adds 2 s of CPU time per reading over 2 vCPUs.
	if got := e.m.stats(ctx)["web"].CPUPercent; got < 49 || got > 51 {
		t.Fatalf("cpu = %v", got)
	}
}

func TestOnStartStartsInOrder(t *testing.T) {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	ctx := context.Background()
	for i, id := range []string{"third", "first", "never", "second"} {
		s := linuxSpec(t)
		s.ID = id
		s.Autostart = Autostart{Enabled: id != "never", Order: map[string]int{"first": 1, "second": 2, "third": 3}[id]}
		_ = i
		if _, err := e.m.Create(ctx, CreateArgs{Spec: s, Password: "longenough"}); err != nil {
			t.Fatal(err)
		}
	}
	e.m.OnStart(ctx)
	var order []string
	for _, l := range e.sim.Lines() {
		if id, ok := strings.CutPrefix(l, "virsh -c qemu:///system -q start "); ok {
			order = append(order, id)
		}
	}
	if strings.Join(order, ",") != "first,second,third" {
		t.Fatalf("started %v", order)
	}
}
