package vms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/devices"
)

// Tests for the security review fixes (decisions 134-141).

// rootedStreamer runs the real qemu-img and xz (DirectStreamer) with the
// manager's host paths moved under the test's root.
type rootedStreamer struct {
	root string
	jobs []ImgJob
}

func (r *rootedStreamer) QemuImg(ctx context.Context, j ImgJob) ([]byte, error) {
	r.jobs = append(r.jobs, j)
	args := make([]string, len(j.Args))
	for i, a := range j.Args {
		if j.Image != "" {
			a = strings.ReplaceAll(a, j.Image, filepath.Join(r.root, j.Image))
		}
		if j.Target != "" && a == j.Target {
			a = filepath.Join(r.root, j.Target)
		}
		args[i] = a
	}
	out, err := DirectStreamer{}.QemuImg(ctx, ImgJob{Args: args, OnPct: j.OnPct})
	// What qemu-img reports names the files as they are under the root.
	out = bytes.ReplaceAll(out, []byte(filepath.Join(r.root, j.Image)), []byte(j.Image))
	return out, err
}

func (r *rootedStreamer) Unpack(ctx context.Context, in io.Reader, out io.Writer, on func(int64)) error {
	return DirectStreamer{}.Unpack(ctx, in, out, on)
}

func needTool(t *testing.T, names ...string) {
	t.Helper()
	for _, n := range names {
		if _, err := exec.LookPath(n); err != nil {
			t.Skipf("%s isn't installed", n)
		}
	}
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func waitDone(t *testing.T, m *Manager, id string) *Task {
	t.Helper()
	for i := 0; i < 1000; i++ {
		st, _ := m.TaskStatus(TaskArgs{ID: id})
		if st != nil && st.Done {
			return st
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the task didn't finish")
	return nil
}

// importEnv is a VM "web" whose disk0 imports file from the library,
// with qemu-img for real and the zvol as a 64 MiB file.
func importEnv(t *testing.T, file string) (*testEnv, *rootedStreamer) {
	t.Helper()
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, file, 1)
	rs := &rootedStreamer{root: e.root}
	e.m.Stream = rs
	s := linuxSpec(t)
	s.Disks[0].Import = &Import{File: file}
	if _, err := e.m.Create(context.Background(), CreateArgs{Spec: s, Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(filepath.Join(e.root, "dev/zvol/tank/vms/web/disk0"), 64<<20); err != nil {
		t.Fatal(err)
	}
	return e, rs
}

func importNow(t *testing.T, e *testEnv) *Task {
	t.Helper()
	task, err := e.m.StartImport(context.Background(), ImportArgs{ID: "web", Disk: "disk0"})
	if err != nil {
		t.Fatal(err)
	}
	return waitDone(t, e.m, task.ID)
}

func zvol(t *testing.T, e *testEnv) []byte {
	b, err := os.ReadFile(filepath.Join(e.root, "dev/zvol/tank/vms/web/disk0"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// H1: a qcow2 whose backing file is a secret is refused, and even if the
// check were skipped, qemu-img with HardyOS's arguments reads no byte of it.
func TestImportBackingFileSecret(t *testing.T) {
	needTool(t, "qemu-img")
	secretDir := t.TempDir()
	secret := filepath.Join(secretDir, "secret.raw")
	if err := os.WriteFile(secret, bytes.Repeat([]byte("TOPSECRET"), 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	e, rs := importEnv(t, "evil.qcow2")
	evil := filepath.Join(e.isoDir, "evil.qcow2")
	run(t, "qemu-img", "create", "-q", "-f", "qcow2", "-b", secret, "-F", "raw", evil, "1M")

	st := importNow(t, e)
	if !strings.Contains(st.Error, "backing file") {
		t.Fatalf("import = %+v", st)
	}
	if bytes.Contains(zvol(t, e), []byte("TOPSECRET")) {
		t.Fatal("the secret reached the disk")
	}
	if len(rs.jobs) != 1 || rs.jobs[0].Args[0] != "info" {
		t.Fatalf("qemu-img ran: %+v", rs.jobs)
	}
	// The private copy is gone.
	if m, _ := filepath.Glob(filepath.Join(e.root, "mnt/tank/vms/web/import-*")); len(m) != 0 {
		t.Fatalf("left behind: %v", m)
	}

	// Without the check: the conversion itself never opens the backing file.
	out := filepath.Join(t.TempDir(), "out.raw")
	if err := os.WriteFile(out, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(out, 1<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := (DirectStreamer{}).QemuImg(context.Background(), ImgJob{Args: convertArgs("qcow2", evil, out)}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); bytes.Contains(b, []byte("TOPSECRET")) {
		t.Fatal("convert read the backing file")
	}
}

// H1: an image with real content arrives intact; a VMDK descriptor naming
// another file is refused before qemu-img opens it.
func TestImportRealImage(t *testing.T) {
	needTool(t, "qemu-img")
	e, rs := importEnv(t, "disk.qcow2")
	raw := filepath.Join(t.TempDir(), "src.raw")
	content := bytes.Repeat([]byte("hardyos-disk!"), 80000)
	if err := os.WriteFile(raw, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(e.isoDir, "disk.qcow2")); err != nil {
		t.Fatal(err)
	}
	run(t, "qemu-img", "convert", "-q", "-f", "raw", "-O", "qcow2", raw, filepath.Join(e.isoDir, "disk.qcow2"))
	if st := importNow(t, e); st.Error != "" {
		t.Fatal(st.Error)
	}
	if !bytes.HasPrefix(zvol(t, e), content) {
		t.Fatal("the disk doesn't hold the image")
	}
	if rs.jobs[1].Target != "/dev/zvol/tank/vms/web/disk0" {
		t.Fatalf("target = %q", rs.jobs[1].Target)
	}

	e2, rs2 := importEnv(t, "split.vmdk")
	desc := "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\nRW 2048 FLAT \"/etc/shadow\" 0\n"
	if err := os.WriteFile(filepath.Join(e2.isoDir, "split.vmdk"), []byte(desc), 0o644); err != nil {
		t.Fatal(err)
	}
	if st := importNow(t, e2); !strings.Contains(st.Error, "other files") {
		t.Fatalf("descriptor VMDK = %+v", st)
	}
	if len(rs2.jobs) != 0 {
		t.Fatalf("qemu-img opened a descriptor: %+v", rs2.jobs)
	}
}

// H1/L5: the private copy is bounded by the pool's free space, also when
// unpacking .xz.
func TestImportSizeLimit(t *testing.T) {
	needTool(t, "xz")
	e, _ := importEnv(t, "bomb.raw.xz")
	cmd := exec.Command("xz", "-c")
	cmd.Stdin = bytes.NewReader(make([]byte, 8<<20))
	b, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.isoDir, "bomb.raw.xz"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	e.sim.mu.Lock()
	e.sim.available = spaceReserve + 1<<20 // room for 1 MiB
	e.sim.mu.Unlock()
	if st := importNow(t, e); !strings.Contains(st.Error, "bigger than the space") {
		t.Fatalf("xz bomb = %+v", st)
	}
	// The space limit was raised for the copy and put back after.
	if !e.sim.has("zfs set quota=45098205184 tank/vms/web") || !e.sim.has("zfs set quota=45097156608 tank/vms/web") {
		t.Fatalf("quota:\n%s", strings.Join(e.sim.Lines(), "\n"))
	}
}

func TestCheckImage(t *testing.T) {
	for _, info := range []string{
		`{"format":"qcow2","virtual-size":1,"backing-filename":"/etc/shadow"}`,
		`{"format":"qcow2","virtual-size":1,"format-specific":{"data":{"data-file":"/dev/sda"}}}`,
		`{"format":"vmdk","virtual-size":1,"format-specific":{"data":{"create-type":"twoGbMaxExtentSparse"}}}`,
		`{"format":"vmdk","virtual-size":1,"format-specific":{"data":{"create-type":"monolithicFlat","extents":[{"filename":"/x"}]}}}`,
		`{"format":"vmdk","virtual-size":1,"format-specific":{"data":{"create-type":"monolithicSparse","extents":[{"filename":"/x"},{"filename":"/etc/shadow"}]}}}`,
		`{"format":"luks","virtual-size":1}`,
		`{"format":"raw","virtual-size":999999999999999999}`,
	} {
		var ii imageInfo
		_ = json.Unmarshal([]byte(info), &ii)
		if err := checkImage(ii, "/x"); err == nil {
			t.Errorf("accepted %s", info)
		}
	}
	// The sandbox gets only the job's files, no root, no network.
	p := strings.Join(sandboxProps("hardyos-import", "/mnt/tank/vms/web/import-1.img", "/dev/zd16"), "\n")
	for _, want := range []string{"User=hardyos-import", "PrivateNetwork=yes", "ProtectSystem=strict", "CapabilityBoundingSet=",
		"BindReadOnlyPaths=/mnt/tank/vms/web/import-1.img", "DeviceAllow=/dev/zd16 rw", "PrivateDevices=yes", "TemporaryFileSystem=/mnt:ro", "NoNewPrivileges=yes"} {
		if !strings.Contains(p, want) {
			t.Errorf("sandbox lacks %s", want)
		}
	}
	if _, err := sandboxCommand(context.Background(), "root", "/x", "", "qemu-img"); err == nil {
		t.Error("the sandbox ran as root")
	}
	if _, err := sandboxCommand(context.Background(), "hardyos-import", "/x y", "", "qemu-img"); err == nil {
		t.Error("an odd path went into the sandbox's settings")
	}
}

// M1: vm.json from a pool is checked like a spec from hardyd.
func TestStoredSpecsChecked(t *testing.T) {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	ctx := context.Background()
	for _, id := range []string{"aaa", "bbb", "ccc"} {
		s := linuxSpec(t)
		s.ID = id
		s.Firmware.TPM = true
		if _, err := e.m.Create(ctx, CreateArgs{Spec: s, Password: "longenough"}); err != nil {
			t.Fatal(err)
		}
	}
	edit := func(id string, f func(*Spec)) {
		p := filepath.Join(e.root, "mnt/tank/vms", id, specFile)
		b, _ := os.ReadFile(p)
		var s Spec
		_ = json.Unmarshal(b, &s)
		f(&s)
		b, _ = json.Marshal(s)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var aaa Spec
	edit("aaa", func(s *Spec) { aaa = *s })
	edit("bbb", func(s *Spec) { s.UUID = "../../../../etc" })
	edit("ccc", func(s *Spec) { s.UUID = aaa.UUID })
	l, err := e.m.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.VMs) != 1 || l.VMs[0].ID != "aaa" {
		t.Fatalf("listed %+v", l.VMs)
	}
	if _, err := e.m.libvirtTPM("../x"); err == nil {
		t.Fatal("libvirtTPM took a path")
	}
	edit("bbb", func(s *Spec) { s.UUID = NewUUID(); s.CloudInit.PasswordHash = "$1$weak" })
	if _, err := e.m.Get(ctx, "bbb"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a spec with a bad hash: %v", err)
	}

	// A VM libvirt refuses at start isn't treated as stopped: its TPM
	// state and devices aren't touched.
	tpm := filepath.Join(e.root, "var/lib/libvirt/swtpm", aaa.UUID)
	if err := os.MkdirAll(filepath.Join(tpm, "tpm2"), 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(tpm, "tpm2", "tpm2-00.permall"), "state")
	e.sim.fail["virsh -c qemu:///system -q define"] = "error: invalid"
	e.m.OnStart(ctx)
	if _, err := os.Stat(filepath.Join(e.root, "mnt/tank/vms/aaa", tpmDir)); err == nil {
		t.Fatal("the TPM state of a VM that wasn't defined was saved")
	}
	delete(e.sim.fail, "virsh -c qemu:///system -q define")
	e.m.OnStart(ctx)
	if b, err := os.ReadFile(filepath.Join(e.root, "mnt/tank/vms/aaa", tpmDir, "tpm2", "tpm2-00.permall")); err != nil || string(b) != "state" {
		t.Fatalf("TPM state after a good start: %q %v", b, err)
	}
}

// L2: copying TPM state never follows links.
func TestCopyTreeSkipsLinks(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	secret := filepath.Join(t.TempDir(), "secret")
	write(t, secret, "TOPSECRET")
	write(t, filepath.Join(src, "tpm2", "state"), "tpm")
	if err := os.Chmod(filepath.Join(src, "tpm2", "state"), 0o640); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink(secret, filepath.Join(src, "tpm2", "link"))
	_ = os.Symlink(filepath.Dir(secret), filepath.Join(src, "dirlink"))
	dst := filepath.Join(t.TempDir(), "dst")
	if err := copyTree(src, dst); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "tpm2", "state")); err != nil || string(b) != "tpm" {
		t.Fatalf("state = %q %v", b, err)
	}
	if fi, _ := os.Stat(filepath.Join(dst, "tpm2", "state")); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v", fi.Mode())
	}
	for _, n := range []string{"tpm2/link", "dirlink"} {
		if _, err := os.Lstat(filepath.Join(dst, n)); err == nil {
			t.Errorf("%s was copied", n)
		}
	}
	// An existing destination (a link someone planted) is refused.
	planted := filepath.Join(t.TempDir(), "planted")
	_ = os.Symlink(t.TempDir(), planted)
	if err := copyTree(src, planted); err == nil {
		t.Fatal("copied into a link")
	}
}

// L3: the seed is QEMU's own and nobody else's.
func TestSeedOwnedByQEMU(t *testing.T) {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	if _, err := e.m.Create(context.Background(), CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(e.root, "mnt/tank/vms/web", seedFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("seed = %v %v", fi, err)
	}
}

func vlanVM(t *testing.T, e *testEnv) {
	t.Helper()
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	s := linuxSpec(t)
	s.NICs = []NIC{{Mode: NICVLAN, VLAN: 20, Model: "virtio"}}
	if _, err := e.m.Create(context.Background(), CreateArgs{Spec: s, Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
}

// M2: a VLAN card is on its VLAN only before the VM runs at all.
func TestVLANStartsPaused(t *testing.T) {
	e := newEnv(t)
	vlanVM(t, e)
	ctx := context.Background()
	if _, err := e.m.Start(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	lines := strings.Join(e.sim.Lines(), "\n")
	si, ai, ri := strings.Index(lines, "start web --paused"), strings.Index(lines, "bridge vlan add"), strings.Index(lines, "resume web")
	if si < 0 || ai < si || ri < ai {
		t.Fatalf("order:\n%s", lines)
	}
	v, _ := e.m.Get(ctx, "web")
	tap := tapName(v.UUID, 0)
	if got := e.sim.vlans[tap]; len(got) != 1 || got[0] != 20 || e.sim.pvid[tap] != 20 {
		t.Fatalf("port VLANs = %v pvid %d", got, e.sim.pvid[tap])
	}
	if _, err := e.m.Stop(ctx, StopArgs{ID: "web", Force: true}); err != nil {
		t.Fatal(err)
	}

	// The bridge ignoring the VLAN, or not filtering at all: turned off.
	for _, broken := range []func(){
		func() { e.sim.vlanAdd = "20" },
		func() { e.sim.vlanAdd = ""; e.sim.filtering = 0 },
	} {
		broken()
		if _, err := e.m.Start(ctx, "web"); err == nil || !strings.Contains(err.Error(), "VLAN") {
			t.Fatalf("start = %v", err)
		}
		if s := e.m.state(ctx, "web"); s != "stopped" {
			t.Fatalf("state after a failed VLAN = %s", s)
		}
	}
	// A VM left paused (a start cut short) isn't resumed onto the wrong network.
	e.sim.domains["web"].state = "paused"
	if _, err := e.m.Start(ctx, "web"); err == nil {
		t.Fatal("resumed without its VLAN")
	}
}

// M3: cards on the home network can't spoof unless allowed; NAT cards
// and routers are left alone.
func TestSpoofingFilter(t *testing.T) {
	s := fromTemplate(t, "web", "linux")
	s.NICs = append(s.NICs, NIC{Mode: NICNAT, Model: "virtio", MAC: "52:54:00:aa:bb:cc"}, NIC{Mode: NICVLAN, VLAN: 5, Model: "virtio", MAC: "52:54:00:aa:bb:cd", AllowSpoofing: true})
	x, err := DomainXML(s, x86, testPaths(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(x), `<filterref filter="clean-traffic">`); n != 1 {
		t.Fatalf("%d filters:\n%s", n, x)
	}
	r := fromTemplate(t, "fw", "opnsense")
	if x, _ := DomainXML(r, x86, testPaths(), nil); strings.Contains(string(x), "filterref") {
		t.Fatal("the router template's cards are filtered")
	}

	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	if _, err := e.m.Create(context.Background(), CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	e.sim.filters = false
	if _, err := e.m.Start(context.Background(), "web"); err == nil || !strings.Contains(err.Error(), "clean-traffic") {
		t.Fatalf("start without the filter = %v", err)
	}
	if c := e.m.Capabilities(context.Background()); c.SpoofingFilter {
		t.Fatal("capabilities claim the filter")
	}
}

// M4: no AppArmor confinement, no VMs.
func TestConfinementRequired(t *testing.T) {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	ctx := context.Background()
	if c := e.m.Capabilities(ctx); !c.Supported || c.Security != "apparmor" {
		t.Fatalf("caps = %+v", c)
	}
	if _, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	e.sim.secmodels = []string{"dac"}
	c := e.m.Capabilities(ctx)
	if c.Supported || !strings.Contains(c.Problem, "AppArmor") {
		t.Fatalf("caps = %+v", c)
	}
	if _, err := e.m.Start(ctx, "web"); err == nil || !strings.Contains(err.Error(), "AppArmor") {
		t.Fatalf("start = %v", err)
	}
}

// M5: disks must fit the pool unless overcommitting is allowed, and each
// VM's dataset has a space limit that follows its disks.
func TestSpaceLimits(t *testing.T) {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	ctx := context.Background()
	e.sim.available = 20 << 30
	if _, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err == nil || !strings.Contains(err.Error(), "overcommit") {
		t.Fatalf("create on a small pool = %v", err)
	}
	if _, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough", AllowOvercommit: true}); err != nil {
		t.Fatal(err)
	}
	v, _ := e.m.Get(ctx, "web")
	s := v.Spec
	s.Disks[0].SizeGB = 64
	if _, err := e.m.Update(ctx, UpdateArgs{Spec: s}); err == nil {
		t.Fatal("grew past the free space")
	}
	e.sim.available = 1 << 40
	if _, err := e.m.Update(ctx, UpdateArgs{Spec: s}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Join(e.sim.Lines(), "\n")
	qi, gi := strings.Index(lines, "zfs set quota=88046829568 tank/vms/web"), strings.Index(lines, "zfs set volsize=64G")
	if qi < 0 || gi < qi {
		t.Fatalf("the limit didn't grow before the disk:\n%s", lines)
	}
	// An image bigger than any VM disk is refused.
	var ii imageInfo
	ii.Format, ii.VirtualSize = "raw", int64(MaxDiskGB+1)<<30
	if err := checkImage(ii, "/x"); err == nil {
		t.Fatal("a too-big image was accepted")
	}
}

// L1: a disc that became a link, or a library shared over NFS, is refused.
func TestMediaVerified(t *testing.T) {
	e := newEnv(t)
	e.addISO(t, "a.iso", 4)
	f, _ := e.lib.Folder(context.Background(), "", false)
	if err := verifyPath(f, "a.iso"); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(e.isoDir, "a.iso")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink("/etc/passwd", p)
	if err := verifyPath(f, "a.iso"); err == nil {
		t.Fatal("a link passed")
	}

	e = newEnv(t)
	gamingVM(t, e)
	e.lib.nfs = true
	if _, err := e.m.Start(context.Background(), "game"); err == nil || !strings.Contains(err.Error(), "NFS") {
		t.Fatalf("start with an NFS library = %v", err)
	}
	e.lib.nfs = false
	if _, err := e.m.Start(context.Background(), "game"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(e.verified, ",") != "Win11_24H2_English_x64.iso,"+VirtioFile {
		t.Fatalf("verified %v", e.verified)
	}
}

// L4: downloads never go to local, translated or tunnelled addresses, nor
// to the server's own networks, and stalled ones end.
func TestDownloadGuard(t *testing.T) {
	for _, a := range []string{"64:ff9b::a00:1", "2002:c0a8:101::1", "240.1.2.3", "255.255.255.255", "198.18.0.1", "100.64.1.1",
		"::ffff:10.0.0.1", "::10.0.0.1", "fd00::1", "fe80::1", "2001:0:4136:e378::1", "127.0.0.1", "0.1.2.3"} {
		if !localAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s isn't treated as local", a)
		}
	}
	for _, a := range []string{"151.101.1.1", "2a04:4e42::1"} {
		if localAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s is treated as local", a)
		}
	}
	lan := []netip.Prefix{netip.MustParsePrefix("203.0.114.0/24")}
	if !onPrefixes(netip.MustParseAddr("203.0.114.9"), lan) || onPrefixes(netip.MustParseAddr("203.0.115.9"), lan) {
		t.Fatal("on-link check")
	}
	m := &Manager{onLink: func() []netip.Prefix { return lan }}
	_, err := m.client().Get("https://203.0.114.9/x.iso")
	if err == nil || !strings.Contains(err.Error(), "own network") {
		t.Fatalf("on-link download = %v", err)
	}

	a, b := net.Pipe()
	defer b.Close()
	c := &idleConn{Conn: a, idle: 50 * time.Millisecond}
	start := time.Now()
	if _, err := c.Read(make([]byte, 1)); err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("a stalled read = %v", err)
	}
}

// L6: a freeze that fails is still followed by a thaw.
func TestThawAfterFailedFreeze(t *testing.T) {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	ctx := context.Background()
	if _, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Start(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	e.sim.fail["virsh -c qemu:///system -q domfsfreeze"] = "error: timed out"
	sn, err := e.m.TakeSnapshot(ctx, SnapshotArgs{ID: "web"})
	if err != nil || sn.Consistent {
		t.Fatalf("snapshot = %+v %v", sn, err)
	}
	if !e.sim.has("virsh -c qemu:///system -q domfsthaw web") {
		t.Fatal("no thaw after a failed freeze")
	}
}

// L7: VM locks are only taken for valid names and don't pile up.
func TestLocksDontPileUp(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for _, id := range []string{"../x", "nope", "a-very-long-name-that-is-still-fine", strings.Repeat("x", 100)} {
		_, _ = e.m.Start(ctx, id)
		_, _ = e.m.Stop(ctx, StopArgs{ID: id})
		_ = e.m.Delete(ctx, DeleteArgs{ID: id})
		_, _ = e.m.TakeSnapshot(ctx, SnapshotArgs{ID: id})
	}
	if n := e.m.lockCount(); n != 0 {
		t.Fatalf("%d locks left", n)
	}
	if _, err := e.m.Start(ctx, "../x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("start of a bad name = %v", err)
	}
}

// L10: device fragments are PCI, USB or mdev passthrough only, with ROM
// files only from HardyOS's ROM folder.
func TestCheckFragmentStrict(t *testing.T) {
	good := []string{
		mustFrag(t)(devices.HostdevPCI("0000:01:00.0", RomRunDir+"/abc.rom")),
		mustFrag(t)(devices.HostdevMdev("6f1c2a9e-3b4d-4c5e-8f90-a1b2c3d4e5f6")),
		mustFrag(t)(devices.HostdevUSBByID("1234", "abcd")),
		mustFrag(t)(devices.HostdevUSBByAddress(1, 4)),
	}
	for _, f := range good {
		if _, err := checkFragment(f, RomRunDir); err != nil {
			t.Errorf("refused %s: %v", f, err)
		}
	}
	for _, f := range []string{
		`<hostdev mode='capabilities' type='storage'><source><block>/dev/sda</block></source></hostdev>`,
		`<hostdev mode='subsystem' type='scsi'><source><adapter name='scsi_host0'/></source></hostdev>`,
		`<hostdev mode='subsystem' type='pci'><source><address domain='0' bus='1' slot='0' function='0'/></source><rom file='/etc/shadow'/></hostdev>`,
		`<hostdev mode='subsystem' type='pci'><rom file='/run/hardyos-roms/../../etc/shadow'/></hostdev>`,
		`<hostdev mode='subsystem' type='pci'><source><address domain='0'/></source><qemu:commandline/></hostdev>`,
		`<hostdev mode='subsystem' type='pci'><source><file path='/x'/></source></hostdev>`,
		`<hostdev mode='subsystem' type='pci' onboot='x'></hostdev>`,
		`<hostdev mode='subsystem' type='pci'><hostdev mode='subsystem' type='pci'/></hostdev>`,
	} {
		if _, err := checkFragment(f, RomRunDir); err == nil {
			t.Errorf("accepted %s", f)
		}
	}
}

func mustFrag(t *testing.T) func(string, error) string {
	return func(s string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
}

// L12: VMs on the private network may only ask the server for DHCP and DNS.
func TestNATGuard(t *testing.T) {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	ctx := context.Background()
	s := linuxSpec(t)
	s.NICs = []NIC{{Mode: NICNAT, Model: "virtio"}}
	if _, err := e.m.Create(ctx, CreateArgs{Spec: s, Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Start(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"iptables -w -A HARDYOS-VMNAT -p udp --dport 67 -j ACCEPT",
		"iptables -w -A HARDYOS-VMNAT -p udp --dport 53 -j ACCEPT",
		"iptables -w -A HARDYOS-VMNAT -j DROP",
		"ip6tables -w -A HARDYOS-VMNAT -j DROP",
		"iptables -w -C INPUT -i virbr0 -j HARDYOS-VMNAT",
	} {
		if !e.sim.has(want) {
			t.Errorf("missing %q", want)
		}
	}
	e.sim.fail["iptables -w -F"] = "iptables: no chain"
	_, _ = e.m.Stop(ctx, StopArgs{ID: "web", Force: true})
	if _, err := e.m.Start(ctx, "web"); err == nil {
		t.Fatal("started without the guard")
	}
}
