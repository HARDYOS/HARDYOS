package vms

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/devices"
)

// fakeBackend is part B's sanclient as the VM engine sees it.
type fakeBackend struct {
	att map[string]*AttachedStorage
}

func (b *fakeBackend) Name() string { return BackendCluster }
func (b *fakeBackend) List(context.Context) ([]string, error) {
	var out []string
	for id := range b.att {
		out = append(out, id)
	}
	return out, nil
}
func (b *fakeBackend) Locate(_ context.Context, id string) (*AttachedStorage, error) {
	a, ok := b.att[id]
	if !ok {
		return nil, ErrNotFound
	}
	return a, nil
}

const testWWN = "/dev/disk/by-id/wwn-0x6001405a1b2c3d4e5f60718293a4b5c6"

// clusterEnv has one cluster VM "web" attached under generation 3.
func clusterEnv(t *testing.T) (*testEnv, *Spec) {
	t.Helper()
	e := newEnv(t)
	e.bridge.name = "br0"
	s := fromTemplate(t, "web", "linux")
	s.CPUModel = "x86-64-v2"
	dir := "/mnt/hc/tank/vms/web"
	b, _ := json.Marshal(s)
	write(t, filepath.Join(e.root, dir, specFile), string(b))
	e.m.Backend = &fakeBackend{att: map[string]*AttachedStorage{
		"web": {Backend: BackendCluster, StateDir: dir, Disks: map[string]string{"disk0": testWWN}, Generation: 3},
	}}
	return e, s
}

func TestClusterVMStartsOnlyWithItsGeneration(t *testing.T) {
	e, _ := clusterEnv(t)
	ctx := context.Background()
	if _, err := e.m.Start(ctx, "web"); !errors.Is(err, ErrClusterPlaced) {
		t.Fatalf("a plain start of a cluster VM: %v", err)
	}
	if _, err := e.m.ClusterStart(ctx, ClusterStartArgs{ID: "web", Generation: 2}); !errors.Is(err, ErrGeneration) {
		t.Fatalf("a start with a stale generation: %v", err)
	}
	if _, err := e.m.ClusterStart(ctx, ClusterStartArgs{ID: "web"}); !errors.Is(err, ErrGeneration) {
		t.Fatalf("a start without a generation: %v", err)
	}
	if _, err := e.m.ClusterStart(ctx, ClusterStartArgs{ID: "web", Generation: 3}); err != nil {
		t.Fatal(err)
	}
	x := e.sim.defined["web"]
	for _, want := range []string{`dev="` + testWWN + `"`, `error_policy="stop"`, `rerror_policy="stop"`, `cache="none"`,
		`<model fallback="forbid">x86-64-v2</model>`, `mode="custom"`, `/mnt/hc/tank/vms/web/nvram.fd`} {
		if !strings.Contains(x, want) {
			t.Errorf("the cluster VM's XML lacks %s:\n%s", want, x)
		}
	}
	if strings.Contains(x, "/dev/zvol/") {
		t.Error("a cluster VM's disk points at a local zvol")
	}
	l, err := e.m.ClusterStatus(ctx)
	if err != nil || len(l) != 1 || l[0].State != "running" || l[0].Generation != 3 || !l[0].Attached {
		t.Fatalf("cluster status: %+v %v", l, err)
	}
	v, err := e.m.Get(ctx, "web")
	if err != nil || v.Backend != BackendCluster || v.Generation != 3 {
		t.Fatalf("view: %+v %v", v, err)
	}
}

func TestClusterVMStorageIsTheStorageServers(t *testing.T) {
	e, s := clusterEnv(t)
	ctx := context.Background()
	if _, err := e.m.TakeSnapshot(ctx, SnapshotArgs{ID: "web", Label: "x"}); !errors.Is(err, ErrClusterStorage) {
		t.Fatalf("snapshot: %v", err)
	}
	if err := e.m.Delete(ctx, DeleteArgs{ID: "web", Confirm: s.Name}); !errors.Is(err, ErrClusterStorage) {
		t.Fatalf("delete: %v", err)
	}
	if _, err := e.m.Snapshots(ctx, "web"); !errors.Is(err, ErrClusterStorage) {
		t.Fatalf("snapshots: %v", err)
	}
	bigger := *s
	bigger.Disks = []Disk{{Name: "disk0", SizeGB: s.Disks[0].SizeGB + 10, Bus: s.Disks[0].Bus}}
	if _, err := e.m.Update(ctx, UpdateArgs{Spec: bigger}); !errors.Is(err, ErrClusterStorage) {
		t.Fatalf("growing a disk: %v", err)
	}
}

func TestClusterVMStateFolderMustBeUnderMountRoot(t *testing.T) {
	e, _ := clusterEnv(t)
	e.m.Backend.(*fakeBackend).att["web"].StateDir = "/etc"
	if l := e.m.clusterStored(context.Background()); len(l) != 0 {
		t.Fatalf("a state folder outside /mnt/hc was used: %+v", l)
	}
	e.m.Backend.(*fakeBackend).att["web"].StateDir = "/mnt/hc/tank/vms/web"
	e.m.Backend.(*fakeBackend).att["web"].Disks["disk0"] = "/dev/sda"
	if l := e.m.clusterStored(context.Background()); len(l) != 0 {
		t.Fatal("a host disk was accepted as a cluster VM's disk")
	}
}

func TestClusterForceStopWithoutStorage(t *testing.T) {
	e, _ := clusterEnv(t)
	ctx := context.Background()
	if _, err := e.m.ClusterStart(ctx, ClusterStartArgs{ID: "web", Generation: 3}); err != nil {
		t.Fatal(err)
	}
	// A fence took the storage away: the domain still runs and is listed
	// as stale, and a forced stop works without the storage.
	delete(e.m.Backend.(*fakeBackend).att, "web")
	l, err := e.m.ClusterStatus(ctx)
	if err != nil || len(l) != 1 || l[0].Attached {
		t.Fatalf("a stale domain should be listed unattached: %+v %v", l, err)
	}
	if _, err := e.m.ClusterStop(ctx, ClusterStopArgs{ID: "web", Force: true, Undefine: true}); err != nil {
		t.Fatal(err)
	}
	if d := e.sim.domains["web"]; d != nil && d.state == "running" {
		t.Fatal("the stale VM still runs")
	}
}

// incoming dresses a rendering up the way libvirt sends a running domain.
func incoming(x string) string {
	x = strings.Replace(x, `<domain type="kvm">`, `<domain type="kvm" id="7">`, 1)
	x = strings.Replace(x, "<devices>", "<devices>\n    <emulator>/usr/bin/qemu-system-x86_64</emulator>", 1)
	x = strings.Replace(x, "</devices>", "  <audio id=\"1\" type=\"none\"></audio>\n  </devices>\n  <seclabel type=\"dynamic\" model=\"apparmor\" relabel=\"yes\"><label>libvirt-x</label></seclabel>\n  <resource><partition>/machine</partition></resource>", 1)
	return x
}

func renderWeb(t *testing.T) []byte {
	t.Helper()
	s := fromTemplate(t, "web", "linux")
	s.CPUModel = "x86-64-v2"
	s.Media = nil
	s.CloudInit = nil
	p := testPaths()
	p.StateDir = "/mnt/hc/tank/vms/web"
	p.Cluster = true
	p.Disks = map[string]string{"disk0": testWWN}
	x, err := DomainXML(s, testArch(t), p, nil)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func testArch(t *testing.T) ArchInfo {
	a, ok := ArchFor("amd64")
	if !ok {
		t.Fatal("no amd64")
	}
	return a
}

func TestCheckMigrationXMLAcceptsLibvirtsAdditions(t *testing.T) {
	exp := renderWeb(t)
	if err := CheckMigrationXML(exp, exp); err != nil {
		t.Fatalf("the rendering itself: %v", err)
	}
	in := incoming(string(exp))
	// libvirt reports memory in KiB.
	mem := memRE.FindStringSubmatch(in)
	if mem == nil {
		t.Fatal("no memory element")
	}
	mib, _ := strconv.Atoi(mem[1])
	in = strings.Replace(in, mem[0], `<memory unit="KiB">`+strconv.Itoa(mib*1024)+`</memory>`, 1)
	if err := CheckMigrationXML([]byte(in), exp); err != nil {
		t.Fatalf("libvirt's view of the same domain: %v\n%s", err, in)
	}
}

func TestCheckMigrationXMLRefuses(t *testing.T) {
	exp := renderWeb(t)
	base := incoming(string(exp))
	cases := map[string]func(string) string{
		"another disk": func(x string) string {
			return strings.Replace(x, "</devices>", `<disk type="block" device="disk"><driver name="qemu" type="raw"/><source dev="/dev/sda"/><target dev="sdz" bus="scsi"/></disk></devices>`, 1)
		},
		"a disk's source": func(x string) string {
			return strings.Replace(x, testWWN, "/dev/disk/by-id/wwn-0x6001405ffffffffffffffffffffffff0", 1)
		},
		"a host device": func(x string) string {
			return strings.Replace(x, "</devices>", `<hostdev mode="subsystem" type="pci"><source><address domain="0" bus="1" slot="0" function="0"/></source></hostdev></devices>`, 1)
		},
		"a file system share": func(x string) string {
			return strings.Replace(x, "</devices>", `<filesystem type="mount"><source dir="/"/><target dir="root"/></filesystem></devices>`, 1)
		},
		"QEMU arguments": func(x string) string {
			x = strings.Replace(x, `<domain type="kvm" id="7">`, `<domain type="kvm" id="7" xmlns:qemu="http://libvirt.org/schemas/domain/qemu/1.0">`, 1)
			return strings.Replace(x, "</domain>", `<qemu:commandline><qemu:arg value="-s"/></qemu:commandline></domain>`, 1)
		},
		"another emulator": func(x string) string {
			return strings.Replace(x, "/usr/bin/qemu-system-x86_64", "/tmp/qemu-system-x86_64", 1)
		},
		"unconfined": func(x string) string {
			return strings.Replace(x, `type="dynamic" model="apparmor" relabel="yes"`, `type="none"`, 1)
		},
		"another name": func(x string) string { return strings.Replace(x, "<name>web</name>", "<name>evil</name>", 1) },
		"more memory": func(x string) string {
			return memRE.ReplaceAllString(x, `<memory unit="MiB">999999</memory>`)
		},
		"host CPU": func(x string) string { return strings.Replace(x, `mode="custom"`, `mode="host-passthrough"`, 1) },
		"no traffic filter": func(x string) string {
			return strings.Replace(x, `<filterref filter="clean-traffic"></filterref>`, "", 1)
		},
		"another MAC": func(x string) string { return strings.Replace(x, "52:54:00:12:34:56", "52:54:00:66:66:66", 1) },
		"console on the LAN": func(x string) string {
			return strings.Replace(x, `<listen type="socket"></listen>`, `<listen type="address" address="0.0.0.0"></listen>`, 1)
		},
		"kernel boot":   func(x string) string { return strings.Replace(x, "</os>", "<kernel>/boot/vmlinuz</kernel></os>", 1) },
		"another NVRAM": func(x string) string { return strings.Replace(x, "/mnt/hc/tank/vms/web/nvram.fd", "/etc/shadow", 1) },
		"a network disk": func(x string) string {
			return strings.Replace(x, `<source dev="`+testWWN+`">`, `<source protocol="nbd" name="x"><host name="evil"/>`, 1)
		},
		"a directive": func(x string) string { return `<!DOCTYPE domain [<!ENTITY x "y">]>` + x },
	}
	for name, f := range cases {
		x := f(base)
		if x == base {
			t.Errorf("%s: the test didn't change anything", name)
			continue
		}
		if err := CheckMigrationXML([]byte(x), exp); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMigrationAdmission(t *testing.T) {
	e, s := clusterEnv(t)
	ctx := context.Background()
	r, w, _ := os.Pipe()
	defer w.Close()
	e.m.MigrateConnector = func(context.Context) (*os.File, error) { return r, nil }
	token := strings.Repeat("ab", 16)
	if _, err := e.m.MigrateAccept(ctx, MigrateAcceptArgs{VM: "web", From: "c1", Token: token, DeadlineSec: 60, Generation: 2}); !errors.Is(err, ErrGeneration) {
		t.Fatalf("an admission for another generation: %v", err)
	}
	if _, err := e.m.MigrateAccept(ctx, MigrateAcceptArgs{VM: "web", From: "c1", Token: "short", DeadlineSec: 60, Generation: 3}); err == nil {
		t.Fatal("a bad token was accepted")
	}
	f, err := e.m.MigrateAccept(ctx, MigrateAcceptArgs{VM: "web", From: "c1", Token: token, DeadlineSec: 60, Generation: 3})
	if err != nil || f == nil {
		t.Fatalf("accept: %v", err)
	}
	rules, err := os.ReadFile(filepath.Join(e.root, PolkitRulesDir, polkitAllowFile))
	if err != nil || !strings.Contains(string(rules), `"web"`) || !strings.Contains(string(rules), s.UUID) {
		t.Fatalf("the per-migration rule: %s %v", rules, err)
	}
	st, _ := e.m.find(ctx, "web")
	exp, err := e.m.expectedXML(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.m.MigrateCheck(ctx, MigrateCheckArgs{VM: "web", XML: incoming(string(exp))}); err != nil {
		t.Fatalf("the admitted VM's XML: %v", err)
	}
	if err := e.m.MigrateCheck(ctx, MigrateCheckArgs{VM: "other", XML: incoming(string(exp))}); err == nil {
		t.Fatal("a VM that wasn't admitted passed the hook")
	}
	bad := strings.Replace(incoming(string(exp)), "</devices>", `<hostdev mode="subsystem" type="pci"></hostdev></devices>`, 1)
	if err := e.m.MigrateCheck(ctx, MigrateCheckArgs{VM: "web", XML: bad}); err == nil {
		t.Fatal("a changed XML passed the hook")
	}
	if err := e.m.MigrateEnd(ctx, MigrateEndArgs{VM: "web", Token: token}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.root, PolkitRulesDir, polkitAllowFile)); !os.IsNotExist(err) {
		t.Fatal("the per-migration rule outlived the migration")
	}
	if err := e.m.MigrateCheck(ctx, MigrateCheckArgs{VM: "web", XML: incoming(string(exp))}); err == nil {
		t.Fatal("the hook passed after the admission ended")
	}
}

func TestMigrationRefusesPassthroughAndISOs(t *testing.T) {
	s := fromTemplate(t, "web", "linux")
	if err := liveMigratable(s); err != nil {
		t.Fatalf("a plain VM: %v", err)
	}
	s.Media = append(s.Media, Media{Kind: MediaISO, ISO: "x.iso"})
	if liveMigratable(s) == nil {
		t.Fatal("a VM with an installer disc from this server's library")
	}
	s.Media = nil
	s.Devices = append(s.Devices, deviceForTest())
	if liveMigratable(s) == nil {
		t.Fatal("a VM with a passthrough device")
	}
}

func TestValidMigrateURI(t *testing.T) {
	for _, u := range []string{"tcp://10.77.0.22", "tcp://10.77.0.22:49152", "tcp://[fd00::22]", "tcp://[fd00::22]:49200"} {
		if err := ValidMigrateURI(u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	for _, u := range []string{"tcp://127.0.0.1", "tcp://100.80.1.2", "tcp://10.77.0.22:22", "unix:///run/x", "tcp://host.example", "tcp://0.0.0.0", "tcp://169.254.1.1", "tcp://10.77.0.22:49216"} {
		if ValidMigrateURI(u) == nil {
			t.Errorf("%s accepted", u)
		}
	}
}

func TestChooseBaseline(t *testing.T) {
	a := HostCPU{Usable: []string{"Nehalem", "Westmere", "SandyBridge", "Skylake-Client", "x86-64-v2", "x86-64-v3"}}
	b := HostCPU{Usable: []string{"Nehalem", "Westmere", "SandyBridge", "x86-64-v2"}}
	if got := ChooseBaseline([]HostCPU{a, b}); got != "x86-64-v2" {
		t.Fatalf("got %q", got)
	}
	a.Usable = []string{"Nehalem", "Westmere", "SandyBridge", "Skylake-Client"}
	b.Usable = []string{"Nehalem", "Westmere", "SandyBridge"}
	if got := ChooseBaseline([]HostCPU{a, b}); got != "SandyBridge" {
		t.Fatalf("got %q", got)
	}
	if got := ChooseBaseline([]HostCPU{{Usable: []string{"a"}}, {Usable: []string{"b"}}}); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestParseDomainCapabilities(t *testing.T) {
	x := `<domainCapabilities><arch>x86_64</arch><cpu>
<mode name="host-passthrough" supported="yes"/>
<mode name="host-model" supported="yes"><model fallback="forbid">Skylake-Client-IBRS</model></mode>
<mode name="custom" supported="yes"><model usable="yes" vendor="Intel">Nehalem</model><model usable="no">Icelake-Server</model><model usable="yes">x86-64-v2</model><model usable="yes">bad model!</model></mode>
</cpu></domainCapabilities>`
	h, err := ParseDomainCapabilities([]byte(x))
	if err != nil {
		t.Fatal(err)
	}
	if h.HostModel != "Skylake-Client-IBRS" || strings.Join(h.Usable, ",") != "Nehalem,x86-64-v2" || h.Arch != "x86_64" {
		t.Fatalf("%+v", h)
	}
}

func TestPolkitRules(t *testing.T) {
	r, err := PolkitAllowRules("web", "6f1c2a9e-3b4d-4c5e-8f90-a1b2c3d4e5f6")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`subject.user !== "hardyos-migrate"`, `"org.libvirt.api.domain.migrate": true`, `action.lookup("domain_name") === "web"`,
		`action.lookup("domain_uuid") === "6f1c2a9e-3b4d-4c5e-8f90-a1b2c3d4e5f6"`, "return polkit.Result.NO;"} {
		if !strings.Contains(r, want) {
			t.Errorf("the rule lacks %s:\n%s", want, r)
		}
	}
	if strings.Contains(r, "org.libvirt.api.domain.delete") || strings.Contains(r, "connect.write") {
		t.Error("the rule allows more than a migration needs")
	}
	if _, err := PolkitAllowRules(`web"); polkit.Result.YES; //`, "6f1c2a9e-3b4d-4c5e-8f90-a1b2c3d4e5f6"); err == nil {
		t.Fatal("an injected name was accepted")
	}
	if !strings.Contains(PolkitDenyRules, `subject.user === "hardyos-migrate"`) || !strings.Contains(PolkitBaseRules, `subject.user === "root"`) {
		t.Fatal("the base and deny rules")
	}
}

func TestWithAccessDriver(t *testing.T) {
	in := "listen_tls = 0\n#access_drivers = [ \"polkit\" ]\naccess_drivers = [ \"none\" ]\n"
	out := string(withAccessDriver([]byte(in)))
	if strings.Count(out, "\naccess_drivers = [ \"polkit\" ]") != 1 || !strings.Contains(out, "listen_tls = 0") || strings.Contains(out, "\naccess_drivers = [ \"none\" ]") {
		t.Fatalf("got:\n%s", out)
	}
	if again := string(withAccessDriver([]byte(out))); again != out {
		t.Fatalf("not idempotent:\n%s\n---\n%s", out, again)
	}
}

func TestClusterDiskPath(t *testing.T) {
	for _, p := range []string{testWWN, "/dev/mapper/36001405a1b2c3d4e5f60718293a4b5c6"} {
		if !ClusterDiskPath(p) {
			t.Errorf("%s refused", p)
		}
	}
	for _, p := range []string{"/dev/sda", "/dev/zvol/tank/vms/web/disk0", "/dev/disk/by-id/wwn-0x../../sda", "/dev/mapper/vg-root"} {
		if ClusterDiskPath(p) {
			t.Errorf("%s accepted", p)
		}
	}
}

var memRE = regexp.MustCompile(`<memory unit="MiB">([0-9]+)</memory>`)

func deviceForTest() devices.Device { return devices.Device{Kind: devices.KindGPU, ID: "0000:01:00.0"} }
