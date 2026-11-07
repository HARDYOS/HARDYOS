package san

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

const testCluster = cluster.ClusterID("abcdefghijklmnopqrstuvwxyz")

var portal = netip.MustParseAddrPort("10.77.0.10:3260")

func vm(id string) cluster.WorkloadRef { return cluster.WorkloadRef{Kind: cluster.KindVM, ID: id} }

func bs(id, disk string) Backstore {
	w := vm(id)
	return Backstore{Name: BackstoreName(w, disk), Workload: w, Dataset: VMDisk("tank", id, disk), Disk: disk, Generation: 1}
}

func plan(d Desired) Plan {
	d.Cluster = testCluster
	d.Portals = []netip.AddrPort{portal}
	d.Normalize()
	p := Plan{Desired: d, Resolved: map[string]Resolved{}, CHAP: map[cluster.NodeID]Secrets{},
		Discovery: Secrets{User: "hc-discovery", Password: "discoverysecret0001", MutualUser: "x", MutualPassword: "discoverysecret0002"}}
	for _, b := range d.Backstores {
		serial := Serial(testCluster, "1234"+b.Name[len(b.Name)-1:])
		p.Resolved[b.Name] = Resolved{Device: "/dev/zvol/" + b.Dataset, GUID: "1", Serial: serial, WWN: WWN(serial), WriteCache: true}
	}
	for _, t := range d.Targets {
		s, _ := NewSecrets(t.Node)
		p.CHAP[t.Node] = s
	}
	return p
}

func TestNamesAndWWN(t *testing.T) {
	if got := TargetIQN(testCluster, "c1"); got != "iqn.2026-11.net.hardynetworks:hardyos.abcdefgh.c1" {
		t.Fatalf("target %s", got)
	}
	if got := InitiatorIQN(testCluster, "c1"); !strings.HasSuffix(got, ".c1.init") {
		t.Fatalf("initiator %s", got)
	}
	if n, ok := NodeOfTarget(testCluster, TargetIQN(testCluster, "c2")); !ok || n != "c2" {
		t.Fatalf("node of target: %s %v", n, ok)
	}
	if _, ok := NodeOfTarget("zzzzzzzzzzzzzzzzzzzzzzzzzz", TargetIQN(testCluster, "c2")); ok {
		t.Fatal("another cluster's target was taken as ours")
	}
	s1, s2 := Serial(testCluster, "111"), Serial(testCluster, "111")
	if s1 != s2 || Serial(testCluster, "112") == s1 || Serial("bbbbbbbbbbbbbbbbbbbbbbbbbb", "111") == s1 {
		t.Fatal("serials must be stable per GUID and cluster, and differ otherwise")
	}
	if !serialRE.MatchString(s1) {
		t.Fatalf("serial %s", s1)
	}
	w := WWN(s1)
	if len(w) != 32 || !strings.HasPrefix(w, "6001405") || w[7:] != strings.ReplaceAll(s1, "-", "")[:25] {
		t.Fatalf("wwn %s for %s", w, s1)
	}
	if BackstoreName(vm("web"), "disk0") == BackstoreName(cluster.WorkloadRef{Kind: cluster.KindApp, ID: "web"}, "disk0") {
		t.Fatal("a VM and an app with one id share a backstore name")
	}
	long := BackstoreName(vm(strings.Repeat("a", 32)), "disk9")
	if len(long) > 63 || ValidBackstoreName(long) != nil {
		t.Fatalf("long name %s", long)
	}
}

func TestValidateMappings(t *testing.T) {
	b := bs("web", "disk0")
	ok := Desired{Cluster: testCluster, Portals: []netip.AddrPort{portal}, Backstores: []Backstore{b},
		Targets: []Target{{Node: "c1", Enabled: true, LUNs: []string{b.Name}}, {Node: "c2", Enabled: true}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	two := ok
	two.Targets = []Target{{Node: "c1", Enabled: true, LUNs: []string{b.Name}}, {Node: "c2", Enabled: true, LUNs: []string{b.Name}}}
	if err := two.Validate(); err == nil || !strings.Contains(err.Error(), "without a live migration") {
		t.Fatalf("two initiators without a migration: %v", err)
	}
	mb := b
	mb.Migration = true
	two.Backstores = []Backstore{mb}
	if err := two.Validate(); err != nil {
		t.Fatalf("migration grant: %v", err)
	}
	fenced := ok
	fenced.Targets = []Target{{Node: "c1", Enabled: false, LUNs: []string{b.Name}}}
	if err := fenced.Validate(); err == nil {
		t.Fatal("a fenced target with LUNs passed")
	}
	other := ok
	ob := b
	ob.Dataset = "tank/vms/other/disk0"
	other.Backstores = []Backstore{ob}
	if err := other.Validate(); err == nil {
		t.Fatal("a backstore naming another VM's disk passed")
	}
	shares := ok
	sb := b
	sb.Dataset = "tank/shares/media"
	shares.Backstores = []Backstore{sb}
	if err := shares.Validate(); err == nil {
		t.Fatal("a backstore outside vms/ and apps/ passed")
	}
	bad := ok
	bad.Portals = []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:3260")}
	if err := bad.Validate(); err == nil {
		t.Fatal("loopback portal passed")
	}
}

func TestReconcileBuildsTargetsAndIsIdempotent(t *testing.T) {
	f := NewFakeFS()
	b0, b1 := bs("web", "disk0"), bs("web", "disk1")
	p := plan(Desired{Backstores: []Backstore{b0, b1},
		Targets: []Target{{Node: "c1", Enabled: true, LUNs: []string{b0.Name, b1.Name}}, {Node: "c2", Enabled: true}}})
	if err := Reconcile(f, p); err != nil {
		t.Fatal(err)
	}
	tpg := tpgDir(TargetIQN(testCluster, "c1"))
	checks := map[string]string{
		tpg + "/enable":                                      "1",
		tpg + "/attrib/authentication":                       "1",
		tpg + "/attrib/generate_node_acls":                   "0",
		tpg + "/param/AuthMethod":                            "CHAP",
		"core/iblock_77/" + b0.Name + "/udev_path":           "/dev/zvol/tank/vms/web/disk0",
		"core/iblock_77/" + b0.Name + "/enable":              "1",
		"core/iblock_77/" + b0.Name + "/attrib/emulate_tpu":  "1",
		"core/iblock_77/" + b0.Name + "/wwn/vpd_unit_serial": p.Resolved[b0.Name].Serial,
		"iscsi/discovery_auth/enforce_discovery_auth":        "1",
	}
	for k, v := range checks {
		if got := f.Value(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	acl := tpg + "/acls/" + InitiatorIQN(testCluster, "c1")
	if f.Value(acl+"/auth/password") != p.CHAP["c1"].Password || f.Value(acl+"/auth/password_mutual") != p.CHAP["c1"].MutualPassword {
		t.Error("CHAP secrets weren't set on the ACL")
	}
	acls, _ := f.List(tpg + "/acls")
	if len(acls) != 1 {
		t.Errorf("want exactly one ACL, got %v", acls)
	}
	if !f.Exists(tpg + "/np/10.77.0.10:3260") {
		t.Error("portal missing")
	}
	cur := Current(f, testCluster)
	if !slices.Equal(cur["c1"].LUNs, []string{b0.Name, b1.Name}) || len(cur["c2"].LUNs) != 0 {
		t.Fatalf("current %+v", cur)
	}
	// Mapped LUNs in the ACL too.
	if !strings.HasPrefix(f.Value(acl+"/lun_0/map"), "-> "+tpg+"/lun/lun_") {
		t.Errorf("ACL mapping missing: %q", f.Value(acl+"/lun_0/map"))
	}
	// Secrets never appear in the change log.
	for _, l := range f.Log {
		if strings.Contains(l, p.CHAP["c1"].Password) || strings.Contains(l, p.CHAP["c1"].MutualPassword) {
			t.Fatalf("a secret was logged: %s", l)
		}
	}
	n := len(f.Log)
	if err := Reconcile(f, p); err != nil {
		t.Fatal(err)
	}
	if len(f.Log) != n {
		t.Fatalf("second reconcile changed things: %v", f.Log[n:])
	}
}

func TestReconcileMovesFencesAndRemoves(t *testing.T) {
	f := NewFakeFS()
	b := bs("web", "disk0")
	p := plan(Desired{Backstores: []Backstore{b}, Targets: []Target{{Node: "c1", Enabled: true, LUNs: []string{b.Name}}, {Node: "c2", Enabled: true}}})
	if err := Reconcile(f, p); err != nil {
		t.Fatal(err)
	}
	// Live migration: both.
	mb := b
	mb.Migration = true
	p2 := plan(Desired{Backstores: []Backstore{mb}, Targets: []Target{{Node: "c1", Enabled: true, LUNs: []string{b.Name}}, {Node: "c2", Enabled: true, LUNs: []string{b.Name}}}})
	p2.CHAP = p.CHAP
	if err := Reconcile(f, p2); err != nil {
		t.Fatal(err)
	}
	cur := Current(f, testCluster)
	if len(cur["c1"].LUNs) != 1 || len(cur["c2"].LUNs) != 1 {
		t.Fatalf("migration: %+v", cur)
	}
	// After: only c2.
	p3 := plan(Desired{Backstores: []Backstore{b}, Targets: []Target{{Node: "c1", Enabled: true}, {Node: "c2", Enabled: true, LUNs: []string{b.Name}}}})
	p3.CHAP = p.CHAP
	if err := Reconcile(f, p3); err != nil {
		t.Fatal(err)
	}
	cur = Current(f, testCluster)
	if len(cur["c1"].LUNs) != 0 || len(cur["c2"].LUNs) != 1 {
		t.Fatalf("after migration: %+v", cur)
	}
	// Fence c2: disabled first, sessions dropped, nothing mapped.
	f.Sessions[TargetIQN(testCluster, "c2")] = 2
	p4 := plan(Desired{Backstores: []Backstore{b}, Targets: []Target{{Node: "c1", Enabled: true}, {Node: "c2", Enabled: false, FenceEpoch: 3}}})
	p4.CHAP = p.CHAP
	mark := len(f.Log)
	if err := Reconcile(f, p4); err != nil {
		t.Fatal(err)
	}
	if f.Sessions[TargetIQN(testCluster, "c2")] != 0 {
		t.Fatal("fence didn't drop the sessions")
	}
	if first := f.Log[mark]; first != "write "+tpgDir(TargetIQN(testCluster, "c2"))+"/enable 0" {
		t.Fatalf("the fence's first step was %q", first)
	}
	cur = Current(f, testCluster)
	if cur["c2"].Enabled || len(cur["c2"].LUNs) != 0 {
		t.Fatalf("fenced: %+v", cur["c2"])
	}
	// c2 removed from the cluster and the backstore no longer wanted.
	p5 := plan(Desired{Targets: []Target{{Node: "c1", Enabled: true}}})
	p5.CHAP = p.CHAP
	if err := Reconcile(f, p5); err != nil {
		t.Fatal(err)
	}
	if f.Exists("iscsi/"+TargetIQN(testCluster, "c2")) || f.Exists("core/iblock_77/"+b.Name) {
		t.Fatalf("leftovers: %v", f.Paths())
	}
}

func TestReconcileRecreatesOnSerialChangeAndLeavesForeignObjects(t *testing.T) {
	f := NewFakeFS()
	// Something an admin made by hand with targetcli.
	_ = f.Mkdir("core/iblock_0")
	_ = f.Mkdir("core/iblock_0/mydisk")
	_ = f.Mkdir("iscsi/iqn.2003-01.org.linux-iscsi.host:sn.1234")
	b := bs("web", "disk0")
	p := plan(Desired{Backstores: []Backstore{b}, Targets: []Target{{Node: "c1", Enabled: true, LUNs: []string{b.Name}}}})
	if err := Reconcile(f, p); err != nil {
		t.Fatal(err)
	}
	r := p.Resolved[b.Name]
	r.Serial = Serial(testCluster, "999")
	p.Resolved[b.Name] = r
	if err := Reconcile(f, p); err != nil {
		t.Fatal(err)
	}
	if got := f.Value("core/iblock_77/" + b.Name + "/wwn/vpd_unit_serial"); got != r.Serial {
		t.Fatalf("serial %s", got)
	}
	if len(Current(f, testCluster)["c1"].LUNs) != 1 {
		t.Fatal("the LUN wasn't mapped again")
	}
	if !f.Exists("core/iblock_0/mydisk") || !f.Exists("iscsi/iqn.2003-01.org.linux-iscsi.host:sn.1234") {
		t.Fatal("objects HardyOS didn't make were touched")
	}
}

func TestFirewallRender(t *testing.T) {
	spec := FirewallSpec{Role: cluster.RoleStorage, Interface: "enp2s0", Subnet: netip.MustParsePrefix("10.77.0.0/24"),
		Members: []netip.Addr{netip.MustParseAddr("10.77.0.22"), netip.MustParseAddr("10.77.0.21")},
		Fenced:  []netip.Addr{netip.MustParseAddr("10.77.0.23")}}
	out, err := RenderFirewall(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table inet hardyos_cluster_storage\ndelete table inet hardyos_cluster_storage\n",
		"elements = { 10.77.0.21, 10.77.0.22 }",
		"elements = { 10.77.0.23 }",
		`iifname != "enp2s0" ip saddr 10.77.0.0/24 drop`,
		`iifname "enp2s0" ip saddr @fenced drop`,
		`tcp dport 3260 iifname != "enp2s0" drop`,
		`iifname "enp2s0" tcp dport { 2049, 3260 } ip saddr @members accept`,
		`iifname "enp2s0" tcp dport { 2049, 3260 } drop`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Index(out, "@fenced drop") > strings.Index(out, "@members accept") {
		t.Error("fenced addresses must be dropped before members are accepted")
	}
	spec.Role = cluster.RoleCompute
	out, _ = RenderFirewall(spec)
	if !strings.Contains(out, "tcp dport 49152-49215 ip saddr @members accept") || strings.Contains(out, "3260") {
		t.Errorf("compute table:\n%s", out)
	}
	for _, bad := range []FirewallSpec{
		{Role: cluster.RoleStorage, Interface: "eth0; drop", Subnet: spec.Subnet},
		{Role: cluster.RoleStorage, Interface: "eth0", Subnet: netip.MustParsePrefix("0.0.0.0/0")},
		{Role: cluster.RoleStorage, Interface: "eth0", Subnet: spec.Subnet, Members: []netip.Addr{netip.MustParseAddr("192.168.1.5")}},
		{Role: cluster.RoleWitness, Interface: "eth0", Subnet: spec.Subnet},
	} {
		if _, err := RenderFirewall(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestSecrets(t *testing.T) {
	s, err := NewSecrets("c1")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(s.Password) != SecretLen || s.Password == s.MutualPassword {
		t.Fatalf("%d %v", len(s.Password), s.Password == s.MutualPassword)
	}
	if strings.Contains(s.String(), s.Password) || strings.Contains(strings.ReplaceAll(strings.TrimSpace(sprint(s)), " ", ""), s.Password) {
		t.Fatal("secrets would show in logs")
	}
	bad := s
	bad.Password = "short"
	if bad.Validate() == nil {
		t.Fatal("short secret passed")
	}
	bad = s
	bad.MutualPassword = s.Password
	if bad.Validate() == nil {
		t.Fatal("equal secrets passed")
	}
}
