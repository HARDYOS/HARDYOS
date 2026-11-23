package san

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/nfs"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func sprint(v any) string { return fmt.Sprintf("%v %+v %#v", v, v, v) }

func newRoot(t *testing.T) (*Root, *FakeFS, *sysexec.Fake) {
	t.Helper()
	sys := t.TempDir()
	fx := &sysexec.Fake{}
	f := NewFakeFS()
	r := &Root{Runner: fx, FS: f, Dir: filepath.Join(sys, "state"), Sys: sys,
		NFS: &nfs.ClusterManager{Runner: fx, Root: sys}}
	fx.OnPrefix("nft ", sysexec.Result{})
	fx.OnPrefix("systemctl ", sysexec.Result{})
	fx.OnPrefix("exportfs ", sysexec.Result{})
	fx.OnPrefix("ip ", sysexec.Result{})
	return r, f, fx
}

func zvolProps(fx *sysexec.Fake, ds, kind, id string) {
	fx.On("zfs get -H -p -o property,value type,guid,sync,org.hardyos:role,org.hardyos:"+kind+" "+ds,
		"type\tvolume\nguid\t4242\nsync\tstandard\norg.hardyos:role\tcluster\norg.hardyos:"+kind+"\t"+id+"\n")
}

func desired(idx uint64, b []Backstore, t ...Target) Desired {
	return Desired{Cluster: testCluster, Index: idx, Portals: []netip.AddrPort{portal}, Backstores: b, Targets: t}
}

// testNodes are two compute nodes with their keys and storage addresses.
type testNodes struct {
	ids   map[cluster.NodeID]*cluster.Identity
	addrs map[cluster.NodeID]netip.Addr
}

func newNodes(t *testing.T) *testNodes {
	t.Helper()
	n := &testNodes{ids: map[cluster.NodeID]*cluster.Identity{}, addrs: map[cluster.NodeID]netip.Addr{
		"c1": netip.MustParseAddr("10.77.0.21"), "c2": netip.MustParseAddr("10.77.0.22")}}
	for _, id := range []cluster.NodeID{"c1", "c2"} {
		ident, err := cluster.NewIdentity(string(id))
		if err != nil {
			t.Fatal(err)
		}
		n.ids[id] = ident
	}
	return n
}

func (n *testNodes) keys() map[cluster.NodeID][]byte {
	k := map[cluster.NodeID][]byte{}
	for id, i := range n.ids {
		k[id] = i.PublicKey
	}
	return k
}

func (n *testNodes) args(d Desired) ApplyArgs {
	return ApplyArgs{Desired: d, Addresses: n.addrs, Keys: n.keys(), Subnet: netip.MustParsePrefix("10.77.0.0/24")}
}

func (n *testNodes) rejoin(t *testing.T, node cluster.NodeID, epoch uint64) *RejoinStatement {
	t.Helper()
	s, err := SignRejoin(n.ids[node].Key, RejoinStatement{Cluster: testCluster, Node: node, Epoch: epoch, BootID: "b2"})
	if err != nil {
		t.Fatal(err)
	}
	return &s
}

func TestRootApplyChecksDatasetsAndKeepsFences(t *testing.T) {
	r, f, fx := newRoot(t)
	ctx := context.Background()
	nodes := newNodes(t)
	b := bs("web", "disk0")
	zvolProps(fx, b.Dataset, "vm", "web")
	st, err := r.Apply(ctx, nodes.args(desired(5, []Backstore{b}, Target{Node: "c1", Enabled: true, LUNs: []string{b.Name}}, Target{Node: "c2", Enabled: true})))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Current["c1"].LUNs) != 1 || st.Resolved[b.Name].WWN != WWN(Serial(testCluster, "4242")) {
		t.Fatalf("status %+v", st)
	}
	if !f.Locked {
		t.Fatal("LIO's configfs folder wasn't locked down")
	}
	// Root's files are 0600 in a 0700 folder.
	for _, p := range []string{r.statePath(), r.chapPath()} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, fi.Mode(), err)
		}
	}
	// An older desired state is refused (no replay of an old request).
	if _, err := r.Apply(ctx, nodes.args(desired(4, nil, Target{Node: "c1", Enabled: true}))); err == nil {
		t.Fatal("an older desired state was applied")
	}
	// A zvol of another VM (or not marked cluster) is refused.
	other := bs("db", "disk0")
	fx.On("zfs get -H -p -o property,value type,guid,sync,org.hardyos:role,org.hardyos:vm "+other.Dataset,
		"type\tvolume\nguid\t1\nsync\tstandard\norg.hardyos:role\t-\norg.hardyos:vm\tdb\n")
	_, err = r.Apply(ctx, nodes.args(desired(6, []Backstore{other}, Target{Node: "c1", Enabled: true, LUNs: []string{other.Name}})))
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("a non-cluster zvol: %v", err)
	}
	// Fence c1 (its address is pinned, but no firewall yet: incomplete).
	res, err := r.Fence(ctx, FenceArgs{Node: "c1", Epoch: 2, Confirm: "c1"})
	if err == nil || !strings.Contains(err.Error(), "firewall") {
		t.Fatalf("a fence without the address block counts as complete: %v", err)
	}
	if !res.TargetDisabled || res.AddressBlocked {
		t.Fatalf("fence %+v", res)
	}
	if cur := Current(f, testCluster)["c1"]; cur.Enabled || len(cur.LUNs) != 0 {
		t.Fatalf("after fence %+v", cur)
	}
	// hardyd can't hand the LUN back to a fenced node by applying again:
	// its target stays off, the rest of the apply goes through (M2).
	st, err = r.Apply(ctx, nodes.args(desired(7, []Backstore{b}, Target{Node: "c1", Enabled: true, LUNs: []string{b.Name}}, Target{Node: "c2", Enabled: true})))
	if err != nil {
		t.Fatal(err)
	}
	if c1 := st.Current["c1"]; c1.Enabled || len(c1.LUNs) != 0 || !st.Current["c2"].Enabled {
		t.Fatalf("re-granting a fenced node: %+v", st.Current)
	}
	// Nor get its CHAP secrets.
	if _, err := r.CHAP(ctx, CHAPArgs{Node: "c1"}); err == nil {
		t.Fatal("a fenced node's secrets were handed out")
	}
	old, _ := r.loadCHAP()
	// Fence needs the typed name; unfence needs the epoch and the node's
	// own signed statement.
	if _, err := r.Fence(ctx, FenceArgs{Node: "c2", Epoch: 1}); err == nil {
		t.Fatal("fence without confirmation")
	}
	if err := r.Unfence(ctx, UnfenceArgs{Node: "c1", Epoch: 1, Statement: nodes.rejoin(t, "c1", 1)}); err == nil {
		t.Fatal("unfence with the wrong epoch")
	}
	if err := r.Unfence(ctx, UnfenceArgs{Node: "c1", Epoch: 2}); err == nil || !strings.Contains(err.Error(), "signed rejoin") {
		t.Fatalf("unfence without the node's statement: %v", err)
	}
	forged, _ := SignRejoin(nodes.ids["c2"].Key, RejoinStatement{Cluster: testCluster, Node: "c1", Epoch: 2})
	if err := r.Unfence(ctx, UnfenceArgs{Node: "c1", Epoch: 2, Statement: &forged}); err == nil {
		t.Fatal("unfenced with a statement signed by another node's key")
	}
	if err := r.Unfence(ctx, UnfenceArgs{Node: "c1", Epoch: 2, Statement: nodes.rejoin(t, "c1", 2)}); err != nil {
		t.Fatal(err)
	}
	// Rejoining means new CHAP secrets (L3).
	now, _ := r.loadCHAP()
	if now["c1"].Password == old["c1"].Password || now["c1"].MutualPassword == old["c1"].MutualPassword {
		t.Fatal("the CHAP secrets weren't rotated on unfence")
	}
	// An old fence epoch can't be replayed after the unfence.
	if _, err := r.Fence(ctx, FenceArgs{Node: "c1", Epoch: 2, Confirm: "c1"}); err == nil || !strings.Contains(err.Error(), "newer epoch") {
		t.Fatalf("an old fence was replayed: %v", err)
	}
	if _, err := r.Apply(ctx, nodes.args(desired(8, []Backstore{b}, Target{Node: "c1", Enabled: true, LUNs: []string{b.Name}}, Target{Node: "c2", Enabled: true}))); err != nil {
		t.Fatal(err)
	}
	sec, err := r.CHAP(ctx, CHAPArgs{Node: "c1"})
	if err != nil || sec.Validate() != nil {
		t.Fatal(err)
	}
	// The secrets never went through a command line.
	for _, l := range fx.Lines() {
		if strings.Contains(l, sec.Password) || strings.Contains(l, sec.MutualPassword) {
			t.Fatalf("secret on a command line: %s", l)
		}
	}
}

func TestRootPinsAddressesKeysAndSubnet(t *testing.T) {
	r, _, _ := newRoot(t)
	ctx := context.Background()
	nodes := newNodes(t)
	d := func(i uint64) Desired {
		return desired(i, nil, Target{Node: "c1", Enabled: true}, Target{Node: "c2", Enabled: true})
	}
	if _, err := r.Apply(ctx, nodes.args(d(1))); err != nil {
		t.Fatal(err)
	}
	// A changed address disables that node's target only (M1).
	a := nodes.args(d(2))
	a.Addresses = map[cluster.NodeID]netip.Addr{"c1": netip.MustParseAddr("10.77.0.99"), "c2": nodes.addrs["c2"]}
	st, err := r.Apply(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if st.Current["c1"].Enabled || !st.Current["c2"].Enabled || !strings.Contains(st.Problem, "hardyctl cluster-storage repin c1") {
		t.Fatalf("address change: %+v %q", st.Current, st.Problem)
	}
	// So does a changed key.
	a = nodes.args(d(3))
	other, _ := cluster.NewIdentity("x")
	a.Keys["c2"] = other.PublicKey
	st, _ = r.Apply(ctx, a)
	if st.Current["c2"].Enabled || !strings.Contains(st.Problem, "key changed") {
		t.Fatalf("key change: %+v %q", st.Current, st.Problem)
	}
	// An administrator's repin (root only) takes the new address.
	if err := r.PinReset(ctx, PinResetArgs{Node: "c1", Confirm: "nope"}); err == nil {
		t.Fatal("repin without confirmation")
	}
	if err := r.PinReset(ctx, PinResetArgs{Node: "c1", Confirm: "c1"}); err != nil {
		t.Fatal(err)
	}
	a = nodes.args(d(4))
	a.Addresses = map[cluster.NodeID]netip.Addr{"c1": netip.MustParseAddr("10.77.0.99"), "c2": nodes.addrs["c2"]}
	st, _ = r.Apply(ctx, a)
	if !st.Current["c1"].Enabled || st.Pins["c1"].Address.String() != "10.77.0.99" {
		t.Fatalf("after repin: %+v %+v", st.Current, st.Pins)
	}
	// New pins must be in the subnet, not the storage node's, not taken.
	r2, _, _ := newRoot(t)
	for name, addr := range map[string]string{"outside": "10.88.0.5", "storage's own": "10.77.0.10", "network": "10.77.0.0", "broadcast": "10.77.0.255"} {
		a := nodes.args(desired(1, nil, Target{Node: "c1", Enabled: true}))
		a.Addresses = map[cluster.NodeID]netip.Addr{"c1": netip.MustParseAddr(addr)}
		st, err := r2.Apply(ctx, a)
		if err != nil || st.Current["c1"].Enabled {
			t.Errorf("%s address %s was pinned: %v", name, addr, err)
		}
	}
	a = nodes.args(desired(1, nil, Target{Node: "c1", Enabled: true}, Target{Node: "c2", Enabled: true}))
	a.Addresses = map[cluster.NodeID]netip.Addr{"c1": nodes.addrs["c1"], "c2": nodes.addrs["c1"]}
	st, _ = r2.Apply(ctx, a)
	if st.Current["c1"].Enabled == st.Current["c2"].Enabled {
		t.Fatalf("two nodes pinned one address: %+v", st.Current)
	}
	// The subnet is pinned too.
	a = nodes.args(d(5))
	a.Subnet = netip.MustParsePrefix("10.78.0.0/24")
	if _, err := r.Apply(ctx, a); err == nil || !strings.Contains(err.Error(), "repin --subnet") {
		t.Fatalf("subnet change: %v", err)
	}
}

func TestRootIndexJumpsAreCapped(t *testing.T) {
	r, _, _ := newRoot(t)
	ctx := context.Background()
	nodes := newNodes(t)
	clock := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	r.Now = func() time.Time { return clock }
	if _, err := r.Apply(ctx, nodes.args(desired(100, nil, Target{Node: "c1", Enabled: true}))); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Apply(ctx, nodes.args(desired(100+indexJumpBase+5, nil, Target{Node: "c1", Enabled: true}))); err == nil {
		t.Fatal("a huge index jump was accepted")
	}
	clock = clock.Add(10 * time.Second)
	if _, err := r.Apply(ctx, nodes.args(desired(100+indexJumpBase+5, nil, Target{Node: "c1", Enabled: true}))); err != nil {
		t.Fatalf("a jump that fits the elapsed time: %v", err)
	}
	// Persisted: a new Root on the same folder keeps the mark.
	r2 := &Root{Runner: r.Runner, FS: r.FS, Dir: r.Dir, Sys: r.Sys, NFS: r.NFS, Now: r.Now}
	if _, err := r2.Apply(ctx, nodes.args(desired(^uint64(0)>>1, nil, Target{Node: "c1", Enabled: true}))); err == nil {
		t.Fatal("the mark wasn't kept")
	}
	// The firewall and the exports carry the index too.
	spec := FirewallSpec{Role: cluster.RoleStorage, Interface: "enp2s0", Subnet: netip.MustParsePrefix("10.77.0.0/24"), Index: 50}
	if err := r.FirewallApply(ctx, spec); err != nil {
		t.Fatal(err)
	}
	spec.Index = 49
	if err := r.FirewallApply(ctx, spec); err == nil {
		t.Fatal("an older firewall was applied")
	}
	if _, err := r.NFSApply(ctx, NFSApplyArgs{Index: 7}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.NFSApply(ctx, NFSApplyArgs{Index: 6}); err == nil {
		t.Fatal("older exports were applied")
	}
}

func TestRootFenceCutsExportsAndFirewall(t *testing.T) {
	r, _, fx := newRoot(t)
	ctx := context.Background()
	nodes := newNodes(t)
	c1, c2 := nodes.addrs["c1"], nodes.addrs["c2"]
	if _, err := r.Apply(ctx, nodes.args(desired(1, nil, Target{Node: "c1", Enabled: true}, Target{Node: "c2", Enabled: true}))); err != nil {
		t.Fatal(err)
	}
	fx.On("zfs get -H -p -o property,value type,guid,mountpoint,mounted,org.hardyos:vm,org.hardyos:role tank/vms/web",
		"type\tfilesystem\nguid\t77\nmountpoint\t/mnt/tank/vms/web\nmounted\tyes\norg.hardyos:vm\tweb\norg.hardyos:role\tcluster\n")
	fx.On("zfs get -H -p -o property,value type,guid,mountpoint,mounted,org.hardyos:share,org.hardyos:role tank/shares/media",
		"type\tfilesystem\nguid\t78\nmountpoint\t/mnt/tank/shares/media\nmounted\tyes\norg.hardyos:share\tmedia\norg.hardyos:role\t-\n")
	got, err := r.NFSApply(ctx, NFSApplyArgs{Exports: []nfs.ClusterExport{
		{Kind: nfs.KindVMState, Dataset: "tank/vms/web", Path: "/evil", GUID: "1", Clients: []netip.Addr{c1}},
		{Kind: nfs.KindShare, Dataset: "tank/shares/media", Clients: []netip.Addr{c1, c2, netip.MustParseAddr("10.77.0.50")}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Path != "/mnt/tank/vms/web" || got[0].GUID != "77" {
		t.Fatalf("root must use the dataset's own mountpoint and GUID: %+v", got[0])
	}
	if len(got[1].Clients) != 2 {
		t.Fatalf("an address root hasn't pinned got an export (H3): %+v", got[1])
	}
	if err := r.FirewallApply(ctx, FirewallSpec{Role: cluster.RoleStorage, Interface: "enp2s0", Subnet: netip.MustParsePrefix("10.77.0.0/24"),
		Members: []netip.Addr{c1, c2, netip.MustParseAddr("10.77.0.50")}}); err != nil {
		t.Fatal(err)
	}
	fw, _ := os.ReadFile(filepath.Join(r.Sys, FirewallFile))
	if strings.Contains(string(fw), "10.77.0.50") {
		t.Fatalf("an unpinned address became a firewall member:\n%s", fw)
	}
	// An NFSv4 client of c1 to expire.
	cdir := filepath.Join(r.Sys, "proc/fs/nfsd/clients/7")
	_ = os.MkdirAll(cdir, 0o755)
	_ = os.WriteFile(filepath.Join(cdir, "info"), []byte("clientid: 0x1\naddress: \"10.77.0.21:812\"\n"), 0o644)
	_ = os.WriteFile(filepath.Join(cdir, "ctl"), nil, 0o644)
	res, err := r.Fence(ctx, FenceArgs{Node: "c1", Epoch: 1, Confirm: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExportsRemoved != 2 || res.ClientsExpired != 1 || !res.AddressBlocked {
		t.Fatalf("fence %+v", res)
	}
	ex, _ := os.ReadFile(filepath.Join(r.Sys, nfs.ClusterExportsFile))
	if strings.Contains(string(ex), "10.77.0.21") || !strings.Contains(string(ex), "10.77.0.22(rw,sync,no_subtree_check,root_squash") {
		t.Fatalf("exports after fence:\n%s", ex)
	}
	if ctl, _ := os.ReadFile(filepath.Join(cdir, "ctl")); string(ctl) != "expire\n" {
		t.Fatalf("client not expired: %q", ctl)
	}
	fw, _ = os.ReadFile(filepath.Join(r.Sys, FirewallFile))
	if !strings.Contains(string(fw), "set fenced {\n\t\ttype ipv4_addr\n\t\telements = { 10.77.0.21 }") {
		t.Fatalf("firewall after fence:\n%s", fw)
	}
	// A later firewall or export change can't let c1 back in.
	_ = r.FirewallApply(ctx, FirewallSpec{Role: cluster.RoleStorage, Interface: "enp2s0", Subnet: netip.MustParsePrefix("10.77.0.0/24"), Members: []netip.Addr{c1, c2}})
	fw, _ = os.ReadFile(filepath.Join(r.Sys, FirewallFile))
	if strings.Contains(string(fw), "elements = { 10.77.0.21, 10.77.0.22 }") {
		t.Fatal("the fenced address came back into the members")
	}
	_, _ = r.NFSApply(ctx, NFSApplyArgs{Exports: []nfs.ClusterExport{{Kind: nfs.KindVMState, Dataset: "tank/vms/web", Clients: []netip.Addr{c1}}}})
	ex, _ = os.ReadFile(filepath.Join(r.Sys, nfs.ClusterExportsFile))
	if strings.Contains(string(ex), "10.77.0.21") {
		t.Fatalf("the fenced node got an export back:\n%s", ex)
	}
	// The fence survives a removal in hardyd's eyes; only root's forget
	// (an administrator, as root) clears it (M2).
	if err := r.Forget(ctx, ForgetArgs{Node: "c1", Confirm: "c1"}); err != nil {
		t.Fatal(err)
	}
	st, _ := r.Status(ctx)
	if _, ok := st.Fences["c1"]; ok || st.Pins["c1"].Address.IsValid() {
		t.Fatalf("after forget: %+v", st)
	}
	if err := r.Forget(ctx, ForgetArgs{Node: "c2", Confirm: "c2"}); err == nil {
		t.Fatal("forgot a node that still has an enabled target")
	}
}

func TestRootOwnerExportsFollowTheLUNsAndTheLAN(t *testing.T) {
	r, _, fx := newRoot(t)
	ctx := context.Background()
	nodes := newNodes(t)
	b := bs("web", "disk0")
	zvolProps(fx, b.Dataset, "vm", "web")
	if _, err := r.Apply(ctx, nodes.args(desired(1, []Backstore{b}, Target{Node: "c1", Enabled: true, LUNs: []string{b.Name}}, Target{Node: "c2", Enabled: true}))); err != nil {
		t.Fatal(err)
	}
	fx.On("zfs get -H -p -o property,value type,guid,mountpoint,mounted,org.hardyos:vm,org.hardyos:role tank/vms/web",
		"type\tfilesystem\nguid\t77\nmountpoint\t/mnt/tank/vms/web\nmounted\tyes\norg.hardyos:vm\tweb\norg.hardyos:role\tcluster\n")
	// web's disks are mapped to c1 only: its state isn't exported to c2.
	got, err := r.NFSApply(ctx, NFSApplyArgs{Exports: []nfs.ClusterExport{
		{Kind: nfs.KindVMState, Dataset: "tank/vms/web", Clients: []netip.Addr{nodes.addrs["c2"]}}}})
	if err != nil || len(got) != 0 {
		t.Fatalf("VM state exported to a node without its disks: %v %+v", err, got)
	}
	// On the LAN itself, owner-only exports (no_root_squash) are refused (H2).
	fx.On("ip -j route show default", `[{"dst":"default","gateway":"192.168.1.1","dev":"eno1"}]`)
	if err := r.FirewallApply(ctx, FirewallSpec{Role: cluster.RoleStorage, Interface: "eno1", Subnet: netip.MustParsePrefix("10.77.0.0/24"),
		Members: []netip.Addr{nodes.addrs["c1"]}}); err != nil {
		t.Fatal(err)
	}
	got, _ = r.NFSApply(ctx, NFSApplyArgs{Exports: []nfs.ClusterExport{
		{Kind: nfs.KindVMState, Dataset: "tank/vms/web", Clients: []netip.Addr{nodes.addrs["c1"]}}}})
	st, _ := r.Status(ctx)
	if len(got) != 0 || !strings.Contains(st.Problem, "the storage network is the LAN") {
		t.Fatalf("owner export on the LAN: %+v %q", got, st.Problem)
	}
	fw, _ := os.ReadFile(filepath.Join(r.Sys, FirewallFile))
	if strings.Contains(string(fw), "20048") {
		t.Fatalf("on the LAN, the LAN's own NFSv3 ports must stay open:\n%s", fw)
	}
}

func TestRootPinsMACsAndAllowsMigrations(t *testing.T) {
	r, _, fx := newRoot(t)
	ctx := context.Background()
	c1, c2 := netip.MustParseAddr("10.77.0.21"), netip.MustParseAddr("10.77.0.22")
	fx.On("ip -j neigh show dev enp2s0", `[{"dst":"10.77.0.21","lladdr":"52:54:00:AA:BB:01","state":["REACHABLE"]},{"dst":"10.77.0.99","lladdr":"52:54:00:aa:bb:99","state":["STALE"]},{"dst":"10.77.0.22","state":["FAILED"]}]`)
	spec := FirewallSpec{Role: cluster.RoleCompute, Interface: "enp2s0", Subnet: netip.MustParsePrefix("10.77.0.0/24"), Members: []netip.Addr{c1, c2}}
	if err := r.FirewallApply(ctx, spec); err != nil {
		t.Fatal(err)
	}
	fw, _ := os.ReadFile(filepath.Join(r.Sys, FirewallFile))
	for _, want := range []string{"elements = { 10.77.0.21 . 52:54:00:aa:bb:01 }", "ip saddr @mac_pinned ip saddr . ether saddr != @member_macs drop",
		"ip saddr . tcp dport @migrations accept"} {
		if !strings.Contains(string(fw), want) {
			t.Fatalf("firewall lacks %q:\n%s", want, fw)
		}
	}
	if strings.Contains(string(fw), "10.77.0.99") || strings.Contains(string(fw), "tcp dport 49152-49215 ip saddr @members accept") {
		t.Fatalf("a non-member was pinned, or every member may migrate:\n%s", fw)
	}
	if !contains(fx.Lines(), "ip neigh replace 10.77.0.21 lladdr 52:54:00:aa:bb:01 dev enp2s0 nud permanent") {
		t.Fatalf("no static neighbour entry: %v", fx.Lines())
	}
	// A pinned MAC isn't replaced by a later neighbour entry.
	fx.On("ip -j neigh show dev enp2s0", `[{"dst":"10.77.0.21","lladdr":"52:54:00:ee:ee:ee","state":["REACHABLE"]}]`)
	_ = r.FirewallApply(ctx, spec)
	st, _ := r.load()
	if st.MACs[c1] != "52:54:00:aa:bb:01" {
		t.Fatalf("MAC pin changed: %v", st.MACs)
	}
	// A migration allowance for one source and port (M6).
	clock := time.Now()
	r.Now = func() time.Time { return clock }
	if err := r.AllowMigration(ctx, MigrationArgs{Source: netip.MustParseAddr("10.77.0.50"), Port: 49152}); err == nil {
		t.Fatal("a non-member may migrate here")
	}
	if err := r.AllowMigration(ctx, MigrationArgs{Source: c2, Port: 49160, Seconds: 60}); err != nil {
		t.Fatal(err)
	}
	fw, _ = os.ReadFile(filepath.Join(r.Sys, FirewallFile))
	if !strings.Contains(string(fw), "elements = { 10.77.0.22 . 49160 timeout 60s }") {
		t.Fatalf("migration allowance:\n%s", fw)
	}
	// It survives a reload while it lasts, and goes when it expires.
	clock = clock.Add(30 * time.Second)
	_ = r.FirewallApply(ctx, spec)
	fw, _ = os.ReadFile(filepath.Join(r.Sys, FirewallFile))
	if !strings.Contains(string(fw), "10.77.0.22 . 49160 timeout 30s") {
		t.Fatalf("allowance lost on reload:\n%s", fw)
	}
	clock = clock.Add(31 * time.Second)
	_ = r.FirewallApply(ctx, spec)
	fw, _ = os.ReadFile(filepath.Join(r.Sys, FirewallFile))
	if strings.Contains(string(fw), "49160 timeout") {
		t.Fatalf("expired allowance kept:\n%s", fw)
	}
	if err := r.AllowMigration(ctx, MigrationArgs{Source: c2, Seconds: 3600}); err == nil {
		t.Fatal("an allowance longer than the maximum")
	}
}

func TestRootCHAPRotationNeedsNothingMapped(t *testing.T) {
	r, f, fx := newRoot(t)
	ctx := context.Background()
	nodes := newNodes(t)
	b := bs("web", "disk0")
	zvolProps(fx, b.Dataset, "vm", "web")
	if _, err := r.Apply(ctx, nodes.args(desired(1, []Backstore{b}, Target{Node: "c1", Enabled: true, LUNs: []string{b.Name}}, Target{Node: "c2", Enabled: true}))); err != nil {
		t.Fatal(err)
	}
	if err := r.RotateCHAP(ctx, CHAPArgs{Node: "c1"}); err == nil {
		t.Fatal("rotated the secrets of a node with mapped volumes")
	}
	old, _ := r.loadCHAP()
	iqn := TargetIQN(testCluster, "c2")
	f.Sessions[iqn] = 1
	if err := r.RotateCHAP(ctx, CHAPArgs{Node: "c2"}); err != nil {
		t.Fatal(err)
	}
	now, _ := r.loadCHAP()
	if now["c2"].Password == old["c2"].Password || f.Sessions[iqn] != 0 {
		t.Fatalf("rotation: secrets changed %v, sessions %d", now["c2"].Password != old["c2"].Password, f.Sessions[iqn])
	}
	if cur := Current(f, testCluster)["c2"]; !cur.Enabled {
		t.Fatal("the target stayed disabled after the rotation")
	}
}

func TestRootConfigFSLockdownRefusal(t *testing.T) {
	r, f, _ := newRoot(t)
	nodes := newNodes(t)
	f.LockErr = errors.New("read-only")
	if _, err := r.Apply(context.Background(), nodes.args(desired(1, nil, Target{Node: "c1", Enabled: true}))); err == nil || !strings.Contains(err.Error(), "root's alone") {
		t.Fatalf("secrets written into an unlocked configfs: %v", err)
	}
}

func TestFenceRecordReadsTheEarlierFormat(t *testing.T) {
	var st rootState
	if err := json.Unmarshal([]byte(`{"fences":{"c1":3,"c2":{"epoch":4,"keyPin":"ab"}}}`), &st); err != nil {
		t.Fatal(err)
	}
	if st.Fences["c1"].Epoch != 3 || st.Fences["c2"].KeyPin != "ab" {
		t.Fatalf("%+v", st.Fences)
	}
}

func TestHoldersTrackWriters(t *testing.T) {
	var st rootState
	st.setHolders("x", []cluster.NodeID{"c1"})
	st.setHolders("x", []cluster.NodeID{"c1"})
	h := st.Holders["x"]
	if h.Seq != 1 || h.OthersWrote("c1") || !h.OthersWrote("c2") {
		t.Fatalf("%+v", h)
	}
	st.setHolders("x", []cluster.NodeID{"c2", "c1"})
	st.setHolders("x", []cluster.NodeID{"c2"})
	if h.Seq != 3 || !h.OthersWrote("c2") {
		t.Fatalf("%+v", h)
	}
	var nilH *Holders
	if !nilH.OthersWrote("c1") {
		t.Fatal("unknown holders must count as someone else")
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestRootVolumeChecks(t *testing.T) {
	r, _, fx := newRoot(t)
	ctx := context.Background()
	nodes := newNodes(t)
	w := WorkloadArgs{Kind: cluster.KindVM, ID: "web", Pool: "tank"}
	for _, bad := range []VolumeArgs{
		{WorkloadArgs: WorkloadArgs{Kind: cluster.KindVM, ID: "../x", Pool: "tank"}, Disk: "disk0", SizeGB: 1},
		{WorkloadArgs: w, Disk: "disk10", SizeGB: 1},
		{WorkloadArgs: w, Disk: "disk0", SizeGB: 0},
		{WorkloadArgs: WorkloadArgs{Kind: cluster.KindApp, ID: "web", Pool: "tank"}, Disk: "block", SizeGB: 1, FS: "btrfs"},
	} {
		if _, err := r.VolumeCreate(ctx, testCluster, bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	// Destroy needs the typed name and refuses what is mapped.
	if err := r.DatasetDestroy(ctx, DestroyArgs{WorkloadArgs: w, Confirm: "nope"}); err == nil {
		t.Fatal("destroy without confirmation")
	}
	b := bs("web", "disk0")
	zvolProps(fx, b.Dataset, "vm", "web")
	if _, err := r.Apply(ctx, nodes.args(desired(1, []Backstore{b}, Target{Node: "c1", Enabled: true, LUNs: []string{b.Name}}))); err != nil {
		t.Fatal(err)
	}
	fx.On("zfs get -H -p -o property,value org.hardyos:vm,org.hardyos:role tank/vms/web", "org.hardyos:vm\tweb\norg.hardyos:role\tcluster\n")
	if err := r.DatasetDestroy(ctx, DestroyArgs{WorkloadArgs: w, Confirm: "web"}); err == nil || !strings.Contains(err.Error(), "granted") {
		t.Fatalf("destroying a mapped VM: %v", err)
	}
	if err := r.SnapshotRollback(ctx, SnapshotArgs{WorkloadArgs: w, Name: "s1", Confirm: "s1"}); err == nil {
		t.Fatal("rolled back a mapped VM")
	}
	for _, l := range fx.Lines() {
		if strings.HasPrefix(l, "zfs destroy") || strings.HasPrefix(l, "zfs rollback") {
			t.Fatalf("ran %s", l)
		}
	}
	// Snapshots are capped per workload (M4).
	var many strings.Builder
	for i := 0; i < MaxSnapshots; i++ {
		fmt.Fprintf(&many, "tank/vms/web@s%d\t1700000000\t0\n", i)
	}
	fx.On("zfs list -H -p -t snapshot -d 1 -o name,creation,used tank/vms/web", many.String())
	if _, err := r.SnapshotCreate(ctx, SnapshotArgs{WorkloadArgs: w, Name: "one-more"}); err == nil || !strings.Contains(err.Error(), "delete some") {
		t.Fatalf("snapshot over the cap: %v", err)
	}
}

func TestDatasetCreateCapsTheParents(t *testing.T) {
	r, _, fx := newRoot(t)
	ctx := context.Background()
	fx.OnPrefix("zfs create ", sysexec.Result{})
	fx.OnPrefix("zfs set ", sysexec.Result{})
	fx.OnResult("zfs list -H -o name tank/vms", sysexec.Result{ExitCode: 1})
	fx.On("zfs get -H -p -o property,value quota tank/vms", "quota\t0\n")
	fx.On("zfs get -H -p -o property,value used,available tank", "used\t1000\navailable\t9000\n")
	fx.OnResult("zfs list -H -o name tank/vms/web", sysexec.Result{ExitCode: 1})
	fx.On("zfs get -H -p -o property,value mountpoint,guid,used tank/vms/web", "mountpoint\t/mnt/tank/vms/web\nguid\t5\nused\t0\n")
	if _, err := r.DatasetCreate(ctx, DatasetCreateArgs{WorkloadArgs: WorkloadArgs{Kind: cluster.KindVM, ID: "web", Pool: "tank"}}); err != nil {
		t.Fatal(err)
	}
	if !contains(fx.Lines(), "zfs set quota=9000 tank/vms") {
		t.Fatalf("parent not capped: %v", fx.Lines())
	}
}

func TestMigrateChecksAndNamesTheFileSystem(t *testing.T) {
	r, _, fx := newRoot(t)
	ctx := context.Background()
	fx.On("zfs get -H -p -o property,value org.hardyos:app,org.hardyos:role tank/apps/db", "org.hardyos:app\tdb\norg.hardyos:role\tcluster\n")
	fx.On("zfs get -H -p -o property,value org.hardyos:app,org.hardyos:role tank/apps/db/block", "org.hardyos:app\tdb\norg.hardyos:role\tcluster\n")
	fx.On("zfs get -H -p -o property,value mountpoint,guid,used tank/apps/db", "mountpoint\t/mnt/tank/apps/db\nguid\t5\nused\t0\n")
	for _, p := range []string{"zfs snapshot ", "mount ", "umount ", "rsync ", "mkfs.ext4 ", "find "} {
		fx.OnPrefix(p, sysexec.Result{})
	}
	args := MigrateArgs{App: "db", Pool: "tank", To: cluster.StorageNFS, Confirm: "db"}
	if _, err := r.Migrate(ctx, args); err == nil {
		t.Fatal("moved without naming the file system")
	}
	args.FS = BlockExt4
	fx.OnResult("e2fsck -f -n /dev/zvol/tank/apps/db/block", sysexec.Result{ExitCode: 4, Stdout: []byte("Inode 12 has illegal blocks")})
	if _, err := r.Migrate(ctx, args); err == nil || !strings.Contains(err.Error(), "didn't pass its check") {
		t.Fatalf("a failing file system check: %v", err)
	}
	for _, l := range fx.Lines() {
		if strings.HasPrefix(l, "mount ") {
			t.Fatalf("mounted a file system that failed its check: %s", l)
		}
	}
	fx.On("e2fsck -f -n /dev/zvol/tank/apps/db/block", "clean")
	args.RemoveOld = true
	res, err := r.Migrate(ctx, args)
	if err != nil {
		t.Fatal(err)
	}
	mnt := filepath.Join(r.Sys, "run/hardyos/cluster/migrate/db")
	if !contains(fx.Lines(), "mount -t ext4 -o nosuid,nodev,noexec,ro,noload /dev/zvol/tank/apps/db/block "+mnt) {
		t.Fatalf("the source wasn't mounted read-only as ext4: %v", fx.Lines())
	}
	if !res.Removed || !contains(fx.Lines(), "mkfs.ext4 -q -F -L hc-db /dev/zvol/tank/apps/db/block") {
		t.Fatalf("the old copy wasn't cleared by formatting: %+v %v", res, fx.Lines())
	}
	st, _ := r.load()
	if h := st.Holders[BackstoreName(cluster.WorkloadRef{Kind: cluster.KindApp, ID: "db"}, "block")]; h == nil || !h.OthersWrote("c1") {
		t.Fatalf("the storage node wasn't recorded as the writer: %+v", h)
	}
}
