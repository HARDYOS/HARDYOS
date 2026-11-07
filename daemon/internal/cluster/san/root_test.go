package san

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	return r, f, fx
}

func zvolProps(fx *sysexec.Fake, ds, kind, id string) {
	fx.On("zfs get -H -p -o property,value type,guid,sync,org.hardyos:role,org.hardyos:"+kind+" "+ds,
		"type\tvolume\nguid\t4242\nsync\tstandard\norg.hardyos:role\tcluster\norg.hardyos:"+kind+"\t"+id+"\n")
}

func desired(idx uint64, b []Backstore, t ...Target) Desired {
	return Desired{Cluster: testCluster, Index: idx, Portals: []netip.AddrPort{portal}, Backstores: b, Targets: t}
}

func TestRootApplyChecksDatasetsAndKeepsFences(t *testing.T) {
	r, f, fx := newRoot(t)
	ctx := context.Background()
	b := bs("web", "disk0")
	zvolProps(fx, b.Dataset, "vm", "web")
	addrs := map[cluster.NodeID]netip.Addr{"c1": netip.MustParseAddr("10.77.0.21"), "c2": netip.MustParseAddr("10.77.0.22")}
	st, err := r.Apply(ctx, ApplyArgs{Desired: desired(5, []Backstore{b}, Target{Node: "c1", Enabled: true, LUNs: []string{b.Name}}, Target{Node: "c2", Enabled: true}), Addresses: addrs})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Current["c1"].LUNs) != 1 || st.Resolved[b.Name].WWN != WWN(Serial(testCluster, "4242")) {
		t.Fatalf("status %+v", st)
	}
	// Root's files are 0600 in a 0700 folder.
	for _, p := range []string{r.statePath(), r.chapPath()} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, fi.Mode(), err)
		}
	}
	// An older desired state is refused (no replay of an old request).
	if _, err := r.Apply(ctx, ApplyArgs{Desired: desired(4, nil, Target{Node: "c1", Enabled: true})}); err == nil {
		t.Fatal("an older desired state was applied")
	}
	// A zvol of another VM (or not marked cluster) is refused.
	other := bs("db", "disk0")
	fx.On("zfs get -H -p -o property,value type,guid,sync,org.hardyos:role,org.hardyos:vm "+other.Dataset,
		"type\tvolume\nguid\t1\nsync\tstandard\norg.hardyos:role\t-\norg.hardyos:vm\tdb\n")
	_, err = r.Apply(ctx, ApplyArgs{Desired: desired(6, []Backstore{other}, Target{Node: "c1", Enabled: true, LUNs: []string{other.Name}})})
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("a non-cluster zvol: %v", err)
	}
	// Fence c1.
	res, err := r.Fence(ctx, FenceArgs{Node: "c1", Epoch: 2, Confirm: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.TargetDisabled {
		t.Fatalf("fence %+v", res)
	}
	if cur := Current(f, testCluster)["c1"]; cur.Enabled || len(cur.LUNs) != 0 {
		t.Fatalf("after fence %+v", cur)
	}
	// hardyd can't hand the LUN back to a fenced node by applying again.
	_, err = r.Apply(ctx, ApplyArgs{Desired: desired(7, []Backstore{b}, Target{Node: "c1", Enabled: true, LUNs: []string{b.Name}}, Target{Node: "c2", Enabled: true})})
	if !errors.As(err, &ve) || !strings.Contains(err.Error(), "fenced") {
		t.Fatalf("re-granting a fenced node: %v", err)
	}
	// Nor get its CHAP secrets.
	if _, err := r.CHAP(ctx, CHAPArgs{Node: "c1"}); err == nil {
		t.Fatal("a fenced node's secrets were handed out")
	}
	// Fence needs the typed name; unfence needs the epoch.
	if _, err := r.Fence(ctx, FenceArgs{Node: "c2", Epoch: 1}); err == nil {
		t.Fatal("fence without confirmation")
	}
	if err := r.Unfence(ctx, UnfenceArgs{Node: "c1", Epoch: 1}); err == nil {
		t.Fatal("unfence with the wrong epoch")
	}
	if err := r.Unfence(ctx, UnfenceArgs{Node: "c1", Epoch: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Apply(ctx, ApplyArgs{Desired: desired(8, []Backstore{b}, Target{Node: "c1", Enabled: true, LUNs: []string{b.Name}}, Target{Node: "c2", Enabled: true})}); err != nil {
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

func TestRootFenceCutsExportsAndFirewall(t *testing.T) {
	r, _, fx := newRoot(t)
	ctx := context.Background()
	c1, c2 := netip.MustParseAddr("10.77.0.21"), netip.MustParseAddr("10.77.0.22")
	if _, err := r.Apply(ctx, ApplyArgs{Desired: desired(1, nil, Target{Node: "c1", Enabled: true}, Target{Node: "c2", Enabled: true}),
		Addresses: map[cluster.NodeID]netip.Addr{"c1": c1, "c2": c2}}); err != nil {
		t.Fatal(err)
	}
	fx.On("zfs get -H -p -o property,value type,guid,mountpoint,mounted,org.hardyos:vm,org.hardyos:role tank/vms/web",
		"type\tfilesystem\nguid\t77\nmountpoint\t/mnt/tank/vms/web\nmounted\tyes\norg.hardyos:vm\tweb\norg.hardyos:role\tcluster\n")
	fx.On("zfs get -H -p -o property,value type,guid,mountpoint,mounted,org.hardyos:share,org.hardyos:role tank/shares/media",
		"type\tfilesystem\nguid\t78\nmountpoint\t/mnt/tank/shares/media\nmounted\tyes\norg.hardyos:share\tmedia\norg.hardyos:role\t-\n")
	got, err := r.NFSApply(ctx, NFSApplyArgs{Exports: []nfs.ClusterExport{
		{Kind: nfs.KindVMState, Dataset: "tank/vms/web", Path: "/evil", GUID: "1", Clients: []netip.Addr{c1}},
		{Kind: nfs.KindShare, Dataset: "tank/shares/media", Clients: []netip.Addr{c1, c2}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Path != "/mnt/tank/vms/web" || got[0].GUID != "77" {
		t.Fatalf("root must use the dataset's own mountpoint and GUID: %+v", got[0])
	}
	if err := r.FirewallApply(ctx, FirewallSpec{Role: cluster.RoleStorage, Interface: "enp2s0", Subnet: netip.MustParsePrefix("10.77.0.0/24"), Members: []netip.Addr{c1, c2}}); err != nil {
		t.Fatal(err)
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
	fw, _ := os.ReadFile(filepath.Join(r.Sys, FirewallFile))
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
}

func TestRootVolumeChecks(t *testing.T) {
	r, _, fx := newRoot(t)
	ctx := context.Background()
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
	if _, err := r.Apply(ctx, ApplyArgs{Desired: desired(1, []Backstore{b}, Target{Node: "c1", Enabled: true, LUNs: []string{b.Name}})}); err != nil {
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
}
