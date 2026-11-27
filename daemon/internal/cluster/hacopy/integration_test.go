package hacopy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/nfs"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// TestHAConvertIntegration makes a VM's storage highly available and local
// again against the real kernel (docs/plans/make-ha.md): a file-backed
// "local" pool (a compute server's) and a "storage" pool (the storage
// server's); the VM's state folder and disk, with two snapshots, are sent
// across as single-dataset streams (an interrupted one resumed from its
// token), adopted as cluster storage, exported through LIO and read by an
// iSCSI initiator with mutual CHAP; then the local copy is parked, and the
// cluster copy sent back and adopted as the server's own again.
//
// Needs root, ZFS, open-iscsi and the LIO modules: CI's Cluster
// (namespaces) job, HARDYOS_CLUSTER_INTEGRATION=1. Missing kernel support
// is a skip with the reason.
func TestHAConvertIntegration(t *testing.T) {
	if os.Getenv("HARDYOS_CLUSTER_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_CLUSTER_INTEGRATION=1 to run against real ZFS, LIO and iSCSI (needs root)")
	}
	if os.Geteuid() != 0 {
		t.Fatal("must run as root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	sh := func(name string, args ...string) (string, error) {
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		return string(out), err
	}
	must := func(name string, args ...string) string {
		t.Helper()
		out, err := sh(name, args...)
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return out
	}
	for _, tool := range []string{"zpool", "zfs", "iscsiadm", "iscsid", "ip"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s isn't installed", tool)
		}
	}
	dir := t.TempDir()
	mkPool := func(name string) {
		vdev := filepath.Join(dir, name+".vdev")
		f, _ := os.Create(vdev)
		_ = f.Truncate(1 << 30)
		f.Close()
		_, _ = sh("zpool", "destroy", "-f", name)
		must("zpool", "create", "-o", "ashift=12", "-m", "/mnt/"+name, "-O", "xattr=sa", name, vdev)
		t.Cleanup(func() { _, _ = exec.Command("zpool", "destroy", "-f", name).CombinedOutput() })
	}
	const localPool, storePool = "hchalocal", "hchastore"
	mkPool(localPool)
	mkPool(storePool)

	// A local VM as the VM engine makes it: <pool>/vms/<id> with vm.json,
	// a zvol disk0, org.hardyos:vm on both.
	must("zfs", "create", localPool+"/vms")
	must("zfs", "create", "-o", "org.hardyos:vm=web", "-o", "canmount=on", "-o", "devices=off", "-o", "setuid=off", "-o", "exec=off", localPool+"/vms/web")
	spec := []byte(`{"id":"web","name":"Web","pool":"` + localPool + `"}` + "\n")
	if err := os.WriteFile("/mnt/"+localPool+"/vms/web/vm.json", spec, 0o600); err != nil {
		t.Fatal(err)
	}
	must("zfs", "create", "-s", "-V", "64M", "-o", "volblocksize=16K", "-o", "org.hardyos:vm=web", localPool+"/vms/web/disk0")
	dev := "/dev/zvol/" + localPool + "/vms/web/disk0"
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(dev); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	writeAt := func(dev string, b []byte, off int64) {
		t.Helper()
		f, err := os.OpenFile(dev, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteAt(b, off); err != nil {
			t.Fatal(err)
		}
		_ = f.Sync()
		f.Close()
	}
	first := bytes.Repeat([]byte("hardyos-make-ha!"), 256) // 4 KiB
	writeAt(dev, first, 0)
	must("zfs", "snapshot", "-r", localPool+"/vms/web@s1")
	// Enough data that a stream can be cut in the middle.
	noise := make([]byte, 8<<20)
	for i := range noise {
		noise[i] = byte(i*7 + i/4096)
	}
	writeAt(dev, noise, 1<<20)
	must("zfs", "snapshot", "-r", localPool+"/vms/web@s2")

	run := sysexec.Exec{}
	sanRoot := &san.Root{Runner: run, FS: san.OSFS{Root: san.ConfigFSRoot}, Dir: filepath.Join(dir, "san"), Sys: "/",
		NFS: &nfs.ClusterManager{Runner: run, Root: "/"}}
	compute := &Root{Runner: run}
	storage := &Root{Runner: run, Busy: sanRoot.InUse, EnsureParent: sanRoot.EnsureParent}
	local := Ref{Kind: cluster.KindVM, ID: "web", Pool: localPool, Side: SideLocal}
	clRef := Ref{Kind: cluster.KindVM, ID: "web", Pool: storePool, Side: SideCluster}
	const conv = "hatestconv01"

	waitStream := func(r *Root, id string) StreamState {
		t.Helper()
		for i := 0; i < 600; i++ {
			st, err := r.Stream(id)
			if err != nil {
				t.Fatal(err)
			}
			if st.Done {
				return *st
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("a stream never finished")
		return StreamState{}
	}
	// copyStep sends one stream from src to dst (cut after limit bytes
	// when limit > 0) and reports how the receive ended.
	copyStep := func(src, dst *Root, from, to Ref, conv, child, fromSnap, toSnap, token string, limit int64) StreamState {
		t.Helper()
		ss, rf, err := src.Send(ctx, SendArgs{Ref: from, Child: child, From: fromSnap, To: toSnap, Token: token})
		if err != nil {
			t.Fatalf("send %s %s@%s: %v", from.Side, child, toSnap, err)
		}
		label := toSnap
		if token != "" {
			label = toSnap
		}
		rs, wf, err := dst.Recv(ctx, RecvArgs{Ref: to, Conv: conv, Child: child, Label: label})
		if err != nil {
			rf.Close()
			t.Fatalf("recv %s %s@%s: %v", to.Side, child, toSnap, err)
		}
		var in io.Reader = rf
		if limit > 0 {
			in = io.LimitReader(rf, limit)
		}
		_, _ = io.Copy(wf, in)
		wf.Close()
		rf.Close()
		if limit > 0 {
			_ = src.Cancel(ss.Stream)
		}
		waitStream(src, ss.Stream)
		return waitStream(dst, rs.Stream)
	}
	// sendAll brings dst's incoming copy up to src's snapshots.
	sendAll := func(src, dst *Root, from, to Ref, conv string) {
		t.Helper()
		var srcTree *Tree
		var err error
		if from.Side == SideLocal || from.Side == SideCluster {
			srcTree, err = src.Tree(ctx, TreeArgs{Ref: from})
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range srcTree.Datasets {
			dstTree, err := dst.Tree(ctx, TreeArgs{Ref: to, Conv: conv})
			if err != nil {
				t.Fatal(err)
			}
			var have []Snap
			for _, x := range dstTree.Datasets {
				if x.Child == d.Child {
					have = x.Snaps
				}
			}
			prev := ""
			if len(have) > 0 {
				prev = have[len(have)-1].Name
			}
			started := prev == ""
			for _, s := range d.Snaps {
				if !started {
					started = s.Name == prev
					continue
				}
				if st := copyStep(src, dst, from, to, conv, d.Child, prev, s.Name, "", 0); !st.OK {
					t.Fatalf("copying %q@%s: %s", d.Child, s.Name, st.Error)
				}
				prev = s.Name
			}
		}
	}

	// The state folder first; then disk0's full stream is cut in the
	// middle and resumed from the receive's token.
	if st := copyStep(compute, storage, local, clRef, conv, "", "", "s1", "", 0); !st.OK {
		t.Fatalf("the state folder: %s", st.Error)
	}
	if st := copyStep(compute, storage, local, clRef, conv, "", "s1", "s2", "", 0); !st.OK {
		t.Fatalf("the state folder's increment: %s", st.Error)
	}
	if st := copyStep(compute, storage, local, clRef, conv, "disk0", "", "s1", "", 0); !st.OK {
		t.Fatalf("disk0@s1: %s", st.Error)
	}
	if st := copyStep(compute, storage, local, clRef, conv, "disk0", "s1", "s2", "", 1<<20); st.OK {
		t.Fatal("a stream cut in the middle was received whole")
	}
	tree, err := storage.Tree(ctx, TreeArgs{Ref: clRef, Conv: conv})
	if err != nil {
		t.Fatal(err)
	}
	token := ""
	for _, d := range tree.Datasets {
		if d.Child == "disk0" {
			token = d.Token
		}
	}
	if token == "" {
		t.Fatalf("no resume token after an interrupted receive: %+v", tree)
	}
	// A token is accepted only for the dataset it is of.
	if _, _, err := compute.Send(ctx, SendArgs{Ref: local, Child: "", Token: token}); err == nil {
		t.Fatal("a resume token of disk0 was accepted for the state folder")
	}
	if st := copyStep(compute, storage, local, clRef, conv, "disk0", "", "s2", token, 0); !st.OK {
		t.Fatalf("resuming disk0: %s", st.Error)
	}
	sendAll(compute, storage, local, clRef, conv) // nothing left: a no-op

	// Nothing is received over cluster storage that isn't the
	// conversion's own incoming copy.
	cid := cluster.ClusterID("hchatestclusteraaaaaaaaaaaa")
	res, err := storage.Adopt(ctx, AdoptArgs{Ref: clRef, Conv: conv, Cluster: cid})
	if err != nil {
		t.Fatal(err)
	}
	if res.Dataset != storePool+"/vms/web" || len(res.Volumes) != 1 || res.Volumes[0].WWN == "" {
		t.Fatalf("adopted %+v", res)
	}
	props := strings.Fields(must("zfs", "get", "-H", "-o", "value", "org.hardyos:role,org.hardyos:vm", storePool+"/vms/web/disk0"))
	if !slices.Equal(props, []string{"cluster", "web"}) {
		t.Fatalf("the adopted disk's marks: %v", props)
	}
	snaps := must("zfs", "list", "-H", "-o", "name", "-t", "snapshot", "-r", storePool+"/vms/web")
	for _, want := range []string{"web@s1", "web@s2", "disk0@s1", "disk0@s2"} {
		if !strings.Contains(snaps, want) {
			t.Fatalf("snapshot %s didn't arrive:\n%s", want, snaps)
		}
	}
	if b, err := os.ReadFile("/mnt/" + storePool + "/vms/web/vm.json"); err != nil || !bytes.Equal(b, spec) {
		t.Fatalf("the state folder on cluster storage: %q %v", b, err)
	}
	// Adopting again (an answer lost) describes what is there; nothing is
	// received over it.
	if again, err := storage.Adopt(ctx, AdoptArgs{Ref: clRef, Conv: conv, Cluster: cid}); err != nil || again.Volumes[0].WWN != res.Volumes[0].WWN {
		t.Fatalf("adopting again: %+v %v", again, err)
	}
	if _, err := compute.Adopt(ctx, AdoptArgs{Ref: local, Conv: conv}); err == nil {
		t.Fatal("this server adopted a copy it never received")
	}

	// LIO exports the adopted disk; an initiator with the node's CHAP
	// secrets reads what the VM wrote.
	exportAndRead(t, ctx, sh, must, sanRoot, cid, dir, res.Volumes[0], first)

	// The local copy is parked: no longer a VM. Compared with a snapshot
	// it doesn't have, it counts as changed and isn't parked.
	if _, err := compute.Park(ctx, ParkArgs{Ref: local, Confirm: "web", Conv: conv, Since: SnapPrefix + "nosuchsnap", RefuseChanged: true}); !errors.Is(err, ErrChanged) {
		t.Fatalf("parked a copy not compared with its final snapshot: %v", err)
	}
	pr, err := compute.Park(ctx, ParkArgs{Ref: local, Confirm: "web", Conv: conv})
	if err != nil {
		t.Fatal(err)
	}
	// Asked again (an answer lost): the same parked copy.
	if again, err := compute.Park(ctx, ParkArgs{Ref: local, Confirm: "web", Conv: conv}); err != nil || !again.Existing || again.Name != pr.Name {
		t.Fatalf("parking again: %+v %v", again, err)
	}
	if _, err := sh("zfs", "list", localPool+"/vms/web"); err == nil {
		t.Fatal("the local copy is still a VM's dataset after parking")
	}
	if v := strings.TrimSpace(must("zfs", "get", "-H", "-o", "value", "org.hardyos:vm", localPool+"/"+ParkedDir+"/"+pr.Name+"/disk0")); v != "-" {
		t.Fatalf("a parked disk is still marked as the VM's: %q", v)
	}
	parked, err := compute.ParkedList(ctx)
	if err != nil || len(parked) != 1 || parked[0].ID != "web" || parked[0].Side != SideLocal {
		t.Fatalf("parked copies: %+v %v", parked, err)
	}

	// Make local again: a final snapshot on cluster storage, sent back
	// into this server's incoming copy and adopted as its own.
	if err := storage.Snapshot(ctx, SnapArgs{Ref: clRef, Name: "hardyos-ha-hatestconv02-final"}); err != nil {
		t.Fatal(err)
	}
	const conv2 = "hatestconv02"
	sendAll(storage, compute, clRef, local, conv2)
	if _, err := compute.Adopt(ctx, AdoptArgs{Ref: local, Conv: conv2}); err != nil {
		t.Fatal(err)
	}
	if v := strings.TrimSpace(must("zfs", "get", "-H", "-o", "value", "org.hardyos:role", localPool+"/vms/web/disk0")); v == "cluster" {
		t.Fatal("the copy back is marked as cluster storage")
	}
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(dev); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	got := make([]byte, len(first))
	f, err := os.Open(dev)
	if err == nil {
		_, err = f.ReadAt(got, 0)
		f.Close()
	}
	if err != nil || !bytes.Equal(got, first) {
		t.Fatalf("the disk that came back: %v", err)
	}
	snaps = must("zfs", "list", "-H", "-o", "name", "-t", "snapshot", "-r", localPool+"/vms/web")
	for _, want := range []string{"web@s1", "web@s2", "web@hardyos-ha-hatestconv02-final", "disk0@s2"} {
		if !strings.Contains(snaps, want) {
			t.Fatalf("snapshot %s didn't come back:\n%s", want, snaps)
		}
	}

	// The cluster copy is parked too (nothing maps it any more), and both
	// kept copies are deleted with a typed confirmation.
	cp, err := storage.Park(ctx, ParkArgs{Ref: clRef, Confirm: "web", KeepUntil: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.ParkedDestroy(ctx, ParkedDestroyArgs{Pool: storePool, Name: cp.Name, Confirm: "nope"}); err == nil {
		t.Fatal("a kept copy was deleted without its name typed")
	}
	// The local copy has no expiry: deleted only as the possibly last copy.
	if err := compute.ParkedDestroy(ctx, ParkedDestroyArgs{Pool: localPool, Name: pr.Name, Confirm: "web"}); !errors.Is(err, ErrLastCopy) {
		t.Fatalf("a copy without an expiry was deleted: %v", err)
	}
	for _, p := range []struct {
		r    *Root
		pool string
		name string
		last bool
	}{{storage, storePool, cp.Name, false}, {compute, localPool, pr.Name, true}} {
		if err := p.r.ParkedDestroy(ctx, ParkedDestroyArgs{Pool: p.pool, Name: p.name, Confirm: "web", LastCopy: p.last}); err != nil {
			t.Fatal(err)
		}
	}
}

// exportAndRead maps vol into compute node c1's target and reads its first
// 4 KiB from an initiator with c1's secrets (a private iscsid in its own
// mount namespace, as san's integration test does).
func exportAndRead(t *testing.T, ctx context.Context, sh func(string, ...string) (string, error), must func(string, ...string) string,
	r *san.Root, cid cluster.ClusterID, dir string, vol VolumeInfo, want []byte) {
	t.Helper()
	for _, m := range []string{"configfs", "target_core_mod", "target_core_iblock", "iscsi_target_mod", "iscsi_tcp"} {
		if out, err := sh("modprobe", m); err != nil {
			t.Skipf("this kernel can't load %s (%v: %s)", m, err, strings.TrimSpace(out))
		}
	}
	if _, err := os.Stat(san.ConfigFSRoot); err != nil {
		_, _ = sh("mount", "-t", "configfs", "none", "/sys/kernel/config")
		_, _ = sh("mkdir", "-p", san.ConfigFSRoot)
	}
	if _, err := os.Stat(filepath.Join(san.ConfigFSRoot, "core")); err != nil {
		t.Skipf("LIO's configfs isn't there: %v", err)
	}
	if out, err := sh("pgrep", "-x", "iscsid"); err == nil {
		t.Skipf("an iscsid is already running on this machine (%s)", strings.TrimSpace(out))
	}
	const link = "hcha0"
	_, _ = sh("ip", "link", "del", link)
	must("ip", "link", "add", link, "type", "dummy")
	must("ip", "addr", "add", "10.178.0.10/24", "dev", link)
	must("ip", "link", "set", link, "up")
	t.Cleanup(func() {
		_ = san.Reconcile(r.FS, san.Plan{Desired: san.Desired{Cluster: cid}})
		_, _ = exec.Command("ip", "link", "del", link).CombinedOutput()
	})
	w := cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web"}
	b := san.Backstore{Name: san.BackstoreName(w, vol.Disk), Workload: w, Dataset: vol.Dataset, Disk: vol.Disk, Generation: 1}
	id, err := cluster.NewIdentity("c1")
	if err != nil {
		t.Fatal(err)
	}
	d := san.Desired{Cluster: cid, Index: 1, Portals: []netip.AddrPort{netip.MustParseAddrPort("10.178.0.10:3260")}, Backstores: []san.Backstore{b},
		Targets: []san.Target{{Node: "c1", Enabled: true, LUNs: []string{b.Name}}}}
	if _, err := r.Apply(ctx, san.ApplyArgs{Desired: d, Addresses: map[cluster.NodeID]netip.Addr{"c1": netip.MustParseAddr("10.178.0.21")},
		Keys: map[cluster.NodeID][]byte{"c1": id.PublicKey}, Subnet: netip.MustParsePrefix("10.178.0.0/24")}); err != nil {
		t.Fatal(err)
	}
	if busy, err := r.InUse(ctx, cluster.KindVM, "web", strings.SplitN(vol.Dataset, "/", 2)[0]); err != nil || !busy {
		t.Fatalf("a mapped disk isn't in use: %v %v", busy, err)
	}
	sec, err := r.CHAP(ctx, san.CHAPArgs{Node: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	target := san.TargetIQN(cid, "c1")
	etc := filepath.Join(dir, "c1", "etc")
	lib := filepath.Join(dir, "c1", "lib")
	_ = os.MkdirAll(filepath.Join(etc, "nodes", target, "10.178.0.10,3260,1"), 0o700)
	_ = os.MkdirAll(lib, 0o700)
	_ = os.WriteFile(filepath.Join(etc, "initiatorname.iscsi"), []byte("InitiatorName="+san.InitiatorIQN(cid, "c1")+"\n"), 0o600)
	_ = os.WriteFile(filepath.Join(etc, "iscsid.conf"), []byte("node.startup = manual\n"), 0o600)
	rec := strings.Join([]string{"# BEGIN RECORD", "node.name = " + target, "node.tpgt = 1", "node.startup = manual",
		"iface.iscsi_ifacename = default", "iface.transport_name = tcp", "node.discovery_type = static",
		"node.session.auth.authmethod = CHAP", "node.session.auth.username = " + sec.User, "node.session.auth.password = " + sec.Password,
		"node.session.auth.username_in = " + sec.MutualUser, "node.session.auth.password_in = " + sec.MutualPassword,
		"node.session.timeo.replacement_timeout = 5", "node.conn[0].address = 10.178.0.10", "node.conn[0].port = 3260",
		"node.conn[0].startup = manual", "# END RECORD", ""}, "\n")
	_ = os.WriteFile(filepath.Join(etc, "nodes", target, "10.178.0.10,3260,1", "default"), []byte(rec), 0o600)
	devPath := san.ByIDPath(vol.WWN)
	logf := filepath.Join(dir, "c1", "iscsid.log")
	script := "set -e; mount --make-rprivate /; mkdir -p /etc/iscsi /var/lib/iscsi /run/lock/iscsi; mount --bind " + etc + " /etc/iscsi; " +
		"mount --bind " + lib + " /var/lib/iscsi; mount -t tmpfs tmpfs /run/lock/iscsi; " +
		"iscsid -f -n -d 1 >>" + logf + " 2>&1 & pid=$!; trap 'kill $pid 2>/dev/null; wait $pid 2>/dev/null || true' EXIT; " +
		"for i in $(seq 1 20); do rc=0; iscsiadm -m session >/dev/null 2>&1 || rc=$?; if [ $rc -eq 0 ] || [ $rc -eq 21 ]; then break; fi; sleep 0.25; done; " +
		"iscsiadm -m node -T " + target + " -p 10.178.0.10:3260 --login; " +
		"for i in $(seq 1 40); do [ -e " + devPath + " ] && break; sleep 0.25; done; " +
		"dd if=" + devPath + " bs=4096 count=1 iflag=direct 2>/dev/null | sha256sum; " +
		"iscsiadm -m node -T " + target + " --logout || true"
	out, err := sh("setsid", "-w", "unshare", "-m", "-p", "--fork", "--mount-proc", "sh", "-c", script)
	if err != nil {
		l, _ := os.ReadFile(logf)
		t.Fatalf("the initiator: %v\n%s\n--- iscsid log ---\n%s", err, out, l)
	}
	sum := sha256.Sum256(want)
	if !strings.Contains(out, hex.EncodeToString(sum[:])) {
		t.Fatalf("the initiator read something else than the VM wrote:\n%s", out)
	}
	// Unmapped again before the copy goes back (as workload.remove does).
	d.Index, d.Backstores, d.Targets = 2, nil, []san.Target{{Node: "c1", Enabled: true}}
	if _, err := r.Apply(ctx, san.ApplyArgs{Desired: d, Addresses: map[cluster.NodeID]netip.Addr{"c1": netip.MustParseAddr("10.178.0.21")},
		Keys: map[cluster.NodeID][]byte{"c1": id.PublicKey}, Subnet: netip.MustParsePrefix("10.178.0.0/24")}); err != nil {
		t.Fatal(err)
	}
}
