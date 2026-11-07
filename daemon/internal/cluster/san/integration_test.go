package san

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/nfs"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// TestClusterStorageIntegration runs the storage node's root side against
// the real kernel: LIO through configfs on a file-backed ZFS pool's zvols,
// iSCSI logins with mutual CHAP from two compute "nodes" (each with a
// private iscsid and /etc/iscsi in its own mount namespace, so this
// machine's iSCSI configuration is never touched), a fence dropping the
// session, and the cluster NFS exports mounted from two network
// namespaces (owner only, root_squash on shares).
//
// It needs root, ZFS, open-iscsi, the NFS server and the LIO target
// modules (target_core_mod, target_core_iblock, iscsi_target_mod; on
// Ubuntu runners linux-modules-extra). It writes the cluster exports file
// and restarts nfs-server, so it only runs on a throwaway machine:
// HARDYOS_CLUSTER_INTEGRATION=1 (CI's "Cluster (namespaces)" job). Missing
// kernel support is a skip with the reason, not a failure.
func TestClusterStorageIntegration(t *testing.T) {
	if os.Getenv("HARDYOS_CLUSTER_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_CLUSTER_INTEGRATION=1 to run against real LIO, ZFS, iSCSI and NFS (needs root; changes the NFS server)")
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
	for _, m := range []string{"configfs", "target_core_mod", "target_core_iblock", "iscsi_target_mod", "iscsi_tcp"} {
		if out, err := sh("modprobe", m); err != nil {
			t.Skipf("this kernel can't load %s (%v: %s); install linux-modules-extra-$(uname -r) to run the LIO tests", m, err, strings.TrimSpace(out))
		}
	}
	if _, err := os.Stat(ConfigFSRoot); err != nil {
		_, _ = sh("mount", "-t", "configfs", "none", "/sys/kernel/config")
		_, _ = sh("mkdir", "-p", ConfigFSRoot)
	}
	if _, err := os.Stat(filepath.Join(ConfigFSRoot, "core")); err != nil {
		t.Skipf("LIO's configfs isn't there: %v", err)
	}
	for _, tool := range []string{"iscsiadm", "iscsid", "zpool", "exportfs", "ip"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s isn't installed", tool)
		}
	}

	// A file-backed pool.
	dir := t.TempDir()
	vdev := filepath.Join(dir, "vdev")
	f, _ := os.Create(vdev)
	_ = f.Truncate(1 << 30)
	f.Close()
	const pool = "hcbtest"
	_, _ = sh("zpool", "destroy", "-f", pool)
	must("zpool", "create", "-o", "ashift=12", "-m", "/mnt/"+pool, "-O", "xattr=sa", "-O", "acltype=posixacl", pool, vdev)
	t.Cleanup(func() { _, _ = exec.Command("zpool", "destroy", "-f", pool).CombinedOutput() })

	// Two compute nodes in network namespaces on a bridge; the storage
	// node is the init namespace at 10.177.0.10.
	const br = "hcbbr0"
	cleanupNet := func() {
		for _, ns := range []string{"hcb-c1", "hcb-c2"} {
			_ = exec.Command("ip", "netns", "pids", ns).Run()
			out, _ := exec.Command("ip", "netns", "pids", ns).Output()
			for _, pid := range strings.Fields(string(out)) {
				_ = exec.Command("kill", "-9", pid).Run()
			}
			_ = exec.Command("ip", "netns", "del", ns).Run()
		}
		_ = exec.Command("ip", "link", "del", br).Run()
	}
	cleanupNet()
	t.Cleanup(cleanupNet)
	must("ip", "link", "add", br, "type", "bridge")
	must("ip", "addr", "add", "10.177.0.10/24", "dev", br)
	must("ip", "link", "set", br, "up")
	for i, ns := range []string{"hcb-c1", "hcb-c2"} {
		host, peer := "hcbh"+string(rune('1'+i)), "hcbp"+string(rune('1'+i))
		must("ip", "netns", "add", ns)
		must("ip", "link", "add", host, "type", "veth", "peer", "name", peer)
		must("ip", "link", "set", host, "master", br, "up")
		must("ip", "link", "set", peer, "netns", ns)
		must("ip", "-n", ns, "addr", "add", "10.177.0.2"+string(rune('1'+i))+"/24", "dev", peer)
		must("ip", "-n", ns, "link", "set", peer, "up")
		must("ip", "-n", ns, "link", "set", "lo", "up")
	}

	r := &Root{Runner: sysexec.Exec{}, FS: OSFS{Root: ConfigFSRoot}, Dir: filepath.Join(dir, "state"), Sys: "/",
		NFS: &nfs.ClusterManager{Runner: sysexec.Exec{}, Root: "/"}}
	const cl = cluster.ClusterID("hcbtestclusteraaaaaaaaaaaa")
	t.Cleanup(func() {
		_ = Reconcile(r.FS, Plan{Desired: Desired{Cluster: cl}})
		_ = os.Remove(nfs.ClusterExportsFile)
		_ = os.Remove(nfs.ClusterConfFile)
		_ = os.Remove(FirewallFile)
		_ = os.Remove(FSBlacklistFile)
		_, _ = exec.Command("nft", "delete", "table", "inet", FirewallTable).CombinedOutput()
		_, _ = exec.Command("exportfs", "-ra").CombinedOutput()
	})
	web := WorkloadArgs{Kind: cluster.KindVM, ID: "web", Pool: pool}
	if _, err := r.DatasetCreate(ctx, DatasetCreateArgs{WorkloadArgs: web}); err != nil {
		t.Fatal(err)
	}
	vol, err := r.VolumeCreate(ctx, cl, VolumeArgs{WorkloadArgs: web, Disk: "disk0", SizeGB: 1})
	if err != nil {
		t.Fatal(err)
	}
	b := Backstore{Name: BackstoreName(cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web"}, "disk0"),
		Workload: cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web"}, Dataset: vol.Dataset, Disk: "disk0", Generation: 1}
	addrs := map[cluster.NodeID]netip.Addr{"c1": netip.MustParseAddr("10.177.0.21"), "c2": netip.MustParseAddr("10.177.0.22")}
	d := Desired{Cluster: cl, Index: 1, Portals: []netip.AddrPort{netip.MustParseAddrPort("10.177.0.10:3260")}, Backstores: []Backstore{b},
		Targets: []Target{{Node: "c1", Enabled: true, LUNs: []string{b.Name}}, {Node: "c2", Enabled: true}}}
	ids := map[cluster.NodeID]*cluster.Identity{}
	keys := map[cluster.NodeID][]byte{}
	for _, n := range []cluster.NodeID{"c1", "c2"} {
		id, err := cluster.NewIdentity(string(n))
		if err != nil {
			t.Fatal(err)
		}
		ids[n], keys[n] = id, id.PublicKey
	}
	subnet := netip.MustParsePrefix("10.177.0.0/24")
	st, err := r.Apply(ctx, ApplyArgs{Desired: d, Addresses: addrs, Keys: keys, Subnet: subnet})
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(ConfigFSRoot); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("LIO's configfs folder isn't root's alone: %v %v", fi.Mode(), err)
	}
	if len(st.Current["c1"].LUNs) != 1 || len(st.Drift) != 0 {
		t.Fatalf("LIO after apply: %+v drift %+v", st.Current, st.Drift)
	}
	sec1, _ := r.CHAP(ctx, CHAPArgs{Node: "c1"})

	// An initiator with its own iscsid and /etc/iscsi. The kernel's iSCSI
	// initiator (scsi_transport_iscsi's netlink) only serves the initial
	// network namespace, so an iscsid inside a namespace dies as soon as it
	// asks the kernel for a session (the target sees the TCP connection
	// close before the first login PDU). The initiators therefore run in
	// the initial network namespace, each in a private mount namespace
	// with its own node records and a private iscsid that is stopped after
	// every run (iscsid's control socket is per network namespace, so two
	// at once would share one daemon). The target's ACLs are by initiator
	// name, which is what these runs check; NFS, which is namespace-aware,
	// still runs from the namespaces below.
	if out, err := sh("pgrep", "-x", "iscsid"); err == nil {
		t.Skipf("an iscsid is already running on this machine (%s); this test runs its own", strings.TrimSpace(out))
	}
	initiator := func(ns, initName, target string, s Secrets, script string) (string, error) {
		etc := filepath.Join(dir, ns, "etc")
		lib := filepath.Join(dir, ns, "lib")
		_ = os.MkdirAll(filepath.Join(etc, "nodes", target, "10.177.0.10,3260,1"), 0o700)
		_ = os.MkdirAll(lib, 0o700)
		_ = os.WriteFile(filepath.Join(etc, "initiatorname.iscsi"), []byte("InitiatorName="+initName+"\n"), 0o600)
		_ = os.WriteFile(filepath.Join(etc, "iscsid.conf"), []byte("node.startup = manual\n"), 0o600)
		rec := strings.Join([]string{"# BEGIN RECORD", "node.name = " + target, "node.tpgt = 1", "node.startup = manual",
			"iface.iscsi_ifacename = default", "iface.transport_name = tcp", "node.discovery_type = static",
			"node.session.auth.authmethod = CHAP", "node.session.auth.username = " + s.User, "node.session.auth.password = " + s.Password,
			"node.session.auth.username_in = " + s.MutualUser, "node.session.auth.password_in = " + s.MutualPassword,
			"node.session.timeo.replacement_timeout = 5", "node.conn[0].address = 10.177.0.10", "node.conn[0].port = 3260",
			"node.conn[0].startup = manual", "# END RECORD", ""}, "\n")
		_ = os.WriteFile(filepath.Join(etc, "nodes", target, "10.177.0.10,3260,1", "default"), []byte(rec), 0o600)
		logf := filepath.Join(dir, ns, "iscsid.log")
		full := "set -e; mount --make-rprivate /; mkdir -p /etc/iscsi /var/lib/iscsi /run/lock/iscsi; mount --bind " + etc + " /etc/iscsi; " +
			"mount --bind " + lib + " /var/lib/iscsi; mount -t tmpfs tmpfs /run/lock/iscsi; " +
			"iscsid -f -n -d 1 >>" + logf + " 2>&1 & pid=$!; trap 'kill $pid 2>/dev/null; wait $pid 2>/dev/null || true' EXIT; " +
			"for i in $(seq 1 20); do rc=0; iscsiadm -m session >/dev/null 2>&1 || rc=$?; if [ $rc -eq 0 ] || [ $rc -eq 21 ]; then break; fi; sleep 0.25; done; " +
			script
		out, err := sh("unshare", "-m", "sh", "-c", full)
		if err != nil {
			if l, rerr := os.ReadFile(logf); rerr == nil {
				out += "\n--- iscsid log ---\n" + string(l)
			}
		}
		return out, err
	}
	t1 := TargetIQN(cl, "c1")
	login := "iscsiadm -m node -T " + t1 + " -p 10.177.0.10:3260 --login"
	// Wrong secret: refused.
	bad := *sec1
	bad.Password = "WrongSecretWrongSecret12"
	if out, err := initiator("hcb-c1", InitiatorIQN(cl, "c1"), t1, bad, login); err == nil {
		t.Fatalf("a login with the wrong CHAP secret worked:\n%s", out)
	}
	// c2 can't use c1's target even with c1's secrets (one ACL: c1's initiator).
	if out, err := initiator("hcb-c2", InitiatorIQN(cl, "c2"), t1, *sec1, login); err == nil {
		t.Fatalf("another node logged in to c1's target:\n%s", out)
	}
	// c1 logs in and sees its LUN by WWN; then it is fenced while logged in.
	dev := ByIDPath(vol.WWN)
	fencedFlag := filepath.Join(dir, "fenced")
	readFlag := filepath.Join(dir, "read")
	script := login + "; for i in $(seq 1 40); do [ -e " + dev + " ] && break; sleep 0.25; done; [ -e " + dev + " ]; " +
		"dd if=" + dev + " of=/dev/null bs=4k count=1 iflag=direct; echo FENCE-NOW; touch " + readFlag + "; " +
		"for i in $(seq 1 60); do [ -e " + fencedFlag + " ] && break; sleep 0.25; done; " +
		"if dd if=" + dev + " of=/dev/null bs=4k count=1 iflag=direct 2>/dev/null; then echo READ-AFTER-FENCE; fi; " +
		"iscsiadm -m node -T " + t1 + " --logout || true"
	done := make(chan struct{})
	var out string
	var lerr error
	go func() {
		defer close(done)
		out, lerr = initiator("hcb-c1", InitiatorIQN(cl, "c1"), t1, *sec1, script)
	}()
	deadline := time.Now().Add(30 * time.Second)
	for Sessions(r.FS, cl)["c1"] == 0 && time.Now().Before(deadline) {
		time.Sleep(250 * time.Millisecond)
	}
	if Sessions(r.FS, cl)["c1"] == 0 {
		<-done
		t.Fatalf("c1 never logged in: %v\n%s", lerr, out)
	}
	// c1 read its disk before anything is cut.
	for _, err := os.Stat(readFlag); err != nil && time.Now().Before(deadline.Add(30*time.Second)); _, err = os.Stat(readFlag) {
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := os.Stat(readFlag); err != nil {
		_ = os.WriteFile(fencedFlag, nil, 0o644)
		<-done
		t.Fatalf("c1 couldn't read its disk: %v\n%s", lerr, out)
	}
	// The storage firewall (a fence is complete only once the node's
	// address is blocked). The initiators above reach the portal over the
	// loopback, which the firewall then cuts too.
	if err := r.FirewallApply(ctx, FirewallSpec{Role: cluster.RoleStorage, Interface: br, Subnet: subnet,
		Members: []netip.Addr{addrs["c1"], addrs["c2"]}, Index: 1}); err != nil {
		t.Fatal(err)
	}
	res, err := r.Fence(ctx, FenceArgs{Node: "c1", Epoch: 1, Confirm: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.TargetDisabled || res.SessionsDropped != 1 || !res.AddressBlocked {
		t.Fatalf("fence %+v", res)
	}
	_ = os.WriteFile(fencedFlag, nil, 0o644)
	<-done
	if strings.Contains(out, "READ-AFTER-FENCE") || !strings.Contains(out, "FENCE-NOW") {
		t.Fatalf("fenced node could still read, or never read before: %v\n%s", lerr, out)
	}
	if n := Sessions(r.FS, cl)["c1"]; n != 0 {
		t.Fatalf("sessions after fence: %d", n)
	}
	if err := r.Unfence(ctx, UnfenceArgs{Node: "c1", Epoch: 1}); err == nil {
		t.Fatal("unfenced without the node's signed rejoin")
	}
	stmt, err := SignRejoin(ids["c1"].Key, RejoinStatement{Cluster: cl, Node: "c1", Epoch: 1, BootID: "b2"})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Unfence(ctx, UnfenceArgs{Node: "c1", Epoch: 1, Statement: &stmt}); err != nil {
		t.Fatal(err)
	}
	// web is granted to c1 again (its state is exported only to the node
	// that holds its disks).
	d.Index = 2
	if _, err := r.Apply(ctx, ApplyArgs{Desired: d, Addresses: addrs, Keys: keys, Subnet: subnet}); err != nil {
		t.Fatal(err)
	}

	// NFS: the VM's state only to c1 (no_root_squash); a share to both
	// with root squashed.
	must("zfs", "create", "-o", "org.hardyos:share=media", pool+"/shares")
	must("zfs", "create", "-o", "org.hardyos:share=media", pool+"/shares/media")
	exports, err := r.NFSApply(ctx, NFSApplyArgs{Exports: []nfs.ClusterExport{
		{Kind: nfs.KindVMState, Dataset: pool + "/vms/web", Clients: []netip.Addr{addrs["c1"]}},
		{Kind: nfs.KindShare, Dataset: pool + "/shares/media", Clients: []netip.Addr{addrs["c1"], addrs["c2"]}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(exports) != 2 {
		t.Fatalf("exports %+v", exports)
	}
	_ = os.Chmod("/mnt/"+pool+"/shares/media", 0o777)
	nfsMount := func(ns, path, script string) (string, error) {
		return sh("ip", "netns", "exec", ns, "sh", "-c", "set -e; mkdir -p /tmp/hcbm; mount -t nfs4 -o vers=4.2,hard,timeo=50,retrans=1,nosuid,nodev 10.177.0.10:"+path+" /tmp/hcbm; "+script+"; umount /tmp/hcbm")
	}
	if out, err := nfsMount("hcb-c1", "/mnt/"+pool+"/vms/web", "touch /tmp/hcbm/vm.json; stat -c %u /tmp/hcbm/vm.json"); err != nil || strings.TrimSpace(out) != "0" {
		t.Fatalf("owner mount of VM state: %v\n%s", err, out)
	}
	if out, err := sh("timeout", "20", "ip", "netns", "exec", "hcb-c2", "sh", "-c", "mkdir -p /tmp/hcbm; mount -t nfs4 -o vers=4.2,soft,timeo=20,retrans=1 10.177.0.10:/mnt/"+pool+"/vms/web /tmp/hcbm"); err == nil {
		t.Fatalf("another node mounted c1's VM state:\n%s", out)
	}
	if out, err := nfsMount("hcb-c2", "/mnt/"+pool+"/shares/media", "touch /tmp/hcbm/f; stat -c %u /tmp/hcbm/f"); err != nil || strings.TrimSpace(out) != "65534" {
		t.Fatalf("root on a cluster share must be squashed: %v\n%s", err, out)
	}
}
