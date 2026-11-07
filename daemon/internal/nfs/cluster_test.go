package nfs

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, x := range s {
		out = append(out, netip.MustParseAddr(x))
	}
	return out
}

func TestRenderCluster(t *testing.T) {
	exports := []ClusterExport{
		{Kind: KindShare, Dataset: "tank/shares/media", Path: "/mnt/tank/shares/media", GUID: "9", Clients: addrs("10.77.0.22", "10.77.0.21")},
		{Kind: KindVMState, Dataset: "tank/vms/web", Path: "/mnt/tank/vms/web", GUID: "8", Clients: addrs("10.77.0.21")},
		{Kind: KindAppData, Dataset: "tank/apps/notes", Path: "/mnt/tank/apps/notes", GUID: "7", Clients: addrs("10.77.0.22")},
	}
	out, err := RenderCluster(exports)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCluster(out, exports); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/mnt/tank/apps/notes 10.77.0.22(rw,sync,no_subtree_check,no_root_squash,sec=sys,fsid=" + FSID("7") + ")",
		"/mnt/tank/shares/media 10.77.0.21(rw,sync,no_subtree_check,root_squash,sec=sys,fsid=" + FSID("9") + ") 10.77.0.22(rw,sync,no_subtree_check,root_squash,sec=sys,fsid=" + FSID("9") + ")",
		"/mnt/tank/vms/web 10.77.0.21(rw,sync,no_subtree_check,no_root_squash,sec=sys,fsid=" + FSID("8") + ")",
	}
	for _, w := range want {
		if !strings.Contains(out, w+"\n") {
			t.Errorf("missing %q in\n%s", w, out)
		}
	}
	if FSID("7") == FSID("8") || FSID("7") != FSID("7") {
		t.Fatal("fsid must be stable and per dataset")
	}
	for _, bad := range []ClusterExport{
		{Kind: KindVMState, Dataset: "tank/vms/web", Path: "/mnt/tank/vms/web", GUID: "8", Clients: addrs("10.77.0.21", "10.77.0.22", "10.77.0.23")},
		{Kind: KindVMState, Dataset: "tank/shares/web", Path: "/mnt/x", GUID: "8", Clients: addrs("10.77.0.21")},
		{Kind: KindShare, Dataset: "tank/shares/m", Path: "/mnt/tank/shares/m", GUID: "8"},
		{Kind: KindShare, Dataset: "tank/shares/m", Path: "/mnt/tank/shares/m x", GUID: "8", Clients: addrs("10.77.0.21")},
		{Kind: KindShare, Dataset: "tank/shares/m", Path: "/mnt/tank/shares/m", GUID: "8", Clients: addrs("0.0.0.0")},
		{Kind: "other", Dataset: "tank/shares/m", Path: "/mnt/tank/shares/m", GUID: "8", Clients: addrs("10.77.0.21")},
	} {
		if _, err := RenderCluster([]ClusterExport{bad}); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	// Validation refuses hand-made dangerous lines. no_root_squash is
	// decided by the export's kind, not its path (L4): a share mounted
	// somewhere without "/shares/" in its path still gets root_squash.
	kinds := []ClusterExport{{Kind: KindShare, Path: "/mnt/tank/shares/m"}, {Kind: KindVMState, Path: "/mnt/tank/vms/web"},
		{Kind: KindShare, Path: "/srv/media"}, {Kind: KindAppData, Path: "/mnt/tank/apps/x"}}
	for _, bad := range []string{
		"/mnt/tank/shares/m 10.77.0.21(rw,sync,no_subtree_check,no_root_squash,sec=sys,fsid=" + FSID("1") + ")\n",
		"/srv/media 10.77.0.21(rw,sync,no_subtree_check,no_root_squash,sec=sys,fsid=" + FSID("1") + ")\n",
		"/mnt/tank/apps/x 10.77.0.21(rw,sync,no_subtree_check,root_squash,sec=sys,fsid=" + FSID("1") + ")\n",
		"/mnt/tank/vms/web 10.77.0.0/24(rw,sync,no_subtree_check,no_root_squash,sec=sys,fsid=" + FSID("1") + ")\n",
		"/mnt/tank/vms/web *(rw,no_root_squash)\n",
		"/mnt/tank/vms/web 10.77.0.21(rw,sync,no_subtree_check,no_root_squash,sec=sys,insecure,fsid=" + FSID("1") + ")\n",
		"/mnt/other 10.77.0.21(rw,sync,no_subtree_check,root_squash,sec=sys,fsid=" + FSID("1") + ")\n",
		"/mnt/tank/vms/web 10.77.0.21(rw,sync,no_subtree_check,no_root_squash,sec=sys,fsid=" + FSID("1") + ") 10.77.0.22(rw,sync,no_subtree_check,no_root_squash,sec=sys,fsid=" + FSID("1") + ") 10.77.0.23(rw,sync,no_subtree_check,no_root_squash,sec=sys,fsid=" + FSID("1") + ")\n",
	} {
		if ValidateCluster(bad, kinds) == nil {
			t.Errorf("validated %q", bad)
		}
	}
	if err := ValidateCluster("/srv/media 10.77.0.21(rw,sync,no_subtree_check,root_squash,sec=sys,fsid="+FSID("1")+")\n", kinds); err != nil {
		t.Errorf("a share outside /shares/: %v", err)
	}
}

func TestClusterConfTurnsNFSv3Off(t *testing.T) {
	if !strings.Contains(ClusterConf(false), "vers3=n\n") || strings.Contains(ClusterConf(true), "vers3") {
		t.Fatalf("%q / %q", ClusterConf(false), ClusterConf(true))
	}
}

func TestClusterManagerApplyAndRollback(t *testing.T) {
	root := t.TempDir()
	fx := &sysexec.Fake{}
	fx.OnResult("systemctl is-active --quiet nfs-server.service", sysexec.Result{ExitCode: 3})
	fx.OnPrefix("systemctl enable", sysexec.Result{})
	fx.OnPrefix("exportfs", sysexec.Result{})
	m := &ClusterManager{Runner: fx, Root: root}
	ex := []ClusterExport{{Kind: KindVMState, Dataset: "tank/vms/web", Path: "/mnt/tank/vms/web", GUID: "8", Clients: addrs("10.77.0.21")}}
	if err := m.Apply(context.Background(), ex); err != nil {
		t.Fatal(err)
	}
	if !HasClusterExports(root) {
		t.Fatal("HasClusterExports")
	}
	conf, _ := os.ReadFile(filepath.Join(root, ClusterConfFile))
	if !strings.Contains(string(conf), "lease-time=15") || !strings.Contains(string(conf), "grace-time=15") {
		t.Fatalf("conf %s", conf)
	}
	if got := m.Current()["/mnt/tank/vms/web"]; len(got) != 1 || got[0] != netip.MustParseAddr("10.77.0.21") {
		t.Fatalf("current %v", m.Current())
	}
	// exportfs fails: the previous file is put back.
	fx2 := &sysexec.Fake{}
	fx2.OnResult("systemctl is-active --quiet nfs-server.service", sysexec.Result{})
	fx2.OnResult("exportfs -ra", sysexec.Result{ExitCode: 1, Stderr: []byte("bad")})
	m.Runner = fx2
	ex[0].Clients = addrs("10.77.0.22")
	if err := m.Apply(context.Background(), ex); err == nil {
		t.Fatal("exportfs failure not reported")
	}
	if got := m.Current()["/mnt/tank/vms/web"]; got[0] != netip.MustParseAddr("10.77.0.21") {
		t.Fatal("the previous exports weren't restored")
	}
}

func TestClientAddress(t *testing.T) {
	for in, want := range map[string]string{
		"clientid: 0xabc\naddress: \"10.77.0.21:861\"\n": "10.77.0.21",
		"address: \"[::ffff:10.77.0.22]:900\"\n":         "10.77.0.22",
		"address: 10.77.0.23\n":                          "10.77.0.23",
	} {
		if got := clientAddress(in); got.String() != want {
			t.Errorf("%q: %s", in, got)
		}
	}
}
