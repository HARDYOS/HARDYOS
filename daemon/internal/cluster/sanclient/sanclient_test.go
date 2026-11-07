package sanclient

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

const cid = cluster.ClusterID("abcdefghijklmnopqrstuvwxyz")

func newClient(t *testing.T) (*Client, *sysexec.Fake) {
	t.Helper()
	fx := &sysexec.Fake{}
	c := &Client{Runner: fx, Sys: t.TempDir(), DeviceWait: 300 * time.Millisecond}
	fx.On("ip -j route get 10.77.0.10", `[{"dst":"10.77.0.10","dev":"enp2s0","prefsrc":"10.77.0.21","flags":[],"uid":0,"cache":[]}]`)
	fx.OnPrefix("systemctl ", sysexec.Result{})
	return c, fx
}

func secrets(t *testing.T) san.Secrets {
	s, err := san.NewSecrets("c1")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNodeRecordAndLoginKeepSecretsOffArgv(t *testing.T) {
	c, fx := newClient(t)
	fx.OnResult("iscsiadm -m node -T "+san.TargetIQN(cid, "c1")+" -p 10.77.0.10:3260 -I default --login", sysexec.Result{ExitCode: iscsiSessionExists})
	sec := secrets(t)
	err := c.Login(context.Background(), LoginArgs{SessionArgs: SessionArgs{Cluster: cid, Node: "c1"},
		Portals: []netip.AddrPort{netip.MustParseAddrPort("10.77.0.10:3260")}, Interface: "enp2s0", CHAP: sec})
	if err != nil {
		t.Fatal(err)
	}
	rec := filepath.Join(c.Sys, ISCSIDir, "nodes", san.TargetIQN(cid, "c1"), "10.77.0.10,3260,1", "default")
	b, err := os.ReadFile(rec)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(rec)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("record mode %v", fi.Mode())
	}
	for _, want := range []string{"node.startup = manual", "node.conn[0].startup = manual", "node.session.auth.authmethod = CHAP",
		"node.session.auth.password = " + sec.Password, "node.session.auth.password_in = " + sec.MutualPassword,
		"node.session.timeo.replacement_timeout = 15", "node.conn[0].timeo.noop_out_interval = 5"} {
		if !strings.Contains(string(b), want+"\n") {
			t.Errorf("record lacks %q", want)
		}
	}
	init, _ := os.ReadFile(filepath.Join(c.Sys, ISCSIDir, "initiatorname.iscsi"))
	if !strings.Contains(string(init), "InitiatorName="+san.InitiatorIQN(cid, "c1")+"\n") {
		t.Fatalf("initiator %s", init)
	}
	for _, call := range fx.Calls {
		if strings.Contains(call.Line, sec.Password) || strings.Contains(call.Line, sec.MutualPassword) ||
			strings.Contains(string(call.Stdin), sec.Password) {
			t.Fatalf("secret passed to a command: %s", call.Line)
		}
	}
}

func TestRouteCheck(t *testing.T) {
	c, fx := newClient(t)
	ctx := context.Background()
	if err := c.RouteCheck(ctx, "enp2s0", netip.MustParseAddr("10.77.0.10")); err != nil {
		t.Fatal(err)
	}
	fx.On("ip -j route get 10.77.0.11", `[{"dst":"10.77.0.11","dev":"wt0","prefsrc":"100.80.1.2"}]`)
	fx.On("ip -j route get 10.77.0.12", `[{"dst":"10.77.0.12","gateway":"192.168.1.1","dev":"enp2s0","prefsrc":"10.77.0.21"}]`)
	fx.On("ip -j route get 10.77.0.13", `[{"dst":"10.77.0.13","dev":"enp1s0","prefsrc":"192.168.1.21"}]`)
	for _, a := range []string{"10.77.0.11", "10.77.0.12", "10.77.0.13", "100.80.0.1"} {
		if err := c.RouteCheck(ctx, "enp2s0", netip.MustParseAddr(a)); err == nil {
			t.Errorf("%s passed", a)
		}
	}
	if err := c.RouteCheck(ctx, "wt0", netip.MustParseAddr("10.77.0.10")); err == nil {
		t.Error("NetBird interface passed")
	}
}

func TestAttachRecordsAndBackends(t *testing.T) {
	c, fx := newClient(t)
	ctx := context.Background()
	wwn := san.WWN(san.Serial(cid, "42"))
	dev := filepath.Join(c.Sys, "dev/disk/by-id/wwn-0x"+wwn)
	_ = os.MkdirAll(filepath.Dir(dev), 0o755)
	_ = os.WriteFile(dev, nil, 0o644)
	fx.OnPrefix("mount -t nfs4 -o "+NFSMountOptions+",noexec 10.77.0.10:/mnt/tank/vms/web /mnt/hc/tank/vms/web", sysexec.Result{})
	ws := cluster.WorkloadStorage{Pool: "tank",
		Volumes: []cluster.Volume{{Dataset: "tank/vms/web/disk0", Disk: "disk0", SizeGB: 10, WWN: wwn}},
		Exports: []cluster.Export{{Kind: cluster.ExportVMState, Dataset: "tank/vms/web", Path: "/mnt/tank/vms/web", MountPath: "/mnt/hc/tank/vms/web", FSID: "9"}}}
	rec, err := c.Attach(ctx, AttachArgs{Workload: cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web"}, Generation: 3, Storage: ws,
		Server: netip.MustParseAddr("10.77.0.10"), Interface: "enp2s0"})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Disks["disk0"] != "/dev/disk/by-id/wwn-0x"+wwn || rec.StateDir != "/mnt/hc/tank/vms/web" {
		t.Fatalf("record %+v", rec)
	}
	st, err := VMBackend{C: c}.Locate(ctx, "web")
	if err != nil || st.Generation != 3 || st.Backend != vms.BackendCluster || st.Disks["disk0"] == "" {
		t.Fatalf("locate %+v %v", st, err)
	}
	if _, err := (VMBackend{C: c}).Locate(ctx, "other"); !errors.Is(err, vms.ErrNotFound) {
		t.Fatalf("other VM: %v", err)
	}
	if _, err := (AppBackend{C: c}).Locate(ctx, "web"); !errors.Is(err, apps.ErrNotInstalled) {
		t.Fatalf("a VM's attachment answered for an app: %v", err)
	}
	// A volume of another VM is refused.
	bad := ws
	bad.Volumes = []cluster.Volume{{Dataset: "tank/vms/other/disk0", Disk: "disk0", WWN: wwn}}
	if _, err := c.Attach(ctx, AttachArgs{Workload: cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web"}, Storage: bad,
		Server: netip.MustParseAddr("10.77.0.10"), Interface: "enp2s0"}); err == nil {
		t.Fatal("attached another VM's disk")
	}
	// A disk that doesn't appear (not granted) fails.
	missing := ws
	missing.Volumes = []cluster.Volume{{Dataset: "tank/vms/web/disk1", Disk: "disk1", WWN: san.WWN(san.Serial(cid, "43"))}}
	if _, err := c.Attach(ctx, AttachArgs{Workload: cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web"}, Storage: missing,
		Server: netip.MustParseAddr("10.77.0.10"), Interface: "enp2s0"}); err == nil || !strings.Contains(err.Error(), "didn't appear") {
		t.Fatalf("missing disk: %v", err)
	}
	// Detach (not mounted in the fake's mountinfo: nothing to unmount);
	// the LUN's SCSI disk is removed, others are left alone.
	for name, id := range map[string]string{"sdb": "naa." + wwn, "sda": "t10.ATA disk"} {
		d := filepath.Join(c.Sys, "sys/block", name, "device")
		_ = os.MkdirAll(d, 0o755)
		_ = os.WriteFile(filepath.Join(d, "wwid"), []byte(id+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(d, "delete"), nil, 0o644) // sysfs attributes exist
	}
	if err := c.Detach(ctx, DetachArgs{Workload: cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web"}}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(c.Sys, "sys/block/sdb/device/delete")); string(b) != "1" {
		t.Fatal("the LUN's SCSI disk wasn't removed")
	}
	if b, _ := os.ReadFile(filepath.Join(c.Sys, "sys/block/sda/device/delete")); len(b) != 0 {
		t.Fatal("another disk was removed")
	}
	if l, _ := (VMBackend{C: c}).List(ctx); len(l) != 0 {
		t.Fatalf("still listed: %v", l)
	}
}

func TestMountPathsAndMultipath(t *testing.T) {
	for ds, want := range map[string]string{"tank/vms/web": "/mnt/hc/tank/vms/web", "tank/apps/notes": "/mnt/hc/tank/apps/notes", "tank/shares/media": "/mnt/hc/tank/shares/media"} {
		if got, err := MountPath(ds); err != nil || got != want {
			t.Errorf("%s: %s %v", ds, got, err)
		}
	}
	for _, bad := range []string{"tank/vms/../x", "tank/system/x", "tank/vms", "tank/vms/web/disk0", "/etc"} {
		if _, err := MountPath(bad); err == nil {
			t.Errorf("%s passed", bad)
		}
	}
	wwn := san.WWN(san.Serial(cid, "1"))
	out, err := RenderMultipath([]string{wwn, wwn})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"find_multipaths strict", "no_path_retry 3", `wwid ".*"`, `wwid "3` + wwn + `"`} {
		if !strings.Contains(out, want) {
			t.Errorf("multipath lacks %q", want)
		}
	}
	if strings.Count(out, wwn) != 1 {
		t.Error("duplicate WWID")
	}
	if _, err := RenderMultipath([]string{"3600"}); err == nil {
		t.Error("bad WWN accepted")
	}
}

func TestFreezeOnlyAttachedVMs(t *testing.T) {
	c, fx := newClient(t)
	fx.OnPrefix("virsh ", sysexec.Result{})
	if _, err := c.Freeze(context.Background(), FreezeArgs{VM: "web"}); err == nil {
		t.Fatal("froze a VM that isn't attached here")
	}
	if _, err := c.AppDump(context.Background(), DumpArgs{App: "notes"}); err == nil {
		t.Fatal("dumped an app that isn't attached here")
	}
}
