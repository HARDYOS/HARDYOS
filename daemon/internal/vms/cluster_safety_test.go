package vms

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// webHash is the approved hash of clusterEnv's VM.
func webHash(t *testing.T, e *testEnv) string {
	t.Helper()
	h, err := e.m.ClusterHash(context.Background(), "web")
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// wrapRunner answers some commands itself and hands the rest on.
type wrapRunner struct {
	inner sysexec.Runner
	on    map[string]string // command line prefix -> stdout ("!..." fails)
	lines []string
}

func (w *wrapRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) (sysexec.Result, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	best := ""
	for p := range w.on {
		if strings.HasPrefix(line, p) && len(p) > len(best) {
			best = p
		}
	}
	if best == "" {
		return w.inner.Run(ctx, stdin, name, args...)
	}
	w.lines = append(w.lines, line)
	if out := w.on[best]; strings.HasPrefix(out, "!") {
		return sysexec.Result{ExitCode: 1, Stderr: []byte(out[1:])}, errors.New(out[1:])
	}
	return sysexec.Result{Stdout: []byte(w.on[best])}, nil
}

func TestClusterVMStartNeedsTheApprovedSpec(t *testing.T) {
	e, s := clusterEnv(t)
	ctx := context.Background()
	approved := webHash(t, e)
	if _, err := e.m.ClusterStart(ctx, ClusterStartArgs{ID: "web", Generation: 3}); err == nil {
		t.Fatal("started without the approved hash")
	}
	// Another server rewrites the spec on cluster storage.
	evil := *s
	evil.Memory.MB *= 4
	write(t, filepath.Join(e.root, "/mnt/hc/tank/vms/web", specFile), string(mustJSON(t, evil)))
	if _, err := e.m.ClusterStart(ctx, ClusterStartArgs{ID: "web", Generation: 3, SpecHash: approved}); !errors.Is(err, ErrSpecChanged) {
		t.Fatalf("a changed spec started: %v", err)
	}
	// A display name isn't part of the approval.
	renamed := *s
	renamed.Name = "Another name"
	write(t, filepath.Join(e.root, "/mnt/hc/tank/vms/web", specFile), string(mustJSON(t, renamed)))
	if _, err := e.m.ClusterStart(ctx, ClusterStartArgs{ID: "web", Generation: 3, SpecHash: approved}); err != nil {
		t.Fatal(err)
	}
	r, w, _ := os.Pipe()
	defer w.Close()
	defer r.Close()
	e.m.MigrateConnector = func(context.Context) (*os.File, error) { return r, nil }
	if _, err := e.m.MigrateAccept(ctx, MigrateAcceptArgs{VM: "web", From: "c1", Token: strings.Repeat("ab", 16), DeadlineSec: 60,
		Generation: 3, SpecHash: "sha256:" + strings.Repeat("0", 64)}); !errors.Is(err, ErrSpecChanged) {
		t.Fatalf("an admission with another hash: %v", err)
	}
}

func mustJSON(t *testing.T, s Spec) []byte {
	t.Helper()
	h, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHookChecksEveryStartOfAClusterVM(t *testing.T) {
	e, _ := clusterEnv(t)
	ctx := context.Background()
	st, _ := e.m.find(ctx, "web")
	exp, err := e.m.expectedXML(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	good := incoming(string(exp))
	hostdev := strings.Replace(good, "</devices>", `<hostdev mode="subsystem" type="pci"><source><address domain="0" bus="1" slot="0" function="0"/></source></hostdev></devices>`, 1)
	for _, op := range []string{HookPrepare, HookStart, HookRestore} {
		if err := e.m.MigrateCheck(ctx, MigrateCheckArgs{VM: "web", Op: op, XML: good}); err != nil {
			t.Fatalf("%s of the rendering: %v", op, err)
		}
		if err := e.m.MigrateCheck(ctx, MigrateCheckArgs{VM: "web", Op: op, XML: hostdev}); err == nil {
			t.Fatalf("%s of a cluster VM with a host device passed", op)
		}
	}
	// Root's own start: the XML it defined (here with the same rendering).
	if _, err := e.m.ClusterStart(ctx, ClusterStartArgs{ID: "web", Generation: 3, SpecHash: webHash(t, e)}); err != nil {
		t.Fatal(err)
	}
	if err := e.m.MigrateCheck(ctx, MigrateCheckArgs{VM: "web", Op: HookPrepare, XML: incoming(e.sim.defined["web"])}); err != nil {
		t.Fatalf("root's own definition: %v", err)
	}
	// A VM on this server's pool passes; another name pointing at a LUN
	// doesn't.
	if err := e.m.MigrateCheck(ctx, MigrateCheckArgs{VM: "local", Op: HookPrepare, XML: "<domain><name>local</name></domain>"}); err != nil {
		t.Fatalf("a local VM: %v", err)
	}
	if err := e.m.MigrateCheck(ctx, MigrateCheckArgs{VM: "sneaky", Op: HookPrepare, XML: strings.Replace(good, "<name>web</name>", "<name>sneaky</name>", 1)}); err == nil {
		t.Fatal("a domain on a cluster LUN under another name passed")
	}
	// Operations after QEMU started aren't checked.
	if err := e.m.MigrateCheck(ctx, MigrateCheckArgs{VM: "web", Op: "started", XML: hostdev}); err != nil {
		t.Fatal(err)
	}
}

func TestAdmissionIsConsumedAndExpiresInRoot(t *testing.T) {
	e, _ := clusterEnv(t)
	ctx := context.Background()
	wr := &wrapRunner{inner: e.sim, on: map[string]string{
		"virt-admin -c libvirtd:///system srv-clients-list libvirtd": " Id    Transport       Connected since\n-----------------------------------\n 6     unix            2026-11-07 10:00:00+0000\n 7     unix            2026-11-07 10:00:01+0000\n",
		"virt-admin -c libvirtd:///system client-info libvirtd 6":    "id             : 6\nunix_user_name : hardyos-migrate\n",
		"virt-admin -c libvirtd:///system client-info libvirtd 7":    "id             : 7\nunix_user_name : root\n",
		"virt-admin -c libvirtd:///system client-disconnect":         "",
		"virt-admin": "!no such daemon",
	}}
	e.m.Runner = wr
	r, w, _ := os.Pipe()
	defer w.Close()
	defer r.Close()
	e.m.MigrateConnector = func(context.Context) (*os.File, error) { return r, nil }
	token := strings.Repeat("ab", 16)
	if _, err := e.m.MigrateAccept(ctx, MigrateAcceptArgs{VM: "web", From: "c1", Token: token, DeadlineSec: 60, Generation: 3, SpecHash: webHash(t, e)}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.root, MigrateAdmittedDir, "web")); err != nil {
		t.Fatal("no admission marker for the hook")
	}
	st, _ := e.m.find(ctx, "web")
	exp, _ := e.m.expectedXML(ctx, st)
	in := incoming(string(exp))
	if err := e.m.MigrateCheck(ctx, MigrateCheckArgs{VM: "web", Op: HookMigrate, XML: in}); err != nil {
		t.Fatal(err)
	}
	if err := e.m.MigrateCheck(ctx, MigrateCheckArgs{VM: "web", Op: HookMigrate, XML: in}); err == nil {
		t.Fatal("an admission was used twice")
	}
	// While admitted, a start must match the admitted rendering.
	if err := e.m.MigrateCheck(ctx, MigrateCheckArgs{VM: "web", Op: HookStart, XML: strings.Replace(in, `cache="none"`, `cache="unsafe"`, 1)}); err == nil {
		t.Fatal("a start with an unsafe cache passed during the admission")
	}
	// Root's own timer ends it at the deadline: rule, marker and the
	// migration user's connection go, whatever hardyd does.
	e.m.expireAdmission("web", "ff"+token[2:])
	if _, err := os.Stat(filepath.Join(e.root, PolkitRulesDir, polkitAllowFile)); err != nil {
		t.Fatal("another token's expiry ended the admission")
	}
	e.m.expireAdmission("web", token)
	if _, err := os.Stat(filepath.Join(e.root, PolkitRulesDir, polkitAllowFile)); !os.IsNotExist(err) {
		t.Fatal("the rule outlived the deadline")
	}
	if _, err := os.Stat(filepath.Join(e.root, MigrateAdmittedDir, "web")); !os.IsNotExist(err) {
		t.Fatal("the marker outlived the deadline")
	}
	disc := 0
	for _, l := range wr.lines {
		if strings.Contains(l, "client-disconnect") {
			disc++
			if !strings.HasSuffix(l, " 6") {
				t.Fatalf("disconnected another user's client: %s", l)
			}
		}
	}
	if disc != 1 {
		t.Fatalf("the migration user's connection wasn't closed: %v", wr.lines)
	}
}

func TestForcedStopKillsQEMUWhenLibvirtCant(t *testing.T) {
	e, _ := clusterEnv(t)
	ctx := context.Background()
	if _, err := e.m.ClusterStart(ctx, ClusterStartArgs{ID: "web", Generation: 3, SpecHash: webHash(t, e)}); err != nil {
		t.Fatal(err)
	}
	e.sim.fail = map[string]string{"virsh -c qemu:///system -q destroy": "error: access denied: polkit is not running"}
	write(t, filepath.Join(e.root, qemuPIDDir, "web.pid"), "4242\n")
	write(t, filepath.Join(e.root, "proc/4242/cmdline"), "/usr/bin/qemu-system-x86_64\x00-name\x00guest=web,debug-threads=on\x00")
	var killed []int
	e.m.killPID = func(pid int) error { killed = append(killed, pid); return nil }
	delete(e.m.Backend.(*fakeBackend).att, "web")
	if _, err := e.m.ClusterStop(ctx, ClusterStopArgs{ID: "web", Force: true}); err != nil {
		t.Fatal(err)
	}
	if len(killed) != 1 || killed[0] != 4242 {
		t.Fatalf("killed %v", killed)
	}
	// A pid file pointing at something else is never killed.
	write(t, filepath.Join(e.root, "proc/4242/cmdline"), "/usr/sbin/sshd\x00-D\x00")
	killed = nil
	if _, err := e.m.ClusterStop(ctx, ClusterStopArgs{ID: "web", Force: true}); err == nil || len(killed) != 0 {
		t.Fatalf("killed a process that isn't the VM's QEMU: %v %v", killed, err)
	}
	write(t, filepath.Join(e.root, "proc/4242/cmdline"), "/usr/bin/qemu-system-x86_64\x00-name\x00guest=other\x00")
	if _, err := e.m.ClusterStop(ctx, ClusterStopArgs{ID: "web", Force: true}); err == nil || len(killed) != 0 {
		t.Fatalf("killed another VM's QEMU: %v %v", killed, err)
	}
}

func TestStorageRoute(t *testing.T) {
	e, _ := clusterEnv(t)
	ctx := context.Background()
	cases := map[string]struct {
		out string
		ok  bool
	}{
		"direct":   {`[{"dst":"10.77.0.22","dev":"enp2s0","prefsrc":"10.77.0.21"}]`, true},
		"routed":   {`[{"dst":"10.77.0.22","gateway":"192.168.1.1","dev":"enp1s0"}]`, false},
		"netbird":  {`[{"dst":"10.77.0.22","dev":"wt0"}]`, false},
		"loopback": {`[{"type":"local","dst":"10.77.0.22","dev":"lo"}]`, false},
		"no route": {`!RTNETLINK answers: Network is unreachable`, false},
	}
	for name, c := range cases {
		e.m.Runner = &wrapRunner{inner: e.sim, on: map[string]string{"ip -j route get 10.77.0.22": c.out}}
		err := e.m.storageRoute(ctx, "tcp://10.77.0.22:49152")
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestMigrateSetupChecksTheAccessDriver(t *testing.T) {
	e, _ := clusterEnv(t)
	ctx := context.Background()
	write(t, filepath.Join(e.root, "usr/lib/polkit-1/polkitd"), "")
	write(t, filepath.Join(e.root, LibvirtdConf), "listen_tls = 0\n")
	write(t, filepath.Join(e.root, QEMUConf), "#migration_address = \"0.0.0.0\"\nmigration_address = \"0.0.0.0\"\n")
	wr := &wrapRunner{inner: e.sim, on: map[string]string{
		"systemctl is-active --quiet polkit.service": "",
		"systemctl is-enabled":                       "!disabled",
		"systemctl restart":                          "",
		"id -u hardyos-migrate":                      "998\n",
		"id -nG hardyos-migrate":                     "hardyos-migrate libvirt\n",
		"gpasswd -d hardyos-migrate libvirt":         "",
		"virsh -c qemu:///system -q version":         "Compiled against library: libvirt 11.3.0\n",
	}}
	e.m.Runner = wr
	asked := 0
	e.m.MigrateRunAs = func(context.Context, string, ...string) ([]byte, error) {
		asked++
		return []byte("error: access denied: 'list' not allowed"), errors.New("exit status 1")
	}
	if err := e.m.MigrateSetup(ctx, MigrateSetupArgs{StorageAddress: "10.77.0.21"}); err != nil {
		t.Fatal(err)
	}
	if asked != 1 {
		t.Fatal("setup didn't check the migration user is refused")
	}
	joined := strings.Join(wr.lines, "\n")
	if !strings.Contains(joined, "gpasswd -d hardyos-migrate libvirt") || strings.Contains(joined, "--groups") {
		t.Fatalf("the migration user stays in libvirt's group:\n%s", joined)
	}
	q, _ := os.ReadFile(filepath.Join(e.root, QEMUConf))
	if !strings.Contains(string(q), "\nmigration_address = \"10.77.0.21\"\n") || strings.Contains(string(q), "\nmigration_address = \"0.0.0.0\"") {
		t.Fatalf("qemu.conf:\n%s", q)
	}
	// The access driver isn't in force: libvirt lets the user list VMs.
	e.m.MigrateRunAs = func(context.Context, string, ...string) ([]byte, error) { return []byte("web\n"), nil }
	write(t, filepath.Join(e.root, LibvirtdConf), "listen_tls = 0\n")
	if err := e.m.MigrateSetup(ctx, MigrateSetupArgs{}); err == nil {
		t.Fatal("setup succeeded although libvirt let the migration user in")
	}
	if b, _ := os.ReadFile(filepath.Join(e.root, LibvirtdConf)); strings.Contains(string(b), libvirtdBegin) {
		t.Fatal("the failed setup wasn't reverted")
	}
	// Modular daemons get the driver in their own files.
	write(t, filepath.Join(e.root, "etc/libvirt/virtqemud.conf"), "")
	write(t, filepath.Join(e.root, "etc/libvirt/virtproxyd.conf"), "")
	wr.on["systemctl is-enabled --quiet virtqemud.socket"] = ""
	e.m.MigrateRunAs = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("error: authentication failed"), errors.New("exit status 1")
	}
	if err := e.m.MigrateSetup(ctx, MigrateSetupArgs{}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"etc/libvirt/virtqemud.conf", "etc/libvirt/virtproxyd.conf"} {
		if b, _ := os.ReadFile(filepath.Join(e.root, f)); !strings.Contains(string(b), `access_drivers = [ "polkit" ]`) {
			t.Fatalf("%s lacks the access driver", f)
		}
	}
	if !strings.Contains(strings.Join(wr.lines, "\n"), "systemctl restart virtqemud.service") {
		t.Fatal("virtqemud wasn't restarted")
	}
	// polkitd down: setup refuses.
	wr.on["systemctl is-active --quiet polkit.service"] = "!inactive"
	if err := e.m.MigrateSetup(ctx, MigrateSetupArgs{}); err == nil {
		t.Fatal("set up while polkitd is down")
	}
}

func TestParseVirtAdmin(t *testing.T) {
	ids := parseClientIDs([]byte(" Id    Transport       Connected since\n--------\n 6     unix   x\n 12    unix   y\n"))
	if strings.Join(ids, ",") != "6,12" {
		t.Fatal(ids)
	}
	if u := clientUser([]byte("id : 6\nunix_user_name   :  hardyos-migrate\n")); u != "hardyos-migrate" {
		t.Fatal(u)
	}
}
