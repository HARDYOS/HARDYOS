package install

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// These tests mount for real, so they only run as root with
// HARDYOS_MOUNTNS_TEST=1, and then always inside a new private mount
// namespace (unshare -m --propagation private): there the mounts are made
// shared again, like a systemd host's, and nothing done there reaches this
// machine's own mounts. The namespace ends with the test.
// inMountNS reports whether the test body should run here (true inside the
// namespace); outside, it runs the test in one and reports the result.
func inMountNS(t *testing.T, name string) bool {
	t.Helper()
	if os.Getenv("HARDYOS_MOUNTNS_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("needs root and HARDYOS_MOUNTNS_TEST=1 (runs in a private mount namespace)")
	}
	if os.Getenv("HARDYOS_IN_MOUNTNS") == "1" {
		return true
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare isn't installed")
	}
	cmd := exec.Command("unshare", "-m", "--propagation", "private", os.Args[0], "-test.run=^"+name+"$", "-test.v")
	cmd.Env = append(os.Environ(), "HARDYOS_IN_MOUNTNS=1")
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil || !strings.Contains(string(out), "--- PASS: "+name) {
		t.Fatalf("in the private namespace: %v", err)
	}
	return false
}

func mustRun(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v: %s", args, err, out)
	}
	return string(out)
}

// TestSystemDirsKeepServerMounts proves the chroot mounts never take the
// server's own /dev/pts, /dev/shm, /dev/hugepages or /dev/mqueue down with
// them (the security review: a shared rbind unmounted with umount -R -l
// unmounted them on the host during every update).
func TestSystemDirsKeepServerMounts(t *testing.T) {
	if !inMountNS(t, "TestSystemDirsKeepServerMounts") {
		return
	}
	mustRun(t, "mount", "--make-rshared", "/")
	before := devSubmounts(t)
	if len(before) == 0 {
		t.Skip("no mounts under /dev to protect here")
	}
	target := t.TempDir()
	mustRun(t, "mount", "-t", "tmpfs", "hardyos-test-target", target)
	ctx := context.Background()
	if err := bindSystemDirs(ctx, sysexec.Exec{}, "/", target); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "dev/null")); err != nil {
		t.Fatalf("no /dev inside the target: %v", err)
	}
	if err := unbindSystemDirs(ctx, sysexec.Exec{}, "/", target); err != nil {
		t.Fatal(err)
	}
	checkHostAndTarget(t, before, target)
	mustRun(t, "umount", target)
}

// TestSystemDirsBusyTeardown: a process left holding a file in the
// target's /dev (what made the installer's "zpool export" fail with "pool
// is busy") is reported, the target's own copies are still detached, the
// server's /dev is untouched, and the target itself can be unmounted
// afterwards (as zpool export must). With HARDYOS_ZFS_INTEGRATION=1 and ZFS
// installed, the target is a file-backed pool that is exported at the end.
func TestSystemDirsBusyTeardown(t *testing.T) {
	if !inMountNS(t, "TestSystemDirsBusyTeardown") {
		return
	}
	mustRun(t, "mount", "--make-rshared", "/")
	before := devSubmounts(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	_ = os.MkdirAll(target, 0o755)
	pool := ""
	if os.Getenv("HARDYOS_ZFS_INTEGRATION") == "1" {
		if _, err := exec.LookPath("zpool"); err == nil {
			pool = "hardyosmountnstest"
			_ = exec.Command("zpool", "destroy", "-f", pool).Run()
			img := filepath.Join(dir, "pool.img")
			f, _ := os.Create(img)
			_ = f.Truncate(256 << 20)
			f.Close()
			mustRun(t, "zpool", "create", "-m", target, pool, img)
			defer func() { _ = exec.Command("zpool", "destroy", "-f", pool).Run() }()
		}
	}
	if pool == "" {
		mustRun(t, "mount", "-t", "tmpfs", "hardyos-test-target", target)
	}
	ctx := context.Background()
	if err := bindSystemDirs(ctx, sysexec.Exec{}, "/", target); err != nil {
		t.Fatal(err)
	}
	// A leftover process (a daemon a package started) holding /dev/null in
	// the target open.
	holder := exec.Command("sh", "-c", "exec 3<"+filepath.Join(target, "dev/null")+"; exec sleep 60")
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Process.Kill(); _ = holder.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for len(Holders("/", target)) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	err := unbindSystemDirs(ctx, sysexec.Exec{}, "/", target)
	var te *TeardownError
	if !errors.As(err, &te) || te.fatal() || !strings.Contains(err.Error(), "in use by") || !strings.Contains(err.Error(), "sleep (open "+filepath.Join(target, "dev/null")) {
		t.Fatalf("busy teardown not reported: %v", err)
	}
	checkHostAndTarget(t, before, target)
	if pool != "" {
		mustRun(t, "zpool", "export", pool)
	} else {
		mustRun(t, "umount", target)
	}
}

// TestWithSystemDirsLeavesNoCopies reproduces the installer's "pool is
// busy": services (libvirtd, logind, ...) run in mount namespaces that are
// slaves of the server's, made at boot; a target mounted later on the
// server shows in them too. Binds made on the server under that target
// were copied into every such namespace, and unmounting them after cutting
// propagation left the copies there, holding the target. WithSystemDirs
// works in a private namespace of its own: nothing reaches the service's
// namespace, a daemon left running in the chroot is stopped, and the
// target unmounts (or its pool exports) cleanly, in the service's
// namespace too. The old way is checked to be visible in
// OtherNamespaceMounts.
func TestWithSystemDirsLeavesNoCopies(t *testing.T) {
	if !inMountNS(t, "TestWithSystemDirsLeavesNoCopies") {
		return
	}
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid isn't installed")
	}
	mustRun(t, "mount", "--make-rshared", "/")
	before := devSubmounts(t)
	// A "service" with its own namespace, a slave of ours, made first.
	svc := exec.Command("unshare", "-m", "--propagation", "slave", "sleep", "120")
	if err := svc.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = svc.Process.Kill(); _ = svc.Wait() }()
	time.Sleep(200 * time.Millisecond)
	svcMounts := func() []string {
		b, _ := os.ReadFile(filepath.Join("/proc", strconv.Itoa(svc.Process.Pid), "mountinfo"))
		var out []string
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.Fields(line); len(f) > 4 {
				out = append(out, f[4])
			}
		}
		return out
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	_ = os.MkdirAll(target, 0o755)
	pool := ""
	if os.Getenv("HARDYOS_ZFS_INTEGRATION") == "1" {
		if _, err := exec.LookPath("zpool"); err == nil {
			pool = "hardyosnscopytest"
			_ = exec.Command("zpool", "destroy", "-f", pool).Run()
			img := filepath.Join(dir, "pool.img")
			f, _ := os.Create(img)
			_ = f.Truncate(256 << 20)
			f.Close()
			mustRun(t, "zpool", "create", "-m", target, pool, img)
			defer func() { _ = exec.Command("zpool", "destroy", "-f", pool).Run() }()
		}
	}
	if pool == "" {
		mustRun(t, "mount", "-t", "tmpfs", "hardyos-test-target", target)
	}
	if !contains(svcMounts(), target) {
		t.Fatalf("the target didn't propagate to the service: %v", svcMounts())
	}
	ctx := context.Background()
	held := filepath.Join(target, "dev/null")
	err := WithSystemDirs(ctx, sysexec.Exec{}, "/", target, func() error {
		if _, err := os.Stat(held); err != nil {
			return err
		}
		// A daemon a package starts and leaves running.
		_, err := sysexec.Output(ctx, sysexec.Exec{}, "setsid", "-f", "sh", "-c", "exec 3<"+held+" >/dev/null 2>&1; exec sleep 60")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range svcMounts() {
		if strings.HasPrefix(m, target+"/") {
			t.Errorf("copied into the service's namespace: %s", m)
		}
	}
	checkHostAndTarget(t, before, target)
	if other := OtherNamespaceMounts(target); len(other) > 0 {
		t.Errorf("still mounted elsewhere: %v", other)
	}
	if h := Holders("/", target); len(h) > 0 {
		t.Errorf("left running: %v", h)
	}
	if pool != "" {
		mustRun(t, "zpool", "export", pool)
	} else {
		mustRun(t, "umount", target)
	}
	if contains(svcMounts(), target) {
		t.Error("the target is still mounted in the service's namespace")
	}

	// The old way (binds on the server, cut off, then unmounted) leaves
	// copies in the service's namespace, and the diagnostics name them.
	mustRun(t, "mount", "-t", "tmpfs", "hardyos-test-target", target)
	if err := bindSystemDirs(ctx, sysexec.Exec{}, "/", target); err != nil {
		t.Fatal(err)
	}
	_ = unbindSystemDirs(ctx, sysexec.Exec{}, "/", target)
	other := OtherNamespaceMounts(target)
	if len(other) == 0 || !strings.Contains(strings.Join(other, " "), target+"/dev (pid "+strconv.Itoa(svc.Process.Pid)) {
		t.Errorf("copies in other namespaces not found: %v", other)
	}
	// Ending the service's namespace frees the target.
	_ = svc.Process.Kill()
	_ = svc.Wait()
	mustRun(t, "umount", target)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func checkHostAndTarget(t *testing.T, before map[string]bool, target string) {
	t.Helper()
	after := devSubmounts(t)
	for m := range before {
		if !after[m] {
			t.Errorf("the server's %s was unmounted", m)
		}
	}
	for _, m := range mountinfo(t) {
		if strings.HasPrefix(m, target+"/") {
			t.Errorf("left mounted: %s", m)
		}
	}
}

func mountinfo(t *testing.T) []string {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) > 4 {
			out = append(out, f[4])
		}
	}
	return out
}

func devSubmounts(t *testing.T) map[string]bool {
	out := map[string]bool{}
	for _, m := range mountinfo(t) {
		if strings.HasPrefix(m, "/dev/") {
			out[m] = true
		}
	}
	return out
}

func TestMountsUnderDeepestFirst(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "proc/self"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "proc/self/mountinfo"), []byte(strings.Join([]string{
		"1 0 0:1 / / rw - zfs rpool/ROOT/x rw",
		"2 1 0:2 / /target rw - zfs rpool/ROOT/y rw",
		"3 2 0:3 / /target/dev rw - devtmpfs udev rw",
		"4 3 0:4 / /target/dev/pts rw - devpts devpts rw",
		"5 2 0:5 / /target/var/lib/hardyos rw - zfs rpool/hardyos rw",
		"6 2 0:6 / /target/sys rw - sysfs sysfs rw",
		"7 6 0:7 / /target/sys/firmware/efi/efivars rw - efivarfs efivarfs rw",
		"8 1 0:8 / /target2/dev rw - devtmpfs udev rw",
	}, "\n")+"\n"), 0o644)
	got := strings.Join(mountsUnder(root, "/target", true), " ")
	if got != "/target/sys/firmware/efi/efivars /target/dev/pts /target/sys /target/dev" {
		t.Fatalf("system dirs = %s", got)
	}
	if all := mountsUnder(root, "/target", false); len(all) != 5 {
		t.Fatalf("all = %v", all)
	}
}
