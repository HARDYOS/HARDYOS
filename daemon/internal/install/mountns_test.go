package install

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// TestSystemDirsKeepServerMounts proves the chroot mounts never take the
// server's own /dev/pts, /dev/shm, /dev/hugepages or /dev/mqueue down with
// them (the security review: a shared rbind unmounted with umount -R -l
// unmounted them on the host during every update).
//
// It mounts for real, so it only runs as root with
// HARDYOS_MOUNTNS_TEST=1, and then always inside a new private mount
// namespace (unshare -m --propagation private): there /dev's mounts are
// made shared again, like a systemd host's, and nothing done there
// reaches this machine's own mounts. The namespace ends with the test.
func TestSystemDirsKeepServerMounts(t *testing.T) {
	if os.Getenv("HARDYOS_MOUNTNS_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("needs root and HARDYOS_MOUNTNS_TEST=1 (runs in a private mount namespace)")
	}
	if os.Getenv("HARDYOS_IN_MOUNTNS") != "1" {
		if _, err := exec.LookPath("unshare"); err != nil {
			t.Skip("unshare isn't installed")
		}
		cmd := exec.Command("unshare", "-m", "--propagation", "private", os.Args[0], "-test.run=^TestSystemDirsKeepServerMounts$", "-test.v")
		cmd.Env = append(os.Environ(), "HARDYOS_IN_MOUNTNS=1")
		out, err := cmd.CombinedOutput()
		t.Logf("%s", out)
		if err != nil || !strings.Contains(string(out), "--- PASS: TestSystemDirsKeepServerMounts") {
			t.Fatalf("in the private namespace: %v", err)
		}
		return
	}

	// Inside the private namespace from here on.
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
	}
	run("mount", "--make-rshared", "/")
	before := devSubmounts(t)
	if len(before) == 0 {
		t.Skip("no mounts under /dev to protect here")
	}
	target := t.TempDir()
	run("mount", "-t", "tmpfs", "hardyos-test-target", target)
	ctx := context.Background()
	if err := bindSystemDirs(ctx, sysexec.Exec{}, "/", target); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "dev/null")); err != nil {
		t.Fatalf("no /dev inside the target: %v", err)
	}
	unbindSystemDirs(ctx, sysexec.Exec{}, target)
	after := devSubmounts(t)
	for m := range before {
		if !after[m] {
			t.Errorf("the server's %s was unmounted", m)
		}
	}
	for _, line := range mountinfo(t) {
		if strings.HasPrefix(line, target+"/") {
			t.Errorf("left mounted: %s", line)
		}
	}
	run("umount", target)
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
