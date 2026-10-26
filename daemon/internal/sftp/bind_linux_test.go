//go:build linux

package sftp

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"golang.org/x/sys/unix"
)

// A view is only ever bound from a verified mount: no device (unverified)
// or another device means no bind mount at all.
func TestBindNeedsTheVerifiedMount(t *testing.T) {
	d := t.TempDir()
	src, dst := filepath.Join(d, "src"), filepath.Join(d, "dst")
	os.Mkdir(src, 0o755)
	os.Mkdir(dst, 0o755)
	var st syscall.Stat_t
	syscall.Stat(src, &st)
	for _, dev := range []uint64{0, uint64(st.Dev) + 1} {
		if err := (SysMounter{}).Bind(src, dev, dst, true); !errors.Is(err, shares.ErrUnverified) {
			t.Errorf("Bind with device %d = %v", dev, err)
		}
	}
	os.Symlink(src, filepath.Join(d, "link"))
	if err := (SysMounter{}).Bind(filepath.Join(d, "link"), uint64(st.Dev), dst, true); err == nil {
		t.Error("bound through a link")
	}
	if ok, _ := (SysMounter{}).IsMount(dst); ok {
		t.Error("something was mounted")
	}
}

// TestRealBindNamespace makes real mounts, so it runs only with
// HARDYOS_MOUNT_NS=1, as root, and only inside a private mount namespace
// of its own (it re-runs itself under unshare -m --propagation private;
// everything it mounts goes away with that namespace).
func TestRealBindNamespace(t *testing.T) {
	if os.Getenv("HARDYOS_IN_MOUNT_NS") != "1" {
		if os.Getenv("HARDYOS_MOUNT_NS") != "1" || os.Geteuid() != 0 {
			t.Skip("set HARDYOS_MOUNT_NS=1 and run as root to test real bind mounts in a private mount namespace")
		}
		unshare, err := exec.LookPath("unshare")
		if err != nil {
			t.Skip("unshare isn't installed")
		}
		cmd := exec.Command(unshare, "-m", "--propagation", "private", os.Args[0], "-test.run", "^TestRealBindNamespace$", "-test.v")
		cmd.Env = append(os.Environ(), "HARDYOS_IN_MOUNT_NS=1")
		out, err := cmd.CombinedOutput()
		t.Logf("%s", out)
		if err != nil {
			t.Fatalf("in the namespace: %v", err)
		}
		return
	}
	for _, old := range []bool{false, true} {
		name := "open_tree"
		if old {
			name = "mount(2)"
		}
		t.Run(name, func(t *testing.T) { realBinds(t, SysMounter{NoNewAPI: old}) })
	}
}

func mustMount(t *testing.T, src, dst, fstype string, flags uintptr) {
	t.Helper()
	if err := unix.Mount(src, dst, fstype, flags, ""); err != nil {
		t.Fatalf("mount %s on %s: %v", src, dst, err)
	}
}

func realBinds(t *testing.T, mt SysMounter) {
	base := t.TempDir()
	mustMount(t, "hardyos-ns-base", base, "tmpfs", 0)
	t.Cleanup(func() { _ = unix.Unmount(base, unix.MNT_DETACH) })
	src := filepath.Join(base, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	// The shared folder's own mount: shared, like everything systemd mounts.
	mustMount(t, "hardyos-src", src, "tmpfs", 0)
	mustMount(t, "", src, "", unix.MS_SHARED)
	for _, d := range []string{"child", "child2"} {
		_ = os.Mkdir(filepath.Join(src, d), 0o777)
	}
	_ = os.WriteFile(filepath.Join(src, "f.txt"), []byte("x"), 0o644)
	var st unix.Stat_t
	if err := unix.Stat(src, &st); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Root: filepath.Join(base, "views", "sftp"), Mounter: mt}
	if err := os.Mkdir(filepath.Join(base, "views"), 0o755); err != nil {
		t.Fatal(err)
	}
	root := m.root()
	media := Bind{UID: 101103, Name: "Media", Source: src, Dataset: "hardyos-src", Dev: st.Dev, ReadOnly: true}

	// Views made the old way: the root a private mount of its own (not
	// recursively), each view a plain MS_BIND, so a peer of the source.
	legacy := filepath.Join(root, "101104", "Old")
	if err := os.MkdirAll(legacy, 0o755); err != nil {
		t.Fatal(err)
	}
	mustMount(t, root, root, "", unix.MS_BIND)
	mustMount(t, "", root, "", unix.MS_PRIVATE)
	mustMount(t, src, legacy, "", unix.MS_BIND)
	if l, _ := mt.List(root); len(l) != 1 || !l[0].Shared {
		t.Fatalf("test setup: the old view isn't a peer of the source: %+v", l)
	}

	if n, err := m.syncViews([]Bind{media}); err != nil || n != 1 {
		t.Fatalf("sync = %d %v", n, err)
	}
	target := filepath.Join(root, "101103", "Media")
	l, _ := mt.List(root)
	var got *MountPoint
	for i := range l {
		if l[i].Target == target {
			got = &l[i]
		}
		if l[i].Target == legacy {
			t.Errorf("the old view is still mounted: %+v", l[i])
		}
	}
	if got == nil || !got.Restricted() || !got.ReadOnly || got.Root != "/" || got.Source != "hardyos-src" || got.Dev != st.Dev {
		t.Fatalf("bind %+v (all: %+v)", got, l)
	}
	if b, err := os.ReadFile(filepath.Join(target, "f.txt")); err != nil || string(b) != "x" {
		t.Errorf("reading through the view: %q %v", b, err)
	}
	if err := os.WriteFile(filepath.Join(target, "new.txt"), nil, 0o644); !errors.Is(err, unix.EROFS) {
		t.Errorf("writing into a read-only view: %v", err)
	}

	// A child file system mounted on the host afterwards doesn't show up in
	// the view (an empty folder there).
	mustMount(t, "hardyos-child", filepath.Join(src, "child"), "tmpfs", 0)
	_ = os.WriteFile(filepath.Join(src, "child", "secret"), nil, 0o644)
	if below, _ := mt.List(target); len(below) != 0 {
		t.Errorf("mounts propagated into the view: %+v", below)
	}
	if ents, _ := os.ReadDir(filepath.Join(target, "child")); len(ents) != 0 {
		t.Errorf("the child dataset is visible in the view: %v", ents)
	}

	// The old way again, now with a child mount propagated into it; taking
	// it away must leave the host's child mounts alone.
	if err := os.MkdirAll(legacy, 0o755); err != nil {
		t.Fatal(err)
	}
	// Re-join the source's peer group the way an old view did.
	mustMount(t, src, legacy, "", unix.MS_BIND)
	mustMount(t, "", legacy, "", unix.MS_SHARED)
	mustMount(t, "hardyos-child2", filepath.Join(src, "child2"), "tmpfs", 0)
	if ok, _ := mt.IsMount(filepath.Join(legacy, "child2")); !ok {
		t.Fatal("test setup: the child mount didn't propagate into the old view")
	}
	if _, err := m.syncViews([]Bind{media}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(src, "child"), filepath.Join(src, "child2")} {
		if ok, _ := mt.IsMount(p); !ok {
			t.Errorf("%s was unmounted on the host", p)
		}
	}
	if ok, _ := mt.IsMount(legacy); ok {
		t.Error("the old view is still mounted")
	}

	// Off: everything goes from the views, nothing from the host.
	if _, err := m.syncViews(nil); err != nil {
		t.Fatal(err)
	}
	if l, _ := mt.List(root); len(l) != 0 {
		t.Errorf("left in the views: %+v", l)
	}
	for _, p := range []string{src, filepath.Join(src, "child"), filepath.Join(src, "child2")} {
		if ok, _ := mt.IsMount(p); !ok {
			t.Errorf("%s was unmounted on the host", p)
		}
	}
	if _, err := os.Stat(filepath.Join(src, "f.txt")); err != nil {
		t.Errorf("the source lost a file: %v", err)
	}
}
