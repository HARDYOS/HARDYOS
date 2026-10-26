package update

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"github.com/hardyos/hardyos/daemon/internal/rootfile"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func testKey(t *testing.T) (ed25519.PrivateKey, PublicKey) {
	t.Helper()
	privText, pubText, err := GenerateKey("test")
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParsePrivateKey([]byte(privText))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(pubText)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func makeBundle(t *testing.T, priv ed25519.PrivateKey, version, arch string, image []byte) string {
	t.Helper()
	dir := t.TempDir()
	img := filepath.Join(dir, "rootfs.squashfs")
	if err := os.WriteFile(img, image, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "update.hupd")
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateBundle(f, priv, version, arch, "test notes", img); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return out
}

func TestBundleRoundTrip(t *testing.T) {
	priv, pub := testKey(t)
	image := bytes.Repeat([]byte("hardyos"), 1000)
	path := makeBundle(t, priv, "0.2.0", "amd64", image)

	m, err := ReadManifest(path, []PublicKey{pub})
	if err != nil || m.Version != "0.2.0" || m.Notes != "test notes" {
		t.Fatalf("manifest %+v, %v", m, err)
	}
	dst := filepath.Join(t.TempDir(), "out.squashfs")
	if _, err := Extract(path, []PublicKey{pub}, dst); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dst); !bytes.Equal(got, image) {
		t.Fatal("extracted image differs")
	}
}

func TestBundleRejectsUntrustedAndTampered(t *testing.T) {
	priv, pub := testKey(t)
	_, other := testKey(t)
	image := bytes.Repeat([]byte("x"), 4096)
	path := makeBundle(t, priv, "0.2.0", "amd64", image)

	if _, err := ReadManifest(path, []PublicKey{other}); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("other key: %v", err)
	}
	if _, err := ReadManifest(path, nil); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("no keys: %v", err)
	}

	// Flip one byte of the image: the signature still checks, the hash doesn't.
	raw, _ := os.ReadFile(path)
	i := bytes.LastIndex(raw, image[:64])
	raw[i+10] ^= 0xff
	tampered := filepath.Join(t.TempDir(), "tampered.hupd")
	_ = os.WriteFile(tampered, raw, 0o644)
	dst := filepath.Join(t.TempDir(), "out")
	if _, err := Extract(tampered, []PublicKey{pub}, dst); err == nil || !strings.Contains(err.Error(), "doesn't match") {
		t.Fatalf("tampered image: %v", err)
	}
	if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("tampered image left on disk")
	}

	// Change the manifest: the signature no longer matches.
	raw, _ = os.ReadFile(path)
	raw = bytes.Replace(raw, []byte(`"version": "0.2.0"`), []byte(`"version": "9.9.9"`), 1)
	forged := filepath.Join(t.TempDir(), "forged.hupd")
	_ = os.WriteFile(forged, raw, 0o644)
	if _, err := ReadManifest(forged, []PublicKey{pub}); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("forged manifest: %v", err)
	}

	// Not a bundle at all.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "evil.sh", Mode: 0o755, Size: 2})
	_, _ = tw.Write([]byte("hi"))
	tw.Close()
	junk := filepath.Join(t.TempDir(), "junk.hupd")
	_ = os.WriteFile(junk, buf.Bytes(), 0o644)
	if _, err := ReadManifest(junk, []PublicKey{pub}); err == nil || !strings.Contains(err.Error(), "not a HardyOS update") {
		t.Fatalf("junk: %v", err)
	}
}

func TestKeyParsing(t *testing.T) {
	if _, err := ParsePublicKey("ssh-ed25519 AAAA"); err == nil {
		t.Error("accepted an SSH key")
	}
	if _, err := ParsePrivateKey([]byte("hardyos-ed25519 abc")); err == nil {
		t.Error("accepted a public key as private")
	}
	root := t.TempDir()
	_, pubText, _ := GenerateKey("lab")
	_ = os.MkdirAll(filepath.Join(root, TrustedKeysDir), 0o755)
	_ = os.WriteFile(filepath.Join(root, TrustedKeysDir, "lab.pub"), []byte(pubText), 0o644)
	keys := TrustedKeys(root)
	found := false
	for _, k := range keys {
		if k.Comment == "lab" {
			found = true
		}
	}
	if !found {
		t.Fatalf("server key not loaded: %+v", keys)
	}
}

// hookRunner is a fake that also runs side effects for some commands, so
// steps that check files written by commands (unsquashfs, update-initramfs)
// work against a temp directory.
type hookRunner struct {
	*sysexec.Fake
	mu    sync.Mutex
	hooks map[string]func(args []string)
}

func (h *hookRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) (sysexec.Result, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	h.mu.Lock()
	for prefix, fn := range h.hooks {
		if strings.HasPrefix(line, prefix) {
			fn(args)
		}
	}
	h.mu.Unlock()
	return h.Fake.Run(ctx, stdin, name, args...)
}

type world struct {
	t       *testing.T
	root    string
	runner  *hookRunner
	u       *Updater
	priv    ed25519.PrivateKey
	booted  string
	bootfs  string
	bes     []string // datasets under rpool/ROOT, oldest first
	reboots atomic.Int32
}

func (w *world) write(p, data string) {
	full := filepath.Join(w.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) setBooted(ds string) {
	w.booted = ds
	w.write("/proc/mounts", ds+" / zfs rw 0 0\nrpool/hardyos /var/lib/hardyos zfs rw 0 0\n")
}

// refresh re-scripts the fake for the current boot environments.
func (w *world) refresh() {
	var list strings.Builder
	list.WriteString("rpool/ROOT\t1\t-\n")
	for i, ds := range w.bes {
		ver := strings.TrimPrefix(filepath.Base(ds), "hardyos-")
		list.WriteString(ds + "\t" + strconv.Itoa(100*(i+1)) + "\t" + ver + "\n")
	}
	f := w.runner.Fake
	f.OnResult("zfs list -H -p -o name,creation,org.hardyos:version -d 1 -r rpool/ROOT", sysexec.Result{Stdout: []byte(list.String())})
	f.OnResult("zpool get -H -o value bootfs rpool", sysexec.Result{Stdout: []byte(w.bootfs + "\n")})
}

func newWorld(t *testing.T) *world {
	t.Helper()
	priv, pub := testKey(t)
	w := &world{t: t, root: t.TempDir(), priv: priv}
	w.runner = &hookRunner{Fake: &sysexec.Fake{}, hooks: map[string]func([]string){}}
	f := w.runner.Fake
	w.bes = []string{"rpool/ROOT/hardyos-0.1.0"}
	w.bootfs = "rpool/ROOT/hardyos-0.1.0"
	w.setBooted("rpool/ROOT/hardyos-0.1.0")
	w.write("/var/lib/hardyos/boot.json", `{"pool":"rpool","disks":[{"byId":"/dev/disk/by-id/a","espPartUUID":"aaaaaaaa-0000-0000-0000-000000000001"}]}`)
	w.write("/dev/disk/by-partuuid/aaaaaaaa-0000-0000-0000-000000000001", "")
	// The running system's settings that carry over.
	w.write("/etc/hostname", "nas\n")
	w.write("/etc/hostid", "\x01\x02\x03\x04")
	w.write("/etc/ssh/ssh_host_ed25519_key", "host-key")
	w.write("/etc/network/interfaces", "iface eno1 inet dhcp\n")
	w.write("/run/hardyos/boot/be/hardyos-0.1.0/boot/vmlinuz-6.12.1", "k1")
	w.write("/run/hardyos/boot/be/hardyos-0.1.0/boot/initrd.img-6.12.1", "i1")
	// The running system is mounted at / ; Sync reads its kernel from /boot.
	w.write("/boot/vmlinuz-6.12.1", "k1")
	w.write("/boot/initrd.img-6.12.1", "i1")
	w.refresh()

	mnt := "/run/hardyos/update/root"
	w.runner.hooks["unsquashfs "] = func([]string) {
		w.write(mnt+"/lib/modules/6.12.2/modules.dep", "")
		w.write(mnt+"/boot/vmlinuz-6.12.2", "k2")
		w.write(mnt+"/etc/hostname", "hardyos\n")
		w.write(mnt+"/etc/hardyos/live-installer", "")
	}
	w.runner.hooks["chroot "+mnt+" update-initramfs -c -k 6.12.2"] = func([]string) {
		w.write(mnt+"/boot/initrd.img-6.12.2", "i2")
	}
	w.runner.hooks["zfs create -o canmount=noauto"] = func(args []string) {
		w.bes = append(w.bes, args[len(args)-1])
		w.refresh()
	}
	w.runner.hooks["zfs destroy -r rpool/ROOT/"] = func(args []string) {
		ds := args[len(args)-1]
		var keep []string
		for _, b := range w.bes {
			if b != ds {
				keep = append(keep, b)
			}
		}
		w.bes = keep
		w.refresh()
	}
	w.runner.hooks["zpool set bootfs="] = func(args []string) {
		w.bootfs = strings.TrimPrefix(args[1], "bootfs=")
		w.refresh()
	}
	f.OnResult("zfs list -H -o name rpool/ROOT/hardyos-0.2.0", sysexec.Result{ExitCode: 1})
	f.On("zfs get -H -o value org.hardyos:version rpool/ROOT/hardyos-0.1.0", "0.1.0\n")
	f.OnPrefix("", sysexec.Result{})

	w.u = &Updater{
		Runner: w.runner, Root: w.root, Arch: "amd64",
		Keys:   func() []PublicKey { return []PublicKey{pub} },
		Now:    func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) },
		Reboot: func() { w.reboots.Add(1) },
	}
	return w
}

func (w *world) upload(version string) string {
	src := makeBundle(w.t, w.priv, version, "amd64", []byte("squashfs-bytes-"+version))
	b, _ := os.ReadFile(src)
	host := filepath.Join(w.u.UploadDir(), "upload-"+version+".hupd")
	w.write(host, string(b))
	return host
}

func (w *world) has(cmd string) bool {
	for _, l := range w.runner.Fake.Lines() {
		if strings.Contains(l, cmd) {
			return true
		}
	}
	return false
}

func TestStageConfirm(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	bundle := w.upload("0.2.0")

	res, err := w.u.Stage(ctx, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if res.BE != "hardyos-0.2.0" || res.Notes != "test notes" {
		t.Fatalf("stage result %+v", res)
	}
	mnt := filepath.Join(w.root, "run/hardyos/update/root")
	if b, _ := os.ReadFile(filepath.Join(mnt, "etc/hostname")); string(b) != "nas\n" {
		t.Errorf("hostname not carried over: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(mnt, "etc/ssh/ssh_host_ed25519_key")); string(b) != "host-key" {
		t.Error("SSH host key not carried over")
	}
	if _, err := os.Stat(filepath.Join(mnt, "etc/hardyos/live-installer")); err == nil {
		t.Error("live marker left in the new version")
	}
	if _, err := os.Stat(filepath.Join(w.root, bundle)); err == nil {
		t.Error("uploaded bundle not removed")
	}
	for _, want := range []string{
		"zfs create -o canmount=noauto -o mountpoint=/ -o org.hardyos:version=0.2.0 rpool/ROOT/hardyos-0.2.0",
		"mount -t zfs -o zfsutil rpool/ROOT/hardyos-0.2.0 /run/hardyos/update/root",
		"unsquashfs -f -no-progress -d /run/hardyos/update/root /var/lib/hardyos/updates/staging.squashfs",
		"grub-editenv /run/hardyos/boot/esp0/grub/grubenv set next_entry=hardyos-0.2.0",
	} {
		if !w.has(want) {
			t.Errorf("missing %q", want)
		}
	}
	if w.has("zpool set bootfs") {
		t.Error("staging must not change the default version")
	}
	st, _ := w.u.Status(ctx)
	if st.Pending == nil || st.Pending.Version != "0.2.0" || st.Pending.FromVersion != "0.1.0" || st.Running != "hardyos-0.1.0" {
		t.Fatalf("status %+v", st)
	}
	if _, err := w.u.Stage(ctx, w.upload("0.3.0")); err == nil || !strings.Contains(err.Error(), "waiting for a restart") {
		t.Fatalf("second stage: %v", err)
	}

	// Restart: snapshot first, without the pending marker inside it.
	markerInSnapshot := true
	w.runner.hooks["zfs snapshot rpool/hardyos@pre-"] = func([]string) {
		_, err := os.Stat(filepath.Join(w.root, "var/lib/hardyos/update-pending.json"))
		markerInSnapshot = err == nil
	}
	if err := w.u.BeforeReboot(ctx); err != nil {
		t.Fatal(err)
	}
	if !w.has("zfs snapshot rpool/hardyos@pre-hardyos-0.2.0-20261025-120000") {
		t.Error("no state snapshot before restarting")
	}
	if markerInSnapshot {
		t.Error("the settings snapshot contains the pending marker")
	}
	if p, _ := w.u.PendingUpdate(); p == nil || p.Snapshot == "" {
		t.Fatalf("pending marker after restart prep: %+v", p)
	}
	// Not booted into it yet: confirm does nothing.
	if r, _ := w.u.Confirm(ctx); r.Confirmed {
		t.Fatal("confirmed while the old version runs")
	}

	// First boot of the new version.
	w.setBooted("rpool/ROOT/hardyos-0.2.0")
	w.u.ConfirmTimeout = time.Hour
	bootCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	w.u.OnBoot(bootCtx)
	r, err := w.u.Confirm(ctx)
	if err != nil || !r.Confirmed {
		t.Fatalf("confirm %+v, %v", r, err)
	}
	if w.bootfs != "rpool/ROOT/hardyos-0.2.0" {
		t.Errorf("default is %s", w.bootfs)
	}
	st, _ = w.u.Status(ctx)
	if st.Pending != nil || st.Last == nil || !st.Last.OK || st.Running != "hardyos-0.2.0" {
		t.Fatalf("after confirm %+v", st)
	}
	if !w.has("grub-editenv /run/hardyos/boot/esp0/grub/grubenv unset next_entry") {
		t.Error("one-time boot choice not cleared")
	}
}

func TestFailedUpdateFallsBack(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	if _, err := w.u.Stage(ctx, w.upload("0.2.0")); err != nil {
		t.Fatal(err)
	}
	if err := w.u.BeforeReboot(ctx); err != nil {
		t.Fatal(err)
	}
	// The new version never confirmed; firmware came back on the old one.
	w.setBooted("rpool/ROOT/hardyos-0.1.0")
	w.u.OnBoot(ctx)
	for _, want := range []string{
		"zfs rollback -r rpool/hardyos@pre-hardyos-0.2.0-20261025-120000",
		"zfs destroy -r rpool/ROOT/hardyos-0.2.0",
	} {
		if !w.has(want) {
			t.Errorf("missing %q", want)
		}
	}
	st, _ := w.u.Status(ctx)
	if st.Pending != nil || st.Last == nil || st.Last.OK || !strings.Contains(st.Last.Message, "went back to 0.1.0") {
		t.Fatalf("status %+v / %+v", st, st.Last)
	}
	if len(st.Versions) != 1 {
		t.Fatalf("failed version not removed: %+v", st.Versions)
	}
}

func TestWatchdogRestarts(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	if _, err := w.u.Stage(ctx, w.upload("0.2.0")); err != nil {
		t.Fatal(err)
	}
	w.setBooted("rpool/ROOT/hardyos-0.2.0")
	w.u.ConfirmTimeout = 20 * time.Millisecond
	w.u.OnBoot(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for w.reboots.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if w.reboots.Load() != 1 {
		t.Fatal("an unconfirmed version was not restarted")
	}
}

func TestStageRejects(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	if _, err := w.u.Stage(ctx, "/etc/passwd"); err == nil {
		t.Error("staged a file outside the upload directory")
	}
	if _, err := w.u.Stage(ctx, w.u.UploadDir()+"/../../../etc/shadow"); err == nil {
		t.Error("followed .. out of the upload directory")
	}
	w.u.Arch = "arm64"
	if _, err := w.u.Stage(ctx, w.upload("0.2.0")); err == nil || !strings.Contains(err.Error(), "for amd64") {
		t.Errorf("arch mismatch: %v", err)
	}
	w.u.Arch = "amd64"
	w.u.Keys = func() []PublicKey { return nil }
	if _, err := w.u.Stage(ctx, w.upload("0.2.0")); err == nil || !strings.Contains(err.Error(), "trusts no release key") {
		t.Errorf("no keys: %v", err)
	}
	if w.has("zfs create") {
		t.Error("created a boot environment for a rejected update")
	}
}

func TestActivateDeleteCleanup(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.bes = []string{"rpool/ROOT/hardyos-0.1.0", "rpool/ROOT/hardyos-0.2.0", "rpool/ROOT/hardyos-0.3.0", "rpool/ROOT/hardyos-0.4.0", "rpool/ROOT/hardyos-0.5.0"}
	w.bootfs = "rpool/ROOT/hardyos-0.5.0"
	w.setBooted("rpool/ROOT/hardyos-0.5.0")
	w.refresh()
	for _, ds := range w.bes {
		be := filepath.Base(ds)
		w.write("/run/hardyos/boot/be/"+be+"/boot/vmlinuz-6.12.1", "k")
		w.write("/run/hardyos/boot/be/"+be+"/boot/initrd.img-6.12.1", "i")
	}
	w.runner.Fake.On("zfs list -H -t snapshot -o name -s creation rpool/hardyos",
		"rpool/hardyos@pre-hardyos-0.5.0-20261020-100000\nrpool/hardyos@pre-hardyos-0.1.0-20260101-000000\n")

	w.runner.Fake.On("zfs get -H -o value org.hardyos:version rpool/ROOT/hardyos-0.4.0", "0.4.0\n")
	if err := w.u.Activate(ctx, "hardyos-0.5.0", false); err == nil {
		t.Error("activated the running version")
	}
	if err := w.u.Activate(ctx, "hardyos-9.9.9", false); err == nil {
		t.Error("activated a missing version")
	}
	if err := w.u.Activate(ctx, "hardyos-0.4.0", true); err != nil {
		t.Fatal(err)
	}
	if w.bootfs != "rpool/ROOT/hardyos-0.4.0" {
		t.Errorf("default %s", w.bootfs)
	}
	st, _ := w.u.Status(ctx)
	if !st.RestoreOnBoot {
		t.Error("settings restore not scheduled")
	}
	// The snapshot was taken right before restarting into 0.5.0, so rolling
	// back brings 0.5.0's old pending marker with it (found on a real VM).
	w.runner.hooks["zfs rollback -r rpool/hardyos@pre-hardyos-0.5.0-"] = func([]string) {
		w.write("/var/lib/hardyos/update-pending.json", `{"bootEnvironment":"hardyos-0.5.0","dataset":"rpool/ROOT/hardyos-0.5.0","version":"0.5.0","fromBootEnvironment":"hardyos-0.4.0","fromVersion":"0.4.0","stagedAt":"2026-10-20T10:00:00Z","snapshot":"rpool/hardyos@pre-hardyos-0.5.0-20261020-100000"}`)
	}
	// The next boot restores settings before hardyd starts.
	w.setBooted("rpool/ROOT/hardyos-0.4.0")
	w.u.OnBoot(ctx)
	if !w.has("zfs rollback -r rpool/hardyos@pre-hardyos-0.5.0-20261020-100000") {
		t.Error("settings not restored on boot")
	}
	if w.has("zfs destroy -r rpool/ROOT/hardyos-0.5.0") {
		t.Fatal("going back by hand destroyed the newer version")
	}
	st, _ = w.u.Status(ctx)
	if st.Pending != nil || st.Last == nil || !st.Last.OK || !strings.Contains(st.Last.Message, "Switched to HardyOS 0.4.0 and restored settings") {
		t.Fatalf("after restore: pending=%+v last=%+v", st.Pending, st.Last)
	}

	if err := w.u.Delete(ctx, "hardyos-0.4.0"); err == nil {
		t.Error("deleted the running version")
	}
	if err := w.u.Delete(ctx, "hardyos-0.1.0"); err != nil {
		t.Fatal(err)
	}
	if !w.has("zfs destroy rpool/hardyos@pre-hardyos-0.1.0-20260101-000000") {
		t.Error("deleted version's settings snapshot kept")
	}

	// Keep 2: 0.5.0 and 0.4.0 are newest... 0.4.0 runs and is default.
	w.u.Cleanup(ctx, 2)
	got := strings.Join(w.bes, ",")
	if got != "rpool/ROOT/hardyos-0.4.0,rpool/ROOT/hardyos-0.5.0" {
		t.Fatalf("after cleanup: %s", got)
	}
}

func TestForgedStateFilesAreIgnored(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership checks need root")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "update-pending.json")
	_ = os.WriteFile(p, []byte(`{"dataset":"tank/photos","bootEnvironment":"x"}`), 0o644)
	_ = os.Chown(p, 1000, 1000)
	rootfile.Enforce = true
	defer func() { rootfile.Enforce = false }()
	var pend Pending
	if ok, err := readJSON(p, &pend); ok || err == nil {
		t.Fatalf("hardyd-owned pending file read: ok=%v err=%v", ok, err)
	}
}
