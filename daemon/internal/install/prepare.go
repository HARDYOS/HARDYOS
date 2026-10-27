package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// livePackages are only for the live ISO and are removed from installed systems.
var livePackages = []string{"live-boot", "live-boot-initramfs-tools", "live-config", "live-config-systemd", "live-tools"}

// FinishRoot turns a freshly unpacked system image at target (a host path
// under root) into an installable system: it drops the live-installer marker
// and the live-system packages, creates any missing SSH host keys and builds
// the initramfs (with ZFS support) for every kernel. The installer and system
// updates both use it.
func FinishRoot(ctx context.Context, r sysexec.Runner, root, target string) error {
	path := func(p string) string { return filepath.Join(root, target, p) }
	for _, rel := range []string{"etc/hardyos/live-installer", "var/lib/dbus/machine-id"} {
		_ = os.Remove(path(rel))
	}
	if err := bindSystemDirs(ctx, r, root, target); err != nil {
		return err
	}
	defer unbindSystemDirs(context.WithoutCancel(ctx), r, target)

	run := func(args ...string) error {
		_, err := sysexec.Output(ctx, r, "chroot", append([]string{target}, args...)...)
		var ce *sysexec.CommandError
		if errors.As(err, &ce) {
			return errors.New(ce.Error())
		}
		return err
	}
	if live := installedLivePackages(ctx, r, target); len(live) > 0 {
		if err := run(append([]string{"env", "DEBIAN_FRONTEND=noninteractive", "dpkg", "--purge"}, live...)...); err != nil {
			return fmt.Errorf("remove live-system packages: %w", err)
		}
	}
	// Creates only the host keys that are missing (kept keys stay).
	if err := run("ssh-keygen", "-A"); err != nil {
		return err
	}
	kernels, err := os.ReadDir(path("lib/modules"))
	if err != nil {
		return err
	}
	for _, k := range kernels {
		if _, err := os.Stat(path("boot/vmlinuz-" + k.Name())); err != nil {
			continue
		}
		_ = os.Remove(path("boot/initrd.img-" + k.Name()))
		if err := run("update-initramfs", "-c", "-k", k.Name()); err != nil {
			return fmt.Errorf("build initramfs for %s: %w", k.Name(), err)
		}
	}
	return nil
}

func installedLivePackages(ctx context.Context, r sysexec.Runner, target string) []string {
	args := append([]string{target, "dpkg-query", "-W", "-f=${Package} ${db:Status-Status}\\n"}, livePackages...)
	res, err := r.Run(ctx, nil, "chroot", args...)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[1] == "installed" {
			out = append(out, f[0])
		}
	}
	return out
}

// systemDirs are mounted inside a target for chroot work. /dev is a
// recursive bind of the server's own /dev (with /dev/pts, /dev/shm,
// /dev/hugepages, /dev/mqueue under it); the others are fresh mounts.
var systemDirs = [][]string{
	{"--rbind", "/dev", "dev"},
	{"-t", "proc", "proc", "proc"},
	{"-t", "sysfs", "sysfs", "sys"},
	{"-t", "tmpfs", "tmpfs", "run"},
}

// bindSystemDirs mounts /dev, /proc, /sys and /run inside target.
//
// The server's mounts are shared (systemd makes / shared), so a bind of
// /dev joins /dev's peer group: unmounting target/dev/pts would unmount
// the server's own /dev/pts, /dev/shm and the rest too. Every mount is made
// a recursive slave right after it's made, so nothing done inside the
// target ever propagates back to the server, while the server's own
// changes still show inside.
func bindSystemDirs(ctx context.Context, r sysexec.Runner, root, target string) error {
	for _, m := range systemDirs {
		dst := filepath.Join(target, m[len(m)-1])
		args := append(append([]string{}, m[:len(m)-1]...), dst)
		if err := os.MkdirAll(filepath.Join(root, dst), 0o755); err != nil {
			return err
		}
		err := mountCmd(ctx, r, args...)
		if err == nil {
			if err = mountCmd(ctx, r, "--make-rslave", dst); err != nil {
				// Mounted but not cut off from the server: take it down at
				// once, without -R (a plain umount of the top fails rather
				// than reaching into shared submounts).
				_, _ = r.Run(context.WithoutCancel(ctx), nil, "umount", dst)
			}
		}
		if err != nil {
			unbindSystemDirs(context.WithoutCancel(ctx), r, target)
			return err
		}
	}
	return nil
}

func mountCmd(ctx context.Context, r sysexec.Runner, args ...string) error {
	_, err := sysexec.Output(ctx, r, "mount", args...)
	var ce *sysexec.CommandError
	if errors.As(err, &ce) {
		return errors.New(ce.Error())
	}
	return err
}

// WithSystemDirs runs fn with /dev, /proc, /sys and /run mounted inside
// target (an unpacked system under root), for work done with chroot, and
// unmounts them afterwards. Update hooks (the GPU drivers) use it.
func WithSystemDirs(ctx context.Context, r sysexec.Runner, root, target string, fn func() error) error {
	if err := bindSystemDirs(ctx, r, root, target); err != nil {
		return err
	}
	defer unbindSystemDirs(context.WithoutCancel(ctx), r, target)
	return fn()
}

// unbindSystemDirs unmounts what bindSystemDirs mounted, recursively and
// never lazily: a lazy unmount detaches whatever is still busy and can't
// be checked. Something still busy (a process left in the chroot) is
// retried briefly and then left mounted; that only keeps the new system's
// directory busy, never touches the server's own /dev.
func unbindSystemDirs(ctx context.Context, r sysexec.Runner, target string) {
	for _, m := range []string{"run", "sys", "proc", "dev"} {
		dir := filepath.Join(target, m)
		for attempt := 0; attempt < 3; attempt++ {
			res, err := r.Run(ctx, nil, "umount", "-R", dir)
			if err == nil && (res.ExitCode == 0 || !strings.Contains(string(res.Stderr), "busy")) {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(attempt+1) * 500 * time.Millisecond):
			}
		}
	}
}
