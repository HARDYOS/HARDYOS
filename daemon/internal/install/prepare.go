package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

func bindSystemDirs(ctx context.Context, r sysexec.Runner, root, target string) error {
	mounts := [][]string{
		{"--rbind", "/dev", filepath.Join(target, "dev")},
		{"-t", "proc", "proc", filepath.Join(target, "proc")},
		{"-t", "sysfs", "sysfs", filepath.Join(target, "sys")},
		{"-t", "tmpfs", "tmpfs", filepath.Join(target, "run")},
	}
	for _, m := range mounts {
		if err := os.MkdirAll(filepath.Join(root, m[len(m)-1]), 0o755); err != nil {
			return err
		}
		if _, err := sysexec.Output(ctx, r, "mount", m...); err != nil {
			unbindSystemDirs(ctx, r, target)
			var ce *sysexec.CommandError
			if errors.As(err, &ce) {
				return errors.New(ce.Error())
			}
			return err
		}
	}
	return nil
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

func unbindSystemDirs(ctx context.Context, r sysexec.Runner, target string) {
	for _, m := range []string{"run", "sys", "proc", "dev"} {
		_, _ = r.Run(ctx, nil, "umount", "-R", "-l", filepath.Join(target, m))
	}
}
