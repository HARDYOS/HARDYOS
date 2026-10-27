package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
	defer func() { _ = unbindSystemDirs(context.WithoutCancel(ctx), r, root, target) }()

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
			_ = unbindSystemDirs(context.WithoutCancel(ctx), r, root, target)
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
	err := fn()
	var te *TeardownError
	if uerr := unbindSystemDirs(context.WithoutCancel(ctx), r, root, target); errors.As(uerr, &te) && te.fatal() && err == nil {
		err = uerr
	}
	return err
}

// unbindSystemDirs unmounts what bindSystemDirs mounted, and anything
// else still mounted below those directories, so the target's own
// filesystems (the new system's ZFS datasets) can be unmounted next.
//
// Each tree is first made private (mount --make-rprivate): from then on
// nothing done to it can reach the server's own mounts, whatever the
// propagation was. It is then unmounted recursively; when that fails
// because something is still busy, the processes holding files under the
// target are reported, and the tree, private by now, is detached lazily:
// a lazy unmount of a private copy only ever affects that copy. Whatever
// is still mounted under the target afterwards (per /proc/self/mountinfo)
// is unmounted deepest first. The error lists what couldn't be unmounted
// and which processes still hold files under the target.
func unbindSystemDirs(ctx context.Context, r sysexec.Runner, root, target string) error {
	var problems []string
	var holders []string
	for _, m := range []string{"run", "sys", "proc", "dev"} {
		dir := filepath.Join(target, m)
		if !mountedAt(root, dir) {
			continue
		}
		if res, err := r.Run(ctx, nil, "mount", "--make-rprivate", dir); err != nil || res.ExitCode != 0 {
			// Not private: never fall back to a lazy unmount for it.
			if res, err := r.Run(ctx, nil, "umount", "-R", dir); err != nil || res.ExitCode != 0 {
				problems = append(problems, fmt.Sprintf("%s: %s", dir, strings.TrimSpace(string(res.Stderr))))
			}
			continue
		}
		res, err := r.Run(ctx, nil, "umount", "-R", dir)
		if err == nil && res.ExitCode == 0 {
			continue
		}
		// Busy: say who holds it (before detaching it, while the paths
		// still read as under the target), then detach the private copy.
		if holders == nil {
			holders = Holders(root, target)
			if holders == nil {
				holders = []string{}
			}
		}
		if res, err := r.Run(ctx, nil, "umount", "-R", "-l", dir); err != nil || res.ExitCode != 0 {
			problems = append(problems, fmt.Sprintf("%s: %s", dir, strings.TrimSpace(string(res.Stderr))))
		}
	}
	// Anything left below the system directories, deepest first.
	for _, mp := range mountsUnder(root, target, true) {
		if res, err := r.Run(ctx, nil, "umount", mp); err != nil || res.ExitCode != 0 {
			problems = append(problems, fmt.Sprintf("%s: %s", mp, strings.TrimSpace(string(res.Stderr))))
		}
	}
	for _, mp := range mountsUnder(root, target, true) {
		problems = append(problems, mp+" is still mounted")
	}
	if holders != nil && len(holders) == 0 {
		holders = []string{"an unknown process"}
	}
	if len(problems) > 0 || holders != nil {
		return &TeardownError{Target: target, Left: problems, Holders: holders}
	}
	return nil
}

// TeardownError says what unbindSystemDirs found. With Left empty
// everything was unmounted, but only by detaching copies that processes
// (Holders) still used: harmless for the server, worth reporting.
type TeardownError struct {
	Target  string
	Left    []string // couldn't be unmounted
	Holders []string // processes holding files under the target
}

func (e *TeardownError) Error() string {
	var parts []string
	if len(e.Left) > 0 {
		parts = append(parts, strings.Join(e.Left, "; "))
	}
	if len(e.Holders) > 0 {
		parts = append(parts, "in use by "+strings.Join(e.Holders, ", ")+" (detached; the server's own mounts are untouched)")
	}
	return fmt.Sprintf("unmounting the system directories in %s: %s", e.Target, strings.Join(parts, "; "))
}

// fatal reports whether something is still mounted.
func (e *TeardownError) fatal() bool { return len(e.Left) > 0 }

// mountInfo lists mount points from /proc/self/mountinfo (under root).
func mountInfo(root string) []string {
	b, err := os.ReadFile(filepath.Join(root, "proc/self/mountinfo"))
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) > 4 {
			out = append(out, unescapeOctal(f[4]))
		}
	}
	return out
}

func mountedAt(root, dir string) bool {
	info := mountInfo(root)
	if info == nil {
		return true // can't tell (tests without procfs): try
	}
	for _, mp := range info {
		if mp == dir {
			return true
		}
	}
	return false
}

// mountsUnder lists mount points below target's system directories (or,
// with sysOnly false, anywhere below target), deepest first.
func mountsUnder(root, target string, sysOnly bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, mp := range mountInfo(root) {
		ok := false
		if sysOnly {
			for _, m := range []string{"run", "sys", "proc", "dev"} {
				d := filepath.Join(target, m)
				if mp == d || strings.HasPrefix(mp, d+"/") {
					ok = true
				}
			}
		} else {
			ok = strings.HasPrefix(mp, strings.TrimSuffix(target, "/")+"/")
		}
		if ok && !seen[mp] {
			seen[mp] = true
			out = append(out, mp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		di, dj := strings.Count(out[i], "/"), strings.Count(out[j], "/")
		if di != dj {
			return di > dj
		}
		return out[i] > out[j]
	})
	return out
}

// Holders lists the processes with their working directory, root or an
// open file under target ("1234 dpkg (cwd /target/var/lib)"), like fuser.
func Holders(root, target string) []string {
	procs, _ := os.ReadDir(filepath.Join(root, "proc"))
	prefix := strings.TrimSuffix(target, "/")
	under := func(p string) bool { return p == prefix || strings.HasPrefix(p, prefix+"/") }
	var out []string
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		dir := filepath.Join(root, "proc", p.Name())
		what := ""
		for _, l := range []string{"root", "cwd"} {
			if t, err := os.Readlink(filepath.Join(dir, l)); err == nil && under(t) && t != "/" {
				what = l + " " + t
				break
			}
		}
		if what == "" {
			fds, _ := os.ReadDir(filepath.Join(dir, "fd"))
			for _, fd := range fds {
				if t, err := os.Readlink(filepath.Join(dir, "fd", fd.Name())); err == nil && under(t) {
					what = "open " + t
					break
				}
			}
		}
		if what == "" {
			continue
		}
		comm, _ := os.ReadFile(filepath.Join(dir, "comm"))
		out = append(out, fmt.Sprintf("%d %s (%s)", pid, strings.TrimSpace(string(comm)), what))
		if len(out) >= 20 {
			out = append(out, "…")
			break
		}
	}
	return out
}

func unescapeOctal(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	return regexp.MustCompile(`\\([0-7]{3})`).ReplaceAllStringFunc(s, func(m string) string {
		n, _ := strconv.ParseUint(m[1:], 8, 8)
		return string(rune(n))
	})
}
