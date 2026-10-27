package gpu

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/install"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// PrepareNewRoot is the update hook: a new HardyOS version is a fresh
// system image without the NVIDIA driver, so before it's added to the boot
// menu the driver HardyOS installed here is installed into it again and
// built (DKMS) for each of its kernels, and root's GPU directory (the
// admin's agreement, the vGPU driver file) is copied over. newRoot is
// where the new system is mounted (a path on the server). Any failure
// stops the update; the current version stays active.
func (m *Manager) PrepareNewRoot(ctx context.Context, newRoot string) error {
	if !filepath.IsAbs(newRoot) || newRoot == "/" {
		return fmt.Errorf("invalid new system path %q", newRoot)
	}
	rec, err := m.load()
	if err != nil {
		return err
	}
	driver := rec.Driver != nil && rec.Driver.Installed
	vgpu := rec.VGPU != nil && rec.VGPU.Installed
	if exists(m.path(Dir)) {
		if err := copyTree(m.path(Dir), m.path(filepath.Join(newRoot, Dir))); err != nil {
			return fmt.Errorf("copy the GPU settings: %w", err)
		}
	}
	if !driver && !vgpu {
		return nil
	}
	kernels := newKernels(m.path(newRoot))
	if len(kernels) == 0 {
		return errors.New("the new version has no kernel to build the NVIDIA driver for")
	}
	chroot := func(args ...string) error {
		_, err := sysexec.Output(ctx, m.Runner, "chroot", append([]string{newRoot}, args...)...)
		var ce *sysexec.CommandError
		if errors.As(err, &ce) {
			return errors.New(ce.Error())
		}
		return err
	}
	return install.WithSystemDirs(ctx, m.Runner, m.Root, newRoot, func() error {
		if driver {
			if err := writeSources(m.path(newRoot), m.Arch); err != nil {
				return err
			}
			if err := chroot("env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update"); err != nil {
				return fmt.Errorf("the NVIDIA driver can't be downloaded for the new version (is the server online?): %w", err)
			}
			if err := chroot(append([]string{"env", "DEBIAN_FRONTEND=noninteractive", "apt-get"}, aptInstallArgs(rec.Driver.Packages...)...)...); err != nil {
				return fmt.Errorf("installing the NVIDIA driver into the new version: %w", err)
			}
			for _, k := range kernels {
				if !moduleBuilt(m.path(newRoot), k, "nvidia") {
					_ = chroot("dkms", "autoinstall", "-k", k)
				}
				if !moduleBuilt(m.path(newRoot), k, "nvidia") {
					return fmt.Errorf("the NVIDIA driver couldn't be built for the new version's kernel %s", k)
				}
			}
		}
		if vgpu {
			if !vgpuFileRE.MatchString(rec.VGPU.File) {
				return errors.New("the recorded vGPU driver file name is invalid")
			}
			run := filepath.Join(Dir, "vgpu", rec.VGPU.File)
			for _, k := range kernels {
				if err := chroot("sh", run, "--silent", "--dkms", "--kernel-name="+k, "--skip-module-load"); err != nil {
					return fmt.Errorf("NVIDIA's vGPU host driver couldn't be installed for the new version's kernel %s: %w", k, err)
				}
				if !moduleBuilt(m.path(newRoot), k, "nvidia") {
					return fmt.Errorf("NVIDIA's vGPU host driver couldn't be built for the new version's kernel %s", k)
				}
			}
		}
		for _, k := range kernels {
			if err := chroot("update-initramfs", "-u", "-k", k); err != nil {
				return fmt.Errorf("rebuild the new version's initramfs: %w", err)
			}
		}
		return nil
	})
}

// newKernels lists the kernel versions in a system (with an image).
func newKernels(sysRoot string) []string {
	entries, _ := os.ReadDir(filepath.Join(sysRoot, "lib/modules"))
	var out []string
	for _, e := range entries {
		if strings.ContainsAny(e.Name(), "/*?[ ") {
			continue
		}
		if _, err := os.Stat(filepath.Join(sysRoot, "boot", "vmlinuz-"+e.Name())); err == nil {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// copyTree copies regular files and directories (no links) from src to dst.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			if strings.HasSuffix(p, "licence-tmp") {
				return filepath.SkipDir
			}
			return os.MkdirAll(target, 0o700)
		case d.Type().IsRegular():
			in, err := os.Open(p)
			if err != nil {
				return err
			}
			defer in.Close()
			fi, _ := in.Stat()
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fi.Mode().Perm())
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, in); err != nil {
				out.Close()
				return err
			}
			return out.Close()
		}
		return nil
	})
}
