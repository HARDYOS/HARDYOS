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
//
// The NVIDIA driver goes in only at the version whose licence the admin
// agreed to: when the new system's packages offer another version, the
// update stops with a ConsentError. And when the admin chose to update
// without the NVIDIA drivers this time (SetSkipNextUpdate), nothing is
// built: the new version records that its drivers need installing again,
// and the choice is used up.
func (m *Manager) PrepareNewRoot(ctx context.Context, newRoot string) error {
	err := m.prepareNewRoot(ctx, newRoot)
	if err != nil && !errors.Is(err, ErrConsent) {
		return fmt.Errorf("%w. To install the update anyway, choose \"Update without the NVIDIA driver this time\" in Devices & GPUs (the driver is then installed again afterwards)", err)
	}
	return err
}

func (m *Manager) prepareNewRoot(ctx context.Context, newRoot string) error {
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
	if rec.SkipNextUpdate != nil {
		return m.skipNewRoot(newRoot, rec, driver, vgpu)
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
			// Which driver version the new system would get.
			out, err := sysexec.Output(ctx, m.Runner, "chroot", append([]string{newRoot, "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-s", "--no-install-recommends", "install"}, rec.Driver.Packages...)...)
			if err != nil {
				return fmt.Errorf("listing the NVIDIA driver packages for the new version: %w", err)
			}
			offered := parseSimulation(string(out))
			if _, v := licenceVersion(offered); v != "" {
				same, err := compareVersions(ctx, m.Runner, v, "eq", rec.Driver.Version)
				if err != nil {
					return err
				}
				if !same {
					return &ConsentError{Agreed: rec.Driver.Version, Offered: v}
				}
			} else if rec.Driver.Version != "" {
				// Not offered at all: install exactly the agreed version (or fail).
				offered = map[string]string{}
				for p, v := range rec.Driver.Versions {
					offered[p] = v
				}
			}
			if err := chroot(append([]string{"env", "DEBIAN_FRONTEND=noninteractive", "apt-get"}, aptInstallArgs(pinned(rec.Driver.Packages, offered)...)...)...); err != nil {
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

// skipNewRoot leaves the drivers out of the new system, as the admin
// chose: the new system's record says which ones to install again, and
// the choice is used up here.
func (m *Manager) skipNewRoot(newRoot string, rec *Record, driver, vgpu bool) error {
	skip := rec.SkipNextUpdate
	nm := &Manager{Runner: m.Runner, Root: m.path(newRoot), Log: m.Log, Arch: m.Arch}
	nrec, err := nm.load()
	if err != nil {
		return err
	}
	nrec.SkipNextUpdate = nil
	nrec.ReinstallNeeded = &Reinstall{Driver: driver, VGPU: vgpu, By: skip.By, At: skip.At,
		Reason: "This version was installed without the NVIDIA drivers, as chosen by " + skip.By + ". Install them again in Devices & GPUs."}
	if nrec.Driver != nil {
		nrec.Driver.Installed = false
	}
	if nrec.VGPU != nil {
		nrec.VGPU.Installed = false
	}
	if err := nm.save(nrec); err != nil {
		return fmt.Errorf("record the drivers the new version needs: %w", err)
	}
	rec.SkipNextUpdate = nil
	if err := m.save(rec); err != nil {
		return err
	}
	m.log().Warn("update installed without the NVIDIA drivers", "by", skip.By, "chosenAt", skip.At, "driver", driver, "vgpu", vgpu)
	return nil
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
