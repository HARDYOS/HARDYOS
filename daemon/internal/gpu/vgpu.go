package gpu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// NVIDIA's vGPU host driver ("vgpu-kvm") comes from the admin, who gets it
// from NVIDIA with a vGPU licence. HardyOS never downloads, ships, patches
// or unlocks it: hardyd saves the uploaded file, hardyd-priv copies it into
// root's directory checking the SHA-256 hardyd computed while receiving it,
// checks it's NVIDIA's host driver installer for this architecture and a
// supported branch, and runs NVIDIA's installer with DKMS as a task.

// MinVGPUBranch is the oldest vGPU host driver branch accepted (vGPU 16,
// R535); older ones don't build on HardyOS's kernel. Whether a given
// branch builds is settled by the DKMS build itself.
const MinVGPUBranch = 535

var vgpuFileRE = regexp.MustCompile(`^NVIDIA-Linux-(x86_64|aarch64)-([0-9]{3})\.([0-9]{1,3})(\.[0-9]{1,3})?-vgpu-kvm\.run$`)
var uploadNameRE = regexp.MustCompile(`^upload-[0-9a-f]{16}\.run$`)
var labelRE = regexp.MustCompile(`label="([^"\n]{1,200})"`)

// VGPUArgs installs an uploaded vGPU host driver.
type VGPUArgs struct {
	// Upload is the file hardyd saved (in UploadDir).
	Upload string `json:"upload"`
	// SHA256 is what hardyd computed while receiving it.
	SHA256 string `json:"sha256"`
	// FileName is NVIDIA's original name for it.
	FileName string `json:"fileName"`
	By       string `json:"by"`
	// ReplaceDriver confirms removing Debian's NVIDIA driver first (the
	// two can't be installed together).
	ReplaceDriver bool `json:"replaceDriver"`
}

// CheckVGPUFileName validates NVIDIA's file name and returns the version.
func CheckVGPUFileName(name, goarch string) (string, error) {
	m := vgpuFileRE.FindStringSubmatch(name)
	if m == nil {
		if strings.Contains(name, "-grid") {
			return "", errors.New("that's NVIDIA's guest (GRID) driver, which goes inside the VM; the server needs the vGPU host driver (…-vgpu-kvm.run)")
		}
		return "", errors.New("choose NVIDIA's vGPU host driver file, named like NVIDIA-Linux-x86_64-550.90.05-vgpu-kvm.run")
	}
	want := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[goarch]
	if m[1] != want {
		return "", fmt.Errorf("this driver is for %s, but this server is %s", m[1], goarch)
	}
	branch, _ := strconv.Atoi(m[2])
	if branch < MinVGPUBranch {
		return "", fmt.Errorf("vGPU driver %s.%s is too old for this version of HardyOS (it needs R%d or newer)", m[2], m[3], MinVGPUBranch)
	}
	return m[2] + "." + m[3] + m[4], nil
}

func (m *Manager) goarch() string {
	if m.Arch != "" {
		return m.Arch
	}
	return runtime.GOARCH
}

// InstallVGPU starts installing the admin's vGPU host driver.
func (m *Manager) InstallVGPU(a VGPUArgs) (*Task, error) {
	version, err := CheckVGPUFileName(a.FileName, m.goarch())
	if err != nil {
		return nil, err
	}
	if !sha256RE.MatchString(a.SHA256) {
		return nil, errors.New("the file's checksum is missing")
	}
	if a.By == "" || len(a.By) > 200 {
		return nil, errors.New("who installs the driver is missing")
	}
	if filepath.Dir(a.Upload) != UploadDir || !uploadNameRE.MatchString(filepath.Base(a.Upload)) {
		return nil, fmt.Errorf("uploaded drivers must be in %s", UploadDir)
	}
	if m.nvidiaGPUs() == 0 {
		return nil, ErrNoNVIDIA
	}
	if m.packageInstalled(context.Background(), "nvidia-kernel-dkms") && !a.ReplaceDriver {
		return nil, errors.New("Debian's NVIDIA driver is installed. The vGPU host driver replaces it (Docker apps then can't use NVIDIA cards); confirm to go ahead")
	}
	return m.start(TaskVGPUInstall, func(ctx context.Context, c *tc) (any, error) {
		c.step(5, "Checking the driver file")
		d, err := m.ensureDir("vgpu")
		if err != nil {
			return nil, err
		}
		dst := filepath.Join(d, a.FileName)
		if err := copyVerified(m.path(a.Upload), dst, a.SHA256); err != nil {
			return nil, err
		}
		_ = os.Remove(m.path(a.Upload))
		if err := checkInstaller(dst, version); err != nil {
			_ = os.Remove(dst)
			return nil, err
		}
		c.logf("%s: SHA-256 %s, version %s", a.FileName, a.SHA256, version)
		kernel := readTrim(m.path("/proc/sys/kernel/osrelease"))
		if !exists(m.path("/lib/modules/"+kernel+"/build")) && kernel != "" {
			return nil, fmt.Errorf("the kernel headers for %s are missing, so the driver can't be built", kernel)
		}
		if m.packageInstalled(ctx, "nvidia-kernel-dkms") {
			c.step(15, "Removing Debian's NVIDIA driver, which the vGPU host driver replaces")
			var pkgs []string
			for _, p := range DriverPackages {
				if !strings.HasPrefix(p, "firmware-") {
					pkgs = append(pkgs, p)
				}
			}
			if _, err := c.run(ctx, aptEnv, "apt-get", append([]string{"-y", "purge"}, pkgs...)...); err != nil {
				return nil, err
			}
			removeSources(m.Root)
			if rec, err := m.load(); err == nil {
				rec.Driver, rec.Licence = nil, nil
				_ = m.save(rec)
			}
		}
		c.step(30, "Installing NVIDIA's vGPU host driver and building it for this kernel (this takes several minutes)")
		rel, _ := filepath.Rel(m.Root, dst)
		if _, err := c.run(ctx, nil, "sh", "/"+rel, "--silent", "--dkms"); err != nil {
			return nil, fmt.Errorf("NVIDIA's installer failed: %w", err)
		}
		if !moduleBuilt(m.path("/"), kernel, "nvidia") {
			return nil, fmt.Errorf("the vGPU driver wasn't built for this server's kernel (%s); the log has the details", kernel)
		}
		c.step(90, "Loading the driver")
		restart := true
		if _, err := c.run(ctx, nil, "modprobe", "nvidia_vgpu_vfio"); err == nil {
			restart = false
		}
		rec, err := m.load()
		if err != nil {
			return nil, err
		}
		rec.VGPU = &VGPUDriver{File: a.FileName, SHA256: a.SHA256, Version: version, By: a.By, At: time.Now().UTC(), Installed: true}
		if err := m.save(rec); err != nil {
			return nil, err
		}
		return map[string]any{"restartNeeded": restart, "version": version}, nil
	})
}

// RemoveVGPU uninstalls the vGPU host driver.
func (m *Manager) RemoveVGPU() (*Task, error) {
	rec, err := m.load()
	if err != nil {
		return nil, err
	}
	if rec.VGPU == nil {
		return nil, errors.New("no vGPU host driver was installed by HardyOS")
	}
	file := rec.VGPU.File
	if !vgpuFileRE.MatchString(file) {
		return nil, errors.New("the recorded driver file name is invalid")
	}
	return m.start(TaskVGPURemove, func(ctx context.Context, c *tc) (any, error) {
		c.step(10, "Removing NVIDIA's vGPU host driver")
		p := filepath.Join(Dir, "vgpu", file)
		if exists(m.path(p)) {
			if _, err := c.run(ctx, nil, "sh", p, "--uninstall", "--silent"); err != nil {
				return nil, err
			}
			_ = os.Remove(m.path(p))
		}
		rec, err := m.load()
		if err != nil {
			return nil, err
		}
		rec.VGPU = nil
		if err := m.save(rec); err != nil {
			return nil, err
		}
		return map[string]bool{"restartNeeded": true}, nil
	})
}

// copyVerified copies src (never through a symlink, a regular file at most
// MaxDriverBytes) to dst, root's, checking its SHA-256 on the copy root
// will run, so a file swapped after the check can't be the one executed.
func copyVerified(src, dst, want string) error {
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("the uploaded driver isn't there any more: %w", err)
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Size() > MaxDriverBytes {
		return errors.New("the upload isn't a driver file")
	}
	tmp := dst + ".tmp"
	_ = os.Remove(tmp)
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(out, h), io.LimitReader(in, MaxDriverBytes+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && hex.EncodeToString(h.Sum(nil)) != want {
		err = errors.New("the driver file changed after it was uploaded (its checksum doesn't match); upload it again")
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// checkInstaller reads the makeself header of NVIDIA's .run file: a shell
// script whose label names NVIDIA's driver and the version in its name.
func checkInstaller(p, version string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	head := make([]byte, 32<<10)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	if !bytes.HasPrefix(head, []byte("#!/bin/sh")) {
		return errors.New("this isn't NVIDIA's driver installer (it doesn't start like one)")
	}
	m := labelRE.FindSubmatch(head)
	if m == nil || !bytes.Contains(m[1], []byte("NVIDIA")) {
		return errors.New("this isn't NVIDIA's driver installer (no NVIDIA label)")
	}
	if !bytes.Contains(m[1], []byte(version)) {
		return fmt.Errorf("the installer says %q, which doesn't match the version %s in its name", m[1], version)
	}
	return nil
}
