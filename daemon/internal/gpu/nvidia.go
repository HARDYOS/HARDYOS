package gpu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Installing Debian's NVIDIA driver is two steps, so the admin reads the
// licence of exactly the packages that get installed:
//
//  1. PrepareNvidia (task): add the apt sources, download the packages and
//     take NVIDIA's licence text out of the downloaded package.
//  2. InstallNvidia (task), with the SHA-256 of the licence text the admin
//     agreed to: the agreement is recorded, then the packages are installed
//     and the driver is built (DKMS) for the running kernel.

// MaxLicenceBytes bounds the licence text.
const MaxLicenceBytes = 512 << 10

// licencePackages are the downloaded packages the licence is read from,
// in order of preference.
var licencePackages = []string{"nvidia-kernel-support", "nvidia-kernel-dkms", "nvidia-driver", "nvidia-driver-libs"}

var debVersionRE = regexp.MustCompile(`^[0-9A-Za-z.+~:-]{1,64}$`)

var sha256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ErrNoNVIDIA means the server has no NVIDIA card.
var ErrNoNVIDIA = errors.New("this server has no NVIDIA graphics card")

// PrepareNvidia starts fetching the driver packages and their licence.
func (m *Manager) PrepareNvidia() (*Task, error) {
	if m.nvidiaGPUs() == 0 {
		return nil, ErrNoNVIDIA
	}
	return m.start(TaskNvidiaPrepare, func(ctx context.Context, c *tc) (any, error) {
		c.step(5, "Adding Debian's non-free packages and NVIDIA's container toolkit repository")
		if err := writeSources(m.Root, m.Arch); err != nil {
			return nil, err
		}
		c.step(15, "Updating the package lists")
		if _, err := c.run(ctx, aptEnv, "apt-get", "update"); err != nil {
			return nil, fmt.Errorf("updating the package lists (is the server online?): %w", err)
		}
		c.step(35, "Downloading the NVIDIA driver packages")
		args := append([]string{"-y", "--no-install-recommends", "--download-only", "install"}, DriverPackages...)
		if _, err := c.run(ctx, aptEnv, "apt-get", args...); err != nil {
			return nil, fmt.Errorf("downloading the packages: %w", err)
		}
		c.step(80, "Reading NVIDIA's licence from the packages")
		text, src, version, err := m.extractLicence(ctx, c)
		if err != nil {
			return nil, err
		}
		d, err := m.ensureDir("")
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(d, "licence-nvidia.txt"), []byte(text), 0o600); err != nil {
			return nil, err
		}
		sum := sha256.Sum256([]byte(text))
		rec, err := m.load()
		if err != nil {
			return nil, err
		}
		rec.Licence = &Licence{SHA256: hex.EncodeToString(sum[:]), Version: version, Packages: DriverPackages, Prepared: time.Now().UTC(), Source: src}
		if err := m.save(rec); err != nil {
			return nil, err
		}
		return map[string]string{"licenceSha256": rec.Licence.SHA256, "version": version}, nil
	})
}

// extractLicence unpacks the downloaded package and returns the licence.
func (m *Manager) extractLicence(ctx context.Context, c *tc) (text, source, version string, err error) {
	for _, pkg := range licencePackages {
		debs, _ := filepath.Glob(m.path("/var/cache/apt/archives/" + pkg + "_*.deb"))
		if len(debs) == 0 {
			continue
		}
		sort.Strings(debs)
		deb := debs[len(debs)-1]
		version = debVersion(filepath.Base(deb))
		tmp, err := m.ensureDir("licence-tmp")
		if err != nil {
			return "", "", "", err
		}
		_ = os.RemoveAll(tmp)
		if tmp, err = m.ensureDir("licence-tmp"); err != nil {
			return "", "", "", err
		}
		rel, _ := filepath.Rel(m.Root, deb)
		relTmp, _ := filepath.Rel(m.Root, tmp)
		if _, err := c.run(ctx, nil, "dpkg-deb", "-x", "/"+rel, "/"+relTmp); err != nil {
			return "", "", "", fmt.Errorf("unpacking %s: %w", filepath.Base(deb), err)
		}
		text, src := findLicence(tmp)
		_ = os.RemoveAll(tmp)
		if text != "" {
			return text, filepath.Base(deb) + ":" + src, version, nil
		}
	}
	return "", "", "", errors.New("NVIDIA's licence wasn't found in the downloaded packages, so the driver can't be offered")
}

// findLicence looks for the copyright file carrying NVIDIA's licence.
func findLicence(dir string) (string, string) {
	var text, src string
	_ = filepath.WalkDir(filepath.Join(dir, "usr/share/doc"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || text != "" || !d.Type().IsRegular() {
			return nil
		}
		if n := d.Name(); n != "copyright" && !strings.HasPrefix(strings.ToUpper(n), "LICENSE") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil || len(b) > MaxLicenceBytes {
			return nil
		}
		s := string(b)
		if strings.Contains(s, "NVIDIA") && strings.Contains(strings.ToLower(s), "license") {
			text = s
			src, _ = filepath.Rel(dir, p)
		}
		return nil
	})
	return text, src
}

// debVersion takes the version out of "pkg_1%3a550.163.01-2_amd64.deb".
func debVersion(name string) string {
	parts := strings.Split(strings.TrimSuffix(name, ".deb"), "_")
	if len(parts) < 2 {
		return ""
	}
	v, err := url.PathUnescape(parts[1])
	if err != nil || !debVersionRE.MatchString(v) {
		return ""
	}
	return v
}

// InstallArgs installs the NVIDIA driver once the admin agreed.
type InstallArgs struct {
	// LicenceSHA256 is the hash of the licence text the admin read.
	LicenceSHA256 string `json:"licenceSha256"`
	// By is the admin who agreed (for the record).
	By string `json:"by"`
}

// InstallNvidia records the admin's agreement and installs the driver.
func (m *Manager) InstallNvidia(a InstallArgs) (*Task, error) {
	if !sha256RE.MatchString(a.LicenceSHA256) {
		return nil, errors.New("the licence agreement is missing")
	}
	if a.By == "" || len(a.By) > 200 {
		return nil, errors.New("who agreed to the licence is missing")
	}
	text, lic, err := m.LicenceText()
	if err != nil {
		return nil, errors.New("show NVIDIA's licence first (it's read from the packages)")
	}
	sum := sha256.Sum256([]byte(text))
	if hex.EncodeToString(sum[:]) != lic.SHA256 || lic.SHA256 != a.LicenceSHA256 {
		return nil, errors.New("the licence changed since it was shown; read it again")
	}
	if m.nvidiaGPUs() == 0 {
		return nil, ErrNoNVIDIA
	}
	return m.start(TaskNvidiaInstall, func(ctx context.Context, c *tc) (any, error) {
		c.step(3, "Recording your agreement to NVIDIA's licence")
		rec, err := m.load()
		if err != nil {
			return nil, err
		}
		rec.Driver = &Consent{By: a.By, At: time.Now().UTC(), LicenceSHA256: lic.SHA256, Version: lic.Version, Packages: DriverPackages}
		if err := m.save(rec); err != nil {
			return nil, err
		}
		c.logf("Licence %s agreed to by %s", lic.SHA256, a.By)
		if err := writeSources(m.Root, m.Arch); err != nil {
			return nil, err
		}
		c.step(8, "Finishing any package install that was interrupted")
		if _, err := c.run(ctx, aptEnv, "dpkg", "--configure", "-a"); err != nil {
			return nil, err
		}
		c.step(12, "Updating the package lists")
		if _, err := c.run(ctx, aptEnv, "apt-get", "update"); err != nil {
			return nil, fmt.Errorf("updating the package lists (is the server online?): %w", err)
		}
		c.step(25, "Installing the NVIDIA driver and building it for this kernel (this takes several minutes)")
		if _, err := c.run(ctx, aptEnv, "apt-get", aptInstallArgs(DriverPackages...)...); err != nil {
			return nil, fmt.Errorf("installing the packages: %w", err)
		}
		kernel := readTrim(m.path("/proc/sys/kernel/osrelease"))
		c.step(85, "Checking the driver was built for kernel "+kernel)
		if !moduleBuilt(m.path("/"), kernel, "nvidia") {
			_, _ = c.run(ctx, nil, "dkms", "autoinstall", "-k", kernel)
			if !moduleBuilt(m.path("/"), kernel, "nvidia") {
				return nil, fmt.Errorf("the NVIDIA driver couldn't be built for this server's kernel (%s); the log has the details", kernel)
			}
		}
		restart := true
		c.step(93, "Loading the driver")
		if !exists(m.path("/sys/module/nouveau")) {
			if _, err := c.run(ctx, nil, "modprobe", "nvidia"); err == nil {
				restart = false
			}
		}
		rec, err = m.load()
		if err != nil {
			return nil, err
		}
		if rec.Driver != nil {
			rec.Driver.Installed = true
		}
		if err := m.save(rec); err != nil {
			return nil, err
		}
		return map[string]bool{"restartNeeded": restart}, nil
	})
}

// RemoveNvidia removes the driver and the toolkit.
func (m *Manager) RemoveNvidia() (*Task, error) {
	return m.start(TaskNvidiaRemove, func(ctx context.Context, c *tc) (any, error) {
		c.step(10, "Removing the NVIDIA driver and container toolkit")
		var pkgs []string
		for _, p := range DriverPackages {
			if !strings.HasPrefix(p, "firmware-") {
				pkgs = append(pkgs, p)
			}
		}
		if _, err := c.run(ctx, aptEnv, "apt-get", append([]string{"-y", "purge"}, pkgs...)...); err != nil {
			return nil, err
		}
		c.step(70, "Removing packages nothing needs any more")
		if _, err := c.run(ctx, aptEnv, "apt-get", "-y", "autoremove"); err != nil {
			return nil, err
		}
		removeSources(m.Root)
		rec, err := m.load()
		if err != nil {
			return nil, err
		}
		rec.Driver, rec.Licence = nil, nil
		if err := m.save(rec); err != nil {
			return nil, err
		}
		return map[string]bool{"restartNeeded": true}, nil
	})
}

// moduleBuilt reports whether kernel version kv under sysRoot has the
// DKMS-built module (nvidia.ko, possibly compressed).
func moduleBuilt(sysRoot, kv, module string) bool {
	if kv == "" || strings.ContainsAny(kv, "/*?[") {
		return false
	}
	for _, dir := range []string{"updates/dkms", "updates", "kernel/drivers/video", "extra"} {
		if m, _ := filepath.Glob(filepath.Join(sysRoot, "lib/modules", kv, dir, module+".ko*")); len(m) > 0 {
			return true
		}
	}
	return false
}
