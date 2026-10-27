// Package gpu installs and keeps the GPU drivers HardyOS doesn't ship:
// Debian's NVIDIA driver with NVIDIA's container toolkit (so Docker apps can
// use NVIDIA cards), installed only after the admin has read NVIDIA's
// licence and agreed, and NVIDIA's official vGPU host driver, which the
// admin supplies. It runs inside hardyd-priv. Long work runs as a
// background task with a log (one at a time), so no single privileged
// call outlives the helper's time limit.
//
// State lives in Dir, root's own directory in the running system (not
// hardyd's state dataset): the vGPU driver file root executes must never
// sit where hardyd can swap it. Updates copy Dir into the new version and
// rebuild the drivers there (UpdateHook).
package gpu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/rootfile"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Defaults.
const (
	// Dir is root's GPU directory (0700) in each system.
	Dir = "/var/lib/hardyos-gpu"
	// UploadDir is where hardyd saves an uploaded vGPU driver (hardyd's).
	UploadDir = "/var/lib/hardyos/gpu-uploads"
	// MaxDriverBytes bounds an uploaded vGPU driver file.
	MaxDriverBytes = 1 << 30
)

// Manager does the root-side GPU driver work.
type Manager struct {
	Runner sysexec.Runner
	// Root prefixes every path ("/" on a server).
	Root string
	Log  *slog.Logger
	// Arch overrides runtime.GOARCH (tests).
	Arch string
	// TaskTimeout bounds a background task (default 90 minutes).
	TaskTimeout time.Duration

	mu   sync.Mutex
	task *task
}

func (m *Manager) path(p string) string { return filepath.Join(m.Root, p) }

func (m *Manager) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

// Record is what HardyOS installed, kept in Dir/state.json.
type Record struct {
	// Driver: Debian's NVIDIA driver, with the admin's agreement.
	Driver *Consent `json:"driver,omitempty"`
	// Licence: the licence prepared for agreement (not agreed yet).
	Licence *Licence `json:"licence,omitempty"`
	// VGPU: NVIDIA's vGPU host driver from the admin.
	VGPU *VGPUDriver `json:"vgpu,omitempty"`
	// SkipNextUpdate: the admin chose to install the next update without
	// the NVIDIA drivers (used up by that update).
	SkipNextUpdate *Skip `json:"skipNextUpdate,omitempty"`
	// ReinstallNeeded: this version was installed without the NVIDIA
	// drivers HardyOS had installed before; install them again.
	ReinstallNeeded *Reinstall `json:"reinstallNeeded,omitempty"`
}

// Skip records who chose to update without the NVIDIA drivers, and when.
type Skip struct {
	By string    `json:"by"`
	At time.Time `json:"at"`
}

// Reinstall says which drivers an update left out and why.
type Reinstall struct {
	Driver bool      `json:"driver"` // Debian's NVIDIA driver for Docker apps
	VGPU   bool      `json:"vgpu"`   // NVIDIA's vGPU host driver
	By     string    `json:"by"`
	At     time.Time `json:"at"`
	Reason string    `json:"reason"`
}

// Consent records who agreed to NVIDIA's licence, and what was installed.
type Consent struct {
	By            string    `json:"by"`
	At            time.Time `json:"at"`
	LicenceSHA256 string    `json:"licenceSha256"`
	// Version is the driver version the licence came with: the agreement
	// covers that version only (an update offering another one asks again).
	Version  string   `json:"version"`
	Packages []string `json:"packages"`
	// Versions are the exact package versions installed (pkg=version).
	Versions map[string]string `json:"versions,omitempty"`
	// Installed is set once the packages are in.
	Installed bool `json:"installed"`
}

// Licence is NVIDIA's licence text as shipped in the packages about to be
// installed (from the downloaded package itself).
type Licence struct {
	SHA256   string   `json:"sha256"`
	Version  string   `json:"version"`
	Packages []string `json:"packages"`
	// Versions: the exact version of each package downloaded, the ones
	// installed after the agreement (from the download, never fetched again).
	Versions map[string]string `json:"versions,omitempty"`
	Prepared time.Time         `json:"prepared"`
	Source   string            `json:"source"` // the file it came from
}

// VGPUDriver is the admin's NVIDIA vGPU host driver.
type VGPUDriver struct {
	File    string    `json:"file"` // NVIDIA-Linux-x86_64-<ver>-vgpu-kvm.run, in Dir/vgpu
	SHA256  string    `json:"sha256"`
	Version string    `json:"version"`
	By      string    `json:"by"`
	At      time.Time `json:"at"`
	// Installed is set once it's built and installed.
	Installed bool `json:"installed"`
}

func (m *Manager) stateFile() string { return m.path(filepath.Join(Dir, "state.json")) }

// ensureDir creates root's directory, 0700, and refuses one that isn't a
// plain directory of root's (only checked when running as root).
func (m *Manager) ensureDir(sub string) (string, error) {
	d := m.path(filepath.Join(Dir, sub))
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	_ = os.Chmod(m.path(Dir), 0o700)
	fi, err := os.Lstat(m.path(Dir))
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("%s isn't a directory", Dir)
	}
	if os.Geteuid() == 0 {
		if err := ownedByRoot(fi); err != nil {
			return "", err
		}
	}
	return d, nil
}

func (m *Manager) load() (*Record, error) {
	var r Record
	b, err := os.ReadFile(m.stateFile())
	if errors.Is(err, os.ErrNotExist) {
		return &r, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("parse %s: %w", m.stateFile(), err)
	}
	return &r, nil
}

func (m *Manager) save(r *Record) error {
	if _, err := m.ensureDir(""); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return rootfile.WriteAtomic(m.stateFile(), append(b, '\n'), 0o600)
}

// Status is what the NVIDIA setup card shows.
type Status struct {
	// NVIDIAGPUs counts NVIDIA graphics cards in the server.
	NVIDIAGPUs int `json:"nvidiaGpus"`
	// Installed: Debian's NVIDIA driver package is installed.
	Installed bool `json:"installed"`
	// Loaded and Version: the nvidia kernel module running now.
	Loaded  bool   `json:"loaded"`
	Version string `json:"version"`
	// Toolkit: NVIDIA's container toolkit is installed (Docker apps).
	Toolkit bool `json:"toolkit"`
	// Nouveau: the basic open-source driver is loaded (a restart after
	// installing switches to NVIDIA's).
	Nouveau       bool `json:"nouveau"`
	RestartNeeded bool `json:"restartNeeded"`
	// Packages HardyOS installs.
	Packages []string    `json:"packages"`
	Consent  *Consent    `json:"consent"`
	Licence  *Licence    `json:"licence"`
	VGPU     *VGPUDriver `json:"vgpu"`
	// VGPUHostDriver: NVIDIA's vGPU host driver is loaded.
	VGPUHostDriver bool  `json:"vgpuHostDriver"`
	Task           *Task `json:"task"`
	// SkipNextUpdate and ReinstallNeeded: see Record.
	SkipNextUpdate  *Skip      `json:"skipNextUpdate"`
	ReinstallNeeded *Reinstall `json:"reinstallNeeded"`
}

// Status reports the drivers.
func (m *Manager) Status(ctx context.Context) (*Status, error) {
	r, err := m.load()
	if err != nil {
		return nil, err
	}
	st := &Status{Packages: DriverPackages, Consent: r.Driver, Licence: r.Licence, VGPU: r.VGPU, SkipNextUpdate: r.SkipNextUpdate, ReinstallNeeded: r.ReinstallNeeded}
	st.NVIDIAGPUs = m.nvidiaGPUs()
	st.Installed = m.packageInstalled(ctx, "nvidia-kernel-dkms")
	st.Version = readTrim(m.path("/sys/module/nvidia/version"))
	st.Loaded = st.Version != ""
	st.Nouveau = exists(m.path("/sys/module/nouveau"))
	st.Toolkit = exists(m.path("/usr/bin/nvidia-ctk")) || exists(m.path("/usr/bin/nvidia-container-runtime-hook"))
	st.VGPUHostDriver = exists(m.path("/sys/module/nvidia_vgpu_vfio"))
	st.RestartNeeded = (st.Installed && !st.Loaded && st.NVIDIAGPUs > 0) || (r.VGPU != nil && r.VGPU.Installed && !st.VGPUHostDriver)
	st.Task = m.Task()
	return st, nil
}

// LicenceText returns the prepared licence text.
func (m *Manager) LicenceText() (string, *Licence, error) {
	r, err := m.load()
	if err != nil {
		return "", nil, err
	}
	if r.Licence == nil {
		return "", nil, errors.New("the licence hasn't been fetched yet")
	}
	b, err := os.ReadFile(m.path(filepath.Join(Dir, "licence-nvidia.txt")))
	if err != nil {
		return "", nil, err
	}
	return string(b), r.Licence, nil
}

func (m *Manager) nvidiaGPUs() int {
	n := 0
	entries, _ := os.ReadDir(m.path("/sys/bus/pci/devices"))
	for _, e := range entries {
		dir := m.path("/sys/bus/pci/devices/" + e.Name())
		if readTrim(dir+"/vendor") == "0x10de" && strings.HasPrefix(readTrim(dir+"/class"), "0x03") && !exists(dir+"/physfn") {
			n++
		}
	}
	return n
}

func (m *Manager) packageInstalled(ctx context.Context, pkg string) bool {
	if m.Runner == nil {
		return false
	}
	res, err := m.Runner.Run(ctx, nil, "dpkg-query", "-W", "-f=${db:Status-Status}", pkg)
	return err == nil && res.ExitCode == 0 && strings.TrimSpace(string(res.Stdout)) == "installed"
}

func readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}
