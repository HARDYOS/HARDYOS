package hw

import (
	"bufio"
	"bytes"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
)

// CPU describes the processor.
type CPU struct {
	Model          string `json:"model"`
	Vendor         string `json:"vendor"`
	Threads        int    `json:"threads"`
	Virtualization string `json:"virtualization"` // "vt-x", "amd-v" or ""
}

// Memory describes installed RAM.
type Memory struct {
	TotalBytes uint64 `json:"totalBytes"`
	// ECC is true when an ECC memory controller driver (EDAC) is active,
	// false when none is, and nil when it can't be determined.
	ECC *bool `json:"ecc"`
}

// PCIDevice is a PCI device relevant to HardyOS (GPUs, for passthrough and acceleration).
type PCIDevice struct {
	Address    string `json:"address"` // 0000:01:00.0
	Class      string `json:"class"`   // 0x030000
	VendorID   string `json:"vendorId"`
	DeviceID   string `json:"deviceId"`
	Vendor     string `json:"vendor"` // intel, amd, nvidia, other
	Driver     string `json:"driver"`
	IOMMUGroup *int   `json:"iommuGroup"`
}

// NIC is a physical network interface.
type NIC struct {
	Name      string `json:"name"`
	MAC       string `json:"mac"`
	SpeedMbps int    `json:"speedMbps"` // -1 or 0 when the link is down or unknown
	Up        bool   `json:"up"`
	Driver    string `json:"driver"`
}

// System is everything detected apart from disks.
type System struct {
	CPU          CPU         `json:"cpu"`
	Memory       Memory      `json:"memory"`
	GPUs         []PCIDevice `json:"gpus"`
	NICs         []NIC       `json:"nics"`
	IOMMUEnabled bool        `json:"iommuEnabled"`
	IOMMUGroups  int         `json:"iommuGroups"`
	Virtual      bool        `json:"virtual"` // running inside a VM
}

// ReadSystem collects CPU, memory, GPU, NIC and IOMMU details from /proc and
// /sys under root (a filesystem rooted at "/").
func ReadSystem(root fs.FS) System {
	s := System{GPUs: []PCIDevice{}, NICs: []NIC{}}
	s.CPU, s.Virtual = readCPU(root)
	s.Memory = readMemory(root)
	groups, _ := fs.ReadDir(root, "sys/kernel/iommu_groups")
	s.IOMMUGroups = len(groups)
	s.IOMMUEnabled = len(groups) > 0
	s.GPUs = readGPUs(root)
	s.NICs = readNICs(root)
	return s
}

func readCPU(root fs.FS) (CPU, bool) {
	var c CPU
	virtual := false
	data, err := fs.ReadFile(root, "proc/cpuinfo")
	if err != nil {
		return c, false
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "processor":
			c.Threads++
		case "model name":
			if c.Model == "" {
				c.Model = v
			}
		case "vendor_id":
			if c.Vendor == "" {
				c.Vendor = v
			}
		case "flags":
			if c.Virtualization != "" {
				continue
			}
			for _, f := range strings.Fields(v) {
				switch f {
				case "vmx":
					c.Virtualization = "vt-x"
				case "svm":
					c.Virtualization = "amd-v"
				case "hypervisor":
					virtual = true
				}
			}
		}
	}
	return c, virtual
}

func readMemory(root fs.FS) Memory {
	var m Memory
	if data, err := fs.ReadFile(root, "proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if rest, ok := strings.CutPrefix(line, "MemTotal:"); ok {
				f := strings.Fields(rest)
				if len(f) > 0 {
					kb, _ := strconv.ParseUint(f[0], 10, 64)
					m.TotalBytes = kb * 1024
				}
			}
		}
	}
	if _, err := fs.Stat(root, "sys/devices/system/edac/mc/mc0"); err == nil {
		t := true
		m.ECC = &t
	} else if _, err := fs.Stat(root, "sys/devices/system/edac/mc"); err == nil {
		f := false
		m.ECC = &f
	}
	return m
}

func readGPUs(root fs.FS) []PCIDevice {
	out := []PCIDevice{}
	entries, err := fs.ReadDir(root, "sys/bus/pci/devices")
	if err != nil {
		return out
	}
	for _, e := range entries {
		dir := path.Join("sys/bus/pci/devices", e.Name())
		class := readTrim(root, path.Join(dir, "class"))
		if !strings.HasPrefix(class, "0x03") { // display controllers
			continue
		}
		d := PCIDevice{
			Address:  e.Name(),
			Class:    class,
			VendorID: readTrim(root, path.Join(dir, "vendor")),
			DeviceID: readTrim(root, path.Join(dir, "device")),
		}
		switch d.VendorID {
		case "0x8086":
			d.Vendor = "intel"
		case "0x1002":
			d.Vendor = "amd"
		case "0x10de":
			d.Vendor = "nvidia"
		default:
			d.Vendor = "other"
		}
		if target, err := fs.ReadLink(root, path.Join(dir, "driver")); err == nil {
			d.Driver = path.Base(target)
		}
		if target, err := fs.ReadLink(root, path.Join(dir, "iommu_group")); err == nil {
			if g, err := strconv.Atoi(path.Base(target)); err == nil {
				d.IOMMUGroup = &g
			}
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}

func readNICs(root fs.FS) []NIC {
	out := []NIC{}
	entries, err := fs.ReadDir(root, "sys/class/net")
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		dir := path.Join("sys/class/net", name)
		// Physical NICs have a backing device; bridges, bonds, veths and lo don't.
		if _, err := fs.Stat(root, path.Join(dir, "device")); err != nil {
			continue
		}
		n := NIC{Name: name, MAC: readTrim(root, path.Join(dir, "address"))}
		n.Up = readTrim(root, path.Join(dir, "operstate")) == "up"
		if sp, err := strconv.Atoi(readTrim(root, path.Join(dir, "speed"))); err == nil {
			n.SpeedMbps = sp
		}
		if target, err := fs.ReadLink(root, path.Join(dir, "device", "driver")); err == nil {
			n.Driver = path.Base(target)
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func readTrim(root fs.FS, p string) string {
	b, err := fs.ReadFile(root, p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
