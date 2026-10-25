package hw

// GiB is 2^30 bytes.
const GiB = 1 << 30

// Capabilities is the profile features check before they appear in the UI.
type Capabilities struct {
	// Virtualization: the CPU can run VMs (VT-x / AMD-V exposed to this OS).
	Virtualization bool `json:"virtualization"`
	// PCIePassthrough: IOMMU is on, so devices can be handed to VMs.
	PCIePassthrough bool `json:"pciePassthrough"`
	// HardwareTranscode: a GPU that can accelerate video (Intel, AMD, NVIDIA).
	HardwareTranscode bool `json:"hardwareTranscode"`
	// SpecialVdev: at least two unused SSD/NVMe drives to mirror for metadata.
	SpecialVdev bool `json:"specialVdev"`
	// SLOG: at least two unused SSDs, ideally with power-loss protection.
	SLOG bool `json:"slog"`
	// L2ARC: a spare SSD and enough RAM (32 GiB+) for the read cache to help.
	L2ARC bool `json:"l2arc"`
	// ECCMemory: ECC detected (nil = unknown). Non-ECC only triggers an advisory.
	ECCMemory *bool `json:"eccMemory"`
	// ARCMaxBytes: suggested ZFS ARC limit, leaving room for apps and VMs.
	ARCMaxBytes uint64 `json:"arcMaxBytes"`
	// Advisories are one-line notes for the user ("Enable IOMMU in BIOS to ...").
	Advisories []string `json:"advisories"`
}

// Profile derives capabilities from detected hardware.
func Profile(sys System, disks []Disk) Capabilities {
	c := Capabilities{Advisories: []string{}, ECCMemory: sys.Memory.ECC}
	c.Virtualization = sys.CPU.Virtualization != ""
	c.PCIePassthrough = sys.IOMMUEnabled && c.Virtualization
	for _, g := range sys.GPUs {
		if g.Vendor == "intel" || g.Vendor == "amd" || g.Vendor == "nvidia" {
			c.HardwareTranscode = true
		}
	}

	var freeFlash, freeFlashPLP int
	for _, d := range disks {
		if !d.Usage.Usable() || d.Removable || d.Kind == KindHDD {
			continue
		}
		freeFlash++
		if d.PowerLossProt != nil && *d.PowerLossProt {
			freeFlashPLP++
		}
	}
	ram := sys.Memory.TotalBytes
	c.SpecialVdev = freeFlash >= 2
	c.SLOG = freeFlash >= 2
	c.L2ARC = freeFlash >= 1 && ram >= 32*GiB
	c.ARCMaxBytes = suggestARC(ram)

	if !c.Virtualization {
		c.Advisories = append(c.Advisories, "Virtualization (VT-x / AMD-V) is off or unsupported, so virtual machines are unavailable. Enable it in the BIOS if the CPU supports it.")
	} else if !sys.IOMMUEnabled {
		c.Advisories = append(c.Advisories, "IOMMU (VT-d / AMD-Vi) is off, so PCIe passthrough to VMs is unavailable. Enable it in the BIOS to pass GPUs or controllers to VMs.")
	}
	if c.SLOG && freeFlashPLP < 2 {
		c.Advisories = append(c.Advisories, "The spare SSDs don't report power-loss protection. They still work as a log (SLOG) device, but drives with power-loss protection are safer for that role.")
	}
	if sys.Memory.ECC != nil && !*sys.Memory.ECC {
		c.Advisories = append(c.Advisories, "ECC memory wasn't detected. HardyOS works fine without it; ECC adds protection against rare memory errors.")
	}
	if ram > 0 && ram < 8*GiB {
		c.Advisories = append(c.Advisories, "Less than 8 GB of RAM: ZFS and the built-in apps will be slow. 16 GB or more is recommended.")
	}
	return c
}

// suggestARC leaves at least 4 GiB (or a quarter of RAM, whichever is more)
// for the OS, apps and VMs, and caps the ARC at three quarters of RAM.
func suggestARC(ram uint64) uint64 {
	if ram == 0 {
		return 0
	}
	reserve := ram / 4
	if reserve < 4*GiB {
		reserve = 4 * GiB
	}
	if ram <= reserve {
		return ram / 2
	}
	return ram - reserve
}
