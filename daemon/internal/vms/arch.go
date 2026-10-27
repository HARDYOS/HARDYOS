package vms

import "runtime"

// ArchInfo is what the domain XML needs to know about the server's CPU
// architecture. HardyOS's code is architecture-neutral (decision 2): the
// differences between architectures are data, chosen at run time.
type ArchInfo struct {
	// Arch is libvirt's name (x86_64, aarch64).
	Arch string `json:"arch"`
	// Machine is the default machine type (q35, virt).
	Machine string `json:"machine"`
	// SATA: the machine has an AHCI controller for SATA disks and drives.
	SATA bool `json:"sata"`
	// CDBus is the bus for CD/DVD drives.
	CDBus string `json:"cdBus"`
	// TPMModel is the TPM device (tpm-crb, tpm-tis-device).
	TPMModel string `json:"tpmModel"`
	// HyperV: Hyper-V enlightenments for Windows guests exist.
	HyperV bool `json:"hyperV"`
	// SMM: Secure Boot needs System Management Mode on this machine.
	SMM bool `json:"smm"`
	// VMPort: the VMware backdoor port exists (and is turned off).
	VMPort bool `json:"vmport"`
	// LegacyBIOS: a BIOS (SeaBIOS) firmware exists besides UEFI.
	LegacyBIOS bool `json:"legacyBios"`
	// PIT and RTC timers exist (x86 clock tuning).
	PIT bool `json:"pit"`
}

// archTable maps Go's GOARCH to libvirt's view of it.
var archTable = map[string]ArchInfo{
	"amd64": {Arch: "x86_64", Machine: "q35", SATA: true, CDBus: "sata", TPMModel: "tpm-crb", HyperV: true, SMM: true, VMPort: true, LegacyBIOS: true, PIT: true},
	"arm64": {Arch: "aarch64", Machine: "virt", CDBus: "scsi", TPMModel: "tpm-tis-device"},
}

// HostArch is the running server's architecture (false when VMs aren't
// supported on it).
func HostArch() (ArchInfo, bool) { return ArchFor(runtime.GOARCH) }

// ArchFor looks up a GOARCH.
func ArchFor(goarch string) (ArchInfo, bool) {
	a, ok := archTable[goarch]
	return a, ok
}
