// Package vms runs virtual machines with QEMU/KVM through libvirt. It runs
// inside hardyd-priv. See docs/plans/vms.md section 1 and docs/vms.md.
//
// HardyOS never takes libvirt XML from hardyd: a VM is a Spec, checked here,
// and the domain XML is built from it (xml.go). Each VM lives on one pool:
//
//	<pool>/vms/<id>             filesystem, root only: vm.json (the spec),
//	                            nvram.fd, tpm/ (saved TPM state), cloud-init seed
//	<pool>/vms/<id>/<disk>      a zvol per disk
//
// so a recursive ZFS snapshot of <pool>/vms/<id> holds the whole VM.
package vms

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/devices"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// Spec describes one virtual machine. It's what hardyd sends and what's kept
// in vm.json on the VM's dataset.
type Spec struct {
	// ID is the VM's short name: libvirt's domain name and its datasets.
	ID string `json:"id"`
	// Name is the display name.
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Template is the template the VM was made from (templates.go).
	Template string `json:"template"`
	// OS family: windows, linux or other (drives clock and enlightenments).
	OS string `json:"os"`
	// Pool keeps the VM's disks and state.
	Pool string `json:"pool"`
	// UUID is libvirt's; set when the VM is created.
	UUID string `json:"uuid,omitempty"`

	CPU      CPU      `json:"cpu"`
	Memory   Memory   `json:"memory"`
	Firmware Firmware `json:"firmware"`
	Disks    []Disk   `json:"disks"`
	Media    []Media  `json:"media"`
	NICs     []NIC    `json:"nics"`
	// Video is the emulated display: virtio, vga, bochs or none (a GPU
	// that is the VM's main display).
	Video string `json:"video"`
	// GuestAgent adds the QEMU guest agent channel (shutdown, addresses,
	// file-system freeze for snapshots).
	GuestAgent bool              `json:"guestAgent"`
	CloudInit  *CloudInit        `json:"cloudInit,omitempty"`
	Boot       []string          `json:"boot"` // order of disk, cdrom, network
	Autostart  Autostart         `json:"autostart"`
	Devices    []devices.Device  `json:"devices"`
	Streaming  *Streaming        `json:"streaming,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// CPU is the VM's processor.
type CPU struct {
	// Cores per VM; Threads per core (1 or 2). vCPUs = Cores * Threads.
	Cores   int `json:"cores"`
	Threads int `json:"threads"`
}

// VCPUs is the number of virtual CPUs.
func (c CPU) VCPUs() int { return c.Cores * max(c.Threads, 1) }

// Memory is the VM's RAM.
type Memory struct {
	MB int `json:"mb"`
	// Balloon lets the guest give unused memory back (virtio-balloon with
	// free page reporting) and report its use.
	Balloon bool `json:"balloon"`
}

// Firmware is how the VM boots.
type Firmware struct {
	// Type is uefi (default) or bios.
	Type       string `json:"type"`
	SecureBoot bool   `json:"secureBoot"`
	TPM        bool   `json:"tpm"`
}

// Disk is one virtual disk: a zvol <pool>/vms/<vm>/<name>.
type Disk struct {
	Name   string `json:"name"` // disk0, disk1, …
	SizeGB int    `json:"sizeGB"`
	// Bus: virtio-scsi (default), virtio-blk or sata (appliances and
	// installers without VirtIO drivers).
	Bus string `json:"bus"`
	// Import fills the disk from an image when the VM is created.
	Import *Import `json:"import,omitempty"`
}

// Import names a disk image to copy into a new disk: a file in the ISOs
// shared folder (qcow2, raw, vmdk, vdi, vhdx, or one of those .xz
// compressed).
type Import struct {
	File string `json:"file"`
}

// Media is a CD/DVD drive.
type Media struct {
	// Kind: iso (a file in the ISOs shared folder), virtio (the VirtIO
	// drivers disc for Windows), cloudinit (the generated seed) or empty
	// (a drive with nothing in it).
	Kind string `json:"kind"`
	ISO  string `json:"iso,omitempty"`
}

// NIC is a network card.
type NIC struct {
	// Mode: bridge (on the home network, the default), nat (behind the
	// server) or vlan (a VLAN on the home network's bridge).
	Mode  string `json:"mode"`
	VLAN  int    `json:"vlan,omitempty"`
	Model string `json:"model"` // virtio or e1000e
	MAC   string `json:"mac,omitempty"`
	// AllowSpoofing turns off the filter that keeps a card on the home
	// network to its own MAC and IP addresses (libvirt's clean-traffic).
	// Routers and firewalls (OPNsense) need it off; everything else
	// should keep it.
	AllowSpoofing bool `json:"allowSpoofing,omitempty"`
}

// CloudInit sets up a Linux cloud image on first boot.
type CloudInit struct {
	User     string   `json:"user"`
	SSHKeys  []string `json:"sshKeys"`
	Hostname string   `json:"hostname,omitempty"`
	// PasswordHash is a crypt(3) SHA-512 hash; hardyd sends a password
	// (CreateArgs.Password), never stored, and root hashes it.
	PasswordHash string `json:"passwordHash,omitempty"`
	// InstallAgent installs and starts qemu-guest-agent on first boot.
	InstallAgent bool `json:"installAgent"`
}

// Autostart starts the VM when the server starts.
type Autostart struct {
	Enabled bool `json:"enabled"`
	// Order: lower starts first.
	Order int `json:"order"`
	// DelaySec waits this long after starting this VM before the next.
	DelaySec int `json:"delaySec"`
}

// Streaming is the game streaming (Moonlight/Sunshine) panel's settings.
type Streaming struct {
	// Remote publishes Sunshine's ports through the VPN (needs the remote
	// access part; recorded here, applied by it).
	Remote bool `json:"remote"`
}

// Limits.
const (
	MaxDisks      = 8
	MaxMedia      = 4
	MaxNICs       = 8
	MaxDevices    = 16
	MaxDiskGB     = 64 << 10 // 64 TiB
	MaxMemoryMB   = 4 << 20  // 4 TiB
	MinMemoryMB   = 128
	MaxCores      = 256
	MaxSSHKeys    = 16
	MaxDescLength = 500
)

// Allowed values.
var (
	OSFamilies   = []string{"windows", "linux", "other"}
	DiskBuses    = []string{BusVirtioSCSI, BusVirtioBlk, BusSATA}
	NICModels    = []string{"virtio", "e1000e"}
	NICModes     = []string{NICBridge, NICNAT, NICVLAN}
	VideoModels  = []string{"virtio", "vga", "bochs", "none"}
	MediaKinds   = []string{MediaISO, MediaVirtio, MediaCloudInit, MediaEmpty}
	BootDevices  = []string{"disk", "cdrom", "network"}
	FirmwareKind = []string{FirmwareUEFI, FirmwareBIOS}
)

// Names of values.
const (
	BusVirtioSCSI  = "virtio-scsi"
	BusVirtioBlk   = "virtio-blk"
	BusSATA        = "sata"
	NICBridge      = "bridge"
	NICNAT         = "nat"
	NICVLAN        = "vlan"
	MediaISO       = "iso"
	MediaVirtio    = "virtio"
	MediaCloudInit = "cloudinit"
	MediaEmpty     = "empty"
	FirmwareUEFI   = "uefi"
	FirmwareBIOS   = "bios"
)

var (
	idRE       = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)
	diskNameRE = regexp.MustCompile(`^disk[0-9]$`)
	macRE      = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
	uuidRE     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	userRE     = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)
	hostRE     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	// ISO library file names: no paths, no leading dot, a known extension.
	fileRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()+,-]{0,199}$`)
	sshRE  = regexp.MustCompile(`^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com) [A-Za-z0-9+/=]{16,}( [^\x00-\x1f\x7f]{0,200})?$`)
	// cryptRE: SHA-512 crypt only.
	cryptRE    = regexp.MustCompile(`^\$6\$(rounds=[0-9]{4,9}\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$`)
	labelKeyRE = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,30}$`)
	pciRE      = regexp.MustCompile(`^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$`)
	usbIDRE    = regexp.MustCompile(`^([0-9a-f]{4}:[0-9a-f]{4}|[0-9]{1,3}-[0-9]{1,3}(\.[0-9]{1,3}){0,6})$`)
	vgpuTypeRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	romRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.(rom|bin)$`)
	ifnameRE   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
)

// ImageExtensions are the disk image formats an import accepts.
var ImageExtensions = []string{".qcow2", ".img", ".raw", ".vmdk", ".vdi", ".vhdx", ".qcow2.xz", ".img.xz", ".raw.xz"}

// ISOExtensions are files usable as a CD/DVD.
var ISOExtensions = []string{".iso"}

// reservedIDs are names the API uses for other things (/vms/isos…), and
// what kept disks look like.
var reservedIDs = map[string]bool{"isos": true, "templates": true, "capabilities": true, "bridge": true, "kept": true, "new": true}

// ValidID checks a VM id.
func ValidID(id string) error {
	if !idRE.MatchString(id) || strings.Contains(id, "--") || strings.Contains(id, "-kept-") {
		return fmt.Errorf("%q isn't a valid VM name: use 2-32 lowercase letters, digits and dashes, starting with a letter", id)
	}
	if reservedIDs[id] {
		return fmt.Errorf("%q is a word HardyOS keeps for itself; choose another VM name", id)
	}
	return nil
}

// ValidFile checks a file name in the ISO library.
func ValidFile(name string) error {
	if !fileRE.MatchString(name) || strings.Contains(name, "..") || strings.TrimSpace(name) != name {
		return fmt.Errorf("%q isn't a file name the ISO library accepts", name)
	}
	return nil
}

// IsISO reports whether name is a CD/DVD image.
func IsISO(name string) bool { return hasExt(name, ISOExtensions) }

// IsDiskImage reports whether name is a disk image that can be imported.
func IsDiskImage(name string) bool { return hasExt(name, ImageExtensions) }

func hasExt(name string, exts []string) bool {
	l := strings.ToLower(name)
	for _, e := range exts {
		if strings.HasSuffix(l, e) {
			return true
		}
	}
	return false
}

// Problems lists everything wrong with a request, so a form can show them all.
type Problems []string

func (p Problems) Error() string { return strings.Join(p, "; ") }

// Host is what validation needs to know about the server.
type Host struct {
	CPUs     int // logical CPUs
	MemoryMB int // total RAM
	Pools    []string
	Arch     ArchInfo // see arch.go
	// TPM and SecureBoot report whether swtpm and Secure Boot firmware
	// are installed.
	TPM        bool
	SecureBoot bool
}

// Normalize fills in defaults and tidies lists, so equal specs compare
// equal and render the same.
func (s *Spec) Normalize() {
	s.ID = strings.TrimSpace(s.ID)
	s.Name = strings.TrimSpace(s.Name)
	s.Description = strings.TrimSpace(s.Description)
	if s.Name == "" {
		s.Name = s.ID
	}
	if s.CPU.Threads == 0 {
		s.CPU.Threads = 1
	}
	if s.Firmware.Type == "" {
		s.Firmware.Type = FirmwareUEFI
	}
	if s.Video == "" {
		s.Video = "virtio"
	}
	for i := range s.Disks {
		if s.Disks[i].Name == "" {
			s.Disks[i].Name = fmt.Sprintf("disk%d", i)
		}
		if s.Disks[i].Bus == "" {
			s.Disks[i].Bus = BusVirtioSCSI
		}
	}
	for i := range s.NICs {
		s.NICs[i].MAC = strings.ToLower(strings.TrimSpace(s.NICs[i].MAC))
		if s.NICs[i].Model == "" {
			s.NICs[i].Model = "virtio"
		}
		if s.NICs[i].Mode == "" {
			s.NICs[i].Mode = NICBridge
		}
		if s.NICs[i].Mode != NICVLAN {
			s.NICs[i].VLAN = 0
		}
		if s.NICs[i].Mode == NICNAT {
			s.NICs[i].AllowSpoofing = false
		}
	}
	if s.Boot == nil {
		s.Boot = []string{"disk", "cdrom"}
	}
	if s.Devices == nil {
		s.Devices = []devices.Device{}
	}
	if s.Disks == nil {
		s.Disks = []Disk{}
	}
	if s.Media == nil {
		s.Media = []Media{}
	}
	if s.NICs == nil {
		s.NICs = []NIC{}
	}
	if s.CloudInit != nil {
		ci := s.CloudInit
		ci.User = strings.TrimSpace(ci.User)
		ci.Hostname = strings.ToLower(strings.TrimSpace(ci.Hostname))
		keys := []string{}
		for _, k := range ci.SSHKeys {
			if k = strings.TrimSpace(k); k != "" && !slices.Contains(keys, k) {
				keys = append(keys, k)
			}
		}
		ci.SSHKeys = keys
	}
}

// Validate checks s against the host. Call Normalize first.
func (s *Spec) Validate(h Host) error {
	var p Problems
	add := func(format string, a ...any) { p = append(p, fmt.Sprintf(format, a...)) }

	if err := ValidID(s.ID); err != nil {
		add("%v", err)
	}
	if len(s.Name) > 64 || strings.ContainsAny(s.Name, "\x00\n\r\t") {
		add("the display name must be at most 64 characters on one line")
	}
	if len(s.Description) > MaxDescLength || strings.ContainsRune(s.Description, 0) {
		add("the description must be at most %d characters", MaxDescLength)
	}
	if _, ok := TemplateByID(s.Template); !ok {
		add("%q isn't a VM template", s.Template)
	}
	if !slices.Contains(OSFamilies, s.OS) {
		add("the operating system must be windows, linux or other")
	}
	if s.UUID != "" && !uuidRE.MatchString(s.UUID) {
		add("the VM's UUID %q isn't valid", s.UUID)
	}
	if zfs.ValidPoolName(s.Pool) != nil || (len(h.Pools) > 0 && !slices.Contains(h.Pools, s.Pool)) {
		add("there's no pool called %q for the VM's disks", s.Pool)
	}

	// CPU and memory.
	if s.CPU.Cores < 1 || s.CPU.Cores > MaxCores {
		add("the VM needs 1 to %d CPU cores", MaxCores)
	}
	if s.CPU.Threads != 1 && s.CPU.Threads != 2 {
		add("threads per core must be 1 or 2")
	}
	if h.CPUs > 0 && s.CPU.VCPUs() > h.CPUs {
		add("the VM has %d virtual CPUs but the server only has %d", s.CPU.VCPUs(), h.CPUs)
	}
	if s.Memory.MB < MinMemoryMB || s.Memory.MB > MaxMemoryMB {
		add("memory must be between %d MB and %d GB", MinMemoryMB, MaxMemoryMB>>10)
	}
	if h.MemoryMB > 0 && s.Memory.MB > h.MemoryMB {
		add("the VM has %d MB of memory but the server only has %d MB", s.Memory.MB, h.MemoryMB)
	}

	// Firmware.
	if !slices.Contains(FirmwareKind, s.Firmware.Type) {
		add("firmware must be uefi or bios")
	}
	if s.Firmware.Type == FirmwareBIOS && !h.Arch.LegacyBIOS {
		add("this server's VMs only have UEFI firmware")
	}
	if s.Firmware.SecureBoot && s.Firmware.Type != FirmwareUEFI {
		add("Secure Boot needs UEFI firmware")
	}
	if s.Firmware.SecureBoot && !h.SecureBoot {
		add("this server has no Secure Boot firmware for VMs (the ovmf package)")
	}
	if s.Firmware.TPM && !h.TPM {
		add("this server has no virtual TPM (the swtpm package)")
	}

	// Disks.
	if len(s.Disks) > MaxDisks {
		add("at most %d disks", MaxDisks)
	}
	seen := map[string]bool{}
	for _, d := range s.Disks {
		if !diskNameRE.MatchString(d.Name) {
			add("disk name %q must be disk0 to disk9", d.Name)
		}
		if seen[d.Name] {
			add("there are two disks called %s", d.Name)
		}
		seen[d.Name] = true
		if d.SizeGB < 1 || d.SizeGB > MaxDiskGB {
			add("%s: size must be 1 GB to %d TB", d.Name, MaxDiskGB>>10)
		}
		if !slices.Contains(DiskBuses, d.Bus) {
			add("%s: the disk type must be virtio-scsi, virtio-blk or sata", d.Name)
		}
		if d.Bus == BusSATA && !h.Arch.SATA {
			add("%s: this server's VMs have no SATA controller; use virtio-scsi", d.Name)
		}
		if d.Import != nil {
			if err := ValidFile(d.Import.File); err != nil {
				add("%s: %v", d.Name, err)
			} else if !IsDiskImage(d.Import.File) {
				add("%s: %s isn't a disk image (qcow2, raw, img, vmdk, vdi or vhdx)", d.Name, d.Import.File)
			}
		}
	}

	// Media.
	if len(s.Media) > MaxMedia {
		add("at most %d CD/DVD drives", MaxMedia)
	}
	kinds := map[string]int{}
	for i, m := range s.Media {
		kinds[m.Kind]++
		switch m.Kind {
		case MediaISO:
			if err := ValidFile(m.ISO); err != nil {
				add("CD/DVD %d: %v", i+1, err)
			} else if !IsISO(m.ISO) {
				add("CD/DVD %d: %s isn't an .iso file", i+1, m.ISO)
			}
		case MediaVirtio, MediaCloudInit, MediaEmpty:
			if m.ISO != "" {
				add("CD/DVD %d: a %s drive can't name a file", i+1, m.Kind)
			}
		default:
			add("CD/DVD %d: the kind must be iso, virtio, cloudinit or empty", i+1)
		}
	}
	if kinds[MediaVirtio] > 1 || kinds[MediaCloudInit] > 1 {
		add("the drivers disc and the cloud-init disc can each be attached once")
	}
	if (kinds[MediaCloudInit] > 0) != (s.CloudInit != nil) {
		add("cloud-init settings and the cloud-init disc go together")
	}

	// Network.
	if len(s.NICs) > MaxNICs {
		add("at most %d network cards", MaxNICs)
	}
	macs := map[string]bool{}
	for i, n := range s.NICs {
		if !slices.Contains(NICModes, n.Mode) {
			add("network card %d: connect it to bridge (home network), nat or vlan", i+1)
		}
		if n.Mode == NICVLAN && (n.VLAN < 1 || n.VLAN > 4094) {
			add("network card %d: the VLAN must be 1 to 4094", i+1)
		}
		if !slices.Contains(NICModels, n.Model) {
			add("network card %d: the model must be virtio or e1000e", i+1)
		}
		if n.MAC != "" {
			if !macRE.MatchString(n.MAC) || !validMAC(n.MAC) {
				add("network card %d: %q isn't a usable MAC address", i+1, n.MAC)
			}
			if macs[n.MAC] {
				add("two network cards have the MAC address %s", n.MAC)
			}
			macs[n.MAC] = true
		}
	}

	// Display and boot.
	if !slices.Contains(VideoModels, s.Video) {
		add("the display must be virtio, vga, bochs or none")
	}
	if len(s.Boot) == 0 || len(s.Boot) > len(BootDevices) {
		add("the boot order needs disk, cdrom and/or network")
	}
	bseen := map[string]bool{}
	for _, b := range s.Boot {
		if !slices.Contains(BootDevices, b) || bseen[b] {
			add("the boot order has %q more than once or doesn't know it", b)
		}
		bseen[b] = true
	}
	if s.Autostart.Order < 0 || s.Autostart.Order > 999 {
		add("the start order must be 0 to 999")
	}
	if s.Autostart.DelaySec < 0 || s.Autostart.DelaySec > 600 {
		add("the start delay must be 0 to 600 seconds")
	}

	// Cloud-init.
	if ci := s.CloudInit; ci != nil {
		if s.OS != "linux" {
			add("cloud-init is for Linux VMs")
		}
		if !userRE.MatchString(ci.User) || ci.User == "root" {
			add("the cloud-init user name %q isn't valid (lowercase letters, digits, - and _; not root)", ci.User)
		}
		if ci.Hostname != "" && !hostRE.MatchString(ci.Hostname) {
			add("the VM's host name %q isn't valid", ci.Hostname)
		}
		if len(ci.SSHKeys) > MaxSSHKeys {
			add("at most %d SSH keys", MaxSSHKeys)
		}
		for _, k := range ci.SSHKeys {
			if !sshRE.MatchString(k) {
				add("an SSH key doesn't look like a public key (ssh-ed25519 AAAA… name)")
				break
			}
		}
		if ci.PasswordHash != "" && !cryptRE.MatchString(ci.PasswordHash) {
			add("the cloud-init password hash isn't a SHA-512 crypt hash")
		}
		if len(ci.SSHKeys) == 0 && ci.PasswordHash == "" {
			add("give the cloud-init user an SSH key or a password, or nobody can sign in")
		}
	}

	// Devices: shape only; devices.Manager.Check decides whether they can
	// be used.
	if len(s.Devices) > MaxDevices {
		add("at most %d passed-through devices", MaxDevices)
	}
	dseen := map[string]bool{}
	primary := 0
	for _, d := range s.Devices {
		switch d.Kind {
		case devices.KindPCI, devices.KindGPU, devices.KindVGPU:
			if !pciRE.MatchString(d.ID) {
				add("device %q isn't a PCI address like 0000:01:00.0", d.ID)
			}
		case devices.KindUSB:
			if !usbIDRE.MatchString(d.ID) {
				add("USB device %q must be vendor:product (1234:abcd) or a port (1-4.2)", d.ID)
			}
		default:
			add("device kind %q must be pci, usb, gpu or vgpu", d.Kind)
		}
		if d.Kind == devices.KindVGPU {
			if !vgpuTypeRE.MatchString(d.VGPUType) {
				add("vGPU %s needs a slice type", d.ID)
			}
		} else if d.VGPUType != "" {
			add("only a vGPU has a slice type")
		}
		if d.ROMFile != "" && !romRE.MatchString(d.ROMFile) {
			add("ROM file %q isn't a ROM name", d.ROMFile)
		}
		if d.Primary {
			primary++
			if d.Kind != devices.KindGPU {
				add("only a whole GPU can be the main display")
			}
		}
		key := d.Kind + ":" + d.ID
		if d.Kind != devices.KindVGPU && dseen[key] {
			add("device %s is listed twice", d.ID)
		}
		dseen[key] = true
	}
	if primary > 1 {
		add("only one GPU can be the main display")
	}
	if len(s.Labels) > 16 {
		add("at most 16 labels")
	}
	for k, v := range s.Labels {
		if !labelKeyRE.MatchString(k) || len(v) > 200 || strings.ContainsAny(v, "\x00\n") {
			add("label %q isn't valid", k)
		}
	}
	if len(p) > 0 {
		return p
	}
	return nil
}

// validMAC accepts unicast addresses only (the low bit of the first byte
// is the multicast bit).
func validMAC(mac string) bool {
	b, err := hex.DecodeString(mac[:2])
	return err == nil && b[0]&1 == 0 && mac != "00:00:00:00:00:00"
}

// NewMAC returns a random address in QEMU's 52:54:00 range.
func NewMAC() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return fmt.Sprintf("52:54:00:%02x:%02x:%02x", b[0], b[1], b[2])
}

// NewUUID returns a random version 4 UUID.
func NewUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// NeedsBridge reports whether a NIC is on the home network's bridge.
func (s *Spec) NeedsBridge() bool {
	for _, n := range s.NICs {
		if n.Mode == NICBridge || n.Mode == NICVLAN {
			return true
		}
	}
	return false
}

// NeedsVirtio reports whether the VirtIO drivers disc is attached.
func (s *Spec) NeedsVirtio() bool {
	for _, m := range s.Media {
		if m.Kind == MediaVirtio {
			return true
		}
	}
	return false
}

// HasGPU reports whether the VM gets a GPU or vGPU (game streaming panel).
func (s *Spec) HasGPU() bool {
	for _, d := range s.Devices {
		if d.Kind == devices.KindGPU || d.Kind == devices.KindVGPU {
			return true
		}
	}
	return false
}

// Files lists the ISO library files the VM uses.
func (s *Spec) Files() []string {
	var out []string
	for _, m := range s.Media {
		if m.Kind == MediaISO {
			out = append(out, m.ISO)
		}
	}
	return out
}

// Dataset is the VM's own dataset.
func Dataset(pool, id string) string { return pool + "/vms/" + id }

// DiskDataset is one disk's zvol.
func DiskDataset(pool, id, disk string) string { return Dataset(pool, id) + "/" + disk }

// ZvolPath is a zvol's block device.
func ZvolPath(pool, id, disk string) string { return "/dev/zvol/" + DiskDataset(pool, id, disk) }

// tapName is a NIC's host-side device: "hv" + 6 hex digits of the VM's
// UUID + the NIC's index. libvirt keeps "vnet" names for itself.
func tapName(uuid string, i int) string {
	h := strings.ReplaceAll(uuid, "-", "")
	if len(h) < 6 {
		h += "000000"
	}
	return fmt.Sprintf("hv%s%d", h[:6], i)
}
