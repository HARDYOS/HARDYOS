package vms

// Templates are the starting points the New VM wizard offers. They're data:
// sensible hardware for each kind of guest, presets in plain words, and
// where to get an installer. hardyd serves them to the web desktop as-is.

// Template is one starting point.
type Template struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Summary string `json:"summary"`
	// Group: windows, linux, gaming, appliance, other.
	Group string `json:"group"`
	OS    string `json:"os"`
	// Install: iso (boot an installer), image (import a disk image) or
	// cloud (a Linux cloud image set up with cloud-init).
	Install  string   `json:"install"`
	Firmware Firmware `json:"firmware"`
	DiskBus  string   `json:"diskBus"`
	NICModel string   `json:"nicModel"`
	// NICs is how many network cards to add (routers want two).
	NICs int `json:"nics"`
	// AllowSpoofing turns the home network's anti-spoofing filter off for
	// the template's cards (routers forward other computers' traffic).
	AllowSpoofing bool   `json:"allowSpoofing"`
	Video         string `json:"video"`
	// Virtio attaches the VirtIO drivers disc (Windows).
	Virtio    bool `json:"virtio"`
	CloudInit bool `json:"cloudInit"`
	Balloon   bool `json:"balloon"`
	// GPU: the template is meant for a passed-through GPU.
	GPU           bool     `json:"gpu"`
	Presets       []Preset `json:"presets"`
	DefaultPreset string   `json:"defaultPreset"`
	MinMemoryMB   int      `json:"minMemoryMB"`
	MinDiskGB     int      `json:"minDiskGB"`
	// Images are suggested downloads, per architecture (ArchInfo.Arch).
	Images []Image `json:"images"`
	// Notes are tips shown in the wizard.
	Notes []string `json:"notes"`
}

// Preset is a named size.
type Preset struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Summary  string `json:"summary"`
	Cores    int    `json:"cores"`
	Threads  int    `json:"threads"`
	MemoryMB int    `json:"memoryMB"`
	DiskGB   int    `json:"diskGB"`
}

// Image is a suggested installer or disk image.
type Image struct {
	Name string `json:"name"`
	// Kind: iso or disk.
	Kind string `json:"kind"`
	// URLs per architecture; a missing architecture isn't offered there.
	URLs map[string]string `json:"urls"`
	// Page is where to get it by hand (Windows can't be downloaded by link).
	Page string `json:"page,omitempty"`
}

func presets(light, standard, power Preset) []Preset {
	light.ID, light.Name = "light", "Light"
	standard.ID, standard.Name = "standard", "Standard"
	power.ID, power.Name = "power", "Power"
	return []Preset{light, standard, power}
}

var windowsNotes = []string{
	"Get the Windows installer (.iso) from Microsoft and put it in the ISOs shared folder, or paste a download link.",
	"When Windows Setup asks where to install and shows no disk, choose Load driver and open the VirtIO drivers disc (vioscsi folder). After Windows starts, run virtio-win-guest-tools.exe from the same disc.",
}

// Templates is the list the wizard shows, in order.
var Templates = []Template{
	{
		ID: "windows11", Name: "Windows 11", Summary: "With Secure Boot and a TPM, as Windows 11 requires.",
		Group: "windows", OS: "windows", Install: "iso",
		Firmware: Firmware{Type: FirmwareUEFI, SecureBoot: true, TPM: true},
		DiskBus:  BusVirtioSCSI, NICModel: "virtio", NICs: 1, Video: "vga", Virtio: true, Balloon: true,
		Presets: presets(
			Preset{Summary: "Office work and browsing", Cores: 2, Threads: 1, MemoryMB: 4096, DiskGB: 64},
			Preset{Summary: "Everyday use", Cores: 4, Threads: 1, MemoryMB: 8192, DiskGB: 96},
			Preset{Summary: "Heavy apps", Cores: 8, Threads: 1, MemoryMB: 16384, DiskGB: 160},
		),
		DefaultPreset: "standard", MinMemoryMB: 4096, MinDiskGB: 64,
		Images: []Image{{Name: "Windows 11", Kind: "iso", Page: "https://www.microsoft.com/software-download/windows11"}},
		Notes:  windowsNotes,
	},
	{
		ID: "windows10", Name: "Windows 10", Summary: "For older software that needs Windows 10.",
		Group: "windows", OS: "windows", Install: "iso",
		Firmware: Firmware{Type: FirmwareUEFI},
		DiskBus:  BusVirtioSCSI, NICModel: "virtio", NICs: 1, Video: "vga", Virtio: true, Balloon: true,
		Presets: presets(
			Preset{Summary: "Office work and browsing", Cores: 2, Threads: 1, MemoryMB: 4096, DiskGB: 64},
			Preset{Summary: "Everyday use", Cores: 4, Threads: 1, MemoryMB: 8192, DiskGB: 96},
			Preset{Summary: "Heavy apps", Cores: 8, Threads: 1, MemoryMB: 16384, DiskGB: 160},
		),
		DefaultPreset: "standard", MinMemoryMB: 2048, MinDiskGB: 32,
		Images: []Image{{Name: "Windows 10", Kind: "iso", Page: "https://www.microsoft.com/software-download/windows10"}},
		Notes:  windowsNotes,
	},
	{
		ID: "linux", Name: "Linux server", Summary: "Ubuntu or Debian, ready in a minute with your SSH key (cloud-init).",
		Group: "linux", OS: "linux", Install: "cloud",
		Firmware: Firmware{Type: FirmwareUEFI},
		DiskBus:  BusVirtioSCSI, NICModel: "virtio", NICs: 1, Video: "virtio", CloudInit: true, Balloon: true,
		Presets: presets(
			Preset{Summary: "Small services, a DNS server", Cores: 1, Threads: 1, MemoryMB: 1024, DiskGB: 16},
			Preset{Summary: "Web apps and databases", Cores: 2, Threads: 1, MemoryMB: 4096, DiskGB: 32},
			Preset{Summary: "Build servers, big databases", Cores: 8, Threads: 1, MemoryMB: 16384, DiskGB: 128},
		),
		DefaultPreset: "standard", MinMemoryMB: 512, MinDiskGB: 8,
		Images: []Image{
			{Name: "Ubuntu Server 24.04 LTS (cloud image)", Kind: "disk", URLs: map[string]string{
				"x86_64":  "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
				"aarch64": "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img",
			}},
			{Name: "Debian 13 (cloud image)", Kind: "disk", URLs: map[string]string{
				"x86_64":  "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2",
				"aarch64": "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-arm64.qcow2",
			}},
		},
		Notes: []string{"Cloud images start set up: sign in over SSH with the key you give (or the password) as the user you choose."},
	},
	{
		ID: "linux-iso", Name: "Linux from an installer", Summary: "Any Linux distribution from its .iso, desktop or server.",
		Group: "linux", OS: "linux", Install: "iso",
		Firmware: Firmware{Type: FirmwareUEFI},
		DiskBus:  BusVirtioSCSI, NICModel: "virtio", NICs: 1, Video: "virtio", Balloon: true,
		Presets: presets(
			Preset{Summary: "Servers", Cores: 2, Threads: 1, MemoryMB: 2048, DiskGB: 32},
			Preset{Summary: "Desktops", Cores: 4, Threads: 1, MemoryMB: 8192, DiskGB: 64},
			Preset{Summary: "Heavy desktops", Cores: 8, Threads: 1, MemoryMB: 16384, DiskGB: 128},
		),
		DefaultPreset: "standard", MinMemoryMB: 512, MinDiskGB: 8,
		Images: []Image{
			{Name: "Ubuntu Desktop 24.04 LTS", Kind: "iso", Page: "https://ubuntu.com/download/desktop"},
			{Name: "Debian 13", Kind: "iso", Page: "https://www.debian.org/download"},
		},
	},
	{
		ID: "gaming", Name: "Gaming PC", Summary: "Windows 11 with a graphics card, streamed with Moonlight.",
		Group: "gaming", OS: "windows", Install: "iso",
		Firmware: Firmware{Type: FirmwareUEFI, SecureBoot: true, TPM: true},
		DiskBus:  BusVirtioSCSI, NICModel: "virtio", NICs: 1, Video: "vga", Virtio: true, GPU: true,
		Presets: presets(
			Preset{Summary: "Indie and older games", Cores: 4, Threads: 2, MemoryMB: 8192, DiskGB: 128},
			Preset{Summary: "Most games", Cores: 6, Threads: 2, MemoryMB: 16384, DiskGB: 256},
			Preset{Summary: "New big games", Cores: 8, Threads: 2, MemoryMB: 32768, DiskGB: 512},
		),
		DefaultPreset: "standard", MinMemoryMB: 8192, MinDiskGB: 96,
		Images: []Image{{Name: "Windows 11", Kind: "iso", Page: "https://www.microsoft.com/software-download/windows11"}},
		Notes: append([]string{
			"Add your graphics card in the Devices step. While the VM is off, the card goes back to Docker apps.",
			"Install Sunshine in Windows, then play from any device with Moonlight (see Game streaming on the VM's page).",
		}, windowsNotes...),
	},
	{
		ID: "haos", Name: "Home Assistant OS", Summary: "Home automation, from the official disk image.",
		Group: "appliance", OS: "linux", Install: "image",
		Firmware: Firmware{Type: FirmwareUEFI},
		DiskBus:  BusVirtioSCSI, NICModel: "virtio", NICs: 1, Video: "virtio",
		Presets: presets(
			Preset{Summary: "A few devices", Cores: 2, Threads: 1, MemoryMB: 2048, DiskGB: 32},
			Preset{Summary: "Most homes", Cores: 2, Threads: 1, MemoryMB: 4096, DiskGB: 64},
			Preset{Summary: "Many add-ons and cameras", Cores: 4, Threads: 1, MemoryMB: 8192, DiskGB: 128},
		),
		DefaultPreset: "standard", MinMemoryMB: 2048, MinDiskGB: 32,
		Images: []Image{{Name: "Home Assistant OS 16.2", Kind: "disk", Page: "https://www.home-assistant.io/installation/linux", URLs: map[string]string{
			"x86_64":  "https://github.com/home-assistant/operating-system/releases/download/16.2/haos_ova-16.2.qcow2.xz",
			"aarch64": "https://github.com/home-assistant/operating-system/releases/download/16.2/haos_generic-aarch64-16.2.qcow2.xz",
		}}},
		Notes: []string{"Home Assistant opens at http://<the VM's address>:8123 a few minutes after the first start. Zigbee or Z-Wave sticks can be added in the Devices step."},
	},
	{
		ID: "opnsense", Name: "OPNsense or pfSense", Summary: "A firewall and router, with a WAN and a LAN port.",
		Group: "appliance", OS: "other", Install: "iso",
		Firmware: Firmware{Type: FirmwareUEFI},
		DiskBus:  BusVirtioSCSI, NICModel: "virtio", NICs: 2, AllowSpoofing: true, Video: "vga",
		Presets: presets(
			Preset{Summary: "Home internet up to 1 Gbit/s", Cores: 2, Threads: 1, MemoryMB: 2048, DiskGB: 16},
			Preset{Summary: "With VPNs and intrusion detection", Cores: 4, Threads: 1, MemoryMB: 4096, DiskGB: 32},
			Preset{Summary: "Multi-gigabit", Cores: 8, Threads: 1, MemoryMB: 8192, DiskGB: 32},
		),
		DefaultPreset: "standard", MinMemoryMB: 1024, MinDiskGB: 8,
		Images: []Image{
			{Name: "OPNsense (DVD image)", Kind: "iso", Page: "https://opnsense.org/download/"},
			{Name: "pfSense CE", Kind: "iso", Page: "https://www.pfsense.org/download/"},
		},
		Notes: []string{"Put the WAN card on its own VLAN (or pass a network port through in the Devices step) so the router sits between the internet and your network."},
	},
	{
		ID: "truenas", Name: "TrueNAS", Summary: "Another NAS inside this one, for testing or with passed-through disks.",
		Group: "appliance", OS: "linux", Install: "iso",
		Firmware: Firmware{Type: FirmwareUEFI},
		DiskBus:  BusVirtioSCSI, NICModel: "virtio", NICs: 1, Video: "vga",
		Presets: presets(
			Preset{Summary: "Testing", Cores: 2, Threads: 1, MemoryMB: 8192, DiskGB: 32},
			Preset{Summary: "Small storage", Cores: 4, Threads: 1, MemoryMB: 16384, DiskGB: 32},
			Preset{Summary: "Big storage", Cores: 8, Threads: 1, MemoryMB: 32768, DiskGB: 64},
		),
		DefaultPreset: "standard", MinMemoryMB: 8192, MinDiskGB: 16,
		Images: []Image{{Name: "TrueNAS Community Edition", Kind: "iso", Page: "https://www.truenas.com/download/"}},
		Notes:  []string{"For real data, pass a disk controller through in the Devices step instead of using virtual disks."},
	},
	{
		ID: "other", Name: "Other operating system", Summary: "Anything else, from an .iso installer.",
		Group: "other", OS: "other", Install: "iso",
		Firmware: Firmware{Type: FirmwareUEFI},
		DiskBus:  BusVirtioSCSI, NICModel: "virtio", NICs: 1, Video: "vga",
		Presets: presets(
			Preset{Summary: "Small", Cores: 1, Threads: 1, MemoryMB: 2048, DiskGB: 16},
			Preset{Summary: "Medium", Cores: 2, Threads: 1, MemoryMB: 4096, DiskGB: 32},
			Preset{Summary: "Large", Cores: 4, Threads: 1, MemoryMB: 8192, DiskGB: 64},
		),
		DefaultPreset: "standard", MinMemoryMB: 128, MinDiskGB: 1,
		Notes: []string{"If the installer doesn't see the disk, change the disk type to SATA in Hardware."},
	},
	{
		ID: "import", Name: "Import a disk image", Summary: "Bring a VM from Proxmox, VirtualBox, VMware or Hyper-V (qcow2, vmdk, vdi, vhdx, raw).",
		Group: "other", OS: "other", Install: "image",
		Firmware: Firmware{Type: FirmwareUEFI},
		DiskBus:  BusVirtioSCSI, NICModel: "virtio", NICs: 1, Video: "vga",
		Presets: presets(
			Preset{Summary: "Small", Cores: 1, Threads: 1, MemoryMB: 2048, DiskGB: 32},
			Preset{Summary: "Medium", Cores: 2, Threads: 1, MemoryMB: 4096, DiskGB: 64},
			Preset{Summary: "Large", Cores: 4, Threads: 1, MemoryMB: 8192, DiskGB: 128},
		),
		DefaultPreset: "standard", MinMemoryMB: 128, MinDiskGB: 1,
		Notes: []string{
			"Copy the image into the ISOs shared folder first, or paste a download link. The disk grows to the image's size if it's bigger.",
			"A Windows VM from another hypervisor may only start with a SATA disk until the VirtIO drivers are installed; older VMs often need BIOS firmware.",
		},
	},
}

// TemplateByID finds a template.
func TemplateByID(id string) (Template, bool) {
	for _, t := range Templates {
		if t.ID == id {
			return t, true
		}
	}
	return Template{}, false
}
