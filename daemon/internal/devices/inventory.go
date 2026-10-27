package devices

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/boot"
)

// Inventory is everything the Devices view and the VM wizard show.
type Inventory struct {
	IOMMU  IOMMUState    `json:"iommu"`
	Groups []Group       `json:"groups"`
	PCI    []PCIDevice   `json:"pci"`
	USB    []USBDevice   `json:"usb"`
	GPUs   []GPU         `json:"gpus"`
	Stuck  []StuckDevice `json:"stuck"`
}

// IOMMUState says whether devices can be handed to VMs and what to do if not.
type IOMMUState struct {
	Enabled bool `json:"enabled"`
	Groups  int  `json:"groups"`
	// CPUVendor: intel, amd or other.
	CPUVendor string `json:"cpuVendor"`
	// FirmwareTable: the firmware describes an IOMMU (ACPI DMAR or IVRS),
	// so it's switched on in the BIOS.
	FirmwareTable bool `json:"firmwareTable"`
	// Flags are the kernel arguments this CPU needs for passthrough.
	Flags []string `json:"flags"`
	// Configured: the flags are in the boot configuration.
	Configured bool `json:"configured"`
	// Active: the running kernel was started with them.
	Active bool `json:"active"`
	// RestartNeeded: configured but not active yet.
	RestartNeeded bool `json:"restartNeeded"`
	// CanTurnOn: "Turn on IOMMU" has something to add.
	CanTurnOn bool `json:"canTurnOn"`
	// KernelArgs are all the extra kernel arguments configured.
	KernelArgs []string `json:"kernelArgs"`
	// Message explains the state in plain words.
	Message string `json:"message"`
}

// Group is one IOMMU group: the devices that can only go to a VM together.
type Group struct {
	ID          int      `json:"id"`
	Devices     []string `json:"devices"`
	Explanation string   `json:"explanation"`
}

// PCIDevice is one PCI function.
type PCIDevice struct {
	Address  string `json:"address"`
	VendorID string `json:"vendorId"`
	DeviceID string `json:"deviceId"`
	Vendor   string `json:"vendor"` // name from pci.ids ("" if unknown)
	Name     string `json:"name"`   // device name from pci.ids
	Class    string `json:"class"`  // 0x030000
	Kind     string `json:"kind"`   // plain words: "Graphics card"
	Driver   string `json:"driver"`
	// IOMMUGroup is nil when IOMMU is off.
	IOMMUGroup *int `json:"iommuGroup"`
	// ResetMethods: the kernel's ways to reset it (flr, pm, bus...).
	ResetMethods []string `json:"resetMethods"`
	// Resettable: it can be reset between VMs.
	Resettable bool `json:"resettable"`
	Bridge     bool `json:"bridge"`
	BootVGA    bool `json:"bootVga"`
	// PhysFn: for an SR-IOV virtual function, its parent.
	PhysFn string `json:"physFn,omitempty"`
	// Critical: why the server itself needs it ("" if it can be lent).
	Critical string `json:"critical"`
	// Owner: the VM using it now ("" for the server).
	Owner string `json:"owner"`
	// Assigned: VMs configured with it.
	Assigned []string `json:"assigned"`
}

// USBDevice is one USB device (hubs included, interfaces not).
type USBDevice struct {
	Port         string   `json:"port"` // 1-4.2
	Bus          int      `json:"bus"`
	Dev          int      `json:"dev"`
	VendorID     string   `json:"vendorId"`
	ProductID    string   `json:"productId"`
	Manufacturer string   `json:"manufacturer"`
	Product      string   `json:"product"`
	Speed        string   `json:"speed"` // Mb/s as the kernel reports it
	Hub          bool     `json:"hub"`
	Critical     string   `json:"critical"`
	Owner        string   `json:"owner"`
	Assigned     []string `json:"assigned"`
}

// GPU is a graphics card (or integrated graphics) with its functions.
type GPU struct {
	Address    string `json:"address"` // its first display function
	Vendor     string `json:"vendor"`  // nvidia, amd, intel, other
	VendorName string `json:"vendorName"`
	Model      string `json:"model"`
	// VRAMBytes is 0 when unknown; SharedMemory marks integrated graphics.
	VRAMBytes    uint64        `json:"vramBytes"`
	SharedMemory bool          `json:"sharedMemory"`
	Functions    []GPUFunction `json:"functions"`
	Driver       string        `json:"driver"`
	BootVGA      bool          `json:"bootVga"`
	IOMMUGroup   *int          `json:"iommuGroup"`
	Owner        GPUOwner      `json:"owner"`
	// Users are processes (apps) using it right now.
	Users    []DeviceUser `json:"users"`
	Assigned []string     `json:"assigned"`
	// Problem: why it can't go to a VM ("" if it can).
	Problem string `json:"problem"`
	// Hints are plain-words tips (reset quirks, drivers...).
	Hints []string  `json:"hints"`
	VGPU  *VGPUInfo `json:"vgpu"`
}

// GPUFunction is one PCI function of a GPU (display, HDMI audio, USB-C...).
type GPUFunction struct {
	Address string `json:"address"`
	Kind    string `json:"kind"`
	Driver  string `json:"driver"`
}

// Owner kinds.
const (
	OwnerApps  = "apps"  // host driver: Docker apps can use it
	OwnerVM    = "vm"    // lent to a running VM
	OwnerVGPU  = "vgpu"  // split into vGPU slices
	OwnerNone  = "none"  // no driver: install one for apps to use it
	OwnerStuck = "stuck" // couldn't be given back: restart the server
)

// GPUOwner says who has a GPU now.
type GPUOwner struct {
	Kind  string `json:"kind"`
	VM    string `json:"vm,omitempty"`
	Label string `json:"label"`
}

// DeviceUser is a process with one of a GPU's device files open.
type DeviceUser struct {
	PID     int    `json:"pid"`
	Process string `json:"process"`
	// App is the HardyOS app it belongs to ("" if none).
	App string `json:"app,omitempty"`
	// Container: it runs in a Docker container.
	Container bool `json:"container"`
}

// StuckDevice is a device that couldn't be given back after a VM stopped.
type StuckDevice struct {
	Address string `json:"address"`
	VM      string `json:"vm"`
	// Driver is the driver it should go back to.
	Driver  string `json:"driver"`
	Message string `json:"message"`
}

// Inventory reads everything. It changes nothing.
func (h *Host) Inventory(ctx context.Context) (*Inventory, error) {
	h.mu.Lock()
	st := h.loadState()
	h.mu.Unlock()
	return h.inventory(ctx, st), nil
}

func (h *Host) inventory(ctx context.Context, st *state) *Inventory {
	inv := &Inventory{Groups: []Group{}, PCI: []PCIDevice{}, USB: []USBDevice{}, GPUs: []GPU{}, Stuck: []StuckDevice{}}
	pci := h.readPCI()
	crit, usbCrit := h.critical(ctx, pci)
	owners := st.owners()
	assigned := h.assigned(ctx)
	for i := range pci {
		p := &pci[i]
		p.Critical = crit[p.Address]
		p.Owner = owners[p.Address]
		p.Assigned = assigned[p.Address]
	}
	inv.PCI = pci
	inv.IOMMU = h.iommuState(len(pci) > 0)
	inv.Groups = h.groups(pci)
	inv.USB = h.readUSB(usbCrit, st, assigned)
	inv.GPUs = h.gpus(ctx, pci, st, assigned)
	for _, s := range st.Stuck {
		inv.Stuck = append(inv.Stuck, s)
	}
	return inv
}

// assigned maps device IDs to the VMs configured with them.
func (h *Host) assigned(ctx context.Context) map[string][]string {
	out := map[string][]string{}
	if h.Assignments == nil {
		return out
	}
	m, err := h.Assignments(ctx)
	if err != nil {
		return out
	}
	vms := make([]string, 0, len(m))
	for vm := range m {
		vms = append(vms, vm)
	}
	sort.Strings(vms)
	for _, vm := range vms {
		for _, d := range m[vm] {
			if !contains(out[d.ID], vm) {
				out[d.ID] = append(out[d.ID], vm)
			}
		}
	}
	return out
}

// readPCI lists every PCI function, sorted by address.
func (h *Host) readPCI() []PCIDevice {
	entries, _ := os.ReadDir(h.path("/sys/bus/pci/devices"))
	var out []PCIDevice
	want := map[string]bool{}
	for _, e := range entries {
		addr := e.Name()
		if !pciAddrRE.MatchString(addr) {
			continue
		}
		dir := pciDev(addr)
		p := PCIDevice{
			Address:  addr,
			VendorID: strings.TrimPrefix(h.readTrim(dir+"/vendor"), "0x"),
			DeviceID: strings.TrimPrefix(h.readTrim(dir+"/device"), "0x"),
			Class:    h.readTrim(dir + "/class"),
			Driver:   h.driverOf(addr),
			BootVGA:  h.readTrim(dir+"/boot_vga") == "1",
			PhysFn:   h.linkBase(dir + "/physfn"),
			Assigned: []string{},
		}
		p.Kind = className(p.Class)
		p.Bridge = strings.HasPrefix(strings.TrimPrefix(p.Class, "0x"), "06")
		if g := h.linkBase(dir + "/iommu_group"); g != "" {
			if n, err := strconv.Atoi(g); err == nil {
				p.IOMMUGroup = &n
			}
		}
		p.ResetMethods = []string{}
		if m := h.readTrim(dir + "/reset_method"); m != "" {
			p.ResetMethods = strings.Fields(m)
			p.Resettable = true
		} else if h.exists(dir + "/reset") {
			p.Resettable = true
		}
		want[p.VendorID] = true
		want[p.VendorID+":"+p.DeviceID] = true
		out = append(out, p)
	}
	names := h.loadIDs(pciIDFiles, want)
	for i := range out {
		out[i].Vendor = names[out[i].VendorID]
		out[i].Name = names[out[i].VendorID+":"+out[i].DeviceID]
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}

func findPCI(pci []PCIDevice, addr string) *PCIDevice {
	for i := range pci {
		if pci[i].Address == addr {
			return &pci[i]
		}
	}
	return nil
}

// iommuFlags are the kernel arguments that turn IOMMU on for this CPU.
func (h *Host) iommuFlags() (vendor string, flags []string) {
	vendor = "other"
	for _, line := range strings.Split(h.readTrim("/proc/cpuinfo"), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(k) != "vendor_id" {
			continue
		}
		switch strings.TrimSpace(v) {
		case "GenuineIntel":
			vendor = "intel"
		case "AuthenticAMD", "HygonGenuine":
			vendor = "amd"
		}
		break
	}
	arch := h.Arch
	if arch == "" {
		arch = runtime.GOARCH
	}
	if arch != "amd64" && arch != "386" {
		return vendor, nil // other architectures (SMMU) need no flags
	}
	switch vendor {
	case "intel":
		return vendor, []string{"intel_iommu=on", "iommu=pt"}
	case "amd":
		// AMD-Vi is on by default once the BIOS enables it; the flag
		// is harmless and makes the intent visible.
		return vendor, []string{"amd_iommu=on", "iommu=pt"}
	}
	return vendor, nil
}

func (h *Host) iommuState(havePCI bool) IOMMUState {
	s := IOMMUState{Flags: []string{}, KernelArgs: []string{}}
	groups, _ := os.ReadDir(h.path("/sys/kernel/iommu_groups"))
	s.Groups = len(groups)
	s.Enabled = s.Groups > 0
	s.FirmwareTable = h.exists("/sys/firmware/acpi/tables/DMAR") || h.exists("/sys/firmware/acpi/tables/IVRS")
	var flags []string
	s.CPUVendor, flags = h.iommuFlags()
	if flags != nil {
		s.Flags = flags
	}
	if args, err := boot.LoadKernelArgs(h.bootEnv()); err == nil && args != nil {
		s.KernelArgs = args
	}
	cmdline := " " + h.readTrim("/proc/cmdline") + " "
	s.Configured, s.Active = len(s.Flags) > 0, len(s.Flags) > 0
	for _, f := range s.Flags {
		if !contains(s.KernelArgs, f) {
			s.Configured = false
		}
		if !strings.Contains(cmdline, " "+f+" ") {
			s.Active = false
		}
	}
	s.RestartNeeded = s.Configured && !s.Active
	s.CanTurnOn = len(s.Flags) > 0 && !s.Configured
	bios := "VT-d"
	if s.CPUVendor == "amd" {
		bios = "AMD-Vi (often called IOMMU or SVM)"
	}
	switch {
	case s.Enabled && s.RestartNeeded:
		s.Message = fmt.Sprintf("IOMMU is on (%d groups). Restart the server to use the new boot settings too.", s.Groups)
	case s.Enabled:
		s.Message = fmt.Sprintf("IOMMU is on: %d groups. Devices can be handed to virtual machines.", s.Groups)
	case s.RestartNeeded:
		s.Message = "The boot settings to turn IOMMU on are in place. Restart the server for them to take effect."
	case s.Active || (len(s.Flags) == 0 && havePCI):
		s.Message = fmt.Sprintf("IOMMU is still off. Turn on %s in the server's BIOS/UEFI settings, then restart.", bios)
	default:
		s.Message = fmt.Sprintf("IOMMU is off, so devices can't be handed to virtual machines. \"Turn on IOMMU\" adds the boot settings (a restart is needed), and %s must also be enabled in the BIOS.", bios)
	}
	return s
}

// groups lists IOMMU groups that hold at least one device, with a
// plain-words explanation of what lending one of its devices means.
func (h *Host) groups(pci []PCIDevice) []Group {
	byGroup := map[int][]string{}
	for _, p := range pci {
		if p.IOMMUGroup != nil {
			byGroup[*p.IOMMUGroup] = append(byGroup[*p.IOMMUGroup], p.Address)
		}
	}
	ids := make([]int, 0, len(byGroup))
	for id := range byGroup {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	out := []Group{}
	for _, id := range ids {
		devs := byGroup[id]
		out = append(out, Group{ID: id, Devices: devs, Explanation: groupExplanation(id, devs, pci)})
	}
	return out
}

func groupExplanation(id int, devs []string, pci []PCIDevice) string {
	var endpoints, bridges []string
	for _, a := range devs {
		p := findPCI(pci, a)
		if p == nil {
			continue
		}
		label := p.Kind + " " + a
		if p.Bridge {
			bridges = append(bridges, label)
		} else {
			endpoints = append(endpoints, label)
		}
	}
	switch {
	case len(endpoints) == 0:
		return fmt.Sprintf("Group %d only holds bridges, which stay with the server.", id)
	case len(endpoints) == 1:
		return fmt.Sprintf("Group %d holds one device (%s), so it can go to a VM on its own.", id, endpoints[0])
	}
	slots := map[string]bool{}
	for _, a := range devs {
		if p := findPCI(pci, a); p != nil && !p.Bridge {
			slots[slotOf(a)] = true
		}
	}
	if len(slots) == 1 {
		return fmt.Sprintf("Group %d is one card with %d parts (%s). They go to a VM together.", id, len(endpoints), strings.Join(endpoints, ", "))
	}
	return fmt.Sprintf("Group %d holds %d devices (%s). The hardware can't keep them apart, so when one goes to a VM the others are taken from the server too, for as long as the VM runs.", id, len(endpoints), strings.Join(endpoints, ", "))
}

// readUSB lists USB devices (not root hubs or interfaces).
func (h *Host) readUSB(crit map[string]string, st *state, assigned map[string][]string) []USBDevice {
	entries, _ := os.ReadDir(h.path("/sys/bus/usb/devices"))
	out := []USBDevice{}
	want := map[string]bool{}
	owners := st.owners()
	for _, e := range entries {
		port := e.Name()
		if !usbPortRE.MatchString(port) {
			continue // usb1 (root hub) or 1-4:1.0 (an interface)
		}
		dir := "/sys/bus/usb/devices/" + port
		d := USBDevice{
			Port: port, VendorID: h.readTrim(dir + "/idVendor"), ProductID: h.readTrim(dir + "/idProduct"),
			Manufacturer: h.readTrim(dir + "/manufacturer"), Product: h.readTrim(dir + "/product"),
			Speed: h.readTrim(dir + "/speed"), Hub: h.readTrim(dir+"/bDeviceClass") == "09",
			Critical: crit[port], Assigned: []string{},
		}
		d.Bus, _ = h.readInt(dir + "/busnum")
		d.Dev, _ = h.readInt(dir + "/devnum")
		id := d.VendorID + ":" + d.ProductID
		if o := owners[id]; o != "" {
			d.Owner = o
		} else {
			d.Owner = owners[port]
		}
		d.Assigned = append(append(d.Assigned, assigned[id]...), assigned[port]...)
		want[d.VendorID], want[id] = true, true
		out = append(out, d)
	}
	names := h.loadIDs(usbIDFiles, want)
	for i := range out {
		if out[i].Manufacturer == "" {
			out[i].Manufacturer = names[out[i].VendorID]
		}
		if out[i].Product == "" {
			out[i].Product = names[out[i].VendorID+":"+out[i].ProductID]
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// usbByID finds a USB device by vendor:product or port.
func usbByID(usb []USBDevice, id string) *USBDevice {
	for i := range usb {
		if usb[i].Port == id || usb[i].VendorID+":"+usb[i].ProductID == id {
			return &usb[i]
		}
	}
	return nil
}

func isDisplay(class string) bool {
	return strings.HasPrefix(strings.TrimPrefix(strings.ToLower(class), "0x"), "03")
}

// gpus groups display devices with the other functions of their card.
func (h *Host) gpus(ctx context.Context, pci []PCIDevice, st *state, assigned map[string][]string) []GPU {
	out := []GPU{}
	var displays []PCIDevice
	for _, p := range pci {
		if isDisplay(p.Class) && p.PhysFn == "" {
			displays = append(displays, p)
		}
	}
	seenSlot := map[string]bool{}
	vram := h.nvidiaVRAM(ctx, pci)
	for _, p := range displays {
		if seenSlot[slotOf(p.Address)] {
			continue
		}
		seenSlot[slotOf(p.Address)] = true
		g := GPU{
			Address: p.Address, Vendor: vendorKey(p.VendorID), VendorName: p.Vendor, Model: p.Name,
			Driver: p.Driver, BootVGA: p.BootVGA, IOMMUGroup: p.IOMMUGroup,
			Assigned: append([]string{}, assigned[p.Address]...), Hints: []string{}, Users: []DeviceUser{},
		}
		if g.Model == "" {
			g.Model = fmt.Sprintf("Graphics %s:%s", p.VendorID, p.DeviceID)
		}
		for _, f := range pci {
			if slotOf(f.Address) == slotOf(p.Address) && f.PhysFn == "" {
				g.Functions = append(g.Functions, GPUFunction{Address: f.Address, Kind: f.Kind, Driver: f.Driver})
			}
		}
		switch {
		case g.Vendor == "amd":
			if b, ok := h.readInt(pciDev(p.Address) + "/mem_info_vram_total"); ok && b > 0 {
				g.VRAMBytes = uint64(b)
			}
		case g.Vendor == "nvidia":
			g.VRAMBytes = vram[p.Address]
		}
		// Integrated graphics sit on the root bus (00:02.0 for Intel, an
		// APU's on bus 0 behind the CPU); they share the system's memory.
		if g.Vendor == "intel" && strings.HasPrefix(p.Address, "0000:00:") {
			g.SharedMemory = true
		}
		g.VGPU = h.vgpuInfo(p, pci, st)
		g.Users = h.deviceUsers(p.Address)
		g.Owner = h.gpuOwner(g, st)
		g.Problem = gpuProblem(p, pci, displays)
		if c := findPCI(pci, p.Address).Critical; c != "" && g.Problem == "" {
			g.Problem = c
		}
		g.Hints = gpuHints(p, g)
		out = append(out, g)
	}
	return out
}

// gpuProblem: the only display GPU stays with the server (its console).
func gpuProblem(p PCIDevice, pci []PCIDevice, displays []PCIDevice) string {
	if len(displays) <= 1 {
		return "This is the server's only graphics card and shows its console, so it stays with the server. Add a second card (or use the motherboard's graphics) to give one to a VM."
	}
	return ""
}

func (h *Host) gpuOwner(g GPU, st *state) GPUOwner {
	for _, s := range st.Stuck {
		if slotOf(s.Address) == slotOf(g.Address) {
			return GPUOwner{Kind: OwnerStuck, VM: s.VM, Label: "Needs a restart to come back"}
		}
	}
	if vm := st.owners()[g.Address]; vm != "" {
		return GPUOwner{Kind: OwnerVM, VM: vm, Label: "VM " + vm}
	}
	if g.VGPU != nil && g.VGPU.Mode != ModeSRIOVVF && (len(g.VGPU.Types) > 0 || len(g.VGPU.Instances) > 0) {
		used := 0
		for _, in := range g.VGPU.Instances {
			if in.VM != "" {
				used++
			}
		}
		return GPUOwner{Kind: OwnerVGPU, Label: fmt.Sprintf("vGPU slices (%d in use)", used)}
	}
	switch g.Driver {
	case "", "vfio-pci":
		return GPUOwner{Kind: OwnerNone, Label: "No driver loaded"}
	case "nouveau":
		return GPUOwner{Kind: OwnerApps, Label: "Docker apps (basic open-source driver)"}
	}
	return GPUOwner{Kind: OwnerApps, Label: "Docker apps"}
}

// nvidiaVRAM asks nvidia-smi for each card's memory when the driver runs.
func (h *Host) nvidiaVRAM(ctx context.Context, pci []PCIDevice) map[string]uint64 {
	out := map[string]uint64{}
	any := false
	for _, p := range pci {
		if p.Driver == "nvidia" && isDisplay(p.Class) {
			any = true
		}
	}
	if !any || h.Runner == nil {
		return out
	}
	res, err := h.Runner.Run(ctx, nil, "nvidia-smi", "--query-gpu=pci.bus_id,memory.total", "--format=csv,noheader,nounits")
	if err != nil || res.ExitCode != 0 {
		return out
	}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		id, mib, ok := strings.Cut(line, ",")
		if !ok {
			continue
		}
		// nvidia-smi prints an 8-digit domain: 00000000:01:00.0.
		id = strings.ToLower(strings.TrimSpace(id))
		if len(id) == 16 {
			id = id[4:]
		}
		if n, err := strconv.ParseUint(strings.TrimSpace(mib), 10, 64); err == nil && pciAddrRE.MatchString(id) {
			out[id] = n << 20
		}
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// endpointsInGroup lists a group's devices that aren't bridges.
func (h *Host) endpointsInGroup(group int, pci []PCIDevice) []string {
	var out []string
	members, _ := os.ReadDir(h.path(filepath.Join("/sys/kernel/iommu_groups", strconv.Itoa(group), "devices")))
	for _, m := range members {
		if p := findPCI(pci, m.Name()); p != nil && !p.Bridge {
			out = append(out, p.Address)
		}
	}
	sort.Strings(out)
	return out
}
