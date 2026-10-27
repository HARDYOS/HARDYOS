package devices

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// GPU ownership. A whole GPU is with the server (its own driver, so Docker
// apps can use it) unless a running VM has it:
//
//	apps --Prepare--> vm --Release--> apps
//	                    \--Release fails--> stuck --Reconcile/restart--> apps
//
// Prepare refuses while a process (an app) has the card's device files
// open. Release puts the card back on the driver it had. Reconcile (at
// hardyd-priv start) releases devices of VMs that aren't running any more.

// readyGrace is how long after Prepare a VM may take to show up as running
// before Reconcile treats its devices as left over.
const readyGrace = 2 * time.Minute

type planItem struct {
	dev   Device
	addrs []string // PCI functions the VM gets (pci, gpu)
	rom   string
	gpu   string // the GPU's first function, for gpu (and display pci)
	usb   *USBDevice
	vgpu  *VGPUInfo
}

type plan struct {
	items []planItem
	bind  []boundDev // to move to vfio-pci, in order
}

// Check implements Manager.
func (h *Host) Check(ctx context.Context, vm string, ds []Device) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.loadState()
	_, probs := h.plan(ctx, vm, ds, st, h.inventory(ctx, st))
	if len(probs) > 0 {
		return probs
	}
	return nil
}

func (h *Host) plan(ctx context.Context, vm string, ds []Device, st *state, inv *Inventory) (*plan, Problems) {
	var probs Problems
	add := func(dev, format string, args ...any) {
		probs = append(probs, Problem{Device: dev, Message: fmt.Sprintf(format, args...)})
	}
	if !vmNameRE.MatchString(vm) {
		add("", "Invalid VM name %q.", vm)
		return nil, probs
	}
	owners := st.owners()
	otherVM := func(id string) string {
		if o := owners[id]; o != "" && o != vm {
			return o
		}
		return ""
	}
	pl := &plan{}
	taken := map[string]bool{} // PCI functions given to this VM
	seen := map[string]bool{}
	iommuNeeded := false
	for _, d := range ds {
		key := d.Kind + "|" + d.ID + "|" + d.VGPUType
		if seen[key] && d.Kind != KindVGPU {
			add(d.ID, "%s is listed twice.", d.ID)
			continue
		}
		seen[key] = true
		it := planItem{dev: d}
		switch d.Kind {
		case KindPCI, KindGPU:
			p := findPCI(inv.PCI, d.ID)
			if !pciAddrRE.MatchString(d.ID) {
				add(d.ID, "%q isn't a PCI address (like 0000:01:00.0).", d.ID)
				continue
			}
			if p == nil {
				add(d.ID, "There's no PCI device at %s any more (was it removed or moved to another slot?).", d.ID)
				continue
			}
			if p.Bridge {
				add(d.ID, "%s is a PCI bridge; bridges stay with the server.", d.ID)
				continue
			}
			iommuNeeded = true
			display := isDisplay(p.Class)
			if d.Kind == KindGPU && !display {
				add(d.ID, "%s (%s) isn't a graphics card.", d.ID, p.Kind)
				continue
			}
			it.addrs = []string{d.ID}
			if display {
				g := gpuAt(inv.GPUs, d.ID)
				if g == nil {
					add(d.ID, "%s isn't a graphics card HardyOS can hand over.", d.ID)
					continue
				}
				it.gpu = g.Address
				it.addrs = nil
				for _, f := range g.Functions {
					it.addrs = append(it.addrs, f.Address)
				}
				if g.Problem != "" {
					add(d.ID, "%s", g.Problem)
					continue
				}
				if o := otherVM(g.Address); o != "" {
					add(d.ID, "The graphics card %s is in use by the VM %s. Stop that VM first.", d.ID, o)
					continue
				}
				if g.VGPU != nil && len(g.VGPU.Instances) > 0 {
					add(d.ID, "The graphics card %s is split into vGPU slices. Remove the slices before giving the whole card to a VM.", d.ID)
					continue
				}
				if len(g.Users) > 0 {
					add(d.ID, "%s", usersMessage(d.ID, g.Users))
					continue
				}
			}
			bad := false
			for _, a := range it.addrs {
				q := findPCI(inv.PCI, a)
				if q != nil && q.Critical != "" {
					add(d.ID, "%s (%s) can't go to a VM: %s", a, q.Kind, q.Critical)
					bad = true
				} else if o := otherVM(a); o != "" {
					add(d.ID, "%s is in use by the VM %s. Stop that VM first.", a, o)
					bad = true
				} else if taken[a] {
					add(d.ID, "%s is listed twice (on its own and as part of a card).", a)
					bad = true
				}
			}
			if bad {
				continue
			}
			if d.ROMFile != "" {
				if !romFileRE.MatchString(d.ROMFile) {
					add(d.ID, "ROM file names end in .rom or .bin and use letters, digits and ._- only.")
					continue
				}
				it.rom = filepath.Join(h.romDir(), d.ROMFile)
				if !h.exists(it.rom) {
					add(d.ID, "The ROM file %s isn't in the ROM library (%s).", d.ROMFile, h.romDir())
					continue
				}
			}
			for _, a := range it.addrs {
				taken[a] = true
			}
		case KindUSB:
			switch {
			case usbIDRE.MatchString(d.ID):
				if u := usbByID(inv.USB, d.ID); u != nil {
					it.usb = u
				}
			case usbPortRE.MatchString(d.ID):
				u := usbByID(inv.USB, d.ID)
				if u == nil {
					add(d.ID, "Nothing is plugged into USB port %s right now.", d.ID)
					continue
				}
				it.usb = u
			default:
				add(d.ID, "%q isn't a USB device ID (like 046d:c52b) or port (like 1-4.2).", d.ID)
				continue
			}
			if u := it.usb; u != nil {
				if u.Hub {
					add(d.ID, "%s is a USB hub. Pick the devices plugged into it instead.", d.ID)
					continue
				}
				if u.Critical != "" {
					add(d.ID, "The USB device %s can't go to a VM: %s", d.ID, u.Critical)
					continue
				}
				if o := firstNonEmpty(otherVM(u.Port), otherVM(u.VendorID+":"+u.ProductID)); o != "" {
					add(d.ID, "The USB device %s is in use by the VM %s.", d.ID, o)
					continue
				}
			}
			if o := otherVM(d.ID); o != "" {
				add(d.ID, "The USB device %s is in use by the VM %s.", d.ID, o)
				continue
			}
		case KindVGPU:
			if !pciAddrRE.MatchString(d.ID) {
				add(d.ID, "%q isn't a PCI address (like 0000:01:00.0).", d.ID)
				continue
			}
			g := gpuAt(inv.GPUs, d.ID)
			if g == nil || g.VGPU == nil || len(g.VGPU.Types) == 0 {
				add(d.ID, "The graphics card %s doesn't offer vGPU slices.", d.ID)
				continue
			}
			if o := otherVM(g.Address); o != "" {
				add(d.ID, "The whole graphics card %s is in use by the VM %s.", d.ID, o)
				continue
			}
			if taken[g.Address] {
				add(d.ID, "%s can't be given to the same VM whole and as a slice.", d.ID)
				continue
			}
			if !vgpuTypeRE.MatchString(d.VGPUType) {
				add(d.ID, "Choose a vGPU type for %s.", d.ID)
				continue
			}
			var vt *VGPUType
			for i := range g.VGPU.Types {
				if g.VGPU.Types[i].ID == d.VGPUType {
					vt = &g.VGPU.Types[i]
				}
			}
			if vt == nil {
				add(d.ID, "The graphics card %s has no vGPU type %q.", d.ID, d.VGPUType)
				continue
			}
			want := 0
			for _, x := range ds {
				if x.Kind == KindVGPU && x.ID == d.ID && x.VGPUType == d.VGPUType {
					want++
				}
			}
			if want > vt.Available && seen[key+"|counted"] == false {
				add(d.ID, "The graphics card %s has room for %d more %s slice(s); this VM asks for %d.", d.ID, vt.Available, vt.Name, want)
				seen[key+"|counted"] = true
				continue
			}
			seen[key+"|counted"] = true
			if g.VGPU.Mode != ModeMdev {
				iommuNeeded = true
			}
			it.vgpu = g.VGPU
			it.gpu = g.Address
		default:
			add(d.ID, "Unknown device kind %q.", d.Kind)
			continue
		}
		pl.items = append(pl.items, it)
	}
	if iommuNeeded && !inv.IOMMU.Enabled {
		probs = append(Problems{{Message: "IOMMU is off, so PCI devices and GPUs can't be handed to VMs. " + inv.IOMMU.Message}}, probs...)
	}
	if len(probs) > 0 {
		return nil, probs
	}

	// Whole IOMMU groups: every other device in a lent device's group is
	// held away from the server too (not given to the VM).
	inBind := map[string]bool{}
	for _, it := range pl.items {
		for _, a := range it.addrs {
			if !inBind[a] {
				inBind[a] = true
				pl.bind = append(pl.bind, boundDev{Address: a})
			}
		}
	}
	for _, it := range pl.items {
		for _, a := range it.addrs {
			p := findPCI(inv.PCI, a)
			if p == nil || p.IOMMUGroup == nil {
				continue
			}
			for _, c := range h.endpointsInGroup(*p.IOMMUGroup, inv.PCI) {
				if inBind[c] {
					continue
				}
				q := findPCI(inv.PCI, c)
				switch {
				case q.Critical != "":
					add(it.dev.ID, "%s shares IOMMU group %d with %s (%s), and the hardware can't separate them. That device can't leave the server: %s",
						a, *p.IOMMUGroup, c, q.Kind, q.Critical)
				case otherVM(c) != "":
					add(it.dev.ID, "%s shares IOMMU group %d with %s, which the VM %s is using.", a, *p.IOMMUGroup, c, otherVM(c))
				case isDisplay(q.Class) && len(h.deviceUsers(c)) > 0:
					add(it.dev.ID, "%s shares IOMMU group %d with the graphics card %s. %s", a, *p.IOMMUGroup, c, usersMessage(c, h.deviceUsers(c)))
				default:
					inBind[c] = true
					pl.bind = append(pl.bind, boundDev{Address: c, Companion: true})
				}
			}
		}
	}
	if len(probs) > 0 {
		return nil, probs
	}
	return pl, nil
}

func gpuAt(gpus []GPU, addr string) *GPU {
	for i := range gpus {
		for _, f := range gpus[i].Functions {
			if f.Address == addr {
				return &gpus[i]
			}
		}
	}
	return nil
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

// Prepare implements Manager.
func (h *Host) Prepare(ctx context.Context, vm string, ds []Device) ([]Prepared, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.loadState()
	if st.VMs[vm] != nil {
		// Left over from a start that never got its Release. Never pull
		// devices from under a VM that's still running.
		if running, err := h.running(ctx); err == nil && contains(running, vm) {
			return nil, fmt.Errorf("the VM %s is already running with its devices", vm)
		}
		if err := h.release(ctx, vm, st); err != nil {
			return nil, fmt.Errorf("giving back the devices from the VM's last run: %w", err)
		}
	}
	pl, probs := h.plan(ctx, vm, ds, st, h.inventory(ctx, st))
	if len(probs) > 0 {
		return nil, probs
	}
	vs := &vmState{Phase: phasePreparing, Devices: ds}
	st.VMs[vm] = vs
	if err := h.saveState(st); err != nil {
		return nil, err
	}
	out, err := h.apply(ctx, vm, pl, vs, st)
	if err != nil {
		if rerr := h.release(context.WithoutCancel(ctx), vm, st); rerr != nil {
			h.log().Warn("undoing a failed device setup", "vm", vm, "err", rerr)
		}
		return nil, err
	}
	vs.Phase = phaseReady
	vs.ReadyAt = time.Now().UTC()
	if err := h.saveState(st); err != nil {
		return nil, err
	}
	h.log().Info("devices lent to VM", "vm", vm, "devices", len(out))
	return out, nil
}

func (h *Host) apply(ctx context.Context, vm string, pl *plan, vs *vmState, st *state) ([]Prepared, error) {
	k := h.kernel()
	// NVIDIA's persistence daemon keeps every NVIDIA card open.
	for _, b := range pl.bind {
		if h.driverOf(b.Address) == "nvidia" {
			h.stopHelpers(ctx, vs)
			break
		}
	}
	vfioLoaded := false
	loadVFIO := func() error {
		if vfioLoaded {
			return nil
		}
		if _, err := sysexec.Output(ctx, h.Runner, "modprobe", "vfio-pci"); err != nil {
			return fmt.Errorf("load vfio-pci: %w", err)
		}
		vfioLoaded = true
		return nil
	}
	bind := func(b boundDev) error {
		if err := loadVFIO(); err != nil {
			return err
		}
		b.Driver = h.driverOf(b.Address)
		vs.Bound = append(vs.Bound, b)
		if err := h.saveState(st); err != nil {
			return err
		}
		if b.Driver == "vfio-pci" {
			return nil
		}
		if err := k.WriteSysfs(pciDev(b.Address)+"/driver_override", "vfio-pci"); err != nil {
			return err
		}
		if b.Driver != "" {
			if err := k.WriteSysfs("/sys/bus/pci/drivers/"+b.Driver+"/unbind", b.Address); err != nil {
				return fmt.Errorf("take %s from its driver %s: %w", b.Address, b.Driver, err)
			}
		}
		_ = k.WriteSysfs("/sys/bus/pci/drivers_probe", b.Address)
		if d := h.driverOf(b.Address); d != "vfio-pci" {
			return fmt.Errorf("%s didn't move to vfio-pci (driver now %q)", b.Address, d)
		}
		h.dropStuck(st, b.Address)
		return nil
	}
	for _, b := range pl.bind {
		if err := bind(b); err != nil {
			return nil, err
		}
	}
	// Other NVIDIA cards still with the server get their daemon back.
	if len(vs.Helpers) > 0 && h.anyDriver("nvidia") {
		h.startHelpers(ctx, vs)
	}

	var out []Prepared
	mdevN := map[string]int{}
	for _, it := range pl.items {
		p := Prepared{Device: it.dev}
		var b strings.Builder
		switch it.dev.Kind {
		case KindPCI, KindGPU:
			for i, a := range it.addrs {
				rom := ""
				if i == 0 {
					rom = it.rom
				}
				x, err := HostdevPCI(a, rom)
				if err != nil {
					return nil, err
				}
				b.WriteString(x)
			}
			p.Addresses = it.addrs
			if it.gpu != "" {
				vs.GPUs = append(vs.GPUs, it.gpu)
			}
		case KindUSB:
			vs.USB = append(vs.USB, it.dev.ID)
			var x string
			var err error
			if usbIDRE.MatchString(it.dev.ID) {
				x, err = HostdevUSBByID(it.dev.ID[:4], it.dev.ID[5:])
			} else {
				x, err = HostdevUSBByAddress(it.usb.Bus, it.usb.Dev)
			}
			if err != nil {
				return nil, err
			}
			b.WriteString(x)
		case KindVGPU:
			switch it.vgpu.Mode {
			case ModeMdev:
				parent := h.mdevParent(it.gpu, it.dev.VGPUType)
				if parent == "" {
					return nil, fmt.Errorf("no room left for a %s slice on %s", it.dev.VGPUType, it.gpu)
				}
				n := mdevN[parent+it.dev.VGPUType]
				mdevN[parent+it.dev.VGPUType]++
				id := stableUUID(vm, parent, it.dev.VGPUType, n)
				if h.exists("/sys/bus/mdev/devices/" + id) {
					_ = k.WriteSysfs("/sys/bus/mdev/devices/"+id+"/remove", "1")
				}
				vs.Mdevs = append(vs.Mdevs, mdevInst{UUID: id, Parent: parent, Type: it.dev.VGPUType})
				if err := h.saveState(st); err != nil {
					return nil, err
				}
				if err := k.WriteSysfs(pciDev(parent)+"/mdev_supported_types/"+it.dev.VGPUType+"/create", id); err != nil {
					return nil, fmt.Errorf("create the vGPU slice: %w", err)
				}
				if !h.exists("/sys/bus/mdev/devices/" + id) {
					return nil, fmt.Errorf("the vGPU slice %s didn't appear", id)
				}
				x, err := HostdevMdev(id)
				if err != nil {
					return nil, err
				}
				b.WriteString(x)
				p.MdevUUID = id
			case ModeNvidiaVF:
				vf := h.freeNvidiaVF(it.gpu, it.dev.VGPUType, st)
				if vf == "" {
					return nil, fmt.Errorf("no free virtual function on %s offers the type %s", it.gpu, it.dev.VGPUType)
				}
				vs.VFTypes = append(vs.VFTypes, vf)
				if err := h.saveState(st); err != nil {
					return nil, err
				}
				if err := k.WriteSysfs(pciDev(vf)+"/nvidia/current_vgpu_type", it.dev.VGPUType); err != nil {
					return nil, fmt.Errorf("set the vGPU type: %w", err)
				}
				if got := h.readTrim(pciDev(vf) + "/nvidia/current_vgpu_type"); got != it.dev.VGPUType {
					return nil, fmt.Errorf("the vGPU type didn't stick on %s (it reads %q)", vf, got)
				}
				x, err := HostdevPCI(vf, "")
				if err != nil {
					return nil, err
				}
				b.WriteString(x)
				p.Addresses = []string{vf}
			case ModeSRIOVVF:
				vf := ""
				owners := st.owners()
				for _, f := range h.virtfns(it.gpu) {
					if owners[f] == "" {
						vf = f
						break
					}
				}
				if vf == "" {
					return nil, fmt.Errorf("no free virtual function on %s", it.gpu)
				}
				if err := bind(boundDev{Address: vf}); err != nil {
					return nil, err
				}
				x, err := HostdevPCI(vf, "")
				if err != nil {
					return nil, err
				}
				b.WriteString(x)
				p.Addresses = []string{vf}
			}
		}
		p.XML = b.String()
		out = append(out, p)
	}
	return out, nil
}

// mdevParent picks the card, or one of its virtual functions, with room
// for another instance of typ.
func (h *Host) mdevParent(gpu, typ string) string {
	for _, parent := range append([]string{gpu}, h.virtfns(gpu)...) {
		if n, ok := h.readInt(pciDev(parent) + "/mdev_supported_types/" + typ + "/available_instances"); ok && n > 0 {
			return parent
		}
	}
	return ""
}

func (h *Host) freeNvidiaVF(gpu, typ string, st *state) string {
	owners := st.owners()
	for _, vf := range h.virtfns(gpu) {
		cur := h.readTrim(pciDev(vf) + "/nvidia/current_vgpu_type")
		if owners[vf] != "" || (cur != "" && cur != "0") {
			continue
		}
		if _, ok := parseCreatable(h.readTrim(pciDev(vf) + "/nvidia/creatable_vgpu_types"))[typ]; ok {
			return vf
		}
	}
	return ""
}

func (h *Host) anyDriver(name string) bool {
	for _, p := range h.readPCI() {
		if p.Driver == name {
			return true
		}
	}
	return false
}

func (h *Host) unitExists(unit string) bool {
	for _, d := range []string{"/lib/systemd/system/", "/usr/lib/systemd/system/", "/etc/systemd/system/"} {
		if h.exists(d + unit) {
			return true
		}
	}
	return false
}

// stopHelpers stops the services that hold GPUs open, remembering which
// ran so they can be started again.
func (h *Host) stopHelpers(ctx context.Context, vs *vmState) {
	units := make([]string, 0, len(hostHelpers))
	for _, u := range hostHelpers {
		units = append(units, u)
	}
	sort.Strings(units)
	for _, u := range units {
		if !h.unitExists(u) || contains(vs.Helpers, u) {
			continue
		}
		if res, err := h.Runner.Run(ctx, nil, "systemctl", "is-active", "--quiet", u); err != nil || res.ExitCode != 0 {
			continue
		}
		if _, err := sysexec.Output(ctx, h.Runner, "systemctl", "stop", u); err == nil {
			vs.Helpers = append(vs.Helpers, u)
		}
	}
}

func (h *Host) startHelpers(ctx context.Context, vs *vmState) {
	for _, u := range vs.Helpers {
		if _, err := sysexec.Output(ctx, h.Runner, "systemctl", "start", u); err != nil {
			h.log().Warn("starting a GPU helper again", "unit", u, "err", err)
		}
	}
	vs.Helpers = nil
}

// Release implements Manager.
func (h *Host) Release(ctx context.Context, vm string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.loadState()
	if st.VMs[vm] == nil {
		return nil
	}
	if running, err := h.running(ctx); err == nil && contains(running, vm) {
		return fmt.Errorf("the VM %s is still running; its devices are given back once it stops", vm)
	}
	return h.release(ctx, vm, st)
}

// release gives back everything vm holds. It always forgets the VM; what
// couldn't be given back is listed as stuck.
func (h *Host) release(ctx context.Context, vm string, st *state) error {
	vs := st.VMs[vm]
	if vs == nil {
		return nil
	}
	k := h.kernel()
	var errs []string
	for i := len(vs.Mdevs) - 1; i >= 0; i-- {
		m := vs.Mdevs[i]
		if h.exists("/sys/bus/mdev/devices/" + m.UUID) {
			if err := k.WriteSysfs("/sys/bus/mdev/devices/"+m.UUID+"/remove", "1"); err != nil {
				errs = append(errs, fmt.Sprintf("vGPU slice %s: %v", m.UUID, err))
			}
		}
	}
	for _, vf := range vs.VFTypes {
		if err := k.WriteSysfs(pciDev(vf)+"/nvidia/current_vgpu_type", "0"); err != nil {
			errs = append(errs, fmt.Sprintf("vGPU slice %s: %v", vf, err))
		}
	}
	if len(vs.Bound) > 0 && h.anyDriver("nvidia") {
		h.stopHelpers(ctx, vs) // the daemon would grab cards half way back
	}
	for i := len(vs.Bound) - 1; i >= 0; i-- {
		b := vs.Bound[i]
		if err := h.restore(b); err != nil {
			errs = append(errs, err.Error())
			h.addStuck(st, StuckDevice{Address: b.Address, VM: vm, Driver: b.Driver,
				Message: stuckMessage(h, b, vm)})
		}
	}
	if len(vs.Helpers) > 0 {
		h.startHelpers(ctx, vs)
	}
	delete(st.VMs, vm)
	if err := h.saveState(st); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("some devices of the VM %s weren't given back: %s", vm, strings.Join(errs, "; "))
	}
	h.log().Info("devices given back", "vm", vm)
	return nil
}

// restore moves a device from vfio-pci back to the driver it had.
func (h *Host) restore(b boundDev) error {
	if b.Driver == "vfio-pci" || !h.exists(pciDev(b.Address)) {
		return nil
	}
	k := h.kernel()
	if err := k.WriteSysfs(pciDev(b.Address)+"/driver_override", "\n"); err != nil {
		return err
	}
	if h.driverOf(b.Address) == "vfio-pci" {
		if err := k.WriteSysfs("/sys/bus/pci/drivers/vfio-pci/unbind", b.Address); err != nil {
			return fmt.Errorf("take %s from vfio-pci: %w", b.Address, err)
		}
	}
	if b.Driver == "" {
		return nil
	}
	if !driverRE.MatchString(b.Driver) {
		return fmt.Errorf("%s: invalid driver name %q", b.Address, b.Driver)
	}
	_ = k.WriteSysfs("/sys/bus/pci/drivers_probe", b.Address)
	if h.driverOf(b.Address) != b.Driver && h.exists("/sys/bus/pci/drivers/"+b.Driver) {
		_ = k.WriteSysfs("/sys/bus/pci/drivers/"+b.Driver+"/bind", b.Address)
	}
	if d := h.driverOf(b.Address); d != b.Driver {
		return fmt.Errorf("%s didn't go back to its driver %s", b.Address, b.Driver)
	}
	return nil
}

func stuckMessage(h *Host, b boundDev, vm string) string {
	kind := "The device"
	if isDisplay(h.readTrim(pciDev(b.Address) + "/class")) {
		kind = "The graphics card"
	}
	msg := fmt.Sprintf("%s %s didn't come back from the VM %s (it should go back to its driver %s). Restart the server to get it back.", kind, b.Address, vm, firstNonEmpty(b.Driver, "none"))
	if strings.TrimPrefix(h.readTrim(pciDev(b.Address)+"/vendor"), "0x") == vendorAMD &&
		amdResetBug[strings.TrimPrefix(h.readTrim(pciDev(b.Address)+"/device"), "0x")] {
		msg += " This AMD card is known for not resetting itself; the vendor-reset module fixes that."
	}
	return msg
}

func (h *Host) addStuck(st *state, s StuckDevice) {
	for i, x := range st.Stuck {
		if x.Address == s.Address {
			st.Stuck[i] = s
			return
		}
	}
	st.Stuck = append(st.Stuck, s)
}

func (h *Host) dropStuck(st *state, addr string) {
	out := st.Stuck[:0]
	for _, s := range st.Stuck {
		if s.Address != addr {
			out = append(out, s)
		}
	}
	st.Stuck = out
}

// Reconcile implements Reconciler.
func (h *Host) Reconcile(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.loadState()
	if len(st.VMs) == 0 && len(st.Stuck) == 0 {
		return nil
	}
	var errs []string
	if len(st.VMs) > 0 {
		running, err := h.running(ctx)
		if err != nil {
			return fmt.Errorf("can't tell which VMs are running, so their devices stay as they are: %w", err)
		}
		vms := make([]string, 0, len(st.VMs))
		for vm := range st.VMs {
			vms = append(vms, vm)
		}
		sort.Strings(vms)
		for _, vm := range vms {
			vs := st.VMs[vm]
			if contains(running, vm) {
				continue
			}
			if vs.Phase == phaseReady && time.Since(vs.ReadyAt) < readyGrace {
				continue // still starting
			}
			if err := h.release(ctx, vm, st); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	// Try the stuck ones again (a reset may work now).
	owners := st.owners()
	for _, s := range append([]StuckDevice(nil), st.Stuck...) {
		if owners[s.Address] != "" {
			continue
		}
		if err := h.restore(boundDev{Address: s.Address, Driver: s.Driver}); err == nil {
			h.dropStuck(st, s.Address)
		}
	}
	if err := h.saveState(st); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// Owners lists which VM has which device now (for the VM engine's pages).
func (h *Host) Owners() map[string]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.loadState().owners()
}
