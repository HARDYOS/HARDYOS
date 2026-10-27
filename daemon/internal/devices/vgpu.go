package devices

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// vGPU slices. Three ways a card can be split, all found at runtime:
//
//   - mdev: the driver lists slice types in mdev_supported_types (NVIDIA's
//     vGPU host driver on cards it supports, on the card or on its
//     virtual functions); an instance is made by writing a UUID to the
//     type's create file and given to a VM as an mdev hostdev.
//   - nvidia-vf: NVIDIA's vGPU host driver on newer kernels exposes the
//     types per virtual function (nvidia/creatable_vgpu_types); a slice is
//     a virtual function with nvidia/current_vgpu_type set, given to the
//     VM as a PCI device.
//   - sriov-vf: a GPU whose driver offers SR-IOV virtual functions (Intel
//     integrated graphics with i915/xe SR-IOV); a slice is one virtual
//     function bound to vfio-pci.
//
// HardyOS never ships, patches or unlocks a vGPU driver: slices appear only
// when the admin's own NVIDIA vGPU host driver (or the kernel's driver)
// offers them.

// vGPU modes.
const (
	ModeMdev     = "mdev"
	ModeNvidiaVF = "nvidia-vf"
	ModeSRIOVVF  = "sriov-vf"
)

// SRIOVType is the one slice type of a sriov-vf GPU.
const SRIOVType = "sriov-vf"

// VGPUInfo is what a GPU offers as slices.
type VGPUInfo struct {
	Mode string `json:"mode"`
	// HostDriver: NVIDIA's vGPU host driver is loaded.
	HostDriver bool           `json:"hostDriver"`
	Types      []VGPUType     `json:"types"`
	Instances  []VGPUInstance `json:"instances"`
	// VFs and MaxVFs: SR-IOV virtual functions on and possible.
	VFs    int    `json:"vfs"`
	MaxVFs int    `json:"maxVfs"`
	Note   string `json:"note,omitempty"`
}

// VGPUType is one kind of slice.
type VGPUType struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Available is how many more can be made now.
	Available int `json:"available"`
	// FramebufferMB and MaxInstances come from the description when the
	// driver gives them (0 = unknown).
	FramebufferMB int `json:"framebufferMb"`
	MaxInstances  int `json:"maxInstances"`
}

// VGPUInstance is one slice that exists now.
type VGPUInstance struct {
	ID     string `json:"id"` // mdev UUID or virtual function address
	Type   string `json:"type"`
	Parent string `json:"parent"`
	VM     string `json:"vm"` // "" if no running VM has it
}

var (
	fbRE      = regexp.MustCompile(`framebuffer=([0-9]+)M`)
	maxInstRE = regexp.MustCompile(`max_instance=([0-9]+)`)
)

// virtfns lists a physical function's virtual functions.
func (h *Host) virtfns(pf string) []string {
	entries, _ := os.ReadDir(h.path(pciDev(pf)))
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "virtfn") {
			if vf := h.linkBase(pciDev(pf) + "/" + e.Name()); pciAddrRE.MatchString(vf) {
				out = append(out, vf)
			}
		}
	}
	sort.Strings(out)
	return out
}

// nvidiaVGPUDriver: NVIDIA's vGPU host driver is loaded.
func (h *Host) nvidiaVGPUDriver() bool {
	return h.exists("/sys/module/nvidia_vgpu_vfio") || h.exists("/usr/lib/nvidia/sriov-manage")
}

func (h *Host) vgpuInfo(p PCIDevice, pci []PCIDevice, st *state) *VGPUInfo {
	info := &VGPUInfo{Types: []VGPUType{}, Instances: []VGPUInstance{}}
	vfs := h.virtfns(p.Address)
	info.VFs = len(vfs)
	info.MaxVFs, _ = h.readInt(pciDev(p.Address) + "/sriov_totalvfs")
	isNVIDIA := p.VendorID == vendorNVIDIA
	if isNVIDIA {
		info.HostDriver = h.nvidiaVGPUDriver()
	}
	owners := st.owners()

	// mdev types on the card itself or on its virtual functions.
	parents := append([]string{p.Address}, vfs...)
	byID := map[string]*VGPUType{}
	for _, parent := range parents {
		dir := pciDev(parent) + "/mdev_supported_types"
		types, _ := os.ReadDir(h.path(dir))
		for _, t := range types {
			id := t.Name()
			avail, _ := h.readInt(dir + "/" + id + "/available_instances")
			vt := byID[id]
			if vt == nil {
				desc := h.readTrim(dir + "/" + id + "/description")
				vt = &VGPUType{ID: id, Name: h.readTrim(dir + "/" + id + "/name"), Description: desc}
				if m := fbRE.FindStringSubmatch(desc); m != nil {
					vt.FramebufferMB, _ = strconv.Atoi(m[1])
				}
				if m := maxInstRE.FindStringSubmatch(desc); m != nil {
					vt.MaxInstances, _ = strconv.Atoi(m[1])
				}
				if vt.Name == "" {
					vt.Name = id
				}
				byID[id] = vt
			}
			vt.Available += avail
		}
	}
	if len(byID) > 0 {
		info.Mode = ModeMdev
		for _, vt := range byID {
			info.Types = append(info.Types, *vt)
		}
		mdevs, _ := os.ReadDir(h.path("/sys/bus/mdev/devices"))
		for _, m := range mdevs {
			parent := filepath.Base(filepath.Dir(h.resolve("/sys/bus/mdev/devices/" + m.Name())))
			if !contains(parents, parent) {
				continue
			}
			info.Instances = append(info.Instances, VGPUInstance{
				ID: m.Name(), Type: h.linkBase("/sys/bus/mdev/devices/" + m.Name() + "/mdev_type"),
				Parent: parent, VM: owners[m.Name()],
			})
		}
	} else if isNVIDIA && len(vfs) > 0 && h.exists(pciDev(vfs[0])+"/nvidia/creatable_vgpu_types") {
		info.Mode = ModeNvidiaVF
		byID := map[string]*VGPUType{}
		for _, vf := range vfs {
			cur := h.readTrim(pciDev(vf) + "/nvidia/current_vgpu_type")
			if cur != "" && cur != "0" {
				info.Instances = append(info.Instances, VGPUInstance{ID: vf, Type: cur, Parent: p.Address, VM: owners[vf]})
				continue
			}
			for id, name := range parseCreatable(h.readTrim(pciDev(vf) + "/nvidia/creatable_vgpu_types")) {
				if byID[id] == nil {
					byID[id] = &VGPUType{ID: id, Name: name}
				}
				byID[id].Available++
			}
		}
		for _, vt := range byID {
			info.Types = append(info.Types, *vt)
		}
	} else if isNVIDIA && info.HostDriver && info.MaxVFs > 0 {
		info.Mode = ModeNvidiaVF
		info.Note = "Turn on slices to see the types this card offers (it switches on the card's virtual functions)."
	} else if !isNVIDIA && info.MaxVFs > 0 && isDisplay(p.Class) {
		info.Mode = ModeSRIOVVF
		free := 0
		for _, vf := range vfs {
			if vm := owners[vf]; vm != "" {
				info.Instances = append(info.Instances, VGPUInstance{ID: vf, Type: SRIOVType, Parent: p.Address, VM: vm})
			} else {
				free++
			}
		}
		info.Types = append(info.Types, VGPUType{ID: SRIOVType, Name: "Virtual graphics (SR-IOV)",
			Description: fmt.Sprintf("%d of %d virtual functions on", len(vfs), info.MaxVFs), Available: free, MaxInstances: info.MaxVFs})
		if len(vfs) == 0 {
			info.Note = "The driver can split this GPU. Turn on slices to create its virtual functions."
		}
	} else if isNVIDIA && info.HostDriver {
		info.Mode = ModeMdev
		info.Note = "NVIDIA's vGPU host driver is loaded, but this card offers no vGPU types. Only cards NVIDIA supports for vGPU can be split; this one can still go to a VM whole."
	} else {
		return nil
	}
	sort.Slice(info.Types, func(i, j int) bool { return info.Types[i].ID < info.Types[j].ID })
	sort.Slice(info.Instances, func(i, j int) bool { return info.Instances[i].ID < info.Instances[j].ID })
	return info
}

// parseCreatable reads "ID : name" lines (the header line is skipped).
func parseCreatable(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		id, name, ok := strings.Cut(line, ":")
		id = strings.TrimSpace(id)
		if !ok || id == "" || id == "ID" {
			continue
		}
		if _, err := strconv.Atoi(id); err != nil {
			continue
		}
		out[id] = strings.TrimSpace(name)
	}
	return out
}

// stableUUID gives a VM's slice the same UUID every time it starts.
func stableUUID(vm, parent, typ string, n int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("hardyos-vgpu|%s|%s|%s|%d", vm, parent, typ, n)))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50 // version 5 style (name-based)
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// SetVFs switches a GPU's SR-IOV virtual functions on (count > 0) or off.
// NVIDIA cards use the vGPU driver's sriov-manage tool; others the
// kernel's sriov_numvfs. Refused while a VM uses one of them.
func (h *Host) SetVFs(ctx context.Context, addr string, count int) error {
	if !pciAddrRE.MatchString(addr) {
		return fmt.Errorf("invalid PCI address %q", addr)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.loadState()
	owners := st.owners()
	for _, vf := range h.virtfns(addr) {
		if vm := owners[vf]; vm != "" {
			return fmt.Errorf("the VM %s is using one of this card's slices; stop it first", vm)
		}
		if cur := h.readTrim(pciDev(vf) + "/nvidia/current_vgpu_type"); cur != "" && cur != "0" {
			return fmt.Errorf("slice %s still has a vGPU type set; remove it first", vf)
		}
	}
	if !h.exists(pciDev(addr)) {
		return fmt.Errorf("no PCI device %s", addr)
	}
	if strings.TrimPrefix(h.readTrim(pciDev(addr)+"/vendor"), "0x") == vendorNVIDIA {
		if !h.exists("/usr/lib/nvidia/sriov-manage") {
			return fmt.Errorf("NVIDIA's vGPU host driver isn't installed, so this card's slices can't be turned on")
		}
		flag := "-d"
		if count > 0 {
			flag = "-e"
		}
		if _, err := sysexec.Output(ctx, h.Runner, "/usr/lib/nvidia/sriov-manage", flag, addr); err != nil {
			return fmt.Errorf("sriov-manage: %w", err)
		}
		return nil
	}
	total, ok := h.readInt(pciDev(addr) + "/sriov_totalvfs")
	if !ok || total == 0 {
		return fmt.Errorf("%s can't be split (no SR-IOV)", addr)
	}
	if count < 0 || count > total {
		return fmt.Errorf("this GPU offers 0 to %d virtual functions", total)
	}
	k := h.kernel()
	// The kernel only changes the count from zero.
	if err := k.WriteSysfs(pciDev(addr)+"/sriov_numvfs", "0"); err != nil {
		return err
	}
	if count > 0 {
		if err := k.WriteSysfs(pciDev(addr)+"/sriov_numvfs", strconv.Itoa(count)); err != nil {
			return err
		}
	}
	return nil
}

// RemoveSlice removes a vGPU instance no running VM uses (a leftover).
func (h *Host) RemoveSlice(ctx context.Context, id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.loadState()
	if vm := st.owners()[id]; vm != "" {
		return fmt.Errorf("the VM %s is using this slice; stop it first", vm)
	}
	switch {
	case uuidRE.MatchString(id):
		if !h.exists("/sys/bus/mdev/devices/" + id) {
			return fmt.Errorf("no vGPU slice %s", id)
		}
		return h.kernel().WriteSysfs("/sys/bus/mdev/devices/"+id+"/remove", "1")
	case pciAddrRE.MatchString(id) && h.exists(pciDev(id)+"/nvidia/current_vgpu_type"):
		return h.kernel().WriteSysfs(pciDev(id)+"/nvidia/current_vgpu_type", "0")
	}
	return fmt.Errorf("%q isn't a vGPU slice", id)
}
