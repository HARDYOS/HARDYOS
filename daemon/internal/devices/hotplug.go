package devices

import (
	"context"
	"fmt"
	"slices"
	"time"
)

// HotPlugger lends USB devices to a VM that is already running (decision
// 417). The VM engine attaches the fragment with virsh; the device counts
// as the VM's (inventory, other VMs' checks) until it's unplugged or the
// VM's devices are released when it stops.
type HotPlugger interface {
	// HotplugUSB checks a USB device by vendor:product like Check does
	// (devices the server needs, other VMs' devices, hubs) and records it
	// as the running VM's. It returns the <hostdev> fragment to attach.
	HotplugUSB(ctx context.Context, vm string, d Device) (string, error)
	// UnplugUSB forgets a hot-plugged device (after it was detached).
	UnplugUSB(ctx context.Context, vm, id string) error
}

// HotplugUSB implements HotPlugger.
func (h *Host) HotplugUSB(ctx context.Context, vm string, d Device) (string, error) {
	if d.Kind != KindUSB || !usbIDRE.MatchString(d.ID) || d.VGPUType != "" || d.ROMFile != "" || d.Primary {
		return "", Problems{{Device: d.ID, Message: "Only a USB device by its vendor:product ID (like 046d:c52b) can be plugged into a running VM."}}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.loadState()
	vs := st.VMs[vm]
	if vs != nil && slices.Contains(vs.USB, d.ID) {
		return "", Problems{{Device: d.ID, Message: fmt.Sprintf("The USB device %s is already with the VM %s.", d.ID, vm)}}
	}
	if vs != nil && vs.Phase != phaseReady {
		return "", fmt.Errorf("the VM %s's devices are still being set up", vm)
	}
	pl, probs := h.plan(ctx, vm, []Device{d}, st, h.inventory(ctx, st))
	if len(probs) > 0 {
		return "", probs
	}
	if len(pl.items) != 1 || len(pl.bind) != 0 {
		return "", fmt.Errorf("unexpected plan for the USB device %s", d.ID)
	}
	frag, err := HostdevUSBByID(d.ID[:4], d.ID[5:])
	if err != nil {
		return "", err
	}
	if vs == nil {
		vs = &vmState{Phase: phaseReady, Devices: []Device{}, ReadyAt: time.Now().UTC()}
		st.VMs[vm] = vs
	}
	vs.Devices = append(vs.Devices, d)
	vs.USB = append(vs.USB, d.ID)
	if err := h.saveState(st); err != nil {
		return "", err
	}
	return frag, nil
}

// UnplugUSB implements HotPlugger.
func (h *Host) UnplugUSB(_ context.Context, vm, id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.loadState()
	vs := st.VMs[vm]
	if vs == nil {
		return nil
	}
	vs.USB = slices.DeleteFunc(vs.USB, func(u string) bool { return u == id })
	vs.Devices = slices.DeleteFunc(vs.Devices, func(d Device) bool { return d.Kind == KindUSB && d.ID == id })
	return h.saveState(st)
}
