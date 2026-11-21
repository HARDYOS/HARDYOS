package devices

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// HotPlugger lends USB devices to a VM that is already running (decision
// 417). The VM engine attaches the fragment with virsh; the device counts
// as the VM's (inventory, other VMs' checks) until it's unplugged or the
// VM's devices are released when it stops.
type HotPlugger interface {
	// HotplugUSB checks a USB device by vendor:product like Check does
	// (devices the server needs, other VMs' devices, hubs), refuses one a
	// program on the server has open (the UPS monitor, an app's Zigbee
	// stick) and, unless opt.AllowInput, a keyboard or mouse, and records
	// it as the running VM's. It returns the <hostdev> fragment to attach.
	HotplugUSB(ctx context.Context, vm string, d Device, opt HotplugOptions) (string, error)
	// UnplugUSB forgets a hot-plugged device (after it was detached).
	UnplugUSB(ctx context.Context, vm, id string) error
}

// HotplugOptions are what the person confirmed.
type HotplugOptions struct {
	// AllowInput: a keyboard or mouse may go (the server's console loses it).
	AllowInput bool `json:"allowInput"`
}

// HotplugUSB implements HotPlugger.
func (h *Host) HotplugUSB(ctx context.Context, vm string, d Device, opt HotplugOptions) (string, error) {
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
	inv := h.inventory(ctx, st)
	pl, probs := h.plan(ctx, vm, []Device{d}, st, inv)
	if len(probs) > 0 {
		return "", probs
	}
	// Every device with that ID goes (libvirt passes them by ID): none may
	// be busy on the server, and none an input device unless confirmed.
	for _, u := range usbAllByID(inv.USB, d.ID) {
		if users := h.openers(h.usbNodes(u)); len(users) > 0 {
			return "", Problems{{Device: d.ID, Message: fmt.Sprintf("The USB device %s (port %s) is in use on the server by %s; stop that first.", d.ID, u.Port, usbUsers(users))}}
		}
		if u.Input && !opt.AllowInput {
			return "", Problems{{Device: d.ID, Message: fmt.Sprintf("The USB device %s (port %s) is a keyboard or mouse: the server's own console loses it while the VM has it. Confirm to plug it in anyway.", d.ID, u.Port)}}
		}
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

// usbNodes are the device files of a USB device: its usbfs node, and the
// serial ports and HID raw devices its interfaces made.
func (h *Host) usbNodes(u *USBDevice) map[string]bool {
	out := map[string]bool{}
	if u.Bus > 0 && u.Dev > 0 {
		out[fmt.Sprintf("/dev/bus/usb/%03d/%03d", u.Bus, u.Dev)] = true
	}
	base := h.path("/sys/bus/usb/devices/" + u.Port)
	for _, pat := range []string{":*/tty*", ":*/tty/tty*", ":*/*/hidraw/hidraw*", ":*/*/input/input*/event*"} {
		matches, _ := filepath.Glob(base + pat)
		for _, mt := range matches {
			name := filepath.Base(mt)
			if devNodeRE.MatchString(name) {
				if strings.HasPrefix(name, "event") {
					out["/dev/input/"+name] = true
				} else {
					out["/dev/"+name] = true
				}
			}
		}
	}
	return out
}

var devNodeRE = regexp.MustCompile(`^(ttyUSB|ttyACM|hidraw|event)[0-9]{1,3}$`)

func usbUsers(users []DeviceUser) string {
	var who []string
	for _, u := range users {
		w := u.Process
		switch {
		case u.App != "":
			w = "the app " + u.App
		case u.Container:
			w = "a Docker container (" + u.Process + ")"
		}
		if !slices.Contains(who, w) {
			who = append(who, w)
		}
	}
	return strings.Join(who, " and ")
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
