package vms

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"syscall"

	"github.com/hardyos/hardyos/daemon/internal/devices"
)

// USB hot-plug (decision 417): a USB device by vendor:product goes to a
// running VM now, through part D's checks (devices.HotPlugger), and comes
// out again the same way. Persist also adds it to (or takes it off) the
// VM's devices for its next start.

var usbVendorProductRE = regexp.MustCompile(`^[0-9a-f]{4}:[0-9a-f]{4}$`)

// USBArgs plugs a USB device into a running VM, or out of it.
type USBArgs struct {
	ID string `json:"id"`
	// Device is vendor:product (046d:c52b).
	Device string `json:"device"`
	// Persist: also add it to (or remove it from) the VM's devices.
	Persist bool `json:"persist"`
}

func (m *Manager) hotPlugger() (devices.HotPlugger, error) {
	hp, ok := m.Devices.(devices.HotPlugger)
	if !ok || m.Devices == nil {
		return nil, Problems{"plugging USB devices into running VMs isn't available on this server"}
	}
	return hp, nil
}

// liveDevice runs virsh attach-device or detach-device with a fragment.
func (m *Manager) liveDevice(ctx context.Context, st *stored, verb, frag string) error {
	clean, err := checkFragment(frag, RomRunDir)
	if err != nil {
		return err
	}
	host := filepath.Join(st.dir, "hotplug-"+randomHex(6)+".xml")
	name := m.sys(host)
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(name)
	if _, err := f.WriteString(clean); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_, err = m.virsh(ctx, verb, st.spec.ID, host, "--live")
	return err
}

// AttachUSB plugs a USB device into a running VM.
func (m *Manager) AttachUSB(ctx context.Context, a USBArgs) (*VM, error) {
	if !usbVendorProductRE.MatchString(a.Device) {
		return nil, Problems{fmt.Sprintf("%q isn't a USB vendor:product ID like 046d:c52b", a.Device)}
	}
	hp, err := m.hotPlugger()
	if err != nil {
		return nil, err
	}
	unlock, err := m.lockValid(a.ID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	st, err := m.find(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	if m.state(ctx, a.ID) != "running" {
		return nil, Problems{"start the VM first; a VM that's off gets its USB devices in Hardware"}
	}
	for _, d := range st.spec.Devices {
		if d.Kind == devices.KindUSB && d.ID == a.Device {
			return nil, Problems{fmt.Sprintf("%s already has the USB device %s", st.spec.Name, a.Device)}
		}
	}
	if a.Persist && len(st.spec.Devices) >= MaxDevices {
		return nil, Problems{fmt.Sprintf("at most %d passed-through devices", MaxDevices)}
	}
	dev := devices.Device{Kind: devices.KindUSB, ID: a.Device}
	frag, err := hp.HotplugUSB(ctx, a.ID, dev)
	if err != nil {
		return nil, err
	}
	if err := m.liveDevice(ctx, st, "attach-device", frag); err != nil {
		_ = hp.UnplugUSB(context.WithoutCancel(ctx), a.ID, a.Device)
		return nil, fmt.Errorf("plugging %s into the VM: %w", a.Device, err)
	}
	m.statsMu.Lock()
	if m.prepared == nil {
		m.prepared = map[string]bool{}
	}
	m.prepared[a.ID] = true // given back with the VM's devices when it stops
	if m.hotplugged == nil {
		m.hotplugged = map[string][]string{}
	}
	m.hotplugged[a.ID] = append(m.hotplugged[a.ID], a.Device)
	m.statsMu.Unlock()
	if a.Persist {
		st.spec.Devices = append(st.spec.Devices, dev)
		if err := m.saveSpec(st); err != nil {
			return nil, err
		}
	}
	m.log().Info("vms: USB device plugged in", "id", a.ID, "device", a.Device, "persist", a.Persist)
	return m.Get(ctx, a.ID)
}

// DetachUSB takes a hot-plugged (or configured) USB device out of a
// running VM.
func (m *Manager) DetachUSB(ctx context.Context, a USBArgs) (*VM, error) {
	if !usbVendorProductRE.MatchString(a.Device) {
		return nil, Problems{fmt.Sprintf("%q isn't a USB vendor:product ID like 046d:c52b", a.Device)}
	}
	hp, err := m.hotPlugger()
	if err != nil {
		return nil, err
	}
	unlock, err := m.lockValid(a.ID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	st, err := m.find(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	if m.state(ctx, a.ID) != "running" {
		return nil, Problems{"the VM isn't running; change its USB devices in Hardware"}
	}
	frag, err := devices.HostdevUSBByID(a.Device[:4], a.Device[5:])
	if err != nil {
		return nil, err
	}
	if err := m.liveDevice(ctx, st, "detach-device", frag); err != nil {
		return nil, fmt.Errorf("taking %s out of the VM: %w", a.Device, err)
	}
	if err := hp.UnplugUSB(ctx, a.ID, a.Device); err != nil {
		m.log().Warn("vms: forgetting an unplugged USB device", "id", a.ID, "device", a.Device, "err", err)
	}
	m.statsMu.Lock()
	m.hotplugged[a.ID] = slices.DeleteFunc(m.hotplugged[a.ID], func(d string) bool { return d == a.Device })
	m.statsMu.Unlock()
	if a.Persist {
		st.spec.Devices = slices.DeleteFunc(st.spec.Devices, func(d devices.Device) bool { return d.Kind == devices.KindUSB && d.ID == a.Device })
		if err := m.saveSpec(st); err != nil {
			return nil, err
		}
	}
	m.log().Info("vms: USB device unplugged", "id", a.ID, "device", a.Device)
	return m.Get(ctx, a.ID)
}

// liveUSB lists the USB devices plugged into a running VM by hand.
func (m *Manager) liveUSB(id string) []string {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	out := append([]string{}, m.hotplugged[id]...)
	sort.Strings(out)
	return out
}

func (m *Manager) forgetHotplugged(id string) {
	m.statsMu.Lock()
	delete(m.hotplugged, id)
	m.statsMu.Unlock()
}
