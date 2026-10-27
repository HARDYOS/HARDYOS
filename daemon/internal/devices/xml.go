package devices

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// libvirt <hostdev> fragments. Every value written here has been checked
// against a strict pattern (addresses, UUIDs, IDs, ROM names), so nothing
// needs escaping; xmlAttr still refuses anything unusual as a last guard.
//
// PCI devices use managed='no': HardyOS binds them to vfio-pci itself
// before the VM starts and gives them back to their own driver after it
// stops (libvirt would hand a GPU back to its driver at the wrong time).

func xmlAttr(s string) string {
	if strings.ContainsAny(s, `<>&'"`) {
		panic("devices: unsafe XML value " + strconv.Quote(s))
	}
	return s
}

// HostdevPCI is the fragment for one host PCI function. rom is an absolute
// ROM file path or "".
func HostdevPCI(addr, rom string) (string, error) {
	if !pciAddrRE.MatchString(addr) {
		return "", fmt.Errorf("invalid PCI address %q", addr)
	}
	dom, bus, slot, fn := addr[0:4], addr[5:7], addr[8:10], addr[11:12]
	var b strings.Builder
	b.WriteString("  <hostdev mode='subsystem' type='pci' managed='no'>\n")
	b.WriteString("    <driver name='vfio'/>\n")
	b.WriteString("    <source>\n")
	fmt.Fprintf(&b, "      <address domain='0x%s' bus='0x%s' slot='0x%s' function='0x%s'/>\n", dom, bus, slot, fn)
	b.WriteString("    </source>\n")
	if rom != "" {
		if !filepath.IsAbs(rom) {
			return "", fmt.Errorf("ROM path must be absolute")
		}
		fmt.Fprintf(&b, "    <rom file='%s'/>\n", xmlAttr(rom))
	}
	b.WriteString("  </hostdev>\n")
	return b.String(), nil
}

// HostdevMdev is the fragment for a vGPU (mdev) instance.
func HostdevMdev(uuid string) (string, error) {
	if !uuidRE.MatchString(uuid) {
		return "", fmt.Errorf("invalid mdev UUID %q", uuid)
	}
	return fmt.Sprintf("  <hostdev mode='subsystem' type='mdev' managed='no' model='vfio-pci' display='off'>\n"+
		"    <source>\n      <address uuid='%s'/>\n    </source>\n  </hostdev>\n", uuid), nil
}

// HostdevUSBByID passes a USB device by vendor and product. The VM still
// starts when it's unplugged (startupPolicy optional).
func HostdevUSBByID(vendor, product string) (string, error) {
	if !usbIDRE.MatchString(vendor + ":" + product) {
		return "", fmt.Errorf("invalid USB ID %s:%s", vendor, product)
	}
	return fmt.Sprintf("  <hostdev mode='subsystem' type='usb' managed='yes'>\n"+
		"    <source startupPolicy='optional'>\n      <vendor id='0x%s'/>\n      <product id='0x%s'/>\n    </source>\n  </hostdev>\n", vendor, product), nil
}

// HostdevUSBByAddress passes whatever is plugged into a port, by the bus
// and device number it has now (resolved from the port at start).
func HostdevUSBByAddress(bus, dev int) (string, error) {
	if bus < 1 || bus > 999 || dev < 1 || dev > 999 {
		return "", fmt.Errorf("invalid USB address %d.%d", bus, dev)
	}
	return fmt.Sprintf("  <hostdev mode='subsystem' type='usb' managed='yes'>\n"+
		"    <source>\n      <address bus='%d' device='%d'/>\n    </source>\n  </hostdev>\n", bus, dev), nil
}
