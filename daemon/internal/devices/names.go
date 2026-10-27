package devices

import (
	"bufio"
	"os"
	"strings"
)

// Device names come from the pci.ids and usb.ids databases (pciutils and
// usbutils), read once per inventory and only for the IDs present.

var pciIDFiles = []string{"/usr/share/misc/pci.ids", "/usr/share/hwdata/pci.ids"}
var usbIDFiles = []string{"/usr/share/misc/usb.ids", "/var/lib/usbutils/usb.ids", "/usr/share/hwdata/usb.ids"}

// idNames maps "vvvv" to a vendor name and "vvvv:dddd" to a device name.
type idNames map[string]string

// loadIDs reads the vendor and device names wanted from the first ids file
// found. want holds "vvvv" and "vvvv:dddd" keys.
func (h *Host) loadIDs(files []string, want map[string]bool) idNames {
	out := idNames{}
	if len(want) == 0 {
		return out
	}
	for _, f := range files {
		fh, err := os.Open(h.path(f))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		vendor := ""
		for sc.Scan() {
			line := sc.Text()
			if line == "" || line[0] == '#' {
				continue
			}
			// The class list at the end of pci.ids ("C 03  Display controller").
			if strings.HasPrefix(line, "C ") {
				break
			}
			switch {
			case line[0] != '\t':
				id, name, ok := splitID(line)
				vendor = ""
				if ok {
					vendor = id
					if want[id] {
						out[id] = name
					}
				}
			case len(line) > 1 && line[1] != '\t' && vendor != "":
				id, name, ok := splitID(line[1:])
				if ok && want[vendor+":"+id] {
					out[vendor+":"+id] = name
				}
			}
		}
		fh.Close()
		return out
	}
	return out
}

func splitID(s string) (id, name string, ok bool) {
	if len(s) < 6 || s[4] != ' ' {
		return "", "", false
	}
	id = strings.ToLower(s[:4])
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return "", "", false
		}
	}
	return id, strings.TrimSpace(s[5:]), true
}

// classNames are plain-words names for the PCI classes people meet, keyed
// by class and subclass ("0300") or class only ("03").
var classNames = map[string]string{
	"0100": "SCSI storage controller", "0101": "IDE storage controller", "0104": "RAID controller",
	"0106": "SATA controller", "0107": "SAS controller", "0108": "NVMe drive", "01": "Storage controller",
	"0200": "Ethernet network port", "0280": "Wi-Fi", "02": "Network controller",
	"0300": "Graphics card", "0302": "Graphics accelerator", "0380": "Graphics card", "03": "Display controller",
	"0400": "Video capture", "0401": "Audio device", "0403": "Audio (HDMI/DisplayPort)", "04": "Multimedia device",
	"0500": "Memory controller", "05": "Memory controller",
	"0600": "Host bridge", "0601": "ISA bridge", "0604": "PCI bridge", "06": "Bridge",
	"0700": "Serial port", "0780": "Communication controller", "07": "Communication controller",
	"0805": "SD card reader", "0880": "System peripheral", "08": "System peripheral",
	"0c03": "USB controller", "0c05": "SMBus", "0c80": "Serial bus controller", "0c": "Serial bus controller",
	"0d": "Wireless controller", "10": "Encryption controller", "11": "Signal processing controller",
	"12": "Processing accelerator", "13": "Non-essential instrumentation",
}

// className names a PCI class ("0x030000").
func className(class string) string {
	c := strings.TrimPrefix(strings.ToLower(class), "0x")
	if len(c) >= 4 {
		if n, ok := classNames[c[:4]]; ok {
			return n
		}
	}
	if len(c) >= 2 {
		if n, ok := classNames[c[:2]]; ok {
			return n
		}
	}
	return "Other device"
}

// Vendor IDs HardyOS knows about.
const (
	vendorNVIDIA = "10de"
	vendorAMD    = "1002"
	vendorIntel  = "8086"
)

// vendorKey is a short vendor name for logic and icons.
func vendorKey(id string) string {
	switch id {
	case vendorNVIDIA:
		return "nvidia"
	case vendorAMD:
		return "amd"
	case vendorIntel:
		return "intel"
	}
	return "other"
}
