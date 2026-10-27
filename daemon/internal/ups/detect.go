package ups

import (
	"bufio"
	"context"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Device is a UPS found on USB.
type Device struct {
	Driver    string `json:"driver"`
	Port      string `json:"port"`
	VendorID  string `json:"vendorId"`
	ProductID string `json:"productId"`
	Vendor    string `json:"vendor"`
	Product   string `json:"product"`
	Serial    string `json:"serial"`
	Bus       string `json:"bus"`
}

// knownVendors are USB vendor IDs of UPS makers whose UPSes speak HID
// power device class (usbhid-ups), for the fallback scan.
var knownVendors = map[string]string{
	"0764": "CyberPower", "051d": "APC", "0463": "Eaton", "09ae": "Tripp Lite", "06da": "Phoenixtec",
	"050d": "Belkin", "0d9f": "Powercom", "10af": "Liebert", "0665": "INNO TECH",
	"0592": "Powerware", "075d": "Riello", "2b2d": "AEG",
}

// parseScanner reads nut-scanner's output ("[nutdev1]" sections of
// key = "value" lines).
func parseScanner(out []byte) []Device {
	var devs []Device
	var cur *Device
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			devs = append(devs, Device{})
			cur = &devs[len(devs)-1]
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || cur == nil {
			continue
		}
		v = unquote(strings.TrimSpace(v))
		switch strings.TrimSpace(k) {
		case "driver":
			cur.Driver = v
		case "port":
			cur.Port = v
		case "vendorid":
			cur.VendorID = strings.ToLower(v)
		case "productid":
			cur.ProductID = strings.ToLower(v)
		case "vendor":
			cur.Vendor = v
		case "product":
			cur.Product = v
		case "serial":
			cur.Serial = v
		case "bus":
			cur.Bus = v
		}
	}
	var out2 []Device
	for _, d := range devs {
		if Drivers[d.Driver] && d.Driver != "dummy-ups" {
			out2 = append(out2, d)
		}
	}
	return out2
}

func readTrim(root fs.FS, p string) string {
	b, err := fs.ReadFile(root, p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// scanSysfs finds USB devices from known UPS makers with a HID interface.
func scanSysfs(root fs.FS) []Device {
	entries, err := fs.ReadDir(root, "sys/bus/usb/devices")
	if err != nil {
		return nil
	}
	var out []Device
	for _, e := range entries {
		dir := path.Join("sys/bus/usb/devices", e.Name())
		vid := strings.ToLower(readTrim(root, path.Join(dir, "idVendor")))
		if vid == "" {
			continue
		}
		maker, known := knownVendors[vid]
		if !known {
			continue
		}
		hid := false
		subs, _ := fs.ReadDir(root, dir)
		for _, s := range subs {
			if strings.HasPrefix(s.Name(), e.Name()+":") && readTrim(root, path.Join(dir, s.Name(), "bInterfaceClass")) == "03" {
				hid = true
			}
		}
		if !hid {
			continue
		}
		vendor := readTrim(root, path.Join(dir, "manufacturer"))
		if vendor == "" {
			vendor = maker
		}
		out = append(out, Device{Driver: "usbhid-ups", Port: "auto", VendorID: vid, ProductID: strings.ToLower(readTrim(root, path.Join(dir, "idProduct"))),
			Vendor: vendor, Product: readTrim(root, path.Join(dir, "product")), Serial: readTrim(root, path.Join(dir, "serial")), Bus: readTrim(root, path.Join(dir, "busnum"))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VendorID+out[i].ProductID < out[j].VendorID+out[j].ProductID })
	return out
}

// Detect looks for UPSes on USB: nut-scanner first, then (if it isn't
// installed or found nothing) known UPS makers in sysfs. It needs root.
func Detect(ctx context.Context, r sysexec.Runner, root fs.FS) []Device {
	if res, err := r.Run(ctx, nil, "nut-scanner", "-U", "-q"); err == nil && res.ExitCode == 0 {
		if d := parseScanner(res.Stdout); len(d) > 0 {
			return d
		}
	}
	d := scanSysfs(root)
	if d == nil {
		d = []Device{}
	}
	return d
}
