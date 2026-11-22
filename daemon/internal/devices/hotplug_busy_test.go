package devices

import (
	"context"
	"strings"
	"testing"
)

// Busy devices (the UPS monitor, an app's Zigbee stick) and keyboards stay
// with the server; a keyboard goes only when the person confirms.
func TestHotplugRefusesBusyAndInput(t *testing.T) {
	f := server(t)
	h := f.host()
	ctx := context.Background()
	f.usbDev("1-5", "0764", "0501") // a UPS
	f.procOpener(4242, "usbhid-ups", "0::/system.slice/nut-driver.service", "/dev/bus/usb/001/013")
	if _, err := h.HotplugUSB(ctx, "web", Device{Kind: KindUSB, ID: "0764:0501"}, HotplugOptions{}); err == nil || !strings.Contains(err.Error(), "in use on the server by usbhid-ups") {
		t.Fatalf("UPS: %v", err)
	}
	f.usbDev("1-6", "1a86", "55d4") // a Zigbee stick, an app's serial port
	iface := f.devPath("0000:00:14.0") + "/usb1/1-6/1-6:1.0"
	f.mkdir(iface + "/ttyUSB0")
	f.link("/sys/bus/usb/devices/1-6:1.0", iface)
	f.procOpener(4343, "node", "0::/hardyos.slice/hardyos-app-zigbee2mqtt.slice/docker-abc.scope", "/dev/ttyUSB0")
	if _, err := h.HotplugUSB(ctx, "web", Device{Kind: KindUSB, ID: "1a86:55d4"}, HotplugOptions{}); err == nil || !strings.Contains(err.Error(), "the app zigbee2mqtt") {
		t.Fatalf("Zigbee stick: %v", err)
	}
	f.usbDev("1-10", "046d", "c31c") // a keyboard
	kb := f.devPath("0000:00:14.0") + "/usb1/1-10/1-10:1.0"
	f.file(kb+"/bInterfaceClass", "03\n")
	f.link("/sys/bus/usb/devices/1-10:1.0", kb)
	if _, err := h.HotplugUSB(ctx, "web", Device{Kind: KindUSB, ID: "046d:c31c"}, HotplugOptions{}); err == nil || !strings.Contains(err.Error(), "keyboard or mouse") {
		t.Fatalf("keyboard: %v", err)
	}
	if _, err := h.HotplugUSB(ctx, "web", Device{Kind: KindUSB, ID: "046d:c31c"}, HotplugOptions{AllowInput: true}); err != nil {
		t.Fatalf("confirmed keyboard: %v", err)
	}
	inv, _ := h.Inventory(ctx)
	for _, u := range inv.USB {
		if u.Port == "1-10" && !u.Input {
			t.Fatal("the keyboard isn't marked as input")
		}
	}
}
