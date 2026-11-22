package devices

import (
	"context"
	"strings"
	"testing"
)

func TestHotplugUSB(t *testing.T) {
	f := server(t)
	h := f.host()
	ctx := context.Background()
	f.usbDev("1-5", "0781", "5583")

	frag, err := h.HotplugUSB(ctx, "web", Device{Kind: KindUSB, ID: "0781:5583"}, HotplugOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(frag, "<vendor id='0x0781'/>") || !strings.Contains(frag, "<product id='0x5583'/>") {
		t.Fatalf("fragment = %s", frag)
	}
	// It's the VM's now: another VM can't have it, and it shows.
	if p := problems(t, h.Check(ctx, "other", []Device{{Kind: KindUSB, ID: "0781:5583"}})); !hasProblem(p, "VM web") {
		t.Fatalf("problems = %v", p)
	}
	if _, err := h.HotplugUSB(ctx, "web", Device{Kind: KindUSB, ID: "0781:5583"}, HotplugOptions{}); err == nil {
		t.Fatal("plugged twice")
	}
	inv, _ := h.Inventory(ctx)
	found := false
	for _, u := range inv.USB {
		if u.Port == "1-5" {
			found = true
			if u.Owner != "web" || u.Controller != "0000:00:14.0" {
				t.Fatalf("usb = %+v", u)
			}
		}
	}
	if !found {
		t.Fatal("the stick isn't listed")
	}
	if err := h.UnplugUSB(ctx, "web", "0781:5583"); err != nil {
		t.Fatal(err)
	}
	if err := h.Check(ctx, "other", []Device{{Kind: KindUSB, ID: "0781:5583"}}); err != nil {
		t.Fatalf("after unplugging: %v", err)
	}
	// Only vendor:product, never a port or another kind.
	for _, d := range []Device{{Kind: KindUSB, ID: "1-5"}, {Kind: KindPCI, ID: "0000:01:00.0"}, {Kind: KindUSB, ID: "0781:5583", Primary: true}} {
		if _, err := h.HotplugUSB(ctx, "web", d, HotplugOptions{}); err == nil {
			t.Errorf("%+v hot-plugged", d)
		}
	}
}

// A device the server needs (the boot stick) can't be hot-plugged either.
func TestHotplugRefusesCritical(t *testing.T) {
	f := server(t)
	h := f.host()
	f.usbDev("1-8", "0951", "1666")
	stick := f.devPath("0000:00:14.0") + "/usb1/1-8/1-8:1.0/host7/target7:0:0/7:0:0:0/block/sdy"
	f.mkdir(stick)
	f.link("/sys/class/block/sdy", stick)
	f.file("/dev/sdy", "")
	f.link("/dev/disk/by-id/usb-Kingston-BOOT", "/dev/sdy")
	f.file("/var/lib/hardyos/boot.json", `{"pool":"rpool","disks":[{"byId":"/dev/disk/by-id/usb-Kingston-BOOT","espPartUUID":"11111111-aaaa-bbbb-cccc-000000000001"}]}`)
	if _, err := h.HotplugUSB(context.Background(), "web", Device{Kind: KindUSB, ID: "0951:1666"}, HotplugOptions{}); err == nil || !strings.Contains(err.Error(), "can't go to a VM") {
		t.Fatalf("boot stick: %v", err)
	}
}
