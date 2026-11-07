package network

import (
	"net/netip"
	"testing"
)

func storageStatus() Status {
	return Status{
		Config: Config{Hostname: "c1", Interfaces: []Interface{
			{Name: "enp1s0", Addressing: Addressing{Mode: ModeDHCP}},
			{Name: "enp2s0", Addressing: Addressing{Mode: ModeOff}},
			{Name: "enp3s0", Addressing: Addressing{Mode: ModeOff}},
		}},
		Ports:   []string{"enp1s0", "enp2s0", "enp3s0"},
		Gateway: "192.168.1.1",
		Live: []LiveInterface{
			{Name: "enp1s0", Kind: "port", Carrier: true, SpeedMbps: 1000, Addresses: []string{"192.168.1.21/24"}},
			{Name: "enp2s0", Kind: "port", Carrier: true, SpeedMbps: 10000},
			{Name: "enp3s0", Kind: "port", Carrier: false, SpeedMbps: 0},
			{Name: "wt0", Kind: "other", Addresses: []string{"100.80.0.5/16"}},
		},
	}
}

func TestStorageCandidates(t *testing.T) {
	c := StorageCandidates(storageStatus())
	if len(c) != 4 {
		t.Fatalf("%+v", c)
	}
	if c[0].Interface != "enp2s0" || c[0].Kind != StorageDedicated || c[1].Interface != "enp3s0" || c[1].Warning == "" {
		t.Fatalf("dedicated ports, fastest with link first: %+v", c[:2])
	}
	if c[2].Kind != StorageVLAN || c[3].Kind != StorageShared || c[3].Interface != "enp1s0" || c[3].Warning == "" {
		t.Fatalf("then VLAN, then the LAN with a warning: %+v", c[2:])
	}
}

func TestStoragePlan(t *testing.T) {
	st := storageStatus()
	p := StoragePlan{Kind: StorageDedicated, Interface: "enp2s0", Address: "10.77.0.21/24", MTU: JumboMTU}
	if err := p.Validate(st); err != nil {
		t.Fatal(err)
	}
	c, err := ApplyStoragePlan(st.Config, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(st.Ports); err != nil {
		t.Fatal(err)
	}
	for _, i := range c.Interfaces {
		if i.Name == "enp2s0" && (i.Mode != ModeStatic || i.Address != "10.77.0.21/24" || i.Gateway != "" || i.MTU != JumboMTU) {
			t.Fatalf("storage port %+v", i)
		}
		if i.Name == "enp1s0" && i.Mode != ModeDHCP {
			t.Fatal("the LAN port changed")
		}
	}
	v := StoragePlan{Kind: StorageVLAN, Interface: "enp1s0", VLAN: 77, Address: "10.77.0.21/24"}
	if err := v.Validate(st); err != nil {
		t.Fatal(err)
	}
	c, _ = ApplyStoragePlan(st.Config, v)
	if len(c.VLANs) != 1 || c.VLANs[0].Name() != "enp1s0.77" || c.VLANs[0].Gateway != "" || v.StorageInterface() != "enp1s0.77" {
		t.Fatalf("vlan %+v", c.VLANs)
	}
	if err := c.Validate(st.Ports); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []StoragePlan{
		{Kind: StorageDedicated, Interface: "enp1s0", Address: "10.77.0.21/24"},   // the LAN port
		{Kind: StorageDedicated, Interface: "enp2s0", Address: "8.8.8.8/24"},      // public
		{Kind: StorageDedicated, Interface: "enp2s0", Address: "192.168.1.30/24"}, // the LAN's network
		{Kind: StorageDedicated, Interface: "enp2s0", Address: "10.77.0.0/24"},    // network address
		{Kind: StorageDedicated, Interface: "enp2s0", Address: "10.77.0.21/24", MTU: 4000},
		{Kind: StorageDedicated, Interface: "eth9", Address: "10.77.0.21/24"},
		{Kind: StorageVLAN, Interface: "enp1s0", VLAN: 0, Address: "10.77.0.21/24"},
		{Kind: StorageShared, Interface: "enp1s0", Address: "192.168.1.21/24", MTU: JumboMTU},
		{Kind: "wifi", Interface: "enp2s0", Address: "10.77.0.21/24"},
	} {
		if bad.Validate(st) == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	a, iface, ok := StorageAddress(st, netip.MustParsePrefix("192.168.1.0/24"))
	if !ok || iface != "enp1s0" || a != netip.MustParseAddr("192.168.1.21") {
		t.Fatalf("%v %s %v", a, iface, ok)
	}
	if _, _, ok := StorageAddress(st, netip.MustParsePrefix("100.80.0.0/16")); ok {
		t.Fatal("NetBird's interface counted as the storage network")
	}
	if !JumboCapable(st, "enp2s0") || JumboCapable(st, "enp3s0") {
		t.Fatal("jumbo")
	}
}
