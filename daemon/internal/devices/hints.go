package devices

import "strings"

// amdResetBug lists AMD GPUs (Polaris, Vega, Navi 10/12/14) that often
// can't reset after a VM stops and that the vendor-reset kernel module
// handles. Device IDs, lower case.
var amdResetBug = map[string]bool{}

func init() {
	for _, id := range strings.Fields(`
		67c0 67c1 67c2 67c4 67c7 67c8 67c9 67ca 67cc 67cf 67d0 67df 6fdf
		67e0 67e1 67e3 67e7 67e8 67e9 67eb 67ef 67ff
		6980 6981 6985 6986 6987 6995 6997 699f
		6860 6861 6862 6863 6864 6867 6868 6869 686a 686b 686c 686d 686e 687f
		66a0 66a1 66a2 66a3 66a4 66a7 66af
		7310 7312 7318 7319 731a 731b 731e 731f
		7360 7362
		7340 7341 7347 734f`) {
		amdResetBug[id] = true
	}
}

// gpuHints are plain-words tips for a GPU.
func gpuHints(p PCIDevice, g GPU) []string {
	hints := []string{}
	if g.Vendor == "amd" && amdResetBug[p.DeviceID] {
		if contains(p.ResetMethods, "device_specific") {
			hints = append(hints, "vendor-reset is looking after this card's reset, so it comes back cleanly after a VM stops.")
		} else {
			hints = append(hints, "AMD cards of this generation often can't reset themselves after a VM stops, so the card may only come back after the server restarts. The vendor-reset kernel module fixes this for this model.")
		}
	} else if !p.Resettable {
		hints = append(hints, "This card has no way to reset itself, so after a VM stops it may need a server restart before it works again.")
	}
	if g.Vendor == "nvidia" && (p.Driver == "" || p.Driver == "nouveau") {
		hints = append(hints, "Install NVIDIA's driver (NVIDIA setup, below) so Docker apps can use this card for video and AI.")
	}
	if p.BootVGA && g.Problem == "" {
		hints = append(hints, "This card shows the server's console, which goes blank while a VM has the card.")
	}
	if g.VGPU != nil && g.VGPU.Mode == ModeSRIOVVF && g.VGPU.VFs == 0 {
		hints = append(hints, "This GPU can be split into virtual GPUs for several VMs (SR-IOV).")
	}
	return hints
}
