package install

import (
	"fmt"
	"net/netip"
	"strings"
)

func renderHosts(hostname string) string {
	return fmt.Sprintf(`127.0.0.1	localhost
127.0.1.1	%s

::1	localhost ip6-localhost ip6-loopback
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
`, hostname)
}

func renderResolv(dns []string) string {
	var b strings.Builder
	b.WriteString("# Written by the HardyOS installer\n")
	for _, d := range dns {
		fmt.Fprintf(&b, "nameserver %s\n", d)
	}
	return b.String()
}

// RenderInterfaces writes /etc/network/interfaces (ifupdown). With DHCP every
// physical interface asks for an address, so the server comes up on whichever
// port is plugged in. With a static address the chosen interface gets it and
// the others stay on DHCP.
func RenderInterfaces(n Network, nics []string) string {
	var b strings.Builder
	b.WriteString("# Written by the HardyOS installer. Network settings will move to the\n# Control Panel; until then edit this file and run \"systemctl restart networking\".\n\n")
	b.WriteString("source /etc/network/interfaces.d/*\n\nauto lo\niface lo inet loopback\n")
	staticDone := false
	for _, nic := range nics {
		if n.Mode == "static" && nic == n.Interface {
			writeStatic(&b, n)
			staticDone = true
			continue
		}
		fmt.Fprintf(&b, "\nallow-hotplug %s\niface %s inet dhcp\n", nic, nic)
	}
	if n.Mode == "static" && !staticDone {
		writeStatic(&b, n)
	}
	return b.String()
}

func writeStatic(b *strings.Builder, n Network) {
	prefix, _ := netip.ParsePrefix(n.Address)
	family := "inet"
	if prefix.Addr().Is6() {
		family = "inet6"
	}
	fmt.Fprintf(b, "\nauto %s\niface %s %s static\n\taddress %s\n", n.Interface, n.Interface, family, n.Address)
	if n.Gateway != "" {
		fmt.Fprintf(b, "\tgateway %s\n", n.Gateway)
	}
}
