package network

import (
	"fmt"
	"net/netip"
	"strings"
)

// Files is everything a Config (and TimeConfig) turns into, keyed by path
// relative to /. A nil value means the file must not exist.
type Files map[string]*string

func str(s string) *string { return &s }

// Paths written by Render, so the Manager can back them up and restore them.
const (
	InterfacesPath = "etc/network/interfaces"
	ResolvPath     = "etc/resolv.conf"
	HostsPath      = "etc/hosts"
	HostnamePath   = "etc/hostname"
	// DNSHookPath stops dhclient from replacing resolv.conf when the person
	// chose their own DNS servers.
	DNSHookPath = "etc/dhcp/dhclient-enter-hooks.d/hardyos-dns"
)

// NetworkPaths are the files Render owns.
var NetworkPaths = []string{InterfacesPath, ResolvPath, HostsPath, HostnamePath, DNSHookPath, DomainHookPath}

const header = "# Written by HardyOS. Change these settings in Control Panel > Network;\n# edits made here are replaced the next time settings are saved.\n"

// Render turns c into system files. c must be normalized and valid.
func Render(c Config) Files {
	f := Files{
		InterfacesPath: str(RenderInterfaces(c)),
		HostsPath:      str(RenderHosts(c.Hostname)),
		HostnamePath:   str(c.Hostname + "\n"),
		DNSHookPath:    nil,
	}
	if len(c.DNS) > 0 {
		f[ResolvPath] = str(RenderResolv(c.DNS, c.Search))
		f[DNSHookPath] = str("# Written by HardyOS: DNS servers are set in Control Panel > Network,\n# so DHCP must not replace /etc/resolv.conf.\nmake_resolv_conf() { :; }\n")
	}
	// With DNS from DHCP, resolv.conf is left to dhclient.
	return f
}

// RenderInterfaces writes ifupdown's /etc/network/interfaces. DHCP ports use
// allow-hotplug, so a port without a cable doesn't hold up booting; fixed
// addresses, bonds and VLANs use auto.
func RenderInterfaces(c Config) string {
	var b strings.Builder
	b.WriteString(header)
	b.WriteString("\nsource /etc/network/interfaces.d/*\n\nauto lo\niface lo inet loopback\n")

	vlanParents := map[string]bool{}
	for _, v := range c.VLANs {
		vlanParents[v.Parent] = true
	}

	for _, it := range c.Interfaces {
		switch it.Mode {
		case ModeMember:
			// The bond stanza lists its members (bond-slaves).
			continue
		case ModeBridged:
			// The bridge brings it up (bridge-ports).
			fmt.Fprintf(&b, "\niface %s inet manual\n", it.Name)
			writeMTU(&b, it.Name, it.MTU)
		case ModeOff:
			if !vlanParents[it.Name] {
				fmt.Fprintf(&b, "\n# %s is off\n", it.Name)
				continue
			}
			// No address, but up so its VLANs work.
			fmt.Fprintf(&b, "\nauto %s\niface %s inet manual\n", it.Name, it.Name)
			writeMTU(&b, it.Name, it.MTU)
		default:
			writeStanza(&b, it.Name, it.Addressing, nil, true)
		}
	}
	for _, bd := range c.Bonds {
		opts := []string{
			"bond-slaves " + strings.Join(bd.Members, " "),
			"bond-mode " + bd.Policy,
			"bond-miimon 100",
		}
		if bd.Policy == "802.3ad" {
			opts = append(opts, "bond-lacp-rate fast", "bond-xmit-hash-policy layer3+4")
		}
		if bd.Policy == "active-backup" && len(bd.Members) > 0 {
			opts = append(opts, "bond-primary "+bd.Members[0])
		}
		a := bd.Addressing
		if a.Mode == ModeOff || a.Mode == ModeBridged {
			a.Mode = "manual"
		}
		writeStanza(&b, bd.Name, a, opts, false)
	}
	bridges := map[string]bool{}
	for _, br := range c.Bridges {
		bridges[br.Name] = true
		a := br.Addressing
		if a.Mode == ModeOff {
			a.Mode = "manual"
		}
		writeStanza(&b, br.Name, a, BridgeOptions(br), false)
	}
	for _, v := range c.VLANs {
		a := v.Addressing
		if a.Mode == ModeOff {
			a.Mode = "manual"
		}
		opts := []string{"vlan-raw-device " + v.Parent}
		if bridges[v.Parent] {
			// The bridge filters VLANs, so its own port must carry this one.
			opts = append(opts, fmt.Sprintf("pre-up bridge vlan add dev %s vid %d self", v.Parent, v.ID))
		}
		writeStanza(&b, v.Name(), a, opts, false)
	}
	return b.String()
}

// BridgeOptions are a bridge's ifupdown options: no spanning tree or
// forwarding delay (one uplink, nothing to loop), the port's own MAC
// address (DHCP keeps giving the server its address), and VLAN filtering
// with every VLAN allowed on the uplink so VMs can be put on VLANs.
func BridgeOptions(br Bridge) []string {
	opts := []string{
		"bridge-ports " + br.Port,
		"bridge-stp off",
		"bridge-fd 0",
		"bridge-waitport 0",
	}
	if br.MAC != "" {
		opts = append(opts, "hwaddress ether "+br.MAC)
	}
	opts = append(opts,
		"post-up ip link set dev "+br.Name+" type bridge vlan_filtering 1",
		"post-up bridge vlan add dev "+br.Port+" vid 2-4094",
	)
	return opts
}

// writeStanza writes one interface. hotplug (physical ports on DHCP) uses
// allow-hotplug so a port without a cable doesn't hold up booting; bonds and
// VLANs get no hotplug events, so they use auto.
func writeStanza(b *strings.Builder, name string, a Addressing, opts []string, hotplug bool) {
	switch a.Mode {
	case ModeDHCP:
		start := "auto"
		if hotplug {
			start = "allow-hotplug"
		}
		fmt.Fprintf(b, "\n%s %s\niface %s inet dhcp\n", start, name, name)
	case ModeStatic:
		prefix, _ := netip.ParsePrefix(a.Address)
		family := "inet"
		if prefix.Addr().Is6() {
			family = "inet6"
		}
		fmt.Fprintf(b, "\nauto %s\niface %s %s static\n\taddress %s\n", name, name, family, a.Address)
		if a.Gateway != "" {
			fmt.Fprintf(b, "\tgateway %s\n", a.Gateway)
		}
	default: // manual
		fmt.Fprintf(b, "\nauto %s\niface %s inet manual\n", name, name)
	}
	for _, o := range opts {
		fmt.Fprintf(b, "\t%s\n", o)
	}
	writeMTU(b, name, a.MTU)
}

// writeMTU uses a pre-up command because ifupdown's dhcp method has no mtu
// option.
func writeMTU(b *strings.Builder, name string, mtu int) {
	if mtu > 0 {
		fmt.Fprintf(b, "\tpre-up ip link set dev %s mtu %d\n", name, mtu)
	}
}

// RenderResolv writes /etc/resolv.conf.
func RenderResolv(dns, search []string) string {
	var b strings.Builder
	b.WriteString(header)
	for _, d := range dns {
		fmt.Fprintf(&b, "nameserver %s\n", d)
	}
	if len(search) > 0 {
		fmt.Fprintf(&b, "search %s\n", strings.Join(search, " "))
	}
	return b.String()
}

// RenderHosts writes /etc/hosts.
func RenderHosts(hostname string) string {
	return fmt.Sprintf(`127.0.0.1	localhost
127.0.1.1	%s

::1	localhost ip6-localhost ip6-loopback
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
`, hostname)
}

// ChronyPath is chrony's main configuration file.
const ChronyPath = "etc/chrony/chrony.conf"

// RenderChrony writes chrony.conf: Debian's defaults with the chosen time
// servers (or the Debian pool).
func RenderChrony(servers []string) string {
	var b strings.Builder
	b.WriteString(strings.Replace(header, "Network", "Date & Time", 1))
	b.WriteString("\n")
	if len(servers) == 0 {
		b.WriteString("pool 2.debian.pool.ntp.org iburst\n")
	}
	for _, s := range servers {
		fmt.Fprintf(&b, "server %s iburst\n", s)
	}
	b.WriteString(`
# Time servers offered by DHCP, and extra sources dropped in by packages.
sourcedir /run/chrony-dhcp
sourcedir /etc/chrony/sources.d

keyfile /etc/chrony/chrony.keys
driftfile /var/lib/chrony/chrony.drift
ntsdumpdir /var/lib/chrony
logdir /var/log/chrony
maxupdateskew 100.0
rtcsync
makestep 1 3
leapseclist /usr/share/zoneinfo/leap-seconds.list
confdir /etc/chrony/conf.d
`)
	return b.String()
}
