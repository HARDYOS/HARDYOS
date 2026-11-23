package network

// The cluster's storage network (docs/plans/cluster.md section 5.1): a
// dedicated port (best), a VLAN on the LAN port (needs switch support), or
// the LAN itself (warned against). It is set as a static address with no
// gateway and applied like any other network change: through the Network
// settings, confirmed or rolled back automatically (decision 343).

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
)

// Storage network kinds.
const (
	StorageDedicated = "dedicated" // its own port
	StorageVLAN      = "vlan"      // a VLAN on a port that also carries the LAN
	StorageShared    = "lan"       // the LAN port itself (an extra address)
)

// DefaultStorageSubnet is the suggested storage network.
var DefaultStorageSubnet = netip.MustParsePrefix("10.77.0.0/24")

// JumboMTU is the MTU offered when every member's port supports it.
const JumboMTU = 9000

// StorageCandidate is one way to carry the storage network on this server.
type StorageCandidate struct {
	Kind      string `json:"kind"`
	Interface string `json:"interface"` // port or bond; the VLAN's parent for vlan
	SpeedMbps int    `json:"speedMbps"`
	Carrier   bool   `json:"carrier"`
	// DefaultRoute: the LAN's port (the default route leaves through it).
	DefaultRoute bool `json:"defaultRoute"`
	// Warning explains a worse choice.
	Warning string `json:"warning,omitempty"`
}

// StorageCandidates ranks the ways this server can reach the storage
// network: unused ports that aren't the default route's, fastest first
// (with carrier before without); then a VLAN on the LAN port; then the LAN
// itself.
func StorageCandidates(st Status) []StorageCandidate {
	live := map[string]LiveInterface{}
	for _, l := range st.Live {
		live[l.Name] = l
	}
	lanPort := defaultRoutePort(st)
	used := usedPorts(st.Config)
	var dedicated []StorageCandidate
	for _, p := range st.Ports {
		if p == lanPort || used[p] {
			continue
		}
		l := live[p]
		c := StorageCandidate{Kind: StorageDedicated, Interface: p, SpeedMbps: l.SpeedMbps, Carrier: l.Carrier}
		if !l.Carrier {
			c.Warning = "no cable or link on this port right now"
		}
		dedicated = append(dedicated, c)
	}
	sort.SliceStable(dedicated, func(i, j int) bool {
		a, b := dedicated[i], dedicated[j]
		if a.Carrier != b.Carrier {
			return a.Carrier
		}
		if a.SpeedMbps != b.SpeedMbps {
			return a.SpeedMbps > b.SpeedMbps
		}
		return a.Interface < b.Interface
	})
	out := dedicated
	if lanPort != "" {
		l := live[lanPort]
		out = append(out,
			StorageCandidate{Kind: StorageVLAN, Interface: lanPort, SpeedMbps: l.SpeedMbps, Carrier: l.Carrier, DefaultRoute: true,
				Warning: "shares the LAN port's bandwidth; your switch must carry the VLAN"},
			StorageCandidate{Kind: StorageShared, Interface: lanPort, SpeedMbps: l.SpeedMbps, Carrier: l.Carrier, DefaultRoute: true,
				Warning: "storage traffic shares the wire with everyone on the LAN: slower, and only as private as the LAN"})
	}
	return out
}

// defaultRoutePort finds the port (or bond) whose network holds the
// current gateway.
func defaultRoutePort(st Status) string {
	gw, err := netip.ParseAddr(st.Gateway)
	if err != nil {
		return ""
	}
	parentOf := map[string]string{}
	for _, b := range st.Config.Bridges {
		parentOf[b.Name] = b.Port
	}
	for _, v := range st.Config.VLANs {
		parentOf[v.Name()] = v.Parent
	}
	for _, l := range st.Live {
		for _, a := range l.Addresses {
			p, err := netip.ParsePrefix(a)
			if err != nil || !p.Masked().Contains(gw) {
				continue
			}
			name := l.Name
			for parentOf[name] != "" {
				name = parentOf[name]
			}
			return name
		}
	}
	return ""
}

// usedPorts are ports already carrying something (an address, a bond, a
// bridge or VLANs).
func usedPorts(c Config) map[string]bool {
	u := map[string]bool{}
	for _, i := range c.Interfaces {
		if i.Mode != ModeOff && i.Mode != "" {
			u[i.Name] = true
		}
	}
	for _, b := range c.Bonds {
		for _, m := range b.Members {
			u[m] = true
		}
	}
	for _, v := range c.VLANs {
		u[v.Parent] = true
	}
	for _, b := range c.Bridges {
		u[b.Port] = true
	}
	return u
}

// StoragePlan is the storage network the wizard chose for this server.
type StoragePlan struct {
	Kind      string `json:"kind"`
	Interface string `json:"interface"`
	// VLAN is the VLAN id (Kind vlan).
	VLAN int `json:"vlan,omitempty"`
	// Address is this server's address with the subnet, e.g. 10.77.0.21/24.
	Address string `json:"address"`
	// MTU: 0 (1500) or JumboMTU; jumbo frames only when every member's
	// port and the switch support it.
	MTU int `json:"mtu,omitempty"`
}

// StorageInterface is the interface name that carries the storage address
// under this plan.
func (p StoragePlan) StorageInterface() string {
	if p.Kind == StorageVLAN {
		return VLAN{Parent: p.Interface, ID: p.VLAN}.Name()
	}
	return p.Interface
}

// Validate checks the plan on its own: a host address in a private IPv4
// network that isn't the LAN's (unless sharing the LAN), and no gateway
// ever.
func (p StoragePlan) Validate(st Status) error {
	var probs []string
	add := func(format string, a ...any) { probs = append(probs, fmt.Sprintf(format, a...)) }
	pre, err := netip.ParsePrefix(p.Address)
	switch {
	case err != nil || !pre.Addr().Is4():
		add("the storage address %q must look like 10.77.0.21/24", p.Address)
	case !pre.Addr().IsPrivate():
		add("the storage network must use private addresses (10.x, 172.16-31.x or 192.168.x)")
	case pre.Bits() < 8 || pre.Bits() > 30:
		add("the storage network size /%d doesn't fit (use /8 to /30)", pre.Bits())
	case pre.Addr() == pre.Masked().Addr() || isBroadcast(pre):
		add("%s is the network's own or broadcast address; pick a host address", p.Address)
	}
	if p.MTU != 0 && p.MTU != 1500 && p.MTU != JumboMTU {
		add("the storage network's MTU is 1500 or %d", JumboMTU)
	}
	if !slices.Contains(st.Ports, p.Interface) && !slices.ContainsFunc(st.Config.Bonds, func(b Bond) bool { return b.Name == p.Interface }) {
		add("%q isn't a port or bond of this server", p.Interface)
	}
	lan := defaultRoutePort(st)
	switch p.Kind {
	case StorageDedicated:
		if p.Interface == lan {
			add("%s carries the LAN; choose another port, a VLAN, or share the LAN", p.Interface)
		}
	case StorageVLAN:
		if p.VLAN < 1 || p.VLAN > 4094 {
			add("the VLAN id must be 1-4094")
		}
	case StorageShared:
		if p.Interface != lan {
			add("sharing the LAN means using the LAN's port (%s)", lan)
		}
		if p.MTU == JumboMTU {
			add("jumbo frames can't be used on the LAN itself")
		}
	default:
		add("choose a dedicated port, a VLAN or the LAN")
	}
	if err == nil && pre.Addr().Is4() {
		for _, l := range st.Live {
			if l.Name == p.StorageInterface() && p.Kind != StorageShared {
				continue
			}
			for _, a := range l.Addresses {
				if q, err := netip.ParsePrefix(a); err == nil && q.Masked().Overlaps(pre.Masked()) && p.Kind != StorageShared {
					add("%s overlaps %s's network %s; the storage network needs its own", pre.Masked(), l.Name, q.Masked())
				}
			}
		}
	}
	if len(probs) > 0 {
		return &ValidationError{Problems: probs}
	}
	return nil
}

// ApplyStoragePlan returns c with the storage network set up as planned:
// the port (or the VLAN on it) gets the static address without gateway
// and the MTU. Sharing the LAN changes nothing in the settings: ifupdown
// can't add a second address to an interface here, so the cluster uses
// the LAN address itself (the subnet must be the LAN's then).
func ApplyStoragePlan(c Config, p StoragePlan) (Config, error) {
	out := c
	out.Interfaces = slices.Clone(c.Interfaces)
	out.VLANs = slices.Clone(c.VLANs)
	mtu := p.MTU
	if mtu == 1500 {
		mtu = 0
	}
	addr := Addressing{Mode: ModeStatic, Address: p.Address, MTU: mtu}
	switch p.Kind {
	case StorageDedicated:
		found := false
		for i := range out.Interfaces {
			if out.Interfaces[i].Name == p.Interface {
				out.Interfaces[i].Addressing = addr
				found = true
			}
		}
		if !found {
			for i := range out.Bonds {
				if out.Bonds[i].Name == p.Interface {
					out.Bonds = slices.Clone(c.Bonds)
					out.Bonds[i].Addressing = addr
					found = true
				}
			}
		}
		if !found {
			out.Interfaces = append(out.Interfaces, Interface{Name: p.Interface, Addressing: addr})
		}
	case StorageVLAN:
		replaced := false
		for i := range out.VLANs {
			if out.VLANs[i].Parent == p.Interface && out.VLANs[i].ID == p.VLAN {
				out.VLANs[i].Addressing = addr
				replaced = true
			}
		}
		if !replaced {
			out.VLANs = append(out.VLANs, VLAN{Parent: p.Interface, ID: p.VLAN, Addressing: addr})
		}
		if mtu == JumboMTU {
			// The parent must carry the bigger frames too.
			for i := range out.Interfaces {
				if out.Interfaces[i].Name == p.Interface && out.Interfaces[i].MTU < JumboMTU {
					out.Interfaces[i].MTU = JumboMTU
				}
			}
		}
	case StorageShared:
		return out, nil
	default:
		return c, errors.New("unknown storage network kind")
	}
	out.Normalize()
	return out, nil
}

// StorageAddress finds this server's address in the storage subnet and the
// interface carrying it, from the live interfaces.
func StorageAddress(st Status, subnet netip.Prefix) (netip.Addr, string, bool) {
	for _, l := range st.Live {
		for _, a := range l.Addresses {
			p, err := netip.ParsePrefix(a)
			if err == nil && subnet.Contains(p.Addr()) && !strings.HasPrefix(l.Name, "wt") {
				return p.Addr(), l.Name, true
			}
		}
	}
	return netip.Addr{}, "", false
}

// JumboCapable reports whether a port can be set to the jumbo MTU (it is a
// physical port with link at 1 Gb/s or more; the switch is the admin's to
// check, which the wizard says).
func JumboCapable(st Status, iface string) bool {
	for _, l := range st.Live {
		if l.Name == iface {
			return l.Kind == "port" && l.SpeedMbps >= 1000
		}
	}
	return false
}
