package vms

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// IPv6 for cards behind the anti-spoofing filter (decisions 137, 511-513).
//
// libvirt's clean-traffic drops every IPv6 frame, so filtered cards used to
// be IPv4-only. HardyOSFilter is clean-traffic plus "IPv6 passes libvirt",
// and the IPv6 rules themselves are an nftables bridge table root keeps
// (hardyos_vmguard6), one chain per filtered card: what libvirt's
// ebtables filters can't express (ICMPv6 types behind extension headers,
// the target of a neighbour advertisement, the link-layer address in its
// options) nft can. A card may send IPv6 only
//
//   - from its own MAC,
//   - from a link-local address (fe80::/64: EUI-64, stable-privacy and
//     Windows' random identifiers alike) or an address in a prefix
//     advertised on its network (SLAAC and privacy addresses; the
//     prefixes are the on-link routes this server has on that network),
//   - from :: only for duplicate address detection (neighbour
//     solicitations without a link-layer option, MLD reports),
//   - never as a router: router advertisements, redirects and router
//     renumbering are dropped, and so are DHCPv6 server and relay
//     replies (UDP from 547 or to 546),
//   - never claiming this server's or the router's addresses (as the
//     source, or as the target of a neighbour advertisement), and its
//     neighbour solicitations and advertisements carry its own MAC.
//
// IPv4 and ARP stay exactly clean-traffic's.

// HardyOSFilter is the libvirt filter filtered cards reference.
const HardyOSFilter = "hardyos-clean-traffic"

// hardyosFilterUUID is fixed so redefining the filter replaces it.
const hardyosFilterUUID = "6a1d3c52-8f0e-4b7a-9c21-5e4f7d0b9a13"

// hardyosFilterXML is HardyOSFilter: clean-traffic (MAC, IPv4 and ARP
// spoofing, nothing else at layer 2) with IPv6 let through to the
// hardyos_vmguard6 table, at clean-traffic's own priority for IPv4.
var hardyosFilterXML = `<filter name='` + HardyOSFilter + `' chain='root'>
  <uuid>` + hardyosFilterUUID + `</uuid>
  <filterref filter='` + CleanTraffic + `'/>
  <rule action='accept' direction='out' priority='-650'>
    <mac protocolid='ipv6'/>
  </rule>
  <rule action='accept' direction='in' priority='-650'>
    <mac protocolid='ipv6'/>
  </rule>
</filter>
`

// ensureFilter defines HardyOSFilter (once per hardyd-priv run: a
// redefinition rebuilds every running VM's rules).
func (m *Manager) ensureFilter(ctx context.Context) error {
	m.guard6Mu.Lock()
	defer m.guard6Mu.Unlock()
	if m.filterDefined {
		return nil
	}
	dir := m.sys("/run/hardyos/vms")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f := filepath.Join(dir, HardyOSFilter+".xml")
	if err := writeAtomic(f, []byte(hardyosFilterXML), 0o600); err != nil {
		return err
	}
	defer os.Remove(f)
	if _, err := m.virsh(ctx, "nwfilter-define", filepath.Join("/run/hardyos/vms", HardyOSFilter+".xml")); err != nil {
		return fmt.Errorf("defining the network filter %s: %w", HardyOSFilter, err)
	}
	m.filterDefined = true
	return nil
}

// guard6Table is root's nftables table for filtered cards' IPv6.
const guard6Table = "hardyos_vmguard6"

// guard6NIC is one filtered card.
type guard6NIC struct {
	Tap  string
	MAC  string
	VLAN int // 0: the home network itself
}

// Guard6Card is a filtered card as RenderGuard6 writes it.
type Guard6Card struct {
	Tap      string
	MAC      string
	Prefixes []netip.Prefix // the global and unique-local prefixes advertised on its network
}

// Guard6 is everything the hardyos_vmguard6 table is made from.
type Guard6 struct {
	Cards []Guard6Card
	// Protected are this server's and the routers' addresses on the
	// networks the cards are on: no card may use them.
	Protected []netip.Addr
}

var (
	tapRE = regexp.MustCompile(`^hv[0-9a-f]{6}[0-9]{1,2}$`)
	// linkLocal64 is the link-local prefix guests use (RFC 4291 2.5.6).
	linkLocal64 = netip.MustParsePrefix("fe80::/64")
)

// maxGuard6 caps the protected addresses and each card's prefixes, so a
// strange network can't make the ruleset huge.
const maxGuard6 = 64

// okPrefix reports whether p may be a card's source prefix: IPv6, masked,
// at least a /48 (a shorter on-link route would open nearly everything),
// and not link-local or multicast (those have rules of their own).
func okPrefix(p netip.Prefix) bool {
	a := p.Addr()
	return p.IsValid() && a.Is6() && !a.Is4In6() && a.Zone() == "" && p == p.Masked() && p.Bits() >= 48 &&
		!a.IsLinkLocalUnicast() && !a.IsMulticast() && !a.IsLoopback() && !a.IsUnspecified()
}

func okProtected(a netip.Addr) bool {
	return a.IsValid() && a.Is6() && !a.Is4In6() && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback()
}

// RenderGuard6 is the nftables ruleset for filtered cards' IPv6. It
// replaces the whole table atomically (nft -f), and with no cards still
// loads an empty one.
func RenderGuard6(g Guard6) (string, error) {
	cards := slices.Clone(g.Cards)
	slices.SortFunc(cards, func(a, b Guard6Card) int { return strings.Compare(a.Tap, b.Tap) })
	var prot []string
	seen := map[netip.Addr]bool{}
	for _, a := range g.Protected {
		a = a.WithZone("")
		if !okProtected(a) || seen[a] {
			continue
		}
		seen[a] = true
		prot = append(prot, a.String())
	}
	if len(prot) > maxGuard6 {
		return "", fmt.Errorf("%d protected addresses (at most %d)", len(prot), maxGuard6)
	}
	slices.Sort(prot)
	var b strings.Builder
	fmt.Fprintf(&b, "# Made by HardyOS: IPv6 for VM network cards behind the anti-spoofing filter (decisions 511-513).\n")
	fmt.Fprintf(&b, "table bridge %[1]s\ndelete table bridge %[1]s\ntable bridge %[1]s {\n", guard6Table)
	b.WriteString("\tset protected {\n\t\ttype ipv6_addr\n")
	if len(prot) > 0 {
		fmt.Fprintf(&b, "\t\telements = { %s }\n", strings.Join(prot, ", "))
	}
	b.WriteString("\t}\n")
	b.WriteString("\tchain pre {\n\t\ttype filter hook prerouting priority -200; policy accept;\n")
	taps := map[string]bool{}
	for _, c := range cards {
		if !tapRE.MatchString(c.Tap) {
			return "", fmt.Errorf("%q isn't a VM network card's device", c.Tap)
		}
		if taps[c.Tap] {
			return "", fmt.Errorf("%s twice", c.Tap)
		}
		taps[c.Tap] = true
		if !macRE.MatchString(c.MAC) || !validMAC(c.MAC) {
			return "", fmt.Errorf("%s: %q isn't a unicast MAC address", c.Tap, c.MAC)
		}
		fmt.Fprintf(&b, "\t\tiifname %q ether type ip6 jump g_%s\n", c.Tap, c.Tap)
		fmt.Fprintf(&b, "\t\tiifname %q ether type { 8021q, 8021ad } drop\n", c.Tap)
	}
	b.WriteString("\t}\n")
	for _, c := range cards {
		var pfx []string
		for _, p := range c.Prefixes {
			if okPrefix(p) && !slices.Contains(pfx, p.String()) {
				pfx = append(pfx, p.String())
			}
		}
		if len(pfx) > maxGuard6 {
			return "", fmt.Errorf("%s: %d prefixes (at most %d)", c.Tap, len(pfx), maxGuard6)
		}
		slices.Sort(pfx)
		mac := strings.ReplaceAll(c.MAC, ":", "")
		fmt.Fprintf(&b, "\tchain g_%s {\n", c.Tap)
		fmt.Fprintf(&b, "\t\tether saddr != %s drop\n", c.MAC)
		b.WriteString("\t\tip6 saddr @protected drop\n")
		// Router advertisements, redirects and router renumbering.
		b.WriteString("\t\tmeta l4proto ipv6-icmp icmpv6 type { nd-router-advert, nd-redirect, router-renumbering } drop\n")
		// DHCPv6 servers and relays answer from 547 to 546.
		b.WriteString("\t\tmeta l4proto udp udp sport 547 drop\n")
		b.WriteString("\t\tmeta l4proto udp udp dport 546 drop\n")
		b.WriteString("\t\tmeta l4proto ipv6-icmp icmpv6 type nd-neighbor-advert icmpv6 taddr @protected drop\n")
		// Duplicate address detection: from :: only solicitations without
		// a link-layer option (a nonce is fine) and MLD reports.
		b.WriteString("\t\tip6 saddr :: meta l4proto ipv6-icmp icmpv6 type nd-neighbor-solicit @th,192,8 1 drop\n")
		b.WriteString("\t\tip6 saddr :: meta l4proto ipv6-icmp icmpv6 type { nd-neighbor-solicit, mld2-listener-report, mld-listener-report } accept\n")
		b.WriteString("\t\tip6 saddr :: drop\n")
		// A solicitation's or advertisement's first option, when there is
		// one, is its own link-layer address (Linux takes the first of
		// several).
		b.WriteString("\t\tmeta l4proto ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } @th,192,8 != { 1, 2 } drop\n")
		fmt.Fprintf(&b, "\t\tmeta l4proto ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } @th,208,48 != 0x%s drop\n", mac)
		fmt.Fprintf(&b, "\t\tip6 saddr %s accept\n", linkLocal64)
		if len(pfx) > 0 {
			fmt.Fprintf(&b, "\t\tip6 saddr { %s } accept\n", strings.Join(pfx, ", "))
		}
		b.WriteString("\t\tdrop\n\t}\n")
	}
	b.WriteString("}\n")
	return b.String(), nil
}

// guard6NICs are a spec's cards the filter applies to.
func guard6NICs(s *Spec) []guard6NIC {
	var l []guard6NIC
	for i, n := range s.NICs {
		if n.Mode == NICNAT || n.AllowSpoofing {
			continue
		}
		v := 0
		if n.Mode == NICVLAN {
			v = n.VLAN
		}
		l = append(l, guard6NIC{Tap: tapName(s.UUID, i), MAC: n.MAC, VLAN: v})
	}
	return l
}

// netInfo6 is what this server knows of one network: the prefixes on it
// and its own and the routers' addresses there.
type netInfo6 struct {
	prefixes  []netip.Prefix
	protected []netip.Addr
}

// ipRoute6 and ipAddr6 are what `ip -j -6 route|addr show dev X` print.
type ipRoute6 struct {
	Dst      string `json:"dst"`
	Gateway  string `json:"gateway"`
	Protocol string `json:"protocol"`
	Nexthops []struct {
		Gateway string `json:"gateway"`
	} `json:"nexthops"`
}

type ipAddr6 struct {
	AddrInfo []struct {
		Family string `json:"family"`
		Local  string `json:"local"`
	} `json:"addr_info"`
}

// parseNetInfo6 reads an interface's IPv6 routes and addresses: on-link
// routes (no gateway: from router advertisements and the server's own
// addresses) are the prefixes, gateways and the server's addresses are
// protected.
func parseNetInfo6(routes, addrs []byte) netInfo6 {
	var ni netInfo6
	var rl []ipRoute6
	if json.Unmarshal(routes, &rl) == nil {
		for _, r := range rl {
			for _, g := range append([]string{r.Gateway}, gateways(r)...) {
				if a, err := netip.ParseAddr(g); err == nil && okProtected(a.WithZone("")) {
					ni.protected = append(ni.protected, a.WithZone(""))
				}
			}
			if r.Gateway != "" || len(r.Nexthops) > 0 || r.Dst == "default" {
				continue
			}
			switch r.Protocol {
			case "ra", "kernel", "static", "boot", "dhcp":
			default:
				continue
			}
			if p, err := netip.ParsePrefix(r.Dst); err == nil && okPrefix(p) {
				ni.prefixes = append(ni.prefixes, p)
			}
		}
	}
	var al []ipAddr6
	if json.Unmarshal(addrs, &al) == nil {
		for _, i := range al {
			for _, a := range i.AddrInfo {
				if a.Family != "inet6" {
					continue
				}
				if ad, err := netip.ParseAddr(a.Local); err == nil && okProtected(ad.WithZone("")) {
					ni.protected = append(ni.protected, ad.WithZone(""))
				}
			}
		}
	}
	return ni
}

func gateways(r ipRoute6) []string {
	var l []string
	for _, n := range r.Nexthops {
		l = append(l, n.Gateway)
	}
	return l
}

// netInfo6For reads a network's IPv6 from the server's interface on it:
// the bridge for the home network, <bridge>.<vlan> for a VLAN (none: only
// link-local addresses for cards on that VLAN).
func (m *Manager) netInfo6For(ctx context.Context, vlan int) netInfo6 {
	br := ""
	if m.Network != nil {
		br = m.Network.BridgeName()
	}
	if !ifnameRE.MatchString(br) {
		return netInfo6{}
	}
	dev := br
	if vlan > 0 {
		dev = br + "." + strconv.Itoa(vlan)
		if !ifnameRE.MatchString(dev) {
			return netInfo6{}
		}
	}
	routes, err := m.run(ctx, "ip", "-j", "-6", "route", "show", "dev", dev)
	if err != nil {
		return netInfo6{}
	}
	addrs, _ := m.run(ctx, "ip", "-j", "-6", "addr", "show", "dev", dev)
	return parseNetInfo6(routes, addrs)
}

// guard6Locked renders the table for the cards known (m.guard6Mu held).
func (m *Manager) guard6Locked(ctx context.Context) (string, error) {
	infos := map[int]netInfo6{}
	g := Guard6{}
	taps := make([]string, 0, len(m.guard6VMs))
	for tap := range m.guard6VMs {
		taps = append(taps, tap)
	}
	slices.Sort(taps)
	for _, tap := range taps {
		n := m.guard6VMs[tap]
		ni, ok := infos[n.VLAN]
		if !ok {
			ni = m.netInfo6For(ctx, n.VLAN)
			infos[n.VLAN] = ni
			g.Protected = append(g.Protected, ni.protected...)
		}
		g.Cards = append(g.Cards, Guard6Card{Tap: n.Tap, MAC: n.MAC, Prefixes: ni.prefixes})
	}
	if _, ok := infos[0]; !ok && len(g.Cards) > 0 {
		g.Protected = append(g.Protected, m.netInfo6For(ctx, 0).protected...)
	}
	if len(g.Protected) > maxGuard6 {
		g.Protected = g.Protected[:maxGuard6]
	}
	return RenderGuard6(g)
}

// applyGuard6Locked loads the table when it changed (m.guard6Mu held).
func (m *Manager) applyGuard6Locked(ctx context.Context) error {
	text, err := m.guard6Locked(ctx)
	if err != nil {
		return err
	}
	if text == m.guard6Applied {
		return nil
	}
	res, err := m.Runner.Run(ctx, []byte(text), "nft", "-f", "-")
	if err == nil && res.ExitCode != 0 {
		err = fmt.Errorf("%s", strings.TrimSpace(string(res.Stderr)))
	}
	if err != nil {
		return fmt.Errorf("loading the IPv6 rules for VM network cards: %w", err)
	}
	m.guard6Applied = text
	return nil
}

// guardVM puts a VM's filtered cards under the IPv6 rules (and takes its
// other cards out) before it runs here. Any failure is an error: a
// filtered card must not run with IPv6 open.
func (m *Manager) guardVM(ctx context.Context, s *Spec) error {
	m.guard6Mu.Lock()
	defer m.guard6Mu.Unlock()
	if m.guard6VMs == nil {
		m.guard6VMs = map[string]guard6NIC{}
	}
	for i := range s.NICs {
		delete(m.guard6VMs, tapName(s.UUID, i))
	}
	for _, n := range guard6NICs(s) {
		m.guard6VMs[n.Tap] = n
	}
	return m.applyGuard6Locked(ctx)
}

// seedGuard6 records the filtered cards of VMs that already run (a
// hardyd-priv restart) and loads the table.
func (m *Manager) seedGuard6(ctx context.Context, specs []*Spec) {
	m.guard6Mu.Lock()
	defer m.guard6Mu.Unlock()
	if m.guard6VMs == nil {
		m.guard6VMs = map[string]guard6NIC{}
	}
	for _, s := range specs {
		for _, n := range guard6NICs(s) {
			m.guard6VMs[n.Tap] = n
		}
	}
	m.guard6Applied = "" // whatever was loaded before, load it again
	if err := m.applyGuard6Locked(ctx); err != nil {
		m.log().Error("vms: the IPv6 rules for VM network cards couldn't be loaded", "err", err)
	}
}

// refreshGuard6 follows the networks' prefixes and addresses (a new
// prefix from the router, a changed server address).
func (m *Manager) refreshGuard6(ctx context.Context) {
	m.guard6Mu.Lock()
	defer m.guard6Mu.Unlock()
	if len(m.guard6VMs) == 0 {
		return
	}
	if err := m.applyGuard6Locked(ctx); err != nil {
		m.log().Warn("vms: refreshing the IPv6 rules for VM network cards", "err", err)
	}
}
