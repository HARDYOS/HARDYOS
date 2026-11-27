package vms

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// IPv6 for cards behind the anti-spoofing filter (decisions 137, 511-513,
// 518).
//
// libvirt's clean-traffic drops every IPv6 frame, so filtered cards used to
// be IPv4-only. HardyOSFilter is clean-traffic plus "IPv6 passes libvirt",
// and the IPv6 rules themselves are an nftables bridge table root keeps
// (hardyos_vmguard6), one chain per filtered card: what libvirt's
// ebtables filters can't express (ICMPv6 types behind extension headers,
// the target of a neighbour advertisement, the link-layer address in its
// options) nft can. IPv6 from any other VM card ("hv*") is dropped unless
// the card may spoof, so a card without its chain is closed, not open. A
// filtered card may send IPv6 only
//
//   - from its own MAC,
//   - from a link-local address (fe80::/64: EUI-64, stable-privacy and
//     Windows' random identifiers alike) or an address in a prefix
//     on-link on its network (SLAAC and privacy addresses), carrying a
//     transport header nft can read (unreadable chains are dropped),
//   - from :: only for duplicate address detection (neighbour
//     solicitations without a link-layer option, MLD reports),
//   - never as a router: router advertisements, redirects, router
//     renumbering, multicast listener queries and multicast router
//     discovery are dropped, and so are DHCPv6 server and relay replies
//     (UDP from 547 or to 546) and fragmented ICMPv6,
//   - never claiming a protected address (the server's, its gateways',
//     DNS servers' and router neighbours'), as the source or the target of
//     neighbour discovery, nor an address another computer on the network
//     was seen using with another MAC (learned from neighbour discovery
//     arriving from the network's own ports), and its neighbour
//     solicitations and advertisements carry its own MAC.
//
// A card on a VLAN the server has no interface on gets no IPv6. IPv4 and
// ARP stay exactly clean-traffic's.

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

// guard6Table is root's nftables table for VM cards' IPv6.
const guard6Table = "hardyos_vmguard6"

// learnTTL is how long an address seen on the network's own ports stays
// protected after it was last seen in neighbour discovery.
const learnTTL = 3600

// guard6NIC is a VM card on the home network or a VLAN.
type guard6NIC struct {
	Tap   string
	MAC   string
	VLAN  int  // 0: the home network itself
	Spoof bool // may use other addresses (routers): no chain, accepted
}

// Guard6Card is a filtered card as RenderGuard6 writes it.
type Guard6Card struct {
	Tap      string
	MAC      string
	Prefixes []netip.Prefix // the global and unique-local prefixes on-link on its network
	// NoIPv6: the server has no interface on the card's network, so it
	// knows nothing of it: no IPv6 at all.
	NoIPv6 bool
}

// Learned6 is an address (with the MAC it was seen with, for pairs) that
// the data plane learned, carried over a reload with its time left.
type Learned6 struct {
	Addr netip.Addr
	MAC  string // "" in the address set
	TTL  int    // seconds left
}

// Guard6 is everything the hardyos_vmguard6 table is made from.
type Guard6 struct {
	Cards []Guard6Card
	// Spoof are the taps of cards that may spoof (accepted as they are).
	Spoof []string
	// Protected no card may use, as the source or the target of neighbour
	// discovery.
	Protected []netip.Addr
	// Learned are the data plane's sets as they were before a reload.
	Learned []Learned6
}

var (
	tapRE = regexp.MustCompile(`^hv[0-9a-f]{6}[0-9]{1,2}$`)
	// linkLocal64 is the link-local prefix guests use (RFC 4291 2.5.6).
	linkLocal64 = netip.MustParsePrefix("fe80::/64")
)

// maxPrefixes caps each card's prefixes and maxProtected the protected
// addresses, so a strange network can't make the ruleset huge; over a cap
// the table isn't changed (decision 518).
const (
	maxPrefixes  = 64
	maxProtected = 256
	maxLearned   = 4096
)

// knownL4 are the transport protocols a filtered card's IPv6 may carry: a
// packet whose header chain nft can't follow to one of these is dropped.
const knownL4 = "{ tcp, udp, ipv6-icmp, esp, ah, sctp, udplite }"

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

// dedupeProtected keeps the valid addresses once each, sorted.
func dedupeProtected(l []netip.Addr) []string {
	seen := map[netip.Addr]bool{}
	var out []string
	for _, a := range l {
		a = a.WithZone("")
		if !okProtected(a) || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a.String())
	}
	slices.Sort(out)
	return out
}

func checkCard(tap, mac string) error {
	if !tapRE.MatchString(tap) {
		return fmt.Errorf("%q isn't a VM network card's device", tap)
	}
	if !macRE.MatchString(mac) || !validMAC(mac) {
		return fmt.Errorf("%s: %q isn't a unicast MAC address", tap, mac)
	}
	return nil
}

// RenderGuard6 is the nftables ruleset for VM cards' IPv6. It replaces the
// whole table atomically (nft -f), and with no cards still loads one that
// drops IPv6 from every VM card.
func RenderGuard6(g Guard6) (string, error) {
	cards := slices.Clone(g.Cards)
	slices.SortFunc(cards, func(a, b Guard6Card) int { return strings.Compare(a.Tap, b.Tap) })
	prot := dedupeProtected(g.Protected)
	if len(prot) > maxProtected {
		return "", fmt.Errorf("%d protected addresses (at most %d)", len(prot), maxProtected)
	}
	taps := map[string]bool{}
	for _, c := range cards {
		if err := checkCard(c.Tap, c.MAC); err != nil {
			return "", err
		}
		if taps[c.Tap] {
			return "", fmt.Errorf("%s twice", c.Tap)
		}
		taps[c.Tap] = true
	}
	spoof := slices.Clone(g.Spoof)
	slices.Sort(spoof)
	spoof = slices.Compact(spoof)
	for _, t := range spoof {
		if !tapRE.MatchString(t) {
			return "", fmt.Errorf("%q isn't a VM network card's device", t)
		}
		if taps[t] {
			return "", fmt.Errorf("%s is both filtered and allowed to spoof", t)
		}
	}
	var addrs, pairs []string
	for _, l := range g.Learned {
		ttl := min(max(l.TTL, 1), learnTTL)
		a := l.Addr.WithZone("")
		if !okProtected(a) {
			continue
		}
		if l.MAC == "" {
			addrs = append(addrs, fmt.Sprintf("%s timeout %ds", a, ttl))
			continue
		}
		hw, err := net.ParseMAC(l.MAC)
		if err != nil || len(hw) != 6 {
			continue
		}
		pairs = append(pairs, fmt.Sprintf("%s . %s timeout %ds", a, hw, ttl))
	}
	addrs, pairs = addrs[:min(len(addrs), maxLearned)], pairs[:min(len(pairs), maxLearned)]
	var b strings.Builder
	fmt.Fprintf(&b, "# Made by HardyOS: IPv6 for VM network cards behind the anti-spoofing filter (decisions 511-513, 518).\n")
	fmt.Fprintf(&b, "table bridge %[1]s\ndelete table bridge %[1]s\ntable bridge %[1]s {\n", guard6Table)
	set := func(name, typ, extra string, elems []string) {
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype %s\n%s", name, typ, extra)
		if len(elems) > 0 {
			fmt.Fprintf(&b, "\t\telements = { %s }\n", strings.Join(elems, ", "))
		}
		b.WriteString("\t}\n")
	}
	learned := fmt.Sprintf("\t\tsize %d\n\t\tflags dynamic, timeout\n", maxLearned)
	set("protected", "ipv6_addr", "", prot)
	set("lanaddrs", "ipv6_addr", learned, addrs)
	set("lanpairs", "ipv6_addr . ether_addr", learned, pairs)
	var quoted []string
	for _, t := range spoof {
		quoted = append(quoted, strconv.Quote(t))
	}
	set("spoofok", "ifname", "", quoted)
	b.WriteString("\tchain pre {\n\t\ttype filter hook prerouting priority -200; policy accept;\n")
	// Learn who is on the network from neighbour discovery arriving from
	// its own ports (never a VM card's).
	fmt.Fprintf(&b, "\t\tiifname != \"hv*\" ether type ip6 ip6 saddr != :: meta l4proto ipv6-icmp icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } update @lanaddrs { ip6 saddr timeout %ds } update @lanpairs { ip6 saddr . ether saddr timeout %ds }\n", learnTTL, learnTTL)
	b.WriteString("\t\tiifname @spoofok accept\n")
	for _, c := range cards {
		fmt.Fprintf(&b, "\t\tiifname %q ether type ip6 jump g_%s\n", c.Tap, c.Tap)
		fmt.Fprintf(&b, "\t\tiifname %q ether type { 8021q, 8021ad } drop\n", c.Tap)
	}
	// Any other VM card: no IPv6 (a card whose chain is missing is closed).
	b.WriteString("\t\tiifname \"hv*\" ether type ip6 drop\n")
	b.WriteString("\t}\n")
	b.WriteString("\tchain frag_udp {\n\t\tudp sport 547 drop\n\t\tudp dport 546 drop\n\t\tudp sport 0-65535 return\n\t\tdrop\n\t}\n")
	for _, c := range cards {
		fmt.Fprintf(&b, "\tchain g_%s {\n", c.Tap)
		if c.NoIPv6 {
			b.WriteString("\t\tdrop\n\t}\n")
			continue
		}
		var pfx []string
		for _, p := range c.Prefixes {
			if okPrefix(p) && !slices.Contains(pfx, p.String()) {
				pfx = append(pfx, p.String())
			}
		}
		if len(pfx) > maxPrefixes {
			return "", fmt.Errorf("%s: %d prefixes (at most %d)", c.Tap, len(pfx), maxPrefixes)
		}
		slices.Sort(pfx)
		mac := strings.ReplaceAll(c.MAC, ":", "")
		nd := "meta l4proto ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert }"
		fmt.Fprintf(&b, "\t\tether saddr != %s drop\n", c.MAC)
		b.WriteString("\t\tip6 saddr @protected drop\n")
		b.WriteString("\t\tip6 saddr @lanaddrs ip6 saddr . ether saddr != @lanpairs drop\n")
		// Neighbour discovery is never fragmented (RFC 6980): no ICMPv6
		// fragments at all; a first UDP fragment shows its ports.
		b.WriteString("\t\texthdr frag exists meta l4proto ipv6-icmp drop\n")
		b.WriteString("\t\tfrag frag-off 0 meta l4proto udp jump frag_udp\n")
		// Router advertisements, redirects, router renumbering, multicast
		// listener queries and multicast router advertisements and
		// terminations (a router's or a querier's).
		b.WriteString("\t\tmeta l4proto ipv6-icmp icmpv6 type { nd-router-advert, nd-redirect, router-renumbering, mld-listener-query, 151, 153 } drop\n")
		// DHCPv6 servers and relays answer from 547 to 546.
		b.WriteString("\t\tmeta l4proto udp udp sport 547 drop\n")
		b.WriteString("\t\tmeta l4proto udp udp dport 546 drop\n")
		// No claiming a protected address, or one another computer uses,
		// in neighbour discovery (duplicate address detection included).
		fmt.Fprintf(&b, "\t\t%s icmpv6 taddr @protected drop\n", nd)
		fmt.Fprintf(&b, "\t\t%s icmpv6 taddr @lanaddrs icmpv6 taddr . ether saddr != @lanpairs drop\n", nd)
		// Duplicate address detection: from :: only solicitations without
		// a link-layer option (a nonce is fine) and MLD reports.
		b.WriteString("\t\tip6 saddr :: meta l4proto ipv6-icmp icmpv6 type nd-neighbor-solicit @th,192,8 1 drop\n")
		b.WriteString("\t\tip6 saddr :: meta l4proto ipv6-icmp icmpv6 type { nd-neighbor-solicit, mld2-listener-report, mld-listener-report } accept\n")
		b.WriteString("\t\tip6 saddr :: drop\n")
		// A solicitation's or advertisement's first option, when there is
		// one, is its own link-layer address (Linux takes the first of
		// several).
		fmt.Fprintf(&b, "\t\t%s @th,192,8 != { 1, 2 } drop\n", nd)
		fmt.Fprintf(&b, "\t\t%s @th,208,48 != 0x%s drop\n", nd, mac)
		fmt.Fprintf(&b, "\t\tip6 saddr %s meta l4proto %s accept\n", linkLocal64, knownL4)
		if len(pfx) > 0 {
			fmt.Fprintf(&b, "\t\tip6 saddr { %s } meta l4proto %s accept\n", strings.Join(pfx, ", "), knownL4)
		}
		b.WriteString("\t\tdrop\n\t}\n")
	}
	b.WriteString("}\n")
	return b.String(), nil
}

// emergencyGuard6 is what is loaded when the full table can't be: IPv6
// from VM cards dropped, but for cards that may spoof.
func emergencyGuard6(spoof []string) string {
	var q []string
	for _, t := range spoof {
		if tapRE.MatchString(t) {
			q = append(q, strconv.Quote(t))
		}
	}
	accept := ""
	if len(q) > 0 {
		accept = "\t\tiifname { " + strings.Join(q, ", ") + " } accept\n"
	}
	return fmt.Sprintf("table bridge %[1]s\ndelete table bridge %[1]s\ntable bridge %[1]s {\n\tchain pre {\n\t\ttype filter hook prerouting priority -200; policy accept;\n%[2]s\t\tiifname \"hv*\" ether type ip6 drop\n\t}\n}\n", guard6Table, accept)
}

// guard6NICs are a spec's cards on the home network or a VLAN.
func guard6NICs(s *Spec) []guard6NIC {
	var l []guard6NIC
	for i, n := range s.NICs {
		if n.Mode == NICNAT {
			continue
		}
		v := 0
		if n.Mode == NICVLAN {
			v = n.VLAN
		}
		l = append(l, guard6NIC{Tap: tapName(s.UUID, i), MAC: n.MAC, VLAN: v, Spoof: n.AllowSpoofing})
	}
	return l
}

// netInfo6 is what this server knows of one network: the prefixes on it
// and the addresses there no card may use.
type netInfo6 struct {
	present   bool // the server has an interface on it
	prefixes  []netip.Prefix
	protected []netip.Addr
}

// ipRoute6, ipAddr6 and ipNeigh6 are what `ip -j -6 route|addr|neigh show
// dev X` print.
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

// parseNetInfo6 reads an interface's IPv6 routes, addresses and
// neighbours: on-link routes (no gateway: from router advertisements and
// the server's own addresses) are the prefixes; gateways, the server's
// addresses and neighbours flagged as routers are protected.
func parseNetInfo6(routes, addrs, neigh []byte) netInfo6 {
	ni := netInfo6{present: true}
	add := func(s string) {
		if a, err := netip.ParseAddr(s); err == nil && okProtected(a.WithZone("")) {
			ni.protected = append(ni.protected, a.WithZone(""))
		}
	}
	var rl []ipRoute6
	if json.Unmarshal(routes, &rl) == nil {
		for _, r := range rl {
			add(r.Gateway)
			for _, n := range r.Nexthops {
				add(n.Gateway)
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
				if a.Family == "inet6" {
					add(a.Local)
				}
			}
		}
	}
	var nl []map[string]json.RawMessage
	if json.Unmarshal(neigh, &nl) == nil {
		for _, n := range nl {
			if _, router := n["router"]; !router {
				continue
			}
			var dst string
			if json.Unmarshal(n["dst"], &dst) == nil {
				add(dst)
			}
		}
	}
	return ni
}

// noDevice reports whether ip failed because the interface isn't there.
func noDevice(err error) bool {
	s := err.Error()
	return strings.Contains(s, "Cannot find device") || strings.Contains(s, "does not exist")
}

// netInfo6For reads a network's IPv6 from the server's interface on it:
// the bridge for the home network, <bridge>.<vlan> for a VLAN. A missing
// interface is a network the server knows nothing of (present false); any
// other failure is an error.
func (m *Manager) netInfo6For(ctx context.Context, vlan int) (netInfo6, error) {
	br := ""
	if m.Network != nil {
		br = m.Network.BridgeName()
	}
	if !ifnameRE.MatchString(br) {
		return netInfo6{}, nil
	}
	dev := br
	if vlan > 0 {
		dev = br + "." + strconv.Itoa(vlan)
		if !ifnameRE.MatchString(dev) {
			return netInfo6{}, nil
		}
	}
	routes, err := m.run(ctx, "ip", "-j", "-6", "route", "show", "dev", dev)
	if err != nil {
		if noDevice(err) {
			return netInfo6{}, nil
		}
		return netInfo6{}, fmt.Errorf("reading %s's IPv6 routes: %w", dev, err)
	}
	addrs, err := m.run(ctx, "ip", "-j", "-6", "addr", "show", "dev", dev)
	if err != nil {
		return netInfo6{}, fmt.Errorf("reading %s's IPv6 addresses: %w", dev, err)
	}
	neigh, err := m.run(ctx, "ip", "-j", "-6", "neigh", "show", "dev", dev)
	if err != nil {
		return netInfo6{}, fmt.Errorf("reading %s's IPv6 neighbours: %w", dev, err)
	}
	return parseNetInfo6(routes, addrs, neigh), nil
}

// dnsServers6 are the IPv6 name servers the server uses (resolv.conf, and
// systemd-resolved's upstream list when it answers on 127.0.0.53).
func (m *Manager) dnsServers6() []netip.Addr {
	var out []netip.Addr
	for _, f := range []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"} {
		b, err := os.ReadFile(m.sys(f))
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			fl := strings.Fields(l)
			if len(fl) >= 2 && fl[0] == "nameserver" {
				if a, err := netip.ParseAddr(fl[1]); err == nil && a.Is6() {
					out = append(out, a.WithZone(""))
				}
			}
		}
	}
	return out
}

// readLearned reads the data plane's learned sets from the live table, so
// a reload keeps them.
func (m *Manager) readLearned(ctx context.Context) []Learned6 {
	var out []Learned6
	for _, name := range []string{"lanaddrs", "lanpairs"} {
		b, err := m.run(ctx, "nft", "-j", "list", "set", "bridge", guard6Table, name)
		if err != nil {
			continue
		}
		out = append(out, parseLearned(b)...)
	}
	return out
}

// parseLearned reads `nft -j list set` output.
func parseLearned(b []byte) []Learned6 {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []struct {
					Elem struct {
						Val     json.RawMessage `json:"val"`
						Expires int             `json:"expires"`
					} `json:"elem"`
				} `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return nil
	}
	var out []Learned6
	for _, n := range doc.Nftables {
		if n.Set == nil {
			continue
		}
		for _, e := range n.Set.Elem {
			l := Learned6{TTL: e.Elem.Expires}
			var s string
			var c struct {
				Concat []string `json:"concat"`
			}
			switch {
			case json.Unmarshal(e.Elem.Val, &s) == nil:
			case json.Unmarshal(e.Elem.Val, &c) == nil && len(c.Concat) == 2:
				s, l.MAC = c.Concat[0], c.Concat[1]
			default:
				continue
			}
			a, err := netip.ParseAddr(s)
			if err != nil || l.TTL <= 0 {
				continue
			}
			l.Addr = a
			out = append(out, l)
		}
	}
	return out
}

// guard6Locked renders the table for the cards known (m.guard6Mu held).
// A network that can't be read keeps what was last read of it; one never
// read is an error (nothing is reloaded).
func (m *Manager) guard6Locked(ctx context.Context) (string, error) {
	if m.guard6Info == nil {
		m.guard6Info = map[int]netInfo6{}
	}
	g := Guard6{Protected: m.dnsServers6()}
	taps := make([]string, 0, len(m.guard6VMs))
	for tap := range m.guard6VMs {
		taps = append(taps, tap)
	}
	slices.Sort(taps)
	read := map[int]bool{}
	info := func(vlan int) (netInfo6, error) {
		if !read[vlan] {
			ni, err := m.netInfo6For(ctx, vlan)
			if err != nil {
				last, ok := m.guard6Info[vlan]
				if !ok {
					return netInfo6{}, err
				}
				m.log().Warn("vms: reading the network for the IPv6 rules; keeping what was read before", "vlan", vlan, "err", err)
				ni = last
			}
			m.guard6Info[vlan] = ni
			read[vlan] = true
			g.Protected = append(g.Protected, ni.protected...)
		}
		return m.guard6Info[vlan], nil
	}
	for _, tap := range taps {
		n := m.guard6VMs[tap]
		if n.Spoof {
			g.Spoof = append(g.Spoof, n.Tap)
			continue
		}
		ni, err := info(n.VLAN)
		if err != nil {
			return "", err
		}
		g.Cards = append(g.Cards, Guard6Card{Tap: n.Tap, MAC: n.MAC, Prefixes: ni.prefixes, NoIPv6: !ni.present})
	}
	if len(g.Cards) > 0 {
		// The server's own addresses on the home network are protected
		// whatever network the cards are on.
		if _, err := info(0); err != nil {
			return "", err
		}
	}
	if n := len(dedupeProtected(g.Protected)); n > maxProtected {
		return "", fmt.Errorf("%d addresses to protect, more than the %d the IPv6 rules hold; the rules weren't changed", n, maxProtected)
	}
	g.Learned = m.readLearned(ctx)
	return RenderGuard6(g)
}

// loadNFT loads a ruleset atomically.
func (m *Manager) loadNFT(ctx context.Context, text string) error {
	res, err := m.Runner.Run(ctx, []byte(text), "nft", "-f", "-")
	if err == nil && res.ExitCode != 0 {
		err = errors.New(strings.TrimSpace(string(res.Stderr)))
	}
	return err
}

// tableCloses reports whether the live table still drops IPv6 from VM
// cards it doesn't know.
func (m *Manager) tableCloses(ctx context.Context) bool {
	out, err := m.run(ctx, "nft", "list", "chain", "bridge", guard6Table, "pre")
	return err == nil && strings.Contains(string(out), `iifname "hv*" ether type ip6 drop`)
}

// applyGuard6Locked loads the table (m.guard6Mu held). Every load is the
// whole table, so whatever changed in the kernel since is put back. When
// the table can't be made or loaded and the live one no longer closes IPv6
// to unknown cards, the emergency table is loaded: filtered cards lose
// IPv6, they never get it unfiltered.
func (m *Manager) applyGuard6Locked(ctx context.Context) error {
	text, err := m.guard6Locked(ctx)
	if err == nil {
		if err = m.loadNFT(ctx, text); err == nil {
			m.guard6Applied = text
			return nil
		}
		err = fmt.Errorf("loading the IPv6 rules for VM network cards: %w", err)
	}
	m.guard6Applied = ""
	if !m.tableCloses(ctx) {
		var spoof []string
		for _, n := range m.guard6VMs {
			if n.Spoof {
				spoof = append(spoof, n.Tap)
			}
		}
		slices.Sort(spoof)
		if eerr := m.loadNFT(ctx, emergencyGuard6(spoof)); eerr != nil {
			m.log().Error("vms: VM network cards' IPv6 couldn't be closed either", "err", eerr)
		} else {
			m.log().Error("vms: the IPv6 rules couldn't be loaded; IPv6 from VM cards is dropped until they can", "err", err)
		}
	}
	return err
}

// guardVM puts a VM's cards under the IPv6 rules before it runs here. Any
// failure is an error: a filtered card must not run with IPv6 open.
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

// seedGuard6 records the cards of VMs that already run (a hardyd-priv
// restart) and loads the table; on failure the table still closes IPv6
// to every VM card (applyGuard6Locked), and every refresh tries again.
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
	if err := m.applyGuard6Locked(ctx); err != nil {
		m.log().Error("vms: the IPv6 rules for VM network cards couldn't be loaded", "err", err)
	}
}

// refreshGuard6 reloads the table: the networks' prefixes and addresses
// may have changed, and whatever happened to the live table is undone.
func (m *Manager) refreshGuard6(ctx context.Context) {
	m.guard6Mu.Lock()
	defer m.guard6Mu.Unlock()
	if len(m.guard6VMs) == 0 && m.guard6Applied == "" && m.guard6Info == nil {
		return // no VM card was ever seen here
	}
	if err := m.applyGuard6Locked(ctx); err != nil {
		m.log().Warn("vms: refreshing the IPv6 rules for VM network cards", "err", err)
	}
}

// kickGuard6 asks for a refresh soon (an address or route changed).
func (m *Manager) kickGuard6() {
	m.guard6Once.Do(func() { m.guard6Kick = make(chan struct{}, 1) })
	select {
	case m.guard6Kick <- struct{}{}:
	default:
	}
}

// watchGuard6 refreshes the table when the kernel reports an IPv6 address,
// route or link change (coalesced over a second), besides the periodic
// refresh in Watch.
func (m *Manager) watchGuard6(ctx context.Context) {
	m.guard6Once.Do(func() { m.guard6Kick = make(chan struct{}, 1) })
	go func() {
		if err := watchNetlink6(ctx, m.kickGuard6); err != nil && ctx.Err() == nil {
			m.log().Warn("vms: watching IPv6 address changes; the IPv6 rules follow them every 30 s only", "err", err)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.guard6Kick:
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
		m.refreshGuard6(ctx)
	}
}

// guardedTaps are the taps of a domain XML's cards that use HardyOSFilter.
func guardedTaps(domXML string) ([]string, error) {
	var d struct {
		Interfaces []struct {
			Target struct {
				Dev string `xml:"dev,attr"`
			} `xml:"target"`
			FilterRef *struct {
				Filter string `xml:"filter,attr"`
			} `xml:"filterref"`
		} `xml:"devices>interface"`
	}
	if err := xml.Unmarshal([]byte(domXML), &d); err != nil {
		return nil, fmt.Errorf("reading the domain's network cards: %w", err)
	}
	var out []string
	for _, i := range d.Interfaces {
		if i.FilterRef == nil || i.FilterRef.Filter != HardyOSFilter {
			continue
		}
		if !tapRE.MatchString(i.Target.Dev) {
			return nil, fmt.Errorf("a filtered network card has the device %q, not one of HardyOS's", i.Target.Dev)
		}
		out = append(out, i.Target.Dev)
	}
	return out, nil
}

// CheckGuardedStart is the qemu hook's check before a domain starts: every
// card using HardyOSFilter has its chain in the live table.
func (m *Manager) CheckGuardedStart(ctx context.Context, domXML string) error {
	taps, err := guardedTaps(domXML)
	if err != nil {
		return err
	}
	for _, t := range taps {
		if _, err := m.run(ctx, "nft", "list", "chain", "bridge", guard6Table, "g_"+t); err != nil {
			return fmt.Errorf("the network card %s has no IPv6 rules loaded; refusing to start it", t)
		}
	}
	return nil
}
