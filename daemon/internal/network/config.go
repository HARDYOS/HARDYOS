// Package network holds HardyOS's network and time settings: the model the
// Control Panel edits, its validation, and rendering to the files the system
// reads (ifupdown's /etc/network/interfaces, resolv.conf, hosts, chrony.conf).
//
// The root-side Manager (manager.go) applies settings with a safety net: new
// network settings are rolled back automatically unless they are confirmed
// from the web UI within a few minutes, so a typo can't lock anyone out.
package network

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Config is the server's network setup.
type Config struct {
	Hostname string `json:"hostname"`
	// DNS servers and search domains. Used whenever any interface is static;
	// with DHCP everywhere and no servers listed, DHCP's DNS is used.
	DNS    []string `json:"dns"`
	Search []string `json:"search"`
	// Interfaces are physical ports. A port that's a bond member has
	// Mode "member" (set by Normalize from the bond list).
	Interfaces []Interface `json:"interfaces"`
	Bonds      []Bond      `json:"bonds"`
	VLANs      []VLAN      `json:"vlans"`
}

// Addressing is how an interface gets its address.
type Addressing struct {
	// Mode is dhcp, static, or off (no address; the port stays down unless
	// it carries VLANs). Bond members use "member".
	Mode    string `json:"mode"`
	Address string `json:"address,omitempty"` // static: CIDR, 192.168.1.20/24
	Gateway string `json:"gateway,omitempty"` // static, optional
	MTU     int    `json:"mtu,omitempty"`     // 0 = default (1500)
}

// Interface is a physical port.
type Interface struct {
	Name string `json:"name"`
	Addressing
}

// Bond joins ports into one link.
type Bond struct {
	Name    string   `json:"name"`    // bond0, bond1, …
	Members []string `json:"members"` // physical ports
	// Policy: active-backup (works with any switch), 802.3ad (LACP; the
	// switch must be set up for it) or balance-alb (no switch setup).
	Policy string `json:"policy"`
	Addressing
}

// VLAN is a tagged network on a port or bond.
type VLAN struct {
	Parent string `json:"parent"` // physical port or bond
	ID     int    `json:"id"`     // 1-4094
	Addressing
}

// Name is the VLAN interface's name, like eth0.20.
func (v VLAN) Name() string { return fmt.Sprintf("%s.%d", v.Parent, v.ID) }

// Mode names.
const (
	ModeDHCP   = "dhcp"
	ModeStatic = "static"
	ModeOff    = "off"
	ModeMember = "member"
)

// BondPolicies are the supported bonding policies.
var BondPolicies = []string{"active-backup", "802.3ad", "balance-alb"}

var (
	hostnameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	ifaceRE    = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,14}$`)
	bondRE     = regexp.MustCompile(`^bond[0-9]{1,2}$`)
	domainRE   = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
)

// ValidationError lists every problem found, so the form can show them all.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string { return strings.Join(e.Problems, "; ") }

// Normalize sorts lists, drops empty DNS entries and marks bond members, so
// equal settings compare equal and render the same.
func (c *Config) Normalize() {
	c.Hostname = strings.ToLower(strings.TrimSpace(c.Hostname))
	c.DNS = cleanList(c.DNS)
	c.Search = cleanList(c.Search)
	members := map[string]bool{}
	for i := range c.Bonds {
		c.Bonds[i].Members = cleanList(c.Bonds[i].Members)
		sort.Strings(c.Bonds[i].Members)
		for _, m := range c.Bonds[i].Members {
			members[m] = true
		}
	}
	for i := range c.Interfaces {
		if members[c.Interfaces[i].Name] {
			c.Interfaces[i].Addressing = Addressing{Mode: ModeMember}
		} else if c.Interfaces[i].Mode == ModeMember {
			c.Interfaces[i].Mode = ModeOff
		}
	}
	sort.Slice(c.Interfaces, func(i, j int) bool { return c.Interfaces[i].Name < c.Interfaces[j].Name })
	sort.Slice(c.Bonds, func(i, j int) bool { return c.Bonds[i].Name < c.Bonds[j].Name })
	sort.Slice(c.VLANs, func(i, j int) bool {
		if c.VLANs[i].Parent != c.VLANs[j].Parent {
			return c.VLANs[i].Parent < c.VLANs[j].Parent
		}
		return c.VLANs[i].ID < c.VLANs[j].ID
	})
}

func cleanList(in []string) []string {
	out := []string{}
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// Validate checks c against the server's physical ports. Call Normalize first.
func (c *Config) Validate(ports []string) error {
	var p []string
	add := func(format string, a ...any) { p = append(p, fmt.Sprintf(format, a...)) }

	if !hostnameRE.MatchString(c.Hostname) {
		add("the server name must be 1-63 lowercase letters, digits or dashes, not starting or ending with a dash")
	}
	if len(c.DNS) > 3 {
		add("at most 3 DNS servers")
	}
	for _, d := range c.DNS {
		if a, err := netip.ParseAddr(d); err != nil || a.Zone() != "" {
			add("DNS server %q is not an IP address", d)
		}
	}
	if len(c.Search) > 6 {
		add("at most 6 search domains")
	}
	for _, s := range c.Search {
		if len(s) > 253 || !domainRE.MatchString(s) {
			add("search domain %q is not a valid domain", s)
		}
	}

	known := map[string]bool{}
	for _, port := range ports {
		known[port] = true
	}
	names := map[string]string{} // interface name -> what defined it
	claim := func(name, what string) {
		if prev, ok := names[name]; ok {
			add("%s is defined twice (%s and %s)", name, prev, what)
		}
		names[name] = what
	}

	gateways := 0
	addressed := 0
	checkAddr := func(name string, a Addressing, allowMember bool) {
		switch a.Mode {
		case ModeDHCP:
			addressed++
			if a.Address != "" || a.Gateway != "" {
				add("%s uses DHCP, so it can't also have a fixed address or gateway", name)
			}
		case ModeStatic:
			addressed++
			prefix, err := netip.ParsePrefix(a.Address)
			if err != nil || prefix.Addr().Zone() != "" {
				add("%s: address %q must look like 192.168.1.20/24", name, a.Address)
				break
			}
			if prefix.Addr().Is4() && (prefix.Bits() < 8 || prefix.Bits() > 30) {
				add("%s: the network size /%d doesn't leave room for other devices (use /8 to /30)", name, prefix.Bits())
			}
			if prefix.Addr() == prefix.Masked().Addr() {
				add("%s: %s is the network's own address; pick a host address", name, a.Address)
			}
			if prefix.Addr().Is4() && prefix.Bits() < 31 && isBroadcast(prefix) {
				add("%s: %s is the network's broadcast address", name, a.Address)
			}
			if a.Gateway != "" {
				gateways++
				gw, err := netip.ParseAddr(a.Gateway)
				switch {
				case err != nil || gw.Zone() != "":
					add("%s: gateway %q is not an IP address", name, a.Gateway)
				case !prefix.Masked().Contains(gw):
					add("%s: gateway %s is outside %s, so the server couldn't reach it", name, a.Gateway, prefix.Masked())
				case gw == prefix.Addr():
					add("%s: the gateway can't be the server's own address", name)
				}
			}
		case ModeOff:
			if a.Address != "" || a.Gateway != "" {
				add("%s is off, so it can't have an address", name)
			}
		case ModeMember:
			if !allowMember {
				add("%s: only physical ports can be bond members", name)
			}
		default:
			add("%s: addressing must be dhcp, static or off", name)
		}
		if a.MTU != 0 && (a.MTU < 1280 || a.MTU > 9216) {
			add("%s: MTU must be between 1280 and 9216 (or empty for the default 1500)", name)
		}
	}

	for _, it := range c.Interfaces {
		if !known[it.Name] {
			add("there is no network port named %q on this server", it.Name)
			continue
		}
		claim(it.Name, "port")
		checkAddr(it.Name, it.Addressing, true)
	}
	for _, port := range ports {
		if _, ok := names[port]; !ok {
			add("port %s is missing from the settings", port)
		}
	}

	memberOf := map[string]string{}
	for _, b := range c.Bonds {
		if !bondRE.MatchString(b.Name) {
			add("bond name %q must be bond0 to bond99", b.Name)
			continue
		}
		claim(b.Name, "bond")
		if !slices.Contains(BondPolicies, b.Policy) {
			add("%s: mode must be one of %s", b.Name, strings.Join(BondPolicies, ", "))
		}
		if len(b.Members) < 1 {
			add("%s needs at least one port", b.Name)
		}
		for _, m := range b.Members {
			if !known[m] {
				add("%s: there is no network port named %q", b.Name, m)
			}
			if other, ok := memberOf[m]; ok {
				add("port %s is in both %s and %s", m, other, b.Name)
			}
			memberOf[m] = b.Name
		}
		checkAddr(b.Name, b.Addressing, false)
	}

	vlanIDs := map[string]bool{}
	for _, v := range c.VLANs {
		name := v.Name()
		if v.ID < 1 || v.ID > 4094 {
			add("VLAN ID %d on %s must be between 1 and 4094", v.ID, v.Parent)
			continue
		}
		if !ifaceRE.MatchString(v.Parent) || len(name) > 15 {
			add("VLAN %d: parent %q is not a valid interface name", v.ID, v.Parent)
			continue
		}
		parentKind, ok := names[v.Parent]
		if !ok || (parentKind != "port" && parentKind != "bond") {
			add("VLAN %d: %s is not a port or bond on this server", v.ID, v.Parent)
		}
		if _, isMember := memberOf[v.Parent]; isMember {
			add("VLAN %d: %s is a bond member; put the VLAN on %s instead", v.ID, v.Parent, memberOf[v.Parent])
		}
		key := name
		if vlanIDs[key] {
			add("VLAN %d is defined twice on %s", v.ID, v.Parent)
		}
		vlanIDs[key] = true
		names[name] = "vlan"
		checkAddr(name, v.Addressing, false)
	}

	if c.HasStatic() && len(c.DNS) == 0 && !c.hasDHCP() {
		add("add a DNS server: with no port on DHCP, the server has no other way to look up names")
	}
	if addressed == 0 {
		add("at least one port, bond or VLAN needs an address, or the server can't be reached")
	}
	if gateways > 1 {
		add("only one interface can have a gateway")
	}
	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

func isBroadcast(p netip.Prefix) bool {
	a := p.Addr().As4()
	host := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	mask := uint32(0xffffffff) >> p.Bits()
	return host&mask == mask
}

// HasStatic reports whether any interface uses a fixed address.
func (c *Config) HasStatic() bool {
	for _, it := range c.Interfaces {
		if it.Mode == ModeStatic {
			return true
		}
	}
	for _, b := range c.Bonds {
		if b.Mode == ModeStatic {
			return true
		}
	}
	for _, v := range c.VLANs {
		if v.Mode == ModeStatic {
			return true
		}
	}
	return false
}

func (c *Config) hasDHCP() bool {
	for _, it := range c.Interfaces {
		if it.Mode == ModeDHCP {
			return true
		}
	}
	for _, b := range c.Bonds {
		if b.Mode == ModeDHCP {
			return true
		}
	}
	for _, v := range c.VLANs {
		if v.Mode == ModeDHCP {
			return true
		}
	}
	return false
}

// StaticAddresses lists the fixed addresses (without prefix length), so the
// UI can say where the server will be after a change.
func (c *Config) StaticAddresses() []string {
	var out []string
	each := func(a Addressing) {
		if a.Mode == ModeStatic {
			if p, err := netip.ParsePrefix(a.Address); err == nil {
				out = append(out, p.Addr().String())
			}
		}
	}
	for _, it := range c.Interfaces {
		each(it.Addressing)
	}
	for _, b := range c.Bonds {
		each(b.Addressing)
	}
	for _, v := range c.VLANs {
		each(v.Addressing)
	}
	return out
}

// Default is DHCP on every port, which is what a fresh install uses.
func Default(hostname string, ports []string) Config {
	c := Config{Hostname: hostname, DNS: []string{}, Search: []string{}, Bonds: []Bond{}, VLANs: []VLAN{}}
	for _, p := range ports {
		c.Interfaces = append(c.Interfaces, Interface{Name: p, Addressing: Addressing{Mode: ModeDHCP}})
	}
	if c.Interfaces == nil {
		c.Interfaces = []Interface{}
	}
	c.Normalize()
	return c
}

// TimeConfig is the server's clock setup.
type TimeConfig struct {
	Timezone string `json:"timezone"`
	// NTP keeps the clock right over the network (chrony).
	NTP bool `json:"ntp"`
	// NTPServers are host names or addresses; empty uses the Debian pool.
	NTPServers []string `json:"ntpServers"`
}

var (
	tzRE      = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$`)
	ntpHostRE = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)
)

// ErrNoTimezone is returned for an unknown time zone.
var ErrNoTimezone = errors.New("unknown time zone")

// Validate checks t. zoneExists reports whether a time zone name exists.
func (t *TimeConfig) Validate(zoneExists func(string) bool) error {
	var p []string
	t.NTPServers = cleanList(t.NTPServers)
	if !tzRE.MatchString(t.Timezone) || strings.Contains(t.Timezone, "..") || !zoneExists(t.Timezone) {
		p = append(p, fmt.Sprintf("%q is not a known time zone", t.Timezone))
	}
	if len(t.NTPServers) > 8 {
		p = append(p, "at most 8 time servers")
	}
	for _, s := range t.NTPServers {
		if _, err := netip.ParseAddr(s); err == nil {
			continue
		}
		if !ntpHostRE.MatchString(s) || !domainRE.MatchString(s) {
			p = append(p, fmt.Sprintf("time server %q is not a host name or IP address", s))
		}
	}
	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}
