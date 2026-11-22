package nbstandby

import "net/netip"

// nonPublic are ranges that are never a server's internet address: shared
// address space (CGNAT, and NetBird's own network), IETF protocol
// assignments, benchmarking, documentation, reserved, NAT64 and Teredo
// (decision 424, L8 of the security review).
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

// PublicAddr reports whether s is an internet address of family v4 (or v6):
// global unicast, not private, link-local or any range in nonPublic.
func PublicAddr(s string, v4 bool) bool {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" || a.Is4In6() || a.Is4() != v4 {
		return false
	}
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// PublicAddrAny is PublicAddr for either family.
func PublicAddrAny(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && PublicAddr(s, a.Is4())
}
