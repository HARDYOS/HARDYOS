package vms

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// eui64 is the link-local address SLAAC derives from a MAC.
func eui64(mac string) netip.Addr {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return netip.Addr{}
	}
	b := [16]byte{0xfe, 0x80}
	b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15] = hw[0]^2, hw[1], hw[2], 0xff, 0xfe, hw[3], hw[4], hw[5]
	return netip.AddrFrom16(b)
}

func testGuard6() Guard6 {
	return Guard6{
		Cards: []Guard6Card{{Tap: "hvabcdef0", MAC: "52:54:00:aa:bb:cc", Prefixes: []netip.Prefix{
			netip.MustParsePrefix("2001:db8:1::/64"), netip.MustParsePrefix("fd00:1::/64"),
			netip.MustParsePrefix("2001:db8::/32"), // too short: ignored
			netip.MustParsePrefix("fe80::/64"),     // link-local has its own rule
		}}, {Tap: "hvabcdef2", MAC: "52:54:00:aa:bb:ce", NoIPv6: true}},
		Spoof: []string{"hvabcdef1"},
		Protected: []netip.Addr{netip.MustParseAddr("fe80::1"), netip.MustParseAddr("2001:db8:1::10"), netip.MustParseAddr("fe80::1"),
			netip.MustParseAddr("::"), netip.MustParseAddr("ff02::1")},
		Learned: []Learned6{{Addr: netip.MustParseAddr("fe80::77"), TTL: 300}, {Addr: netip.MustParseAddr("fe80::77"), MAC: "52:54:00:77:77:77", TTL: 99999}},
	}
}

func TestRenderGuard6(t *testing.T) {
	text, err := RenderGuard6(testGuard6())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table bridge hardyos_vmguard6\ndelete table bridge hardyos_vmguard6\n",
		"elements = { 2001:db8:1::10, fe80::1 }",
		"elements = { fe80::77 timeout 300s }",
		"elements = { fe80::77 . 52:54:00:77:77:77 timeout 3600s }",
		`elements = { "hvabcdef1" }`,
		`iifname != "hv*" ether type ip6 ip6 saddr != :: meta l4proto ipv6-icmp icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } update @lanaddrs`,
		"iifname @spoofok accept",
		`iifname "hvabcdef0" ether type ip6 jump g_hvabcdef0`,
		`iifname "hvabcdef0" ether type { 8021q, 8021ad } drop`,
		"\t\tiifname \"hv*\" ether type ip6 drop\n\t}\n",
		"chain g_hvabcdef2 {\n\t\tdrop\n\t}",
		"ether saddr != 52:54:00:aa:bb:cc drop",
		"ip6 saddr @lanaddrs ip6 saddr . ether saddr != @lanpairs drop",
		"exthdr frag exists meta l4proto ipv6-icmp drop",
		"frag frag-off 0 meta l4proto udp jump frag_udp",
		"icmpv6 type { nd-router-advert, nd-redirect, router-renumbering, mld-listener-query, 151, 153 } drop",
		"udp sport 547 drop", "udp dport 546 drop",
		"icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } icmpv6 taddr @protected drop",
		"icmpv6 taddr @lanaddrs icmpv6 taddr . ether saddr != @lanpairs drop",
		"@th,208,48 != 0x525400aabbcc drop",
		"ip6 saddr fe80::/64 meta l4proto " + knownL4 + " accept",
		"ip6 saddr { 2001:db8:1::/64, fd00:1::/64 } meta l4proto " + knownL4 + " accept",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	if strings.Contains(text, "2001:db8::/32") || strings.Contains(text, "ff02::1") || strings.Count(text, "fe80::/64") != 1 {
		t.Fatalf("a prefix or address that isn't allowed:\n%s", text)
	}
	// The catch-all comes after every card's jump.
	if strings.Index(text, "jump g_hvabcdef2") > strings.Index(text, "iifname \"hv*\" ether type ip6 drop") {
		t.Fatal("catch-all before a card's chain")
	}
	if again, _ := RenderGuard6(testGuard6()); again != text {
		t.Fatal("not deterministic")
	}
	// Nothing filtered: IPv6 from every VM card is still dropped.
	if empty, err := RenderGuard6(Guard6{}); err != nil || strings.Contains(empty, "jump g_") || !strings.Contains(empty, `iifname "hv*" ether type ip6 drop`) {
		t.Fatalf("%q %v", empty, err)
	}
	for name, g := range map[string]Guard6{
		"bad tap":       {Cards: []Guard6Card{{Tap: "eth0\" accept #", MAC: "52:54:00:aa:bb:cc"}}},
		"vnet tap":      {Cards: []Guard6Card{{Tap: "vnet0", MAC: "52:54:00:aa:bb:cc"}}},
		"twice":         {Cards: []Guard6Card{{Tap: "hvabcdef0", MAC: "52:54:00:aa:bb:cc"}, {Tap: "hvabcdef0", MAC: "52:54:00:aa:bb:cd"}}},
		"multicast mac": {Cards: []Guard6Card{{Tap: "hvabcdef0", MAC: "33:33:00:00:00:01"}}},
		"bad mac":       {Cards: []Guard6Card{{Tap: "hvabcdef0", MAC: "52:54:00:aa:bb:cc } accept"}}},
		"bad spoof tap": {Spoof: []string{"eth0"}},
		"both":          {Cards: []Guard6Card{{Tap: "hvabcdef0", MAC: "52:54:00:aa:bb:cc"}}, Spoof: []string{"hvabcdef0"}},
	} {
		if _, err := RenderGuard6(g); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
	// Duplicates don't count towards the cap; over it, nothing renders.
	many := Guard6{}
	for i := 0; i <= maxProtected; i++ {
		a := netip.MustParseAddr("2001:db8::" + strconv.FormatInt(int64(i+1), 16))
		many.Protected = append(many.Protected, a, a)
	}
	if _, err := RenderGuard6(many); err == nil {
		t.Fatal("too many protected addresses")
	}
	many.Protected = many.Protected[:2*maxProtected]
	if _, err := RenderGuard6(many); err != nil {
		t.Fatalf("duplicates counted: %v", err)
	}
	// Learned values that aren't addresses or MACs are dropped, not
	// written into the ruleset.
	bad := Guard6{Learned: []Learned6{{Addr: netip.MustParseAddr("fe80::5"), MAC: "x } accept", TTL: 5}}}
	if text, _ := RenderGuard6(bad); strings.Contains(text, "accept\n\t\t}") || strings.Contains(text, "x }") {
		t.Fatalf("%s", text)
	}
	if e := emergencyGuard6([]string{"hvabcdef1", "bad\""}); !strings.Contains(e, `iifname { "hvabcdef1" } accept`) || strings.Contains(e, "bad") || !strings.Contains(e, `iifname "hv*" ether type ip6 drop`) {
		t.Fatalf("emergency %s", e)
	}
}

func TestParseNetInfo6(t *testing.T) {
	routes := `[{"dst":"2001:db8:1::/64","protocol":"ra"},{"dst":"fd00:1::/64","protocol":"kernel"},{"dst":"fe80::/64","protocol":"kernel"},
	  {"dst":"2001:db8:9::/64","gateway":"fe80::2","protocol":"static"},{"dst":"2001:db8:7::/48","protocol":"bird"},
	  {"dst":"default","gateway":"fe80::1","protocol":"ra"},{"dst":"default","nexthops":[{"gateway":"fe80::3"}]},{"dst":"::/0","protocol":"kernel"}]`
	addrs := `[{"ifname":"br0","addr_info":[{"family":"inet6","local":"2001:db8:1::10"},{"family":"inet6","local":"fe80::10"},{"family":"inet","local":"192.168.1.10"}]}]`
	neigh := `[{"dst":"fe80::4","lladdr":"aa:bb:cc:dd:ee:01","router":null,"state":["STALE"]},{"dst":"fe80::5","lladdr":"aa:bb:cc:dd:ee:02","state":["REACHABLE"]}]`
	ni := parseNetInfo6([]byte(routes), []byte(addrs), []byte(neigh))
	var p, a []string
	for _, x := range ni.prefixes {
		p = append(p, x.String())
	}
	for _, x := range ni.protected {
		a = append(a, x.String())
	}
	sort.Strings(a)
	if !ni.present || strings.Join(p, " ") != "2001:db8:1::/64 fd00:1::/64" {
		t.Fatalf("prefixes %v", p)
	}
	if strings.Join(a, " ") != "2001:db8:1::10 fe80::1 fe80::10 fe80::2 fe80::3 fe80::4" {
		t.Fatalf("protected %v", a)
	}
	if ni := parseNetInfo6([]byte("not json"), nil, nil); len(ni.prefixes)+len(ni.protected) != 0 {
		t.Fatal("garbage")
	}
	l := parseLearned([]byte(`{"nftables": [{"metainfo": {}}, {"set": {"name": "lanpairs", "elem": [{"elem": {"val": {"concat": ["fe80::99", "52:54:00:11:22:33"]}, "timeout": 3000, "expires": 2999}}, {"elem": {"val": "fe80::98", "expires": 10}}, {"elem": {"val": "nope", "expires": 10}}]}}]}`))
	if len(l) != 2 || l[0].MAC != "52:54:00:11:22:33" || l[0].TTL != 2999 || l[1].Addr.String() != "fe80::98" {
		t.Fatalf("learned %+v", l)
	}
}

// A VM with a filtered card starts only with HardyOS's filter defined and
// its card's IPv6 rules loaded; a card that may spoof is accepted as it
// is; a VLAN the server has no interface on gets no IPv6; a VM whose rules
// can't be loaded doesn't start, and the emergency table closes IPv6.
func TestStartLoadsIPv6Guard(t *testing.T) {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	write(t, e.root+"/etc/resolv.conf", "nameserver 2001:db8:1::53\nnameserver 192.168.1.1\n")
	ctx := context.Background()
	spec := linuxSpec(t)
	spec.NICs = append(spec.NICs, NIC{Mode: NICVLAN, VLAN: 7, Model: "virtio"})
	res, err := e.m.Create(ctx, CreateArgs{Spec: spec, Password: "longenough"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Start(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	f := e.sim.nwfilters[HardyOSFilter]
	if !strings.Contains(f, "<filterref filter='clean-traffic'/>") || !strings.Contains(f, "<mac protocolid='ipv6'/>") || !strings.Contains(f, hardyosFilterUUID) {
		t.Fatalf("filter %q", f)
	}
	tap, vtap := tapName(res.VM.UUID, 0), tapName(res.VM.UUID, 1)
	for _, want := range []string{"jump g_" + tap, "ether saddr != " + res.VM.NICs[0].MAC, "ip6 saddr { 2001:db8:1::/64 } meta l4proto",
		"elements = { 2001:db8:1::10, 2001:db8:1::53, fe80::1, fe80::10, fe80::4 }", "chain g_" + vtap + " {\n\t\tdrop\n\t}"} {
		if !strings.Contains(e.sim.nft6, want) {
			t.Fatalf("missing %q:\n%s", want, e.sim.nft6)
		}
	}
	// The qemu hook: its cards have their chains.
	x := e.sim.defined["web"]
	if err := e.m.CheckGuardedStart(ctx, x); err != nil {
		t.Fatalf("hook check: %v", err)
	}
	// Every refresh reloads the whole table (whatever changed in the
	// kernel is put back), keeping what the data plane learned.
	e.sim.nft6Learned = `{"nftables": [{"set": {"elem": [{"elem": {"val": "fe80::66", "expires": 120}}]}}]}`
	n := strings.Count(strings.Join(e.sim.Lines(), "\n"), "nft -f -")
	e.m.refreshGuard6(ctx)
	if strings.Count(strings.Join(e.sim.Lines(), "\n"), "nft -f -") != n+1 || !strings.Contains(e.sim.nft6, "fe80::66 timeout 120s") {
		t.Fatalf("refresh:\n%s", e.sim.nft6)
	}
	// A network that can't be read keeps what was read of it last.
	e.sim.fail["ip -j -6 addr"] = "RTNETLINK answers: Device or resource busy"
	e.m.refreshGuard6(ctx)
	if !strings.Contains(e.sim.nft6, "2001:db8:1::10") {
		t.Fatalf("lost the last good read:\n%s", e.sim.nft6)
	}
	delete(e.sim.fail, "ip -j -6 addr")

	// Allowing spoofing: no chain, accepted as it is.
	s := res.VM.Spec
	s.NICs[0].AllowSpoofing = true
	if err := e.m.guardVM(ctx, &s); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(e.sim.nft6, "g_"+tap) || !strings.Contains(e.sim.nft6, strconv.Quote(tap)) {
		t.Fatalf("a card that may spoof:\n%s", e.sim.nft6)
	}
	// Now the filtered card's chain is gone: the hook refuses the domain.
	if err := e.m.CheckGuardedStart(ctx, x); err == nil {
		t.Fatal("hook passed a filtered card without its chain")
	}

	// The rules can't be loaded: the VM doesn't start, and IPv6 from VM
	// cards is closed by the emergency table.
	e2 := newEnv(t)
	e2.bridge.name = "br0"
	e2.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	if _, err := e2.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	e2.sim.nft6Fail = true
	if _, err := e2.m.Start(ctx, "web"); err == nil || !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("start = %v", err)
	}
	if s := e2.m.state(ctx, "web"); s != "stopped" {
		t.Fatalf("state %s", s)
	}
	if !strings.Contains(e2.sim.nft6, `iifname "hv*" ether type ip6 drop`) || strings.Contains(e2.sim.nft6, "jump g_") {
		t.Fatalf("emergency table:\n%s", e2.sim.nft6)
	}
	// A network never read and unreadable: no reload, the start fails.
	e3 := newEnv(t)
	e3.bridge.name = "br0"
	e3.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	if _, err := e3.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	e3.sim.fail["ip -j -6 route"] = "RTNETLINK answers: Operation not permitted"
	if _, err := e3.m.Start(ctx, "web"); err == nil {
		t.Fatal("started without reading its network")
	}
}

// The qemu hook reads the domain's filtered cards.
func TestGuardedTaps(t *testing.T) {
	x := `<domain><devices><interface type="bridge"><target dev="hvabcdef0"/><filterref filter="hardyos-clean-traffic"/></interface>
	<interface type="bridge"><target dev="hvabcdef1"/></interface><interface type="network"><target dev="hvabcdef2"/><filterref filter="clean-traffic"/></interface></devices></domain>`
	l, err := guardedTaps(x)
	if err != nil || strings.Join(l, ",") != "hvabcdef0" {
		t.Fatalf("%v %v", l, err)
	}
	if _, err := guardedTaps(`<domain><devices><interface><target dev="vnet0"/><filterref filter="hardyos-clean-traffic"/></interface></devices></domain>`); err == nil {
		t.Fatal("a filtered card with libvirt's own device name")
	}
}

// The kernel's address changes reach the refresh (Linux, in a namespace of
// its own: HARDYOS_NFT_TEST=1 as root).
func TestNetlinkWatchKicks(t *testing.T) {
	if os.Getenv("HARDYOS_IN_NETNS") != "1" {
		if os.Getenv("HARDYOS_NFT_TEST") != "1" {
			t.Skip("set HARDYOS_NFT_TEST=1 (as root) to watch netlink in a namespace")
		}
		cmd := exec.Command("unshare", "-n", os.Args[0], "-test.run", "^TestNetlinkWatchKicks$", "-test.v")
		cmd.Env = append(os.Environ(), "HARDYOS_IN_NETNS=1")
		out, err := cmd.CombinedOutput()
		t.Logf("%s", out)
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kicked := make(chan struct{}, 16)
	go func() { _ = watchNetlink6(ctx, func() { kicked <- struct{}{} }) }()
	time.Sleep(300 * time.Millisecond)
	if out, err := exec.Command("ip", "link", "add", "d0", "type", "veth", "peer", "name", "d1").CombinedOutput(); err != nil {
		t.Fatalf("ip link add: %v %s", err, out)
	}
	select {
	case <-kicked:
	case <-time.After(5 * time.Second):
		t.Fatal("no event for a new link")
	}
	if _, err := os.Stat("/proc/sys/net/ipv6"); err != nil {
		t.Log("no IPv6 in this kernel: link events only")
		return
	}
	for len(kicked) > 0 {
		<-kicked
	}
	for _, c := range [][]string{{"link", "set", "d0", "up"}, {"-6", "addr", "add", "2001:db8:5::1/64", "dev", "d0", "nodad"}} {
		if out, err := exec.Command("ip", c...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", c, err, out)
		}
	}
	select {
	case <-kicked:
	case <-time.After(5 * time.Second):
		t.Fatal("no event for a new IPv6 address")
	}
}

// ---- in network namespaces ------------------------------------------------------

// frame6 builds an Ethernet frame with an IPv6 packet whose flow label is
// the case's number. ext puts a hop-by-hop header in front of the payload.
func frame6(src string, mark int, saddr, daddr string, next byte, payload []byte, ext bool) []byte {
	hw, _ := net.ParseMAC(src)
	f := append([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, hw...)
	f = append(f, 0x86, 0xdd)
	body := payload
	if ext {
		body = append([]byte{next, 0, 1, 4, 0, 0, 0, 0}, payload...)
		next = 0
	}
	h := make([]byte, 40)
	binary.BigEndian.PutUint32(h[0:], 6<<28|uint32(mark))
	binary.BigEndian.PutUint16(h[4:], uint16(len(body)))
	h[6], h[7] = next, 255
	s, d := netip.MustParseAddr(saddr).As16(), netip.MustParseAddr(daddr).As16()
	copy(h[8:], s[:])
	copy(h[24:], d[:])
	return append(append(f, h...), body...)
}

func icmp6(typ byte, rest ...[]byte) []byte {
	b := []byte{typ, 0, 0, 0}
	for _, r := range rest {
		b = append(b, r...)
	}
	return b
}

func a16(s string) []byte { a := netip.MustParseAddr(s).As16(); return a[:] }

func lla(typ byte, mac string) []byte {
	hw, _ := net.ParseMAC(mac)
	return append([]byte{typ, 1}, hw...)
}

// TestGuard6InNamespaces bridges a "VM" and another computer in network
// namespaces, loads the rendered table on the bridge's namespace and sends
// crafted frames from the VM: the computer sees exactly the allowed ones.
// Root and the kernel only: HARDYOS_NFT_TEST=1 (CI's Cluster (namespaces)
// job).
func TestGuard6InNamespaces(t *testing.T) {
	if os.Getenv("HARDYOS_NFT_TEST") != "1" {
		t.Skip("set HARDYOS_NFT_TEST=1 (as root) to run the namespace test")
	}
	const mac, other = "52:54:00:aa:bb:cc", "52:54:00:11:22:33"
	g := testGuard6()
	text, err := RenderGuard6(g)
	if err != nil {
		t.Fatal(err)
	}
	ll := eui64(mac).String()
	priv := "2001:db8:1::8c3e:17ff:aa01:5d2e" // a privacy address
	z4 := []byte{0, 0, 0, 0}
	nonce := []byte{14, 1, 1, 2, 3, 4, 5, 6}
	na := func(target string, opt []byte) []byte { return icmp6(136, []byte{0x20, 0, 0, 0}, a16(target), opt) }
	ns := func(target string, opt []byte) []byte { return icmp6(135, z4, a16(target), opt) }
	udp := func(sport, dport uint16) []byte {
		b := make([]byte, 12)
		binary.BigEndian.PutUint16(b[0:], sport)
		binary.BigEndian.PutUint16(b[2:], dport)
		binary.BigEndian.PutUint16(b[4:], 12)
		return b
	}
	frag := func(next byte, off uint16, more bool) []byte {
		b := []byte{next, 0, 0, 0, 0, 0, 0x12, 0x34}
		v := off << 3
		if more {
			v |= 1
		}
		binary.BigEndian.PutUint16(b[2:], v)
		return b
	}
	cat := func(l ...[]byte) []byte {
		var b []byte
		for _, x := range l {
			b = append(b, x...)
		}
		return b
	}
	type tc struct {
		name  string
		frame []byte
		pass  bool
	}
	cases := []tc{
		{"NS from its EUI-64 link-local", frame6(mac, 1, ll, "ff02::1:ff00:1", 58, ns("fe80::5", lla(1, mac)), false), true},
		{"NA for its own global address", frame6(mac, 2, priv, "ff02::1", 58, na(priv, lla(2, mac)), false), true},
		{"UDP from a privacy address", frame6(mac, 3, priv, "2001:db8:1::99", 17, udp(40000, 53), false), true},
		{"UDP from the unique-local prefix", frame6(mac, 4, "fd00:1::42", "fd00:1::99", 17, udp(40000, 53), false), true},
		{"UDP from a random link-local", frame6(mac, 5, "fe80::1234:5678:9abc:def0", "ff02::1", 17, udp(40000, 9), false), true},
		{"DAD solicitation", frame6(mac, 6, "::", "ff02::1:ff00:1", 58, ns(priv, nil), false), true},
		{"DAD solicitation with a nonce", frame6(mac, 7, "::", "ff02::1:ff00:1", 58, ns(priv, nonce), false), true},
		{"MLDv2 report from ::", frame6(mac, 8, "::", "ff02::16", 58, icmp6(143, []byte{0, 0, 0, 0}), false), true},
		{"DHCPv6 client solicit", frame6(mac, 9, ll, "ff02::1:2", 17, udp(546, 547), false), true},
		{"NS without options", frame6(mac, 10, ll, "ff02::1:ff00:1", 58, ns("fe80::5", nil), false), true},

		{"UDP from outside the prefixes", frame6(mac, 20, "2001:db8:2::1", "2001:db8:1::99", 17, udp(40000, 53), false), false},
		{"router advertisement", frame6(mac, 21, ll, "ff02::1", 58, icmp6(134, make([]byte, 12)), false), false},
		{"router advertisement behind a hop-by-hop header", frame6(mac, 22, ll, "ff02::1", 58, icmp6(134, make([]byte, 12)), true), false},
		{"redirect", frame6(mac, 23, ll, "fe80::5", 58, icmp6(137, z4, a16("fe80::9"), a16("2001:db8:1::5")), false), false},
		{"multicast listener query", frame6(mac, 35, ll, "ff02::1", 58, icmp6(130, z4, a16("::")), false), false},
		{"multicast listener report", frame6(mac, 11, ll, "ff02::16", 58, icmp6(143, z4), false), true},
		{"DHCPv6 advertise (a server)", frame6(mac, 24, ll, "fe80::5", 17, udp(547, 546), false), false},
		{"NA for the router", frame6(mac, 25, ll, "ff02::1", 58, na("fe80::1", lla(2, mac)), false), false},
		{"NA for the router behind a hop-by-hop header", frame6(mac, 26, ll, "ff02::1", 58, na("fe80::1", lla(2, mac)), true), false},
		{"NA for the server's address", frame6(mac, 27, priv, "ff02::1", 58, na("2001:db8:1::10", lla(2, mac)), false), false},
		{"from the router's address", frame6(mac, 28, "fe80::1", "ff02::1", 17, udp(40000, 9), false), false},
		{"UDP from ::", frame6(mac, 29, "::", "ff02::1", 17, udp(40000, 9), false), false},
		{"DAD solicitation with a link-layer option", frame6(mac, 30, "::", "ff02::1:ff00:1", 58, ns(priv, lla(1, mac)), false), false},
		{"NS with another MAC", frame6(mac, 31, ll, "ff02::1:ff00:1", 58, ns("fe80::5", lla(1, other)), false), false},
		{"NA with another MAC", frame6(mac, 32, priv, "ff02::1", 58, na(priv, lla(2, other)), false), false},
		{"NA with a nonce first", frame6(mac, 33, priv, "ff02::1", 58, na(priv, append(nonce, lla(2, other)...)), false), false},
		{"from another MAC", frame6(other, 34, ll, "ff02::1", 17, udp(40000, 9), false), false},

		// Fragments and header chains nft can't follow (review M1).
		{"fragmented router advertisement", frame6(mac, 40, ll, "ff02::1", 44, cat(frag(58, 0, true), icmp6(134, make([]byte, 12))), false), false},
		{"fragmented DHCPv6 reply, UDP header in the next fragment", frame6(mac, 41, ll, "fe80::5", 44, cat(frag(60, 0, true), []byte{17, 0, 1, 4, 0, 0, 0, 0}), false), false},
		{"truncated header chain", frame6(mac, 42, ll, "fe80::5", 44, cat(frag(60, 0, true), []byte{17, 1, 1, 4, 0, 0, 0, 0}), false), false},
		{"first fragment of a DHCPv6 reply", frame6(mac, 43, ll, "fe80::5", 44, cat(frag(17, 0, true), udp(547, 546)), false), false},
		{"a later UDP fragment", frame6(mac, 12, ll, "fe80::5", 44, cat(frag(17, 1, false), make([]byte, 16)), false), true},
		{"first fragment of ordinary UDP", frame6(mac, 13, ll, "fe80::5", 44, cat(frag(17, 0, true), udp(40000, 53)), false), true},
		{"an unknown transport", frame6(mac, 44, ll, "fe80::5", 253, make([]byte, 16), false), false},
		{"multicast router advertisement (151)", frame6(mac, 45, ll, "ff02::6a", 58, icmp6(151, z4), false), false},
		{"multicast router termination (153)", frame6(mac, 46, ll, "ff02::6a", 58, icmp6(153, z4), false), false},
		// Duplicate address detection against protected addresses (M3).
		{"DAD for the router's address", frame6(mac, 47, "::", "ff02::1:ff00:1", 58, ns("fe80::1", nil), false), false},
		{"DAD for the server's address", frame6(mac, 48, "::", "ff02::1:ff00:10", 58, ns("2001:db8:1::10", nil), false), false},
		// Addresses other computers use (M2): carried over a reload, and
		// learned from the network's own port.
		{"from an address learned before the reload", frame6(mac, 49, "fe80::77", "ff02::1", 17, udp(40000, 9), false), false},
		{"NA for an address learned before the reload", frame6(mac, 50, ll, "ff02::1", 58, na("fe80::77", lla(2, mac)), false), false},
		{"from an address the LAN computer uses", frame6(mac, 51, "fe80::abcd", "ff02::1", 17, udp(40000, 9), false), false},
		{"DAD for the LAN computer's address", frame6(mac, 52, "::", "ff02::1:ff00:abcd", 58, ns("fe80::abcd", nil), false), false},
		// Other cards (M4).
		{"a card that may spoof", frame6(other, 14, "2001:db8:9::1", "ff02::1", 58, icmp6(134, make([]byte, 12)), false), true},
		{"a card on a network the server doesn't know", frame6("52:54:00:aa:bb:ce", 53, "fe80::5054:ff:feaa:bbce", "ff02::1", 17, udp(40000, 9), false), false},
		{"a card without a chain", frame6("52:54:00:aa:bb:cf", 54, "fe80::5054:ff:feaa:bbcf", "ff02::1", 17, udp(40000, 9), false), false},
	}
	// The VM side's interface of each case: eth0 is the filtered card.
	ifaceOf := map[string]string{"a card that may spoof": "eth1", "a card on a network the server doesn't know": "eth2", "a card without a chain": "eth3"}
	iface := func(c tc) string {
		if i := ifaceOf[c.name]; i != "" {
			return i
		}
		return "eth0"
	}
	// The LAN computer's neighbour solicitation, before the VM's frames.
	learn := frame6("52:54:00:99:99:99", 99, "fe80::abcd", "ff02::1:ff00:5", 58, ns("fe80::5", lla(1, "52:54:00:99:99:99")), false)
	// IPv4 isn't the table's (clean-traffic's): it passes here.
	hw, _ := net.ParseMAC(mac)
	v4 := append(append([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, hw...), 0x08, 0x00, 0x45, 0, 0, 28, 0, 50, 0, 0, 64, 17, 0, 0, 192, 168, 1, 77, 255, 255, 255, 255)
	var sum uint32
	for i := 14; i < 34; i += 2 {
		sum += uint32(v4[i])<<8 | uint32(v4[i+1])
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(v4[24:], ^uint16(sum))
	u := udp(40000, 9)[:8]
	binary.BigEndian.PutUint16(u[4:], 8)
	v4 = append(v4, u...)
	var frames []string
	for _, c := range cases {
		frames = append(frames, iface(c)+" "+hex.EncodeToString(c.frame))
	}
	frames = append(frames, "eth0 "+hex.EncodeToString(v4), "eth3 "+hex.EncodeToString(v4))

	dir := t.TempDir()
	for name, body := range map[string]string{
		"guard.nft":  text,
		"frames.hex": strings.Join(frames, "\n") + "\n",
		"learn.hex":  "eth0 " + hex.EncodeToString(learn) + "\n",
		"send.py": `import socket, sys, time
socks = {}
for line in open(sys.argv[1]):
    iface, frame = line.split()
    if iface not in socks:
        socks[iface] = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        socks[iface].bind((iface, 0))
    socks[iface].send(bytes.fromhex(frame)); time.sleep(0.02)
`,
		"sniff.py": `import socket, sys, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind(("eth0", 0)); s.settimeout(0.2)
open(sys.argv[1], "w").write("ready")
end = time.time() + 6
seen = set()
while time.time() < end:
    try:
        b, addr = s.recvfrom(2048)
    except socket.timeout:
        continue
    if addr[2] == 4:
        continue
    if b[12:14] == b"\x86\xdd":
        seen.add(((b[15] & 0x0f) << 16) | (b[16] << 8) | b[17])
    elif b[12:14] == b"\x08\x00" and b[18:20] == b"\x00\x32":
        seen.add("v4")
print(" ".join(sorted(str(x) for x in seen)))
`,
	} {
		if err := os.WriteFile(dir+"/"+name, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sh := `set -e
H=hos-g6h-$$; V=hos-g6v-$$; L=hos-g6l-$$
cleanup() { ip netns del $H 2>/dev/null; ip netns del $V 2>/dev/null; ip netns del $L 2>/dev/null; }
trap cleanup EXIT
ip netns add $H; ip netns add $V; ip netns add $L
for n in $V $L; do ip netns exec $n sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 2>/dev/null || true; done
ip -n $H link add br0 type bridge mcast_snooping 0
# A kernel without IPv6 has br_netfilter drop every IPv6 frame.
[ -d /proc/sys/net/ipv6 ] || ip netns exec $H sysctl -qw net.bridge.bridge-nf-call-ip6tables=0 2>/dev/null || true
for i in 0 1 2 3; do
  ip link add hvabcdef$i netns $H type veth peer name eth$i netns $V
  ip -n $H link set hvabcdef$i master br0; ip -n $H link set hvabcdef$i up; ip -n $V link set eth$i up
done
ip link add lan0 netns $H type veth peer name eth0 netns $L
ip -n $H link set lan0 master br0
for n in $H $V $L; do ip -n $n link set lo up; done
ip -n $H link set br0 up; ip -n $H link set lan0 up; ip -n $L link set eth0 up
ip netns exec $H nft -f DIR/guard.nft
ip netns exec $H nft -f DIR/guard.nft
sleep 1
ip netns exec $L python3 -I DIR/sniff.py DIR/ready > DIR/seen &
SNIFF=$!
for i in $(seq 50); do [ -f DIR/ready ] && break; sleep 0.1; done
ip netns exec $L python3 -I DIR/send.py DIR/learn.hex
sleep 0.3
ip netns exec $H nft list set bridge hardyos_vmguard6 lanpairs | grep -q 'fe80::abcd . 52:54:00:99:99:99' || { echo "not learned"; ip netns exec $H nft list set bridge hardyos_vmguard6 lanpairs; exit 1; }
ip netns exec $V python3 -I DIR/send.py DIR/frames.hex
wait $SNIFF
cat DIR/seen
`
	out, err := exec.Command("bash", "-c", strings.ReplaceAll(sh, "DIR", dir)).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	seen := map[string]bool{}
	for _, f := range strings.Fields(string(out)) {
		seen[f] = true
	}
	for _, c := range cases {
		mark := strconv.Itoa(int(binary.BigEndian.Uint32(c.frame[14:]) & 0xfffff))
		if seen[mark] != c.pass {
			t.Errorf("%s: passed %v, want %v", c.name, seen[mark], c.pass)
		}
	}
	if !seen["v4"] {
		t.Error("IPv4 didn't pass")
	}
	if seen["99"] {
		t.Error("the sniffer counted its own frame")
	}
	if t.Failed() {
		t.Logf("seen by the other computer: %s", out)
	}
}

// TestHardyOSFilterDefines hands HardyOSFilter to the real libvirt, which
// must accept it (clean-traffic referenced, IPv6 let through) and give it
// back with its fixed UUID. CI's KVM job: HARDYOS_VM_INTEGRATION=1.
func TestHardyOSFilterDefines(t *testing.T) {
	if os.Getenv("HARDYOS_VM_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_VM_INTEGRATION=1 (as root, with libvirt) to define the filter")
	}
	ctx := context.Background()
	m := &Manager{Runner: sysexec.Exec{}, Root: "/"}
	if !m.hasFilter(ctx) {
		t.Fatal("libvirt has no clean-traffic filter")
	}
	if err := m.ensureFilter(ctx); err != nil {
		t.Fatal(err)
	}
	out, err := m.virsh(ctx, "nwfilter-dumpxml", HardyOSFilter)
	if err != nil {
		t.Fatal(err)
	}
	x := string(out)
	if !strings.Contains(x, hardyosFilterUUID) || !strings.Contains(x, "clean-traffic") || !strings.Contains(x, "ipv6") {
		t.Fatalf("libvirt has:\n%s", x)
	}
	// Defining it again (another hardyd-priv run) replaces it.
	m.filterDefined = false
	if err := m.ensureFilter(ctx); err != nil {
		t.Fatal(err)
	}
}
