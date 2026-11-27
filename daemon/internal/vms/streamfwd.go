package vms

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/ports"
	"github.com/hardyos/hardyos/daemon/internal/rootfile"
)

// Streaming over NetBird (decisions 404-405). Moonlight
// reaches a VM's Sunshine on fixed ports, so root forwards those ports (and
// only those) from this server's NetBird interface, for the NetBird devices
// the administrator chose (none until they choose), to the one VM whose
// streaming is published:
//
//   - nftables (table ip hardyos_streaming): DNAT of the TCP and UDP
//     streaming ports arriving on the NetBird interface from the chosen
//     peers' addresses for the server's NetBird address, to the VM's
//     address on the home network, and masquerade so the VM's answers come
//     back through the server. Sunshine's web UI and API port (47990) is
//     never forwarded.
//   - iptables (chain HARDYOS-STREAM, first in FORWARD): the same
//     packets accepted, because Docker sets FORWARD's policy to drop.
//
// NetBird's own access policies don't apply to these packets in kernel
// mode (its policy rules sit on the input hook; DNAT happens before, at
// prerouting, so the packets are forwarded, not delivered): the chosen
// peer list is the only access control, which is why it's explicit.
//
// The VM's address is never what the guest says alone: it's the one
// address that the server's neighbour table has as REACHABLE for the VM's
// MAC on the bridge, inside the bridge's subnet, that the guest also
// reports (when the guest agent runs), and whose MAC the bridge learned on
// the VM's own tap port. The card has the anti-spoofing filter on.
// The rules follow the VM: set while it runs, its streaming is published
// to at least one device and NetBird is connected; gone when it stops, is
// deleted, publishing is turned off or hardyd-priv stops. Each resync also
// checks the live ruleset and puts it back if something removed it.

// NetBirdInfo is this server's NetBird state as root sees it.
type NetBirdInfo struct {
	Connected bool
	Interface string // wt0
	IP        string // this server's NetBird address
	Network   string // the NetBird network (100.64.0.0/10 or narrower)
	// Kernel: NetBird uses kernel WireGuard (its policies don't see
	// forwarded traffic; see above).
	Kernel bool
	Peers  []NetBirdPeer
}

// NetBirdPeer is a NetBird device this server sees.
type NetBirdPeer struct {
	IP        string `json:"ip"`
	Name      string `json:"name"`
	Connected bool   `json:"connected"`
}

// MaxStreamPeers bounds the devices one VM is published to.
const MaxStreamPeers = 32

// StreamForward is one VM's forwarding.
type StreamForward struct {
	VM      string
	Iface   string   // NetBird interface
	PeerNet string   // NetBird network (the peers must be in it)
	Peers   []string // the chosen NetBird devices' addresses
	HostIP  string   // this server's NetBird address
	Bridge  string   // the home network's bridge
	VMIP    string   // the VM's verified address
	// Slot is the VM's port set (ports.StreamingSlot): its Sunshine's own
	// port numbers, forwarded as they are (decision 506).
	Slot int
}

func (f StreamForward) set() ports.StreamingSet { return ports.StreamingSlot(f.Slot) }

const (
	streamTable = "hardyos_streaming"
	streamChain = "HARDYOS-STREAM"
	// StreamRunDir holds the ruleset root loads (root's own folder).
	StreamRunDir = "/run/hardyos-streaming"
)

// netBirdRanges are where a NetBird network may lie: the shared address
// space NetBird uses (100.64.0.0/10) or private networks.
var netBirdRanges = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

func within(p netip.Prefix, outer []netip.Prefix) bool {
	for _, o := range outer {
		if o.Bits() <= p.Bits() && o.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// checkPeers validates a peer list against the NetBird network.
func checkPeers(peers []string, network netip.Prefix, host netip.Addr) error {
	if len(peers) == 0 || len(peers) > MaxStreamPeers {
		return Problems{fmt.Sprintf("choose 1 to %d NetBird devices to stream to", MaxStreamPeers)}
	}
	seen := map[string]bool{}
	for _, p := range peers {
		a, err := netip.ParseAddr(p)
		if err != nil || !a.Is4() || a.String() != p || !network.Contains(a) || a == host || seen[p] {
			return Problems{fmt.Sprintf("%q isn't another NetBird device's address (listed once)", p)}
		}
		seen[p] = true
	}
	return nil
}

// check validates every value that goes into a rule.
func (f StreamForward) check() error {
	var p Problems
	if ValidID(f.VM) != nil {
		p = append(p, "bad VM name")
	}
	if !ports.ValidStreamingSlot(f.Slot) {
		p = append(p, "bad streaming port set")
	}
	if !ifnameRE.MatchString(f.Iface) || !ifnameRE.MatchString(f.Bridge) || f.Iface == f.Bridge {
		p = append(p, "bad interface names")
	}
	pn, err := netip.ParsePrefix(f.PeerNet)
	if err != nil || !pn.Addr().Is4() || pn.Masked() != pn || !within(pn, netBirdRanges) {
		p = append(p, "the NetBird network must be an IPv4 network inside 100.64.0.0/10 or a private range")
	}
	h, err := netip.ParseAddr(f.HostIP)
	if err != nil || !h.Is4() || (pn.IsValid() && !pn.Contains(h)) {
		p = append(p, "the server's NetBird address must be in the NetBird network")
	}
	if pn.IsValid() && h.IsValid() {
		if err := checkPeers(f.Peers, pn, h); err != nil {
			p = append(p, err.Error())
		}
	}
	v, err := netip.ParseAddr(f.VMIP)
	if err != nil || !v.Is4() || !v.IsPrivate() || (pn.IsValid() && pn.Contains(v)) {
		p = append(p, "the VM's address must be a private IPv4 address outside the NetBird network")
	}
	if len(p) > 0 {
		return p
	}
	return nil
}

func portList(ps []int, rangeSep string) string {
	s := slices.Clone(ps)
	slices.Sort(s)
	s = slices.Compact(s)
	var out []string
	for i := 0; i < len(s); {
		j := i
		for j+1 < len(s) && s[j+1] == s[j]+1 {
			j++
		}
		if j-i >= 2 {
			out = append(out, strconv.Itoa(s[i])+rangeSep+strconv.Itoa(s[j]))
		} else {
			for k := i; k <= j; k++ {
				out = append(out, strconv.Itoa(s[k]))
			}
		}
		i = j + 1
	}
	return strings.Join(out, ",")
}

func sortedPeers(peers []string) []string {
	s := slices.Clone(peers)
	slices.SortFunc(s, func(a, b string) int { return netip.MustParseAddr(a).Compare(netip.MustParseAddr(b)) })
	return s
}

// RenderStreamingNFT is the nftables ruleset for a forward; nil removes
// the table. It replaces the whole table atomically (nft -f).
func RenderStreamingNFT(f *StreamForward) (string, error) {
	if f == nil {
		return "", nil
	}
	return RenderStreamingNFTAll([]StreamForward{*f})
}

// RenderStreamingNFTAll is the ruleset for every forwarded VM of this
// server (decision 506): each VM's own port set, from its own chosen
// devices, to its own address. Two forwards never share a VM, a port set
// or a VM address; none removes the table.
func RenderStreamingNFTAll(fs []StreamForward) (string, error) {
	if len(fs) == 0 {
		return "", nil
	}
	if err := checkForwards(fs); err != nil {
		return "", err
	}
	fs = slices.Clone(fs)
	slices.SortFunc(fs, func(a, b StreamForward) int { return a.Slot - b.Slot })
	var pre, fwd, post, names []string
	for _, f := range fs {
		set := f.set()
		tcp := strings.ReplaceAll(portList(set.TCP, "-"), ",", ", ")
		udp := strings.ReplaceAll(portList(set.UDP, "-"), ",", ", ")
		peers := "{ " + strings.Join(sortedPeers(f.Peers), ", ") + " }"
		names = append(names, f.VM)
		pre = append(pre,
			fmt.Sprintf("    iifname %q ip saddr %s ip daddr %s tcp dport { %s } dnat to %s", f.Iface, peers, f.HostIP, tcp, f.VMIP),
			fmt.Sprintf("    iifname %q ip saddr %s ip daddr %s udp dport { %s } dnat to %s", f.Iface, peers, f.HostIP, udp, f.VMIP))
		fwd = append(fwd,
			fmt.Sprintf("    iifname %q oifname %q ip saddr %s ip daddr %s ct status dnat tcp dport { %s } accept", f.Iface, f.Bridge, peers, f.VMIP, tcp),
			fmt.Sprintf("    iifname %q oifname %q ip saddr %s ip daddr %s ct status dnat udp dport { %s } accept", f.Iface, f.Bridge, peers, f.VMIP, udp),
			fmt.Sprintf("    iifname %q oifname %q ip saddr %s ct state established,related accept", f.Bridge, f.Iface, f.VMIP))
		post = append(post,
			fmt.Sprintf("    iifname %q oifname %q ip saddr %s ip daddr %s ct status dnat masquerade", f.Iface, f.Bridge, peers, f.VMIP))
	}
	return fmt.Sprintf(`# Made by HardyOS: game streaming for the VMs %[1]s, each from its chosen NetBird devices only (decisions 404, 506).
table ip %[2]s
delete table ip %[2]s
table ip %[2]s {
  chain prerouting {
    type nat hook prerouting priority dstnat - 5; policy accept;
%[3]s
  }
  chain forward {
    type filter hook forward priority filter - 5; policy accept;
%[4]s
  }
  chain postrouting {
    type nat hook postrouting priority srcnat - 5; policy accept;
%[5]s
  }
}
`, strings.Join(names, ", "), streamTable, strings.Join(pre, "\n"), strings.Join(fwd, "\n"), strings.Join(post, "\n")), nil
}

// checkForwards checks every forward and that no two share a VM, a port
// set or an address.
func checkForwards(fs []StreamForward) error {
	vms, slots, addrs := map[string]bool{}, map[int]string{}, map[string]string{}
	for _, f := range fs {
		if err := f.check(); err != nil {
			return err
		}
		if vms[f.VM] {
			return Problems{f.VM + " is forwarded twice"}
		}
		if o, dup := slots[f.Slot]; dup {
			return Problems{fmt.Sprintf("%s and %s have the same streaming ports", o, f.VM)}
		}
		if o, dup := addrs[f.VMIP]; dup {
			return Problems{fmt.Sprintf("%s and %s have the same address", o, f.VM)}
		}
		vms[f.VM], slots[f.Slot], addrs[f.VMIP] = true, f.VM, f.VM
	}
	return nil
}

// StreamingIPTables are the HARDYOS-STREAM chain's rules (Docker's FORWARD
// drop policy otherwise drops the forwarded packets).
func StreamingIPTables(f StreamForward) ([][]string, error) {
	if err := f.check(); err != nil {
		return nil, err
	}
	set := f.set()
	vm := f.VMIP + "/32"
	src := make([]string, 0, len(f.Peers))
	for _, p := range sortedPeers(f.Peers) {
		src = append(src, p+"/32")
	}
	srcs := strings.Join(src, ",")
	return [][]string{
		{"-i", f.Iface, "-o", f.Bridge, "-s", srcs, "-d", vm, "-p", "tcp", "-m", "multiport", "--dports", portList(set.TCP, ":"), "-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"},
		{"-i", f.Iface, "-o", f.Bridge, "-s", srcs, "-d", vm, "-p", "udp", "-m", "multiport", "--dports", portList(set.UDP, ":"), "-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"},
		{"-i", f.Bridge, "-o", f.Iface, "-s", vm, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}, nil
}

// StreamingIPTablesAll are every forward's rules.
func StreamingIPTablesAll(fs []StreamForward) ([][]string, error) {
	if err := checkForwards(fs); err != nil {
		return nil, err
	}
	var out [][]string
	for _, f := range fs {
		r, err := StreamingIPTables(f)
		if err != nil {
			return nil, err
		}
		out = append(out, r...)
	}
	return out, nil
}

// StreamingInfo is a VM's streaming state as root knows it.
type StreamingInfo struct {
	// Address is the VM's verified address on the home network ("" when
	// it isn't running or the server hasn't seen it yet).
	Address    string `json:"address"`
	User       string `json:"user"`
	CertSHA256 string `json:"certSHA256"`
	// BridgeAddress is this server's address on the home network: what
	// Sunshine sees as the client for everything forwarded from NetBird
	// (masquerade), and the only address Sunshine's web page answers
	// besides the VM itself. WebUIFrom is the address the VM's firewall
	// rule was made for.
	BridgeAddress string `json:"bridgeAddress,omitempty"`
	WebUIFrom     string `json:"webUIFrom,omitempty"`
	// Remote: publishing to NetBird devices is on; Peers are the chosen
	// devices' addresses; Forwarding: the rules are in place now;
	// NetBirdAddress is where Moonlight connects then.
	Remote         bool     `json:"remote"`
	Peers          []string `json:"peers"`
	Forwarding     bool     `json:"forwarding"`
	NetBirdAddress string   `json:"netbirdAddress,omitempty"`
	// NetBirdPeers are the devices this server sees (to choose from);
	// NetBirdKernel: kernel WireGuard (its policies don't cover the
	// forwarded ports).
	NetBirdPeers  []NetBirdPeer `json:"netbirdPeers"`
	NetBirdKernel bool          `json:"netbirdKernel"`
	// Problem says why something isn't ready, in a sentence.
	Problem string `json:"problem,omitempty"`
	// Slot is the VM's port set (decision 506): Base is Sunshine's base
	// port in the VM (Moonlight adds this server as NetBirdAddress:Base
	// when Base isn't Sunshine's standard one), WebUI its web page's port
	// (where hardyd reaches it), TCP and UDP what is forwarded.
	Slot     int   `json:"slot"`
	Base     int   `json:"base"`
	WebUI    int   `json:"webUI"`
	TCP      []int `json:"tcp"`
	UDP      []int `json:"udp"`
	AllSlots bool  `json:"allSlots"`
}

// StreamingPortsArgs records the port set a VM's Sunshine was moved to
// (hardyd moved it, through Sunshine's own settings, and checked it
// answers there).
type StreamingPortsArgs struct {
	ID   string `json:"id"`
	Slot int    `json:"slot"`
}

// StreamingPublishArgs turns publishing to NetBird devices on or off and
// names the devices (their NetBird addresses).
type StreamingPublishArgs struct {
	ID      string   `json:"id"`
	Enabled bool     `json:"enabled"`
	Peers   []string `json:"peers,omitempty"`
}

// bridgeIPv4 is the bridge's own IPv4 address and network.
func (m *Manager) bridgeIPv4(ctx context.Context, bridge string) (netip.Prefix, error) {
	if !ifnameRE.MatchString(bridge) {
		return netip.Prefix{}, errors.New("bad bridge name")
	}
	out, err := m.run(ctx, "ip", "-j", "-4", "addr", "show", "dev", bridge)
	if err != nil {
		return netip.Prefix{}, err
	}
	var links []struct {
		AddrInfo []struct {
			Family    string `json:"family"`
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
			Scope     string `json:"scope"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(out, &links); err != nil {
		return netip.Prefix{}, err
	}
	for _, l := range links {
		for _, a := range l.AddrInfo {
			ip, err := netip.ParseAddr(a.Local)
			if err != nil || !ip.Is4() || a.Scope != "global" || a.PrefixLen < 8 || a.PrefixLen > 30 {
				continue
			}
			return netip.PrefixFrom(ip, a.PrefixLen), nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("%s has no IPv4 address", bridge)
}

// neighbours are the bridge's IPv4 neighbour entries for mac, and whether
// each is REACHABLE now (`ip -j -4 neigh show dev <bridge>`).
func (m *Manager) neighbours(ctx context.Context, bridge, mac string) (reachable, other []netip.Addr) {
	out, err := m.run(ctx, "ip", "-j", "-4", "neigh", "show", "dev", bridge)
	if err != nil {
		return nil, nil
	}
	var entries []struct {
		Dst    string   `json:"dst"`
		LLAddr string   `json:"lladdr"`
		State  []string `json:"state"`
	}
	if json.Unmarshal(out, &entries) != nil {
		return nil, nil
	}
	for _, e := range entries {
		a, err := netip.ParseAddr(e.Dst)
		if err != nil || !a.Is4() || !strings.EqualFold(e.LLAddr, mac) {
			continue
		}
		if slices.Contains(e.State, "REACHABLE") {
			reachable = append(reachable, a)
		} else {
			other = append(other, a)
		}
	}
	return reachable, other
}

// macOnPort reports whether the bridge learned mac on port (`bridge -j fdb
// show br <bridge>`), and on no other port.
func (m *Manager) macOnPort(ctx context.Context, bridge, mac, port string) bool {
	out, err := m.run(ctx, "bridge", "-j", "fdb", "show", "br", bridge)
	if err != nil {
		return false
	}
	var entries []struct {
		MAC    string   `json:"mac"`
		IfName string   `json:"ifname"`
		Flags  []string `json:"flags"`
		State  string   `json:"state"`
	}
	if json.Unmarshal(out, &entries) != nil {
		return false
	}
	found := false
	for _, e := range entries {
		if !strings.EqualFold(e.MAC, mac) {
			continue
		}
		if e.IfName != port {
			return false
		}
		found = true
	}
	return found
}

func (m *Manager) dialVM(ctx context.Context, addr string) error {
	if m.streamDial != nil {
		return m.streamDial(ctx, addr)
	}
	d := net.Dialer{Timeout: time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err == nil {
		c.Close()
	}
	return err
}

// vmAddress is a running VM's verified IPv4 address on the home network
// (decision 404): exactly one REACHABLE neighbour entry for the streaming
// card's MAC, inside the bridge's subnet (not the server's own, network or
// broadcast address), also reported by the guest when it has the agent
// running, with the MAC learned by the bridge on the VM's own tap port
// only. When no entry is REACHABLE, root knocks once on the addresses the
// table or the guest has (the kernel then asks by ARP) and looks again.
// Anything else is refused.
func (m *Manager) vmAddress(ctx context.Context, st *stored) (netip.Addr, error) {
	nic, err := streamingNIC(&st.spec)
	if err != nil {
		return netip.Addr{}, err
	}
	if m.Network == nil || m.Network.BridgeName() == "" {
		return netip.Addr{}, Problems{"the home network's bridge isn't set up"}
	}
	br := m.Network.BridgeName()
	pfx, err := m.bridgeIPv4(ctx, br)
	if err != nil {
		return netip.Addr{}, err
	}
	network := pfx.Masked()
	bcast := lastAddr(network)
	inNet := func(a netip.Addr) bool {
		return a.Is4() && network.Contains(a) && a != pfx.Addr() && a != network.Addr() && a != bcast
	}
	m.statsMu.Lock()
	reported := append([]string(nil), m.addrs[st.spec.ID]...)
	m.statsMu.Unlock()
	var guest []netip.Addr
	for _, r := range reported {
		if a, err := netip.ParseAddr(r); err == nil && inNet(a) {
			guest = append(guest, a)
		}
	}
	reach, other := m.neighbours(ctx, br, nic.MAC)
	if len(reach) == 0 {
		knock := map[netip.Addr]bool{}
		for _, a := range append(append([]netip.Addr(nil), other...), guest...) {
			if inNet(a) && !knock[a] && len(knock) < 4 {
				knock[a] = true
				_ = m.dialVM(ctx, netip.AddrPortFrom(a, uint16(st.spec.StreamingPorts().WebUI)).String())
			}
		}
		if len(knock) > 0 {
			reach, _ = m.neighbours(ctx, br, nic.MAC)
		}
	}
	var cands []netip.Addr
	for _, a := range reach {
		if inNet(a) && !slices.Contains(cands, a) {
			cands = append(cands, a)
		}
	}
	if st.spec.GuestAgent && len(guest) > 0 {
		cands = slices.DeleteFunc(cands, func(a netip.Addr) bool { return !slices.Contains(guest, a) })
	}
	switch {
	case len(cands) == 0:
		return netip.Addr{}, Problems{"the server hasn't seen the VM on the home network yet (it gets its address from your router a minute after it starts)"}
	case len(cands) > 1:
		return netip.Addr{}, Problems{"the VM answers on more than one address on the home network; give it one (a DHCP reservation) so HardyOS knows which is its"}
	}
	if !m.macOnPort(ctx, br, nic.MAC, tapName(st.spec.UUID, 0)) {
		return netip.Addr{}, Problems{"the bridge doesn't see the VM's network card only on the VM's own port; HardyOS won't guess its address"}
	}
	return cands[0], nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := 32 - p.Bits()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= (1 << host) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func (m *Manager) netBird(ctx context.Context) NetBirdInfo {
	if m.NetBird == nil {
		return NetBirdInfo{}
	}
	return m.NetBird(ctx)
}

// StreamingInfo reports a VM's streaming state.
func (m *Manager) StreamingInfo(ctx context.Context, id string) (*StreamingInfo, error) {
	st, err := m.find(ctx, id)
	if err != nil {
		return nil, err
	}
	if !st.spec.StreamingSetUp() {
		return nil, Problems{st.spec.Name + " has no game streaming set up by HardyOS"}
	}
	sp := st.spec.Streaming
	set := st.spec.StreamingPorts()
	info := &StreamingInfo{User: sp.User, CertSHA256: sp.CertSHA256, Remote: sp.Remote, Peers: append([]string{}, sp.Peers...),
		WebUIFrom: sp.WebUIFrom, NetBirdPeers: []NetBirdPeer{}, Slot: set.Slot, Base: set.Base, WebUI: set.WebUI,
		TCP: slices.Clone(set.TCP), UDP: slices.Clone(set.UDP), AllSlots: sp.AllSlots}
	if m.Network != nil && m.Network.BridgeName() != "" {
		if p, err := m.bridgeIPv4(ctx, m.Network.BridgeName()); err == nil {
			info.BridgeAddress = p.Addr().String()
		}
	}
	if m.state(ctx, id) != "running" {
		info.Problem = "the VM is off"
	} else if a, err := m.vmAddress(ctx, st); err != nil {
		info.Problem = err.Error()
	} else {
		info.Address = a.String()
	}
	if info.Problem == "" && sp.WebUIFrom != "" && info.BridgeAddress != "" && sp.WebUIFrom != info.BridgeAddress {
		info.Problem = "this server's address on the home network changed since the VM was set up (" + sp.WebUIFrom + " → " + info.BridgeAddress + "); Sunshine's firewall rule in the VM still names the old one, so HardyOS can't reach Sunshine (see Game streaming in the user guide)"
	}
	m.streamMu.Lock()
	info.Forwarding = m.streamActive[id] && m.streamApplied != ""
	m.streamMu.Unlock()
	if p := slotAppPort(sp.Slot, m.appHostPorts(ctx)); info.Problem == "" && sp.Remote && p != "" {
		info.Problem = "an app of this server uses " + p + ", one of this VM's streaming ports, so it isn't forwarded; turn publishing off and on again to give it other ports"
	}
	if info.Problem == "" && sp.Remote && m.state(ctx, id) == "running" && !info.Forwarding {
		// Another published VM running here has the same port set (an HA
		// VM that came here, decision 506): neither is forwarded.
		if all, err := m.all(ctx); err == nil {
			for _, o := range all {
				if o.spec.ID != id && o.spec.StreamingSetUp() && o.spec.Streaming.Remote && o.spec.Streaming.Slot == sp.Slot && m.state(ctx, o.spec.ID) == "running" {
					info.Problem = fmt.Sprintf("%s uses the same streaming ports on this server, so neither is forwarded; turn publishing off and on again for one of them to give it other ports", o.spec.Name)
				}
			}
		}
	}
	nb := m.netBird(ctx)
	if nb.Connected {
		info.NetBirdAddress = nb.IP
		info.NetBirdKernel = nb.Kernel
		info.NetBirdPeers = append(info.NetBirdPeers, nb.Peers...)
	} else if info.Remote && info.Problem == "" {
		info.Problem = "NetBird isn't connected on this server (Control Panel › Remote Access)"
	}
	return info, nil
}

// pickStreamingSlot is the port set a VM gets when it is published
// (decision 506): its own when no other published VM this server knows
// has it, else the lowest free one. A set an app of this server holds a
// host port of is never given (decision 509). A VM set up before HardyOS
// had port sets (its firewall rule covers only the standard web UI port)
// gets the standard set only.
func pickStreamingSlot(st *stored, all []*stored, appPorts map[string]bool) (int, error) {
	used := map[int]string{}
	for _, o := range all {
		if o.spec.ID != st.spec.ID && o.spec.StreamingSetUp() && o.spec.Streaming.Remote {
			used[o.spec.Streaming.Slot] = o.spec.Name
		}
	}
	for s := 0; s < ports.StreamingSlots; s++ {
		if _, taken := used[s]; !taken {
			if p := slotAppPort(s, appPorts); p != "" {
				used[s] = "an app (its port " + p + ")"
			}
		}
	}
	cur := st.spec.Streaming.Slot
	if _, taken := used[cur]; !taken && ports.ValidStreamingSlot(cur) {
		return cur, nil
	}
	if !st.spec.Streaming.AllSlots {
		return 0, Problems{fmt.Sprintf("%s uses the standard streaming ports, and %s's game streaming was set up before HardyOS could give a VM other ports, so it can only use those (turn that off first)", used[0], st.spec.Name)}
	}
	for s := 0; s < ports.StreamingSlots; s++ {
		if _, taken := used[s]; !taken {
			return s, nil
		}
	}
	return 0, Problems{fmt.Sprintf("at most %d VMs of one server are published for game streaming, and apps may hold some of their ports; turn another one off first", ports.StreamingSlots)}
}

// slotAppPort is a port of slot s an app holds ("" none).
func slotAppPort(s int, appPorts map[string]bool) string {
	if len(appPorts) == 0 {
		return ""
	}
	set := ports.StreamingSlot(s)
	for _, p := range set.TCP {
		if k := fmt.Sprintf("%d/tcp", p); appPorts[k] {
			return k
		}
	}
	for _, p := range set.UDP {
		if k := fmt.Sprintf("%d/udp", p); appPorts[k] {
			return k
		}
	}
	return ""
}

func (m *Manager) appHostPorts(ctx context.Context) map[string]bool {
	if m.AppHostPorts == nil {
		return nil
	}
	return m.AppHostPorts(ctx)
}

// SetStreamingRemote turns publishing a VM's streaming ports to NetBird
// devices on or off. Several VMs may be published, each with its own port
// set (decision 506). The devices must be NetBird peers this server sees
// now, in its NetBird network (hardyd also leaves out NetBird's reverse
// proxy peers).
func (m *Manager) SetStreamingRemote(ctx context.Context, a StreamingPublishArgs) (*VM, error) {
	vmUnlock, err := m.lockValid(a.ID)
	if err != nil {
		return nil, err
	}
	// One choice of a port set at a time, until it is saved (two VMs
	// published at once never get the same set, decision 509).
	m.streamPick.Lock()
	unlock := func() { m.streamPick.Unlock(); vmUnlock() }
	st, err := m.find(ctx, a.ID)
	if err != nil {
		unlock()
		return nil, err
	}
	if !st.spec.StreamingSetUp() {
		unlock()
		return nil, Problems{st.spec.Name + " has no game streaming set up by HardyOS"}
	}
	peers := []string{}
	slot := st.spec.Streaming.Slot
	if a.Enabled {
		// A cluster VM may be published too (decision 485, amending 471):
		// the server running it forwards (desiredForward lists the VMs
		// attached here), and hardyd records the changed settings as
		// approved. A live move stays refused while it is published
		// (decision 470).
		if _, err := streamingNIC(&st.spec); err != nil {
			unlock()
			return nil, err
		}
		nb := m.netBird(ctx)
		pn, perr := netip.ParsePrefix(nb.Network)
		host, herr := netip.ParseAddr(nb.IP)
		if !nb.Connected || perr != nil || herr != nil {
			unlock()
			return nil, Problems{"NetBird isn't connected on this server, so its devices can't be chosen (Control Panel › Remote Access)"}
		}
		if err := checkPeers(a.Peers, pn, host); err != nil {
			unlock()
			return nil, err
		}
		for _, p := range a.Peers {
			if !slices.ContainsFunc(nb.Peers, func(x NetBirdPeer) bool { return x.IP == p }) {
				unlock()
				return nil, Problems{fmt.Sprintf("%s isn't a NetBird device this server sees", p)}
			}
		}
		peers = sortedPeers(a.Peers)
		all, err := m.all(ctx)
		if err != nil {
			unlock()
			return nil, err
		}
		if slot, err = pickStreamingSlot(st, all, m.appHostPorts(ctx)); err != nil {
			unlock()
			return nil, err
		}
	}
	s := *st.spec.Streaming
	if s.Remote != a.Enabled || !slices.Equal(s.Peers, peers) || s.Slot != slot {
		if s.Slot != slot {
			// hardyd moves the VM's Sunshine to the new port set next (its
			// own settings, then a restart) and checks it answers there.
			m.log().Info("vms: game streaming port set", "id", a.ID, "slot", slot, "base", ports.StreamingSlot(slot).Base)
		}
		s.Remote, s.Peers, s.Slot = a.Enabled, peers, slot
		st.spec.Streaming = &s
		if err := m.saveSpec(st); err != nil {
			unlock()
			return nil, err
		}
		m.log().Info("vms: game streaming over NetBird", "id", a.ID, "on", a.Enabled, "devices", len(peers))
	}
	unlock()
	if err := m.syncStreaming(ctx); err != nil {
		m.log().Warn("vms: game streaming forwarding", "err", err)
	}
	return m.Get(ctx, a.ID)
}

// desiredForwards is the forwarding that should be in place now: every
// published VM running here with a verified address, each on its own port
// set. VMs that share a port set (an HA VM that came here) or an address
// are left out, all of them, and named in the error.
func (m *Manager) desiredForwards(ctx context.Context) ([]StreamForward, error) {
	all, err := m.all(ctx)
	if err != nil {
		return nil, err
	}
	var pub []*stored
	for _, st := range all {
		if st.spec.StreamingSetUp() && st.spec.Streaming.Remote && len(st.spec.Streaming.Peers) > 0 && m.state(ctx, st.spec.ID) == "running" {
			pub = append(pub, st)
		}
	}
	if len(pub) == 0 {
		return nil, nil
	}
	nb := m.netBird(ctx)
	if !nb.Connected {
		return nil, nil
	}
	var fs []StreamForward
	var errs []error
	for _, st := range pub {
		ip, err := m.vmAddress(ctx, st)
		if err != nil {
			continue
		}
		f := StreamForward{VM: st.spec.ID, Iface: nb.Interface, PeerNet: nb.Network, Peers: st.spec.Streaming.Peers, HostIP: nb.IP,
			Bridge: m.Network.BridgeName(), VMIP: ip.String(), Slot: st.spec.Streaming.Slot}
		if err := f.check(); err != nil {
			errs = append(errs, fmt.Errorf("not forwarding game streaming to %s: %w", st.spec.ID, err))
			continue
		}
		fs = append(fs, f)
	}
	// A port set or an address twice: none of those VMs is forwarded.
	slots, addrs := map[int]int{}, map[string]int{}
	for _, f := range fs {
		slots[f.Slot]++
		addrs[f.VMIP]++
	}
	appPorts := m.appHostPorts(ctx)
	out := fs[:0]
	for _, f := range fs {
		if slots[f.Slot] > 1 || addrs[f.VMIP] > 1 {
			errs = append(errs, fmt.Errorf("not forwarding game streaming to %s: another published VM here has the same ports or address", f.VM))
			continue
		}
		if p := slotAppPort(f.Slot, appPorts); p != "" {
			// An app installed before the sets were reserved holds one of
			// its ports (decision 509): publish it again for another set.
			errs = append(errs, fmt.Errorf("not forwarding game streaming to %s: an app of this server uses its port %s", f.VM, p))
			continue
		}
		out = append(out, f)
	}
	return out, errors.Join(errs...)
}

// kickStreaming updates the forwarding soon (a VM stopped or went away).
func (m *Manager) kickStreaming() {
	m.streamMu.Lock()
	active := m.streamApplied != ""
	m.streamMu.Unlock()
	if active {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if err := m.syncStreaming(ctx); err != nil {
				m.log().Warn("vms: game streaming forwarding", "err", err)
			}
		}()
	}
}

// liveStreamingOK reports whether the kernel still has the forward's rules
// (nobody flushed the table or the chain since root loaded them).
func (m *Manager) liveStreamingOK(ctx context.Context, fs []StreamForward) bool {
	out, err := m.run(ctx, "nft", "list", "table", "ip", streamTable)
	if err != nil {
		return false
	}
	for _, f := range fs {
		if !strings.Contains(string(out), "dnat to "+f.VMIP) || !strings.Contains(string(out), "ip daddr "+f.HostIP) {
			return false
		}
	}
	rules, err := StreamingIPTablesAll(fs)
	if err != nil {
		return false
	}
	if _, err := m.run(ctx, "iptables", "-w", "-S", "FORWARD"); err != nil {
		return true // no iptables: nftables alone decides
	}
	for _, r := range rules {
		if _, err := m.run(ctx, "iptables", append([]string{"-w", "-C", streamChain}, r...)...); err != nil {
			return false
		}
	}
	_, err = m.run(ctx, "iptables", "-w", "-C", "FORWARD", "-j", streamChain)
	return err == nil
}

// syncStreaming puts the forwarding rules in line with the VMs: called
// every 30 seconds by Watch, and after every change. When nothing changed
// it checks the live rules and loads them again if they're gone.
func (m *Manager) syncStreaming(ctx context.Context) error {
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	fs, derr := m.desiredForwards(ctx)
	text, err := RenderStreamingNFTAll(fs)
	if err != nil {
		fs, text = nil, ""
		derr = err
	}
	if m.streamSynced && text == m.streamApplied {
		if len(fs) == 0 || m.liveStreamingOK(ctx, fs) {
			return derr
		}
		m.log().Warn("vms: the game streaming rules were changed outside HardyOS; loading them again", "vms", len(fs))
	}
	if len(fs) == 0 {
		m.clearStreaming(ctx)
		m.streamSynced, m.streamApplied, m.streamActive = true, "", nil
		return derr
	}
	dir, err := m.streamDir()
	if err != nil {
		return err
	}
	file := filepath.Join(dir, "streaming.nft")
	if err := rootfile.WriteAtomic(m.sys(file), []byte(text), 0o600); err != nil {
		return err
	}
	if _, err := m.run(ctx, "nft", "-f", file); err != nil {
		return fmt.Errorf("loading the game streaming rules: %w", err)
	}
	rules, _ := StreamingIPTablesAll(fs)
	m.iptablesStream(ctx, rules)
	active := map[string]bool{}
	for _, f := range fs {
		active[f.VM] = true
		m.log().Info("vms: game streaming forwarded to the chosen NetBird devices", "id", f.VM, "address", f.VMIP, "devices", len(f.Peers), "base", f.set().Base)
	}
	m.streamSynced, m.streamApplied, m.streamActive = true, text, active
	return derr
}

func (m *Manager) clearStreaming(ctx context.Context) {
	_, _ = m.run(ctx, "nft", "delete", "table", "ip", streamTable)
	m.iptablesStream(ctx, nil)
}

// StopStreaming takes the forwarding away (hardyd-priv is stopping: no
// rule outlives the process that keeps it right).
func (m *Manager) StopStreaming(ctx context.Context) {
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	m.clearStreaming(ctx)
	_, _ = m.run(ctx, "iptables", "-w", "-D", "FORWARD", "-j", streamChain)
	m.streamSynced, m.streamApplied, m.streamActive = false, "", nil
}

// iptablesStream fills the HARDYOS-STREAM chain (empty: nothing).
func (m *Manager) iptablesStream(ctx context.Context, rules [][]string) {
	ipt := func(args ...string) error {
		_, err := m.run(ctx, "iptables", append([]string{"-w"}, args...)...)
		return err
	}
	if err := ipt("-S", "FORWARD"); err != nil {
		return // no iptables: nftables alone decides
	}
	_ = ipt("-N", streamChain)
	if err := ipt("-F", streamChain); err != nil {
		m.log().Debug("vms: emptying the game streaming firewall chain", "err", err)
		return
	}
	for _, r := range rules {
		if err := ipt(append([]string{"-A", streamChain}, r...)...); err != nil {
			m.log().Warn("vms: game streaming firewall rule", "err", err)
		}
	}
	if len(rules) > 0 && ipt("-C", "FORWARD", "-j", streamChain) != nil {
		if err := ipt("-I", "FORWARD", "1", "-j", streamChain); err != nil {
			m.log().Warn("vms: game streaming firewall chain", "err", err)
		}
	}
}

// streamDir is root's own folder for the ruleset file.
func (m *Manager) streamDir() (string, error) {
	dir := m.sys(StreamRunDir)
	if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
		return "", err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("%s isn't a folder", StreamRunDir)
	}
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok && rootfile.Enforce && sys.Uid != 0 {
		return "", fmt.Errorf("%s isn't root's", StreamRunDir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	return StreamRunDir, nil
}
