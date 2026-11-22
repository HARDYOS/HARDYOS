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
}

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
	if err := f.check(); err != nil {
		return "", err
	}
	tcp := strings.ReplaceAll(portList(ports.SunshineTCP, "-"), ",", ", ")
	udp := strings.ReplaceAll(portList(ports.SunshineUDP, "-"), ",", ", ")
	peers := "{ " + strings.Join(sortedPeers(f.Peers), ", ") + " }"
	return fmt.Sprintf(`# Made by HardyOS: game streaming for the VM %[1]s, from the chosen NetBird devices only (decision 404).
table ip %[2]s
delete table ip %[2]s
table ip %[2]s {
  chain prerouting {
    type nat hook prerouting priority dstnat - 5; policy accept;
    iifname %[3]q ip saddr %[4]s ip daddr %[5]s tcp dport { %[8]s } dnat to %[7]s
    iifname %[3]q ip saddr %[4]s ip daddr %[5]s udp dport { %[9]s } dnat to %[7]s
  }
  chain forward {
    type filter hook forward priority filter - 5; policy accept;
    iifname %[3]q oifname %[6]q ip saddr %[4]s ip daddr %[7]s ct status dnat tcp dport { %[8]s } accept
    iifname %[3]q oifname %[6]q ip saddr %[4]s ip daddr %[7]s ct status dnat udp dport { %[9]s } accept
    iifname %[6]q oifname %[3]q ip saddr %[7]s ct state established,related accept
  }
  chain postrouting {
    type nat hook postrouting priority srcnat - 5; policy accept;
    iifname %[3]q oifname %[6]q ip saddr %[4]s ip daddr %[7]s ct status dnat masquerade
  }
}
`, f.VM, streamTable, f.Iface, peers, f.HostIP, f.Bridge, f.VMIP, tcp, udp), nil
}

// StreamingIPTables are the HARDYOS-STREAM chain's rules (Docker's FORWARD
// drop policy otherwise drops the forwarded packets).
func StreamingIPTables(f StreamForward) ([][]string, error) {
	if err := f.check(); err != nil {
		return nil, err
	}
	vm := f.VMIP + "/32"
	src := make([]string, 0, len(f.Peers))
	for _, p := range sortedPeers(f.Peers) {
		src = append(src, p+"/32")
	}
	srcs := strings.Join(src, ",")
	return [][]string{
		{"-i", f.Iface, "-o", f.Bridge, "-s", srcs, "-d", vm, "-p", "tcp", "-m", "multiport", "--dports", portList(ports.SunshineTCP, ":"), "-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"},
		{"-i", f.Iface, "-o", f.Bridge, "-s", srcs, "-d", vm, "-p", "udp", "-m", "multiport", "--dports", portList(ports.SunshineUDP, ":"), "-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"},
		{"-i", f.Bridge, "-o", f.Iface, "-s", vm, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}, nil
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
				_ = m.dialVM(ctx, netip.AddrPortFrom(a, ports.SunshineWebUI).String())
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
	info := &StreamingInfo{User: sp.User, CertSHA256: sp.CertSHA256, Remote: sp.Remote, Peers: append([]string{}, sp.Peers...),
		WebUIFrom: sp.WebUIFrom, NetBirdPeers: []NetBirdPeer{}}
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
	info.Forwarding = m.streamActive == id && m.streamApplied != ""
	m.streamMu.Unlock()
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

// SetStreamingRemote turns publishing a VM's streaming ports to NetBird
// devices on or off. Only one VM at a time: Moonlight uses fixed ports.
// The devices must be NetBird peers this server sees now, in its NetBird
// network (hardyd also leaves out NetBird's reverse proxy peers).
func (m *Manager) SetStreamingRemote(ctx context.Context, a StreamingPublishArgs) (*VM, error) {
	unlock, err := m.lockValid(a.ID)
	if err != nil {
		return nil, err
	}
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
	if a.Enabled {
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
		for _, o := range all {
			if o.spec.ID != a.ID && o.spec.Streaming != nil && o.spec.Streaming.Remote {
				unlock()
				return nil, Problems{fmt.Sprintf("%s is already published to NetBird devices; Moonlight uses fixed ports, so only one VM at a time (turn it off there first)", o.spec.Name)}
			}
		}
	}
	s := *st.spec.Streaming
	if s.Remote != a.Enabled || !slices.Equal(s.Peers, peers) {
		s.Remote, s.Peers = a.Enabled, peers
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

// desiredForward is the forwarding that should be in place now, if any.
func (m *Manager) desiredForward(ctx context.Context) (*StreamForward, error) {
	all, err := m.all(ctx)
	if err != nil {
		return nil, err
	}
	var pub []*stored
	for _, st := range all {
		if st.spec.StreamingSetUp() && st.spec.Streaming.Remote && len(st.spec.Streaming.Peers) > 0 {
			pub = append(pub, st)
		}
	}
	if len(pub) == 0 {
		return nil, nil
	}
	if len(pub) > 1 {
		return nil, errors.New("more than one VM is published for game streaming; none is forwarded")
	}
	st := pub[0]
	if m.state(ctx, st.spec.ID) != "running" {
		return nil, nil
	}
	nb := m.netBird(ctx)
	if !nb.Connected {
		return nil, nil
	}
	ip, err := m.vmAddress(ctx, st)
	if err != nil {
		return nil, nil
	}
	f := &StreamForward{VM: st.spec.ID, Iface: nb.Interface, PeerNet: nb.Network, Peers: st.spec.Streaming.Peers, HostIP: nb.IP, Bridge: m.Network.BridgeName(), VMIP: ip.String()}
	if err := f.check(); err != nil {
		return nil, fmt.Errorf("not forwarding game streaming: %w", err)
	}
	return f, nil
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
func (m *Manager) liveStreamingOK(ctx context.Context, f *StreamForward) bool {
	out, err := m.run(ctx, "nft", "list", "table", "ip", streamTable)
	if err != nil || !strings.Contains(string(out), "dnat to "+f.VMIP) || !strings.Contains(string(out), "ip daddr "+f.HostIP) {
		return false
	}
	rules, err := StreamingIPTables(*f)
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
	f, derr := m.desiredForward(ctx)
	text, err := RenderStreamingNFT(f)
	if err != nil {
		f, text = nil, ""
		derr = err
	}
	if m.streamSynced && text == m.streamApplied {
		if f == nil || m.liveStreamingOK(ctx, f) {
			return derr
		}
		m.log().Warn("vms: the game streaming rules were changed outside HardyOS; loading them again", "id", f.VM)
	}
	if f == nil {
		m.clearStreaming(ctx)
		m.streamSynced, m.streamApplied, m.streamActive = true, "", ""
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
	rules, _ := StreamingIPTables(*f)
	m.iptablesStream(ctx, rules)
	m.streamSynced, m.streamApplied, m.streamActive = true, text, f.VM
	m.log().Info("vms: game streaming forwarded to the chosen NetBird devices", "id", f.VM, "address", f.VMIP, "devices", len(f.Peers))
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
	m.streamSynced, m.streamApplied, m.streamActive = false, "", ""
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
