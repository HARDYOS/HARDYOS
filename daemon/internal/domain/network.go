package domain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// ipAddr is the part of `ip -j addr` used here.
type ipAddr struct {
	IfName   string   `json:"ifname"`
	Flags    []string `json:"flags"`
	Link     string   `json:"link"` // parent of a macvlan/vlan
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
		Scope     string `json:"scope"`
	} `json:"addr_info"`
}

func (a ipAddr) ipv4() []netip.Prefix {
	var out []netip.Prefix
	for _, ai := range a.AddrInfo {
		if ai.Family != "inet" || ai.Scope != "global" {
			continue
		}
		if ad, err := netip.ParseAddr(ai.Local); err == nil {
			out = append(out, netip.PrefixFrom(ad, ai.PrefixLen))
		}
	}
	return out
}

// inet lists every IPv4 address, whatever its scope.
func (a ipAddr) inet() []netip.Prefix {
	var out []netip.Prefix
	for _, ai := range a.AddrInfo {
		if ad, err := netip.ParseAddr(ai.Local); err == nil && ai.Family == "inet" {
			out = append(out, netip.PrefixFrom(ad, ai.PrefixLen))
		}
	}
	return out
}

func (a ipAddr) up() bool {
	for _, f := range a.Flags {
		if f == "UP" {
			return true
		}
	}
	return false
}

func (m *Manager) addrs(ctx context.Context, args ...string) ([]ipAddr, error) {
	out, err := sysexec.Output(ctx, m.Runner, "ip", append([]string{"-j"}, args...)...)
	if err != nil {
		return nil, err
	}
	var list []ipAddr
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("reading ip output: %w", err)
	}
	return list, nil
}

func (m *Manager) defaultRoute(ctx context.Context) (gw, dev string) {
	out, err := sysexec.Output(ctx, m.Runner, "ip", "-j", "-4", "route", "show", "default")
	if err != nil {
		return "", ""
	}
	var routes []struct {
		Gateway string `json:"gateway"`
		Dev     string `json:"dev"`
	}
	if json.Unmarshal(out, &routes) == nil && len(routes) > 0 {
		return routes[0].Gateway, routes[0].Dev
	}
	return "", ""
}

func (m *Manager) hostDNS() []string {
	var out []string
	b, _ := os.ReadFile(m.path("/etc/resolv.conf"))
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if a, err := netip.ParseAddr(f[1]); err == nil && a.Is4() && !a.IsLoopback() {
				out = append(out, a.String())
			}
		}
	}
	return out
}

// lan finds the NAS's LAN interface and address: the default route's
// interface, unless want names one that still has an IPv4 address (or want
// is empty and in is a subnet to match).
func (m *Manager) lan(ctx context.Context, want string, in netip.Prefix) (dev string, host netip.Prefix, err error) {
	list, err := m.addrs(ctx, "-4", "addr", "show")
	if err != nil {
		return "", netip.Prefix{}, err
	}
	find := func(name string) (netip.Prefix, bool) {
		for _, a := range list {
			if a.IfName == name && a.IfName != m.shim() {
				if v := a.ipv4(); len(v) > 0 {
					return v[0], true
				}
			}
		}
		return netip.Prefix{}, false
	}
	if want != "" {
		if p, ok := find(want); ok && (!in.IsValid() || p.Masked() == in.Masked()) {
			return want, p, nil
		}
	}
	if in.IsValid() {
		for _, a := range list {
			if a.IfName == m.shim() || strings.HasPrefix(a.IfName, "docker") || strings.HasPrefix(a.IfName, "veth") {
				continue
			}
			for _, p := range a.ipv4() {
				if p.Masked() == in.Masked() {
					return a.IfName, p, nil
				}
			}
		}
	}
	_, d := m.defaultRoute(ctx)
	if p, ok := find(d); ok {
		return d, p, nil
	}
	return "", netip.Prefix{}, errors.New("the NAS has no IPv4 address on its network yet")
}

// Suggest fills in the setup wizard from the NAS's network, including a
// free address for the DC.
func (m *Manager) Suggest(ctx context.Context) (*Suggestion, error) {
	dev, host, err := m.lan(ctx, "", netip.Prefix{})
	if err != nil {
		return nil, err
	}
	gw, _ := m.defaultRoute(ctx)
	s := &Suggestion{Parent: dev, HostAddress: host.String(), Gateway: gw, DNS: m.hostDNS()}
	if s.DNS == nil {
		s.DNS = []string{}
	}
	if a, ok := m.freeAddress(ctx, dev, host, gw); ok {
		s.Address = netip.PrefixFrom(a, host.Bits()).String()
	}
	return s, nil
}

// candidates lists likely-static addresses: .20–.29 then .240–.249 of a /24
// style network, skipping the NAS and the gateway.
func candidates(host netip.Prefix, gw string) []netip.Addr {
	net := host.Masked()
	base := net.Addr().As4()
	var out []netip.Addr
	try := func(last int) {
		a := base
		a[3] = byte(last)
		ad := netip.AddrFrom4(a)
		if !net.Contains(ad) || ad == host.Addr() || ad.String() == gw || ad == net.Addr() {
			return
		}
		out = append(out, ad)
	}
	if host.Bits() <= 24 {
		// Keep the NAS's third octet: the address is "next to" the NAS.
		h := host.Addr().As4()
		base[2] = h[2]
		for i := 20; i < 30; i++ {
			try(i)
		}
		for i := 240; i < 250; i++ {
			try(i)
		}
	} else {
		h := host.Addr().As4()
		for i := 1; i < 16; i++ {
			try(int(h[3]) + i)
		}
	}
	return out
}

// freeAddress probes candidates with duplicate address detection (arping -D
// exits 0 when nobody answers).
func (m *Manager) freeAddress(ctx context.Context, dev string, host netip.Prefix, gw string) (netip.Addr, bool) {
	cands := candidates(host, gw)
	if len(cands) > 8 {
		cands = cands[:8]
	}
	free := make([]bool, len(cands))
	var wg sync.WaitGroup
	for i, c := range cands {
		wg.Add(1)
		go func(i int, c netip.Addr) {
			defer wg.Done()
			free[i] = m.addressFree(ctx, dev, c)
		}(i, c)
	}
	wg.Wait()
	for i, f := range free {
		if f {
			return cands[i], true
		}
	}
	return netip.Addr{}, false
}

func (m *Manager) addressFree(ctx context.Context, dev string, a netip.Addr) bool {
	res, err := m.Runner.Run(ctx, nil, "arping", "-D", "-q", "-c", "2", "-w", "3", "-I", dev, a.String())
	return err == nil && res.ExitCode == 0
}

func (m *Manager) nsExists() bool {
	_, err := os.Stat(m.path(filepath.Join("/run/netns", m.ns())))
	return err == nil
}

func (m *Manager) run(ctx context.Context, name string, args ...string) error {
	_, err := sysexec.Output(ctx, m.Runner, name, args...)
	return err
}

// SetupNetwork creates or repairs the DC's network: its namespace, its
// macvlan with the DC's address and default route, and the NAS's shim route
// to it. Safe to call repeatedly.
func (m *Manager) SetupNetwork(ctx context.Context, c *Config) error {
	dcAddr, err := netip.ParsePrefix(c.Address)
	if err != nil {
		return fmt.Errorf("the domain controller's address %q isn't valid", c.Address)
	}
	parent, _, err := m.lan(ctx, c.Parent, dcAddr)
	if err != nil {
		return err
	}
	moved := m.lastParent != "" && m.lastParent != parent
	m.lastParent = parent

	if !m.nsExists() {
		if err := m.run(ctx, "ip", "netns", "add", m.ns()); err != nil {
			return fmt.Errorf("creating the domain controller's network: %w", err)
		}
	}
	ns := func(args ...string) error {
		return m.run(ctx, "ip", append([]string{"-n", m.ns()}, args...)...)
	}
	_, linkErr := m.addrs(ctx, "-n", m.ns(), "addr", "show", "dev", DCLink)
	if linkErr == nil && moved {
		_ = ns("link", "del", DCLink)
		linkErr = errors.New("moved")
	}
	if linkErr != nil {
		const tmp = "hdc-new"
		_, _ = m.Runner.Run(ctx, nil, "ip", "link", "del", tmp)
		steps := [][]string{
			{"ip", "link", "add", tmp, "link", parent, "address", c.MAC, "type", "macvlan", "mode", "bridge"},
			{"ip", "link", "set", tmp, "netns", m.ns()},
			{"ip", "-n", m.ns(), "link", "set", tmp, "name", DCLink},
		}
		for _, s := range steps {
			if err := m.run(ctx, s[0], s[1:]...); err != nil {
				return fmt.Errorf("attaching the domain controller to %s: %w", parent, err)
			}
		}
	}
	for _, s := range [][]string{
		{"link", "set", "lo", "up"},
		{"addr", "replace", c.Address, "dev", DCLink},
		{"link", "set", DCLink, "up"},
	} {
		// A namespace deleted moments ago (the domain was just deleted or left)
		// is torn down by the kernel in the background; until then its macvlan
		// still holds the DC's MAC address and bringing the new one up fails.
		var err error
		for try := 0; try < 10; try++ {
			if err = ns(s...); err == nil || !strings.Contains(err.Error(), "Address already in use") {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
		}
		if err != nil {
			return fmt.Errorf("setting up the domain controller's address: %w", err)
		}
	}
	if c.Gateway != "" {
		if err := ns("route", "replace", "default", "via", c.Gateway, "dev", DCLink); err != nil {
			return fmt.Errorf("setting the domain controller's gateway: %w", err)
		}
	}
	// Replies to the NAS go back through the shim.
	if err := ns("route", "replace", m.shimAddr()+"/32", "dev", DCLink); err != nil {
		return fmt.Errorf("setting the route back to the NAS: %w", err)
	}
	if err := m.setupShim(ctx, parent, dcAddr.Addr(), moved); err != nil {
		return err
	}
	if c.Domain != "" {
		return m.writeResolv(c)
	}
	return nil
}

// setupShim lets the NAS reach the DC: the NAS can't talk to a macvlan child
// through the parent port, so a second macvlan on the same port carries a
// private address and a host route to the DC.
func (m *Manager) setupShim(ctx context.Context, parent string, dcIP netip.Addr, moved bool) error {
	list, err := m.addrs(ctx, "-d", "addr", "show", "dev", m.shim())
	if err == nil && (moved || len(list) == 0 || (list[0].Link != "" && list[0].Link != parent)) {
		_ = m.run(ctx, "ip", "link", "del", m.shim())
		err = errors.New("recreate")
	}
	if err != nil {
		if err := m.run(ctx, "ip", "link", "add", m.shim(), "link", parent, "type", "macvlan", "mode", "bridge"); err != nil {
			return fmt.Errorf("creating the route to the domain controller: %w", err)
		}
		list = nil
	}
	// Strict reverse-path filtering would drop the DC's replies.
	_ = m.run(ctx, "sysctl", "-q", "-w", "net.ipv4.conf."+m.shim()+".rp_filter=2")
	want := netip.MustParsePrefix(m.shimAddr() + "/32")
	have := false
	if len(list) > 0 {
		for _, p := range list[0].inet() {
			if p == want {
				have = true
			}
		}
	}
	if !have {
		_ = m.run(ctx, "ip", "addr", "flush", "dev", m.shim())
		if err := m.run(ctx, "ip", "addr", "add", want.String(), "dev", m.shim(), "scope", "link"); err != nil {
			return fmt.Errorf("setting up the route to the domain controller: %w", err)
		}
	}
	if err := m.run(ctx, "ip", "link", "set", m.shim(), "up"); err != nil {
		return err
	}
	return m.run(ctx, "ip", "route", "replace", dcIP.String()+"/32", "dev", m.shim(), "src", m.shimAddr())
}

// networkProblem says what's wrong with the DC's network, or "".
func (m *Manager) networkProblem(ctx context.Context, c *Config) string {
	if !m.nsExists() {
		return "The domain controller's network isn't set up yet."
	}
	list, err := m.addrs(ctx, "-n", m.ns(), "addr", "show", "dev", DCLink)
	if err != nil || len(list) == 0 || !list[0].up() {
		return "The domain controller isn't connected to the network. Check the NAS's network settings."
	}
	want, _ := netip.ParsePrefix(c.Address)
	for _, p := range list[0].ipv4() {
		if p == want {
			return ""
		}
	}
	return "The domain controller's address isn't set."
}

// writeResolv gives the DC its own name settings, as a DC should have:
// resolv.conf with itself first, then the domain's other DCs; and krb5.conf
// mapping the domain to its realm (without it, Kerberos asks DNS which realm
// a host is in, walking up to the internet, and replication stalls whenever
// the internet is down). The unit binds both over /etc; files in
// /etc/netns/<namespace>/ do the same for commands HardyOS runs there.
func (m *Manager) writeResolv(c *Config) error {
	var r strings.Builder
	r.WriteString("# Written by HardyOS for the domain controller.\n")
	for _, s := range c.DNSServers() {
		fmt.Fprintf(&r, "nameserver %s\n", s)
	}
	fmt.Fprintf(&r, "search %s\n", c.Domain)
	k := fmt.Sprintf(`# Written by HardyOS for the domain controller.
[libdefaults]
	default_realm = %[1]s
	dns_lookup_realm = false
	dns_lookup_kdc = true
	rdns = false

[domain_realm]
	.%[2]s = %[1]s
	%[2]s = %[1]s
`, c.Realm, c.Domain)
	files := map[string][]byte{"resolv.conf": []byte(r.String()), "krb5.conf": []byte(k)}
	for name, want := range files {
		for _, p := range []string{m.dataPath(name), m.path(filepath.Join("/etc/netns", m.ns(), name))} {
			if cur, err := os.ReadFile(p); err == nil && bytes.Equal(cur, want) {
				continue
			}
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(p, want, 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

// TeardownNetwork removes the DC's namespace and the NAS's shim.
func (m *Manager) TeardownNetwork(ctx context.Context) {
	if m.nsExists() {
		// Delete the macvlan first: a namespace lingers while any process is
		// still inside it, and its macvlan would keep holding the DC's MAC
		// (a new DC with that MAC then can't come up).
		_, _ = m.Runner.Run(ctx, nil, "ip", "-n", m.ns(), "link", "del", DCLink)
		if err := m.run(ctx, "ip", "netns", "del", m.ns()); err != nil {
			m.log().Warn("removing the domain controller's network", "err", err)
		}
	}
	_, _ = m.Runner.Run(ctx, nil, "ip", "link", "del", m.shim())
	m.lastParent = ""
	_ = os.RemoveAll(m.path(filepath.Join("/etc/netns", m.ns())))
}

// Watch keeps the domain controller attached and running: network changes
// (a new address, a bond replacing a port) and crashes are repaired within
// a minute. It returns when ctx ends.
func (m *Manager) Watch(ctx context.Context) {
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		next := 30 * time.Second
		// The NAS's resolver follows the domain (dhclient may have rewritten
		// it, or the domain came or went).
		m.dnsChanged(ctx)
		if err := m.Ensure(ctx); err != nil {
			failures++
			// Say it once, then quietly keep trying.
			if failures == 1 || failures%20 == 0 {
				m.log().Warn("domain controller needs attention", "err", err)
			}
		} else {
			failures = 0
		}
		t.Reset(next)
	}
}

// Ensure brings the DC up if the domain exists and is turned on.
func (m *Manager) Ensure(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.Load()
	if err != nil || c == nil || !c.Enabled {
		return err
	}
	if err := m.SetupNetwork(ctx, c); err != nil {
		return err
	}
	if !m.serviceActive(ctx) {
		if err := m.run(ctx, "systemctl", "start", m.service()); err != nil {
			return fmt.Errorf("starting the domain controller: %w", err)
		}
		return nil
	}
	if time.Since(m.othersChecked) > 5*time.Minute {
		m.othersChecked = time.Now()
		if m.refreshOthers(ctx, c) {
			m.dnsChanged(ctx)
		}
	}
	return nil
}

// refreshOthers updates the list of the domain's other DCs from DNS and
// reports whether it changed.
func (m *Manager) refreshOthers(ctx context.Context, c *Config) bool {
	dig := func(args ...string) []string {
		res, err := m.Runner.Run(ctx, nil, "dig", append([]string{"+short", "+time=2", "+tries=1", "@" + c.IP()}, args...)...)
		if err != nil || res.ExitCode != 0 {
			return nil
		}
		return strings.Split(strings.TrimSpace(string(res.Stdout)), "\n")
	}
	srv := dig("SRV", "_ldap._tcp.dc._msdcs."+c.Domain)
	if srv == nil {
		return false // DNS isn't answering: keep what we know
	}
	var others []DC
	for _, line := range srv {
		f := strings.Fields(line)
		if len(f) != 4 {
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(f[3]), ".")
		if name == strings.ToLower(c.DCName) {
			continue
		}
		dc := DC{Name: name}
		for _, a := range dig("A", name) {
			if ip, err := netip.ParseAddr(strings.TrimSpace(a)); err == nil && ip.Is4() {
				dc.Address = ip.String()
				break
			}
		}
		others = append(others, dc)
	}
	sort.Slice(others, func(i, j int) bool { return others[i].Name < others[j].Name })
	if equalDCs(others, c.Others) {
		return false
	}
	c.Others = others
	if err := m.save(c); err != nil {
		m.log().Warn("saving the list of domain controllers", "err", err)
		return false
	}
	if err := m.writeResolv(c); err != nil {
		m.log().Warn("updating the domain controller's DNS settings", "err", err)
	}
	m.log().Info("domain controllers changed", "others", others)
	return true
}

func equalDCs(a, b []DC) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
