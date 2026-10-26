package domain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
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
			if a.IfName == name && a.IfName != ShimLink {
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
			if a.IfName == ShimLink || strings.HasPrefix(a.IfName, "docker") || strings.HasPrefix(a.IfName, "veth") {
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

// lastParent remembers which LAN interface the DC was attached to, so a
// network change that moves the NAS to another interface (a new bond, say)
// moves the DC too.
var lastParent struct {
	sync.Mutex
	name string
}

func (m *Manager) nsExists() bool {
	_, err := os.Stat(m.path(filepath.Join("/run/netns", Namespace)))
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
	parent, host, err := m.lan(ctx, c.Parent, dcAddr)
	if err != nil {
		return err
	}
	lastParent.Lock()
	moved := lastParent.name != "" && lastParent.name != parent
	lastParent.name = parent
	lastParent.Unlock()

	if !m.nsExists() {
		if err := m.run(ctx, "ip", "netns", "add", Namespace); err != nil {
			return fmt.Errorf("creating the domain controller's network: %w", err)
		}
	}
	ns := func(args ...string) error {
		return m.run(ctx, "ip", append([]string{"-n", Namespace}, args...)...)
	}
	_, linkErr := m.addrs(ctx, "-n", Namespace, "addr", "show", "dev", DCLink)
	if linkErr == nil && moved {
		_ = ns("link", "del", DCLink)
		linkErr = errors.New("moved")
	}
	if linkErr != nil {
		const tmp = "hdc-new"
		_, _ = m.Runner.Run(ctx, nil, "ip", "link", "del", tmp)
		steps := [][]string{
			{"ip", "link", "add", tmp, "link", parent, "address", c.MAC, "type", "macvlan", "mode", "bridge"},
			{"ip", "link", "set", tmp, "netns", Namespace},
			{"ip", "-n", Namespace, "link", "set", tmp, "name", DCLink},
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
		if err := ns(s...); err != nil {
			return fmt.Errorf("setting up the domain controller's address: %w", err)
		}
	}
	if c.Gateway != "" {
		if err := ns("route", "replace", "default", "via", c.Gateway, "dev", DCLink); err != nil {
			return fmt.Errorf("setting the domain controller's gateway: %w", err)
		}
	}
	return m.setupShim(ctx, parent, host.Addr(), dcAddr.Addr(), moved)
}

// setupShim lets the NAS reach the DC: a macvlan on the same port carrying
// the NAS's own address (never answering ARP for it) and a host route.
func (m *Manager) setupShim(ctx context.Context, parent string, hostIP, dcIP netip.Addr, moved bool) error {
	list, err := m.addrs(ctx, "-d", "addr", "show", "dev", ShimLink)
	if err == nil && (moved || len(list) == 0 || (list[0].Link != "" && list[0].Link != parent)) {
		_ = m.run(ctx, "ip", "link", "del", ShimLink)
		err = errors.New("recreate")
	}
	if err != nil {
		if err := m.run(ctx, "ip", "link", "add", ShimLink, "link", parent, "type", "macvlan", "mode", "bridge"); err != nil {
			return fmt.Errorf("creating the route to the domain controller: %w", err)
		}
		list = nil
	}
	// The NAS's address lives on the real port; the shim never claims it.
	for _, kv := range []string{"arp_ignore=8", "arp_announce=2"} {
		_ = m.run(ctx, "sysctl", "-q", "-w", "net.ipv4.conf."+ShimLink+"."+kv)
	}
	want := netip.PrefixFrom(hostIP, 32)
	have := false
	if len(list) > 0 {
		for _, p := range list[0].ipv4() {
			if p == want {
				have = true
			}
		}
	}
	if !have {
		_ = m.run(ctx, "ip", "addr", "flush", "dev", ShimLink)
		if err := m.run(ctx, "ip", "addr", "add", want.String(), "dev", ShimLink); err != nil {
			return fmt.Errorf("setting up the route to the domain controller: %w", err)
		}
	}
	if err := m.run(ctx, "ip", "link", "set", ShimLink, "up"); err != nil {
		return err
	}
	return m.run(ctx, "ip", "route", "replace", dcIP.String()+"/32", "dev", ShimLink, "src", hostIP.String())
}

// networkProblem says what's wrong with the DC's network, or "".
func (m *Manager) networkProblem(ctx context.Context, c *Config) string {
	if !m.nsExists() {
		return "The domain controller's network isn't set up yet."
	}
	list, err := m.addrs(ctx, "-n", Namespace, "addr", "show", "dev", DCLink)
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

// TeardownNetwork removes the DC's namespace and the NAS's shim.
func (m *Manager) TeardownNetwork(ctx context.Context) {
	if m.nsExists() {
		if err := m.run(ctx, "ip", "netns", "del", Namespace); err != nil {
			m.log().Warn("removing the domain controller's network", "err", err)
		}
	}
	_, _ = m.Runner.Run(ctx, nil, "ip", "link", "del", ShimLink)
	lastParent.Lock()
	lastParent.name = ""
	lastParent.Unlock()
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
		if err := m.run(ctx, "systemctl", "start", Service); err != nil {
			return fmt.Errorf("starting the domain controller: %w", err)
		}
	}
	return nil
}
