package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"
)

// The bridge for virtual machines (decision 121). VMs are on the home
// network like any other computer: their network cards plug into br0, a
// virtual switch over the server's LAN port (or bond). The first VM that
// needs it creates it: the port's address moves to the bridge, applied like
// any network change (saved first, undone on failure), then checked here:
// the bridge must get the same address back and reach the gateway, or the
// old settings return at once.

// DefaultBridge is the name HardyOS gives the bridge it creates.
const DefaultBridge = "br0"

// ErrNoUplink means the server's connection can't carry a bridge by itself.
var ErrNoUplink = errors.New("no network port to put the bridge on")

// BridgeName is the first bridge in the saved settings, or "".
func (m *Manager) BridgeName() string {
	c := m.Current()
	if len(c.Bridges) == 0 {
		return ""
	}
	return c.Bridges[0].Name
}

func sameBridges(a, b []Bridge) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Port != b[i].Port {
			return false
		}
	}
	return true
}

// giveBackAddresses returns a removed bridge's addressing to the port it
// ran over, so taking a bridge away doesn't leave the server without an
// address.
func (c *Config) giveBackAddresses(prev Config) {
	keep := map[string]bool{}
	for _, br := range c.Bridges {
		keep[br.Name] = true
	}
	for _, old := range prev.Bridges {
		if keep[old.Name] {
			continue
		}
		a := old.Addressing
		for i := range c.Interfaces {
			if c.Interfaces[i].Name == old.Port && (c.Interfaces[i].Mode == ModeBridged || c.Interfaces[i].Mode == ModeOff) {
				a.MTU = c.Interfaces[i].MTU
				c.Interfaces[i].Addressing = a
			}
		}
		for i := range c.Bonds {
			if c.Bonds[i].Name == old.Port && (c.Bonds[i].Mode == ModeBridged || c.Bonds[i].Mode == ModeOff) {
				a.MTU = c.Bonds[i].MTU
				c.Bonds[i].Addressing = a
			}
		}
		for i := range c.VLANs {
			if c.VLANs[i].Parent == old.Name {
				c.VLANs[i].Parent = old.Port
			}
		}
	}
}

// WithBridge returns c with a bridge over port taking its address (and its
// VLANs). mac is the port's MAC address.
func WithBridge(c Config, name, port, mac string) (Config, error) {
	out := c
	out.Interfaces = append([]Interface{}, c.Interfaces...)
	out.Bonds = append([]Bond{}, c.Bonds...)
	out.VLANs = append([]VLAN{}, c.VLANs...)
	out.Bridges = append([]Bridge{}, c.Bridges...)
	var addr *Addressing
	for i := range out.Interfaces {
		if out.Interfaces[i].Name == port {
			a := out.Interfaces[i].Addressing
			addr = &a
		}
	}
	for i := range out.Bonds {
		if out.Bonds[i].Name == port {
			a := out.Bonds[i].Addressing
			addr = &a
		}
	}
	if addr == nil {
		return c, fmt.Errorf("%w: %s isn't a port or bond", ErrNoUplink, port)
	}
	if addr.Mode != ModeDHCP && addr.Mode != ModeStatic && addr.Mode != ModeOff {
		return c, fmt.Errorf("%w: %s is %s", ErrNoUplink, port, addr.Mode)
	}
	br := Bridge{Name: name, Port: port, MAC: strings.ToLower(mac), Addressing: Addressing{Mode: addr.Mode, Address: addr.Address, Gateway: addr.Gateway}}
	out.Bridges = append(out.Bridges, br)
	for i := range out.VLANs {
		if out.VLANs[i].Parent == port {
			out.VLANs[i].Parent = name
		}
	}
	out.Normalize()
	return out, nil
}

// uplink finds the interface carrying the server's default route (or its
// only addressed port or bond).
func (m *Manager) uplink(ctx context.Context, c Config) (string, error) {
	res, err := m.Runner.Run(ctx, nil, "ip", "-j", "-4", "route", "show", "default")
	if err == nil && res.ExitCode == 0 {
		var routes []struct {
			Dev string `json:"dev"`
		}
		if json.Unmarshal(res.Stdout, &routes) == nil && len(routes) > 0 && routes[0].Dev != "" {
			dev := routes[0].Dev
			if a, ok := c.AddressingOf(dev); ok && (a.Mode == ModeDHCP || a.Mode == ModeStatic) && !strings.Contains(dev, ".") {
				for _, it := range c.Interfaces {
					if it.Name == dev {
						return dev, nil
					}
				}
				for _, b := range c.Bonds {
					if b.Name == dev {
						return dev, nil
					}
				}
			}
			return "", fmt.Errorf("%w: the server reaches the internet through %s, which can't carry a bridge by itself; set one up in Control Panel > Network", ErrNoUplink, dev)
		}
	}
	var found []string
	for _, it := range c.Interfaces {
		if it.Mode == ModeDHCP || it.Mode == ModeStatic {
			found = append(found, it.Name)
		}
	}
	for _, b := range c.Bonds {
		if b.Mode == ModeDHCP || b.Mode == ModeStatic {
			found = append(found, b.Name)
		}
	}
	if len(found) != 1 {
		return "", fmt.Errorf("%w: choose the port for it in Control Panel > Network", ErrNoUplink)
	}
	return found[0], nil
}

func (m *Manager) ipv4Of(ctx context.Context, dev string) []netip.Prefix {
	res, err := m.Runner.Run(ctx, nil, "ip", "-j", "-4", "addr", "show", "dev", dev)
	if err != nil || res.ExitCode != 0 {
		return nil
	}
	var list []ipAddr
	if json.Unmarshal(res.Stdout, &list) != nil {
		return nil
	}
	var out []netip.Prefix
	for _, a := range list {
		for _, ai := range a.AddrInfo {
			if ai.Scope != "global" {
				continue
			}
			if ad, err := netip.ParseAddr(ai.Local); err == nil {
				out = append(out, netip.PrefixFrom(ad, ai.PrefixLen))
			}
		}
	}
	return out
}

// EnsureBridge creates the VM bridge over the server's LAN connection if
// there isn't one, keeping the server's address, and returns its name.
func (m *Manager) EnsureBridge(ctx context.Context) (string, error) {
	m.bridgeMu.Lock()
	defer m.bridgeMu.Unlock()
	if name := m.BridgeName(); name != "" {
		return name, nil
	}
	m.mu.Lock()
	p, err := m.loadPending()
	m.mu.Unlock()
	if err != nil {
		return "", err
	}
	if p != nil {
		return "", ErrPending
	}
	c := m.Current()
	port, err := m.uplink(ctx, c)
	if err != nil {
		return "", err
	}
	mac := strings.TrimSpace(m.readFile(filepath.Join("sys/class/net", port, "address")))
	if !macRE.MatchString(strings.ToLower(mac)) {
		mac = ""
	}
	before := m.ipv4Of(ctx, port)
	gw := m.defaultGateway(ctx)
	next, err := WithBridge(c, DefaultBridge, port, mac)
	if err != nil {
		return "", err
	}
	m.log().Info("network: creating the bridge for virtual machines", "bridge", DefaultBridge, "port", port)
	if _, err := m.Apply(ctx, next); err != nil {
		return "", fmt.Errorf("setting up the bridge for VMs: %w", err)
	}
	want := addressing(next, DefaultBridge)
	if err := m.checkBridge(ctx, DefaultBridge, want, before, gw); err != nil {
		reason := "the bridge for VMs didn't keep the server reachable: " + err.Error()
		if rerr := m.Revert(context.Background(), reason); rerr != nil && !errors.Is(rerr, ErrNothingPending) {
			m.log().Error("network: undoing the bridge", "err", rerr)
		}
		return "", fmt.Errorf("the server's network didn't work over a bridge, so it's back as it was (%v); VMs can use NAT, or set up a bridge in Control Panel > Network", err)
	}
	if _, err := m.Confirm(); err != nil {
		return "", err
	}
	m.log().Info("network: bridge for virtual machines ready", "bridge", DefaultBridge, "port", port)
	return DefaultBridge, nil
}

func addressing(c Config, name string) Addressing {
	a, _ := c.AddressingOf(name)
	return a
}

func (m *Manager) bridgeSettle() time.Duration {
	if m.BridgeSettle > 0 {
		return m.BridgeSettle
	}
	return 90 * time.Second
}

// checkBridge waits for the bridge to have the server's address and the
// gateway to answer.
func (m *Manager) checkBridge(ctx context.Context, br string, want Addressing, before []netip.Prefix, gw string) error {
	deadline := time.Now().Add(m.bridgeSettle())
	var expect netip.Prefix
	switch {
	case want.Mode == ModeStatic:
		expect, _ = netip.ParsePrefix(want.Address)
	case len(before) > 0:
		expect = before[0]
	}
	var have []netip.Prefix
	for {
		have = m.ipv4Of(ctx, br)
		ok := len(have) > 0
		if expect.IsValid() {
			ok = false
			for _, h := range have {
				ok = ok || h.Addr() == expect.Addr()
			}
		}
		if ok {
			break
		}
		if !time.Now().Before(deadline) {
			if len(have) > 0 {
				return fmt.Errorf("it got the address %s instead of %s", have[0].Addr(), expect.Addr())
			}
			return errors.New("it got no address")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if gw == "" {
		return nil
	}
	for i := 0; i < 5; i++ {
		if res, err := m.Runner.Run(ctx, nil, "arping", "-q", "-c", "2", "-w", "3", "-I", br, gw); err == nil && res.ExitCode == 0 {
			return nil
		}
		if res, err := m.Runner.Run(ctx, nil, "ping", "-q", "-c", "1", "-W", "2", gw); err == nil && res.ExitCode == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("the router (%s) didn't answer", gw)
}

func (m *Manager) beforeBridges(ctx context.Context) {
	if m.BeforeBridges != nil {
		m.BeforeBridges(ctx)
	}
}

// afterBridges runs after the lock is released: the domain controller's
// repair can ask for the network's DNS settings.
func (m *Manager) afterBridges() {
	if m.AfterBridges != nil {
		go m.AfterBridges(context.Background())
	}
}
