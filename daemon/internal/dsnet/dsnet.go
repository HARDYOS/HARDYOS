// Package dsnet keeps the office suite's Document Server container in its
// place on the network (decision 266). It runs in hardyd-priv as the named
// operation office.dsnet: it finds the container (Compose project
// hardyos-onlyoffice, service documentserver), reads its one address and
// sets iptables rules so that
//
//   - on this server, only hardyd (by uid) can open connections to it: host
//     network apps and every other local process are refused, so its
//     unpublished port is hardyd's alone;
//   - it can reach this server only at the Docker host gateway on 44251
//     (hardyd's internal listener) and nothing else here;
//   - what it sends on (an "insert image from URL", anything a document makes
//     it fetch) can't reach private, link-local, CGNAT, loopback, multicast
//     or reserved addresses: the home network and the server stay out of
//     reach, the internet doesn't;
//   - nothing forwarded (another container, a routed LAN host) can open a
//     connection to it.
package dsnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// The Document Server app's Compose project and service.
const (
	Project = "hardyos-onlyoffice"
	Service = "documentserver"
	// InternalPort is hardyd's listener for the Document Server.
	InternalPort = 44251
)

// Chain names.
const (
	ChainIn  = "HARDYOS-OFFICE-IN"
	ChainOut = "HARDYOS-OFFICE-OUT"
	ChainFwd = "HARDYOS-OFFICE-FWD"
)

// Blocked are the destinations the Document Server may never reach by
// forwarding (its own network's gateway is the host, handled by ChainIn).
var Blocked = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
}

// Addr is where the Document Server is.
type Addr struct {
	IP      string `json:"ip"`
	Gateway string `json:"gateway"` // the host as the container's network sees it
	HostGW  string `json:"hostGateway"`
}

// Manager discovers the container and applies the rules.
type Manager struct {
	Runner sysexec.Runner
	// HardydUID is the only uid allowed to connect to the container.
	HardydUID func() (int, error)
	// HostGateway is the address host.docker.internal resolves to
	// (docker0's); nil reads docker0.
	HostGateway func() (netip.Addr, error)
}

var idRE = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

func (m *Manager) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return sysexec.Output(ctx, m.Runner, name, args...)
}

// ErrNotRunning: the Document Server container isn't there.
var ErrNotRunning = errors.New("the Document Server container isn't running")

// Discover finds the running container's address on its one network.
func (m *Manager) Discover(ctx context.Context) (netip.Addr, netip.Addr, error) {
	out, err := m.run(ctx, "docker", "ps", "-q", "--no-trunc",
		"--filter", "label=com.docker.compose.project="+Project,
		"--filter", "label=com.docker.compose.service="+Service,
		"--filter", "status=running")
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	ids := strings.Fields(string(out))
	if len(ids) == 0 {
		return netip.Addr{}, netip.Addr{}, ErrNotRunning
	}
	if len(ids) != 1 || !idRE.MatchString(ids[0]) {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("expected one Document Server container, found %d", len(ids))
	}
	out, err = m.run(ctx, "docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", ids[0])
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	return ParseNetworks(out)
}

// ParseNetworks reads `docker inspect` networks: exactly one network, with
// a private IPv4 address and gateway.
func ParseNetworks(out []byte) (netip.Addr, netip.Addr, error) {
	var nets map[string]struct {
		IPAddress string `json:"IPAddress"`
		Gateway   string `json:"Gateway"`
	}
	if err := json.Unmarshal(out, &nets); err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("reading the container's networks: %w", err)
	}
	if len(nets) != 1 {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("the Document Server must be on exactly one network (it's on %d)", len(nets))
	}
	for _, n := range nets {
		ip, err1 := netip.ParseAddr(n.IPAddress)
		gw, err2 := netip.ParseAddr(n.Gateway)
		if err1 != nil || err2 != nil || !ip.Is4() || !gw.Is4() || !ip.IsPrivate() || !gw.IsPrivate() || ip == gw {
			return netip.Addr{}, netip.Addr{}, fmt.Errorf("the Document Server has an unexpected address %q (gateway %q)", n.IPAddress, n.Gateway)
		}
		return ip, gw, nil
	}
	return netip.Addr{}, netip.Addr{}, errors.New("no network")
}

func (m *Manager) hostGateway() (netip.Addr, error) {
	if m.HostGateway != nil {
		return m.HostGateway()
	}
	ifc, err := net.InterfaceByName("docker0")
	if err != nil {
		return netip.Addr{}, err
	}
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap().Is4() {
				return ip.Unmap(), nil
			}
		}
	}
	return netip.Addr{}, errors.New("docker0 has no IPv4 address")
}

// Rules are the chains' contents for a container at ip, the host gateway
// it calls hardyd on, and hardyd's uid.
func Rules(ip, hostGW netip.Addr, uid int) map[string][][]string {
	fwd := [][]string{{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		// Nothing forwarded opens a connection to it.
		{"-d", ip.String() + "/32", "-j", "DROP"}}
	for _, b := range Blocked {
		fwd = append(fwd, []string{"-s", ip.String() + "/32", "-d", b, "-j", "DROP"})
	}
	fwd = append(fwd, []string{"-j", "RETURN"})
	return map[string][][]string{
		ChainIn: {
			{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
			{"-d", hostGW.String() + "/32", "-p", "tcp", "--dport", strconv.Itoa(InternalPort), "-j", "ACCEPT"},
			// Refused at once rather than left to time out.
			{"-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"},
			{"-j", "DROP"},
		},
		ChainOut: {
			{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
			{"-m", "owner", "--uid-owner", strconv.Itoa(uid), "-j", "ACCEPT"},
			{"-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"},
			{"-j", "REJECT"},
		},
		ChainFwd: fwd,
	}
}

// Jumps are the rules that send the container's traffic to the chains.
func Jumps(ip netip.Addr) [][]string {
	h := ip.String() + "/32"
	return [][]string{
		{"INPUT", "-s", h, "-j", ChainIn},
		{"OUTPUT", "-d", h, "-j", ChainOut},
		{"DOCKER-USER", "-s", h, "-j", ChainFwd},
		{"DOCKER-USER", "-d", h, "-j", ChainFwd},
	}
}

// Apply finds the container and (re)writes the rules for it.
func (m *Manager) Apply(ctx context.Context) (*Addr, error) {
	ip, gw, err := m.Discover(ctx)
	if err != nil {
		return nil, err
	}
	hgw, err := m.hostGateway()
	if err != nil {
		return nil, err
	}
	if m.HardydUID == nil {
		return nil, errors.New("hardyd's uid is unknown")
	}
	uid, err := m.HardydUID()
	if err != nil {
		return nil, err
	}
	if err := m.ApplyFor(ctx, ip, hgw, uid); err != nil {
		return nil, err
	}
	return &Addr{IP: ip.String(), Gateway: gw.String(), HostGW: hgw.String()}, nil
}

// ApplyFor writes the rules for a known address (tests; Apply).
func (m *Manager) ApplyFor(ctx context.Context, ip, hostGW netip.Addr, uid int) error {
	if !ip.Is4() || !ip.IsPrivate() || !hostGW.Is4() || uid < 0 {
		return errors.New("invalid Document Server address")
	}
	rules := Rules(ip, hostGW, uid)
	for _, c := range []string{ChainIn, ChainOut, ChainFwd} {
		_, _ = m.run(ctx, "iptables", "-w", "-N", c)
		if _, err := m.run(ctx, "iptables", "-w", "-F", c); err != nil {
			return fmt.Errorf("iptables: %w", err)
		}
		for _, r := range rules[c] {
			if _, err := m.run(ctx, "iptables", append([]string{"-w", "-A", c}, r...)...); err != nil {
				return fmt.Errorf("iptables: %w", err)
			}
		}
	}
	// Jumps for an older address go; the current ones go first in their chain.
	if err := m.dropJumps(ctx, ip); err != nil {
		return err
	}
	for _, j := range Jumps(ip) {
		if _, err := m.run(ctx, "iptables", append([]string{"-w", "-C"}, j...)...); err == nil {
			continue
		}
		if _, err := m.run(ctx, "iptables", append([]string{"-w", "-I", j[0], "1"}, j[1:]...)...); err != nil {
			return fmt.Errorf("iptables: %w", err)
		}
	}
	return nil
}

// dropJumps removes jumps to the chains, except those for keep (zero: all).
func (m *Manager) dropJumps(ctx context.Context, keep netip.Addr) error {
	want := map[string]bool{}
	if keep.IsValid() {
		for _, j := range Jumps(keep) {
			want["-A "+strings.Join(j, " ")] = true
		}
	}
	for _, chain := range []string{"INPUT", "OUTPUT", "DOCKER-USER"} {
		out, err := m.run(ctx, "iptables", "-w", "-S", chain)
		if err != nil {
			continue // DOCKER-USER exists only while Docker runs
		}
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "-A ") || !strings.Contains(line, "-j HARDYOS-OFFICE-") || want[line] {
				continue
			}
			args := append([]string{"-w", "-D"}, strings.Fields(strings.TrimPrefix(line, "-A "))...)
			if _, err := m.run(ctx, "iptables", args...); err != nil {
				return fmt.Errorf("iptables: %w", err)
			}
		}
	}
	return nil
}

// Remove takes every rule away (the office suite was turned off).
func (m *Manager) Remove(ctx context.Context) error {
	if err := m.dropJumps(ctx, netip.Addr{}); err != nil {
		return err
	}
	for _, c := range []string{ChainIn, ChainOut, ChainFwd} {
		_, _ = m.run(ctx, "iptables", "-w", "-F", c)
		_, _ = m.run(ctx, "iptables", "-w", "-X", c)
	}
	return nil
}
