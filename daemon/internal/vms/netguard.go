package vms

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// What keeps VMs in their place on the network and in the host
// (decisions 136-138, 142): VLAN cards are checked before the VM runs, cards on
// the home network can't use other computers' addresses, VMs on the
// private network can only ask the server for addresses and names, and
// QEMU runs confined by AppArmor.

// HasVLAN reports whether a NIC is on a VLAN.
func (s *Spec) HasVLAN() bool {
	for _, n := range s.NICs {
		if n.Mode == NICVLAN {
			return true
		}
	}
	return false
}

// NeedsNAT reports whether a NIC is on the private (NAT) network.
func (s *Spec) NeedsNAT() bool {
	for _, n := range s.NICs {
		if n.Mode == NICNAT {
			return true
		}
	}
	return false
}

// NeedsFilter reports whether a NIC on the home network gets the
// anti-spoofing filter.
func (s *Spec) NeedsFilter() bool {
	for _, n := range s.NICs {
		if n.Mode != NICNAT && !n.AllowSpoofing {
			return true
		}
	}
	return false
}

// CleanTraffic is libvirt's filter against MAC, IP and ARP spoofing.
const CleanTraffic = "clean-traffic"

// hasFilter reports whether libvirt has the clean-traffic filter.
func (m *Manager) hasFilter(ctx context.Context) bool {
	out, err := m.virsh(ctx, "nwfilter-list")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == CleanTraffic {
			return true
		}
	}
	return false
}

// ---- VLANs -------------------------------------------------------------------

type bridgeVLAN struct {
	VLAN  int      `json:"vlan"`
	Flags []string `json:"flags"`
}

// parseBridgeVLANs reads `bridge -j vlan show dev X`, in both the current
// layout ([{"ifname":…,"vlans":[…]}]) and iproute2's older one
// ({"dev":[…]}).
func parseBridgeVLANs(out []byte, dev string) ([]bridgeVLAN, error) {
	var l []struct {
		Ifname string       `json:"ifname"`
		VLANs  []bridgeVLAN `json:"vlans"`
	}
	if err := json.Unmarshal(out, &l); err == nil {
		var res []bridgeVLAN
		found := false
		for _, e := range l {
			if e.Ifname == dev {
				found = true
				res = append(res, e.VLANs...)
			}
		}
		if !found && len(l) > 0 {
			return nil, fmt.Errorf("the bridge reported %s, not %s", l[0].Ifname, dev)
		}
		return res, nil
	}
	var old map[string][]bridgeVLAN
	if err := json.Unmarshal(out, &old); err != nil {
		return nil, fmt.Errorf("reading the port's VLANs: %w", err)
	}
	return old[dev], nil
}

func hasFlag(flags []string, f string) bool {
	for _, x := range flags {
		if strings.EqualFold(x, f) {
			return true
		}
	}
	return false
}

// vlanFiltering reports whether the bridge filters by VLAN; without it,
// VLAN settings on its ports do nothing.
func (m *Manager) vlanFiltering(ctx context.Context, br string) error {
	out, err := m.run(ctx, "ip", "-j", "-d", "link", "show", "dev", br)
	if err != nil {
		return fmt.Errorf("reading the bridge %s: %w", br, err)
	}
	var l []struct {
		LinkInfo struct {
			Kind string `json:"info_kind"`
			Data struct {
				VLANFiltering int `json:"vlan_filtering"`
			} `json:"info_data"`
		} `json:"linkinfo"`
	}
	if err := json.Unmarshal(out, &l); err != nil || len(l) != 1 {
		return fmt.Errorf("reading the bridge %s: %q", br, out)
	}
	if l[0].LinkInfo.Kind != "bridge" || l[0].LinkInfo.Data.VLANFiltering != 1 {
		return fmt.Errorf("%s doesn't filter by VLAN, so a VLAN card would be on every VLAN", br)
	}
	return nil
}

// tagVLANs puts each VLAN NIC's port on its VLAN, untagged and only that
// one, and checks the bridge took it. Any failure is an error: the VM must
// not run with a card on the wrong network.
func (m *Manager) tagVLANs(ctx context.Context, s *Spec) error {
	if !s.HasVLAN() {
		return nil
	}
	br := ""
	if m.Network != nil {
		br = m.Network.BridgeName()
	}
	if br == "" {
		return errors.New("there's no home network bridge")
	}
	if err := m.vlanFiltering(ctx, br); err != nil {
		return err
	}
	for i, n := range s.NICs {
		if n.Mode != NICVLAN {
			continue
		}
		tap := tapName(s.UUID, i)
		vid := strconv.Itoa(n.VLAN)
		have, err := m.portVLANs(ctx, tap)
		if err != nil {
			return err
		}
		for _, v := range have {
			if v.VLAN != n.VLAN {
				if _, err := m.run(ctx, "bridge", "vlan", "del", "dev", tap, "vid", strconv.Itoa(v.VLAN)); err != nil {
					return fmt.Errorf("taking %s off VLAN %d: %w", tap, v.VLAN, err)
				}
			}
		}
		if _, err := m.run(ctx, "bridge", "vlan", "add", "dev", tap, "vid", vid, "pvid", "untagged"); err != nil {
			return fmt.Errorf("putting %s on VLAN %s: %w", tap, vid, err)
		}
		have, err = m.portVLANs(ctx, tap)
		if err != nil {
			return err
		}
		if len(have) != 1 || have[0].VLAN != n.VLAN || !hasFlag(have[0].Flags, "PVID") || !hasFlag(have[0].Flags, "Egress Untagged") {
			return fmt.Errorf("%s isn't only on VLAN %s (the bridge reports %v)", tap, vid, have)
		}
	}
	return nil
}

func (m *Manager) portVLANs(ctx context.Context, tap string) ([]bridgeVLAN, error) {
	out, err := m.run(ctx, "bridge", "-j", "vlan", "show", "dev", tap)
	if err != nil {
		return nil, fmt.Errorf("reading %s's VLANs: %w", tap, err)
	}
	return parseBridgeVLANs(out, tap)
}

// ---- the private (NAT) network ------------------------------------------------

// natChain holds HardyOS's rules for traffic from VMs on libvirt's NAT
// network to the server itself.
const natChain = "HARDYOS-VMNAT"

// natBridge is the NAT network's bridge (libvirt's default: virbr0).
func (m *Manager) natBridge(ctx context.Context) string {
	out, err := m.virsh(ctx, "net-dumpxml", "default")
	if err == nil {
		var n struct {
			Bridge struct {
				Name string `xml:"name,attr"`
			} `xml:"bridge"`
		}
		if xml.Unmarshal(out, &n) == nil && ifnameRE.MatchString(n.Bridge.Name) {
			return n.Bridge.Name
		}
	}
	return "virbr0"
}

// guardNAT lets VMs on the private network reach the server only for DHCP
// and DNS (libvirt's dnsmasq) and answers to what the server started;
// everything else they send to the server itself (its web desktop, SSH,
// SMB, …) is dropped. Forwarding to the internet is libvirt's and
// unchanged. IPv6 to the server is dropped entirely (the network is IPv4).
func (m *Manager) guardNAT(ctx context.Context) error {
	br := m.natBridge(ctx)
	rules := map[string][][]string{
		"iptables": {
			{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
			{"-p", "udp", "--dport", "67", "-j", "ACCEPT"},
			{"-p", "udp", "--dport", "53", "-j", "ACCEPT"},
			{"-p", "tcp", "--dport", "53", "-j", "ACCEPT"},
			{"-j", "DROP"},
		},
		"ip6tables": {
			{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
			{"-j", "DROP"},
		},
	}
	for _, tool := range []string{"iptables", "ip6tables"} {
		// The chain may exist from an earlier start; it's refilled.
		_, _ = m.run(ctx, tool, "-w", "-N", natChain)
		if _, err := m.run(ctx, tool, "-w", "-F", natChain); err != nil {
			return fmt.Errorf("%s: %w", tool, err)
		}
		for _, r := range rules[tool] {
			if _, err := m.run(ctx, tool, append([]string{"-w", "-A", natChain}, r...)...); err != nil {
				return fmt.Errorf("%s: %w", tool, err)
			}
		}
		jump := []string{"INPUT", "-i", br, "-j", natChain}
		if _, err := m.run(ctx, tool, append([]string{"-w", "-C"}, jump...)...); err == nil {
			continue
		}
		if _, err := m.run(ctx, tool, append([]string{"-w", "-I", "INPUT", "1"}, jump[1:]...)...); err != nil {
			return fmt.Errorf("%s: %w", tool, err)
		}
	}
	return nil
}

// ---- confinement ----------------------------------------------------------------

// securityModels reads libvirt's host security drivers (virsh
// capabilities: <host><secmodel><model>).
func (m *Manager) securityModels(ctx context.Context) ([]string, error) {
	out, err := m.virsh(ctx, "capabilities")
	if err != nil {
		return nil, err
	}
	var c struct {
		Host struct {
			SecModels []struct {
				Model string `xml:"model"`
			} `xml:"secmodel"`
		} `xml:"host"`
	}
	if err := xml.Unmarshal(out, &c); err != nil {
		return nil, fmt.Errorf("reading libvirt's capabilities: %w", err)
	}
	var l []string
	for _, s := range c.Host.SecModels {
		l = append(l, strings.TrimSpace(s.Model))
	}
	return l, nil
}

// SecurityModel is the confinement VMs need.
const SecurityModel = "apparmor"

// confined refuses to run VMs unless libvirt confines QEMU with AppArmor:
// a guest that breaks out of QEMU then only reaches its own files.
func (m *Manager) confined(ctx context.Context) error {
	l, err := m.securityModels(ctx)
	if err != nil {
		return fmt.Errorf("checking how VMs are confined: %w", err)
	}
	for _, s := range l {
		if s == SecurityModel {
			return nil
		}
	}
	return Problems{noConfinement(l)}
}

func noConfinement(models []string) string {
	have := "none"
	if len(models) > 0 {
		have = strings.Join(models, ", ")
	}
	return fmt.Sprintf("VMs can't run: libvirt doesn't confine them with AppArmor (it has %s). Turn AppArmor on (apparmor=1 security=apparmor) and set security_driver = \"apparmor\" in /etc/libvirt/qemu.conf", have)
}
