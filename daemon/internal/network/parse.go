package network

import (
	"bufio"
	"strconv"
	"strings"
)

// Import reads the settings from files HardyOS wrote before network settings
// were kept in the Control Panel (the installer's /etc/network/interfaces),
// so existing servers show their real setup. Unknown lines are ignored; the
// result is normalized but not validated.
func Import(hostname, interfaces, resolv string, ports []string) Config {
	c := Default(hostname, ports)
	byName := map[string]*Addressing{}
	for i := range c.Interfaces {
		c.Interfaces[i].Mode = ModeOff
		byName[c.Interfaces[i].Name] = &c.Interfaces[i].Addressing
	}

	var cur *Addressing
	var curBond *Bond
	var curVLAN *VLAN
	finish := func() {
		if curBond != nil {
			c.Bonds = append(c.Bonds, *curBond)
		}
		if curVLAN != nil {
			c.VLANs = append(c.VLANs, *curVLAN)
		}
		cur, curBond, curVLAN = nil, nil, nil
	}

	sc := bufio.NewScanner(strings.NewReader(interfaces))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		switch f[0] {
		case "auto", "allow-hotplug":
			continue
		case "source", "source-directory", "mapping":
			finish()
			continue
		case "iface":
			finish()
			if len(f) < 4 || f[1] == "lo" {
				continue
			}
			name, method := f[1], f[3]
			mode := map[string]string{"dhcp": ModeDHCP, "static": ModeStatic, "manual": ModeOff}[method]
			if mode == "" {
				mode = ModeOff
			}
			switch {
			case strings.HasPrefix(name, "bond"):
				curBond = &Bond{Name: name, Policy: "active-backup", Addressing: Addressing{Mode: mode}}
				cur = &curBond.Addressing
			case strings.Contains(name, "."):
				i := strings.LastIndex(name, ".")
				id, _ := strconv.Atoi(name[i+1:])
				curVLAN = &VLAN{Parent: name[:i], ID: id, Addressing: Addressing{Mode: mode}}
				cur = &curVLAN.Addressing
			default:
				if a, ok := byName[name]; ok {
					a.Mode = mode
					cur = a
				}
			}
			continue
		}
		if cur == nil {
			continue
		}
		switch f[0] {
		case "address":
			if len(f) > 1 {
				cur.Address = f[1]
			}
		case "netmask":
			// Older style: address without a prefix length plus a netmask.
			if len(f) > 1 && !strings.Contains(cur.Address, "/") {
				cur.Address += "/" + strconv.Itoa(maskBits(f[1]))
			}
		case "gateway":
			if len(f) > 1 {
				cur.Gateway = f[1]
			}
		case "mtu":
			if len(f) > 1 {
				cur.MTU, _ = strconv.Atoi(f[1])
			}
		case "pre-up":
			// pre-up ip link set dev NAME mtu N
			if len(f) >= 8 && f[1] == "ip" && f[6] == "mtu" {
				cur.MTU, _ = strconv.Atoi(f[7])
			}
		case "bond-slaves":
			if curBond != nil {
				curBond.Members = append(curBond.Members, f[1:]...)
			}
		case "bond-mode":
			if curBond != nil && len(f) > 1 {
				curBond.Policy = map[string]string{"1": "active-backup", "4": "802.3ad", "6": "balance-alb"}[f[1]]
				if curBond.Policy == "" {
					curBond.Policy = f[1]
				}
			}
		}
	}
	finish()

	// DNS only counts as chosen when it isn't DHCP's (which leaves no header).
	if strings.Contains(resolv, "HardyOS") {
		for _, line := range strings.Split(resolv, "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "nameserver" {
				c.DNS = append(c.DNS, f[1])
			}
			if len(f) >= 2 && f[0] == "search" {
				c.Search = append(c.Search, f[1:]...)
			}
		}
	}
	c.Normalize()
	return c
}

func maskBits(mask string) int {
	bits := 0
	for _, part := range strings.Split(mask, ".") {
		n, _ := strconv.Atoi(part)
		for n > 0 {
			bits += n & 1
			n >>= 1
		}
	}
	return bits
}
