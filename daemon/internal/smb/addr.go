package smb

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// skipIfaces are interfaces that aren't the LAN: Docker's, the domain
// controller's shim, VPN tunnels.
var skipIfaces = []string{"lo", "docker", "br-", "veth", "hdc", "virbr", "wt", "tun", "tap"}

// LANAddresses lists this server's IPv4 addresses on its LAN interfaces
// (what devices on the network reach it by).
func LANAddresses(ctx context.Context, r sysexec.Runner) []string {
	out, err := sysexec.Output(ctx, r, "ip", "-j", "-4", "addr", "show", "scope", "global")
	if err != nil {
		return nil
	}
	var ifs []struct {
		IfName   string `json:"ifname"`
		AddrInfo []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}
	if json.Unmarshal(out, &ifs) != nil {
		return nil
	}
	addrs := []string{}
next:
	for _, i := range ifs {
		for _, p := range skipIfaces {
			if strings.HasPrefix(i.IfName, p) {
				continue next
			}
		}
		for _, a := range i.AddrInfo {
			if ip, err := netip.ParseAddr(a.Local); err == nil && ip.Is4() && !ip.IsLinkLocalUnicast() {
				addrs = append(addrs, ip.String())
			}
		}
	}
	return addrs
}
