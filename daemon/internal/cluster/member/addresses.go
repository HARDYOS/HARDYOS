package member

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// Discover finds this server's addresses: the LAN address on the default
// route's interface, the NetBird address on wt0, and an address inside
// the cluster's storage subnet on any other interface. Docker's,
// libvirt's and the domain controller's interfaces are never used.
func Discover(storage netip.Prefix) cluster.Addresses {
	var a cluster.Addresses
	def := defaultRouteInterface("/proc/net/route")
	ifs, err := net.Interfaces()
	if err != nil {
		return a
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || skipInterface(ifc.Name) {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, x := range addrs {
			ipn, ok := x.(*net.IPNet)
			if !ok || !ipn.IP.IsGlobalUnicast() || ipn.IP.To4() == nil {
				continue
			}
			ip, _ := netip.AddrFromSlice(ipn.IP.To4())
			switch {
			case ifc.Name == "wt0":
				if !a.NetBird.IsValid() {
					a.NetBird = ip
				}
			case storage.IsValid() && storage.Contains(ip):
				if !a.Storage.IsValid() {
					a.Storage = ip
				}
			case ifc.Name == def:
				if !a.LAN.IsValid() {
					a.LAN = ip
				}
			}
		}
	}
	return a
}

func skipInterface(name string) bool {
	for _, p := range []string{"docker", "br-", "veth", "virbr", "vnet", "hdc", "macvtap", "tap"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// defaultRouteInterface reads the interface of the IPv4 default route.
func defaultRouteInterface(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) > 2 && fields[1] == "00000000" && fields[0] != "Iface" {
			return fields[0]
		}
	}
	return ""
}
