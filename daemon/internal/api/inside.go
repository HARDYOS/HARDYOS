package api

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/photos"
	"github.com/hardyos/hardyos/daemon/internal/ports"
)

// signsInWithHardyOS reports whether an app's own sign-in is HardyOS's:
// Photos (Immich) with "Sign in with HardyOS" on and Immich's passwords
// off. Its sessions start at sso.<base>, where outside needs a code, so it
// may be published without the gateway's sign-in in front (decision 441;
// what other apps keep in their own sessions is theirs: docs/sign-in.md).
func (s *Server) signsInWithHardyOS(ctx context.Context, appID string) bool {
	if appID != photos.AppID || s.photos == nil {
		return false
	}
	set, err := s.photos.Settings(ctx)
	return err == nil && set.SSO && !set.PasswordLogin
}

// Where a request comes from, for two-factor sign-in (decision 441, and
// the review's M3/L7): inside is hardyd's own loopback, the networks of
// this server's LAN interfaces (IPv6 global prefixes on them included),
// and NetBird peers. Docker's networks (the bridge, compose bridges, the
// app and webmail networks), libvirt's, the domain controller's shim and
// the router's own address are outside: a container or a port forward the
// router masquerades must not count as someone at home.

// netbirdNet is NetBird's default network.
var netbirdNet = netip.MustParsePrefix("100.64.0.0/10")

// notLAN are interfaces that aren't the LAN (as smb.LANAddresses skips
// them): Docker's, compose bridges (br-…, never br0), veth pairs, the
// domain controller's shim, libvirt, tunnels. NetBird's wt0 is counted by
// its network instead.
var notLAN = []string{"lo", "docker", "br-", "veth", "hdc", "virbr", "wt", "tun", "tap", "vnet"}

type insideNets struct {
	mu     sync.Mutex
	at     time.Time
	lan    []netip.Prefix
	router netip.Addr
	// routerSeen is when a request last came from the router's address.
	routerSeen time.Time

	// lanFor and routerFor replace the system's (tests).
	lanFor    func() []netip.Prefix
	routerFor func() netip.Addr
}

func (n *insideNets) refresh() {
	if !n.at.IsZero() && time.Since(n.at) < 15*time.Second {
		return
	}
	n.at = time.Now()
	if n.lanFor != nil {
		n.lan = n.lanFor()
	} else {
		n.lan = lanPrefixes()
	}
	if n.routerFor != nil {
		n.router = n.routerFor()
	} else {
		n.router = defaultRouter()
	}
}

// lanPrefixes are the networks of this server's LAN interfaces.
func lanPrefixes() []netip.Prefix {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
next:
	for _, i := range ifs {
		for _, p := range notLAN {
			if strings.HasPrefix(i.Name, p) {
				continue next
			}
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok || ip.IsLinkLocalUnicast() {
				continue
			}
			bits, _ := ipn.Mask.Size()
			out = append(out, netip.PrefixFrom(ip.Unmap(), bits).Masked())
		}
	}
	return out
}

// defaultRouter is the IPv4 default gateway from /proc/net/route.
func defaultRouter() netip.Addr {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 3 || fl[1] != "00000000" {
			continue
		}
		b, err := hex.DecodeString(fl[2])
		if err != nil || len(b) != 4 {
			continue
		}
		var a [4]byte
		binary.LittleEndian.PutUint32(a[:], binary.BigEndian.Uint32(b))
		if ip := netip.AddrFrom4(a); !ip.IsUnspecified() {
			return ip
		}
	}
	return netip.Addr{}
}

// insideAddr reports whether a is inside.
func (s *Server) insideAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() {
		return false
	}
	if a.IsLoopback() {
		return true
	}
	if ports.WebmailSubnet.Contains(a) {
		return false
	}
	n := &s.inside
	n.mu.Lock()
	defer n.mu.Unlock()
	n.refresh()
	if n.router.IsValid() && a == n.router {
		// Hairpin NAT or a masqueraded port forward: the internet can hide
		// behind the router's address. It is on the LAN, so it counts as
		// inside (a server in a VM behind NAT sees everyone this way), but
		// Control Panel › Security warns (decision 441).
		n.routerSeen = time.Now()
	}
	if netbirdNet.Contains(a) || (s.remote.netbirdNetwork().IsValid() && s.remote.netbirdNetwork().Contains(a)) {
		return true
	}
	for _, p := range n.lan {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// routerSeen is when a request last came from the router's own address.
func (s *Server) routerSeen() time.Time {
	s.inside.mu.Lock()
	defer s.inside.mu.Unlock()
	return s.inside.routerSeen
}

// outside reports whether a request is from outside: through the app
// gateway (any published service: NetBird's proxy terminated it), or from
// an address that isn't inside (insideAddr). There everyone needs a second
// factor, and passwords never work for services that can't ask for one.
func (s *Server) outside(r *http.Request) bool {
	if viaGateway(r) {
		return true
	}
	a, err := netip.ParseAddr(s.clientIP(r))
	if err != nil {
		// An address we can't read is not trusted as inside.
		return true
	}
	return !s.insideAddr(a)
}
