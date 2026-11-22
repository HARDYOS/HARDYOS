package api

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/clientip"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/photos"
	"github.com/hardyos/hardyos/daemon/internal/ports"
	"github.com/hardyos/hardyos/daemon/internal/router"

	"github.com/hardyos/hardyos/daemon/internal/store"
)

// settingPhotosSignIn is what the last successful Photos sync saw of
// Immich's sign-in.
const settingPhotosSignIn = "auth.photos_signin"

type photosSignIn struct {
	HardyOSOnly bool      `json:"hardyosOnly"`
	At          time.Time `json:"at"`
}

func (s *Server) savePhotosSignIn(ctx context.Context, only bool) {
	b, _ := json.Marshal(photosSignIn{HardyOSOnly: only, At: time.Now().UTC()})
	if err := s.cfg.DB.SetSetting(ctx, settingPhotosSignIn, string(b)); err != nil {
		s.log.Warn("photos: saving what its sign-in is", "err", err)
	}
}

// signsInWithHardyOS reports whether an app's own sign-in is HardyOS's
// (review M5): Photos (Immich) when the last successful sync saw, from
// Immich itself, sign-in with HardyOS working and Immich's own passwords
// off, and the settings still ask for that. The settings alone aren't
// enough; nothing seen, or anything unreadable, fails closed. Its sessions
// start at sso.<base>, where outside needs a code, so it may be published
// without the gateway's sign-in in front (decision 441).
func (s *Server) signsInWithHardyOS(ctx context.Context, appID string) bool {
	if appID != photos.AppID || s.photos == nil || s.cfg.DB == nil {
		return false
	}
	set, err := s.photos.Settings(ctx)
	if err != nil || !set.SSO || set.PasswordLogin {
		return false
	}
	v, err := s.cfg.DB.GetSetting(ctx, settingPhotosSignIn)
	if err != nil {
		return false
	}
	var seen photosSignIn
	return json.Unmarshal([]byte(v), &seen) == nil && seen.HardyOSOnly
}

var errNoRouter = router.ErrNoRouter

// Where a request comes from, for two-factor sign-in (decision 441):
//
//   - home: hardyd's own loopback and this server's own addresses, but only
//     for connections whose other end is hardyd itself (a host-network
//     container connects from the same addresses, often as root); private
//     IPv4 networks and IPv6 unique-local networks of the LAN interfaces;
//     IPv6 global networks only of interfaces that don't carry the default
//     route (on that one a global prefix is the internet's); and NetBird
//     peers while NetBird is connected, except its reverse proxy peers.
//   - router: the router's own address, only while an administrator chose
//     "this server is behind NAT" and the router is still the one (IP and
//     MAC) they trusted. It counts as home for what sign-in asks for, but
//     its codes have a bucket of their own and count in the 60-day budget,
//     and own passwords stay refused for WebDAV, mail and calendars.
//   - outside: everything else, the gateway, Docker's networks (bridge,
//     compose, apps, webmail), libvirt's, the DC shim, and the router's
//     address otherwise (NAT reflection, masqueraded port forwards,
//     reverse proxies or tunnels on the router, subnet routers and QEMU
//     or libvirt NAT all make the internet arrive with it).
type place int

const (
	placeOutside place = iota
	placeRouter
	placeHome
)

// notLAN are interfaces that aren't the LAN (as smb.LANAddresses skips
// them): Docker's, compose bridges (br-…, never br0), veth pairs, the
// domain controller's shim, libvirt, tunnels. NetBird's wt0 is counted by
// its network instead.
var notLAN = []string{"lo", "docker", "br-", "veth", "hdc", "virbr", "wt", "tun", "tap", "vnet"}

// settingRouterSeen is when a request last came from the router's address.
const settingRouterSeen = "auth.mfa.router_seen"

type insideNets struct {
	mu        sync.Mutex
	at        time.Time
	lan       []netip.Prefix
	own       []netip.Addr
	router    netip.Addr
	routerMAC string
	// routerSeen is when a request last came from the router's address
	// (also in the settings: seenSaved is the last write).
	routerSeen, seenSaved time.Time
	// trustNoticed is the trusted router administrators were told about.
	trustNoticed string
	// proxies are NetBird peers seen as the reverse proxy at the gateway.

	proxies map[netip.Addr]bool

	// lanFor, ownFor, routerFor and peerIsSelf replace the system's (tests).
	lanFor     func() []netip.Prefix
	ownFor     func() []netip.Addr
	routerFor  func() (netip.Addr, string)
	peerIsSelf func(r *http.Request) bool
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
	if n.ownFor != nil {
		n.own = n.ownFor()
	} else {
		n.own = ownAddrs()
	}
	if n.routerFor != nil {
		n.router, n.routerMAC = n.routerFor()
	} else {
		n.router, n.routerMAC = router.Default()
	}
}

// private4 are the IPv4 ranges a LAN network can count from.
var private4 = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16")}

// ula is IPv6 unique-local space.
var ula = netip.MustParsePrefix("fc00::/7")

func isLAN(name string) bool {
	for _, p := range notLAN {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	return true
}

// lanPrefixes are the networks of this server's LAN interfaces that count
// as home (review M2): private IPv4, unique-local IPv6, and global IPv6
// only off the default-route interface.
func lanPrefixes() []netip.Prefix {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	def6 := defaultIface6()
	var out []netip.Prefix
	for _, i := range ifs {
		if !isLAN(i.Name) {
			continue
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
			if !ok {
				continue
			}
			ip = ip.Unmap()
			bits, _ := ipn.Mask.Size()
			if p, ok := homePrefix(ip, bits, i.Name == def6); ok {
				out = append(out, p)
			}
		}
	}
	return out
}

// homePrefix is the network of an interface address if it counts as home.
func homePrefix(ip netip.Addr, bits int, defaultRoute6 bool) (netip.Prefix, bool) {
	if ip.IsLinkLocalUnicast() || ip.IsLoopback() {
		return netip.Prefix{}, false
	}
	p := netip.PrefixFrom(ip, bits).Masked()
	if ip.Is4() {
		for _, r := range private4 {
			if r.Contains(ip) && bits >= r.Bits() {
				return p, true
			}
		}
		return netip.Prefix{}, false // a public IPv4 network is the internet's
	}
	if ula.Contains(ip) {
		return p, true
	}
	if ip.IsGlobalUnicast() && !defaultRoute6 && bits >= 48 {
		return p, true
	}
	return netip.Prefix{}, false
}

// ownAddrs are every address of this server (any interface).
func ownAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

// The IPv4 default router and its MAC address: package router.

// defaultIface6 is the interface of the IPv6 default route.
func defaultIface6() string {
	f, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) >= 10 && fl[0] == strings.Repeat("0", 32) && fl[1] == "00" && fl[9] != "lo" {
			return fl[9]
		}
	}
	return ""
}

// localPeer is the other end of a TCP connection from this server to
// itself as /proc/net/tcp and tcp6 list it: its owner's uid and its
// socket's inode.
type localPeer struct {
	uid   int
	inode string
}

// peerProc finds the other end of a local connection to r's listener.
func peerProc(r *http.Request) (localPeer, bool) {
	la, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if la == nil {
		return localPeer{}, false
	}
	local, err := netip.ParseAddrPort(la.String())
	if err != nil {
		return localPeer{}, false
	}
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return localPeer{}, false
	}
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if p, ok := findSocket(file, peer, local); ok {
			return p, true
		}
	}
	return localPeer{}, false
}

// findSocket looks for the socket whose local end is from and remote end
// is to.
func findSocket(file string, from, to netip.AddrPort) (localPeer, bool) {
	f, err := os.Open(file)
	if err != nil {
		return localPeer{}, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 10 {
			continue
		}
		l, ok1 := parseProcAddr(fl[1])
		rem, ok2 := parseProcAddr(fl[2])
		if !ok1 || !ok2 || l.Port() != from.Port() || rem.Port() != to.Port() ||
			l.Addr().Unmap() != from.Addr().Unmap() || rem.Addr().Unmap() != to.Addr().Unmap() {
			continue
		}
		uid, err := strconv.Atoi(fl[7])
		if err != nil || fl[9] == "0" {
			return localPeer{}, false
		}
		return localPeer{uid: uid, inode: fl[9]}, true
	}
	return localPeer{}, false
}

// parseProcAddr reads "0100007F:1F90" (IPv4) or 32 hex digits (IPv6): each
// 32-bit word is printed as the kernel holds it in memory, in this
// machine's byte order (binary.NativeEndian, so it reads right on any
// architecture).
func parseProcAddr(s string) (netip.AddrPort, bool) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	if len(h) != 8 && len(h) != 32 {
		return netip.AddrPort{}, false
	}
	b := make([]byte, len(h)/2)
	for i := 0; i < len(b); i += 4 {
		w, err := strconv.ParseUint(h[2*i:2*i+8], 16, 32)
		if err != nil {
			return netip.AddrPort{}, false
		}
		binary.NativeEndian.PutUint32(b[i:], uint32(w))
	}
	a, _ := netip.AddrFromSlice(b)
	return netip.AddrPortFrom(a, uint16(port)), true
}

// ownsSocket reports whether this process holds the socket with inode.
func ownsSocket(inode string) bool {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return false
	}
	want := "socket:[" + inode + "]"
	for _, e := range ents {
		if l, err := os.Readlink("/proc/self/fd/" + e.Name()); err == nil && l == want {
			return true
		}
	}
	return false
}

// peerIsSelfProc: the other end is hardyd itself (its own uid, and a
// socket this process holds).
func peerIsSelfProc(r *http.Request) bool {
	p, ok := peerProc(r)
	return ok && p.uid == os.Getuid() && ownsSocket(p.inode)
}

// trustedPeer reports whether a connection from this server to itself is
// hardyd's own (review M4). Not root's or any other user's: a container on
// the host's network often runs as root, or as a uid that happens to be
// hardyd's, so only the socket being this very process's counts.
func (s *Server) trustedPeer(r *http.Request) bool {
	look := s.inside.peerIsSelf
	if look == nil {
		look = peerIsSelfProc
	}
	return look(r)
}

func (n *insideNets) isOwn(a netip.Addr) bool {
	if a.IsLoopback() {
		return true
	}
	for _, o := range n.own {
		if o == a {
			return true
		}
	}
	return false
}

// notePeerProxy remembers a NetBird peer that came in as the reverse
// proxy (its direct connections never count as home).
func (s *Server) notePeerProxy(a netip.Addr) {
	n := &s.inside
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.proxies == nil {
		n.proxies = map[netip.Addr]bool{}
	}
	if len(n.proxies) < 64 {
		n.proxies[a.Unmap()] = true
	}
}

// placeOf is where address a is, for a request whose other end isn't
// local (local addresses are decided by placeOfRequest).
func (s *Server) placeOf(ctx context.Context, a netip.Addr) place {
	a = a.Unmap()
	if !a.IsValid() || ports.WebmailSubnet.Contains(a) {
		return placeOutside
	}
	n := &s.inside
	n.mu.Lock()
	n.refresh()
	if n.isOwn(a) {
		n.mu.Unlock()
		return placeOutside // local, but whose? (placeOfRequest decides)
	}
	if n.router.IsValid() && a == n.router {
		mac := n.routerMAC
		n.mu.Unlock()
		s.noteRouter(ctx)
		if t := s.loadTrustedRouter(ctx); t.Matches(a, mac) {
			s.noticeTrustedRouter(ctx, t)
			return placeRouter
		}
		return placeOutside
	}
	nb := s.remote.netbirdNetwork()
	if nb.IsValid() && nb.Contains(a) && !n.proxies[a] {
		n.mu.Unlock()
		return placeHome
	}
	for _, p := range n.lan {
		if p.Contains(a) {
			n.mu.Unlock()
			return placeHome
		}
	}
	n.mu.Unlock()
	return placeOutside
}

// insideAddr reports whether an address alone is home, for services that
// only know the address (mail): local addresses and the router never are.
func (s *Server) insideAddr(a netip.Addr) bool {
	return s.placeOf(context.Background(), a) == placeHome
}

// placeOfRequest is where r comes from.
func (s *Server) placeOfRequest(r *http.Request) place {
	if viaGateway(r) {
		return placeOutside
	}
	ipStr := s.clientIP(r)
	a, err := netip.ParseAddr(ipStr)
	if err != nil {
		// An address we can't read is not trusted as inside.
		return placeOutside
	}
	a = a.Unmap()
	n := &s.inside
	n.mu.Lock()
	n.refresh()
	own := n.isOwn(a)
	n.mu.Unlock()
	if own {
		// A connection from this server itself: home only when its other
		// end is hardyd itself, never a forwarded claim (review M4).
		if ipStr == clientip.Peer(r) && s.trustedPeer(r) {
			return placeHome
		}
		return placeOutside
	}
	return s.placeOf(r.Context(), a)
}

// outside reports whether a request is from outside for what sign-in asks
// (a trusted router counts as home here). There everyone needs a second
// factor.
func (s *Server) outside(r *http.Request) bool { return s.placeOfRequest(r) == placeOutside }

// notHome reports whether a request isn't from home: for codes' buckets
// and budget and for own passwords on WebDAV, mail and calendars, a trusted
// router is not home.
func (s *Server) notHome(r *http.Request) bool { return s.placeOfRequest(r) != placeHome }

// ---- the router -------------------------------------------------------------------

// noteRouter records that a request came from the router's address: in
// memory, in the settings at most once a minute, and administrators are
// told the first time.
func (s *Server) noteRouter(ctx context.Context) {
	n := &s.inside
	n.mu.Lock()
	now := time.Now()
	n.routerSeen = now
	save := now.Sub(n.seenSaved) > time.Minute
	if save {
		n.seenSaved = now
	}
	n.mu.Unlock()
	if !save || s.cfg.DB == nil {
		return
	}
	first := false
	if _, err := s.cfg.DB.GetSetting(ctx, settingRouterSeen); err != nil {
		first = true
	}
	_ = s.cfg.DB.SetSetting(context.WithoutCancel(ctx), settingRouterSeen, store.FormatTime(now))
	if first {
		s.adminNotice(ctx, "security.2fa", "Requests through the router's address",
			"HardyOS saw a request from your router's own address: hairpin NAT, a port forward or a VPN/tunnel on the router. Such requests count as outside (two-factor sign-in). See Control Panel › Security.")
		s.recordSystem(ctx, "auth.2fa.router_seen", "", "a request came from the router's own address")
	}
}

// routerSeen is when a request last came from the router's own address.
func (s *Server) routerSeen(ctx context.Context) time.Time {
	s.inside.mu.Lock()
	t := s.inside.routerSeen
	s.inside.mu.Unlock()
	if t.IsZero() && s.cfg.DB != nil {
		if v, err := s.cfg.DB.GetSetting(ctx, settingRouterSeen); err == nil {
			t = store.ParseTime(v)
		}
	}
	return t
}

func (s *Server) loadTrustedRouter(ctx context.Context) *router.Trusted {
	if s.cfg.DB == nil {
		return nil
	}
	return router.Load(ctx, s.cfg.DB)
}

// routerTrusted: the setting is on and still names this router (IP and
// MAC). A changed router lapses it.
func (s *Server) routerTrusted(ctx context.Context, ip netip.Addr, mac string) bool {
	return s.loadTrustedRouter(ctx).Matches(ip, mac)
}

// currentRouter is the router as this server sees it now.
func (s *Server) currentRouter() (netip.Addr, string) {
	n := &s.inside
	n.mu.Lock()
	defer n.mu.Unlock()
	n.at = time.Time{}
	n.refresh()
	return n.router, n.routerMAC
}

// RouterTrust is the "behind NAT" setting as the API shows it.
type RouterTrust struct {
	On bool `json:"on"`
	// Lapsed: it was turned on for another router (IP or MAC changed).
	Lapsed bool       `json:"lapsed"`
	IP     string     `json:"ip,omitempty"`
	Since  *time.Time `json:"since,omitempty"`
}

func (s *Server) routerTrust(ctx context.Context) RouterTrust {
	t := s.loadTrustedRouter(ctx)
	if t == nil {
		return RouterTrust{}
	}
	ip, mac := s.currentRouter()
	at := t.At
	rt := RouterTrust{IP: t.IP, Since: &at}
	if ip.IsValid() && s.routerTrusted(ctx, ip, mac) {
		rt.On = true
	} else {
		rt.Lapsed = true
	}
	return rt
}

// setRouterTrust turns the setting on (for the router as it is now) or
// off. The caller checked the request is from home.
func (s *Server) setRouterTrust(ctx context.Context, on bool, by string) error {
	if !on {
		return router.Untrust(ctx, s.cfg.DB)
	}
	ip, mac := s.currentRouter()
	if _, err := router.Trust(ctx, s.cfg.DB, ip, mac, by); err != nil {
		return err
	}
	s.noticeTrustedRouter(ctx, router.Load(ctx, s.cfg.DB))
	return nil
}

// settingTrustNoticed is the trusted router's At that administrators were
// told about.
const settingTrustNoticed = "auth.mfa.trust_router_noticed"

// noticeTrustedRouter tells administrators once per turning on (from the
// desktop or hardyctl) that the router's address is trusted.
func (s *Server) noticeTrustedRouter(ctx context.Context, t *router.Trusted) {
	if t == nil || s.cfg.DB == nil {
		return
	}
	at := store.FormatTime(t.At)
	s.inside.mu.Lock()
	done := s.inside.trustNoticed == at
	s.inside.trustNoticed = at
	s.inside.mu.Unlock()
	if done {
		return
	}
	if v, err := s.cfg.DB.GetSetting(ctx, settingTrustNoticed); err == nil && v == at {
		return
	}
	_ = s.cfg.DB.SetSetting(context.WithoutCancel(ctx), settingTrustNoticed, at)
	s.adminNotice(ctx, "security.2fa", "The router's address is trusted",
		"Requests from the router ("+t.IP+") count as home for two-factor sign-in (turned on by "+t.By+"), so anything the router forwards from the internet (port forwards, NAT reflection, tunnels) isn't asked for a code. Turn it off in Control Panel › Security if this server isn't behind NAT.")
}

// adminNotice tells administrators (Notifications).
func (s *Server) adminNotice(ctx context.Context, kind, title, body string) {
	ctx = context.WithoutCancel(ctx)
	if s.cfg.Alerts != nil {
		s.cfg.Alerts.Notify(ctx, notify.Event{Kind: kind, Severity: notify.SeverityWarning, Title: title, Body: body, Link: "control/security", Time: time.Now()})
	} else if s.cfg.Notify != nil {
		_ = s.cfg.Notify.Send(ctx, notify.Notification{Level: notify.Warning, Title: title, Body: body, Source: "security", AdminOnly: true, Kind: kind, Link: "control/security"})
	}
}
