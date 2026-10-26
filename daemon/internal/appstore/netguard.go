package appstore

// Imported catalogs are fetched by hardyd, which sits inside the family's
// network. Without a guard, a catalog address (or a redirect, or a DNS name
// that later resolves elsewhere) could make hardyd fetch from the server
// itself or the LAN: the router's admin page, a printer, another app. The
// guard runs on every connection hardyd's catalog client dials, after DNS
// resolution and after each redirect, so it sees the address actually used.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// LocalAddressError means a catalog fetch would connect to an address on
// this server or its own networks.
type LocalAddressError struct {
	Addr netip.Addr
	// Never is true for addresses refused even with "On my network"
	// (unspecified, multicast, broadcast).
	Never bool
}

func (e *LocalAddressError) Error() string {
	if e.Never {
		return fmt.Sprintf("%s isn't an address a catalog can be fetched from", e.Addr)
	}
	return fmt.Sprintf("%s is on this server or its own network; tick \"On my network\" for this catalog to allow that", e.Addr)
}

var (
	cgnat     = netip.MustParsePrefix("100.64.0.0/10")
	thisNet   = netip.MustParsePrefix("0.0.0.0/8")
	broadcast = netip.MustParseAddr("255.255.255.255")
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
)

// classifyAddr reports whether a catalog may be fetched from ip: never
// (unspecified, multicast, broadcast), only with the catalog's "On my
// network" flag (loopback, link-local, RFC 1918 private, CGNAT, unique
// local), or freely.
func classifyAddr(ip netip.Addr) (local, never bool) {
	ip = ip.Unmap()
	if ip.Is6() && nat64.Contains(ip) {
		// A NAT64 address carries an IPv4 one: judge that.
		b := ip.As16()
		ip = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	switch {
	case !ip.IsValid(), ip.IsUnspecified(), thisNet.Contains(ip), ip.IsMulticast(), ip == broadcast:
		return false, true
	case ip.IsLoopback(), ip.IsLinkLocalUnicast(), ip.IsPrivate(), cgnat.Contains(ip):
		return true, false
	}
	return false, false
}

// checkDialAddr is the dialer's guard for one connection.
func checkDialAddr(address string, allowLocal bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("catalog fetch: %q isn't an IP address", host)
	}
	local, never := classifyAddr(ip)
	if never || (local && !allowLocal) {
		return &LocalAddressError{Addr: ip.Unmap(), Never: never}
	}
	return nil
}

// guardedTransport is an HTTP transport whose every connection goes through
// checkDialAddr. It never uses an HTTP proxy from the environment (the
// proxy's address would be checked instead of the catalog's).
func guardedTransport(base *http.Transport, allowLocal bool) *http.Transport {
	var tr *http.Transport
	if base != nil {
		tr = base.Clone()
	} else {
		tr = &http.Transport{
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: fetchTimeout,
			ForceAttemptHTTP2:     true,
		}
	}
	tr.Proxy = nil
	tr.DisableKeepAlives = true // a client per fetch; no idle connections left behind
	d := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			return checkDialAddr(address, allowLocal)
		},
	}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.DialContext(ctx, network, addr)
	}
	tr.DialTLSContext = nil
	return tr
}
