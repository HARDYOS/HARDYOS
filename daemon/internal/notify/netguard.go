package notify

// Webhooks and the SES API are reached by hardyd from inside the family's
// network. A webhook URL is typed by an administrator, but it must still
// never become a way to make hardyd talk to the server itself, the LAN or
// the NetBird network (the router's admin page, another app): every
// connection is checked after DNS resolution, at dial time, so a name that
// resolves (or later re-resolves) to such an address is refused, and
// redirects are never followed. Email over SMTP is the exception: the
// family's own mail server (phase 7) is on this server or the LAN.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// LocalAddressError means a connection would go to this server or a
// private network.
type LocalAddressError struct{ Addr netip.Addr }

func (e *LocalAddressError) Error() string {
	return fmt.Sprintf("%s is on this server or a private network; alerts are only posted to public https services", e.Addr)
}

var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
		"::/128", "::1/128", "64:ff9b:1::/48", "100::/64", "2001::/32", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// publicAddr reports whether ip is a public unicast address.
func publicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Is6() && nat64.Contains(ip) {
		b := ip.As16()
		ip = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

func checkDial(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%q isn't an IP address", host)
	}
	if !publicAddr(ip) {
		return &LocalAddressError{Addr: ip.Unmap()}
	}
	return nil
}

// errRedirect: webhooks don't follow redirects (a redirect could point
// anywhere).
var errRedirect = errors.New("the webhook answered with a redirect; use the final URL")

// guardedClient is the HTTP client for webhooks and SES. allowLocal turns
// the address check off (tests talk to httptest servers on loopback).
func guardedClient(allowLocal bool) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if !allowLocal {
		d.Control = func(_, address string, _ syscall.RawConn) error { return checkDial(address) }
	}
	tr := &http.Transport{
		Proxy:                 nil, // the proxy's address would be checked instead of the target's
		DialContext:           func(ctx context.Context, n, a string) (net.Conn, error) { return d.DialContext(ctx, n, a) },
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect },
	}
}
