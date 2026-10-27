// Package clientip says which address a request came from. Behind a
// reverse proxy every request comes from the proxy, so the address the
// proxy saw is taken from X-Forwarded-For, but only when the request's
// peer is one of the configured trusted proxies: anyone else could send
// any X-Forwarded-For they like. With no trusted proxies (the default)
// the header is never read.
package clientip

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Resolver finds a request's client address. The zero value (and nil)
// trusts no proxy.
type Resolver struct {
	// Trusted are the reverse proxies whose X-Forwarded-For is believed.
	Trusted []netip.Prefix
}

// ParseTrusted reads a comma separated list of addresses and CIDR ranges
// ("127.0.0.1, 10.0.0.0/8, ::1"); empty means none.
func ParseTrusted(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range strings.Split(list, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("trusted proxy %q: %w", s, err)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", s, err)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// Peer is the address the connection itself came from.
func Peer(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (c *Resolver) trusted(s string) bool {
	if c == nil || len(c.Trusted) == 0 {
		return false
	}
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return false
	}
	a = a.Unmap().WithZone("")
	for _, p := range c.Trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// IP is the client's address: the peer, or, when the peer is a trusted
// proxy, the right-most X-Forwarded-For entry that isn't itself a trusted
// proxy (entries further left were written by the client and prove nothing).
func (c *Resolver) IP(r *http.Request) string {
	peer := Peer(r)
	if !c.trusted(peer) {
		return peer
	}
	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(h, ",") {
			hops = append(hops, strings.TrimSpace(part))
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(hops[i])
		if err != nil {
			// Something unreadable: stop believing the chain here.
			return peer
		}
		if !c.trusted(hops[i]) {
			return a.Unmap().String()
		}
	}
	return peer
}
