// Package clustertest has test doubles for the cluster core: an in-memory
// network with links that can be cut (partitions, a failed LAN, a lost
// witness) and an in-memory membership store.
package clustertest

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// Networks every fake address belongs to (a node dials from its own
// address on the target's network).
var Networks = []netip.Prefix{
	netip.MustParsePrefix("192.168.1.0/24"), // LAN
	netip.MustParsePrefix("10.77.0.0/24"),   // storage network
	netip.MustParsePrefix("100.64.0.0/16"),  // NetBird
}

// Net is an in-memory network of hosts with addresses. Links between two
// addresses can be cut and healed; cutting closes the connections over
// them.
type Net struct {
	mu        sync.Mutex
	listeners map[string]*listener // "ip:port"
	cut       map[[2]netip.Addr]bool
	conns     map[*pipeEnd]bool
}

// NewNet makes an empty network.
func NewNet() *Net {
	return &Net{listeners: map[string]*listener{}, cut: map[[2]netip.Addr]bool{}, conns: map[*pipeEnd]bool{}}
}

// Host is one machine's view of the network.
func (n *Net) Host(addrs ...netip.Addr) cluster.Network { return &host{n: n, addrs: addrs} }

func netOf(a netip.Addr) int {
	for i, p := range Networks {
		if p.Contains(a) {
			return i
		}
	}
	return -1
}

func key(a, b netip.Addr) [2]netip.Addr {
	if b.Less(a) {
		a, b = b, a
	}
	return [2]netip.Addr{a, b}
}

// Cut cuts the link between two addresses (both ways).
func (n *Net) Cut(a, b netip.Addr) {
	n.mu.Lock()
	n.cut[key(a, b)] = true
	var drop []*pipeEnd
	for c := range n.conns {
		if key(c.local, c.remote) == key(a, b) {
			drop = append(drop, c)
		}
	}
	n.mu.Unlock()
	for _, c := range drop {
		c.Close()
	}
}

// Heal restores a link.
func (n *Net) Heal(a, b netip.Addr) {
	n.mu.Lock()
	delete(n.cut, key(a, b))
	n.mu.Unlock()
}

// Isolate cuts every link of an address to the others listed.
func (n *Net) Isolate(a netip.Addr, others ...netip.Addr) {
	for _, o := range others {
		n.Cut(a, o)
	}
}

// Rejoin heals every link of an address to the others listed.
func (n *Net) Rejoin(a netip.Addr, others ...netip.Addr) {
	for _, o := range others {
		n.Heal(a, o)
	}
}

func (n *Net) isCut(a, b netip.Addr) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.cut[key(a, b)]
}

type host struct {
	n     *Net
	addrs []netip.Addr
}

func (h *host) Listen(addr string) (net.Listener, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, err
	}
	h.n.mu.Lock()
	defer h.n.mu.Unlock()
	if h.n.listeners[addr] != nil {
		return nil, errors.New("address in use")
	}
	l := &listener{n: h.n, addr: ap, ch: make(chan net.Conn, 64), done: make(chan struct{})}
	h.n.listeners[addr] = l
	return l, nil
}

var errUnreachable = errors.New("connect: no route to host")

func (h *host) DialContext(ctx context.Context, addr string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, err
	}
	var src netip.Addr
	for _, a := range h.addrs {
		if a.IsValid() && netOf(a) == netOf(ap.Addr()) {
			src = a
		}
	}
	if !src.IsValid() || h.n.isCut(src, ap.Addr()) {
		// A cut link doesn't answer: wait a little like a lost SYN.
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Millisecond):
		}
		return nil, errUnreachable
	}
	h.n.mu.Lock()
	l := h.n.listeners[addr]
	h.n.mu.Unlock()
	if l == nil {
		return nil, errors.New("connect: connection refused")
	}
	a, b := net.Pipe()
	ca := &pipeEnd{Conn: a, n: h.n, local: src, remote: ap.Addr(), lport: 40000, rport: ap.Port()}
	cb := &pipeEnd{Conn: b, n: h.n, local: ap.Addr(), remote: src, lport: ap.Port(), rport: 40000}
	h.n.mu.Lock()
	h.n.conns[ca], h.n.conns[cb] = true, true
	h.n.mu.Unlock()
	select {
	case l.ch <- cb:
	case <-l.done:
		ca.Close()
		cb.Close()
		return nil, errors.New("connect: connection refused")
	case <-ctx.Done():
		ca.Close()
		cb.Close()
		return nil, ctx.Err()
	}
	return ca, nil
}

type listener struct {
	n    *Net
	addr netip.AddrPort
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *listener) Close() error {
	l.once.Do(func() {
		close(l.done)
		l.n.mu.Lock()
		delete(l.n.listeners, l.addr.String())
		l.n.mu.Unlock()
	})
	return nil
}

func (l *listener) Addr() net.Addr { return net.TCPAddrFromAddrPort(l.addr) }

type pipeEnd struct {
	net.Conn
	n             *Net
	local, remote netip.Addr
	lport, rport  uint16
	once          sync.Once
}

func (p *pipeEnd) Close() error {
	p.once.Do(func() {
		p.n.mu.Lock()
		delete(p.n.conns, p)
		p.n.mu.Unlock()
	})
	return p.Conn.Close()
}

func (p *pipeEnd) LocalAddr() net.Addr {
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(p.local, p.lport))
}

func (p *pipeEnd) RemoteAddr() net.Addr {
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(p.remote, p.rport))
}
