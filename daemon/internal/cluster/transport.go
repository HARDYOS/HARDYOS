package cluster

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// The cluster listener (decision 321): one TLS 1.3 port, mutual
// authentication by pinned keys, ALPN-multiplexed:
//
//   - ALPNRaft: the Raft stream layer; only current members.
//   - ALPNPeer: HTTP/2, the peer API; members (role-checked per path), and
//     non-members only for POST /cluster/v1/join.
//   - ALPNRelay: HTTP/1.1, proxied desktop requests with assertions
//     (WebSockets, app windows); current, unfenced HardyOS members only.
//   - ALPNMigrate: a live migration's libvirt connection (part C's hook).
//   - "http/1.1" without a client certificate: only the witness binary,
//     only while a witness join code is open (the install script's curl,
//     which pins this node's key itself).

// Network opens sockets. Production uses TCP; tests use a fake network
// with partitions (clustertest).
type Network interface {
	Listen(addr string) (net.Listener, error)
	DialContext(ctx context.Context, addr string) (net.Conn, error)
}

// TCP is the real network.
type TCP struct{}

// Listen listens on a TCP address.
func (TCP) Listen(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }

// DialContext dials a TCP address.
func (TCP) DialContext(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{KeepAlive: 15 * time.Second}
	return d.DialContext(ctx, "tcp", addr)
}

// PeerBook is who the transport talks to: the current members (from the
// applied state, or from the join answer before the state has them).
type PeerBook interface {
	// ByPin finds a member by its key pin.
	ByPin(pin string) (Node, bool)
	// Member returns a member's record.
	Member(id NodeID) (Node, bool)
}

// isFenced reports whether a node may only use Raft and rejoin.
func isFenced(n Node) bool { return n.State == NodeDead || n.State == NodeFenced }

// Transport is a node's listener and dialer on the cluster port.
type Transport struct {
	ID    *Identity
	Self  NodeID
	Net   Network
	Book  PeerBook
	Paths *Paths
	Port  int
	Log   *slog.Logger

	// Peer serves ALPNPeer (HTTP/2), Relay serves ALPNRelay (HTTP/1.1)
	// and Bootstrap serves unauthenticated HTTP/1.1.
	Peer, Relay, Bootstrap http.Handler
	// Migrate takes a live migration connection (part C); nil refuses.
	Migrate func(conn *tls.Conn, from Node)

	mu        sync.Mutex
	listeners map[string]net.Listener
	raft      *connQueue
	relay     *connQueue
	boot      *connQueue
	conns     map[NodeID]map[net.Conn]bool // outgoing raft and peer conns, closed on a path switch
	closed    bool
	wg        sync.WaitGroup
	h2        *http2.Server
	relaySrv  *http.Server
	bootSrv   *http.Server
}

func (t *Transport) log() *slog.Logger {
	if t.Log != nil {
		return t.Log
	}
	return slog.Default()
}

func (t *Transport) port() int {
	if t.Port != 0 {
		return t.Port
	}
	return Port
}

var serverProtos = []string{ALPNRaft, ALPNPeer, ALPNRelay, ALPNMigrate, "http/1.1"}

func (t *Transport) serverTLS() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{t.ID.Cert},
		// Checked per protocol against the pins (the bootstrap download is
		// the only thing served without a certificate).
		ClientAuth: tls.RequestClientCert,
		MinVersion: tls.VersionTLS13,
		NextProtos: serverProtos,
	}
}

func (t *Transport) init() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.listeners != nil {
		return
	}
	t.listeners = map[string]net.Listener{}
	t.raft = newConnQueue(nil)
	t.relay = newConnQueue(nil)
	t.boot = newConnQueue(nil)
	t.conns = map[NodeID]map[net.Conn]bool{}
	t.h2 = &http2.Server{IdleTimeout: 2 * time.Minute, MaxReadFrameSize: 1 << 20}
	quiet := log.New(io.Discard, "", 0)
	if t.Relay != nil {
		t.relaySrv = &http.Server{Handler: t.Relay, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute, ErrorLog: quiet,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				if rc, ok := c.(*relayConn); ok {
					return context.WithValue(ctx, relayTLSKey{}, &rc.state)
				}
				return ctx
			}}
		go func() { _ = t.relaySrv.Serve(t.relay) }()
	}
	if t.Bootstrap != nil {
		t.bootSrv = &http.Server{Handler: t.Bootstrap, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, ErrorLog: quiet,
			MaxHeaderBytes: 8 << 10}
		go func() { _ = t.bootSrv.Serve(t.boot) }()
	}
}

// RaftListener is the queue of authenticated Raft connections.
func (t *Transport) RaftListener() net.Listener {
	t.init()
	return t.raft
}

// SetListen listens on exactly these host addresses (port added),
// closing listeners on addresses no longer wanted.
func (t *Transport) SetListen(hosts []netip.Addr) {
	t.init()
	want := map[string]bool{}
	for _, h := range hosts {
		if h.IsValid() {
			want[net.JoinHostPort(h.String(), strconv.Itoa(t.port()))] = true
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	for a, ln := range t.listeners {
		if !want[a] {
			ln.Close()
			delete(t.listeners, a)
		}
	}
	for a := range want {
		if t.listeners[a] != nil {
			continue
		}
		ln, err := t.Net.Listen(a)
		if err != nil {
			t.log().Warn("cluster: listening", "addr", a, "err", err)
			continue
		}
		t.listeners[a] = ln
		t.wg.Add(1)
		go t.accept(ln)
	}
}

// Close stops listening and closes every connection queue.
func (t *Transport) Close() {
	t.init()
	t.mu.Lock()
	t.closed = true
	for a, ln := range t.listeners {
		ln.Close()
		delete(t.listeners, a)
	}
	var conns []net.Conn
	for _, m := range t.conns {
		for c := range m {
			conns = append(conns, c)
		}
	}
	t.conns = map[NodeID]map[net.Conn]bool{}
	t.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
	t.raft.Close()
	t.relay.Close()
	t.boot.Close()
	if t.relaySrv != nil {
		_ = t.relaySrv.Close()
	}
	if t.bootSrv != nil {
		_ = t.bootSrv.Close()
	}
	t.wg.Wait()
}

func (t *Transport) accept(ln net.Listener) {
	defer t.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go t.serveConn(c)
	}
}

// peerConn is an accepted connection with its authenticated member.
type peerConn struct {
	*tls.Conn
	peer Node
}

func (t *Transport) peerOf(cs tls.ConnectionState) (Node, bool) {
	if len(cs.PeerCertificates) == 0 {
		return Node{}, false
	}
	return t.Book.ByPin(PinOfCert(cs.PeerCertificates[0]))
}

func (t *Transport) serveConn(c net.Conn) {
	tc := tls.Server(c, t.serverTLS())
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		tc.Close()
		return
	}
	_ = tc.SetDeadline(time.Time{})
	cs := tc.ConnectionState()
	peer, member := t.peerOf(cs)
	switch cs.NegotiatedProtocol {
	case ALPNRaft:
		if !member {
			tc.Close()
			return
		}
		if !t.raft.push(&peerConn{Conn: tc, peer: peer}) {
			tc.Close()
		}
	case ALPNPeer:
		// Membership and roles are checked per request (the join path is
		// open to non-members).
		if len(cs.PeerCertificates) == 0 || t.Peer == nil {
			tc.Close()
			return
		}
		t.h2.ServeConn(tc, &http2.ServeConnOpts{Handler: t.Peer, Context: context.Background()})
	case ALPNRelay:
		if !member || isFenced(peer) || peer.Role == RoleWitness || t.Relay == nil {
			tc.Close()
			return
		}
		// net/http would close a *tls.Conn with an ALPN protocol it doesn't
		// know: hand it over wrapped, with its TLS state in the context.
		if !t.relay.push(&relayConn{Conn: tc, state: cs}) {
			tc.Close()
		}
	case ALPNMigrate:
		if !member || isFenced(peer) || peer.Role != RoleCompute || t.Migrate == nil {
			tc.Close()
			return
		}
		t.Migrate(tc, peer)
	default:
		if t.Bootstrap == nil || !t.boot.push(tc) {
			tc.Close()
		}
	}
}

// ---- dialing -------------------------------------------------------------

// errPin: the peer isn't who was dialled.
var errPin = errors.New("the other server's key isn't the one the cluster knows")

func (t *Transport) clientTLS(alpn string, verify func(tls.ConnectionState) error) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{t.ID.Cert},
		// Not checked against any authority: the key is pinned
		// (VerifyConnection).
		InsecureSkipVerify: true, //nolint:gosec // pinned key, see VerifyConnection
		VerifyConnection:   verify,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{alpn},
	}
}

// PinCheck accepts exactly one pinned key (or records the key seen when
// pin is "" and seen is set).
func PinCheck(pin string, seen *string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("the other server sent no certificate")
		}
		got := PinOfCert(cs.PeerCertificates[0])
		if seen != nil && pin == "" {
			*seen = got
			return nil
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(pin)) != 1 {
			return errPin
		}
		return nil
	}
}

// DialAddr dials an address with a protocol, checking the peer's pin (or
// learning it into seen when pin is "").
func (t *Transport) DialAddr(ctx context.Context, addr, alpn, pin string, seen *string) (*tls.Conn, error) {
	c, err := t.Net.DialContext(ctx, addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(c, t.clientTLS(alpn, PinCheck(pin, seen)))
	if dl, ok := ctx.Deadline(); ok {
		_ = tc.SetDeadline(dl)
	} else {
		_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		tc.Close()
		return nil, err
	}
	_ = tc.SetDeadline(time.Time{})
	if tc.ConnectionState().NegotiatedProtocol != alpn {
		tc.Close()
		return nil, fmt.Errorf("the other server doesn't speak %s", alpn)
	}
	return tc, nil
}

// pathAddr is a member's address on a path.
func pathAddr(a Addresses, p Path) netip.Addr {
	switch p {
	case PathLAN:
		return a.LAN
	case PathStorage:
		return a.Storage
	case PathNetBird:
		return a.NetBird
	}
	return netip.Addr{}
}

// DialNode dials a member on its current path, falling back through the
// other paths in order (LAN, storage network, NetBird). A live migration's
// connection never goes over NetBird.
func (t *Transport) DialNode(ctx context.Context, id NodeID, alpn string) (net.Conn, Path, error) {
	n, ok := t.Book.Member(id)
	if !ok {
		return nil, PathNone, fmt.Errorf("%s: %w", id, ErrNotMember)
	}
	paths := t.Paths.DialOrder(id)
	var lastErr error = fmt.Errorf("no path to %s", id)
	for i, p := range paths {
		if alpn == ALPNMigrate && p == PathNetBird {
			continue
		}
		a := pathAddr(n.Addresses, p)
		if !a.IsValid() {
			continue
		}
		dctx := ctx
		var cancel context.CancelFunc
		if i < len(paths)-1 {
			// Leave time for the next path.
			dctx, cancel = context.WithTimeout(ctx, 3*time.Second)
		}
		c, err := t.DialAddr(dctx, net.JoinHostPort(a.String(), strconv.Itoa(t.port())), alpn, n.Pin, nil)
		if cancel != nil {
			cancel()
		}
		if err == nil {
			return t.track(id, c), p, nil
		}
		lastErr = fmt.Errorf("%s over %s: %w", id, p, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, PathNone, lastErr
}

type trackedConn struct {
	*tls.Conn
	t    *Transport
	id   NodeID
	once sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.t.mu.Lock()
		delete(c.t.conns[c.id], c)
		c.t.mu.Unlock()
	})
	return c.Conn.Close()
}

func (t *Transport) track(id NodeID, c *tls.Conn) net.Conn {
	tc := &trackedConn{Conn: c, t: t, id: id}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		c.Close()
		return tc
	}
	if t.conns[id] == nil {
		t.conns[id] = map[net.Conn]bool{}
	}
	t.conns[id][tc] = true
	return tc
}

// DropConns closes every outgoing connection to a node (its path changed:
// the next dial takes the new one; Raft reconnects by itself).
func (t *Transport) DropConns(id NodeID) {
	t.mu.Lock()
	var l []net.Conn
	for c := range t.conns[id] {
		l = append(l, c)
	}
	delete(t.conns, id)
	t.mu.Unlock()
	for _, c := range l {
		c.Close()
	}
}

// ---- a listener fed with connections ---------------------------------------

type connQueue struct {
	ch     chan net.Conn
	done   chan struct{}
	once   sync.Once
	addr   net.Addr
	closed bool
	mu     sync.Mutex
}

func newConnQueue(addr net.Addr) *connQueue {
	if addr == nil {
		addr = &net.TCPAddr{}
	}
	return &connQueue{ch: make(chan net.Conn, 64), done: make(chan struct{}), addr: addr}
}

func (q *connQueue) push(c net.Conn) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return false
	}
	select {
	case q.ch <- c:
		return true
	default:
		return false
	}
}

func (q *connQueue) Accept() (net.Conn, error) {
	select {
	case c := <-q.ch:
		return c, nil
	case <-q.done:
		return nil, net.ErrClosed
	}
}

func (q *connQueue) Close() error {
	q.once.Do(func() {
		q.mu.Lock()
		q.closed = true
		q.mu.Unlock()
		close(q.done)
		for {
			select {
			case c := <-q.ch:
				c.Close()
			default:
				return
			}
		}
	})
	return nil
}

func (q *connQueue) Addr() net.Addr { return q.addr }

// relayConn is an accepted relay connection with its TLS state.
type relayConn struct {
	net.Conn
	state tls.ConnectionState
}

type relayTLSKey struct{}

// RelayTLS is the TLS state of a request on a relay connection.
func RelayTLS(r *http.Request) *tls.ConnectionState {
	if r.TLS != nil {
		return r.TLS
	}
	cs, _ := r.Context().Value(relayTLSKey{}).(*tls.ConnectionState)
	return cs
}
