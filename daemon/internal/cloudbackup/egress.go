package cloudbackup

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Where restic may connect (SSRF guard). An endpoint is the administrator's
// word, but a name can resolve anywhere, and resolve differently later
// (DNS rebinding), so restic never dials by itself: every connection goes
// through a CONNECT proxy inside hardyd-priv that only lets restic reach
// the target's own host and port, resolves the name itself and dials only
// an address that passes AddrAllowed at that moment.

// Resolver looks names up (net.DefaultResolver in production).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

var (
	cgnat     = netip.MustParsePrefix("100.64.0.0/10")
	ietf      = netip.MustParsePrefix("192.0.0.0/24")
	bench     = netip.MustParsePrefix("198.18.0.0/15")
	thisNet   = netip.MustParsePrefix("0.0.0.0/8")
	reserved  = netip.MustParsePrefix("240.0.0.0/4")
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
	nat64loc  = netip.MustParsePrefix("64:ff9b:1::/48")
	sixToFour = netip.MustParsePrefix("2002::/16")
	teredo    = netip.MustParsePrefix("2001::/32")
)

// AddrAllowed says whether restic may connect to a. Loopback, link-local
// (cloud metadata services), multicast, unspecified, reserved and
// translation ranges never; private and carrier-grade NAT ranges only with
// allowLAN; everything else (the internet) always.
func AddrAllowed(a netip.Addr, allowLAN bool) error {
	a = a.Unmap()
	switch {
	case !a.IsValid(), a.IsUnspecified(), a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(),
		a.IsMulticast(), a.IsInterfaceLocalMulticast(), thisNet.Contains(a), reserved.Contains(a), ietf.Contains(a),
		bench.Contains(a), nat64.Contains(a), nat64loc.Contains(a), sixToFour.Contains(a), teredo.Contains(a),
		a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return fmt.Errorf("%s is not an address backups may be sent to", a)
	case a.IsPrivate(), cgnat.Contains(a):
		if !allowLAN {
			return fmt.Errorf("%s is on the local network; turn on \"Allow a server on my network\" for a MinIO on your LAN", a)
		}
	}
	return nil
}

// allowedHosts is who restic may reach for a target: the endpoint for S3,
// Backblaze's own API and download hosts for B2.
type hostRule struct {
	host     string // exact host, or "" with suffix
	suffix   string // ".backblazeb2.com"
	port     int
	allowLAN bool
}

func (h hostRule) matches(host string, port int) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if port != h.port {
		return false
	}
	if h.host != "" {
		return host == h.host
	}
	return strings.HasSuffix(host, h.suffix) && hostRE.MatchString(host)
}

func rulesFor(t *Target) ([]hostRule, error) {
	switch t.Kind {
	case KindS3:
		host, port, err := ParseEndpoint(t.Endpoint)
		if err != nil {
			return nil, err
		}
		return []hostRule{{host: host, port: port, allowLAN: t.AllowLAN}}, nil
	case KindB2:
		return []hostRule{{suffix: ".backblazeb2.com", port: 443}}, nil
	}
	return nil, nil
}

// egressProxy is a CONNECT-only HTTP proxy on 127.0.0.1 for one restic
// run. It closes when the run ends.
type egressProxy struct {
	ln       net.Listener
	rules    []hostRule
	resolver Resolver
	// testAllow widens AddrAllowed for tests (loopback fake S3).
	testAllow func(netip.Addr) bool
	dialer    net.Dialer
	wg        sync.WaitGroup
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	closed    bool
	refused   string // the last refusal, for the error message
}

func startEgress(rules []hostRule, resolver Resolver, testAllow func(netip.Addr) bool) (*egressProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &egressProxy{ln: ln, rules: rules, resolver: resolver, testAllow: testAllow, conns: map[net.Conn]struct{}{}}
	p.dialer.Timeout = 30 * time.Second
	p.wg.Add(1)
	go p.serve()
	return p, nil
}

// URL is what restic gets as HTTPS_PROXY.
func (p *egressProxy) URL() string { return "http://" + p.ln.Addr().String() }

func (p *egressProxy) Close() {
	p.mu.Lock()
	p.closed = true
	for c := range p.conns {
		c.Close()
	}
	p.mu.Unlock()
	p.ln.Close()
	p.wg.Wait()
}

func (p *egressProxy) lastRefusal() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refused
}

func (p *egressProxy) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.conns[c] = struct{}{}
	return true
}

func (p *egressProxy) untrack(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
	c.Close()
}

func (p *egressProxy) serve() {
	defer p.wg.Done()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		if !p.track(c) {
			c.Close()
			return
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer p.untrack(c)
			p.handle(c)
		}()
	}
}

func (p *egressProxy) refuse(c net.Conn, why string) {
	p.mu.Lock()
	p.refused = why
	p.mu.Unlock()
	_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

func (p *egressProxy) handle(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReaderSize(c, 4096)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		p.refuse(c, "only CONNECT is allowed")
		return
	}
	host, portStr, err := net.SplitHostPort(req.Host)
	port, perr := strconv.Atoi(portStr)
	if err != nil || perr != nil {
		p.refuse(c, "bad CONNECT target")
		return
	}
	var rule *hostRule
	for i := range p.rules {
		if p.rules[i].matches(host, port) {
			rule = &p.rules[i]
			break
		}
	}
	if rule == nil {
		p.refuse(c, fmt.Sprintf("%s:%d isn't this destination's address", host, port))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		addrs, err = p.resolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(addrs) == 0 {
			p.refuse(c, fmt.Sprintf("can't find %s", host))
			return
		}
	}
	var target netip.Addr
	var why error
	for _, a := range addrs {
		err := AddrAllowed(a, rule.allowLAN)
		if err != nil && p.testAllow != nil && p.testAllow(a) {
			err = nil
		}
		if err == nil {
			target = a
			break
		}
		why = err
	}
	if !target.IsValid() {
		p.refuse(c, why.Error())
		return
	}
	up, err := p.dialer.DialContext(ctx, "tcp", netip.AddrPortFrom(target, uint16(port)).String())
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	if !p.track(up) {
		up.Close()
		return
	}
	defer p.untrack(up)
	_ = c.SetReadDeadline(time.Time{})
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		// Anything restic sent after the request is already in br.
		_, _ = io.Copy(up, br)
		if tc, ok := up.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(c, up)
		done <- struct{}{}
	}()
	<-done
}

// CheckEndpoint resolves an S3 endpoint and checks every address now (for
// a clear error when a destination is saved; the proxy checks again at
// every connection).
func CheckEndpoint(ctx context.Context, t *Target, r Resolver, testAllow func(netip.Addr) bool) error {
	if t.Kind != KindS3 {
		return nil
	}
	host, _, err := ParseEndpoint(t.Endpoint)
	if err != nil {
		return err
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		addrs, err = r.LookupNetIP(ctx, "ip", host)
		if err != nil || len(addrs) == 0 {
			return problemf("can't find %s: check the endpoint", host)
		}
	}
	for _, a := range addrs {
		if err := AddrAllowed(a, t.AllowLAN); err != nil && (testAllow == nil || !testAllow(a)) {
			return &Problem{Msg: err.Error()}
		}
	}
	return nil
}

var netResolver = net.DefaultResolver
