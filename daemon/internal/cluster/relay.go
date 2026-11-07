package cluster

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Relays (decision 324, 331): the entry node forwards a person's request to
// another member over ALPNRelay (HTTP/1.1, so WebSocket upgrades work),
// with an assertion bound to the method, path, query and body. The target
// checks the mTLS peer, the assertion and authorizes the person itself.

// MaxRelayBody is the largest request body forwarded; bodies above
// relayMemBody are spooled to a temporary file to be hashed.
const (
	MaxRelayBody = 4 << 30
	relayMemBody = 8 << 20
)

var nonces = &NonceCache{}

type relayState struct {
	once sync.Once
	tr   *http.Transport
}

func (n *Core) relayTransport() *http.Transport {
	n.relay.once.Do(func() {
		n.relay.tr = &http.Transport{
			DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					host = addr
				}
				c, _, err := n.trn().DialNode(ctx, NodeID(host), ALPNRelay)
				return c, err
			},
			ForceAttemptHTTP2:     false,
			MaxIdleConnsPerHost:   8,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 5 * time.Minute,
			DisableCompression:    true,
		}
	})
	return n.relay.tr
}

// SpooledBody holds a request body read once, for hashing and resending.
type SpooledBody struct {
	mem      []byte
	file     *os.File
	Sum      []byte
	Size     int64
	reserved int64
	sp       *Spooler
	once     sync.Once
}

// Spooler spools relayed bodies larger than relayMemBody to files in Dir
// (hardyd's own disk-backed folder, not a tmpfs), at most Quota bytes at
// a time across every relayed request (decision 371).
type Spooler struct {
	Dir   string
	Quota int64

	mu   sync.Mutex
	used int64
}

// DefaultSpoolQuota is the most a node spools at once.
const DefaultSpoolQuota = 8 << 30

// ErrSpoolFull: other relayed uploads use the spool's room now.
var ErrSpoolFull = errors.New("this server is busy forwarding other uploads; try again later")

var defaultSpooler = &Spooler{}

func (s *Spooler) reserve(n int64) bool {
	q := s.Quota
	if q <= 0 {
		q = DefaultSpoolQuota
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used+n > q {
		return false
	}
	s.used += n
	return true
}

func (s *Spooler) release(n int64) {
	s.mu.Lock()
	s.used -= n
	s.mu.Unlock()
}

// Used is how many bytes are spooled now.
func (s *Spooler) Used() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.used
}

// quotaWriter reserves room in the spooler before it writes.
type quotaWriter struct {
	w  io.Writer
	sb *SpooledBody
}

func (q *quotaWriter) Write(p []byte) (int, error) {
	if !q.sb.sp.reserve(int64(len(p))) {
		return 0, ErrSpoolFull
	}
	q.sb.reserved += int64(len(p))
	return q.w.Write(p)
}

// Spool reads a body (at most max bytes) into memory or a temporary file
// in the default place and hashes it.
func Spool(r io.Reader, max int64) (*SpooledBody, error) { return defaultSpooler.Spool(r, max) }

// Spool reads a body (at most max bytes) into memory or a file in Dir and
// hashes it.
func (s *Spooler) Spool(r io.Reader, max int64) (*SpooledBody, error) {
	h := sha256.New()
	sb := &SpooledBody{sp: s}
	if r == nil {
		sb.Sum = h.Sum(nil)
		return sb, nil
	}
	var buf bytes.Buffer
	n, err := io.Copy(io.MultiWriter(&buf, h), io.LimitReader(r, relayMemBody+1))
	if err != nil {
		return nil, err
	}
	if n <= relayMemBody {
		sb.mem, sb.Size, sb.Sum = buf.Bytes(), n, h.Sum(nil)
		return sb, nil
	}
	dir := s.Dir
	if dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	f, err := os.CreateTemp(dir, "hardyos-relay-*")
	if err != nil {
		return nil, err
	}
	_ = os.Remove(f.Name())
	sb.file = f
	qw := &quotaWriter{w: f, sb: sb}
	if _, err := qw.Write(buf.Bytes()); err != nil {
		sb.Close()
		return nil, err
	}
	m, err := io.Copy(io.MultiWriter(qw, h), io.LimitReader(r, max-n+1))
	if err != nil {
		sb.Close()
		return nil, err
	}
	if n+m > max {
		sb.Close()
		return nil, errors.New("the request body is too large to forward")
	}
	sb.Size, sb.Sum = n+m, h.Sum(nil)
	return sb, nil
}

// Reader rereads the body from the start.
func (s *SpooledBody) Reader() io.ReadCloser {
	if s.file != nil {
		_, _ = s.file.Seek(0, io.SeekStart)
		return io.NopCloser(s.file)
	}
	return io.NopCloser(bytes.NewReader(s.mem))
}

// Close frees a spooled file and its room in the spooler.
func (s *SpooledBody) Close() {
	s.once.Do(func() {
		if s.file != nil {
			s.file.Close()
		}
		if s.reserved > 0 && s.sp != nil {
			s.sp.release(s.reserved)
		}
	})
}

// Forward is one request to forward.
type Forward struct {
	Node      NodeID
	Principal Principal
	// SessionHash is the SHA-256 (hex) of the entry node's session id.
	SessionHash string
	// Path and RawQuery are the target's (for the API: /api/v1/<rest>).
	Method, Path, RawQuery string
	Header                 http.Header
	Body                   io.Reader
	// Host is the Host the browser sent to the entry node and Proto how
	// it reached it ("https" or "http"), signed into the assertion; the
	// target serves the request with them.
	Host, Proto string
}

// relayHeaders that never cross to another member.
var dropHeaders = []string{"Cookie", "Authorization", "Origin", "Referer", "X-Forwarded-For", "X-Real-Ip",
	"Forwarded", AssertionHeader, "Proxy-Authorization", "Te", "Trailer", "Keep-Alive", "Proxy-Connection"}

// AssertFor signs an assertion for a forwarded request.
func (n *Core) AssertFor(f *Forward, bodySum []byte) (string, error) {
	info := n.Info()
	if info == nil {
		return "", ErrNotMember
	}
	now := time.Now()
	return SignAssertion(n.cfg.Identity, Assertion{Issuer: info.Node, Audience: f.Node, Subject: f.Principal,
		Session: f.SessionHash, IssuedAt: now.Unix(), ExpiresAt: now.Add(AssertionTTL).Unix(), Nonce: NewNonce(),
		Request: RequestHashDigest(f.Method, f.Path, f.RawQuery, bodySum), Host: f.Host, Proto: f.Proto})
}

// spooler is where this node spools relayed bodies.
func (n *Core) spooler() *Spooler {
	n.spoolOnce.Do(func() {
		n.spool = &Spooler{Dir: n.cfg.SpoolDir, Quota: n.cfg.SpoolQuota}
	})
	return n.spool
}

// ValidHost checks the browser's Host as an assertion carries it: a host
// name or address with an optional port, nothing else.
func ValidHost(h string) bool {
	if h == "" || len(h) > 255 {
		return false
	}
	host := h
	if hh, port, err := net.SplitHostPort(h); err == nil {
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return false
		}
		host = hh
	}
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return a.IsValid()
	}
	for _, c := range host {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	return host != "" && !strings.HasPrefix(host, ".") && !strings.HasPrefix(host, "-")
}

// RelayRequest builds the request to send to the target (without its
// Upgrade handling): cookies and credentials stripped, the assertion
// added. The caller closes the returned body.
func (n *Core) RelayRequest(ctx context.Context, f *Forward) (*http.Request, *SpooledBody, error) {
	if _, ok := n.Member(f.Node); !ok {
		return nil, nil, fmt.Errorf("%s: %w", f.Node, ErrNotMember)
	}
	sb, err := n.spooler().Spool(f.Body, MaxRelayBody)
	if err != nil {
		return nil, nil, err
	}
	jws, err := n.AssertFor(f, sb.Sum)
	if err != nil {
		sb.Close()
		return nil, nil, err
	}
	u := "https://" + string(f.Node) + f.Path
	if f.RawQuery != "" {
		u += "?" + f.RawQuery
	}
	var body io.ReadCloser = http.NoBody
	if sb.Size > 0 {
		body = sb.Reader()
	}
	req, err := http.NewRequestWithContext(ctx, f.Method, u, body)
	if err != nil {
		sb.Close()
		return nil, nil, err
	}
	for k, v := range f.Header {
		req.Header[k] = append([]string(nil), v...)
	}
	for _, h := range dropHeaders {
		req.Header.Del(h)
	}
	req.ContentLength = sb.Size
	req.Header.Set(AssertionHeader, jws)
	req.Header.Set("X-HardyOS-Request", "1")
	return req, sb, nil
}

// RoundTripRelay sends a request built by RelayRequest.
func (n *Core) RoundTripRelay(req *http.Request) (*http.Response, error) {
	resp, err := n.relayTransport().RoundTrip(req)
	if err != nil {
		return nil, unreachable(NodeID(req.URL.Hostname()), err)
	}
	return resp, nil
}

// DialRelay opens a raw relay connection to a member (WebSocket upgrades).
func (n *Core) DialRelay(ctx context.Context, node NodeID) (net.Conn, error) {
	c, _, err := n.trn().DialNode(ctx, node, ALPNRelay)
	if err != nil {
		return nil, unreachable(node, err)
	}
	return c, nil
}

// ---- the target side ---------------------------------------------------------

// Relayed is a verified relayed request.
type Relayed struct {
	From      Node
	Assertion *Assertion
}

// ErrRelayDenied is a relayed request that failed its checks.
var ErrRelayDenied = errors.New("relayed request refused")

// VerifyRelay checks a request that arrived on ALPNRelay: the mTLS peer is
// a current, unfenced HardyOS member, the assertion is its, for this
// node, fresh, unseen and bound to this very request. The body is
// replaced by a rereadable copy.
func (n *Core) VerifyRelay(r *http.Request) (*Relayed, func(), error) {
	noop := func() {}
	cs := RelayTLS(r)
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return nil, noop, fmt.Errorf("%w: no client certificate", ErrRelayDenied)
	}
	from, ok := n.ByPin(PinOfCert(cs.PeerCertificates[0]))
	if !ok || isFenced(from) || from.Role == RoleWitness {
		return nil, noop, fmt.Errorf("%w: not a member that may forward", ErrRelayDenied)
	}
	jws := r.Header.Get(AssertionHeader)
	if jws == "" {
		return nil, noop, fmt.Errorf("%w: no assertion", ErrRelayDenied)
	}
	sb, err := n.spooler().Spool(r.Body, MaxRelayBody)
	if err != nil {
		return nil, noop, fmt.Errorf("%w: %v", ErrRelayDenied, err)
	}
	a, err := VerifyAssertion(jws, AssertionCheck{Issuer: from.ID, IssuerKey: from.PublicKey, Audience: n.ID(),
		Request: RequestHashDigest(r.Method, r.URL.Path, r.URL.RawQuery, sb.Sum), Now: time.Now(), Nonces: nonces})
	if err != nil {
		sb.Close()
		return nil, noop, fmt.Errorf("%w: %v", ErrRelayDenied, err)
	}
	r.Body = sb.Reader()
	r.ContentLength = sb.Size
	r.Header.Del(AssertionHeader)
	// The browser's own Host (signed): links, origins and app windows on
	// this node see the address the person uses, not the node id.
	if a.Proto != "" && a.Proto != "https" && a.Proto != "http" {
		sb.Close()
		return nil, noop, fmt.Errorf("%w: bad scheme", ErrRelayDenied)
	}
	if a.Host != "" {
		if !ValidHost(a.Host) {

			sb.Close()
			return nil, noop, fmt.Errorf("%w: bad host", ErrRelayDenied)
		}
		r.Host = a.Host
	}
	return &Relayed{From: from, Assertion: a}, sb.Close, nil
}

// TLSPeer is a convenience for tests: whether a relay connection's peer is
// a member.
func (n *Core) TLSPeer(cs *tls.ConnectionState) (Node, bool) {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return Node{}, false
	}
	return n.ByPin(PinOfCert(cs.PeerCertificates[0]))
}

// IsUpgrade reports whether a request asks for a protocol switch.
func IsUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}
