package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

// The peer API (ALPNPeer, HTTP/2, PeerPathPrefix): every request is
// authenticated by the TLS client key's pin and authorized by the caller's
// role. Handlers registered with Handle see only current, unfenced HardyOS
// members (never the witness); AllowFenced adds fenced members; part A's
// own endpoints say per path whether the witness may call them. The join
// endpoint is the only one open to keys that aren't members.

type callerKey struct{}

// peerMux implements PeerMux.
type peerMux struct {
	mux  *http.ServeMux
	book PeerBook
}

func newPeerMux(book PeerBook) *peerMux {
	m := &peerMux{mux: http.NewServeMux(), book: book}
	m.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		peerError(w, http.StatusNotFound, "no such cluster endpoint")
	})
	return m
}

// access says who may call a path.
type access struct {
	fenced  bool // dead or fenced members too
	witness bool // the witness too
	public  bool // keys that aren't members (join only)
}

func (m *peerMux) handle(pattern string, a access, h http.Handler) {
	m.mux.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var pin string
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			pin = PinOfCert(r.TLS.PeerCertificates[0])
		}
		n, ok := m.book.ByPin(pin)
		switch {
		case pin == "":
			peerError(w, http.StatusUnauthorized, "a client certificate is required")
			return
		case !ok && !a.public:
			peerError(w, http.StatusForbidden, "this server isn't a member of the cluster")
			return
		case ok && isFenced(n) && !a.fenced:
			peerError(w, http.StatusForbidden, "this server is fenced: it may only rejoin")
			return
		case ok && n.Role == RoleWitness && !a.witness:
			peerError(w, http.StatusForbidden, "the witness may not call this")
			return
		}
		if ok {
			r = r.WithContext(context.WithValue(r.Context(), callerKey{}, n))
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<20)
		h.ServeHTTP(w, r)
	}))
}

// Handle registers a handler for unfenced HardyOS members.
func (m *peerMux) Handle(pattern string, h http.Handler) {
	m.handle(withPrefix(pattern), access{}, h)
}

// AllowFenced registers a handler fenced members may call too.
func (m *peerMux) AllowFenced(pattern string, h http.Handler) {
	m.handle(withPrefix(pattern), access{fenced: true}, h)
}

// Caller is the member that sent r.
func (m *peerMux) Caller(r *http.Request) (Node, bool) {
	n, ok := r.Context().Value(callerKey{}).(Node)
	return n, ok
}

func (m *peerMux) ServeHTTP(w http.ResponseWriter, r *http.Request) { m.mux.ServeHTTP(w, r) }

// withPrefix accepts "POST /storage/x" or "POST /cluster/v1/storage/x".
func withPrefix(pattern string) string {
	method, path, ok := strings.Cut(pattern, " ")
	if !ok {
		path, method = pattern, ""
	}
	if !strings.HasPrefix(path, PeerPathPrefix) {
		path = PeerPathPrefix + strings.TrimPrefix(path, "/")
	}
	if method == "" {
		return path
	}
	return method + " " + path
}

func peerJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type wireError struct {
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

func peerError(w http.ResponseWriter, status int, msg string) {
	peerJSON(w, status, wireError{Message: msg})
}

func peerErrorCode(w http.ResponseWriter, status int, code, msg string) {
	peerJSON(w, status, wireError{Message: msg, Code: code})
}

func decodePeer(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 8<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// ---- the client -------------------------------------------------------------

// peerClient implements PeerClient over HTTP/2 on ALPNPeer.
type peerClient struct {
	t  *Transport
	h2 *http2.Transport
}

func newPeerClient(t *Transport) *peerClient {
	c := &peerClient{t: t}
	c.h2 = &http2.Transport{
		DialTLSContext: func(ctx context.Context, _, addr string, _ *tls.Config) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			conn, _, err := t.DialNode(ctx, NodeID(host), ALPNPeer)
			return conn, err
		},
		ReadIdleTimeout: 5 * time.Second,
		PingTimeout:     3 * time.Second,
	}
	return c
}

// Call implements PeerClient.
func (c *peerClient) Call(ctx context.Context, node NodeID, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	r, err := http.NewRequestWithContext(ctx, method, "https://"+string(node)+withPrefix(path), body)
	if err != nil {
		return err
	}
	if in != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(ctx, node, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var we wireError
		_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&we)
		if we.Message == "" {
			we.Message = fmt.Sprintf("answered %d", resp.StatusCode)
		}
		return &PeerError{Node: node, Status: resp.StatusCode, Message: we.Message}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out)
}

// Do implements PeerClient.
func (c *peerClient) Do(ctx context.Context, node NodeID, r *http.Request) (*http.Response, error) {
	if _, ok := c.t.Book.Member(node); !ok {
		return nil, fmt.Errorf("%s: %w", node, ErrNotMember)
	}
	r = r.Clone(ctx)
	r.URL.Scheme, r.URL.Host, r.Host = "https", string(node), string(node)
	if !strings.HasPrefix(r.URL.Path, PeerPathPrefix) {
		r.URL.Path = withPrefix(r.URL.Path)
	}
	resp, err := c.h2.RoundTrip(r)
	if err != nil {
		return nil, unreachable(node, err)
	}
	return resp, nil
}

// ErrUnreachable: no path to the member answered.
var ErrUnreachable = errors.New("can't reach the server")

func unreachable(node NodeID, err error) error {
	return fmt.Errorf("%w %s: %v", ErrUnreachable, node, err)
}

func (c *peerClient) close() { c.h2.CloseIdleConnections() }
