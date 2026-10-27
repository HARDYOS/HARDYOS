package replication

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/replica"
)

// peer talks to a receiving server: mutual TLS, its key pinned.
type peer struct {
	base string
	hc   *http.Client
}

// RemoteError is an error the other server answered with.
type RemoteError struct {
	Status  int
	Code    string
	Message string
}

func (e *RemoteError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("the other server answered %d", e.Status)
	}
	return "the other server: " + e.Message
}

// pinCheck accepts exactly the pinned key (or records it while pairing).
func pinCheck(pin string, seen *string) func(cs tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("the other server sent no certificate")
		}
		got := PinOf(cs.PeerCertificates[0])
		if seen != nil {
			*seen = got
			return nil
		}
		if !hmac.Equal([]byte(got), []byte(pin)) {
			return fmt.Errorf("the other server's key changed (expected %s…, got %s…): pair the servers again if that's expected", short(pin), short(got))
		}
		return nil
	}
}

func short(pin string) string {
	if len(pin) > 12 {
		return pin[:12]
	}
	return pin
}

func newTransport(id *Identity, verify func(tls.ConnectionState) error) *http.Transport {
	d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		DialContext: d.DialContext,
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{id.Cert},
			// The chain isn't checked against any authority: the key is
			// pinned instead (VerifyConnection).
			InsecureSkipVerify: true, //nolint:gosec // pinned key, see VerifyConnection
			VerifyConnection:   verify,
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{"http/1.1"},
		},
		TLSHandshakeTimeout: 15 * time.Second,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}
}

func (s *Service) peer(ctx context.Context, t *Target) (*peer, error) {
	if t.Pin == "" {
		return nil, fmt.Errorf("this server's record of %s can't be read (restored from another server?): pair again", t.Name)
	}
	id, err := s.Identity(ctx)
	if err != nil {
		return nil, err
	}
	return &peer{base: "https://" + t.Address, hc: newClient(newTransport(id, pinCheck(t.Pin, nil)), 0)}, nil
}

// newClient never follows redirects: another server's answer can't send
// this one anywhere else (a 3xx is an error).
func newClient(tr *http.Transport, timeout time.Duration) *http.Client {
	return &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// Time limits on requests to another server: ordinary calls end after
// PeerTimeout (browsing, which mounts a snapshot there, after
// PeerBrowseTimeout); streams after PeerIdle without a byte moving, and
// PeerFinish after the last byte for the other side's answer.
var (
	PeerTimeout       = 2 * time.Minute
	PeerBrowseTimeout = 3 * time.Minute
	PeerIdle          = 5 * time.Minute
	PeerFinish        = 31 * time.Minute
)

// watchdog cancels a stream's context when nothing moved for idle, or,
// once finished, after the finish allowance.
type watchdog struct {
	last   atomic.Int64 // unix nanoseconds of the last progress
	done   atomic.Int64 // when the body finished (0: not yet)
	cancel context.CancelFunc
	stop   chan struct{}
}

func newWatchdog(parent context.Context, idle, finish time.Duration) (context.Context, *watchdog) {
	ctx, cancel := context.WithCancel(parent)
	w := &watchdog{cancel: cancel, stop: make(chan struct{})}
	w.touch()
	tick := min(idle/4, time.Second)
	go func() {
		t := time.NewTicker(tick)
		defer t.Stop()
		for {
			select {
			case <-w.stop:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				now := time.Now().UnixNano()
				if d := w.done.Load(); d != 0 {
					if now-d > int64(finish) {
						cancel()
						return
					}
				} else if now-w.last.Load() > int64(idle) {
					cancel()
					return
				}
			}
		}
	}()
	return ctx, w
}

func (w *watchdog) touch()  { w.last.Store(time.Now().UnixNano()) }
func (w *watchdog) finish() { w.done.CompareAndSwap(0, time.Now().UnixNano()) }
func (w *watchdog) close() {
	select {
	case <-w.stop:
	default:
		close(w.stop)
	}
	w.cancel()
}

// watched reports progress to a watchdog.
type watched struct {
	r io.Reader
	w *watchdog
}

func (x watched) Read(p []byte) (int, error) {
	n, err := x.r.Read(p)
	if n > 0 {
		x.w.touch()
	}
	if err == io.EOF {
		x.w.finish()
	}
	return n, err
}

func (p *peer) close() { p.hc.CloseIdleConnections() }

func (p *peer) url(path string, q url.Values) string {
	u := p.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return u
}

func decodeReply(resp *http.Response, out any) error {
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var we wireError
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = json.Unmarshal(b, &we)
		return &RemoteError{Status: resp.StatusCode, Code: we.Code, Message: we.Message}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
}

func (p *peer) do(ctx context.Context, method, path string, q url.Values, body any, out any) error {
	limit := PeerTimeout
	if path == "/repl/v1/browse" {
		limit = PeerBrowseTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.url(path, q), rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.hc.Do(req)
	if err != nil {
		return reachErr(err)
	}
	return decodeReply(resp, out)
}

// reachErr explains a failed connection.
func reachErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		err = ue.Err
	}
	if errors.Is(err, context.Canceled) {
		return err
	}
	return fmt.Errorf("can't reach the other server: %w", err)
}

func itemQuery(kind, id, child string) url.Values {
	q := url.Values{"kind": {kind}, "id": {id}}
	if child != "" {
		q.Set("child", child)
	}
	return q
}

func (p *peer) hello(ctx context.Context) (*helloResponse, error) {
	var r helloResponse
	return &r, p.do(ctx, http.MethodGet, "/repl/v1/hello", nil, nil, &r)
}

func (p *peer) putItems(ctx context.Context, items []itemNote) error {
	return p.do(ctx, http.MethodPut, "/repl/v1/items", nil, map[string]any{"items": items}, nil)
}

func (p *peer) items(ctx context.Context) ([]RemoteItem, error) {
	var r struct {
		Items []RemoteItem `json:"items"`
	}
	err := p.do(ctx, http.MethodGet, "/repl/v1/items", nil, nil, &r)
	return r.Items, err
}

func (p *peer) state(ctx context.Context, kind, id, child string) (*replica.RecvState, error) {
	var r replica.RecvState
	return &r, p.do(ctx, http.MethodGet, "/repl/v1/state", itemQuery(kind, id, child), nil, &r)
}

func (p *peer) abort(ctx context.Context, kind, id, child string) error {
	return p.do(ctx, http.MethodPost, "/repl/v1/abort", itemQuery(kind, id, child), nil, nil)
}

func (p *peer) prune(ctx context.Context, task, kind, id string, keep int) (*replica.PruneResult, error) {
	q := itemQuery(kind, id, "")
	q.Set("task", task)
	q.Set("keep", strconv.Itoa(keep))
	var r replica.PruneResult
	return &r, p.do(ctx, http.MethodPost, "/repl/v1/prune", q, nil, &r)
}

func (p *peer) snapshots(ctx context.Context, kind, id string) ([]replica.SnapInfo, error) {
	var r struct {
		Snapshots []replica.SnapInfo `json:"snapshots"`
	}
	err := p.do(ctx, http.MethodGet, "/repl/v1/snapshots", itemQuery(kind, id, ""), nil, &r)
	return r.Snapshots, err
}

func (p *peer) children(ctx context.Context, kind, id, snapshot string) ([]replica.Child, error) {
	q := itemQuery(kind, id, "")
	q.Set("snapshot", snapshot)
	var r struct {
		Children []replica.Child `json:"children"`
	}
	err := p.do(ctx, http.MethodGet, "/repl/v1/children", q, nil, &r)
	return r.Children, err
}

func (p *peer) browse(ctx context.Context, kind, id, child, snapshot, path string) (*replica.BrowseResult, error) {
	q := itemQuery(kind, id, child)
	q.Set("snapshot", snapshot)
	q.Set("path", path)
	var r replica.BrowseResult
	return &r, p.do(ctx, http.MethodGet, "/repl/v1/browse", q, nil, &r)
}

// stream uploads a zfs stream; the answer comes once the other server's
// zfs receive has finished.
func (p *peer) stream(ctx context.Context, task, kind, id, child, snapshot string, body io.Reader) (*StreamResult, error) {
	q := itemQuery(kind, id, child)
	q.Set("task", task)
	q.Set("snapshot", snapshot)
	ctx, wd := newWatchdog(ctx, PeerIdle, PeerFinish)
	defer wd.close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, p.url("/repl/v1/stream", q), watched{r: body, w: wd})
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = -1
	resp, err := p.hc.Do(req)
	if err != nil {
		return nil, reachErr(err)
	}
	var r StreamResult
	return &r, decodeReply(resp, &r)
}

// send downloads a replica's snapshot as a zfs stream. The body is
// watched: no byte for PeerIdle ends it.
func (p *peer) send(ctx context.Context, kind, id, child, snapshot string) (*http.Response, error) {
	q := itemQuery(kind, id, child)
	q.Set("snapshot", snapshot)
	ctx, wd := newWatchdog(ctx, PeerIdle, PeerFinish)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url("/repl/v1/send", q), nil)
	if err != nil {
		wd.close()
		return nil, err
	}
	resp, err := p.hc.Do(req)
	if err != nil {
		wd.close()
		return nil, reachErr(err)
	}
	if resp.StatusCode != http.StatusOK {
		defer wd.close()
		return nil, decodeReply(resp, nil)
	}
	resp.Body = watchedBody{watched: watched{r: resp.Body, w: wd}, c: resp.Body}
	return resp, nil
}

type watchedBody struct {
	watched
	c io.Closer
}

func (b watchedBody) Close() error {
	b.w.close()
	return b.c.Close()
}

// Pair connects to a receiving server with a pairing code it showed, and
// records it as a target: both servers prove they know the code over
// both keys, then each pins the other's.
func (s *Service) Pair(ctx context.Context, address, code string) (*Target, error) {
	s.init()
	addr, err := CleanAddress(address)
	if err != nil {
		return nil, err
	}
	raw, err := ParseCode(code)
	if err != nil {
		return nil, err
	}
	id, err := s.Identity(ctx)
	if err != nil {
		return nil, err
	}
	var seen string
	tr := newTransport(id, pinCheck("", &seen))
	tr.DisableKeepAlives = true
	hc := newClient(tr, time.Minute)
	defer hc.CloseIdleConnections()
	// The receiver's key is learned on the TLS connection and bound into
	// the proof; the proof itself is sent on that same connection.
	if _, err := hc.Get("https://" + addr + "/repl/v1/none"); err != nil {
		return nil, reachErr(err)
	}
	receiverPin := seen
	if receiverPin == "" {
		return nil, errors.New("the other server sent no certificate")
	}
	body, _ := json.Marshal(pairRequest{Proof: hex.EncodeToString(sourceProof(raw, id.Pin, receiverPin)), Name: s.hostname()})
	tr2 := newTransport(id, pinCheck(receiverPin, nil))
	tr2.DisableKeepAlives = true
	hc2 := newClient(tr2, time.Minute)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addr+"/repl/v1/pair", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc2.Do(req)
	if err != nil {
		return nil, reachErr(err)
	}
	var pr pairResponse
	if err := decodeReply(resp, &pr); err != nil {
		return nil, err
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 || PinOf(resp.TLS.PeerCertificates[0]) != receiverPin {
		return nil, errors.New("the other server's key changed during pairing")
	}
	proof, err := hex.DecodeString(pr.Proof)
	if err != nil || !hmac.Equal(proof, receiverProof(raw, id.Pin, receiverPin, pr.SourceID)) {
		return nil, errors.New("the other server couldn't prove it made that pairing code: check the address and code")
	}
	if err := replica.ValidSource(pr.SourceID); err != nil {
		return nil, err
	}
	name := cleanLabel(pr.Name, 60)
	if name == "" {
		name = addr
	}
	// Pairing the same server again replaces the old record's key.
	tl, err := s.st.Targets(ctx)
	if err != nil {
		return nil, err
	}
	for _, t := range tl {
		if t.SourceID == pr.SourceID && t.Pin == receiverPin {
			if err := s.st.UpdateTargetAddress(ctx, t.ID, addr); err != nil {
				return nil, err
			}
			return s.st.Target(ctx, t.ID)
		}
	}
	t := &Target{Name: name, Address: addr, SourceID: pr.SourceID, Pin: receiverPin}
	if err := s.st.AddTarget(ctx, t); err != nil {
		return nil, err
	}
	s.log().Info("replication: paired with a receiving server", "target", t.ID, "name", name, "address", addr)
	return t, nil
}

// TestTarget checks that a target answers and still knows this server.
func (s *Service) TestTarget(ctx context.Context, targetID string) (string, error) {
	s.init()
	t, err := s.st.Target(ctx, targetID)
	if err != nil {
		return "", err
	}
	p, err := s.peer(ctx, t)
	if err != nil {
		return "", err
	}
	defer p.close()
	h, err := p.hello(ctx)
	if err != nil {
		return "", err
	}
	if h.SourceID != t.SourceID {
		return "", fmt.Errorf("%s knows this server under another id: pair again", t.Name)
	}
	return h.Name, nil
}
