package replication

import (
	"context"
	"crypto/hmac"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/replica"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// The receiving side: an HTTPS server on its own port, for other HardyOS
// servers only. Every connection must present a client certificate; a
// request is served only when that certificate's key is a paired
// source's (POST /repl/v1/pair, with the right pairing code, is the only
// way to become one). Sources can add to their own replicas and read
// them back; they can't delete them or reach anything else.

// OpenPairing stores a pairing code for another server to use. The new
// source's rules start as DefaultRules with p's pool, quota (required),
// minimum kept snapshots and minimum age.
func (s *Service) OpenPairing(ctx context.Context, code []byte, p PairingParams) (*Pairing, error) {
	s.init()
	if err := replica.ValidPool(p.Pool); err != nil {
		return nil, errors.New("choose the pool that keeps the replicas")
	}
	r := DefaultRules
	r.QuotaBytes = p.QuotaBytes
	if p.MinKeep != 0 {
		r.MinKeep = p.MinKeep
	}
	if p.MinAgeDays != nil {
		r.MinAgeDays = *p.MinAgeDays
	}
	if err := r.Check(); err != nil {
		return nil, err
	}
	pr := Pairing{Pool: p.Pool, QuotaBytes: r.QuotaBytes, MinKeep: r.MinKeep, MinAgeDays: r.MinAgeDays, ExpiresAt: s.now().Add(PairingTTL)}
	if _, err := s.Identity(ctx); err != nil {
		return nil, err
	}
	if err := s.st.SetPairing(ctx, code, pr); err != nil {
		return nil, err
	}
	s.pairFails.reset()
	return &pr, nil
}

// Receiving reports whether other servers can send here (a pairing code
// is open or a source is paired), so the port is open.
func (s *Service) Receiving(ctx context.Context) bool {
	s.init()
	if p, err := s.st.Pairing(ctx, s.now()); err == nil && p != nil {
		return true
	}
	l, err := s.st.pinned(ctx)
	return err == nil && len(l) > 0
}

// listenAddrs are where the receiving server listens: ListenAddr when
// set, else the port on each of this server's own LAN and NetBird
// addresses (never Docker's, libvirt's or the domain controller's
// interfaces).
func (s *Service) listenAddrs() []string {
	if s.ListenAddr != "" {
		return []string{s.ListenAddr}
	}
	var out []string
	for _, a := range LocalAddresses() {
		out = append(out, net.JoinHostPort(a.Address, strconv.Itoa(DefaultPort)))
	}
	sort.Strings(out)
	return out
}

// serveWhileReceiving runs the receiving server while Receiving is true,
// on the current addresses (rechecked every 15 s).
func (s *Service) serveWhileReceiving(ctx context.Context) {
	var srv *http.Server
	var on []string
	stop := func() {
		if srv != nil {
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(sctx)
			cancel()
			srv, on = nil, nil
		}
	}
	defer stop()
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		want := s.Receiving(ctx)
		addrs := s.listenAddrs()
		if srv != nil && (!want || strings.Join(addrs, ",") != strings.Join(on, ",")) {
			stop()
			s.log().Info("replication: stopped receiving")
		}
		if want && srv == nil && len(addrs) > 0 {
			id, err := s.Identity(ctx)
			if err != nil {
				s.log().Warn("replication: identity", "err", err)
			} else {
				srv = s.newServer(id)
				caps := newConnCaps(MaxConns, MaxConnsPerIP)
				for _, a := range addrs {
					ln, err := net.Listen("tcp", a)
					if err != nil {
						s.log().Warn("replication: listening for other servers", "addr", a, "err", err)
						continue
					}
					on = append(on, a)
					go func(ln net.Listener) {
						if err := srv.ServeTLS(caps.wrap(ln), "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
							s.log().Warn("replication: server", "err", err)
						}
					}(ln)
				}
				on = addrs // retried only when the addresses change
				s.log().Info("replication: receiving from other servers", "addrs", strings.Join(addrs, " "))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Connection limits on the receiving port.
const (
	MaxConns      = 64
	MaxConnsPerIP = 8
)

// connCaps bounds connections, in all and per client address.
type connCaps struct {
	mu    sync.Mutex
	all   int
	perIP map[string]int
	max   int
	maxIP int
}

func newConnCaps(max, maxIP int) *connCaps {
	return &connCaps{perIP: map[string]int{}, max: max, maxIP: maxIP}
}

func (c *connCaps) wrap(ln net.Listener) net.Listener { return &capListener{Listener: ln, c: c} }

type capListener struct {
	net.Listener
	c *connCaps
}

func (l *capListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		l.c.mu.Lock()
		ok := l.c.all < l.c.max && l.c.perIP[ip] < l.c.maxIP
		if ok {
			l.c.all++
			l.c.perIP[ip]++
		}
		l.c.mu.Unlock()
		if !ok {
			conn.Close()
			continue
		}
		return &capConn{Conn: conn, c: l.c, ip: ip}, nil
	}
}

type capConn struct {
	net.Conn
	c    *connCaps
	ip   string
	once sync.Once
}

func (c *capConn) Close() error {
	c.once.Do(func() {
		c.c.mu.Lock()
		c.c.all--
		if c.c.perIP[c.ip]--; c.c.perIP[c.ip] <= 0 {
			delete(c.c.perIP, c.ip)
		}
		c.c.mu.Unlock()
	})
	return c.Conn.Close()
}

func (s *Service) newServer(id *Identity) *http.Server {
	return &http.Server{
		Handler: s.Handler(),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{id.Cert},
			ClientAuth:   tls.RequireAnyClientCert, // checked against pins per request
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{"http/1.1"},
		},
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
}

// Per-request time limits: the whole request for ordinary calls; for
// streams, the time without progress.
const (
	RequestTimeout = time.Minute
	StreamIdle     = 2 * time.Minute
	BrowseTimeout  = 2 * time.Minute
)

// Handler serves the receiving side (exported for tests).
func (s *Service) Handler() http.Handler {
	s.init()
	m := http.NewServeMux()
	m.Handle("POST /repl/v1/pair", withDeadline(RequestTimeout, http.HandlerFunc(s.handlePair)))
	m.Handle("GET /repl/v1/hello", withDeadline(RequestTimeout, s.source(s.handleHello)))
	m.Handle("PUT /repl/v1/items", withDeadline(RequestTimeout, s.source(s.handlePutItems)))
	m.Handle("GET /repl/v1/items", withDeadline(RequestTimeout, s.source(s.handleGetItems)))
	m.Handle("GET /repl/v1/state", withDeadline(RequestTimeout, s.source(s.handleState)))
	m.Handle("POST /repl/v1/abort", withDeadline(RequestTimeout, s.source(s.handleAbort)))
	m.Handle("PUT /repl/v1/stream", s.source(s.handleStream))
	m.Handle("POST /repl/v1/prune", withDeadline(RequestTimeout, s.source(s.handlePrune)))
	m.Handle("GET /repl/v1/snapshots", withDeadline(RequestTimeout, s.source(s.handleSnapshots)))
	m.Handle("GET /repl/v1/children", withDeadline(RequestTimeout, s.source(s.handleChildren)))
	m.Handle("GET /repl/v1/browse", withDeadline(BrowseTimeout, s.source(s.handleBrowse)))
	m.Handle("GET /repl/v1/send", s.source(s.handleSend))
	m.Handle("/", withDeadline(RequestTimeout, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		replyError(w, http.StatusNotFound, "not_found", "no such endpoint")
	})))
	return m
}

// withDeadline gives a request read and write deadlines and a context deadline.
func withDeadline(d time.Duration, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Now().Add(d))
		_ = rc.SetWriteDeadline(time.Now().Add(d))
		ctx, cancel := context.WithTimeout(r.Context(), d)
		defer cancel()
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// idleReader extends the connection's read deadline as data arrives.
type idleReader struct {
	r    io.Reader
	rc   *http.ResponseController
	idle time.Duration
}

func (i idleReader) Read(p []byte) (int, error) {
	_ = i.rc.SetReadDeadline(time.Now().Add(i.idle))
	return i.r.Read(p)
}

// idleWriter extends the connection's write deadline as data leaves.
type idleWriter struct {
	w    io.Writer
	rc   *http.ResponseController
	idle time.Duration
}

func (i idleWriter) Write(p []byte) (int, error) {
	_ = i.rc.SetWriteDeadline(time.Now().Add(i.idle))
	return i.w.Write(p)
}

// wireError is how one server tells another what went wrong.
type wireError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func replyJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func replyError(w http.ResponseWriter, status int, code, msg string) {
	replyJSON(w, status, wireError{Code: code, Message: msg})
}

// replyErr maps a root or store error.
func replyErr(w http.ResponseWriter, err error) {
	var pe *priv.Error
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, replica.ErrNotFound):
		replyError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, replica.ErrInvalid):
		replyError(w, http.StatusBadRequest, "invalid", err.Error())
	case errors.Is(err, replica.ErrBusy), errors.Is(err, replica.ErrTooMany):
		replyError(w, http.StatusConflict, "busy", err.Error())
	case errors.As(err, &pe):
		switch pe.Code {
		case priv.CodeNotFound:
			replyError(w, http.StatusNotFound, "not_found", pe.Message)
		case priv.CodeBadArgs:
			replyError(w, http.StatusBadRequest, "invalid", pe.Message)
		case priv.CodeBusy:
			replyError(w, http.StatusConflict, "busy", pe.Message)
		default:
			replyError(w, http.StatusInternalServerError, "failed", pe.Message)
		}
	default:
		replyError(w, http.StatusInternalServerError, "failed", err.Error())
	}
}

func peerPin(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return PinOf(r.TLS.PeerCertificates[0])
}

func remoteIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// source authenticates a paired source by its key.
func (s *Service) source(fn func(w http.ResponseWriter, r *http.Request, src *Source)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pin := peerPin(r)
		if pin == "" {
			replyError(w, http.StatusUnauthorized, "unauthorized", "a client certificate is required")
			return
		}
		l, err := s.st.pinned(r.Context())
		if err != nil {
			replyErr(w, err)
			return
		}
		for i := range l {
			if l[i].Pin != "" && subtle.ConstantTimeCompare([]byte(l[i].Pin), []byte(pin)) == 1 {
				src := l[i]
				s.st.touchSource(r.Context(), src.ID)
				fn(w, r, &src)
				return
			}
		}
		replyError(w, http.StatusForbidden, "not_paired", "this server isn't paired with the receiving server")
	})
}

// recordPeer audits what a source did here (actor: the source's name).
func (s *Service) recordPeer(ctx context.Context, r *http.Request, src *Source, action, target, detail string, outcome audit.Outcome) {
	if s.Audit == nil {
		return
	}
	e := audit.Entry{Action: action, Target: target, Outcome: outcome, Detail: detail, IP: remoteIP(r), Actor: "server:" + src.Name}
	if err := s.Audit.Record(context.WithoutCancel(ctx), e); err != nil {
		s.log().Warn("replication: audit", "err", err)
	}
}

// Pairing attempts: each address may fail MaxPairFailuresPerIP times per
// code, and the code closes after MaxPairFailures failures in all.
const MaxPairFailuresPerIP = 3

type failCounter struct {
	mu sync.Mutex
	m  map[string]int
}

func (f *failCounter) reset() {
	f.mu.Lock()
	f.m = nil
	f.mu.Unlock()
}

func (f *failCounter) blocked(ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.m[ip] >= MaxPairFailuresPerIP
}

func (f *failCounter) add(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.m == nil {
		f.m = map[string]int{}
	}
	f.m[ip]++
}

type pairRequest struct {
	Proof string `json:"proof"`
	Name  string `json:"name"`
}

type pairResponse struct {
	SourceID string `json:"sourceId"`
	Name     string `json:"name"`
	Proof    string `json:"proof"`
}

func (s *Service) handlePair(w http.ResponseWriter, r *http.Request) {
	pin := peerPin(r)
	if pin == "" {
		replyError(w, http.StatusUnauthorized, "unauthorized", "a client certificate is required")
		return
	}
	var req pairRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		replyError(w, http.StatusBadRequest, "invalid", "invalid request")
		return
	}
	proof, err := hex.DecodeString(req.Proof)
	if err != nil || len(proof) != 32 {
		replyError(w, http.StatusBadRequest, "invalid", "invalid proof")
		return
	}
	ip := remoteIP(r)
	s.pairMu.Lock()
	defer s.pairMu.Unlock()
	ctx := r.Context()
	p, err := s.st.Pairing(ctx, s.now())
	if err != nil {
		replyErr(w, err)
		return
	}
	if p == nil {
		replyError(w, http.StatusForbidden, "no_code", "no pairing code is open on the receiving server: make one in its Control Panel › Replication")
		return
	}
	if s.pairFails.blocked(ip) {
		replyError(w, http.StatusTooManyRequests, "too_many", "too many wrong pairing codes from this address")
		return
	}
	id, err := s.Identity(ctx)
	if err != nil {
		replyErr(w, err)
		return
	}
	if !hmac.Equal(proof, sourceProof(p.code, pin, id.Pin)) {
		s.pairFails.add(ip)
		s.st.pairingFailed(ctx)
		s.record(ctx, "replication.pair", cleanLabel(req.Name, 60), "wrong pairing code", ip, audit.Denied)
		replyError(w, http.StatusForbidden, "wrong_code", "the pairing code doesn't match (or a connection in between changed it)")
		return
	}
	name := cleanLabel(req.Name, 60)
	if name == "" {
		name = ip
	}
	srcID := ""
	l, err := s.st.Sources(ctx)
	if err != nil {
		replyErr(w, err)
		return
	}
	for _, src := range l {
		if src.Pin == pin {
			srcID = src.ID // the same server pairing again keeps its replicas
		}
	}
	if srcID == "" {
		srcID = newID(8)
		rules := DefaultRules
		rules.QuotaBytes, rules.MinKeep, rules.MinAgeDays = p.QuotaBytes, p.MinKeep, p.MinAgeDays
		if err := s.st.AddSource(ctx, &Source{ID: srcID, Name: name, Pin: pin, Pool: p.Pool, SourceRules: rules}); err != nil {
			replyErr(w, err)
			return
		}
	}
	_ = s.st.ClearPairing(ctx)
	s.record(ctx, "replication.pair", name, "source "+srcID+" may send replicas to "+p.Pool, ip, audit.Success)
	s.log().Info("replication: paired with a source", "source", srcID, "name", name, "ip", ip)
	replyJSON(w, http.StatusOK, pairResponse{SourceID: srcID, Name: s.hostname(), Proof: hex.EncodeToString(receiverProof(p.code, pin, id.Pin, srcID))})
}

type helloResponse struct {
	Name     string `json:"name"`
	SourceID string `json:"sourceId"`
}

func (s *Service) handleHello(w http.ResponseWriter, r *http.Request, src *Source) {
	replyJSON(w, http.StatusOK, helloResponse{Name: s.hostname(), SourceID: src.ID})
}

// itemNote is what a source says about one of its items.
type itemNote struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Name string `json:"name"`
	Pool string `json:"pool"`
	Task string `json:"task"`
}

func (s *Service) handlePutItems(w http.ResponseWriter, r *http.Request, src *Source) {
	var req struct {
		Items []itemNote `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&req); err != nil || len(req.Items) > MaxItemsPerTask {
		replyError(w, http.StatusBadRequest, "invalid", "invalid request")
		return
	}
	for _, it := range req.Items {
		if (replica.Item{Kind: it.Kind, ID: it.ID}).Validate() != nil || (it.Pool != "" && replica.ValidPool(it.Pool) != nil) ||
			(it.Task != "" && replica.ValidTask(it.Task) != nil) {
			replyError(w, http.StatusBadRequest, "invalid", "invalid item")
			return
		}
		if err := s.st.putSourceItem(r.Context(), src.ID, SourceItem{Kind: it.Kind, ID: it.ID, Name: cleanLabel(it.Name, 80), Pool: it.Pool, TaskID: it.Task}); err != nil {
			replyErr(w, err)
			return
		}
	}
	replyJSON(w, http.StatusOK, map[string]int{"items": len(req.Items)})
}

// RemoteItem is one of a source's items as its receiving server has it.
type RemoteItem struct {
	Kind         string     `json:"kind"`
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Pool         string     `json:"pool"`
	UsedBytes    uint64     `json:"usedBytes"`
	Snapshots    int        `json:"snapshots"`
	LastSnapshot string     `json:"lastSnapshot,omitempty"`
	LastAt       *time.Time `json:"lastAt,omitempty"`
	Partial      bool       `json:"partial"`
}

func (s *Service) remoteItems(ctx context.Context, src *Source) ([]RemoteItem, error) {
	reps, err := s.Root.Replicas(ctx)
	if err != nil {
		return nil, err
	}
	names := map[string]SourceItem{}
	for _, it := range src.Items {
		names[it.Kind+"/"+it.ID] = it
	}
	out := []RemoteItem{}
	for _, rs := range reps {
		if rs.Source != src.ID || rs.Pool != src.Pool {
			continue
		}
		for _, it := range rs.Items {
			n := names[it.Kind+"/"+it.ID]
			name := n.Name
			if name == "" {
				name = it.ID
			}
			out = append(out, RemoteItem{Kind: it.Kind, ID: it.ID, Name: name, Pool: n.Pool, UsedBytes: it.UsedBytes,
				Snapshots: it.Snapshots, LastSnapshot: it.LastSnapshot, LastAt: it.LastAt, Partial: it.Partial})
		}
	}
	return out, nil
}

func (s *Service) handleGetItems(w http.ResponseWriter, r *http.Request, src *Source) {
	// The cached record has no items; read them.
	full, err := s.st.Source(r.Context(), src.ID)
	if err != nil {
		replyErr(w, err)
		return
	}
	l, err := s.remoteItems(r.Context(), full)
	if err != nil {
		replyErr(w, err)
		return
	}
	replyJSON(w, http.StatusOK, map[string]any{"items": l})
}

// target builds the replica's place from the query: the pool and source
// are this server's record of the caller, never the caller's word.
func target(r *http.Request, src *Source) (replica.Target, error) {
	q := r.URL.Query()
	t := replica.Target{Pool: src.Pool, Source: src.ID, Kind: q.Get("kind"), Item: q.Get("id"), Child: q.Get("child")}
	return t, t.Validate()
}

func (s *Service) handleState(w http.ResponseWriter, r *http.Request, src *Source) {
	t, err := target(r, src)
	if err != nil {
		replyErr(w, err)
		return
	}
	st, err := s.Root.RecvState(r.Context(), t)
	if err != nil {
		replyErr(w, err)
		return
	}
	replyJSON(w, http.StatusOK, st)
}

func (s *Service) handleAbort(w http.ResponseWriter, r *http.Request, src *Source) {
	t, err := target(r, src)
	if err != nil {
		replyErr(w, err)
		return
	}
	if err := s.Root.RecvAbort(r.Context(), t); err != nil {
		s.recordPeer(r.Context(), r, src, "replication.receive.abort", t.Dataset(), err.Error(), audit.Failure)
		replyErr(w, err)
		return
	}
	s.recordPeer(r.Context(), r, src, "replication.receive.abort", t.Dataset(), "interrupted transfer discarded", audit.Success)
	replyJSON(w, http.StatusOK, map[string]bool{"aborted": true})
}

// StreamResult is a receive's outcome.
type StreamResult struct {
	Bytes int64 `json:"bytes"`
}

// waitStream follows a root stream until it's done.
func (s *Service) waitStream(ctx context.Context, id string, limit time.Duration) (*replica.StreamState, error) {
	deadline := time.Now().Add(limit)
	for {
		st, err := s.Root.Stream(ctx, id)
		if err != nil {
			return nil, err
		}
		if st.Done {
			return st, nil
		}
		if time.Now().After(deadline) {
			return st, errors.New("the transfer didn't finish in time")
		}
		select {
		case <-ctx.Done():
			return st, ctx.Err()
		case <-time.After(s.poll()):
		}
	}
}

func (s *Service) handleStream(w http.ResponseWriter, r *http.Request, src *Source) {
	t, err := target(r, src)
	if err != nil {
		replyErr(w, err)
		return
	}
	release, ok := s.slot(src.ID)
	if !ok {
		replyError(w, http.StatusTooManyRequests, "busy", "too many transfers from this server at once")
		return
	}
	defer release()
	q := r.URL.Query()
	task, snap := q.Get("task"), q.Get("snapshot")
	if err := replica.ValidTask(task); err != nil {
		replyErr(w, err)
		return
	}
	if err := replica.ValidSnap(snap, task); err != nil {
		replyErr(w, err)
		return
	}
	ctx := r.Context()
	st, pw, err := s.Root.Recv(ctx, replica.RecvArgs{Target: t, Limits: src.Limits(), Task: task, Snapshot: snap})
	if err != nil {
		s.recordPeer(ctx, r, src, "replication.receive", t.Dataset()+"@"+snap, err.Error(), audit.Denied)
		replyErr(w, err)
		return
	}
	rc := http.NewResponseController(w)
	_, copyErr := io.Copy(pw, idleReader{r: r.Body, rc: rc, idle: StreamIdle})
	pw.Close() // end of stream: zfs receive finishes, or keeps what it got (-s)
	// Root may still be writing; its outcome counts even if the sender left.
	_ = rc.SetWriteDeadline(time.Now().Add(31 * time.Minute))
	wctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	res, err := s.waitStream(wctx, st.Stream, 30*time.Minute)
	if err != nil {
		_ = s.Root.Cancel(wctx, st.Stream)
		s.recordPeer(ctx, r, src, "replication.receive", t.Dataset()+"@"+snap, err.Error(), audit.Failure)
		replyErr(w, err)
		return
	}
	if !res.OK {
		msg := res.Error
		if copyErr != nil && msg == "" {
			msg = copyErr.Error()
		}
		s.log().Warn("replication: receive failed", "source", src.ID, "dataset", t.Dataset(), "err", msg)
		s.recordPeer(ctx, r, src, "replication.receive", t.Dataset()+"@"+snap, msg, audit.Failure)
		replyError(w, http.StatusUnprocessableEntity, "receive_failed", msg)
		return
	}
	if copyErr != nil {
		replyError(w, http.StatusBadRequest, "incomplete", copyErr.Error())
		return
	}
	s.recordPeer(ctx, r, src, "replication.receive", t.Dataset()+"@"+snap, fmt.Sprintf("%d bytes", res.Bytes), audit.Success)
	replyJSON(w, http.StatusOK, StreamResult{Bytes: res.Bytes})
}

func (s *Service) handlePrune(w http.ResponseWriter, r *http.Request, src *Source) {
	t, err := target(r, src)
	if err != nil {
		replyErr(w, err)
		return
	}
	q := r.URL.Query()
	keep, _ := strconv.Atoi(q.Get("keep"))
	// The receiving server keeps at least its own minimum and everything
	// younger than its minimum age, whatever the source asks: a source
	// can't use pruning to wipe its history here.
	keep = max(keep, src.MinKeep, 1)
	res, err := s.Root.RecvPrune(r.Context(), replica.RecvPruneArgs{Target: t, Task: q.Get("task"), Keep: keep, MinAgeDays: src.MinAgeDays})
	if err != nil {
		replyErr(w, err)
		return
	}
	if len(res.Deleted) > 0 {
		s.recordPeer(r.Context(), r, src, "replication.receive.prune", t.ItemDataset(), strings.Join(res.Deleted, " "), audit.Success)
	}
	replyJSON(w, http.StatusOK, res)
}

func (s *Service) handleSnapshots(w http.ResponseWriter, r *http.Request, src *Source) {
	t, err := target(r, src)
	if err != nil {
		replyErr(w, err)
		return
	}
	l, err := s.Root.ReplicaSnapshots(r.Context(), t)
	if err != nil {
		replyErr(w, err)
		return
	}
	replyJSON(w, http.StatusOK, map[string]any{"snapshots": l})
}

func (s *Service) handleChildren(w http.ResponseWriter, r *http.Request, src *Source) {
	t, err := target(r, src)
	if err != nil {
		replyErr(w, err)
		return
	}
	l, err := s.Root.ReplicaChildren(r.Context(), t, r.URL.Query().Get("snapshot"))
	if err != nil {
		replyErr(w, err)
		return
	}
	replyJSON(w, http.StatusOK, map[string]any{"children": l})
}

// BrowseSpacing is the least time between two browses from one source.
const BrowseSpacing = 2 * time.Second

// browseGate lets one browse per source run at a time, spaced out.
type browseGate struct {
	mu   sync.Mutex
	busy map[string]bool
	last map[string]time.Time
}

func (g *browseGate) enter(src string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.busy == nil {
		g.busy, g.last = map[string]bool{}, map[string]time.Time{}
	}
	if g.busy[src] || now.Sub(g.last[src]) < BrowseSpacing {
		return false
	}
	g.busy[src] = true
	return true
}

func (g *browseGate) leave(src string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.busy[src] = false
	g.last[src] = time.Now()
}

// handleBrowse mounts one of the source's replica snapshots here for a
// moment. That makes this server's kernel read file system structures
// the source wrote, so it's off unless this server's administrator
// allows it for that source, one at a time and spaced out.
func (s *Service) handleBrowse(w http.ResponseWriter, r *http.Request, src *Source) {
	t, err := target(r, src)
	if err != nil {
		replyErr(w, err)
		return
	}
	if !src.AllowBrowse {
		replyError(w, http.StatusForbidden, "browse_off", "browsing replicas is off for this server on the receiving server (its administrator can allow it); restore the item to look inside")
		return
	}
	if !s.browse.enter(src.ID, time.Now()) {
		replyError(w, http.StatusTooManyRequests, "busy", "one browse at a time; try again in a moment")
		return
	}
	defer s.browse.leave(src.ID)
	q := r.URL.Query()
	res, err := s.Root.Browse(r.Context(), replica.BrowseArgs{Target: t, Snapshot: q.Get("snapshot"), Path: q.Get("path")})
	outcome := audit.Success
	if err != nil {
		outcome = audit.Failure
	}
	s.recordPeer(r.Context(), r, src, "replication.receive.browse", t.Dataset()+"@"+q.Get("snapshot"), q.Get("path"), outcome)
	if err != nil {
		replyErr(w, err)
		return
	}
	replyJSON(w, http.StatusOK, res)
}

// TrailerStatus carries a send's outcome after its stream.
const TrailerStatus = "X-Hardyos-Stream"

func (s *Service) handleSend(w http.ResponseWriter, r *http.Request, src *Source) {
	t, err := target(r, src)
	if err != nil {
		replyErr(w, err)
		return
	}
	release, ok := s.slot(src.ID)
	if !ok {
		replyError(w, http.StatusTooManyRequests, "busy", "too many transfers from this server at once")
		return
	}
	defer release()
	ctx := r.Context()
	st, rc, err := s.Root.ReplicaSend(ctx, replica.ReplicaSendArgs{Target: t, Snapshot: r.URL.Query().Get("snapshot")})
	if err != nil {
		replyErr(w, err)
		return
	}
	defer rc.Close()
	s.recordPeer(ctx, r, src, "replication.send", t.Dataset()+"@"+r.URL.Query().Get("snapshot"), "sent back for a restore", audit.Success)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Trailer", TrailerStatus)
	if st.Estimate > 0 {
		w.Header().Set("X-Hardyos-Estimate", strconv.FormatInt(st.Estimate, 10))
	}
	w.WriteHeader(http.StatusOK)
	_, copyErr := io.Copy(idleWriter{w: w, rc: http.NewResponseController(w), idle: StreamIdle}, rc)
	if copyErr != nil {
		_ = s.Root.Cancel(context.Background(), st.Stream)
		return
	}
	res, err := s.waitStream(ctx, st.Stream, 5*time.Minute)
	switch {
	case err != nil:
		w.Header().Set(TrailerStatus, "error: "+strings.ReplaceAll(err.Error(), "\n", " "))
	case !res.OK:
		w.Header().Set(TrailerStatus, "error: "+strings.ReplaceAll(res.Error, "\n", " "))
	default:
		w.Header().Set(TrailerStatus, "ok")
	}
}
