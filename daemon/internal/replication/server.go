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
	"strconv"
	"strings"
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

// OpenPairing stores a pairing code for another server to use.
func (s *Service) OpenPairing(ctx context.Context, code []byte, p PairingParams) (*Pairing, error) {
	s.init()
	if err := replica.ValidPool(p.Pool); err != nil {
		return nil, errors.New("choose the pool that keeps the replicas")
	}
	if p.MinKeep == 0 {
		p.MinKeep = 3
	}
	if p.MinKeep < 1 || p.MinKeep > MaxKeep {
		return nil, fmt.Errorf("keep between 1 and %d snapshots", MaxKeep)
	}
	pr := Pairing{Pool: p.Pool, QuotaBytes: p.QuotaBytes, MinKeep: p.MinKeep, ExpiresAt: s.now().Add(PairingTTL)}
	if _, err := s.Identity(ctx); err != nil {
		return nil, err
	}
	if err := s.st.SetPairing(ctx, code, pr); err != nil {
		return nil, err
	}
	return &pr, nil
}

// Receiving reports whether other servers can send here (a pairing code
// is open or a source is paired), so the port is open.
func (s *Service) Receiving(ctx context.Context) bool {
	s.init()
	if p, err := s.st.Pairing(ctx, s.now()); err == nil && p != nil {
		return true
	}
	l, err := s.st.Sources(ctx)
	return err == nil && len(l) > 0
}

func (s *Service) listenAddr() string {
	if s.ListenAddr != "" {
		return s.ListenAddr
	}
	return ":" + strconv.Itoa(DefaultPort)
}

// serveWhileReceiving runs the receiving server while Receiving is true.
func (s *Service) serveWhileReceiving(ctx context.Context) {
	var srv *http.Server
	stop := func() {
		if srv != nil {
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(sctx)
			cancel()
			srv = nil
		}
	}
	defer stop()
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		want := s.Receiving(ctx)
		switch {
		case want && srv == nil:
			id, err := s.Identity(ctx)
			if err != nil {
				s.log().Warn("replication: identity", "err", err)
				break
			}
			ln, err := net.Listen("tcp", s.listenAddr())
			if err != nil {
				s.log().Warn("replication: listening for other servers", "addr", s.listenAddr(), "err", err)
				break
			}
			srv = s.newServer(id)
			go func(srv *http.Server) {
				if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
					s.log().Warn("replication: server", "err", err)
				}
			}(srv)
			s.log().Info("replication: receiving from other servers", "addr", s.listenAddr())
		case !want && srv != nil:
			stop()
			s.log().Info("replication: stopped receiving")
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
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

// Handler serves the receiving side (exported for tests).
func (s *Service) Handler() http.Handler {
	s.init()
	m := http.NewServeMux()
	m.HandleFunc("POST /repl/v1/pair", s.handlePair)
	m.Handle("GET /repl/v1/hello", s.source(s.handleHello))
	m.Handle("PUT /repl/v1/items", s.source(s.handlePutItems))
	m.Handle("GET /repl/v1/items", s.source(s.handleGetItems))
	m.Handle("GET /repl/v1/state", s.source(s.handleState))
	m.Handle("POST /repl/v1/abort", s.source(s.handleAbort))
	m.Handle("PUT /repl/v1/stream", s.source(s.handleStream))
	m.Handle("POST /repl/v1/prune", s.source(s.handlePrune))
	m.Handle("GET /repl/v1/snapshots", s.source(s.handleSnapshots))
	m.Handle("GET /repl/v1/children", s.source(s.handleChildren))
	m.Handle("GET /repl/v1/browse", s.source(s.handleBrowse))
	m.Handle("GET /repl/v1/send", s.source(s.handleSend))
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		replyError(w, http.StatusNotFound, "not_found", "no such endpoint")
	})
	return m
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
	case errors.Is(err, replica.ErrBusy):
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
		l, err := s.st.Sources(r.Context())
		if err != nil {
			replyErr(w, err)
			return
		}
		for i := range l {
			if l[i].Pin != "" && subtle.ConstantTimeCompare([]byte(l[i].Pin), []byte(pin)) == 1 {
				s.st.touchSource(r.Context(), l[i].ID)
				fn(w, r, &l[i])
				return
			}
		}
		replyError(w, http.StatusForbidden, "not_paired", "this server isn't paired with the receiving server")
	})
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
	id, err := s.Identity(ctx)
	if err != nil {
		replyErr(w, err)
		return
	}
	if !hmac.Equal(proof, sourceProof(p.code, pin, id.Pin)) {
		s.st.pairingFailed(ctx)
		s.record(ctx, "replication.pair", cleanLabel(req.Name, 60), "wrong pairing code", remoteIP(r), audit.Denied)
		replyError(w, http.StatusForbidden, "wrong_code", "the pairing code doesn't match (or a connection in between changed it)")
		return
	}
	name := cleanLabel(req.Name, 60)
	if name == "" {
		name = remoteIP(r)
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
		if err := s.st.AddSource(ctx, &Source{ID: srcID, Name: name, Pin: pin, Pool: p.Pool, QuotaBytes: p.QuotaBytes, MinKeep: p.MinKeep}); err != nil {
			replyErr(w, err)
			return
		}
	}
	_ = s.st.ClearPairing(ctx)
	s.record(ctx, "replication.pair", name, "source "+srcID+" may send replicas to "+p.Pool, remoteIP(r), audit.Success)
	s.log().Info("replication: paired with a source", "source", srcID, "name", name, "ip", remoteIP(r))
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
	l, err := s.remoteItems(r.Context(), src)
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
		replyErr(w, err)
		return
	}
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
	st, pw, err := s.Root.Recv(ctx, replica.RecvArgs{Target: t, Task: task, Snapshot: snap, QuotaBytes: src.QuotaBytes})
	if err != nil {
		replyErr(w, err)
		return
	}
	_, copyErr := io.Copy(pw, r.Body)
	pw.Close() // end of stream: zfs receive finishes, or keeps what it got (-s)
	// Root may still be writing; its outcome counts even if the sender left.
	wctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	res, err := s.waitStream(wctx, st.Stream, 30*time.Minute)
	if err != nil {
		_ = s.Root.Cancel(wctx, st.Stream)
		replyErr(w, err)
		return
	}
	if !res.OK {
		msg := res.Error
		if copyErr != nil && msg == "" {
			msg = copyErr.Error()
		}
		s.log().Warn("replication: receive failed", "source", src.ID, "dataset", t.Dataset(), "err", msg)
		replyError(w, http.StatusUnprocessableEntity, "receive_failed", msg)
		return
	}
	if copyErr != nil {
		replyError(w, http.StatusBadRequest, "incomplete", copyErr.Error())
		return
	}
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
	// The receiving server keeps at least its own minimum, whatever the
	// source asks: a source can't use pruning to wipe its history here.
	keep = max(keep, src.MinKeep, 1)
	res, err := s.Root.RecvPrune(r.Context(), replica.RecvPruneArgs{Target: t, Task: q.Get("task"), Keep: keep})
	if err != nil {
		replyErr(w, err)
		return
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

func (s *Service) handleBrowse(w http.ResponseWriter, r *http.Request, src *Source) {
	t, err := target(r, src)
	if err != nil {
		replyErr(w, err)
		return
	}
	q := r.URL.Query()
	res, err := s.Root.Browse(r.Context(), replica.BrowseArgs{Target: t, Snapshot: q.Get("snapshot"), Path: q.Get("path")})
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
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Trailer", TrailerStatus)
	if st.Estimate > 0 {
		w.Header().Set("X-Hardyos-Estimate", strconv.FormatInt(st.Estimate, 10))
	}
	w.WriteHeader(http.StatusOK)
	_, copyErr := io.Copy(w, rc)
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
