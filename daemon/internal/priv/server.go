package priv

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

// HandlerFunc runs one operation. It returns a JSON-encodable result or an *Error.
type HandlerFunc func(ctx context.Context, args json.RawMessage) (any, error)

// Server serves the privileged operation allowlist on a unix socket.
type Server struct {
	// AllowedUIDs lists the user IDs permitted to connect. Root (0) is always allowed.
	AllowedUIDs []uint32
	Logger      *slog.Logger
	// OpTimeout bounds each operation. Zero means 10 minutes.
	OpTimeout time.Duration
	// OpTimeouts overrides OpTimeout for single operations (installing an
	// update that rebuilds the NVIDIA driver takes longer).
	OpTimeouts map[string]time.Duration
	// OnListen runs once the socket is ready (systemd readiness notification).
	OnListen func()
	// QuietOps are logged at debug level (read-only operations hardyd polls).
	QuietOps map[string]bool

	mu  sync.RWMutex
	ops map[string]HandlerFunc

	relMu     sync.Mutex
	releasers []releaser
}

// Handle registers an operation. Registering the same name twice panics.
func (s *Server) Handle(op string, fn HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ops == nil {
		s.ops = map[string]HandlerFunc{}
	}
	if _, dup := s.ops[op]; dup {
		panic("priv: duplicate op " + op)
	}
	s.ops[op] = fn
}

// Ops returns the registered operation names.
func (s *Server) Ops() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.ops))
	for k := range s.ops {
		out = append(out, k)
	}
	return out
}

// ListenAndServe removes any stale socket at path, listens, and serves until ctx is done.
func (s *Server) ListenAndServe(ctx context.Context, path string, mode os.FileMode, gid int) error {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		ln.Close()
		return err
	}
	if gid >= 0 {
		if err := os.Chown(path, 0, gid); err != nil {
			ln.Close()
			return err
		}
	}
	if s.OnListen != nil {
		s.OnListen()
	}
	return s.Serve(ctx, ln.(*net.UnixListener))
}

// Serve accepts connections on ln until ctx is done.
func (s *Server) Serve(ctx context.Context, ln *net.UnixListener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.serveConn(ctx, conn)
		}()
	}
}

func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *Server) serveConn(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()
	log := s.logger()

	uid, err := peerUID(conn)
	if err != nil || !s.allowed(uid) {
		log.Warn("rejected priv connection", "uid", uid, "err", err)
		writeResponse(conn, Response{Error: Errorf(CodeForbidden, "caller not permitted")})
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	var req Request
	if err := json.NewDecoder(io.LimitReader(conn, MaxRequestBytes)).Decode(&req); err != nil {
		writeResponse(conn, Response{Error: Errorf(CodeBadRequest, "invalid request: %v", err)})
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	s.mu.RLock()
	fn, ok := s.ops[req.Op]
	s.mu.RUnlock()
	if !ok {
		writeResponse(conn, Response{Error: Errorf(CodeUnknownOp, "unknown operation %q", req.Op)})
		return
	}

	timeout := s.OpTimeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	if t, ok := s.OpTimeouts[req.Op]; ok && t > 0 {
		timeout = t
	}
	opCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	result, err := fn(opCtx, req.Args)
	if s.QuietOps[req.Op] && err == nil {
		log.Debug("priv op", "op", req.Op, "uid", uid, "ok", true, "duration", time.Since(start).String())
	} else {
		log.Info("priv op", "op", req.Op, "uid", uid, "ok", err == nil, "duration", time.Since(start).String())
	}
	if err != nil {
		var pe *Error
		if !errors.As(err, &pe) {
			pe = Errorf(CodeFailed, "%v", err)
		}
		writeResponse(conn, Response{Error: pe})
		return
	}
	// An operation can hand over an open file (a terminal) with its result.
	var file *os.File
	if fr, ok := result.(*FileResult); ok {
		result, file = fr.Data, fr.File
		defer file.Close() // the caller has its own copy once sent
	}
	data, err := json.Marshal(result)
	if err != nil {
		writeResponse(conn, Response{Error: Errorf(CodeFailed, "encode result: %v", err)})
		return
	}
	if file != nil {
		b, _ := json.Marshal(Response{OK: true, Data: data})
		if _, _, err := conn.WriteMsgUnix(append(b, '\n'), unix.UnixRights(int(file.Fd())), nil); err != nil {
			log.Warn("priv op: sending the file failed", "op", req.Op, "err", err)
		}
		return
	}
	writeResponse(conn, Response{OK: true, Data: data})
}

func (s *Server) allowed(uid uint32) bool {
	if uid == 0 {
		return true
	}
	for _, a := range s.AllowedUIDs {
		if a == uid {
			return true
		}
	}
	return false
}

// FileResult is an operation result that also passes an open file to the
// caller (SCM_RIGHTS over the socket). Only CallFile receives it.
type FileResult struct {
	Data any
	File *os.File
}

func writeResponse(w io.Writer, r Response) {
	_ = json.NewEncoder(w).Encode(r)
}
