package priv

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func startServer(t *testing.T, s *Server) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = s.Serve(ctx, ln)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return sock
}

func TestPingAllowedForCurrentUser(t *testing.T) {
	s := &Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	RegisterBuiltins(s)
	c := NewClient(startServer(t, s))

	var res PingResult
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Call(ctx, OpPing, nil, &res); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if res.Hostname == "" || res.Time.IsZero() {
		t.Fatalf("unexpected ping result %+v", res)
	}
}

func TestUnknownOpRejected(t *testing.T) {
	s := &Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	RegisterBuiltins(s)
	c := NewClient(startServer(t, s))

	err := c.Call(context.Background(), "system.exec", map[string]string{"cmd": "id"}, nil)
	var pe *Error
	if !errors.As(err, &pe) || pe.Code != CodeUnknownOp {
		t.Fatalf("err = %v, want unknown_op", err)
	}
}

func TestCallerNotAllowed(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is always allowed")
	}
	s := &Server{AllowedUIDs: []uint32{999999}}
	RegisterBuiltins(s)
	c := NewClient(startServer(t, s))

	err := c.Call(context.Background(), OpPing, nil, nil)
	var pe *Error
	if !errors.As(err, &pe) || pe.Code != CodeForbidden {
		t.Fatalf("err = %v, want forbidden", err)
	}
}

func TestOperationErrorIsStructured(t *testing.T) {
	s := &Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	s.Handle("test.fail", func(ctx context.Context, args json.RawMessage) (any, error) {
		return nil, Errorf(CodeBadArgs, "pool name required")
	})
	c := NewClient(startServer(t, s))

	err := c.Call(context.Background(), "test.fail", nil, nil)
	var pe *Error
	if !errors.As(err, &pe) || pe.Code != CodeBadArgs || pe.Message != "pool name required" {
		t.Fatalf("err = %v, want bad_args with message", err)
	}
}

func TestUnavailableSocket(t *testing.T) {
	c := NewClient(filepath.Join(t.TempDir(), "missing.sock"))
	err := c.Call(context.Background(), OpPing, nil, nil)
	var pe *Error
	if !errors.As(err, &pe) || pe.Code != CodeUnavailable {
		t.Fatalf("err = %v, want unavailable", err)
	}
}
