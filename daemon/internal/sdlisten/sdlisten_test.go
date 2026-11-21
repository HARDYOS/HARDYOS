package sdlisten

import (
	"fmt"
	"net"
	"path/filepath"
	"syscall"
	"testing"
)

func TestListeners(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	f, err := ln.(*net.UnixListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// Put the copy at the lowest free descriptor above it, like systemd's
	// consecutive ones.
	fd := int(f.Fd())
	dup, err := syscall.Dup(fd)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"LISTEN_PID": "42", "LISTEN_FDS": "1", "LISTEN_FDNAMES": "mail-auth"}
	getenv := func(k string) string { return env[k] }

	// Not for this process: nothing.
	got, err := listeners(getenv, 41, dup)
	if err != nil || len(got) != 0 {
		t.Fatalf("other pid: %v %v", got, err)
	}
	got, err = listeners(getenv, 42, dup)
	if err != nil {
		t.Fatal(err)
	}
	l := got["mail-auth"]
	if l == nil || l.Addr().Network() != "unix" {
		t.Fatalf("got %v", got)
	}
	defer l.Close()
	go func() {
		c, err := net.Dial("unix", path)
		if err == nil {
			fmt.Fprint(c, "x")
			c.Close()
		}
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	env["LISTEN_FDS"] = "100"
	if _, err := listeners(getenv, 42, dup); err == nil {
		t.Fatal("too many accepted")
	}
}
