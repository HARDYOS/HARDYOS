package sftpauth

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type fakeHardyd struct {
	mu   sync.Mutex
	seen []Request
	uid  uint32
}

func (f *fakeHardyd) start(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Serve(ctx, ln, func(_ context.Context, r Request) Answer {
			f.mu.Lock()
			f.seen = append(f.seen, r)
			f.mu.Unlock()
			return Answer{OK: r.Op != OpOwn || r.RHost == "192.168.1.20"}
		}, func(net.Conn) (uint32, error) { return f.uid, nil })
	}()
	t.Cleanup(func() { cancel(); <-done })
	return sock
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestPAMOps(t *testing.T) {
	f := &fakeHardyd{}
	sock := f.start(t)
	ctx := context.Background()
	e := map[string]string{"PAM_TYPE": "auth", "PAM_USER": `HOME\alice`, "PAM_RHOST": "192.168.1.20"}
	// An app password (with pam_exec's NUL) is sent.
	if rc := PAM(ctx, OpApp, env(e), strings.NewReader("abcd-efgh-jkmn-pqrs-tuvw\x00"), sock, io.Discard); rc != 0 {
		t.Fatalf("app = %d", rc)
	}
	// The account's own password never leaves sshd this way.
	if rc := PAM(ctx, OpApp, env(e), strings.NewReader("correct horse battery\x00"), sock, io.Discard); rc != 1 {
		t.Fatalf("own password as app = %d", rc)
	}
	if rc := PAM(ctx, OpOwn, env(e), strings.NewReader(""), sock, io.Discard); rc != 0 {
		t.Fatalf("own at home = %d", rc)
	}
	e["PAM_RHOST"] = "203.0.113.9"
	if rc := PAM(ctx, OpOwn, env(e), nil, sock, io.Discard); rc != 1 {
		t.Fatalf("own from outside = %d", rc)
	}
	// Not the auth stack: nothing asked.
	e["PAM_TYPE"] = "account"
	if rc := PAM(ctx, OpOwn, env(e), nil, sock, io.Discard); rc != 1 {
		t.Fatalf("account stack = %d", rc)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.seen) != 3 || f.seen[0].Password != "abcd-efgh-jkmn-pqrs-tuvw" || f.seen[1].Password != "" || f.seen[2].RHost != "203.0.113.9" {
		t.Fatalf("hardyd saw %+v", f.seen)
	}
	for _, r := range f.seen {
		if strings.Contains(r.Password, "horse") {
			t.Fatal("the own password reached hardyd")
		}
	}
}

// Only root may ask; anyone else gets no.
func TestOnlyRootIsAnswered(t *testing.T) {
	f := &fakeHardyd{uid: 1000}
	sock := f.start(t)
	a, err := Ask(context.Background(), sock, Request{Op: OpOwn, User: "alice", RHost: "192.168.1.20"})
	if err != nil || a.OK || !strings.Contains(a.Reason, "root") {
		t.Fatalf("%+v %v", a, err)
	}
	if len(f.seen) != 0 {
		t.Fatal("the handler ran for a non-root peer")
	}
}

func TestRequestCheck(t *testing.T) {
	for name, r := range map[string]Request{
		"op":            {Op: "shell", User: "alice"},
		"user":          {Op: OpOwn, User: "alice smith"},
		"user newline":  {Op: OpOwn, User: "alice\n"},
		"two domains":   {Op: OpOwn, User: `A\B\c`},
		"empty user":    {Op: OpOwn},
		"password own":  {Op: OpOwn, User: "alice", Password: "x"},
		"no password":   {Op: OpApp, User: "alice"},
		"long rhost":    {Op: OpOwn, User: "alice", RHost: strings.Repeat("1", 65)},
		"long password": {Op: OpApp, User: "alice", Password: strings.Repeat("a", 257)},
	} {
		if err := r.Check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, r := range []Request{{Op: OpApp, User: `HOME\alice`, Password: "x"}, {Op: OpAfter, User: "alice.b", RHost: "fe80::1%eth0"}} {
		if err := r.Check(); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	if a := (&Request{RHost: "fe80::1%eth0"}).Addr(); a.String() != "fe80::1" {
		t.Fatal(a)
	}
	if a := (&Request{RHost: "::ffff:192.168.1.2"}).Addr(); a.String() != "192.168.1.2" {
		t.Fatal(a)
	}
	if (&Request{RHost: "host.example"}).Addr().IsValid() {
		t.Fatal("a host name is an address")
	}
}

func TestPeerUID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	sock := filepath.Join(t.TempDir(), "p.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := net.Dial("unix", sock)
		if err == nil {
			defer c.Close()
			_, _ = c.Read(make([]byte, 1))
		}
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	uid, err := PeerUID(c)
	if err != nil || uid != uint32(os.Getuid()) {
		t.Fatalf("%d %v", uid, err)
	}
}
