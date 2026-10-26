package priv

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestTerminalOverSocket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("terminals need Linux")
	}
	if _, err := os.Stat("/dev/ptmx"); err != nil {
		t.Skip("no /dev/ptmx")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	terms := &terminals{shell: func(user string) *exec.Cmd {
		// A tiny stand-in for bash: greet, echo one line back, report the size.
		return exec.Command("/bin/sh", "-c", `echo "hello $HARDYOS_TERMINAL_USER"; read line; echo "got:$line"; stty size; read wait`)
	}}
	// Make the user visible to the stand-in.
	orig := terms.shell
	terms.shell = func(user string) *exec.Cmd {
		c := orig(user)
		c.Env = append(os.Environ(), "HARDYOS_TERMINAL_USER="+user)
		return c
	}
	registerTerminal(s, terms)
	go func() { _ = s.Serve(ctx, ln) }()
	c := NewClient(sock)

	if _, err := c.CallFile(ctx, OpTerminalOpen, TerminalOpenArgs{Cols: 5, Rows: 1}, nil); err == nil {
		t.Fatal("tiny terminal accepted")
	}
	var res TerminalOpenResult
	f, err := c.CallFile(ctx, OpTerminalOpen, TerminalOpenArgs{Cols: 100, Rows: 30, User: "cade"}, &res)
	if err != nil {
		t.Fatal(err)
	}
	if res.PID <= 0 {
		t.Fatalf("pid = %d", res.PID)
	}
	out := bufio.NewReader(f)
	expect := func(want string) {
		t.Helper()
		_ = f.SetReadDeadline(time.Now().Add(5 * time.Second))
		var seen strings.Builder
		for !strings.Contains(seen.String(), want) {
			line, err := out.ReadString('\n')
			seen.WriteString(line)
			if err != nil {
				t.Fatalf("waiting for %q, got %q: %v", want, seen.String(), err)
			}
		}
	}
	expect("hello cade")
	if _, err := f.Write([]byte("ping\n")); err != nil {
		t.Fatal(err)
	}
	expect("got:ping")
	expect("30 100") // stty size: rows cols
	if err := ResizeTerminal(f, 120, 40); err != nil {
		t.Fatal(err)
	}

	// Closing the terminal ends the shell and frees the slot.
	f.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		terms.mu.Lock()
		n := terms.open
		terms.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d terminals still open after closing", n)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// At most MaxTerminals at once.
	var files []*os.File
	for i := 0; i < MaxTerminals; i++ {
		f, err := c.CallFile(ctx, OpTerminalOpen, TerminalOpenArgs{Cols: 80, Rows: 24}, nil)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if _, err := c.CallFile(ctx, OpTerminalOpen, TerminalOpenArgs{Cols: 80, Rows: 24}, nil); err == nil {
		t.Fatal("more terminals than allowed")
	}
	for _, f := range files {
		f.Close()
	}
}
