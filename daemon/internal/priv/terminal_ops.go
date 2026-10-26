package priv

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

// OpTerminalOpen starts a root shell in a pseudo-terminal and hands the
// terminal to hardyd. It's the one operation that gives the web UI a shell
// (decision 37): hardyd only offers it to administrators who re-enter their
// password, audits every session, and closes idle ones.
const OpTerminalOpen = "terminal.open"

// MaxTerminals bounds open terminal sessions.
const MaxTerminals = 4

// TerminalOpenArgs sizes the new terminal.
type TerminalOpenArgs struct {
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
	User string `json:"user"` // the HardyOS administrator, for the shell's environment and the log
}

// TerminalOpenResult describes the started shell.
type TerminalOpenResult struct {
	PID int `json:"pid"`
}

type terminals struct {
	mu   sync.Mutex
	open int
	// shell builds the command; tests replace it.
	shell func(user string) *exec.Cmd
}

// defaultShell runs a login shell in the host's mount namespace: hardyd-priv
// itself runs with a private /tmp and without /root and /home
// (ProtectHome), which a person at a shell expects to see.
func defaultShell(user string) *exec.Cmd {
	cmd := exec.Command("/bin/bash", "--login")
	// Where the host's mount namespace can be entered (always, as root on a
	// HardyOS server), use it; otherwise stay in ours.
	if _, err := os.Readlink("/proc/1/ns/mnt"); err == nil {
		cmd = exec.Command("/usr/bin/nsenter", "--mount=/proc/1/ns/mnt", "--", "/bin/bash", "--login")
	}
	cmd.Env = []string{
		"TERM=xterm-256color", "COLORTERM=truecolor", "HOME=/root", "USER=root", "LOGNAME=root", "SHELL=/bin/bash",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8",
		"HARDYOS_TERMINAL_USER=" + user,
	}
	cmd.Dir = "/"
	return cmd
}

// RegisterTerminal adds terminal.open.
func RegisterTerminal(s *Server) {
	registerTerminal(s, &terminals{shell: defaultShell})
}

// RegisterTerminalWith adds terminal.open running shell instead of a root
// login shell (for tests of hardyd's side).
func RegisterTerminalWith(s *Server, shell func(user string) *exec.Cmd) {
	registerTerminal(s, &terminals{shell: shell})
}

func registerTerminal(s *Server, t *terminals) {
	s.Handle(OpTerminalOpen, typed(func(ctx context.Context, a TerminalOpenArgs) (any, error) {
		if a.Cols < 10 || a.Cols > 1000 || a.Rows < 2 || a.Rows > 500 {
			return nil, Errorf(CodeBadArgs, "terminal size out of range")
		}
		if len(a.User) > 64 {
			return nil, Errorf(CodeBadArgs, "invalid user")
		}
		t.mu.Lock()
		if t.open >= MaxTerminals {
			t.mu.Unlock()
			return nil, Errorf(CodeForbidden, "%d terminals are already open; close one first", MaxTerminals)
		}
		t.open++
		t.mu.Unlock()
		release := func() {
			t.mu.Lock()
			t.open--
			t.mu.Unlock()
		}

		master, slave, err := openPTY(a.Cols, a.Rows)
		if err != nil {
			release()
			return nil, Errorf(CodeFailed, "open a terminal: %v", err)
		}
		cmd := t.shell(a.User)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
		if err := cmd.Start(); err != nil {
			master.Close()
			slave.Close()
			release()
			return nil, Errorf(CodeFailed, "start the shell: %v", err)
		}
		slave.Close() // the shell has it now
		go func() {
			// The shell ends when hardyd closes the terminal (hangup) or
			// someone types exit.
			_ = cmd.Wait()
			release()
		}()
		return &FileResult{Data: TerminalOpenResult{PID: cmd.Process.Pid}, File: master}, nil
	}))
}

// ResizeTerminal sets a terminal's size; hardyd calls it on the file it got
// from terminal.open.
func ResizeTerminal(f *os.File, cols, rows int) error { return setSize(f, cols, rows) }
