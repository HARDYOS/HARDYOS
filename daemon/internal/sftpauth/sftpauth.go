// Package sftpauth is how sshd's PAM stack asks hardyd about a domain
// account's SFTP sign-in (decisions 514-516): pam_exec runs
// `hardyctl pam-sftp <op>` as root, which sends one request over a Unix
// socket systemd makes for hardyd (hardyd-sftp-auth.socket: owner hardyd,
// mode 0600) and exits 0 for yes. hardyd answers only processes running as
// root (SO_PEERCRED); nothing goes over the network.
//
// The ops, in the order sshd's PAM block runs them:
//
//	app    the typed password is an app password with the sftp scope (it
//	       is sent only when it has an app password's shape)
//	own    the account's own password may be checked from this address
//	       (home, and no two-factor sign-in), before pam_winbind is asked
//	after  the same, again, once pam_winbind said yes; recorded as a sign-in
//	fail   pam_winbind said no: recorded, and counted like WebDAV's
package sftpauth

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// Socket is where hardyd listens (made by systemd).
const Socket = "/run/hardyos-sftp-auth.sock"

// Ops.
const (
	OpApp   = "app"
	OpOwn   = "own"
	OpAfter = "after"
	OpFail  = "fail"
)

// Request is one question. Password is set for OpApp only.
type Request struct {
	Op       string `json:"op"`
	User     string `json:"user"`
	RHost    string `json:"rhost"`
	Password string `json:"password,omitempty"`
}

// Answer is hardyd's reply.
type Answer struct {
	OK bool `json:"ok"`
	// Reason is for the system log (never shown to the person).
	Reason string `json:"reason,omitempty"`
}

// maxRequest caps a request line (a name, an address and a password).
const maxRequest = 4096

// Timeout bounds one question, so a stuck hardyd never hangs sshd's
// sign-in for long.
const Timeout = 10 * time.Second

// slotWait is how long a question waits for one of the answering slots
// before it is closed (a no).
const slotWait = 3 * time.Second

var userRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._$\\-]{0,127}$`)

// Check validates a request before it is sent or answered.
func (r *Request) Check() error {
	switch r.Op {
	case OpApp, OpOwn, OpAfter, OpFail:
	default:
		return fmt.Errorf("unknown op %q", r.Op)
	}
	if !userRE.MatchString(r.User) || strings.Count(r.User, `\`) > 1 {
		return errors.New("the user name isn't valid")
	}
	if len(r.RHost) > 64 {
		return errors.New("the remote address is too long")
	}
	if (r.Op == OpApp) != (r.Password != "") {
		return errors.New("a password goes with the app op only")
	}
	if len(r.Password) > 256 {
		return errors.New("the password is too long")
	}
	return nil
}

// Addr is the request's remote address; an unreadable one (a host name,
// nothing) is invalid, which hardyd treats as outside.
func (r *Request) Addr() netip.Addr {
	a, err := netip.ParseAddr(strings.TrimSpace(r.RHost))
	if err != nil {
		return netip.Addr{}
	}
	return a.WithZone("").Unmap()
}

// Ask sends req over the socket at path and returns the answer.
func Ask(ctx context.Context, path string, req Request) (Answer, error) {
	if err := req.Check(); err != nil {
		return Answer{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return Answer{}, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	b, _ := json.Marshal(req)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return Answer{}, err
	}
	var a Answer
	line, err := bufio.NewReader(io.LimitReader(c, maxRequest)).ReadBytes('\n')
	if err != nil {
		return Answer{}, err
	}
	if err := json.Unmarshal(line, &a); err != nil {
		return Answer{}, err
	}
	return a, nil
}

// Handler answers one validated request from root.
type Handler func(ctx context.Context, req Request) Answer

// Serve answers requests on ln until ctx ends: one request per
// connection, only from root (peerUID), each within Timeout.
func Serve(ctx context.Context, ln net.Listener, h Handler, peerUID func(net.Conn) (uint32, error)) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	sem := make(chan struct{}, 16)     // answered at once (sshd's MaxStartups is about this)
	waiting := make(chan struct{}, 64) // and these wait up to slotWait for a turn
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		select {
		case waiting <- struct{}{}:
		default:
			_ = c.Close() // far more than sshd ever asks at once
			continue
		}
		go func() {
			t := time.NewTimer(slotWait)
			defer t.Stop()
			select {
			case sem <- struct{}{}:
				<-waiting
			case <-t.C:
				<-waiting
				_ = c.Close()
				return
			case <-ctx.Done():
				<-waiting
				_ = c.Close()
				return
			}
			defer func() { <-sem }()
			serveConn(ctx, c, h, peerUID)
		}()
	}
}

func serveConn(ctx context.Context, c net.Conn, h Handler, peerUID func(net.Conn) (uint32, error)) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(Timeout))
	reply := func(a Answer) {
		b, _ := json.Marshal(a)
		_, _ = c.Write(append(b, '\n'))
	}
	uid, uerr := peerUID(c)
	// The request is read either way (so the asker gets its answer, not a
	// broken pipe), and looked at only from root.
	line, err := bufio.NewReader(io.LimitReader(c, maxRequest)).ReadBytes('\n')
	if uerr != nil || uid != 0 {
		reply(Answer{Reason: "only root (sshd's PAM) may ask"})
		return
	}
	if err != nil {
		reply(Answer{Reason: "no request"})
		return
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		reply(Answer{Reason: "not a request"})
		return
	}
	if err := req.Check(); err != nil {
		reply(Answer{Reason: err.Error()})
		return
	}
	cctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	reply(h(cctx, req))
}
