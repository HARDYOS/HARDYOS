package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/coder/websocket"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// VM consoles (decision 124): the browser asks for a console (an
// administrator, audited) and gets a one-time token that hardyd-priv
// issued for that VM. Its WebSocket redeems the token; hardyd-priv then
// connects to the VM's VNC socket and hands the connection to hardyd,
// which relays RFB between it and noVNC in the desktop window.

// VMConsoleMaxLife bounds one console session.
const VMConsoleMaxLife = 12 * time.Hour

// vmConsoleRecheck is how often an open console checks that its desktop
// session is still signed in and still an administrator's.
var vmConsoleRecheck = 15 * time.Second

// VMConsoleSession is a console's one-time pass and where to use it.
type VMConsoleSession struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
	// Path is the WebSocket to open (relative to the server).
	Path string `json:"path"`
}

func (s *Server) handleVMConsole(w http.ResponseWriter, r *http.Request, u *auth.User) {
	id, ok := vmID(w, r)
	if !ok {
		return
	}
	var t vms.ConsoleToken
	if err := s.vmCall(r, priv.OpVMsConsole, vms.ConsoleArgs{ID: id}, &t); err != nil {
		s.record(r, u, "vms.console", id, audit.Failure, err.Error())
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, VMConsoleSession{Token: t.Token, Expires: t.Expires,
		Path: "/api/v1/vms/" + url.PathEscape(id) + "/console/ws?token=" + url.QueryEscape(t.Token)})
}

func (s *Server) handleVMConsoleWS(w http.ResponseWriter, r *http.Request, u *auth.User) {
	id, ok := vmID(w, r)
	if !ok {
		return
	}
	token := r.URL.Query().Get("token")
	ctx, cancel := context.WithTimeout(r.Context(), VMConsoleMaxLife)
	defer cancel()
	octx, ocancel := context.WithTimeout(ctx, 30*time.Second)
	vnc, err := s.cfg.Priv.CallFile(octx, priv.OpVMsConsoleOpen, vms.ConsoleOpenArgs{ID: id, Token: token}, nil)
	ocancel()
	if err != nil {
		s.record(r, u, "vms.console.open", id, audit.Denied, err.Error())
		s.writePrivError(w, err)
		return
	}
	defer vnc.Close()
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"binary"}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(4 << 20)
	started := time.Now()
	s.record(r, u, "vms.console.open", id, audit.Success, "")
	session := ""
	if c, err := r.Cookie(SessionCookie); err == nil {
		session = c.Value
	}
	// Signing out, being demoted or disabled closes the screen too.
	still := func() bool {
		info, err := s.peekSession(ctx, session)
		if err != nil || info.UserID != u.ID {
			return false
		}
		cur, err := s.sessionUser(r, session, info.UserID)
		return err == nil && cur.IsAdmin()
	}
	reason := relayVNC(ctx, conn, vnc, still)
	s.record(r, u, "vms.console.close", id, audit.Success, fmt.Sprintf("%s after %s", reason, time.Since(started).Round(time.Second)))
}

// relayVNC copies RFB bytes between the VM's VNC server and the browser
// while still() says the person may (checked every vmConsoleRecheck).
func relayVNC(ctx context.Context, conn *websocket.Conn, vnc *os.File, still func() bool) string {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan string, 3)
	go func() {
		t := time.NewTicker(vmConsoleRecheck)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if !still() {
					done <- "the session ended or is no longer an administrator's"
					return
				}
			}
		}
	}()
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, err := vnc.Read(buf)
			if n > 0 {
				if werr := conn.Write(ctx, websocket.MessageBinary, buf[:n]); werr != nil {
					done <- "the browser closed it"
					return
				}
			}
			if err != nil {
				done <- "the VM's screen closed (it stopped?)"
				return
			}
		}
	}()
	go func() {
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				done <- "the browser closed it"
				return
			}
			if _, err := vnc.Write(data); err != nil {
				done <- "the VM's screen closed (it stopped?)"
				return
			}
		}
	}()
	var reason string
	select {
	case reason = <-done:
	case <-ctx.Done():
		reason = "reached the 12-hour limit"
	}
	cancel()
	_ = vnc.Close()
	_ = conn.Close(websocket.StatusNormalClosure, reason)
	return reason
}
