package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// Terminal limits.
const (
	terminalTicketTTL = 30 * time.Second
	TerminalIdle      = 15 * time.Minute
	TerminalMaxLife   = 8 * time.Hour
	keyTerminalOn     = "terminal.enabled"
)

// terminalTickets are one-time passes from "password checked" to "terminal
// opened", bound to the administrator who asked.
type terminalTickets struct {
	mu sync.Mutex
	m  map[string]ticket
}

type ticket struct {
	user    int64
	expires time.Time
}

func (t *terminalTickets) issue(user int64) string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[string]ticket{}
	}
	now := time.Now()
	for k, v := range t.m {
		if now.After(v.expires) {
			delete(t.m, k)
		}
	}
	t.m[tok] = ticket{user: user, expires: now.Add(terminalTicketTTL)}
	return tok
}

// redeem uses up a ticket; it's valid once, briefly, for the same user.
func (t *terminalTickets) redeem(tok string, user int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	tk, ok := t.m[tok]
	delete(t.m, tok)
	return ok && tk.user == user && time.Now().Before(tk.expires)
}

func (s *Server) terminalRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/terminal/settings", s.admin(s.handleTerminalSettings))
	m.Handle("PUT /api/v1/terminal/settings", s.admin(s.handleTerminalSettingsSet))
	m.Handle("POST /api/v1/terminal/session", s.admin(s.handleTerminalSession))
	m.Handle("GET /api/v1/terminal/ws", s.admin(s.handleTerminalWS))
}

// TerminalSettings is the on/off switch.
type TerminalSettings struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) terminalEnabled(ctx context.Context) bool {
	v, err := s.cfg.DB.GetSetting(ctx, keyTerminalOn)
	return err != nil || v != "false"
}

func (s *Server) handleTerminalSettings(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	writeJSON(w, http.StatusOK, TerminalSettings{Enabled: s.terminalEnabled(r.Context())})
}

func (s *Server) handleTerminalSettingsSet(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req TerminalSettings
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.cfg.DB.SetSetting(r.Context(), keyTerminalOn, strconv.FormatBool(req.Enabled)); err != nil {
		internalError(s, w, err)
		return
	}
	s.record(r, u, "terminal.settings", "enabled="+strconv.FormatBool(req.Enabled), audit.Success, "")
	writeJSON(w, http.StatusOK, req)
}

type terminalSessionRequest struct {
	Password string `json:"password"`
}

// handleTerminalSession checks the administrator's password again and hands
// out a one-time ticket for the WebSocket.
func (s *Server) handleTerminalSession(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req terminalSessionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !s.terminalEnabled(r.Context()) {
		writeError(w, http.StatusForbidden, "disabled", "the terminal is turned off in Control Panel > Security")
		return
	}
	key := "terminal:" + strconv.FormatInt(u.ID, 10)
	if ok, wait := s.cfg.Limiter.Allowed(key); !ok {
		s.record(r, u, "terminal.unlock", "", audit.Denied, "rate limited")
		writeError(w, http.StatusTooManyRequests, "rate_limited", fmt.Sprintf("too many wrong passwords; try again in %d minutes", int(wait.Minutes())+1))
		return
	}
	if err := s.signin.Verify(r.Context(), u, req.Password); err != nil {
		if errors.Is(err, auth.ErrDomainUnavailable) || errors.Is(err, auth.ErrClockSkew) {
			writeError(w, http.StatusServiceUnavailable, "domain_unavailable", err.Error())
			return
		}
		if errors.Is(err, auth.ErrBadCredentials) || errors.Is(err, auth.ErrAccountRevoked) ||
			errors.Is(err, auth.ErrPasswordExpired) || errors.Is(err, auth.ErrAccountGone) {
			s.cfg.Limiter.Fail(key)
			s.record(r, u, "terminal.unlock", "", audit.Failure, "wrong password")
			writeError(w, http.StatusUnauthorized, "bad_credentials", "that password isn't right")
			return
		}
		internalError(s, w, err)
		return
	}
	s.cfg.Limiter.Succeed(key)
	writeJSON(w, http.StatusOK, map[string]string{"ticket": s.tickets.issue(u.ID)})
}

// terminalControl is a text frame from the browser.
type terminalControl struct {
	Type string `json:"type"` // resize
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

// handleTerminalWS relays a root shell between hardyd-priv's terminal and the
// browser: binary frames carry terminal bytes both ways, text frames carry
// control messages (resize from the browser; closed with a reason to it).
func (s *Server) handleTerminalWS(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if !s.tickets.redeem(r.URL.Query().Get("ticket"), u.ID) {
		writeError(w, http.StatusForbidden, "no_ticket", "enter your password to open the terminal")
		return
	}
	if !s.terminalEnabled(r.Context()) {
		writeError(w, http.StatusForbidden, "disabled", "the terminal is turned off")
		return
	}
	cols, _ := strconv.Atoi(r.URL.Query().Get("cols"))
	rows, _ := strconv.Atoi(r.URL.Query().Get("rows"))
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(1 << 20)

	ctx, cancel := context.WithTimeout(r.Context(), TerminalMaxLife)
	defer cancel()
	var res priv.TerminalOpenResult
	pty, err := s.cfg.Priv.CallFile(ctx, priv.OpTerminalOpen, priv.TerminalOpenArgs{Cols: cols, Rows: rows, User: u.Username}, &res)
	if err != nil {
		s.record(r, u, "terminal.open", "", audit.Failure, err.Error())
		_ = conn.Close(websocket.StatusInternalError, truncate(err.Error(), 120))
		return
	}
	defer pty.Close()
	started := time.Now()
	s.record(r, u, "terminal.open", "pid "+strconv.Itoa(res.PID), audit.Success, "")
	reason := s.relayTerminal(ctx, conn, pty)
	s.record(r, u, "terminal.close", "pid "+strconv.Itoa(res.PID), audit.Success,
		fmt.Sprintf("%s after %s", reason, time.Since(started).Round(time.Second)))
}

func (s *Server) relayTerminal(ctx context.Context, conn *websocket.Conn, pty *os.File) string {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	lastInput := time.Now()
	reason := "closed"
	setReason := func(r string) {
		mu.Lock()
		if reason == "closed" {
			reason = r
		}
		mu.Unlock()
	}

	// Shell -> browser. When the shell ends, say so and close cleanly; the
	// read loop below then stops.
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := pty.Read(buf)
			if n > 0 {
				if werr := conn.Write(ctx, websocket.MessageBinary, buf[:n]); werr != nil {
					cancel()
					return
				}
			}
			if err != nil {
				setReason("the shell ended")
				msg, _ := json.Marshal(map[string]string{"type": "closed", "reason": "The shell ended."})
				_ = conn.Write(ctx, websocket.MessageText, msg)
				_ = conn.Close(websocket.StatusNormalClosure, "the shell ended")
				return
			}
		}
	}()
	// Idle and lifetime limits.
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				mu.Lock()
				idle := time.Since(lastInput)
				mu.Unlock()
				if idle >= TerminalIdle {
					setReason("idle for 15 minutes")
					msg, _ := json.Marshal(map[string]string{"type": "closed", "reason": "The terminal closed after 15 minutes without typing."})
					_ = conn.Write(ctx, websocket.MessageText, msg)
					cancel()
					return
				}
			}
		}
	}()
	// Browser -> shell.
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			setReason("the browser closed it")
			break
		}
		mu.Lock()
		lastInput = time.Now()
		mu.Unlock()
		if typ == websocket.MessageBinary {
			if _, err := pty.Write(data); err != nil {
				break
			}
			continue
		}
		var c terminalControl
		if json.Unmarshal(data, &c) == nil && c.Type == "resize" && c.Cols >= 10 && c.Cols <= 1000 && c.Rows >= 2 && c.Rows <= 500 {
			_ = priv.ResizeTerminal(pty, c.Cols, c.Rows)
		}
	}
	cancel()
	mu.Lock()
	defer mu.Unlock()
	if ctx.Err() == context.DeadlineExceeded && reason == "closed" {
		reason = "reached the 8-hour limit"
	}
	_ = conn.Close(websocket.StatusNormalClosure, reason)
	return reason
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
