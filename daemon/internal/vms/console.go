package vms

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The console: each VM's VNC server listens on a unix socket that only
// libvirt (root) and QEMU can reach. hardyd asks root for a one-time token
// for a VM (vms.console, after checking the person is an administrator),
// and redeems it when the browser's WebSocket arrives (vms.console.open):
// root then connects to the VM's socket and hands the connection over.

// TokenTTL is how long a console token can be redeemed.
const TokenTTL = 60 * time.Second

// MaxTokens bounds tokens waiting to be used.
const MaxTokens = 64

type tokenTable struct {
	mu sync.Mutex
	m  map[string]consoleToken
}

type consoleToken struct {
	vm      string
	expires time.Time
}

func (t *tokenTable) issue(vm string, now time.Time) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[string]consoleToken{}
	}
	for k, v := range t.m {
		if now.After(v.expires) {
			delete(t.m, k)
		}
	}
	if len(t.m) >= MaxTokens {
		return "", errors.New("too many consoles are being opened; try again in a minute")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	t.m[tok] = consoleToken{vm: vm, expires: now.Add(TokenTTL)}
	return tok, nil
}

// redeem uses a token up: it's valid once, briefly, for one VM.
func (t *tokenTable) redeem(tok, vm string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, v := range t.m {
		if subtle.ConstantTimeCompare([]byte(k), []byte(tok)) == 1 {
			delete(t.m, k)
			return v.vm == vm && now.Before(v.expires)
		}
	}
	return false
}

// ConsoleArgs names a VM's console.
type ConsoleArgs struct {
	ID string `json:"id"`
}

// ConsoleToken is a one-time pass to a VM's console.
type ConsoleToken struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}

// Console issues a token for a running VM's console.
func (m *Manager) Console(ctx context.Context, a ConsoleArgs) (*ConsoleToken, error) {
	if _, err := m.find(ctx, a.ID); err != nil {
		return nil, err
	}
	if s := m.state(ctx, a.ID); s != "running" && s != "paused" {
		return nil, Problems{"start the VM to see its screen"}
	}
	tok, err := m.tokens.issue(a.ID, m.now())
	if err != nil {
		return nil, err
	}
	return &ConsoleToken{Token: tok, Expires: m.now().Add(TokenTTL)}, nil
}

// ConsoleOpenArgs redeems a token.
type ConsoleOpenArgs struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

// ConsoleOpen redeems a token and returns a connection to the VM's VNC
// server.
func (m *Manager) ConsoleOpen(ctx context.Context, a ConsoleOpenArgs) (*os.File, error) {
	if len(a.Token) != 64 || !m.tokens.redeem(a.Token, a.ID, m.now()) {
		return nil, Problems{"the console link has expired; open the console again"}
	}
	sock, err := m.vncSocket(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", m.sys(sock))
	if err != nil {
		return nil, fmt.Errorf("connecting to the VM's screen: %w", err)
	}
	f, err := conn.(*net.UnixConn).File()
	conn.Close()
	if err != nil {
		return nil, err
	}
	return f, nil
}

// vncSocket finds the VM's VNC socket in its running definition.
func (m *Manager) vncSocket(ctx context.Context, id string) (string, error) {
	out, err := m.virsh(ctx, "dumpxml", id)
	if err != nil {
		return "", fmt.Errorf("the VM isn't running: %w", err)
	}
	var d struct {
		Devices struct {
			Graphics []struct {
				Type   string `xml:"type,attr"`
				Socket string `xml:"socket,attr"`
				Listen []struct {
					Type   string `xml:"type,attr"`
					Socket string `xml:"socket,attr"`
				} `xml:"listen"`
			} `xml:"graphics"`
		} `xml:"devices"`
	}
	if err := xml.Unmarshal(out, &d); err != nil {
		return "", err
	}
	for _, g := range d.Devices.Graphics {
		if g.Type != "vnc" {
			continue
		}
		cands := []string{g.Socket}
		for _, l := range g.Listen {
			if l.Type == "socket" {
				cands = append(cands, l.Socket)
			}
		}
		for _, s := range cands {
			if okSocket(s) {
				return s, nil
			}
		}
	}
	return "", errors.New("the VM has no screen to show")
}

// okSocket accepts only libvirt's own socket folders.
func okSocket(p string) bool {
	if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return false
	}
	for _, dir := range []string{"/var/lib/libvirt/qemu/", "/run/libvirt/qemu/"} {
		if strings.HasPrefix(p, dir) {
			return true
		}
	}
	return false
}
