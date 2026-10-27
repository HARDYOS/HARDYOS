package netbird

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// This file is hardyd-priv's side: the NetBird client on this server. The
// netbird package (NetBird's official Debian package, pinned in the image)
// installs /usr/bin/netbird and netbird.service; the image leaves the
// service off until the server joins a NetBird network.

// Paths relative to Manager.Root.
const (
	// MarkerFile records that HardyOS joined this server to a NetBird
	// network (management URL and name), so the service comes back after
	// an update (a new boot environment has it disabled) and Leave knows
	// what it's leaving. It lives with NetBird's own state, which updates
	// carry over.
	MarkerFile = "var/lib/netbird/hardyos.json"
	binary     = "usr/bin/netbird"
	unit       = "netbird.service"
)

// DefaultManagementURL is Cade's NetBird server.
const DefaultManagementURL = "https://vpn.hardynetworks.net"

// ClientStatus is the NetBird client's state on this server.
type ClientStatus struct {
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
	// Joined: HardyOS joined this server to a NetBird network.
	Joined bool `json:"joined"`
	// Running: netbird.service is active.
	Running bool `json:"running"`
	// State: not_installed, off, connecting, connected, needs_login,
	// login_failed, session_expired, idle or unknown.
	State     string `json:"state"`
	Connected bool   `json:"connected"`
	// IP is this server's NetBird address and Network the NetBird network
	// it is in (100.x.0.0/16).
	IP                  string `json:"ip,omitempty"`
	Network             string `json:"network,omitempty"`
	FQDN                string `json:"fqdn,omitempty"`
	PeersTotal          int    `json:"peersTotal"`
	PeersConnected      int    `json:"peersConnected"`
	ManagementURL       string `json:"managementUrl,omitempty"`
	ManagementConnected bool   `json:"managementConnected"`
	Hostname            string `json:"hostname,omitempty"`
	Interface           string `json:"interface,omitempty"`
	// Problem says what's wrong in a sentence, if anything.
	Problem string `json:"problem,omitempty"`
}

// Settings are the client's settings as HardyOS set them.
type Settings struct {
	Installed      bool      `json:"installed"`
	Version        string    `json:"version,omitempty"`
	ManagementURL  string    `json:"managementUrl,omitempty"`
	Hostname       string    `json:"hostname,omitempty"`
	JoinedAt       time.Time `json:"joinedAt,omitzero"`
	ServiceEnabled bool      `json:"serviceEnabled"`
}

// JoinArgs joins this server to a NetBird network.
type JoinArgs struct {
	ManagementURL string `json:"managementUrl"`
	// SetupKey goes to `netbird up` in its environment (NB_SETUP_KEY), never
	// on a command line, and is never logged or returned.
	SetupKey string `json:"setupKey"`
	Hostname string `json:"hostname"`
}

// LeaveArgs leaves the NetBird network.
type LeaveArgs struct {
	// Confirm must be the management server's host name.
	Confirm string `json:"confirm"`
}

// LeaveResult says how leaving went.
type LeaveResult struct {
	Left  string `json:"left"`
	Notes string `json:"notes,omitempty"`
}

// marker is MarkerFile's content.
type marker struct {
	ManagementURL string    `json:"managementUrl"`
	Hostname      string    `json:"hostname"`
	JoinedAt      time.Time `json:"joinedAt"`
}

// Manager runs the NetBird client.
type Manager struct {
	Runner sysexec.Runner
	Root   string // "/" in production
	// Wait is how long Join waits for the NetBird daemon to answer after
	// starting it (default 20 s); Sleep is the pause between tries.
	Wait  time.Duration
	Sleep time.Duration
}

func (m *Manager) p(rel string) string { return filepath.Join(m.Root, rel) }

// ValidManagementURL checks a NetBird management URL and returns it
// normalized (scheme and host, an optional port, no path).
func ValidManagementURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.Scheme != "https" {
		return "", errors.New("the NetBird server's address must look like https://vpn.example.net")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
		return "", errors.New("the NetBird server's address is just https:// and its name (and a port, if it isn't 443)")
	}
	host := u.Hostname()
	if !validHostName(host) {
		if _, err := netip.ParseAddr(host); err != nil {
			return "", fmt.Errorf("%q isn't a host name", host)
		}
	}
	return "https://" + u.Host, nil
}

var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func validHostName(h string) bool {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "" || len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if !labelRE.MatchString(l) {
			return false
		}
	}
	return true
}

// ValidDNSLabel reports whether s is one lowercase DNS label (a peer's
// name, an app's or the desktop's name under the base domain).
func ValidDNSLabel(s string) bool { return labelRE.MatchString(s) }

// ValidDomain reports whether s is a lowercase DNS name with at least two
// labels (a base domain like home.example.net).
func ValidDomain(s string) bool {
	return s == strings.ToLower(s) && strings.Contains(s, ".") && validHostName(s) && !strings.HasSuffix(s, ".")
}

var setupKeyRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$`)

// ValidSetupKey checks a setup key's shape (NetBird's are UUIDs).
func ValidSetupKey(k string) bool { return setupKeyRE.MatchString(k) }

// netbirdStatus is the part of `netbird status --json` HardyOS reads
// (client/status/status.go: OutputOverview).
type netbirdStatus struct {
	Peers struct {
		Total     int `json:"total"`
		Connected int `json:"connected"`
	} `json:"peers"`
	CliVersion    string `json:"cliVersion"`
	DaemonVersion string `json:"daemonVersion"`
	DaemonStatus  string `json:"daemonStatus"`
	Management    struct {
		URL       string `json:"url"`
		Connected bool   `json:"connected"`
		Error     string `json:"error"`
	} `json:"management"`
	Signal struct {
		Connected bool   `json:"connected"`
		Error     string `json:"error"`
	} `json:"signal"`
	IP   string `json:"netbirdIp"`
	FQDN string `json:"fqdn"`
}

// ParseStatus reads `netbird status --json` into st.
func ParseStatus(raw []byte, st *ClientStatus) error {
	var s netbirdStatus
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("netbird status: %w", err)
	}
	st.Version = s.DaemonVersion
	if st.Version == "" {
		st.Version = s.CliVersion
	}
	st.PeersTotal, st.PeersConnected = s.Peers.Total, s.Peers.Connected
	st.ManagementURL = strings.TrimSuffix(strings.TrimSuffix(s.Management.URL, ":443"), "/")
	st.ManagementConnected = s.Management.Connected
	st.FQDN = strings.TrimSuffix(s.FQDN, ".")
	if s.IP != "" {
		if p, err := netip.ParsePrefix(s.IP); err == nil {
			st.IP, st.Network = p.Addr().String(), p.Masked().String()
		} else if a, err := netip.ParseAddr(s.IP); err == nil {
			st.IP = a.String()
		}
	}
	switch s.DaemonStatus {
	case "Connected":
		st.State = "connected"
	case "Connecting":
		st.State = "connecting"
	case "NeedsLogin":
		st.State = "needs_login"
	case "LoginFailed":
		st.State = "login_failed"
	case "SessionExpired":
		st.State = "session_expired"
	case "Idle":
		st.State = "idle"
	case "":
		// Older clients don't report it: go by the management connection.
		if s.Management.Connected {
			st.State = "connected"
		} else {
			st.State = "connecting"
		}
	default:
		st.State = "unknown"
	}
	st.Connected = st.State == "connected" && s.Management.Connected && st.IP != ""
	switch {
	case st.State == "needs_login" || st.State == "session_expired":
		st.Problem = "NetBird needs signing in again: leave the network and join with a new setup key."
	case st.State == "login_failed":
		st.Problem = "Signing in to NetBird failed: leave the network and join with a new setup key."
	case s.Management.Error != "":
		st.Problem = "Can't reach the NetBird server: " + clip(s.Management.Error)
	case !s.Management.Connected && st.State != "idle":
		st.Problem = "Not connected to the NetBird server yet."
	case s.Signal.Error != "":
		st.Problem = "NetBird's signal server: " + clip(s.Signal.Error)
	}
	return nil
}

func clip(s string) string { return Clip(s, 300) }

// Clip makes text that came from NetBird (an error message, a status line)
// safe to show: control characters become spaces, runs of spaces one, and
// at most n bytes are kept (on a rune boundary), with … when cut.
func Clip(s string, n int) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == ' ' || r == ' ' || r == utf8.RuneError {
			r = ' '
		}
		if r == ' ' {
			if space {
				continue
			}
			space = true
		} else {
			space = false
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	if len(out) <= n {
		return out
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(out[cut]) {
		cut--
	}
	return strings.TrimSpace(out[:cut]) + "…"
}

func (m *Manager) installed() bool {
	fi, err := os.Stat(m.p(binary))
	return err == nil && fi.Mode().IsRegular()
}

func (m *Manager) readMarker() (*marker, error) {
	b, err := os.ReadFile(m.p(MarkerFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var mk marker
	if err := json.Unmarshal(b, &mk); err != nil {
		return nil, fmt.Errorf("%s: %w", MarkerFile, err)
	}
	return &mk, nil
}

func (m *Manager) writeMarker(mk marker) error {
	b, _ := json.MarshalIndent(mk, "", "  ")
	path := m.p(MarkerFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (m *Manager) active(ctx context.Context) bool {
	res, err := m.Runner.Run(ctx, nil, "systemctl", "is-active", "--quiet", unit)
	return err == nil && res.ExitCode == 0
}

func (m *Manager) enabled(ctx context.Context) bool {
	res, err := m.Runner.Run(ctx, nil, "systemctl", "is-enabled", "--quiet", unit)
	return err == nil && res.ExitCode == 0
}

// Status reports the client's state.
func (m *Manager) Status(ctx context.Context) (*ClientStatus, error) {
	st := &ClientStatus{State: "not_installed", Interface: "wt0"}
	if !m.installed() {
		st.Problem = "The NetBird client isn't installed on this server."
		return st, nil
	}
	mk, err := m.readMarker()
	if err != nil {
		return nil, err
	}
	if mk != nil {
		st.Joined, st.Hostname, st.ManagementURL = true, mk.Hostname, mk.ManagementURL
	}
	st.Running = m.active(ctx)
	if !st.Running {
		st.State = "off"
		if st.Joined {
			st.Problem = "The NetBird service isn't running."
		}
		return st, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := sysexec.Output(ctx, m.Runner, "netbird", "status", "--json")
	if err != nil {
		st.State = "unknown"
		st.Problem = "The NetBird service isn't answering: " + clip(err.Error())
		return st, nil
	}
	joinedURL := st.ManagementURL
	if err := ParseStatus(out, st); err != nil {
		st.State, st.Problem = "unknown", clip(err.Error())
	}
	if st.ManagementURL == "" {
		st.ManagementURL = joinedURL
	}
	return st, nil
}

// Settings reports the client's settings.
func (m *Manager) Settings(ctx context.Context) (*Settings, error) {
	s := &Settings{Installed: m.installed()}
	if !s.Installed {
		return s, nil
	}
	if out, err := sysexec.Output(ctx, m.Runner, "netbird", "version"); err == nil {
		s.Version = strings.TrimSpace(string(out))
	}
	mk, err := m.readMarker()
	if err != nil {
		return nil, err
	}
	if mk != nil {
		s.ManagementURL, s.Hostname, s.JoinedAt = mk.ManagementURL, mk.Hostname, mk.JoinedAt
	}
	s.ServiceEnabled = m.enabled(ctx)
	return s, nil
}

func (m *Manager) sleep(ctx context.Context) {
	d := m.Sleep
	if d == 0 {
		d = 500 * time.Millisecond
	}
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// ErrAlreadyJoined: leave first.
var ErrAlreadyJoined = errors.New("this server is already in a NetBird network: leave it first")

// ErrNotInstalled: the image has no NetBird client.
var ErrNotInstalled = errors.New("the NetBird client isn't installed on this server")

// Join starts the NetBird service and signs this server in with a setup
// key. The key reaches `netbird up` only through its environment.
func (m *Manager) Join(ctx context.Context, a JoinArgs) (*ClientStatus, error) {
	mgmt, err := ValidManagementURL(a.ManagementURL)
	if err != nil {
		return nil, &ValidationError{err.Error()}
	}
	host := strings.ToLower(strings.TrimSpace(a.Hostname))
	if !ValidDNSLabel(host) {
		return nil, &ValidationError{"the server's name in NetBird must be letters, digits and dashes (like nas)"}
	}
	if !ValidSetupKey(a.SetupKey) {
		return nil, &ValidationError{"that doesn't look like a NetBird setup key"}
	}
	if !m.installed() {
		return nil, ErrNotInstalled
	}
	if mk, err := m.readMarker(); err != nil {
		return nil, err
	} else if mk != nil {
		return nil, ErrAlreadyJoined
	}
	if _, err := sysexec.Output(ctx, m.Runner, "systemctl", "enable", "--now", unit); err != nil {
		return nil, fmt.Errorf("starting NetBird: %w", err)
	}
	wait := m.Wait
	if wait == 0 {
		wait = 20 * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		res, err := m.Runner.Run(ctx, nil, "netbird", "status", "--json")
		if err == nil && res.ExitCode == 0 {
			var st ClientStatus
			if ParseStatus(res.Stdout, &st) == nil && st.Connected {
				return nil, ErrAlreadyJoined // joined outside HardyOS
			}
			break
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if time.Now().After(deadline) {
			return nil, errors.New("the NetBird service didn't start")
		}
		m.sleep(ctx)
	}
	upCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	res, err := sysexec.RunEnv(upCtx, m.Runner, []string{"NB_SETUP_KEY=" + a.SetupKey}, nil, "netbird", UpArgs(mgmt, host)...)
	if err == nil && res.ExitCode != 0 {
		msg := clip(strings.ReplaceAll(string(res.Stderr)+" "+string(res.Stdout), a.SetupKey, "…"))
		err = errors.New("NetBird refused to join: " + msg)
	}
	if err != nil {
		_, _ = m.Runner.Run(context.WithoutCancel(ctx), nil, "netbird", "down")
		_, _ = m.Runner.Run(context.WithoutCancel(ctx), nil, "systemctl", "disable", "--now", unit)
		return nil, err
	}
	if err := m.writeMarker(marker{ManagementURL: mgmt, Hostname: host, JoinedAt: time.Now().UTC()}); err != nil {
		return nil, err
	}
	return m.Status(ctx)
}

// UpArgs is `netbird up`'s command line. Besides the management server and
// the name, it refuses what NetBird's management server would push to this
// peer and that would change the server's own networking (flag names as in
// NetBird 0.81.5, client/cmd/system.go; the daemon keeps them in its
// profile, so they survive restarts):
//
//   - --disable-client-routes: no routes from NetBird (a network route or
//     exit node set in NetBird's dashboard could otherwise send this
//     server's traffic, the LAN's included, through another peer);
//   - --disable-server-routes: this server never routes for other peers
//     (it isn't a gateway into the home network);
//   - --disable-dns: NetBird doesn't take over the server's resolver (the
//     domain controller and the setup check rely on it).
//
// Inbound connections stay allowed: NetBird's reverse proxy must reach
// the app gateway on port 44200 (NetBird's policies decide which peers can).
func UpArgs(managementURL, hostname string) []string {
	return []string{"up", "--management-url", managementURL, "--hostname", hostname,
		"--disable-client-routes", "--disable-server-routes", "--disable-dns"}
}

// Leave signs this server out of NetBird (deleting it as a peer when the
// server can be reached) and turns the service off.
func (m *Manager) Leave(ctx context.Context, a LeaveArgs) (*LeaveResult, error) {
	mk, err := m.readMarker()
	if err != nil {
		return nil, err
	}
	if mk == nil {
		return nil, &ValidationError{"this server isn't in a NetBird network"}
	}
	u, _ := url.Parse(mk.ManagementURL)
	if u == nil || !strings.EqualFold(strings.TrimSpace(a.Confirm), u.Hostname()) {
		return nil, &ValidationError{"type the NetBird server's name (" + hostOf(mk.ManagementURL) + ") to confirm"}
	}
	var notes []string
	if res, err := m.Runner.Run(ctx, nil, "netbird", "down"); err != nil || res.ExitCode != 0 {
		notes = append(notes, "netbird down didn't finish cleanly")
	}
	// logout is deregister's old name; both versions know it.
	if res, err := m.Runner.Run(ctx, nil, "netbird", "logout"); err != nil || res.ExitCode != 0 {
		notes = append(notes, "couldn't remove this server from NetBird's peer list (remove it in NetBird's dashboard)")
	}
	if _, err := sysexec.Output(ctx, m.Runner, "systemctl", "disable", "--now", unit); err != nil {
		notes = append(notes, "couldn't turn the NetBird service off: "+clip(err.Error()))
	}
	if err := os.Remove(m.p(MarkerFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return &LeaveResult{Left: mk.ManagementURL, Notes: strings.Join(notes, "; ")}, nil
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Hostname()
	}
	return raw
}

// OnStart starts the NetBird service if HardyOS joined this server (a new
// version's boot environment has it off).
func (m *Manager) OnStart(ctx context.Context) error {
	if !m.installed() {
		return nil
	}
	mk, err := m.readMarker()
	if err != nil || mk == nil {
		return err
	}
	if m.active(ctx) {
		return nil
	}
	_, err = sysexec.Output(ctx, m.Runner, "systemctl", "enable", "--now", unit)
	return err
}

// ValidationError is a request HardyOS can't act on (the caller's to fix).
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }
