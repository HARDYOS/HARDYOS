// Package domain runs the HardyOS Active Directory domain controller: Samba 4
// in its own network namespace with its own address on the LAN, its data in
// one folder (a ZFS dataset shared by every boot environment), managed only
// by hardyd-priv.
//
// Layout:
//
//	/var/lib/hardyos-dc/            all of the DC's state (rpool/hardyos-dc)
//	  hardyos-dc.json               HardyOS settings for the DC
//	  etc/smb.conf                  written by HardyOS
//	  private/ state/ cache/ ...    Samba's databases
//	  run/                          bound over /run/samba inside the DC
//	/run/netns/hardyos-dc           the DC's network namespace
//	hdc0 (inside it)                macvlan on the LAN port, the DC's address
//	hdc-shim (on the host)          macvlan so the NAS itself can reach the DC
//
// The NAS can't talk to a macvlan child through the parent port, so a second
// macvlan (hdc-shim) on the host carries a route to the DC's address.
package domain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Names. The Manager uses these unless its own fields say otherwise (tests
// run two domain controllers on one machine).
const (
	DataDir          = "/var/lib/hardyos-dc"
	DefaultNamespace = "hardyos-dc"
	DCLink           = "hdc0" // inside the DC's namespace
	DefaultShim      = "hdc-shim"
	DefaultShimAddr  = "169.254.250.1"
	DefaultService   = "hardyos-dc.service"
	AdminTool        = "/usr/lib/hardyos/hardyos-dc-admin"
	DCHostName       = "dc1" // the first DC; others are dc2, dc3...
	configName       = "hardyos-dc.json"
)

// Config is what HardyOS knows about the domain it created.
type Config struct {
	Domain     string    `json:"domain"`  // home.hardynetworks.net
	Realm      string    `json:"realm"`   // HOME.HARDYNETWORKS.NET
	NetBIOS    string    `json:"netbios"` // HOME
	DCName     string    `json:"dcName"`  // dc1.home.hardynetworks.net
	Address    string    `json:"address"` // 192.168.1.20/24
	Gateway    string    `json:"gateway"`
	Parent     string    `json:"parent"` // LAN interface the DC sits on
	MAC        string    `json:"mac"`
	Forwarders []string  `json:"forwarders"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"createdAt"`
	// Host is this DC's short name (dc1, dc2…); empty means dc1.
	Host string `json:"host,omitempty"`
	// Joined is true when this DC joined an existing domain rather than
	// creating it.
	Joined bool `json:"joined,omitempty"`
	// Others are the domain's other DCs, as their DNS lists them.
	Others []DC `json:"others,omitempty"`
	// AdminsGroupSID is the objectSid of the HardyOS Admins group, recorded
	// when HardyOS created it or an administrator adopted an existing one
	// (SetUpAdminsGroup). Its members are HardyOS administrators whatever
	// the group is called now; a group that merely has the name isn't.
	AdminsGroupSID string `json:"adminsGroupSid,omitempty"`
}

// DC is one domain controller.
type DC struct {
	Name    string `json:"name"`    // dc2.home.hardynetworks.net
	Address string `json:"address"` // 192.168.1.21
}

// HostName is the DC's short name.
func (c Config) HostName() string {
	if c.Host != "" {
		return c.Host
	}
	return DCHostName
}

// DNSServers lists every DC's address, this one first: what devices should
// use for DNS.
func (c Config) DNSServers() []string {
	out := []string{c.IP()}
	for _, o := range c.Others {
		if o.Address != "" && o.Address != c.IP() {
			out = append(out, o.Address)
		}
	}
	return out
}

// IP is the DC's address without the prefix.
func (c Config) IP() string {
	p, err := netip.ParsePrefix(c.Address)
	if err != nil {
		return ""
	}
	return p.Addr().String()
}

// Status is what the Domain page shows.
type Status struct {
	Provisioned bool    `json:"provisioned"`
	Config      *Config `json:"config"`
	Running     bool    `json:"running"`
	// Responding means the NAS got an answer from the DC's DNS for the
	// domain's LDAP service: network, shim route and Samba all work.
	Responding bool `json:"responding"`
	// Problem explains why the DC isn't working, if it isn't.
	Problem string `json:"problem"`
	// Available is false when this build has no Samba (dev machines).
	Available bool `json:"available"`
}

// Suggestion pre-fills the setup wizard from the NAS's own network.
type Suggestion struct {
	Parent      string   `json:"parent"`
	HostAddress string   `json:"hostAddress"` // CIDR
	Gateway     string   `json:"gateway"`
	DNS         []string `json:"dns"`
	Address     string   `json:"address"` // a free address for the DC, CIDR
}

// ProvisionArgs creates the domain.
type ProvisionArgs struct {
	Domain        string   `json:"domain"`
	NetBIOS       string   `json:"netbios,omitempty"`
	AdminPassword string   `json:"adminPassword"`
	Address       string   `json:"address"` // CIDR, or a plain IP on the NAS's subnet
	Gateway       string   `json:"gateway,omitempty"`
	Forwarders    []string `json:"forwarders,omitempty"`
}

// ValidationError is a problem with the caller's input.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(format string, args ...any) error {
	return &ValidationError{Msg: fmt.Sprintf(format, args...)}
}

// ErrNotProvisioned means there's no domain yet.
var ErrNotProvisioned = errors.New("there's no domain yet: set one up first")

// Manager owns the domain controller. All methods are safe to call
// concurrently.
type Manager struct {
	Runner sysexec.Runner
	Log    *slog.Logger
	// Root prefixes every path (tests use a temp dir). "/" in production.
	Root string
	// DataDir overrides DataDir (tests).
	DataDir string
	// Namespace, Shim, ShimAddr and Service override the defaults (tests run
	// two DCs on one machine).
	Namespace, Shim, ShimAddr, Service string
	// DNSChanged is called after the domain's DNS servers may have changed
	// (created, joined, deleted, another DC appeared), so the NAS's own
	// resolver can follow.
	DNSChanged func(ctx context.Context)

	mu sync.Mutex
	// lastParent is the LAN interface the DC was last attached to, so a
	// network change that moves the NAS (a new bond, say) moves the DC too.
	lastParent string
	// othersChecked is when the list of other DCs was last refreshed.
	othersChecked time.Time

	// netMu guards the DC's links (macvlan and shim) and held; it's taken
	// on its own, never while waiting for the network manager.
	netMu sync.Mutex
	// held: a bridge is being added or removed, so the DC stays off the
	// LAN until it's done (HoldNetwork / ReleaseNetwork).
	held bool
}

func or(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func (m *Manager) ns() string       { return or(m.Namespace, DefaultNamespace) }
func (m *Manager) shim() string     { return or(m.Shim, DefaultShim) }
func (m *Manager) shimAddr() string { return or(m.ShimAddr, DefaultShimAddr) }
func (m *Manager) service() string  { return or(m.Service, DefaultService) }

func (m *Manager) dnsChanged(ctx context.Context) {
	if m.DNSChanged != nil {
		m.DNSChanged(ctx)
	}
}

// DNSServers is what the NAS should use for DNS while a domain is running:
// its DCs and the domain to search. Empty when there's no running domain.
func (m *Manager) DNSServers() (servers []string, domain string) {
	c, err := m.Load()
	if err != nil || c == nil || !c.Enabled {
		return nil, ""
	}
	return c.DNSServers(), c.Domain
}

func (m *Manager) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

func (m *Manager) path(p string) string { return filepath.Join(m.Root, p) }

// Dir is the DC's data folder as seen by commands (without Root).
func (m *Manager) Dir() string {
	if m.DataDir != "" {
		return m.DataDir
	}
	return DataDir
}

func (m *Manager) dataPath(rel ...string) string {
	return m.path(filepath.Join(append([]string{m.Dir()}, rel...)...))
}

// SmbConf is the DC's smb.conf as seen by commands.
func (m *Manager) SmbConf() string { return filepath.Join(m.Dir(), "etc", "smb.conf") }

// Available reports whether Samba's DC is installed.
func (m *Manager) Available() bool {
	_, err := os.Stat(m.path("/usr/sbin/samba"))
	_, err2 := os.Stat(m.path(AdminTool))
	return err == nil && err2 == nil
}

// Load reads the domain's settings; nil, nil when there's no domain.
func (m *Manager) Load() (*Config, error) {
	b, err := os.ReadFile(m.dataPath(configName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("reading the domain settings: %w", err)
	}
	return &c, nil
}

func (m *Manager) save(c *Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	p := m.dataPath(configName)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Status reports on the domain.
func (m *Manager) Status(ctx context.Context) (*Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status(ctx)
}

func (m *Manager) status(ctx context.Context) (*Status, error) {
	st := &Status{Available: m.Available()}
	c, err := m.Load()
	if err != nil {
		return nil, err
	}
	if c == nil {
		return st, nil
	}
	st.Provisioned, st.Config = true, c
	st.Running = m.serviceActive(ctx)
	switch {
	case !c.Enabled:
		st.Problem = "The domain controller is stopped."
	case !st.Running:
		st.Problem = "The domain controller isn't running. HardyOS keeps trying to start it; in the Terminal, journalctl -u hardyos-dc shows why."
	default:
		if p := m.networkProblem(ctx, c); p != "" {
			st.Problem = p
		} else if st.Responding = m.responding(ctx, c); !st.Responding {
			st.Problem = "The domain controller is running but not answering yet. If it just started, give it a minute."
		}
	}
	return st, nil
}

// responding asks the DC's DNS for the domain's LDAP service record.
func (m *Manager) responding(ctx context.Context, c *Config) bool {
	res, err := m.Runner.Run(ctx, nil, "dig", "+short", "+time=2", "+tries=1", "@"+c.IP(), "SRV", "_ldap._tcp."+c.Domain)
	return err == nil && res.ExitCode == 0 && strings.Contains(string(res.Stdout), "389")
}

func (m *Manager) serviceActive(ctx context.Context) bool {
	res, err := m.Runner.Run(ctx, nil, "systemctl", "is-active", "--quiet", m.service())
	return err == nil && res.ExitCode == 0
}

// ---- validation ----------------------------------------------------------

var (
	labelRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	netbiosRE  = regexp.MustCompile(`^[A-Z0-9][A-Z0-9-]{0,14}$`)
	usernameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$`)
	groupRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}[A-Za-z0-9._-]$|^[A-Za-z0-9]$`)
)

// reserved top-level names that break Macs, certificates or the internet.
var badSuffix = []string{".local", ".localhost", ".invalid", ".test", ".example"}

// NormalizeDomain checks a DNS domain name for the domain and lower-cases it.
func NormalizeDomain(d string) (string, error) {
	d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
	if d == "" {
		return "", invalid("enter a domain name, for example home.yourname.net")
	}
	if len(d) > 64 {
		return "", invalid("the domain name is too long (64 characters at most)")
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", invalid("use a name with at least two parts, like home.yourname.net")
	}
	for _, l := range labels {
		if !labelRE.MatchString(l) {
			return "", invalid("%q isn't a valid part of a domain name: use letters, digits and dashes", l)
		}
	}
	for _, s := range badSuffix {
		if strings.HasSuffix(d, s) {
			return "", invalid("names ending in %s cause problems with Macs and certificates; use a subdomain of a domain you own, like home.yourname.net", s)
		}
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", invalid("the domain name can't be an address")
	}
	return d, nil
}

// DefaultNetBIOS derives the short (pre-Windows 2000) domain name.
func DefaultNetBIOS(domain string) string {
	first := strings.ToUpper(strings.Split(domain, ".")[0])
	if len(first) > 15 {
		first = first[:15]
	}
	return strings.Trim(first, "-")
}

// NormalizeNetBIOS checks the short domain name.
func NormalizeNetBIOS(n string) (string, error) {
	n = strings.ToUpper(strings.TrimSpace(n))
	if !netbiosRE.MatchString(n) || strings.HasSuffix(n, "-") {
		return "", invalid("the short domain name must be 1 to 15 letters, digits or dashes")
	}
	if strings.EqualFold(n, DCHostName) {
		return "", invalid("the short domain name can't be %s, that's the domain controller's own name", strings.ToUpper(DCHostName))
	}
	return n, nil
}

// CheckPassword applies the domain's default complexity rules up front, so
// mistakes show before a 30-second setup.
func CheckPassword(pw, username string) error {
	if len(pw) < 8 {
		return invalid("the password needs at least 8 characters")
	}
	if len(pw) > 256 {
		return invalid("the password is too long")
	}
	var lower, upper, digit, other bool
	for _, r := range pw {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			n++
		}
	}
	if n < 3 {
		return invalid("the password needs three of: lower case, upper case, digits, symbols")
	}
	if username != "" && len(username) >= 3 && strings.Contains(strings.ToLower(pw), strings.ToLower(username)) {
		return invalid("the password can't contain the user name")
	}
	return nil
}

// CheckUsername checks a domain account name.
func CheckUsername(u string) error {
	if !usernameRE.MatchString(u) || strings.HasSuffix(u, ".") {
		return invalid("user names are 1 to 20 letters, digits, dots, dashes or underscores")
	}
	return nil
}

// CheckGroupName checks a group name.
func CheckGroupName(g string) error {
	if !groupRE.MatchString(g) {
		return invalid("group names are up to 64 letters, digits, spaces, dots, dashes or underscores")
	}
	return nil
}
