// Package smb runs HardyOS's SMB file server: the host's own Samba (smbd
// and winbindd) as a member of the domain, separate from the domain
// controller's Samba (which lives in its own network namespace). It
// generates /etc/samba/smb.conf from the shared folders and their sharing
// settings, maps their access rules to Samba's user lists and to POSIX ACL
// entries on disk, keeps home folders, the recycle bins and the Avahi
// advertisement, and joins and leaves the domain. It runs in hardyd-priv.
// See docs/plans/file-sharing.md section 1 and docs/file-sharing.md.
//
// Layout:
//
//	/etc/samba/smb.conf             written by HardyOS
//	/var/lib/hardyos-files/         rpool/hardyos-files, shared by every boot environment
//	  settings.json                 File Services settings
//	  state.json                    domain membership, applied permissions
//	  samba/{private,state,cache,lock}  Samba's databases (machine account, ID map)
//	  samba/krb5.keytab             the machine's Kerberos keys
//	/etc/krb5.conf                  the domain's realm
//	/etc/avahi/services/hardyos-smb.service
package smb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Defaults.
const (
	DataDir      = "/var/lib/hardyos-files"
	ConfPath     = "/etc/samba/smb.conf"
	Krb5Conf     = "/etc/krb5.conf"
	NSSwitch     = "/etc/nsswitch.conf"
	AvahiService = "/etc/avahi/services/hardyos-smb.service"

	SmbdUnit    = "smbd.service"
	WinbindUnit = "winbind.service"
	NmbdUnit    = "nmbd.service"

	// RecycleDays: files in a recycle bin longer than this are removed.
	RecycleDays = 30
	// HomesInterval: how often home folders are made for new accounts.
	HomesInterval = 10 * time.Minute
)

// Domain is what the file server needs to know about the domain.
type Domain struct {
	Domain  string `json:"domain"`  // home.example.net
	Realm   string `json:"realm"`   // HOME.EXAMPLE.NET
	NetBIOS string `json:"netbios"` // HOME
	// DCs are domain controllers to use first (this server's own DC);
	// empty means DNS finds them.
	DCs []string `json:"dcs,omitempty"`
	// AdminsGroupSID is the HardyOS Admins group (see decision 79).
	AdminsGroupSID string `json:"adminsGroupSid,omitempty"`
}

// HomesSettings: a home folder per domain account.
type HomesSettings struct {
	Enabled    bool   `json:"enabled"`
	Pool       string `json:"pool"`
	QuotaBytes uint64 `json:"quotaBytes"` // 0 = no limit
}

// Settings are Control Panel > File Services.
type Settings struct {
	SMBEnabled bool          `json:"smbEnabled"`
	Homes      HomesSettings `json:"homes"`
}

// ShareStatus is how one shared folder is offered over SMB.
type ShareStatus struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	SMB              bool   `json:"smb"`
	TimeMachine      bool   `json:"timeMachine"`
	PreviousVersions bool   `json:"previousVersions"`
	Recycle          bool   `json:"recycle"`
	Guest            bool   `json:"guest"`
	// Available: SMB on and the folder mounted.
	Available bool `json:"available"`
	// Skipped names rules that can't apply (another domain, a HardyOS account).
	Skipped []string `json:"skipped"`
}

// Status is what the File Services page shows.
type Status struct {
	// Available is false when this build has no Samba file server.
	Available bool `json:"available"`
	Joined    bool `json:"joined"`
	// Domain is the domain the server is a member of (when joined).
	Domain *Domain `json:"domain"`
	// LocalDomain is the domain this server's own DC runs (it can join it
	// with one click).
	LocalDomain string        `json:"localDomain"`
	ServerName  string        `json:"serverName"` // HARDYOS
	HostName    string        `json:"hostName"`   // hardyos.home.example.net
	Running     bool          `json:"running"`    // smbd
	Winbind     bool          `json:"winbind"`    // winbindd answers and trusts the domain
	Problem     string        `json:"problem"`
	Settings    Settings      `json:"settings"`
	Shares      []ShareStatus `json:"shares"`
	Addresses   []string      `json:"addresses"`
	JoinedAt    *time.Time    `json:"joinedAt,omitempty"`
}

// JoinArgs joins the domain.
type JoinArgs struct {
	// Domain is the DNS name; empty means this server's own DC's domain.
	Domain        string `json:"domain,omitempty"`
	AdminUser     string `json:"adminUser,omitempty"` // default Administrator
	AdminPassword string `json:"adminPassword"`
}

// LeaveArgs leaves the domain. Without a password only this server
// forgets the domain (its computer account stays in the domain).
type LeaveArgs struct {
	Confirm       bool   `json:"confirm"`
	AdminUser     string `json:"adminUser,omitempty"`
	AdminPassword string `json:"adminPassword,omitempty"`
}

// SettingsArgs changes settings; nil fields keep their values.
type SettingsArgs struct {
	SMBEnabled *bool          `json:"smbEnabled,omitempty"`
	Homes      *HomesSettings `json:"homes,omitempty"`
}

// ShareSource lists shared folders (shares.Manager).
type ShareSource interface {
	List(ctx context.Context) ([]shares.Share, error)
}

// ValidationError is the caller's mistake.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(format string, a ...any) error {
	return &ValidationError{Msg: fmt.Sprintf(format, a...)}
}

// Manager runs the file server. Its methods are safe to call concurrently.
type Manager struct {
	Runner sysexec.Runner
	Log    *slog.Logger
	Shares ShareSource
	// LocalDomain is the domain this server's own DC runs, or nil.
	LocalDomain func() *Domain
	// Addresses are this server's LAN addresses (registered in the domain's
	// DNS and shown in "how to connect").
	Addresses func(ctx context.Context) []string

	// Paths and names; empty means the defaults (tests change them).
	DataDir, ConfPath, Krb5Conf, NSSwitch, AvahiService string
	ServerName                                          string
	// Dirs overrides Samba's folders (tests); nil = under DataDir/samba.
	Dirs *Dirs
	Port int // 445
	// Installed reports whether Samba's file server is installed.
	Installed func() bool
	// NoDataset skips creating rpool/hardyos-files (tests).
	NoDataset bool
	// Now is the clock (tests).
	Now func() time.Time
	// walk applies ACLs below a share's root; shares.ApplyPeopleTree
	// unless a test sets it.
	walk func(ctx context.Context, root string, p shares.PeopleACL) (shares.PeopleStats, error)
	// resolver overrides name lookups (tests).
	resolver Resolver

	mu        sync.Mutex // one change at a time
	stateMu   sync.Mutex // state.json
	bgMu      sync.Mutex
	bg        map[string]*bgWalk
	wg        sync.WaitGroup
	lastHomes time.Time
	released  map[string]bool // shares being deleted (m.mu)
}

type bgWalk struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func (m *Manager) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) dataDir() string  { return or(m.DataDir, DataDir) }
func (m *Manager) confPath() string { return or(m.ConfPath, ConfPath) }
func (m *Manager) krb5Conf() string { return or(m.Krb5Conf, Krb5Conf) }
func (m *Manager) nssPath() string  { return or(m.NSSwitch, NSSwitch) }
func (m *Manager) avahiPath() string {
	return or(m.AvahiService, AvahiService)
}
func (m *Manager) port() int {
	if m.Port > 0 {
		return m.Port
	}
	return 445
}

func (m *Manager) dirs() Dirs {
	if m.Dirs != nil {
		return *m.Dirs
	}
	s := filepath.Join(m.dataDir(), "samba")
	return Dirs{
		Private: filepath.Join(s, "private"), State: filepath.Join(s, "state"),
		Cache: filepath.Join(s, "cache"), Lock: filepath.Join(s, "lock"),
		Keytab: filepath.Join(s, "krb5.keytab"),
	}
}

func (m *Manager) installed() bool {
	if m.Installed != nil {
		return m.Installed()
	}
	for _, p := range []string{"/usr/sbin/smbd", "/usr/sbin/winbindd", "/usr/bin/net"} {
		if _, err := os.Stat(p); err != nil {
			return false
		}
	}
	return true
}

// ---- settings and state ----------------------------------------------------

type state struct {
	Joined     bool      `json:"joined"`
	Domain     Domain    `json:"domain"`
	ServerName string    `json:"serverName"`
	JoinedAt   time.Time `json:"joinedAt"`
	// ACL: per share dataset, the hash of the people entries its whole
	// tree was given.
	ACL map[string]string `json:"acl,omitempty"`
	// RecycleCleaned is when the recycle bins were last emptied of old files.
	RecycleCleaned time.Time `json:"recycleCleaned"`
}

func defaultSettings() Settings { return Settings{SMBEnabled: true} }

func (m *Manager) readJSON(name string, v any) error {
	b, err := os.ReadFile(filepath.Join(m.dataDir(), name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func (m *Manager) writeJSON(name string, v any) error {
	if err := os.MkdirAll(m.dataDir(), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(m.dataDir(), name), append(b, '\n'), 0o600)
}

func (m *Manager) loadSettings() Settings {
	s := defaultSettings()
	if err := m.readJSON("settings.json", &s); err != nil {
		m.log().Warn("file services settings are unreadable; using defaults", "err", err)
		return defaultSettings()
	}
	return s
}

func (m *Manager) loadState() state {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	return m.loadStateLocked()
}

func (m *Manager) loadStateLocked() state {
	var s state
	if err := m.readJSON("state.json", &s); err != nil {
		m.log().Warn("file services state is unreadable", "err", err)
	}
	if s.ACL == nil {
		s.ACL = map[string]string{}
	}
	return s
}

func (m *Manager) updateState(fn func(*state)) error {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	s := m.loadStateLocked()
	fn(&s)
	return m.writeJSON("state.json", s)
}

func writeFileAtomic(p string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp := p + ".hardyos-tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// ensureDataDir makes the file server's folder: its own dataset on a ZFS
// root (rpool/hardyos-files), so every boot environment shares the
// machine account and ID map, like the DC's folder.
func (m *Manager) ensureDataDir(ctx context.Context) error {
	dir := m.dataDir()
	if !m.NoDataset {
		if out, err := sysexec.Output(ctx, m.Runner, "findmnt", "-n", "-o", "FSTYPE,SOURCE", "--target", "/"); err == nil {
			if f := strings.Fields(string(out)); len(f) == 2 && f[0] == "zfs" {
				pool, _, _ := strings.Cut(f[1], "/")
				ds := pool + "/hardyos-files"
				if res, err := m.Runner.Run(ctx, nil, "zfs", "list", "-H", "-o", "name", ds); err != nil || res.ExitCode != 0 {
					if _, err := sysexec.Output(ctx, m.Runner, "zfs", "create", "-o", "mountpoint="+dir, "-o", "canmount=on", ds); err != nil {
						return fmt.Errorf("creating the file server's dataset: %w", err)
					}
				}
			}
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	d := m.dirs()
	for _, p := range []string{d.Private, d.State, d.Cache, d.Lock} {
		if p != "" {
			if err := os.MkdirAll(p, 0o755); err != nil {
				return err
			}
		}
	}
	if d.Private != "" {
		_ = os.Chmod(d.Private, 0o700)
	}
	return nil
}

// ---- names -----------------------------------------------------------------

var (
	labelRE   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	netbiosRE = regexp.MustCompile(`^[A-Z0-9][A-Z0-9-]{0,14}$`)
	adminRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,19}$`)
)

// NormalizeDomain checks a DNS domain name and lower-cases it.
func NormalizeDomain(d string) (string, error) {
	d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
	labels := strings.Split(d, ".")
	if d == "" || len(d) > 64 || len(labels) < 2 {
		return "", invalid("enter the domain's name, like home.yourname.net")
	}
	for _, l := range labels {
		if !labelRE.MatchString(l) {
			return "", invalid("%q isn't a valid domain name", d)
		}
	}
	return d, nil
}

// serverName is this server's NetBIOS name, from its host name.
func (m *Manager) serverName() string {
	n := m.ServerName
	if n == "" {
		n, _ = os.Hostname()
	}
	n, _, _ = strings.Cut(n, ".")
	n = strings.ToUpper(n)
	n = strings.Map(func(r rune) rune {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, n)
	if len(n) > 15 {
		n = n[:15]
	}
	n = strings.Trim(n, "-")
	if n == "" {
		n = "HARDYOS"
	}
	return n
}

// ---- commands --------------------------------------------------------------

func (m *Manager) systemctl(ctx context.Context, args ...string) error {
	_, err := sysexec.Output(ctx, m.Runner, "systemctl", args...)
	return err
}

func (m *Manager) active(ctx context.Context, unit string) bool {
	res, err := m.Runner.Run(ctx, nil, "systemctl", "is-active", "--quiet", unit)
	return err == nil && res.ExitCode == 0
}

// net runs Samba's net tool with this server's config.
func (m *Manager) net(ctx context.Context, args ...string) ([]byte, error) {
	return sysexec.Output(ctx, m.Runner, "net", append(args, "-s", m.confPath())...)
}

// netWithPassword runs net as an administrator. The password goes to net
// on stdin (PASSWD_FD=0), never on its command line.
func (m *Manager) netWithPassword(ctx context.Context, user, password string, args ...string) ([]byte, error) {
	return sysexec.OutputEnv(ctx, m.Runner, []string{"PASSWD_FD=0"}, []byte(password+"\n"),
		"net", append(args, "-s", m.confPath(), "-U", user)...)
}

func badCredentials(err error) bool {
	var ce *sysexec.CommandError
	if !errors.As(err, &ce) {
		return false
	}
	t := strings.ToLower(string(ce.Result.Stderr) + string(ce.Result.Stdout))
	for _, s := range []string{"logon failure", "invalid credentials", "the attempted logon is invalid", "nt_status_logon_failure", "wrong_password", "preauthentication failed", "client not found"} {
		if strings.Contains(t, s) {
			return true
		}
	}
	return false
}

// winbindOK asks winbindd whether the machine account still works.
func (m *Manager) winbindOK(ctx context.Context) bool {
	res, err := m.Runner.Run(ctx, nil, "wbinfo", "-t")
	return err == nil && res.ExitCode == 0
}

func (m *Manager) winbindRunning(ctx context.Context) bool {
	res, err := m.Runner.Run(ctx, nil, "wbinfo", "-p")
	return err == nil && res.ExitCode == 0
}

func (m *Manager) waitWinbind(ctx context.Context, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		if m.winbindRunning(ctx) {
			return true
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Second):
		}
	}
}

// ---- name lookups ----------------------------------------------------------

// nssResolver looks names up through NSS (winbind).
type nssResolver struct {
	ctx context.Context
	r   sysexec.Runner
}

func (n nssResolver) lookup(db, name string) (uint32, error) {
	res, err := n.r.Run(n.ctx, nil, "getent", db, name)
	if err != nil {
		return 0, err
	}
	switch res.ExitCode {
	case 0:
	case 2: // not found
		return 0, &ErrUnknownName{Name: name}
	default:
		return 0, fmt.Errorf("looking up %s: getent exited %d", name, res.ExitCode)
	}
	f := strings.Split(strings.TrimSpace(strings.SplitN(string(res.Stdout), "\n", 2)[0]), ":")
	if len(f) < 3 {
		return 0, fmt.Errorf("looking up %s: unexpected answer", name)
	}
	id, err := strconv.ParseUint(f[2], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("looking up %s: %v", name, err)
	}
	return uint32(id), nil
}

func (n nssResolver) UserID(name string) (uint32, error)  { return n.lookup("passwd", name) }
func (n nssResolver) GroupID(name string) (uint32, error) { return n.lookup("group", name) }

var sidRE = regexp.MustCompile(`^S-1-5-21(-[0-9]{1,10}){4}$`)

func (n nssResolver) GroupIDBySID(sid string) (uint32, error) {
	if !sidRE.MatchString(sid) {
		return 0, &ErrUnknownName{Name: sid}
	}
	res, err := n.r.Run(n.ctx, nil, "wbinfo", "--sid-to-gid", sid)
	if err != nil {
		return 0, err
	}
	if res.ExitCode != 0 {
		return 0, &ErrUnknownName{Name: sid}
	}
	id, err := strconv.ParseUint(strings.TrimSpace(string(res.Stdout)), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("the group %s: %v", sid, err)
	}
	return uint32(id), nil
}

func (m *Manager) names(ctx context.Context) Resolver {
	if m.resolver != nil {
		return m.resolver
	}
	return nssResolver{ctx: ctx, r: m.Runner}
}
