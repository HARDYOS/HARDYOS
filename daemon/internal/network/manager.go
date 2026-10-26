package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hardyos/hardyos/daemon/internal/rootfile"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// DefaultRevertAfter is how long new network settings have to be confirmed
// from the web UI before they're undone.
const DefaultRevertAfter = 3 * time.Minute

// Manager applies network and time settings. It runs in hardyd-priv (root).
type Manager struct {
	Runner sysexec.Runner
	Root   string // "/" in production; a temp dir in tests
	// StateDir keeps the saved settings and any change waiting for
	// confirmation (default /var/lib/hardyos/network, shared by all versions).
	StateDir    string
	RevertAfter time.Duration
	Now         func() time.Time
	Log         *slog.Logger
	// Ports lists the physical network ports (default: /sys/class/net
	// entries with a backing device).
	Ports func() []string

	mu    sync.Mutex
	timer *time.Timer
	// hotplug tracks the background start of DHCP ports, so the next change
	// waits for it instead of racing it.
	hotplug sync.WaitGroup
}

// Pending is a network change waiting to be confirmed.
type Pending struct {
	Config    Config    `json:"config"`
	AppliedAt time.Time `json:"appliedAt"`
	Deadline  time.Time `json:"deadline"`
	// Addresses where the server should be reachable after the change
	// (fixed addresses; DHCP ones are unknown until the lease arrives).
	Addresses []string `json:"addresses"`
	// previous holds the files to restore; nil means the file didn't exist.
	Previous map[string]*string `json:"previous"`
	PrevHost string             `json:"previousHostname"`
}

// LiveInterface is an interface as the kernel sees it right now.
type LiveInterface struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind"` // port, bond, vlan, other
	MAC       string   `json:"mac"`
	Up        bool     `json:"up"`
	Carrier   bool     `json:"carrier"`
	SpeedMbps int      `json:"speedMbps"`
	Addresses []string `json:"addresses"` // CIDR
}

// Status is everything the Network page shows.
type Status struct {
	Config  Config          `json:"config"`
	Ports   []string        `json:"ports"`
	Live    []LiveInterface `json:"live"`
	Pending *PendingInfo    `json:"pending"`
	Gateway string          `json:"gateway"` // current default route
	DNS     []string        `json:"dns"`     // in use right now
	// LastRevert explains the most recent automatic undo, if any.
	LastRevert *RevertInfo `json:"lastRevert"`
}

// PendingInfo is the public part of Pending.
type PendingInfo struct {
	AppliedAt time.Time `json:"appliedAt"`
	Deadline  time.Time `json:"deadline"`
	Addresses []string  `json:"addresses"`
}

// RevertInfo records an automatic undo.
type RevertInfo struct {
	At     time.Time `json:"at"`
	Reason string    `json:"reason"`
}

// ErrPending means a change is already waiting for confirmation.
var ErrPending = errors.New("a network change is waiting to be confirmed; keep it or undo it first")

// ErrNothingPending means there's no change to confirm or undo.
var ErrNothingPending = errors.New("no network change is waiting")

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

func (m *Manager) path(rel string) string { return filepath.Join(m.Root, rel) }

func (m *Manager) stateDir() string {
	if m.StateDir != "" {
		return m.StateDir
	}
	return m.path("var/lib/hardyos/network")
}

func (m *Manager) revertAfter() time.Duration {
	if m.RevertAfter > 0 {
		return m.RevertAfter
	}
	return DefaultRevertAfter
}

func (m *Manager) settingsFile() string { return filepath.Join(m.stateDir(), "settings.json") }
func (m *Manager) pendingFile() string  { return filepath.Join(m.stateDir(), "pending.json") }
func (m *Manager) revertFile() string   { return filepath.Join(m.stateDir(), "last-revert.json") }
func (m *Manager) timeFile() string     { return filepath.Join(m.stateDir(), "time.json") }

// PortNames lists the physical ports.
func (m *Manager) PortNames() []string {
	if m.Ports != nil {
		return m.Ports()
	}
	entries, err := os.ReadDir(m.path("sys/class/net"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if _, err := os.Stat(m.path(filepath.Join("sys/class/net", e.Name(), "device"))); err == nil {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func (m *Manager) readFile(rel string) string {
	b, _ := os.ReadFile(m.path(rel))
	return string(b)
}

// Current returns the saved settings, importing them from the system files
// on servers that were set up before settings were saved.
func (m *Manager) Current() Config {
	ports := m.PortNames()
	var c Config
	if b, err := rootfile.ReadFile(m.settingsFile()); err == nil && json.Unmarshal(b, &c) == nil {
		// Ports added since (a new card) show up as off; removed ones drop out.
		known := map[string]bool{}
		for _, it := range c.Interfaces {
			known[it.Name] = true
		}
		var kept []Interface
		present := map[string]bool{}
		for _, p := range ports {
			present[p] = true
		}
		for _, it := range c.Interfaces {
			if present[it.Name] {
				kept = append(kept, it)
			}
		}
		for _, p := range ports {
			if !known[p] {
				kept = append(kept, Interface{Name: p, Addressing: Addressing{Mode: ModeOff}})
			}
		}
		c.Interfaces = kept
		if c.Interfaces == nil {
			c.Interfaces = []Interface{}
		}
		c.Normalize()
		return c
	}
	host := strings.TrimSpace(m.readFile(HostnamePath))
	if host == "" {
		host = "hardyos"
	}
	return Import(host, m.readFile(InterfacesPath), m.readFile(ResolvPath), ports)
}

// loadPending reads the waiting change. Its saved files are written back as
// root on undo, so only a file root wrote is trusted.
func (m *Manager) loadPending() (*Pending, error) {
	b, err := rootfile.ReadFile(m.pendingFile())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p Pending
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("read the waiting network change: %w", err)
	}
	return &p, nil
}

// Status reports settings, live state and any change waiting for confirmation.
func (m *Manager) Status(ctx context.Context) (*Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := &Status{Ports: m.PortNames(), DNS: []string{}}
	if st.Ports == nil {
		st.Ports = []string{}
	}
	p, err := m.loadPending()
	if err != nil {
		return nil, err
	}
	if p != nil {
		st.Config = p.Config
		st.Pending = &PendingInfo{AppliedAt: p.AppliedAt, Deadline: p.Deadline, Addresses: p.Addresses}
	} else {
		st.Config = m.Current()
	}
	st.Live = m.live(ctx)
	st.Gateway = m.defaultGateway(ctx)
	for _, line := range strings.Split(m.readFile(ResolvPath), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "nameserver" {
			st.DNS = append(st.DNS, f[1])
		}
	}
	var ri RevertInfo
	if b, err := os.ReadFile(m.revertFile()); err == nil && json.Unmarshal(b, &ri) == nil {
		st.LastRevert = &ri
	}
	return st, nil
}

// ipAddr is the part of `ip -j addr` we use.
type ipAddr struct {
	IfName    string   `json:"ifname"`
	Flags     []string `json:"flags"`
	OperState string   `json:"operstate"`
	Address   string   `json:"address"`
	LinkInfo  *struct {
		InfoKind string `json:"info_kind"`
	} `json:"linkinfo"`
	AddrInfo []struct {
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
		Scope     string `json:"scope"`
	} `json:"addr_info"`
}

func (m *Manager) live(ctx context.Context) []LiveInterface {
	out := []LiveInterface{}
	res, err := m.Runner.Run(ctx, nil, "ip", "-j", "-d", "addr", "show")
	if err != nil || res.ExitCode != 0 {
		return out
	}
	var list []ipAddr
	if json.Unmarshal(res.Stdout, &list) != nil {
		return out
	}
	ports := map[string]bool{}
	for _, p := range m.PortNames() {
		ports[p] = true
	}
	for _, a := range list {
		if a.IfName == "lo" {
			continue
		}
		li := LiveInterface{Name: a.IfName, MAC: a.Address, Addresses: []string{}}
		switch {
		case ports[a.IfName]:
			li.Kind = "port"
		case a.LinkInfo != nil && a.LinkInfo.InfoKind == "bond":
			li.Kind = "bond"
		case a.LinkInfo != nil && a.LinkInfo.InfoKind == "vlan":
			li.Kind = "vlan"
		default:
			li.Kind = "other" // docker0, veths and the like
		}
		for _, f := range a.Flags {
			if f == "UP" {
				li.Up = true
			}
			if f == "LOWER_UP" {
				li.Carrier = true
			}
		}
		for _, ai := range a.AddrInfo {
			if ai.Scope == "global" {
				li.Addresses = append(li.Addresses, fmt.Sprintf("%s/%d", ai.Local, ai.PrefixLen))
			}
		}
		if b, err := os.ReadFile(m.path(filepath.Join("sys/class/net", a.IfName, "speed"))); err == nil {
			fmt.Sscan(strings.TrimSpace(string(b)), &li.SpeedMbps)
			if li.SpeedMbps < 0 {
				li.SpeedMbps = 0
			}
		}
		out = append(out, li)
	}
	return out
}

func (m *Manager) defaultGateway(ctx context.Context) string {
	res, err := m.Runner.Run(ctx, nil, "ip", "-j", "route", "show", "default")
	if err != nil || res.ExitCode != 0 {
		return ""
	}
	var routes []struct {
		Gateway string `json:"gateway"`
	}
	if json.Unmarshal(res.Stdout, &routes) == nil && len(routes) > 0 {
		return routes[0].Gateway
	}
	return ""
}

func (m *Manager) run(ctx context.Context, name string, args ...string) error {
	res, err := m.Runner.Run(ctx, nil, name, args...)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(string(res.Stderr))
		if msg == "" {
			msg = strings.TrimSpace(string(res.Stdout))
		}
		return fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), msg)
	}
	return nil
}

// Apply switches to c and waits for Confirm; without it the old settings
// come back after RevertAfter.
func (m *Manager) Apply(ctx context.Context, c Config) (*PendingInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c.Normalize()
	if err := c.Validate(m.PortNames()); err != nil {
		return nil, err
	}
	if p, err := m.loadPending(); err != nil {
		return nil, err
	} else if p != nil {
		return nil, ErrPending
	}

	files := Render(c)
	prev := map[string]*string{}
	for rel := range files {
		if b, err := os.ReadFile(m.path(rel)); err == nil {
			s := string(b)
			prev[rel] = &s
		} else if errors.Is(err, fs.ErrNotExist) {
			prev[rel] = nil
		} else {
			return nil, err
		}
	}
	p := &Pending{
		Config:    c,
		AppliedAt: m.now().UTC(),
		Deadline:  m.now().UTC().Add(m.revertAfter()),
		Addresses: c.StaticAddresses(),
		Previous:  prev,
		PrevHost:  strings.TrimSpace(m.readFile(HostnamePath)),
	}
	if p.Addresses == nil {
		p.Addresses = []string{}
	}
	// Record the way back before touching anything.
	if err := writeJSON(m.pendingFile(), p); err != nil {
		return nil, err
	}
	if err := m.switchTo(ctx, files, c.Hostname); err != nil {
		m.log().Error("new network settings failed; restoring the old ones", "err", err)
		if rerr := m.revertLocked(context.Background(), "the new settings couldn't be applied: "+err.Error()); rerr != nil {
			m.log().Error("restoring the old network settings failed", "err", rerr)
		}
		return nil, fmt.Errorf("the new settings couldn't be applied, so the old ones are back: %w", err)
	}
	m.armTimer(p.Deadline)
	return &PendingInfo{AppliedAt: p.AppliedAt, Deadline: p.Deadline, Addresses: p.Addresses}, nil
}

// switchTo takes interfaces down under the current definitions, writes the
// new files and brings interfaces up under them.
func (m *Manager) switchTo(ctx context.Context, files Files, hostname string) error {
	// A DHCP port still starting from the last change would come up after
	// we take everything down; let it finish first.
	m.hotplug.Wait()
	// ifdown needs the definitions the interfaces were brought up with, so it
	// runs before the new file is written. Every interface ifupdown has up is
	// taken down by name (ifdown -a can skip hotplug ports). Failing ifdowns
	// aren't fatal: an interface that's already down is fine.
	for _, iface := range m.upInterfaces(ctx) {
		if err := m.run(ctx, "ifdown", "--force", iface); err != nil {
			m.log().Warn("taking an interface down reported a problem", "iface", iface, "err", err)
		}
	}
	if err := m.run(ctx, "ifdown", "-a", "--force", "--exclude=lo"); err != nil {
		m.log().Warn("taking interfaces down reported a problem", "err", err)
	}
	for _, rel := range sortedKeys(files) {
		if err := writeOrRemove(m.path(rel), files[rel]); err != nil {
			return err
		}
	}
	if hostname != "" {
		if err := m.run(ctx, "hostname", hostname); err != nil {
			m.log().Warn("setting the running host name failed", "err", err)
		}
	}
	upCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := m.run(upCtx, "ifup", "-a", "--exclude=lo"); err != nil {
		return err
	}
	// DHCP ports start in the background: one without a cable would otherwise
	// wait a minute for an address that never comes.
	m.hotplug.Add(1)
	go func() {
		defer m.hotplug.Done()
		bg, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		if err := m.run(bg, "ifup", "-a", "--allow=hotplug", "--exclude=lo"); err != nil {
			m.log().Info("some DHCP ports didn't come up", "err", err)
		}
	}()
	return nil
}

// upInterfaces lists what ifupdown has brought up (ifquery --state prints
// "eth0=eth0" lines), children (VLANs, bonds) first so parents go down last.
func (m *Manager) upInterfaces(ctx context.Context) []string {
	res, err := m.Runner.Run(ctx, nil, "ifquery", "--state")
	if err != nil || res.ExitCode != 0 {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		name, _, _ := strings.Cut(strings.TrimSpace(line), "=")
		if name != "" && name != "lo" {
			out = append(out, name)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i]) < rank(out[j]) })
	return out
}

func rank(iface string) int {
	switch {
	case strings.Contains(iface, "."):
		return 0 // VLAN
	case strings.HasPrefix(iface, "bond"):
		return 1
	default:
		return 2
	}
}

func sortedKeys(f Files) []string {
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// WriteNow saves c and writes its files without restarting the network or
// waiting for confirmation. It's for restoring a backup at start-up: hardyd-priv
// runs before networking.service, which then brings these settings up.
func (m *Manager) WriteNow(c Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c.Normalize()
	if err := c.Validate(m.PortNames()); err != nil {
		return err
	}
	_ = os.Remove(m.pendingFile())
	files := Render(c)
	for _, rel := range sortedKeys(files) {
		if err := writeOrRemove(m.path(rel), files[rel]); err != nil {
			return err
		}
	}
	if err := m.run(context.Background(), "hostname", c.Hostname); err != nil {
		m.log().Warn("setting the running host name failed", "err", err)
	}
	return writeJSON(m.settingsFile(), c)
}

// Confirm keeps the waiting change.
func (m *Manager) Confirm() (*Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.loadPending()
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, ErrNothingPending
	}
	if err := writeJSON(m.settingsFile(), p.Config); err != nil {
		return nil, err
	}
	if err := os.Remove(m.pendingFile()); err != nil {
		return nil, err
	}
	_ = os.Remove(m.revertFile())
	m.stopTimer()
	return &p.Config, nil
}

// Revert undoes the waiting change now.
func (m *Manager) Revert(ctx context.Context, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.revertLocked(ctx, reason)
}

func (m *Manager) revertLocked(ctx context.Context, reason string) error {
	p, err := m.loadPending()
	if err != nil {
		return err
	}
	if p == nil {
		return ErrNothingPending
	}
	m.stopTimer()
	// Only ever the network files Render owns.
	files := Files{}
	for _, rel := range NetworkPaths {
		if content, ok := p.Previous[rel]; ok {
			files[rel] = content
		}
	}
	err = m.switchTo(ctx, files, p.PrevHost)
	// The old settings are back on disk either way; the change is over.
	_ = os.Remove(m.pendingFile())
	_ = writeJSON(m.revertFile(), RevertInfo{At: m.now().UTC(), Reason: reason})
	if err != nil {
		return fmt.Errorf("the old settings are restored, but bringing the network up reported: %w", err)
	}
	return nil
}

func (m *Manager) armTimer(deadline time.Time) {
	m.stopTimer()
	wait := deadline.Sub(m.now())
	if wait < 0 {
		wait = 0
	}
	m.timer = time.AfterFunc(wait, func() {
		m.log().Warn("new network settings weren't confirmed in time; restoring the old ones")
		if err := m.Revert(context.Background(), "the new settings weren't confirmed in time"); err != nil && !errors.Is(err, ErrNothingPending) {
			m.log().Error("restoring the old network settings", "err", err)
		}
	})
}

func (m *Manager) stopTimer() {
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
}

// OnStart resumes a change that was waiting when hardyd-priv stopped (or the
// server restarted): it's undone if its time is up, otherwise the countdown
// continues. It also re-applies the clock settings, since a new version
// starts with Debian's defaults for chrony.
func (m *Manager) OnStart(ctx context.Context) {
	m.mu.Lock()
	p, err := m.loadPending()
	m.mu.Unlock()
	if err != nil {
		m.log().Error("network: reading the waiting change", "err", err)
	} else if p != nil {
		if !m.now().Before(p.Deadline) {
			if err := m.Revert(ctx, "the server restarted before the new settings were confirmed"); err != nil {
				m.log().Error("network: restoring the old settings", "err", err)
			}
		} else {
			m.mu.Lock()
			m.armTimer(p.Deadline)
			m.mu.Unlock()
		}
	}
	if t, err := m.loadTime(); err == nil && t != nil && !t.NTP {
		_ = m.run(ctx, "systemctl", "disable", "--now", "chrony.service")
	}
}

// --- Date and time ---

func (m *Manager) loadTime() (*TimeConfig, error) {
	b, err := rootfile.ReadFile(m.timeFile())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var t TimeConfig
	return &t, json.Unmarshal(b, &t)
}

// TimeStatus is the Date & Time page.
type TimeStatus struct {
	TimeConfig
	Now       time.Time `json:"now"`
	Synced    bool      `json:"synced"`    // chrony reports a good source
	Source    string    `json:"source"`    // current time server
	OffsetSec float64   `json:"offsetSec"` // last measured clock error
}

// Time returns the clock settings and sync state.
func (m *Manager) Time(ctx context.Context) *TimeStatus {
	st := &TimeStatus{Now: m.now().UTC()}
	if t, err := m.loadTime(); err == nil && t != nil {
		st.TimeConfig = *t
	} else {
		st.Timezone = strings.TrimSpace(m.readFile("etc/timezone"))
		if st.Timezone == "" {
			st.Timezone = "Etc/UTC"
		}
		st.NTP = true
		st.NTPServers = []string{}
	}
	if st.NTPServers == nil {
		st.NTPServers = []string{}
	}
	if st.NTP {
		// chronyc -c tracking: CSV, field 2 is the source name, 5 the offset.
		if res, err := m.Runner.Run(ctx, nil, "chronyc", "-c", "tracking"); err == nil && res.ExitCode == 0 {
			f := strings.Split(strings.TrimSpace(string(res.Stdout)), ",")
			if len(f) > 4 {
				st.Source = f[1]
				fmt.Sscan(f[4], &st.OffsetSec)
				st.Synced = f[1] != "" && f[0] != "7F7F0101" // 127.127.1.1 = local clock only
			}
		}
	}
	return st
}

// SetTime applies clock settings. They can't cut the server off, so there's
// no confirmation step.
func (m *Manager) SetTime(ctx context.Context, t TimeConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	exists := func(z string) bool {
		fi, err := os.Stat(m.path(filepath.Join("usr/share/zoneinfo", z)))
		return err == nil && fi.Mode().IsRegular()
	}
	if err := t.Validate(exists); err != nil {
		return err
	}
	tz := "usr/share/zoneinfo/" + t.Timezone
	if err := writeOrRemove(m.path("etc/timezone"), str(t.Timezone+"\n")); err != nil {
		return err
	}
	lt := m.path("etc/localtime")
	_ = os.Remove(lt)
	if err := os.Symlink("/"+tz, lt); err != nil {
		return err
	}
	if err := writeOrRemove(m.path(ChronyPath), str(RenderChrony(t.NTPServers))); err != nil {
		return err
	}
	if t.NTP {
		if err := m.run(ctx, "systemctl", "enable", "chrony.service"); err != nil {
			return err
		}
		if err := m.run(ctx, "systemctl", "restart", "chrony.service"); err != nil {
			return err
		}
	} else if err := m.run(ctx, "systemctl", "disable", "--now", "chrony.service"); err != nil {
		return err
	}
	return writeJSON(m.timeFile(), t)
}

// SetClock sets the date and time by hand (only when NTP is off).
func (m *Manager) SetClock(ctx context.Context, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, _ := m.loadTime(); t == nil || t.NTP {
		return errors.New("turn off automatic time first; with it on, the clock is set from the network")
	}
	if at.Year() < 2024 || at.Year() > 2100 {
		return errors.New("that date is out of range")
	}
	if err := m.run(ctx, "date", "-u", "-s", at.UTC().Format("2006-01-02 15:04:05")); err != nil {
		return err
	}
	// Keep the hardware clock in step when the tool is installed.
	if err := m.run(ctx, "hwclock", "--systohc", "--utc"); err != nil {
		m.log().Info("couldn't update the hardware clock", "err", err)
	}
	return nil
}

// --- files ---

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeOrRemove(path, str(string(b)+"\n"))
}

// writeOrRemove writes content atomically, or removes the file when content
// is nil. Parent directories are created.
func writeOrRemove(path string, content *string) error {
	if content == nil {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	tmp := path + ".hardyos-tmp"
	if err := os.WriteFile(tmp, []byte(*content), mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// AddrOf returns the address part of a CIDR (for messages).
func AddrOf(cidr string) string {
	if p, err := netip.ParsePrefix(cidr); err == nil {
		return p.Addr().String()
	}
	return cidr
}
