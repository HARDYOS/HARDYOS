package smb

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// bgTimeout bounds one background permission walk.
const bgTimeout = 12 * time.Hour

// domainNow is the joined domain with this server's own DC's details
// (its address, the HardyOS Admins group) when it runs the same domain.
func (m *Manager) domainNow(st state) *Domain {
	d := st.Domain
	if m.LocalDomain != nil {
		if l := m.LocalDomain(); l != nil && strings.EqualFold(l.Domain, d.Domain) {
			d.DCs, d.AdminsGroupSID = l.DCs, l.AdminsGroupSID
		}
	}
	return &d
}

func (m *Manager) render(d *Domain, server string, sc []shareConf, homes string) string {
	return renderConf(confInput{Domain: *d, ServerName: server, Shares: sc, HomesPath: homes, Dirs: m.dirs(), Port: m.port()})
}

// installConf checks a config with testparm and puts it in place. It
// reports whether the file changed and whether [global] did.
func (m *Manager) installConf(ctx context.Context, conf string) error {
	_, _, err := m.installConfChanged(ctx, conf)
	return err
}

func (m *Manager) installConfChanged(ctx context.Context, conf string) (changed, global bool, err error) {
	cur, _ := os.ReadFile(m.confPath())
	if string(cur) == conf {
		return false, false, nil
	}
	tmp := m.confPath() + ".hardyos-new"
	if err := os.MkdirAll(filepath.Dir(tmp), 0o755); err != nil {
		return false, false, err
	}
	if err := os.WriteFile(tmp, []byte(conf), 0o644); err != nil {
		return false, false, err
	}
	res, err := m.Runner.Run(ctx, nil, "testparm", "-s", "--suppress-prompt", tmp)
	if err == nil && res.ExitCode != 0 {
		err = fmt.Errorf("Samba refused the generated settings: %s", strings.TrimSpace(string(res.Stderr)))
	}
	if err != nil {
		_ = os.Remove(tmp)
		return false, false, err
	}
	if err := os.Rename(tmp, m.confPath()); err != nil {
		return false, false, err
	}
	return true, globalSection(string(cur)) != globalSection(conf), nil
}

// Apply regenerates the config from the shared folders and settings,
// reloads Samba, sets permissions on the shared folders that changed and
// keeps the Avahi advertisement. hardyd-priv calls it after every shared
// folder change and every 10 minutes.
func (m *Manager) Apply(ctx context.Context) (*Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.apply(ctx, false); err != nil {
		return nil, err
	}
	return m.status(ctx)
}

// Release stops sharing a folder that is about to be deleted: it leaves
// smb.conf, its background permission walk stops and smbd lets go of its
// open files (a busy dataset can't be destroyed).
func (m *Manager) Release(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.loadState().Joined {
		return nil
	}
	list, err := m.Shares.List(ctx)
	if err != nil {
		return err
	}
	for _, sh := range list {
		if sh.ID != id {
			continue
		}
		m.bgMu.Lock()
		j := m.bg[sh.Dataset]
		m.bgMu.Unlock()
		if j != nil {
			j.cancel()
			<-j.done
		}
		if m.released == nil {
			m.released = map[string]bool{}
		}
		m.released[id] = true
		defer delete(m.released, id)
		if _, err := m.apply(ctx, false); err != nil {
			return err
		}
		if m.active(ctx, SmbdUnit) {
			_, _ = m.Runner.Run(ctx, nil, "smbcontrol", "smbd", "close-share", sh.Name)
		}
		return nil
	}
	return nil
}

// apply does the work; m.mu is held. forceHomes makes home folders now
// instead of on their 10-minute schedule.
func (m *Manager) apply(ctx context.Context, forceHomes bool) ([]ShareStatus, error) {
	st := m.loadState()
	if !st.Joined || !m.installed() {
		if _, err := os.Stat(m.avahiPath()); err == nil {
			_ = os.Remove(m.avahiPath())
		}
		return nil, nil
	}
	set := m.loadSettings()
	dom := m.domainNow(st)
	list, err := m.Shares.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing the shared folders: %w", err)
	}
	if err := m.writeKrb5(dom); err != nil {
		m.log().Warn("writing krb5.conf", "err", err)
	}
	if !m.winbindRunning(ctx) {
		_ = m.systemctl(ctx, "start", WinbindUnit)
		m.waitWinbind(ctx, 20*time.Second)
	}
	names := m.names(ctx)
	var (
		confs  []shareConf
		status []ShareStatus
	)
	for _, sh := range list {
		ss := ShareStatus{ID: sh.ID, Name: sh.Name, SMB: sh.Services.SMB.Enabled, TimeMachine: sh.Services.SMB.TimeMachine,
			PreviousVersions: sh.Services.SMB.PreviousVersions, Recycle: sh.Recycle, Guest: sh.Guest, Skipped: []string{}}
		if m.released[sh.ID] {
			continue
		}
		// Only folders whose mount was verified (shares.Manager.List) and
		// whose path is safe in smb.conf.
		usable := sh.Usable() && filepath.IsAbs(sh.Path) && !strings.ContainsFunc(sh.Path, func(r rune) bool {
			return r == '%' || r == '\\' || r == '"' || unicode.IsControl(r)
		})
		if usable {
			m.applyACL(ctx, st, dom, sh, names)
			if sh.Recycle {
				m.ensureRecycle(dom, sh, names)
			}
		}
		lists := mapLists(dom.NetBIOS, sh.Access, sh.Guest, dom.AdminsGroupSID)
		ss.Skipped = append(ss.Skipped, lists.Skipped...)
		if set.SMBEnabled && sh.Services.SMB.Enabled && usable {
			ss.Available = true
			confs = append(confs, shareConf{
				Name: sh.Name, Path: sh.Path, Comment: sh.Description,
				Valid: lists.Valid, Read: lists.Read, Write: lists.Write, Invalid: lists.Invalid,
				Guest: sh.Guest, Recycle: sh.Recycle, PreviousVersions: sh.Services.SMB.PreviousVersions,
				TimeMachine: sh.Services.SMB.TimeMachine, TimeMachineMaxBytes: tmMax(sh),
			})
		}
		status = append(status, ss)
	}
	homes := ""
	if set.Homes.Enabled && set.Homes.Pool != "" {
		p, err := m.homesRoot(ctx, set.Homes.Pool)
		if err != nil {
			m.log().Warn("home folders", "err", err)
		} else {
			homes = p
			if forceHomes || m.now().Sub(m.lastHomes) >= HomesInterval {
				if err := m.makeHomes(ctx, dom, set.Homes, p); err != nil {
					m.log().Warn("making home folders", "err", err)
				}
				m.lastHomes = m.now()
			}
		}
	}
	conf := m.render(dom, st.ServerName, confs, homes)
	changed, global, err := m.installConfChanged(ctx, conf)
	if err != nil {
		return status, err
	}
	if global {
		// ID mapping and the domain's settings live in [global]: winbind
		// has to start again to use them.
		if err := m.systemctl(ctx, "restart", WinbindUnit); err != nil {
			m.log().Warn("restarting winbind", "err", err)
		}
	}
	if set.SMBEnabled {
		switch {
		case !m.active(ctx, SmbdUnit):
			if err := m.systemctl(ctx, "start", SmbdUnit); err != nil {
				return status, fmt.Errorf("starting the SMB server: %w", err)
			}
		case global:
			if err := m.systemctl(ctx, "restart", SmbdUnit); err != nil {
				return status, fmt.Errorf("restarting the SMB server: %w", err)
			}
		case changed:
			if err := m.systemctl(ctx, "reload", SmbdUnit); err != nil {
				m.log().Warn("reloading the SMB server", "err", err)
			}
		}
		if err := m.writeAvahi(confs); err != nil {
			m.log().Warn("advertising the SMB server", "err", err)
		}
	} else {
		if m.active(ctx, SmbdUnit) {
			_ = m.systemctl(ctx, "stop", SmbdUnit)
		}
		_ = os.Remove(m.avahiPath())
	}
	return status, nil
}

func tmMax(sh shares.Share) uint64 {
	if sh.Services.SMB.TimeMachineMaxBytes > 0 {
		return sh.Services.SMB.TimeMachineMaxBytes
	}
	return 0 // the folder's quota limits it anyway
}

// applyACL gives the shared folder's root its people entries now and the
// rest of its files in the background, when they changed.
func (m *Manager) applyACL(ctx context.Context, st state, dom *Domain, sh shares.Share, names Resolver) {
	p, skipped, err := shareACL(dom.NetBIOS, sh.Access, sh.Guest, dom.AdminsGroupSID, names)
	if err != nil {
		m.log().Warn("shared folder permissions not updated: the domain's names can't be looked up", "share", sh.ID, "err", err)
		return
	}
	if len(skipped) > 0 {
		m.log().Info("shared folder access rules that don't apply here", "share", sh.ID, "names", skipped)
	}
	sort.Slice(p.Entries, func(i, j int) bool {
		a, b := p.Entries[i], p.Entries[j]
		if a.Group != b.Group {
			return !a.Group
		}
		return a.ID < b.ID
	})
	hash := aclHash(p)
	if ok, err := shares.PeopleRootMatches(sh.Path, sh.RootDev, p); err == nil && ok && st.ACL[sh.Dataset] == hash && !m.walking(sh.Dataset) {
		return
	}
	if _, err := shares.SetPeopleRoot(sh.Path, sh.RootDev, p); err != nil {
		m.log().Error("setting a shared folder's permissions", "share", sh.ID, "err", err)
		return
	}
	m.background(sh.Dataset, sh.Path, sh.RootDev, p, hash)
}

func (m *Manager) walking(key string) bool {
	m.bgMu.Lock()
	defer m.bgMu.Unlock()
	_, ok := m.bg[key]
	return ok
}

// background applies the entries below root; a newer walk for the same
// share replaces a running one. The hash is recorded when it finishes.
func (m *Manager) background(key, root string, dev uint64, p shares.PeopleACL, hash string) {
	ctx, cancel := context.WithTimeout(context.Background(), bgTimeout)
	job := &bgWalk{cancel: cancel, done: make(chan struct{})}
	m.bgMu.Lock()
	if m.bg == nil {
		m.bg = map[string]*bgWalk{}
	}
	prev := m.bg[key]
	m.bg[key] = job
	m.bgMu.Unlock()
	walk := m.walk
	if walk == nil {
		walk = shares.ApplyPeopleTree
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer close(job.done)
		defer cancel()
		if prev != nil {
			prev.cancel()
			<-prev.done
		}
		start := time.Now()
		stats, err := walk(ctx, root, dev, p)
		m.bgMu.Lock()
		if m.bg[key] == job {
			delete(m.bg, key)
		}
		m.bgMu.Unlock()
		log := m.log().With("dataset", key, "changed", stats.Changed, "seen", stats.Seen, "skipped", stats.Skipped,
			"took", time.Since(start).Round(time.Millisecond))
		switch {
		case err != nil && ctx.Err() != nil:
			log.Info("shared folder permissions for people: stopped before the end")
			return
		case err != nil:
			log.Error("shared folder permissions for people failed", "err", err)
			return
		case stats.Failed > 0:
			log.Warn("shared folder permissions for people: some files couldn't be changed", "failed", stats.Failed, "first", stats.First)
		default:
			log.Info("shared folder permissions for people applied")
		}
		if err := m.updateState(func(s *state) {
			if s.Joined {
				s.ACL[key] = hash
			}
		}); err != nil {
			log.Warn("recording applied permissions", "err", err)
		}
	}()
}

func (m *Manager) stopBackgroundAll() {
	m.bgMu.Lock()
	jobs := make([]*bgWalk, 0, len(m.bg))
	for _, j := range m.bg {
		jobs = append(jobs, j)
	}
	m.bgMu.Unlock()
	for _, j := range jobs {
		j.cancel()
		<-j.done
	}
}

// Wait waits for background permission walks (tests, shutdown).
func (m *Manager) Wait() { m.wg.Wait() }

// ---- Avahi -----------------------------------------------------------------

// writeAvahi advertises the server to Macs: _smb._tcp, and _adisk._tcp
// for Time Machine folders. Avahi notices the file by itself.
func (m *Manager) writeAvahi(confs []shareConf) error {
	esc := func(s string) string {
		var b strings.Builder
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<!-- Written by HardyOS (File Services): changes here are replaced. -->
<service-group>
  <name replace-wildcards="yes">%h</name>
  <service>
    <type>_smb._tcp</type>
    <port>` + strconv.Itoa(m.port()) + `</port>
  </service>
  <service>
    <type>_device-info._tcp</type>
    <port>0</port>
    <txt-record>model=RackMac</txt-record>
  </service>
`)
	var tm []string
	for _, c := range confs {
		if c.TimeMachine {
			tm = append(tm, c.Name)
		}
	}
	if len(tm) > 0 {
		b.WriteString("  <service>\n    <type>_adisk._tcp</type>\n    <port>9</port>\n    <txt-record>sys=waMa=0,adVF=0x100</txt-record>\n")
		for i, n := range tm {
			fmt.Fprintf(&b, "    <txt-record>dk%d=adVN=%s,adVF=0x82</txt-record>\n", i, esc(strings.NewReplacer(",", " ", "=", " ").Replace(n)))
		}
		b.WriteString("  </service>\n")
	}
	b.WriteString("</service-group>\n")
	cur, _ := os.ReadFile(m.avahiPath())
	if string(cur) == b.String() {
		return nil
	}
	if _, err := os.Stat(filepath.Dir(m.avahiPath())); err != nil {
		return nil // Avahi isn't installed
	}
	return writeFileAtomic(m.avahiPath(), []byte(b.String()), 0o644)
}

// ---- settings and status ---------------------------------------------------

// SetSettings changes the File Services settings and applies them.
func (m *Manager) SetSettings(ctx context.Context, a SettingsArgs) (*Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.loadSettings()
	if a.SMBEnabled != nil {
		s.SMBEnabled = *a.SMBEnabled
	}
	if a.Homes != nil {
		h := *a.Homes
		h.Pool = strings.TrimSpace(h.Pool)
		if h.Enabled {
			if h.Pool == "" || zfs.ValidPoolName(h.Pool) != nil {
				return nil, invalid("choose a pool for the home folders")
			}
			if res, err := m.Runner.Run(ctx, nil, "zfs", "list", "-H", "-o", "name", h.Pool); err != nil || res.ExitCode != 0 {
				return nil, invalid("there's no pool called %s", h.Pool)
			}
			if h.QuotaBytes > 0 && h.QuotaBytes < 1<<20 {
				return nil, invalid("the home folder quota is too small: at least 1 MB, or 0 for none")
			}
		}
		s.Homes = h
	}
	if err := m.ensureDataDir(ctx); err != nil {
		return nil, err
	}
	if err := m.writeJSON("settings.json", s); err != nil {
		return nil, err
	}
	if _, err := m.apply(ctx, true); err != nil {
		return nil, err
	}
	return m.status(ctx)
}

// Status reports on the file server.
func (m *Manager) Status(ctx context.Context) (*Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status(ctx)
}

func (m *Manager) status(ctx context.Context) (*Status, error) {
	st := m.loadState()
	out := &Status{Available: m.installed(), Joined: st.Joined, Settings: m.loadSettings(), Shares: []ShareStatus{}, Addresses: []string{}}
	if m.LocalDomain != nil {
		if l := m.LocalDomain(); l != nil {
			out.LocalDomain = l.Domain
		}
	}
	out.ServerName = m.serverName()
	if m.Addresses != nil {
		if a := m.Addresses(ctx); a != nil {
			out.Addresses = a
		}
	}
	if !st.Joined {
		if out.Available {
			out.Problem = "This server isn't a member of a domain yet, so its shared folders can't be opened from computers."
		}
		return out, nil
	}
	out.Domain = m.domainNow(st)
	out.ServerName = st.ServerName
	out.HostName = strings.ToLower(st.ServerName) + "." + st.Domain.Domain
	t := st.JoinedAt
	out.JoinedAt = &t
	out.Running = m.active(ctx, SmbdUnit)
	out.Winbind = m.winbindOK(ctx)
	switch {
	case !out.Winbind:
		out.Problem = "This server can't reach the domain right now (winbind), so people can't sign in to the shared folders. If the domain controller just started, give it a minute."
	case out.Settings.SMBEnabled && !out.Running:
		out.Problem = "The SMB server isn't running. In the Terminal, journalctl -u smbd shows why."
	}
	if m.Shares != nil {
		if list, err := m.Shares.List(ctx); err == nil {
			for _, sh := range list {
				l := mapLists(out.Domain.NetBIOS, sh.Access, sh.Guest, "")
				out.Shares = append(out.Shares, ShareStatus{
					ID: sh.ID, Name: sh.Name, SMB: sh.Services.SMB.Enabled, TimeMachine: sh.Services.SMB.TimeMachine,
					PreviousVersions: sh.Services.SMB.PreviousVersions, Recycle: sh.Recycle, Guest: sh.Guest,
					Available: out.Settings.SMBEnabled && sh.Services.SMB.Enabled && sh.Mounted,
					Skipped:   append([]string{}, l.Skipped...),
				})
			}
		}
	}
	return out, nil
}

// sysOutput is sysexec.Output on m.Runner.
func (m *Manager) sysOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	return sysexec.Output(ctx, m.Runner, name, args...)
}
