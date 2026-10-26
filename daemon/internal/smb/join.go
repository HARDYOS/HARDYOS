package smb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var preWin2kRE = regexp.MustCompile(`(?m)^Pre-Win2k Domain:\s*(\S+)\s*$`)

// lookupDomain finds a domain's short name by asking one of its DCs (found
// through DNS), with a throwaway config.
func (m *Manager) lookupDomain(ctx context.Context, dom string) (*Domain, error) {
	tmp, err := os.MkdirTemp(m.dataDir(), ".lookup-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	conf := filepath.Join(tmp, "smb.conf")
	body := fmt.Sprintf("[global]\n\tsecurity = ads\n\trealm = %s\n\tworkgroup = WORKGROUP\n\tprivate dir = %s\n\tstate directory = %s\n\tcache directory = %s\n\tlock directory = %s\n",
		strings.ToUpper(dom), tmp, tmp, tmp, tmp)
	if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
		return nil, err
	}
	lctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res, err := m.Runner.Run(lctx, nil, "net", "ads", "lookup", "-s", conf, "--realm="+dom)
	if err != nil || res.ExitCode != 0 {
		return nil, invalid("no domain controller for %s answered. Check the name, and that this server uses the domain's DNS servers (Control Panel > Network)", dom)
	}
	mm := preWin2kRE.FindSubmatch(res.Stdout)
	if mm == nil || !netbiosRE.MatchString(strings.ToUpper(string(mm[1]))) {
		return nil, fmt.Errorf("the domain controller for %s didn't give the domain's short name", dom)
	}
	return &Domain{Domain: dom, Realm: strings.ToUpper(dom), NetBIOS: strings.ToUpper(string(mm[1]))}, nil
}

// Join makes this server a member of the domain, so its accounts can use
// the shared folders. The password goes to Samba on stdin only.
func (m *Manager) Join(ctx context.Context, a JoinArgs) (*Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.installed() {
		return nil, invalid("this HardyOS build doesn't include the SMB file server")
	}
	if st := m.loadState(); st.Joined {
		return nil, invalid("this server is already a member of %s; leave it first", st.Domain.Domain)
	}
	if a.AdminPassword == "" {
		return nil, invalid("enter the domain's Administrator password")
	}
	if strings.ContainsAny(a.AdminPassword, "\r\n\x00") || len(a.AdminPassword) > 256 {
		return nil, invalid("the password can't contain line breaks")
	}
	user := strings.TrimSpace(a.AdminUser)
	if user == "" {
		user = "Administrator"
	}
	if !adminRE.MatchString(user) {
		return nil, invalid("%q isn't an account name", user)
	}
	var local *Domain
	if m.LocalDomain != nil {
		local = m.LocalDomain()
	}
	var dom *Domain
	switch {
	case strings.TrimSpace(a.Domain) == "" && local == nil:
		return nil, invalid("enter the domain's name")
	case strings.TrimSpace(a.Domain) == "" || (local != nil && strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(a.Domain), "."), local.Domain)):
		d := *local
		dom = &d
	default:
		name, err := NormalizeDomain(a.Domain)
		if err != nil {
			return nil, err
		}
		if err := m.ensureDataDir(ctx); err != nil {
			return nil, err
		}
		if dom, err = m.lookupDomain(ctx, name); err != nil {
			return nil, err
		}
	}
	server := m.serverName()
	if strings.EqualFold(server, dom.NetBIOS) {
		return nil, invalid("this server's name (%s) is the same as the domain's short name; rename the server first", server)
	}
	m.log().Info("joining the domain as a file server", "domain", dom.Domain, "netbios", dom.NetBIOS, "as", server)
	if err := m.ensureDataDir(ctx); err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			m.forget(context.WithoutCancel(ctx))
		}
	}()
	if err := m.writeKrb5(dom); err != nil {
		return nil, err
	}
	if err := m.enableNSS(); err != nil {
		return nil, err
	}
	conf := m.render(dom, server, nil, "")
	if err := m.installConf(ctx, conf); err != nil {
		return nil, err
	}
	jctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if _, err := m.netWithPassword(jctx, user, a.AdminPassword, "ads", "join", "--no-dns-updates"); err != nil {
		if badCredentials(err) {
			return nil, invalid("the domain's %s password isn't right", user)
		}
		return nil, fmt.Errorf("joining %s: %w", dom.Domain, err)
	}
	if err := m.updateState(func(s *state) {
		*s = state{Joined: true, Domain: Domain{Domain: dom.Domain, Realm: dom.Realm, NetBIOS: dom.NetBIOS},
			ServerName: server, JoinedAt: m.now().UTC().Truncate(time.Second), ACL: map[string]string{}}
	}); err != nil {
		return nil, err
	}
	ok = true
	// Windows finds the server by name through the domain's DNS.
	m.registerDNS(ctx, dom, server)
	if err := m.systemctl(ctx, "enable", WinbindUnit, SmbdUnit); err != nil {
		m.log().Warn("enabling the file server at boot", "err", err)
	}
	if err := m.systemctl(ctx, "restart", WinbindUnit); err != nil {
		return nil, fmt.Errorf("joined %s, but winbind didn't start: %w", dom.Domain, err)
	}
	if !m.waitWinbind(ctx, 30*time.Second) {
		m.log().Warn("winbind isn't answering yet after joining")
	}
	m.lastHomes = time.Time{}
	if _, err := m.apply(ctx, true); err != nil {
		return nil, fmt.Errorf("joined %s, but sharing the folders failed: %w", dom.Domain, err)
	}
	m.log().Info("joined the domain", "domain", dom.Domain, "as", server)
	return m.status(ctx)
}

func (m *Manager) registerDNS(ctx context.Context, dom *Domain, server string) {
	if m.Addresses == nil {
		return
	}
	ips := m.Addresses(ctx)
	if len(ips) == 0 {
		return
	}
	fqdn := strings.ToLower(server) + "." + dom.Domain
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := m.net(dctx, append([]string{"ads", "dns", "register", "-P", fqdn}, ips...)...); err != nil {
		m.log().Info("registering the file server in the domain's DNS", "name", fqdn, "err", err)
	}
}

// Leave takes this server out of the domain. With the Administrator
// password its computer account is deleted too.
func (m *Manager) Leave(ctx context.Context, a LeaveArgs) (*Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !a.Confirm {
		return nil, invalid("confirm leaving the domain: the shared folders stop being reachable from computers")
	}
	st := m.loadState()
	if !st.Joined {
		return nil, invalid("this server isn't a member of a domain")
	}
	if a.AdminPassword != "" {
		if strings.ContainsAny(a.AdminPassword, "\r\n\x00") {
			return nil, invalid("the password can't contain line breaks")
		}
		user := strings.TrimSpace(a.AdminUser)
		if user == "" {
			user = "Administrator"
		}
		if !adminRE.MatchString(user) {
			return nil, invalid("%q isn't an account name", user)
		}
		lctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		if _, err := m.netWithPassword(lctx, user, a.AdminPassword, "ads", "leave"); err != nil {
			if badCredentials(err) {
				return nil, invalid("the domain's %s password isn't right", user)
			}
			return nil, fmt.Errorf("removing this server from %s: %w (leave without the password to only forget the domain here)", st.Domain.Domain, err)
		}
	}
	m.log().Warn("leaving the domain", "domain", st.Domain.Domain, "accountDeleted", a.AdminPassword != "")
	m.forget(ctx)
	return m.status(ctx)
}

// forget stops the file server and removes the machine account's secrets
// and the ID map here. Settings stay.
func (m *Manager) forget(ctx context.Context) {
	m.stopBackgroundAll()
	_ = m.systemctl(ctx, "disable", "--now", SmbdUnit, WinbindUnit)
	d := m.dirs()
	for _, p := range []string{d.Private, d.State, d.Cache, d.Lock} {
		if p == "" {
			continue
		}
		entries, _ := os.ReadDir(p)
		for _, e := range entries {
			_ = os.RemoveAll(filepath.Join(p, e.Name()))
		}
	}
	if d.Keytab != "" {
		_ = os.Remove(d.Keytab)
	}
	_ = os.Remove(m.avahiPath())
	_ = writeFileAtomic(m.confPath(), []byte("# HardyOS file sharing is off: this server isn't a member of a domain.\n[global]\n\tserver role = standalone server\n\tdisable netbios = yes\n\tload printers = no\n"), 0o644)
	if err := m.updateState(func(s *state) { *s = state{RecycleCleaned: s.RecycleCleaned} }); err != nil {
		m.log().Warn("saving the file server's state", "err", err)
	}
}

// writeKrb5 writes the host's Kerberos settings for the domain's realm.
func (m *Manager) writeKrb5(d *Domain) error {
	var b strings.Builder
	realm := strings.ToUpper(d.Realm)
	fmt.Fprintf(&b, "# Written by HardyOS for the domain %s.\n[libdefaults]\n", d.Domain)
	fmt.Fprintf(&b, "\tdefault_realm = %s\n\tdns_lookup_realm = false\n\tdns_lookup_kdc = true\n\trdns = false\n", realm)
	if len(d.DCs) > 0 {
		fmt.Fprintf(&b, "\n[realms]\n\t%s = {\n", realm)
		for _, dc := range d.DCs {
			fmt.Fprintf(&b, "\t\tkdc = %s\n", dc)
		}
		fmt.Fprintf(&b, "\t\tadmin_server = %s\n\t}\n", d.DCs[0])
	}
	fmt.Fprintf(&b, "\n[domain_realm]\n\t.%s = %s\n\t%s = %s\n", d.Domain, realm, d.Domain, realm)
	cur, _ := os.ReadFile(m.krb5Conf())
	if string(cur) == b.String() {
		return nil
	}
	return writeFileAtomic(m.krb5Conf(), []byte(b.String()), 0o644)
}

// enableNSS adds winbind to the passwd and group lines of nsswitch.conf,
// so domain accounts have Linux IDs (for file ownership and ACLs).
func (m *Manager) enableNSS() error {
	b, err := os.ReadFile(m.nssPath())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	text, changed := addWinbindNSS(string(b))
	if !changed {
		return nil
	}
	return writeFileAtomic(m.nssPath(), []byte(text), 0o644)
}

func addWinbindNSS(text string) (string, bool) {
	lines := strings.Split(text, "\n")
	found := map[string]bool{}
	changed := false
	for i, l := range lines {
		key, rest, ok := strings.Cut(l, ":")
		key = strings.TrimSpace(key)
		if !ok || (key != "passwd" && key != "group") || strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		found[key] = true
		if !strings.Contains(" "+strings.Join(strings.Fields(rest), " ")+" ", " winbind ") {
			lines[i] = strings.TrimRight(l, " \t") + " winbind"
			changed = true
		}
	}
	for _, k := range []string{"passwd", "group"} {
		if !found[k] {
			if len(lines) > 0 && lines[len(lines)-1] == "" {
				lines = lines[:len(lines)-1]
			}
			lines = append(lines, k+":         files winbind", "")
			changed = true
		}
	}
	return strings.Join(lines, "\n"), changed
}
