package domain

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// JoinArgs adds this server to an existing domain as another DC.
type JoinArgs struct {
	Domain string `json:"domain"`
	// Existing is the address of one of the domain's DCs.
	Existing      string   `json:"existing"`
	AdminPassword string   `json:"adminPassword"` // the domain's Administrator
	Address       string   `json:"address"`       // this DC's own address
	Gateway       string   `json:"gateway,omitempty"`
	Forwarders    []string `json:"forwarders,omitempty"`
}

// dig asks a DNS server and returns the answer lines (nil when it doesn't
// answer at all).
func (m *Manager) dig(ctx context.Context, server string, args ...string) []string {
	res, err := m.Runner.Run(ctx, nil, "dig", append([]string{"+short", "+time=2", "+tries=2", "@" + server}, args...)...)
	if err != nil || res.ExitCode != 0 {
		return nil
	}
	out := []string{}
	for _, l := range strings.Split(strings.TrimSpace(string(res.Stdout)), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, ";") {
			out = append(out, l)
		}
	}
	return out
}

// authFile writes Samba credentials for the domain's Administrator to a
// root-only file, so the password never shows in a process listing. The
// caller removes it.
func (m *Manager) authFile(realm, password string) (string, error) {
	if strings.ContainsAny(password, "\n\r") {
		return "", invalid("the password can't contain line breaks")
	}
	p := m.dataPath(".join-auth")
	content := fmt.Sprintf("username=Administrator\npassword=%s\ndomain=%s\n", password, realm)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		return "", err
	}
	return filepath.Join(m.Dir(), ".join-auth"), nil
}

// badCredentials reports whether samba-tool failed because the password
// (or account) was wrong. Samba words it several ways.
func badCredentials(err error) bool {
	var ce *sysexec.CommandError
	if !errors.As(err, &ce) {
		return false
	}
	text := strings.ToLower(string(ce.Result.Stderr) + string(ce.Result.Stdout))
	for _, s := range []string{"logon failure", "ldap_invalid_credentials", "invalid username or password", "nt_status_wrong_password"} {
		if strings.Contains(text, s) {
			return true
		}
	}
	return false
}

var workgroupRE = regexp.MustCompile(`(?mi)^\s*workgroup\s*=\s*(\S+)\s*$`)

// Join makes this server another domain controller of an existing domain:
// accounts, groups and DNS replicate between the DCs, so sign-ins and DNS
// keep working while one of them is off.
func (m *Manager) Join(ctx context.Context, a JoinArgs) (*Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.Available() {
		return nil, invalid("this HardyOS build doesn't include the domain controller")
	}
	if c, err := m.Load(); err != nil {
		return nil, err
	} else if c != nil {
		return nil, invalid("this server already has the domain %s", c.Domain)
	}
	domain, err := NormalizeDomain(a.Domain)
	if err != nil {
		return nil, err
	}
	existing, err := netip.ParseAddr(strings.TrimSpace(a.Existing))
	if err != nil || !existing.Is4() {
		return nil, invalid("%q isn't the address of a domain controller", a.Existing)
	}
	if a.AdminPassword == "" {
		return nil, invalid("enter the domain's Administrator password")
	}
	n, err := m.planNetwork(ctx, a.Address, a.Gateway, a.Forwarders)
	if err != nil {
		return nil, err
	}
	if p, _ := netip.ParsePrefix(n.address); p.Addr() == existing {
		return nil, invalid("%s is the other domain controller's address; this one needs its own", existing)
	}
	// Is there a domain controller for it there?
	srv := m.dig(ctx, existing.String(), "SRV", "_ldap._tcp.dc._msdcs."+domain)
	if len(srv) == 0 {
		return nil, invalid("no domain controller for %s answered at %s; check the domain name and address", domain, existing)
	}
	// The next free name: dc2, dc3…
	host := ""
	for i := 2; i < 10 && host == ""; i++ {
		cand := fmt.Sprintf("dc%d", i)
		taken := len(m.dig(ctx, existing.String(), "A", cand+"."+domain)) > 0
		for _, l := range srv {
			if strings.Contains(strings.ToLower(l), " "+cand+"."+domain) {
				taken = true
			}
		}
		if !taken {
			host = cand
		}
	}
	if host == "" {
		return nil, invalid("the domain already has nine domain controllers")
	}
	c := &Config{
		Domain:     domain,
		Realm:      strings.ToUpper(domain),
		DCName:     host + "." + domain,
		Host:       host,
		Address:    n.address,
		Gateway:    n.gateway,
		Parent:     n.parent,
		MAC:        randomMAC(),
		Forwarders: n.forwarders,
		Enabled:    true,
		Joined:     true,
		CreatedAt:  time.Now().UTC().Truncate(time.Second),
		Others:     []DC{{Name: "", Address: existing.String()}},
	}
	m.log().Info("joining the domain", "domain", domain, "existing", existing, "as", c.DCName, "address", c.Address)

	if err := m.makeDataDir(ctx); err != nil {
		return nil, err
	}
	ok := false
	resolv := m.path(filepath.Join("/etc/netns", m.ns(), "resolv.conf"))
	defer func() {
		_ = os.Remove(m.dataPath(".join-auth"))
		if !ok {
			bg := context.WithoutCancel(ctx)
			_, _ = m.Runner.Run(bg, nil, "systemctl", "stop", m.service())
			m.TeardownNetwork(bg)
			if err := m.removeData(bg); err != nil {
				m.log().Warn("cleaning up after a failed join", "err", err)
			}
		}
	}()
	_ = os.MkdirAll(m.dataPath("run"), 0o755)
	_ = os.MkdirAll(m.dataPath("log"), 0o750)
	// The join runs from the DC's own namespace and address, finding the
	// domain through the existing DC's DNS.
	if err := m.SetupNetwork(ctx, c); err != nil {
		return nil, err
	}
	// Until it runs, the new DC finds the domain through the existing one.
	if err := os.WriteFile(resolv, []byte(fmt.Sprintf("nameserver %s\nsearch %s\n", existing, domain)), 0o644); err != nil {
		return nil, err
	}
	auth, err := m.authFile(c.Realm, a.AdminPassword)
	if err != nil {
		return nil, err
	}
	dir := m.Dir()
	jctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if _, err := sysexec.Output(jctx, m.Runner, "ip", "netns", "exec", m.ns(),
		"samba-tool", "domain", "join", domain, "DC",
		"-A", auth,
		"--server="+existing.String(),
		"--dns-backend=SAMBA_INTERNAL",
		"--targetdir="+dir,
		"--option=netbios name = "+strings.ToUpper(host),
		"--option=pid directory = "+filepath.Join(dir, "run"),
		"--option=ncalrpc dir = "+filepath.Join(dir, "run", "ncalrpc"),
		"--option=log file = "+filepath.Join(dir, "log", "log.%m"),
	); err != nil {
		if badCredentials(err) {
			return nil, invalid("the domain's Administrator password isn't right")
		}
		return nil, fmt.Errorf("joining the domain: %w", err)
	}
	// Samba wrote the domain's short name into its smb.conf.
	b, _ := os.ReadFile(m.dataPath("etc", "smb.conf"))
	if mm := workgroupRE.FindSubmatch(b); mm != nil {
		c.NetBIOS = strings.ToUpper(string(mm[1]))
	}
	if err := m.writeSmbConf(c); err != nil {
		return nil, err
	}
	if err := m.save(c); err != nil {
		return nil, err
	}
	if err := m.writeResolv(c); err != nil {
		return nil, err
	}
	if err := m.run(ctx, "systemctl", "start", m.service()); err != nil {
		return nil, fmt.Errorf("starting the domain controller: %w%s", err, m.serviceLog(ctx))
	}
	if !m.waitActive(ctx, 60*time.Second) {
		return nil, fmt.Errorf("the domain controller didn't start%s", m.serviceLog(ctx))
	}
	// Publish this DC in the existing DC's DNS right away (rather than when
	// DNS next replicates), so the domain's devices and the other DC find it
	// within seconds: point lookups at the existing DC for this one update.
	_ = os.WriteFile(resolv, []byte(fmt.Sprintf("nameserver %s\nsearch %s\n", existing, domain)), 0o644)
	if _, err := sysexec.Output(ctx, m.Runner, "ip", "netns", "exec", m.ns(), "samba_dnsupdate", "--use-samba-tool", "-s", m.SmbConf()); err != nil {
		m.log().Info("registering the new domain controller in DNS (Samba retries by itself)", "err", err)
	}
	if err := m.writeResolv(c); err != nil {
		return nil, err
	}
	ok = true
	m.othersChecked = time.Time{}
	m.log().Info("joined the domain", "domain", domain, "as", c.DCName)
	m.dnsChanged(ctx)
	return c, nil
}

// Leave removes this DC from the domain (the other DCs keep it) and deletes
// its copy. Roles this DC held move to another DC.
func (m *Manager) Leave(ctx context.Context, adminPassword string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.Load()
	if err != nil {
		return err
	}
	if c == nil {
		return ErrNotProvisioned
	}
	if len(c.Others) == 0 {
		return invalid("this is the domain's only domain controller: delete the domain instead")
	}
	if adminPassword == "" {
		return invalid("enter the domain's Administrator password")
	}
	partner := ""
	for _, o := range c.Others {
		if o.Name != "" {
			partner = o.Name
			break
		}
		if partner == "" {
			partner = o.Address
		}
	}
	auth, err := m.authFile(c.Realm, adminPassword)
	if err != nil {
		return err
	}
	defer os.Remove(m.dataPath(".join-auth"))
	if _, err := sysexec.Output(ctx, m.Runner, "ip", "netns", "exec", m.ns(),
		"samba-tool", "domain", "demote", "-A", auth, "--server="+partner, "-s", m.SmbConf()); err != nil {
		if badCredentials(err) {
			return invalid("the domain's Administrator password isn't right")
		}
		return fmt.Errorf("removing this domain controller from the domain: %w", err)
	}
	m.log().Warn("left the domain", "domain", c.Domain, "partner", partner)
	_ = m.run(ctx, "systemctl", "stop", m.service())
	m.TeardownNetwork(ctx)
	if err := m.removeData(ctx); err != nil {
		return err
	}
	m.dnsChanged(ctx)
	return nil
}

var fsmoLine = regexp.MustCompile(`(?i)^(\w+)\s+owner:\s+CN=NTDS Settings,CN=([^,]+),`)

// RemoveDead takes a DC that's gone for good out of the domain, from this
// one: its roles move here and its records are deleted. confirm must be
// its name.
func (m *Manager) RemoveDead(ctx context.Context, name, confirm string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.Load()
	if err != nil {
		return err
	}
	if c == nil {
		return ErrNotProvisioned
	}
	name = strings.ToLower(strings.TrimSpace(name))
	var dead *DC
	for i := range c.Others {
		if c.Others[i].Name == name {
			dead = &c.Others[i]
		}
	}
	if dead == nil {
		return invalid("%s isn't one of the domain's other domain controllers", name)
	}
	if !strings.EqualFold(strings.TrimSpace(confirm), name) {
		return invalid("type %s to confirm", name)
	}
	short := strings.SplitN(name, ".", 2)[0]
	// It must really be gone: a DC that still answers would fight back.
	if dead.Address != "" && len(m.dig(ctx, dead.Address, "SRV", "_ldap._tcp."+c.Domain)) > 0 {
		return invalid("%s still answers at %s. Remove it from its own Control Panel instead, or turn it off first", name, dead.Address)
	}
	// Take over the roles it held (FSMO), then delete it.
	if out, err := sysexec.Output(ctx, m.Runner, "samba-tool", "fsmo", "show", "-H", filepath.Join(m.Dir(), "private", "sam.ldb"), "-s", m.SmbConf()); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if mm := fsmoLine.FindStringSubmatch(strings.TrimSpace(line)); mm != nil && strings.EqualFold(mm[2], short) {
				m.log().Warn("taking over a role from a removed domain controller", "dead", name)
				if _, err := sysexec.Output(ctx, m.Runner, "ip", "netns", "exec", m.ns(), "samba-tool", "fsmo", "seize",
					"--role=all", "--force", "-H", filepath.Join(m.Dir(), "private", "sam.ldb"), "-s", m.SmbConf()); err != nil {
					return fmt.Errorf("taking over the domain's roles: %w", err)
				}
				break
			}
		}
	}
	if _, err := sysexec.Output(ctx, m.Runner, "ip", "netns", "exec", m.ns(), "samba-tool", "domain", "demote",
		"--remove-other-dead-server="+short, "-H", filepath.Join(m.Dir(), "private", "sam.ldb"), "-s", m.SmbConf()); err != nil {
		return fmt.Errorf("removing %s: %w", name, err)
	}
	var keep []DC
	for _, o := range c.Others {
		if o.Name != name {
			keep = append(keep, o)
		}
	}
	c.Others = keep
	if err := m.save(c); err != nil {
		return err
	}
	m.log().Warn("removed a dead domain controller", "dead", name)
	m.dnsChanged(ctx)
	return nil
}
