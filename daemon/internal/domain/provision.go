package domain

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Provision creates the domain: Samba's databases in the DC's folder, the
// DC's network and service. It takes about half a minute. On failure nothing
// is left behind.
func (m *Manager) Provision(ctx context.Context, a ProvisionArgs) (*Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.Available() {
		return nil, invalid("this HardyOS build doesn't include the domain controller")
	}
	if c, err := m.Load(); err != nil {
		return nil, err
	} else if c != nil {
		return nil, invalid("a domain (%s) already exists", c.Domain)
	}
	c, err := m.plan(ctx, a)
	if err != nil {
		return nil, err
	}
	m.log().Info("creating the domain", "domain", c.Domain, "netbios", c.NetBIOS, "address", c.Address, "parent", c.Parent)

	if err := m.makeDataDir(ctx); err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_, _ = m.Runner.Run(context.WithoutCancel(ctx), nil, "systemctl", "stop", Service)
			m.TeardownNetwork(context.WithoutCancel(ctx))
			if err := m.removeData(context.WithoutCancel(ctx)); err != nil {
				m.log().Warn("cleaning up after a failed domain setup", "err", err)
			}
		}
	}()

	dir := m.Dir()
	_ = os.MkdirAll(m.dataPath("run"), 0o755)
	_ = os.MkdirAll(m.dataPath("log"), 0o750)
	// No --adminpass: Samba picks a random one and the real one is set
	// through stdin below, so it never shows in a process listing.
	pctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if _, err := sysexec.Output(pctx, m.Runner, "samba-tool", "domain", "provision",
		"--realm="+c.Realm,
		"--domain="+c.NetBIOS,
		"--server-role=dc",
		"--dns-backend=SAMBA_INTERNAL",
		"--use-rfc2307",
		"--host-name="+strings.ToUpper(DCHostName),
		"--host-ip="+c.IP(),
		"--targetdir="+dir,
		"--option=pid directory = "+filepath.Join(dir, "run"),
		"--option=ncalrpc dir = "+filepath.Join(dir, "run", "ncalrpc"),
		"--option=log file = "+filepath.Join(dir, "log", "log.%m"),
	); err != nil {
		return nil, fmt.Errorf("creating the domain database: %w", err)
	}
	if err := m.writeSmbConf(c); err != nil {
		return nil, err
	}
	if err := m.admin(ctx, "policy", map[string]any{}, nil); err != nil {
		return nil, fmt.Errorf("setting the password rules: %w", err)
	}
	if err := m.admin(ctx, "user.password", map[string]any{"username": "Administrator", "password": a.AdminPassword}, nil); err != nil {
		return nil, fmt.Errorf("setting the Administrator password: %w", err)
	}
	if err := m.save(c); err != nil {
		return nil, err
	}
	if err := m.SetupNetwork(ctx, c); err != nil {
		return nil, err
	}
	if err := m.run(ctx, "systemctl", "start", Service); err != nil {
		return nil, fmt.Errorf("starting the domain controller: %w%s", err, m.serviceLog(ctx))
	}
	if !m.waitActive(ctx, 60*time.Second) {
		return nil, fmt.Errorf("the domain controller didn't start%s", m.serviceLog(ctx))
	}
	ok = true
	m.log().Info("domain created", "domain", c.Domain)
	return c, nil
}

// plan validates the request and fills in defaults from the NAS's network.
func (m *Manager) plan(ctx context.Context, a ProvisionArgs) (*Config, error) {
	domain, err := NormalizeDomain(a.Domain)
	if err != nil {
		return nil, err
	}
	nb := a.NetBIOS
	if strings.TrimSpace(nb) == "" {
		nb = DefaultNetBIOS(domain)
	}
	if nb, err = NormalizeNetBIOS(nb); err != nil {
		return nil, err
	}
	if err := CheckPassword(a.AdminPassword, "Administrator"); err != nil {
		return nil, err
	}

	parent, host, err := m.lan(ctx, "", netip.Prefix{})
	if err != nil {
		return nil, invalid("%v", err)
	}
	addrText := strings.TrimSpace(a.Address)
	if addrText == "" {
		return nil, invalid("choose an address for the domain controller")
	}
	if !strings.Contains(addrText, "/") {
		addrText = fmt.Sprintf("%s/%d", addrText, host.Bits())
	}
	dc, err := netip.ParsePrefix(addrText)
	if err != nil || !dc.Addr().Is4() {
		return nil, invalid("%q isn't an IPv4 address", a.Address)
	}
	// The DC lives on the NAS's network, so pick the interface that has it.
	if dc.Masked() != host.Masked() {
		p2, h2, err := m.lan(ctx, "", dc)
		if err != nil || h2.Masked() != dc.Masked() {
			return nil, invalid("%s isn't on the NAS's network (%s)", dc.Addr(), host.Masked())
		}
		parent, host = p2, h2
	}
	if dc.Addr() == host.Addr() {
		return nil, invalid("the domain controller needs its own address, not the NAS's")
	}
	if dc.Addr() == dc.Masked().Addr() || isBroadcast(dc) {
		return nil, invalid("%s can't be used for a device", dc.Addr())
	}
	gw := strings.TrimSpace(a.Gateway)
	if gw == "" {
		gw, _ = m.defaultRoute(ctx)
	}
	if gw != "" {
		g, err := netip.ParseAddr(gw)
		if err != nil || !dc.Contains(g) {
			return nil, invalid("the gateway %s isn't on the domain controller's network", gw)
		}
		if g == dc.Addr() {
			return nil, invalid("%s is the router's address", dc.Addr())
		}
	}
	if !m.addressFree(ctx, parent, dc.Addr()) {
		return nil, invalid("another device is already using %s; choose a free address", dc.Addr())
	}

	fwd := a.Forwarders
	if len(fwd) == 0 {
		fwd = m.hostDNS()
	}
	var forwarders []string
	for _, f := range fwd {
		ad, err := netip.ParseAddr(strings.TrimSpace(f))
		if err != nil {
			return nil, invalid("%q isn't a DNS server address", f)
		}
		if ad == dc.Addr() || ad.IsLoopback() {
			continue
		}
		forwarders = append(forwarders, ad.String())
	}
	if len(forwarders) == 0 && gw != "" {
		forwarders = []string{gw}
	}
	if len(forwarders) > 2 {
		forwarders = forwarders[:2] // Samba uses two at most
	}

	return &Config{
		Domain:     domain,
		Realm:      strings.ToUpper(domain),
		NetBIOS:    nb,
		DCName:     DCHostName + "." + domain,
		Address:    dc.String(),
		Gateway:    gw,
		Parent:     parent,
		MAC:        randomMAC(),
		Forwarders: forwarders,
		Enabled:    true,
		CreatedAt:  time.Now().UTC().Truncate(time.Second),
	}, nil
}

func isBroadcast(p netip.Prefix) bool {
	if !p.Addr().Is4() || p.Bits() >= 31 {
		return false
	}
	a := p.Addr().As4()
	n := p.Masked().Addr().As4()
	host := 32 - p.Bits()
	for i := 3; i >= 0 && host > 0; i-- {
		bits := host
		if bits > 8 {
			bits = 8
		}
		mask := byte(1<<bits - 1)
		if a[i]&mask != mask || a[i]&^mask != n[i] {
			return false
		}
		host -= bits
	}
	return true
}

// randomMAC is a stable locally-administered unicast address for the DC, so
// routers and DHCP reservations see the same device after every restart.
func randomMAC() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	b[0] = (b[0] | 0x02) &^ 0x01
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

var smbConfTmpl = template.Must(template.New("smb.conf").Parse(`# HardyOS domain controller. Written by HardyOS: changes here are replaced.
[global]
	netbios name = {{.Host}}
	realm = {{.C.Realm}}
	workgroup = {{.C.NetBIOS}}
	server role = active directory domain controller
	dns forwarder = {{.Forwarders}}
	idmap_ldb:use rfc2307 = yes
	template shell = /bin/bash
	template homedir = /home/%U

	private dir = {{.Dir}}/private
	lock directory = {{.Dir}}
	state directory = {{.Dir}}/state
	cache directory = {{.Dir}}/cache
	binddns dir = {{.Dir}}/bind-dns
	pid directory = {{.Dir}}/run
	ncalrpc dir = {{.Dir}}/run/ncalrpc

	logging = file
	log file = {{.Dir}}/log/log.%m
	max log size = 5000
	log level = 1

	load printers = no
	printing = bsd
	printcap name = /dev/null
	disable spoolss = yes

[sysvol]
	path = {{.Dir}}/state/sysvol
	read only = No

[netlogon]
	path = {{.Dir}}/state/sysvol/{{.C.Domain}}/scripts
	read only = No
`))

func (m *Manager) writeSmbConf(c *Config) error {
	var b strings.Builder
	if err := smbConfTmpl.Execute(&b, map[string]any{
		"C":          c,
		"Dir":        m.Dir(),
		"Host":       strings.ToUpper(DCHostName),
		"Forwarders": strings.Join(c.Forwarders, " "),
	}); err != nil {
		return err
	}
	p := m.dataPath("etc", "smb.conf")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(b.String()), 0o644)
}

// serviceLog is the DC service's last log lines, for error messages.
func (m *Manager) serviceLog(ctx context.Context) string {
	res, err := m.Runner.Run(ctx, nil, "journalctl", "-u", Service, "-n", "12", "-o", "cat", "--no-pager")
	out := strings.TrimSpace(string(res.Stdout))
	if err != nil || out == "" || strings.HasPrefix(out, "-- No entries") {
		return ""
	}
	return ". Its log ends with:\n" + out
}

func (m *Manager) waitActive(ctx context.Context, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		if m.serviceActive(ctx) {
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

// dataset is the ZFS dataset for the DC's folder when / is on ZFS
// (rpool/hardyos-dc next to rpool/hardyos), or "".
func (m *Manager) dataset(ctx context.Context) string {
	out, err := sysexec.Output(ctx, m.Runner, "findmnt", "-n", "-o", "FSTYPE,SOURCE", "--target", "/")
	if err != nil {
		return ""
	}
	f := strings.Fields(string(out))
	if len(f) != 2 || f[0] != "zfs" {
		return ""
	}
	pool, _, _ := strings.Cut(f[1], "/")
	return pool + "/hardyos-dc"
}

func (m *Manager) datasetExists(ctx context.Context, ds string) bool {
	res, err := m.Runner.Run(ctx, nil, "zfs", "list", "-H", "-o", "name", ds)
	return err == nil && res.ExitCode == 0
}

// makeDataDir creates the DC's folder, as its own dataset on ZFS systems so
// every boot environment shares it and it can be snapshotted.
func (m *Manager) makeDataDir(ctx context.Context) error {
	if ds := m.dataset(ctx); ds != "" {
		if !m.datasetExists(ctx, ds) {
			if err := m.run(ctx, "zfs", "create", "-o", "mountpoint="+m.Dir(), "-o", "canmount=on", ds); err != nil {
				return fmt.Errorf("creating the domain's dataset: %w", err)
			}
		}
	}
	if err := os.MkdirAll(m.dataPath(), 0o700); err != nil {
		return err
	}
	// Leftovers of an earlier, failed setup would make Samba refuse.
	entries, _ := os.ReadDir(m.dataPath())
	for _, e := range entries {
		if err := os.RemoveAll(m.dataPath(e.Name())); err != nil {
			return err
		}
	}
	return os.Chmod(m.dataPath(), 0o700)
}

func (m *Manager) removeData(ctx context.Context) error {
	if ds := m.dataset(ctx); ds != "" && m.datasetExists(ctx, ds) {
		return m.run(ctx, "zfs", "destroy", "-r", ds)
	}
	entries, err := os.ReadDir(m.dataPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	for _, e := range entries {
		if err := os.RemoveAll(m.dataPath(e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// Destroy deletes the domain: every account, group and computer in it.
// confirm must be the domain's name.
func (m *Manager) Destroy(ctx context.Context, confirm string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.Load()
	if err != nil {
		return err
	}
	if c == nil {
		return ErrNotProvisioned
	}
	if !strings.EqualFold(strings.TrimSpace(confirm), c.Domain) {
		return invalid("type the domain name (%s) to confirm", c.Domain)
	}
	m.log().Warn("deleting the domain", "domain", c.Domain)
	_ = m.run(ctx, "systemctl", "stop", Service)
	m.TeardownNetwork(ctx)
	return m.removeData(ctx)
}

// SetEnabled starts or stops the domain controller and keeps it that way.
func (m *Manager) SetEnabled(ctx context.Context, on bool) (*Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.Load()
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, ErrNotProvisioned
	}
	c.Enabled = on
	if err := m.save(c); err != nil {
		return nil, err
	}
	if on {
		if err := m.SetupNetwork(ctx, c); err != nil {
			return nil, err
		}
		if err := m.run(ctx, "systemctl", "start", Service); err != nil {
			return nil, fmt.Errorf("starting the domain controller: %w", err)
		}
		m.waitActive(ctx, 30*time.Second)
	} else {
		if err := m.run(ctx, "systemctl", "stop", Service); err != nil {
			return nil, fmt.Errorf("stopping the domain controller: %w", err)
		}
	}
	return m.status(ctx)
}
