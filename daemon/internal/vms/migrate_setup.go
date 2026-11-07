package vms

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// The polkit rules that narrow the destination's libvirt connection
// (decision 351). With libvirt's polkit access driver every API call is
// checked: root may do everything (hardyd-priv), MigrateUser only what an
// incoming migration of the one admitted domain needs.

// PolkitBaseRules lets root use libvirt as before.
const PolkitBaseRules = `// Written by HardyOS (cluster live migration, decision 351).
// libvirt checks every API call with polkit; root (hardyd-priv) may do all.
polkit.addRule(function(action, subject) {
    if (action.id.indexOf("org.libvirt.") !== 0) { return polkit.Result.NOT_HANDLED; }
    if (subject.user === "root") { return polkit.Result.YES; }
    return polkit.Result.NOT_HANDLED;
});
`

// PolkitDenyRules refuses the migration user anything not allowed before.
const PolkitDenyRules = `// Written by HardyOS (cluster live migration, decision 351).
// The migration user gets nothing that 61-hardyos-migrate.rules didn't allow.
polkit.addRule(function(action, subject) {
    if (subject.user === "` + MigrateUser + `") { return polkit.Result.NO; }
    return polkit.Result.NOT_HANDLED;
});
`

// migrateConnectActions are what libvirt checks on the connection itself.
var migrateConnectActions = []string{
	"org.libvirt.unix.manage",
	"org.libvirt.api.connect.getattr",
	"org.libvirt.api.connect.read",
}

// migrateDomainActions are what libvirt checks for an incoming p2p
// migration with --persistent (Prepare3, Finish3) on the domain.
var migrateDomainActions = []string{
	"org.libvirt.api.domain.migrate",
	"org.libvirt.api.domain.start",
	"org.libvirt.api.domain.write",
	"org.libvirt.api.domain.save",
	"org.libvirt.api.domain.getattr",
	"org.libvirt.api.domain.read",
}

// PolkitAllowRules allows one admitted migration.
func PolkitAllowRules(vm, uuid string) (string, error) {
	if ValidID(vm) != nil || !uuidRE.MatchString(uuid) {
		return "", errors.New("bad VM for the migration rule")
	}
	var b strings.Builder
	b.WriteString("// Written by HardyOS for one live migration into this server (decision 351).\n")
	b.WriteString("polkit.addRule(function(action, subject) {\n")
	fmt.Fprintf(&b, "    if (subject.user !== %q) { return polkit.Result.NOT_HANDLED; }\n", MigrateUser)
	b.WriteString("    var connect = {")
	for i, a := range migrateConnectActions {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%q: true", a)
	}
	b.WriteString("};\n    if (connect[action.id] === true) { return polkit.Result.YES; }\n")
	b.WriteString("    var domain = {")
	for i, a := range migrateDomainActions {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%q: true", a)
	}
	b.WriteString("};\n")
	fmt.Fprintf(&b, "    if (domain[action.id] === true && action.lookup(\"domain_name\") === %q && action.lookup(\"domain_uuid\") === %q) {\n", vm, uuid)
	b.WriteString("        return polkit.Result.YES;\n    }\n    return polkit.Result.NO;\n});\n")
	return b.String(), nil
}

func (m *Manager) writeAllowRule(vm, uuid string) error {
	rules, err := PolkitAllowRules(vm, uuid)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(m.sys(PolkitRulesDir), polkitAllowFile), []byte(rules), 0o644)
}

// libvirtdBlock is HardyOS's managed block in libvirtd.conf.
const (
	libvirtdBegin = "# BEGIN HardyOS cluster (decision 351)"
	libvirtdEnd   = "# END HardyOS cluster"
	libvirtdBlock = libvirtdBegin + "\n# Every libvirt API call is checked with polkit (60/61/69-hardyos-*.rules).\naccess_drivers = [ \"polkit\" ]\n" + libvirtdEnd + "\n"
)

// QEMUConf is libvirt's QEMU driver configuration (migration_address).
const QEMUConf = "/etc/libvirt/qemu.conf"

const (
	qemuBegin = "# BEGIN HardyOS cluster migration address (decision 392)"
	qemuEnd   = "# END HardyOS cluster migration address"
)

// withMigrationAddress returns qemu.conf with HardyOS's block binding
// incoming migrations to addr ("" removes the block), and no other
// migration_address line.
func withMigrationAddress(conf []byte, addr string) []byte {
	var out []string
	skip := false
	for _, l := range strings.Split(string(conf), "\n") {
		t := strings.TrimSpace(l)
		switch {
		case t == qemuBegin:
			skip = true
			continue
		case t == qemuEnd:
			skip = false
			continue
		case skip:
			continue
		case addr != "" && strings.HasPrefix(t, "migration_address"):
			out = append(out, "#"+l+" # replaced by HardyOS")
			continue
		}
		out = append(out, l)
	}
	s := strings.TrimRight(strings.Join(out, "\n"), "\n")
	if addr == "" {
		if s != "" {
			s += "\n"
		}
		return []byte(s)
	}
	if s != "" {
		s += "\n\n"
	}
	return []byte(s + qemuBegin + "\n# QEMU accepts incoming migrations on the storage network only.\nmigration_address = \"" + addr + "\"\n" + qemuEnd + "\n")
}

// withAccessDriver returns libvirtd.conf with HardyOS's block (and no
// other access_drivers line).
func withAccessDriver(conf []byte) []byte {
	var out []string
	skip := false
	for _, l := range strings.Split(string(conf), "\n") {
		t := strings.TrimSpace(l)
		switch {
		case t == libvirtdBegin:
			skip = true
			continue
		case t == libvirtdEnd:
			skip = false
			continue
		case skip:
			continue
		case strings.HasPrefix(t, "access_drivers"):
			out = append(out, "#"+l+" # replaced by HardyOS")
			continue
		}
		out = append(out, l)
	}
	s := strings.TrimRight(strings.Join(out, "\n"), "\n")
	if s != "" {
		s += "\n\n"
	}
	return []byte(s + libvirtdBlock)
}

// migrationReady reports whether MigrateSetup has run and polkit, which
// every libvirt call now goes through, is running.
func (m *Manager) migrationReady() error {
	if m.MigrateConnector != nil {
		return nil // tests
	}
	for _, f := range []string{polkitBaseFile, polkitDenyFile} {
		if _, err := os.Stat(filepath.Join(m.sys(PolkitRulesDir), f)); err != nil {
			return Problems{"live migration isn't set up on this server yet"}
		}
	}
	ok := false
	for _, d := range m.libvirtDaemons(context.Background()) {
		b, err := os.ReadFile(m.sys(d.conf))
		ok = ok || err == nil && bytes.Contains(b, []byte(libvirtdBegin))
	}
	if !ok {
		return Problems{"live migration isn't set up on this server yet"}
	}
	if err := m.PolkitHealth(context.Background()); err != nil {
		return err
	}
	return nil
}

// libvirtDaemon is a libvirt daemon whose configuration takes the access
// driver.
type libvirtDaemon struct {
	unit string // systemd unit restarted after a change
	conf string // its configuration file
}

// libvirtDaemons are the daemons that check API calls here: libvirtd, or
// with libvirt's modular daemons virtqemud (and virtproxyd, which serves
// libvirt-sock and forwards to it).
func (m *Manager) libvirtDaemons(ctx context.Context) []libvirtDaemon {
	modular := false
	if _, err := os.Stat(m.sys("/etc/libvirt/virtqemud.conf")); err == nil {
		for _, u := range []string{"virtqemud.socket", "virtqemud.service"} {
			if _, err := m.run(ctx, "systemctl", "is-enabled", "--quiet", u); err == nil {
				modular = true
			}
		}
	}
	if !modular {
		return []libvirtDaemon{{unit: "libvirtd.service", conf: LibvirtdConf}}
	}
	out := []libvirtDaemon{{unit: "virtqemud.service", conf: "/etc/libvirt/virtqemud.conf"}}
	if _, err := os.Stat(m.sys("/etc/libvirt/virtproxyd.conf")); err == nil {
		out = append(out, libvirtDaemon{unit: "virtproxyd.service", conf: "/etc/libvirt/virtproxyd.conf"})
	}
	return out
}

// PolkitHealth reports whether polkitd is running: with the polkit access
// driver every libvirt call needs it (root's own too; a forced stop then
// kills QEMU by pid instead).
func (m *Manager) PolkitHealth(ctx context.Context) error {
	if _, err := m.run(ctx, "systemctl", "is-active", "--quiet", "polkit.service"); err != nil {
		return Problems{"polkit (polkitd) isn't running: libvirt refuses every call until it is back; start it with systemctl start polkit"}
	}
	return nil
}

// MigrateSetupArgs sets live migration up on this server.
type MigrateSetupArgs struct {
	// StorageAddress is this server's storage network address: QEMU
	// accepts incoming migrations only there (qemu.conf migration_address).
	StorageAddress string `json:"storageAddress,omitempty"`
}

// MigrateSetup prepares this server to receive live migrations: the
// migration user, the polkit rules and libvirt's polkit access driver.
// Idempotent; libvirtd restarts only when its configuration changed
// (running VMs keep running), and the change is undone if root can't use
// libvirt afterwards.
func (m *Manager) MigrateSetup(ctx context.Context, a MigrateSetupArgs) error {
	var storage netip.Addr
	if a.StorageAddress != "" {
		ip, err := netip.ParseAddr(a.StorageAddress)
		if err != nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() ||
			netip.MustParsePrefix("100.64.0.0/10").Contains(ip.Unmap()) {
			return Problems{"the storage address isn't a storage network address"}
		}
		storage = ip.Unmap()
	}
	if _, err := os.Stat(m.sys("/usr/lib/polkit-1/polkitd")); err != nil {
		return Problems{"polkit isn't installed, so libvirt can't limit the migration connection; install the polkitd package"}
	}
	if err := m.PolkitHealth(ctx); err != nil {
		return err
	}
	if _, err := m.run(ctx, "id", "-u", MigrateUser); err != nil {
		// Not in libvirt's group: root's helper adds that group to the one
		// process that connects; the user itself has no standing access.
		if _, err := m.run(ctx, "useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent",
			"--shell", "/usr/sbin/nologin", MigrateUser); err != nil {
			return fmt.Errorf("adding the %s user: %w", MigrateUser, err)
		}
	} else if out, err := m.run(ctx, "id", "-nG", MigrateUser); err == nil && hasWord(string(out), "libvirt") {
		// An earlier setup put it in libvirt's group.
		if _, err := m.run(ctx, "gpasswd", "-d", MigrateUser, "libvirt"); err != nil {
			return fmt.Errorf("taking %s out of libvirt's group: %w", MigrateUser, err)
		}
	}
	dir := m.sys(PolkitRulesDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, body := range map[string]string{polkitBaseFile: PolkitBaseRules, polkitDenyFile: PolkitDenyRules} {
		if err := writeAtomic(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			return err
		}
	}
	type change struct {
		path      string
		old, next []byte
	}
	var changes []change
	units := map[string]bool{}
	daemons := m.libvirtDaemons(ctx)
	for _, d := range daemons {
		p := m.sys(d.conf)
		old, err := os.ReadFile(p)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if next := withAccessDriver(old); !bytes.Equal(old, next) {
			changes = append(changes, change{p, old, next})
			units[d.unit] = true
		}
	}
	if storage.IsValid() {
		p := m.sys(QEMUConf)
		old, err := os.ReadFile(p)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if next := withMigrationAddress(old, storage.String()); !bytes.Equal(old, next) {
			changes = append(changes, change{p, old, next})
			units[daemons[0].unit] = true
		}
	}
	restart := func(ctx context.Context) error {
		for _, d := range daemons {
			if units[d.unit] {
				if _, err := m.run(ctx, "systemctl", "restart", d.unit); err != nil {
					return err
				}
			}
		}
		return nil
	}
	revert := func() {
		for _, c := range changes {
			_ = writeAtomic(c.path, c.old, 0o644)
		}
		_ = restart(context.Background())
	}
	for _, c := range changes {
		if err := writeAtomic(c.path, c.next, 0o644); err != nil {
			revert()
			return err
		}
	}
	if len(changes) > 0 {
		if err := restart(ctx); err != nil {
			revert()
			return fmt.Errorf("libvirt didn't restart with the polkit access driver, so it was left as it was: %w", err)
		}
	}
	// Root still uses libvirt, and the migration user gets nothing
	// without an admission: the access driver really is in force.
	if _, err := m.virsh(ctx, "version"); err != nil {
		revert()
		return fmt.Errorf("libvirt didn't work with the polkit access driver, so it was left as it was: %w", err)
	}
	if err := m.migrateUserDenied(ctx); err != nil {
		revert()
		return err
	}
	m.log().Info("vms: libvirt checks every call with polkit (live migration set up)", "storageAddress", a.StorageAddress)
	return nil
}

// migrateUserDenied checks, as the migration user, that libvirt refuses
// it an ordinary call (listing domains) while no migration is admitted.
func (m *Manager) migrateUserDenied(ctx context.Context) error {
	run := m.MigrateRunAs
	if run == nil {
		run = runAsMigrate
	}
	out, err := run(ctx, "virsh", "-c", "qemu:///system", "-q", "list", "--all", "--name")
	if err == nil {
		return fmt.Errorf("libvirt let %s list the VMs without an admitted migration: the polkit access driver isn't in force, so live migration stays off", MigrateUser)
	}
	msg := strings.ToLower(string(out) + " " + err.Error())
	for _, s := range []string{"access denied", "authentication", "not authorized", "permission denied", "polkit"} {
		if strings.Contains(msg, s) {
			return nil
		}
	}
	return fmt.Errorf("checking that libvirt refuses %s failed for another reason: %s", MigrateUser, strings.TrimSpace(string(out)))
}

func hasWord(s, w string) bool {
	for _, f := range strings.Fields(s) {
		if f == w {
			return true
		}
	}
	return false
}

func (m *Manager) connectAsMigrate(ctx context.Context) (*os.File, error) {
	if m.MigrateConnector != nil {
		return m.MigrateConnector(ctx)
	}
	return connectAs(ctx, m.sys(LibvirtSocket))
}
