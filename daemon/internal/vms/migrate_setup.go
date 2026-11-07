package vms

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

// migrationReady reports whether MigrateSetup has run.
func (m *Manager) migrationReady() error {
	if m.MigrateConnector != nil {
		return nil // tests
	}
	for _, f := range []string{polkitBaseFile, polkitDenyFile} {
		if _, err := os.Stat(filepath.Join(m.sys(PolkitRulesDir), f)); err != nil {
			return Problems{"live migration isn't set up on this server yet"}
		}
	}
	b, err := os.ReadFile(m.sys(LibvirtdConf))
	if err != nil || !bytes.Contains(b, []byte(libvirtdBegin)) {
		return Problems{"live migration isn't set up on this server yet"}
	}
	return nil
}

// MigrateSetup prepares this server to receive live migrations: the
// migration user, the polkit rules and libvirt's polkit access driver.
// Idempotent; libvirtd restarts only when its configuration changed
// (running VMs keep running), and the change is undone if root can't use
// libvirt afterwards.
func (m *Manager) MigrateSetup(ctx context.Context) error {
	if _, err := os.Stat(m.sys("/usr/lib/polkit-1/polkitd")); err != nil {
		return Problems{"polkit isn't installed, so libvirt can't limit the migration connection; install the polkitd package"}
	}
	if _, err := m.run(ctx, "id", "-u", MigrateUser); err != nil {
		if _, err := m.run(ctx, "useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent",
			"--shell", "/usr/sbin/nologin", "--groups", "libvirt", MigrateUser); err != nil {
			return fmt.Errorf("adding the %s user: %w", MigrateUser, err)
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
	confPath := m.sys(LibvirtdConf)
	old, err := os.ReadFile(confPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	next := withAccessDriver(old)
	if bytes.Equal(old, next) {
		return nil
	}
	if err := writeAtomic(confPath, next, 0o644); err != nil {
		return err
	}
	check := func() error {
		if _, err := m.run(ctx, "systemctl", "restart", "libvirtd.service"); err != nil {
			return err
		}
		_, err := m.virsh(ctx, "version")
		return err
	}
	if err := check(); err != nil {
		_ = writeAtomic(confPath, old, 0o644)
		_, _ = m.run(context.Background(), "systemctl", "restart", "libvirtd.service")
		return fmt.Errorf("libvirt didn't work with the polkit access driver, so it was left as it was: %w", err)
	}
	m.log().Info("vms: libvirt now checks every call with polkit (live migration set up)")
	return nil
}

func (m *Manager) connectAsMigrate(ctx context.Context) (*os.File, error) {
	if m.MigrateConnector != nil {
		return m.MigrateConnector(ctx)
	}
	return connectAs(ctx, m.sys(LibvirtSocket))
}
