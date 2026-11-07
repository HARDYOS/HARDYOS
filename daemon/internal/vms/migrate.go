package vms

// Live migration of cluster VMs (Phase 8 part C, docs/plans/cluster.md
// section 6.4, decision 351).
//
// The channel is as narrow as libvirt allows:
//
//   - The source's hardyd-priv runs `virsh migrate --live --p2p` itself. The
//     destination URI is a one-shot unix socket that root makes and hands
//     to hardyd (MigrateListen); hardyd relays it over the cluster port to
//     the destination's hardyd.
//   - The destination's hardyd-priv admits exactly one VM for one token
//     until a deadline (MigrateAccept) and hands hardyd a libvirt
//     connection opened as the unprivileged user hardyos-migrate, never as
//     root. libvirt's polkit access driver lets that user do only what an
//     incoming migration of that one domain (name and UUID) needs; every
//     other API call is refused (rules written by MigrateSetup and, per
//     migration, by MigrateAccept).
//   - libvirt's qemu hook (packaging/libvirt/hooks/qemu) asks root to check
//     the incoming domain XML (MigrateCheck) against the destination's own
//     rendering of the VM's stored spec: anything else is refused before
//     QEMU starts.
//   - The memory stream goes straight between the two QEMUs over the
//     storage network (--migrateuri tcp://<storage address>), never over
//     NetBird.

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Migration defaults.
const (
	// MigrateUser is the user the destination's libvirt connection runs as.
	MigrateUser = "hardyos-migrate"
	// LibvirtSocket is libvirtd's read-write socket.
	LibvirtSocket = "/run/libvirt/libvirt-sock"
	// MigrateRunDir holds the source's one-shot sockets (root only).
	MigrateRunDir = "/run/hardyos/migrate"
	// PolkitRulesDir is where the access rules go.
	PolkitRulesDir = "/etc/polkit-1/rules.d"
	// LibvirtdConf is libvirtd's configuration file.
	LibvirtdConf = "/etc/libvirt/libvirtd.conf"
	// MigratePortMin and MigratePortMax are QEMU's migration ports
	// (libvirt's defaults; the storage firewall opens them to members).
	MigratePortMin = 49152
	MigratePortMax = 49215
	// MaxMigrateDeadline bounds an admission.
	MaxMigrateDeadline = 10 * time.Minute
)

// Polkit rule files (lexical order is evaluation order).
const (
	polkitBaseFile  = "60-hardyos-libvirt.rules"
	polkitAllowFile = "61-hardyos-migrate.rules"
	polkitDenyFile  = "69-hardyos-migrate-deny.rules"
)

var (
	tokenRE    = regexp.MustCompile(`^[0-9a-f]{32,64}$`)
	nodeIDRE   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	errNoAdmit = errors.New("no live migration of this VM is expected here")
)

// admission is one incoming migration the destination expects.
type admission struct {
	vm, uuid, token, from string
	expected              []byte
	deadline              time.Time
	// used: the hook's "migrate" check passed once; a second incoming
	// migration under the same admission is refused.
	used  bool
	timer *time.Timer
}

// MigrateAdmittedDir holds a marker per open admission (root only), for
// the hook to refuse a start of an admitted VM when hardyd-priv can't be
// asked.
const MigrateAdmittedDir = "/run/hardyos/migrate/in"

// outgoing is one source-side socket.
type outgoing struct {
	vm, token, sock string
}

type migrations struct {
	mu  sync.Mutex
	in  map[string]*admission // by VM id
	out map[string]*outgoing  // by token
	// starting: the XML root itself defined for a cluster VM it is
	// starting now (with its prepared devices), by VM id.
	starting map[string][]byte
}

// MigrateAcceptArgs admits one incoming live migration.
type MigrateAcceptArgs struct {
	VM          string `json:"vm"`
	From        string `json:"from"`
	Token       string `json:"token"`
	DeadlineSec int    `json:"deadlineSec"`
	// Generation is the placement generation of the two-node grant; the
	// VM's storage must be attached here under it.
	Generation uint64 `json:"generation"`
	// SpecHash is the approved settings' hash in the replicated placement
	// (decision 386): the stored spec must still be the approved one.
	SpecHash string `json:"specHash"`
}

// MigrateListenArgs makes the source's one-shot socket.
type MigrateListenArgs struct {
	VM    string `json:"vm"`
	Token string `json:"token"`
}

// MigrateSendArgs runs the migration on the source.
type MigrateSendArgs struct {
	VM    string `json:"vm"`
	To    string `json:"to"`
	Token string `json:"token"`
	// MigrateURI is tcp://<destination's storage address> (a QEMU port of
	// the migration range may follow).
	MigrateURI string `json:"migrateUri"`
	Generation uint64 `json:"generation"`
	// TimeoutSec bounds the whole migration (default 600, at most 3600).
	TimeoutSec int `json:"timeoutSec,omitempty"`
}

// MigrateCheckArgs is the qemu hook's question.
type MigrateCheckArgs struct {
	VM  string `json:"vm"`
	XML string `json:"xml"`
	// Op is the hook's operation: "migrate" (an incoming migration),
	// "prepare", "start" or "restore" (QEMU is about to start). Empty is
	// "migrate".
	Op string `json:"op,omitempty"`
}

// MigrateEndArgs closes an admission or an outgoing socket.
type MigrateEndArgs struct {
	VM    string `json:"vm"`
	Token string `json:"token"`
}

func (m *Manager) migs() *migrations {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	if m.migr == nil {
		m.migr = &migrations{in: map[string]*admission{}, out: map[string]*outgoing{}, starting: map[string][]byte{}}
	}
	return m.migr
}

func validToken(t string) error {
	if !tokenRE.MatchString(t) {
		return Problems{"the migration token isn't valid"}
	}
	return nil
}

// liveMigratable checks a cluster VM can migrate live: no passthrough
// devices, no discs from this server's ISO library (the destination's
// library is another folder), a named CPU model or host-passthrough.
func liveMigratable(s *Spec) error {
	var p Problems
	if len(s.Devices) > 0 {
		p = append(p, "it has passthrough devices, which pin it to its server")
	}
	for _, md := range s.Media {
		if md.Kind == MediaISO || md.Kind == MediaVirtio {
			p = append(p, "eject its installer discs first (they are on this server's ISO library)")
			break
		}
	}
	if len(p) > 0 {
		return p
	}
	return nil
}

// expectedXML is this server's rendering of a cluster VM as it would run
// here: what an incoming migration must match.
func (m *Manager) expectedXML(ctx context.Context, st *stored) ([]byte, error) {
	p, err := m.paths(ctx, st)
	if err != nil {
		return nil, err
	}
	return DomainXML(&st.spec, m.arch(), p, nil)
}

// MigrateAccept admits one incoming live migration and returns a
// connection to libvirt as MigrateUser, for hardyd to relay the source's
// libvirt to.
func (m *Manager) MigrateAccept(ctx context.Context, a MigrateAcceptArgs) (*os.File, error) {
	if err := validToken(a.Token); err != nil {
		return nil, err
	}
	if !nodeIDRE.MatchString(a.From) {
		return nil, Problems{"the source server's name isn't valid"}
	}
	d := time.Duration(a.DeadlineSec) * time.Second
	if d < 10*time.Second || d > MaxMigrateDeadline {
		return nil, Problems{fmt.Sprintf("the migration deadline is 10 s to %s", MaxMigrateDeadline)}
	}
	unlock, err := m.lockValid(a.VM)
	if err != nil {
		return nil, err
	}
	defer unlock()
	st, err := m.findCluster(ctx, a.VM)
	if err != nil {
		return nil, err
	}
	if a.Generation == 0 || st.cluster.Generation != a.Generation {
		return nil, fmt.Errorf("%w (attached %d, migration %d)", ErrGeneration, st.cluster.Generation, a.Generation)
	}
	if err := checkSpecHash(&st.spec, a.SpecHash); err != nil {
		return nil, err
	}
	if err := liveMigratable(&st.spec); err != nil {
		return nil, err
	}
	if s := m.state(ctx, a.VM); s == "running" || s == "paused" {
		return nil, Problems{"the VM already runs on this server"}
	}
	exp, err := m.expectedXML(ctx, st)
	if err != nil {
		return nil, err
	}
	if err := m.migrationReady(); err != nil {
		return nil, err
	}
	mg := m.migs()
	mg.mu.Lock()
	for id, ad := range mg.in {
		if m.now().After(ad.deadline) {
			delete(mg.in, id)
			continue
		}
		if id != a.VM {
			mg.mu.Unlock()
			return nil, Problems{"another live migration into this server is in progress; try again in a moment"}
		}
	}
	ad := &admission{vm: a.VM, uuid: st.spec.UUID, token: a.Token, from: a.From, expected: exp, deadline: m.now().Add(d)}
	// Root ends the admission itself at the deadline, whatever hardyd
	// does: the rule goes, the migration user's connections are closed.
	ad.timer = time.AfterFunc(d, func() { m.expireAdmission(a.VM, a.Token) })
	mg.in[a.VM] = ad
	mg.mu.Unlock()
	if err := m.markAdmitted(a.VM, true); err != nil {
		m.dropAdmission(a.VM, a.Token)
		return nil, err
	}
	if err := m.writeAllowRule(st.spec.ID, st.spec.UUID); err != nil {
		m.dropAdmission(a.VM, a.Token)
		return nil, err
	}
	f, err := m.connectAsMigrate(ctx)
	if err != nil {
		m.dropAdmission(a.VM, a.Token)
		return nil, fmt.Errorf("connecting to libvirt for the migration: %w", err)
	}
	m.log().Info("vms: admitted a live migration", "id", a.VM, "from", a.From, "deadline", d.String())
	return f, nil
}

// dropAdmission ends vm's admission when it is the one with token (any
// with token ""): the per-migration rule goes once no admission is left,
// and the migration user's libvirt connections are closed.
func (m *Manager) dropAdmission(vm, token string) bool {
	mg := m.migs()
	mg.mu.Lock()
	ad := mg.in[vm]
	if ad == nil || (token != "" && subtle.ConstantTimeCompare([]byte(ad.token), []byte(token)) != 1) {
		mg.mu.Unlock()
		return false
	}
	delete(mg.in, vm)
	if ad.timer != nil {
		ad.timer.Stop()
	}
	empty := len(mg.in) == 0
	mg.mu.Unlock()
	_ = m.markAdmitted(vm, false)
	if empty {
		_ = os.Remove(filepath.Join(m.sys(PolkitRulesDir), polkitAllowFile))
		m.disconnectMigrateClients(context.Background())
	}
	return true
}

// expireAdmission is root's own timer at an admission's deadline.
func (m *Manager) expireAdmission(vm, token string) {
	if m.dropAdmission(vm, token) {
		m.log().Warn("vms: a live migration's admission expired; its rule and connections are gone", "id", vm)
		m.redefinePersistent(context.Background(), vm)
	}
}

// markAdmitted keeps a root-only marker per open admission for the hook.
func (m *Manager) markAdmitted(vm string, on bool) error {
	dir := m.sys(MigrateAdmittedDir)
	f := filepath.Join(dir, vm)
	if !on {
		err := os.Remove(f)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return writeAtomic(f, nil, 0o600)
}

// redefinePersistent replaces a cluster VM's persistent definition (which
// an incoming migration brings from the source) with this server's own
// rendering of the stored spec.
func (m *Manager) redefinePersistent(ctx context.Context, vm string) {
	unlock, err := m.lockValid(vm)
	if err != nil {
		return
	}
	defer unlock()
	if s := m.state(ctx, vm); s == "stopped" || s == "unknown" {
		return
	}
	st, err := m.findCluster(ctx, vm)
	if err != nil {
		return
	}
	if err := m.define(ctx, st, nil); err != nil {
		m.log().Warn("vms: replacing a migrated VM's persistent definition", "id", vm, "err", err)
	}
}

// Hook operations MigrateCheck answers.
const (
	HookMigrate = "migrate"
	HookPrepare = "prepare"
	HookStart   = "start"
	HookRestore = "restore"
)

// clusterPathRE finds what only a cluster VM's XML names: its state
// folder under /mnt/hc or a LUN.
var clusterPathRE = regexp.MustCompile(`/mnt/hc/|/dev/disk/by-id/wwn-0x|/dev/mapper/[0-9a-f]{17,33}`)

// LooksClustered reports whether a domain XML names cluster storage (the
// hook's fallback when hardyd-priv can't be asked).
func LooksClustered(x []byte) bool { return clusterPathRE.Match(x) }

// MigrateCheck is the qemu hook's check (decision 385). An incoming
// migration ("migrate") must be the admitted VM, once, within the
// deadline, and match this server's rendering. Any start of QEMU
// ("prepare", "start", "restore") of a VM with an open admission or of a
// cluster VM must match root's rendering too: the one root itself is
// starting with, else the stored spec's. Other VMs pass, unless their XML
// names cluster storage.
func (m *Manager) MigrateCheck(ctx context.Context, a MigrateCheckArgs) error {
	if ValidID(a.VM) != nil {
		return errNoAdmit
	}
	op := a.Op
	if op == "" {
		op = HookMigrate
	}
	mg := m.migs()
	mg.mu.Lock()
	ad := mg.in[a.VM]
	var exp []byte
	var from string
	expired, used := false, false
	if ad != nil {
		exp, from = ad.expected, ad.from
		expired = m.now().After(ad.deadline)
		used = ad.used
		if op == HookMigrate && !expired && !used {
			// Consumed by its first use, whatever the outcome.
			ad.used = true
		}
	}
	starting := mg.starting[a.VM]
	mg.mu.Unlock()
	if ad != nil && expired {
		m.dropAdmission(a.VM, "")
		return errors.New("the live migration's admission expired")
	}
	switch op {
	case HookMigrate:
		if ad == nil {
			return errNoAdmit
		}
		if used {
			return errors.New("this admission was already used for an incoming migration")
		}
	case HookPrepare, HookStart, HookRestore:
		switch {
		case ad != nil:
		case starting != nil:
			exp = starting
		default:
			st, err := m.findCluster(ctx, a.VM)
			if err != nil {
				if LooksClustered([]byte(a.XML)) {
					return fmt.Errorf("%s names cluster storage but isn't a cluster VM attached here", a.VM)
				}
				return nil // a VM on this server's own pool
			}
			if exp, err = m.expectedXML(ctx, st); err != nil {
				return err
			}
		}
	default:
		return nil
	}
	if err := CheckMigrationXML([]byte(a.XML), exp); err != nil {
		m.log().Warn("vms: refused a cluster VM's domain XML", "id", a.VM, "op", op, "from", from, "err", err)
		return err
	}
	return nil
}

// MigrateEnd closes the admission (destination) or the socket (source) of
// a migration.
func (m *Manager) MigrateEnd(_ context.Context, a MigrateEndArgs) error {
	if err := validToken(a.Token); err != nil {
		return err
	}
	mg := m.migs()
	mg.mu.Lock()
	out := mg.out[a.Token]
	if out != nil && out.vm == a.VM {
		delete(mg.out, a.Token)
	}
	mg.mu.Unlock()
	if m.dropAdmission(a.VM, a.Token) {
		// The migration brought the source's persistent definition: keep
		// this server's own rendering instead.
		m.redefinePersistent(context.Background(), a.VM)
	}
	if out != nil && out.vm == a.VM {
		_ = os.Remove(m.sys(out.sock))
	}
	return nil
}

// MigrateListen makes the source's one-shot socket for the destination
// URI and returns the listening socket for hardyd to accept on.
func (m *Manager) MigrateListen(ctx context.Context, a MigrateListenArgs) (*os.File, error) {
	if err := validToken(a.Token); err != nil {
		return nil, err
	}
	st, err := m.findCluster(ctx, a.VM)
	if err != nil {
		return nil, err
	}
	if err := liveMigratable(&st.spec); err != nil {
		return nil, err
	}
	if m.state(ctx, a.VM) != "running" {
		return nil, Problems{"only a running VM migrates live"}
	}
	dir := m.sys(MigrateRunDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	sock := path.Join(MigrateRunDir, a.Token+".sock")
	_ = os.Remove(m.sys(sock))
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: m.sys(sock), Net: "unix"})
	if err != nil {
		return nil, err
	}
	ln.SetUnlinkOnClose(false)
	if err := os.Chmod(m.sys(sock), 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	f, err := ln.File()
	ln.Close()
	if err != nil {
		return nil, err
	}
	mg := m.migs()
	mg.mu.Lock()
	mg.out[a.Token] = &outgoing{vm: a.VM, token: a.Token, sock: sock}
	mg.mu.Unlock()
	return f, nil
}

// ValidMigrateURI checks the memory stream's address: tcp:// and an IP
// literal that isn't loopback, link-local, multicast or in NetBird's range
// (100.64.0.0/10), with an optional port of the migration range.
func ValidMigrateURI(u string) error {
	rest, ok := strings.CutPrefix(u, "tcp://")
	if !ok {
		return Problems{"the migration address must be tcp://<storage address>"}
	}
	host, port := rest, ""
	if h, p, err := net.SplitHostPort(rest); err == nil {
		host, port = h, p
	} else if strings.HasPrefix(rest, "[") && strings.HasSuffix(rest, "]") {
		host = rest[1 : len(rest)-1]
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return Problems{"the migration address must be an IP address"}
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() ||
		netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
		return Problems{"the migration stream goes over the storage network only"}
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < MigratePortMin || n > MigratePortMax {
			return Problems{fmt.Sprintf("the migration port is %d-%d", MigratePortMin, MigratePortMax)}
		}
	}
	return nil
}

// MigrateSend runs the live migration from this (source) server. The VM is
// left running here if it fails.
func (m *Manager) MigrateSend(ctx context.Context, a MigrateSendArgs) error {
	if err := validToken(a.Token); err != nil {
		return err
	}
	if !nodeIDRE.MatchString(a.To) {
		return Problems{"the destination server's name isn't valid"}
	}
	if err := ValidMigrateURI(a.MigrateURI); err != nil {
		return err
	}
	if err := m.storageRoute(ctx, a.MigrateURI); err != nil {
		return err
	}
	timeout := time.Duration(a.TimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	if timeout < 30*time.Second || timeout > time.Hour {
		return Problems{"the migration time limit is 30 s to 1 hour"}
	}
	unlock, err := m.lockValid(a.VM)
	if err != nil {
		return err
	}
	defer unlock()
	st, err := m.findCluster(ctx, a.VM)
	if err != nil {
		return err
	}
	if a.Generation == 0 || st.cluster.Generation != a.Generation {
		return fmt.Errorf("%w (attached %d, migration %d)", ErrGeneration, st.cluster.Generation, a.Generation)
	}
	mg := m.migs()
	mg.mu.Lock()
	out := mg.out[a.Token]
	mg.mu.Unlock()
	if out == nil || out.vm != a.VM {
		return Problems{"no migration socket was made for this VM"}
	}
	defer func() {
		_ = m.MigrateEnd(context.Background(), MigrateEndArgs{VM: a.VM, Token: a.Token})
	}()
	mctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dest := "qemu+unix:///system?socket=" + out.sock
	_, err = m.virsh(mctx, "migrate", "--live", "--p2p", "--persistent", "--undefinesource", "--abort-on-error",
		"--auto-converge", a.VM, dest, "--migrateuri", a.MigrateURI)
	if err != nil {
		if mctx.Err() != nil {
			_, _ = m.virsh(context.Background(), "domjobabort", a.VM)
		}
		return fmt.Errorf("the live migration failed (the VM keeps running here): %w", err)
	}
	m.setRunning(a.VM, false)
	m.log().Info("vms: migrated live", "id", a.VM, "to", a.To)
	return nil
}

// ---- the XML check ----------------------------------------------------------------

// xnode is a generic XML element.
type xnode struct {
	Name     string
	Space    string
	Attrs    map[string]string
	Children []*xnode
	Text     string
}

func (n *xnode) child(name string) *xnode {
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (n *xnode) all(name string) []*xnode {
	var out []*xnode
	for _, c := range n.Children {
		if c.Name == name {
			out = append(out, c)
		}
	}
	return out
}

func (n *xnode) text(name string) string {
	if c := n.child(name); c != nil {
		return strings.TrimSpace(c.Text)
	}
	return ""
}

// maxMigrateXML bounds the hook's input.
const maxMigrateXML = 1 << 20

func parseTree(b []byte) (*xnode, error) {
	if len(b) > maxMigrateXML {
		return nil, errors.New("the domain XML is too large")
	}
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = true
	var stack []*xnode
	var root *xnode
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &xnode{Name: t.Name.Local, Space: t.Name.Space, Attrs: map[string]string{}}
			for _, a := range t.Attr {
				if a.Name.Space != "" && a.Name.Space != "xmlns" {
					n.Attrs[a.Name.Space+":"+a.Name.Local] = a.Value
					continue
				}
				n.Attrs[a.Name.Local] = a.Value
			}
			if len(stack) == 0 {
				if root != nil {
					return nil, errors.New("more than one root element")
				}
				root = n
			} else {
				p := stack[len(stack)-1]
				p.Children = append(p.Children, n)
			}
			stack = append(stack, n)
			if len(stack) > 32 {
				return nil, errors.New("the domain XML nests too deep")
			}
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].Text += string(t)
			}
		case xml.Directive:
			return nil, errors.New("the domain XML has a directive")
		case xml.ProcInst:
			if t.Target != "xml" {
				return nil, errors.New("the domain XML has a processing instruction")
			}
		}
	}
	if root == nil {
		return nil, errors.New("empty domain XML")
	}
	return root, nil
}
