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
	"slices"
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
}

// outgoing is one source-side socket.
type outgoing struct {
	vm, token, sock string
}

type migrations struct {
	mu  sync.Mutex
	in  map[string]*admission // by VM id
	out map[string]*outgoing  // by token
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
		m.migr = &migrations{in: map[string]*admission{}, out: map[string]*outgoing{}}
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
	mg.in[a.VM] = &admission{vm: a.VM, uuid: st.spec.UUID, token: a.Token, from: a.From, expected: exp, deadline: m.now().Add(d)}
	mg.mu.Unlock()
	if err := m.writeAllowRule(st.spec.ID, st.spec.UUID); err != nil {
		m.dropAdmission(a.VM)
		return nil, err
	}
	f, err := m.connectAsMigrate(ctx)
	if err != nil {
		m.dropAdmission(a.VM)
		return nil, fmt.Errorf("connecting to libvirt for the migration: %w", err)
	}
	m.log().Info("vms: admitted a live migration", "id", a.VM, "from", a.From, "deadline", d.String())
	return f, nil
}

func (m *Manager) dropAdmission(vm string) {
	mg := m.migs()
	mg.mu.Lock()
	delete(mg.in, vm)
	empty := len(mg.in) == 0
	mg.mu.Unlock()
	if empty {
		_ = os.Remove(filepath.Join(m.sys(PolkitRulesDir), polkitAllowFile))
	}
}

// MigrateCheck is the qemu hook's check: the incoming domain must be the
// admitted VM, within the deadline, and match this server's rendering.
func (m *Manager) MigrateCheck(ctx context.Context, a MigrateCheckArgs) error {
	if ValidID(a.VM) != nil {
		return errNoAdmit
	}
	mg := m.migs()
	mg.mu.Lock()
	ad := mg.in[a.VM]
	mg.mu.Unlock()
	if ad == nil {
		return errNoAdmit
	}
	if m.now().After(ad.deadline) {
		m.dropAdmission(a.VM)
		return errors.New("the live migration's admission expired")
	}
	if err := CheckMigrationXML([]byte(a.XML), ad.expected); err != nil {
		m.log().Warn("vms: refused an incoming migration's XML", "id", a.VM, "from", ad.from, "err", err)
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
	ad := mg.in[a.VM]
	out := mg.out[a.Token]
	if out != nil && out.vm == a.VM {
		delete(mg.out, a.Token)
	}
	mg.mu.Unlock()
	if ad != nil && subtle.ConstantTimeCompare([]byte(ad.token), []byte(a.Token)) == 1 {
		m.dropAdmission(a.VM)
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

// domainTop are the top-level elements an incoming domain may have: what
// HardyOS renders and what libvirt adds to a running domain by itself.
var domainTop = map[string]bool{
	"name": true, "uuid": true, "title": true, "description": true, "metadata": true, "memory": true,
	"currentMemory": true, "vcpu": true, "os": true, "features": true, "cpu": true, "clock": true,
	"on_poweroff": true, "on_reboot": true, "on_crash": true, "pm": true, "devices": true,
	"seclabel": true, "resource": true,
}

// domainDevices are the devices an incoming domain may have.
var domainDevices = map[string]bool{
	"emulator": true, "disk": true, "controller": true, "interface": true, "channel": true, "input": true,
	"graphics": true, "video": true, "tpm": true, "serial": true, "console": true, "memballoon": true,
	"rng": true, "audio": true,
}

// CheckMigrationXML accepts an incoming domain only when everything that
// decides what QEMU touches and how it is confined matches expected (the
// destination's own rendering of the stored spec): identity, size, CPU,
// every disk's source, every network card's MAC, bridge and filter, the
// console, the TPM, the firmware files, and no device or element HardyOS
// didn't render (host devices, file system shares, extra QEMU arguments,
// another emulator, an unconfined security label). libvirt's own additions
// (aliases, addresses, the expanded machine type, generated socket paths)
// are allowed.
func CheckMigrationXML(incoming, expected []byte) error {
	in, err := parseTree(incoming)
	if err != nil {
		return fmt.Errorf("the incoming domain XML: %w", err)
	}
	ex, err := parseTree(expected)
	if err != nil {
		return fmt.Errorf("the expected domain XML: %w", err)
	}
	var p Problems
	bad := func(format string, a ...any) { p = append(p, fmt.Sprintf(format, a...)) }
	if in.Name != "domain" || in.Space != "" {
		return Problems{"not a libvirt domain"}
	}
	if in.Attrs["type"] != ex.Attrs["type"] {
		bad("the hypervisor type differs")
	}
	for k := range in.Attrs {
		if k != "type" && k != "id" && !strings.HasPrefix(k, "xmlns") {
			bad("unexpected domain attribute %s", k)
		}
		if strings.HasPrefix(k, "xmlns:") {
			bad("the domain declares an XML namespace (%s)", k)
		}
	}
	for _, c := range in.Children {
		if !domainTop[c.Name] {
			bad("unexpected element <%s>", c.Name)
		}
		if c.Space != "" && c.Name != "metadata" {
			bad("element <%s> in another namespace", c.Name)
		}
	}
	for _, f := range []string{"name", "uuid"} {
		if in.text(f) != ex.text(f) {
			bad("the domain's %s differs", f)
		}
	}
	if kib(in.child("memory")) != kib(ex.child("memory")) || kib(in.child("currentMemory")) > kib(ex.child("memory")) {
		bad("the memory size differs")
	}
	if in.text("vcpu") != ex.text("vcpu") {
		bad("the number of CPUs differs")
	}
	checkCPU(in.child("cpu"), ex.child("cpu"), bad)
	checkOS(in.child("os"), ex.child("os"), bad)
	for _, sl := range in.all("seclabel") {
		if sl.Attrs["type"] == "none" || sl.Attrs["relabel"] == "no" && sl.Attrs["model"] != "dac" {
			bad("the domain isn't confined")
		}
		if m := sl.Attrs["model"]; m != "" && m != "apparmor" && m != "dac" {
			bad("unexpected security model %s", m)
		}
	}
	if r := in.child("resource"); r != nil {
		if part := r.text("partition"); part != "" && part != "/machine" {
			bad("unexpected resource partition")
		}
	}
	checkDevices(in.child("devices"), ex.child("devices"), bad)
	if len(p) > 0 {
		return p
	}
	return nil
}

func kib(n *xnode) int64 {
	if n == nil {
		return -1
	}
	v, err := strconv.ParseInt(strings.TrimSpace(n.Text), 10, 64)
	if err != nil {
		return -1
	}
	switch strings.ToLower(n.Attrs["unit"]) {
	case "", "kib", "k":
		return v
	case "mib", "m":
		return v << 10
	case "gib", "g":
		return v << 20
	case "b", "bytes":
		return v >> 10
	}
	return -1
}

func checkCPU(in, ex *xnode, bad func(string, ...any)) {
	if ex == nil {
		return
	}
	if in == nil {
		bad("the CPU isn't described")
		return
	}
	if in.Attrs["mode"] != ex.Attrs["mode"] {
		bad("the CPU mode differs (%s, expected %s)", in.Attrs["mode"], ex.Attrs["mode"])
	}
	if em := ex.child("model"); em != nil {
		im := in.child("model")
		if im == nil || strings.TrimSpace(im.Text) != strings.TrimSpace(em.Text) {
			bad("the CPU model differs")
		}
	}
	it, et := in.child("topology"), ex.child("topology")
	if et != nil && (it == nil || it.Attrs["cores"] != et.Attrs["cores"] || it.Attrs["threads"] != et.Attrs["threads"]) {
		bad("the CPU topology differs")
	}
}

func checkOS(in, ex *xnode, bad func(string, ...any)) {
	if in == nil || ex == nil {
		bad("the boot settings aren't described")
		return
	}
	if et, it := ex.child("type"), in.child("type"); et == nil || it == nil || it.Attrs["arch"] != et.Attrs["arch"] {
		bad("the architecture differs")
	}
	for _, c := range in.Children {
		switch c.Name {
		case "type", "loader", "nvram", "bootmenu", "boot", "firmware", "smbios":
		default:
			if !(c.Name == "kernel" || c.Name == "initrd" || c.Name == "cmdline") {
				bad("unexpected boot element <%s>", c.Name)
			} else {
				bad("direct kernel boot isn't allowed")
			}
		}
	}
	// The firmware is libvirt's choice of the packaged files; the NVRAM
	// must be the VM's own file.
	if l := in.child("loader"); l != nil {
		if f := strings.TrimSpace(l.Text); f != "" && !strings.HasPrefix(path.Clean(f), "/usr/share/") {
			bad("the firmware isn't a packaged file")
		}
	}
	en, inv := ex.text("nvram"), in.child("nvram")
	switch {
	case en == "" && inv != nil && strings.TrimSpace(inv.Text) != "":
		bad("unexpected NVRAM file")
	case en != "" && (inv == nil || path.Clean(strings.TrimSpace(inv.Text)) != en):
		bad("the NVRAM file differs")
	}
	if inv != nil {
		if inv.Attrs["type"] != "" && inv.Attrs["type"] != "file" {
			bad("the NVRAM isn't a file")
		}
		if inv.child("source") != nil {
			bad("the NVRAM has a source")
		}
	}
}

// diskKey identifies a disk by what it touches.
func diskKey(d *xnode) string {
	src := d.child("source")
	s := ""
	if src != nil {
		s = src.Attrs["dev"] + "|" + src.Attrs["file"]
	}
	return d.Attrs["type"] + "|" + d.Attrs["device"] + "|" + s
}

func checkDevices(in, ex *xnode, bad func(string, ...any)) {
	if in == nil || ex == nil {
		bad("the devices aren't described")
		return
	}
	for _, c := range in.Children {
		if !domainDevices[c.Name] {
			bad("unexpected device <%s>", c.Name)
		}
	}
	// Emulator: a packaged QEMU.
	if e := in.child("emulator"); e != nil {
		f := path.Clean(strings.TrimSpace(e.Text))
		if path.Dir(f) != "/usr/bin" || !strings.HasPrefix(path.Base(f), "qemu-system-") {
			bad("the emulator isn't the packaged QEMU")
		}
	}
	// Disks: the same set, by type, device and source.
	var ik, ek []string
	for _, d := range in.all("disk") {
		ik = append(ik, diskKey(d))
		if src := d.child("source"); src != nil {
			for k := range src.Attrs {
				if k != "dev" && k != "file" && k != "index" && k != "startupPolicy" {
					bad("a disk's source has %s", k)
				}
			}
			if src.child("host") != nil || src.Attrs["protocol"] != "" {
				bad("a network disk isn't allowed")
			}
		}
		if bs := d.child("backingStore"); bs != nil && bs.child("source") != nil {
			bad("a disk has a backing store")
		}
		if dr := d.child("driver"); dr != nil && dr.Attrs["type"] != "raw" {
			bad("a disk isn't raw")
		}
	}
	for _, d := range ex.all("disk") {
		ek = append(ek, diskKey(d))
	}
	slices.Sort(ik)
	slices.Sort(ek)
	if !slices.Equal(ik, ek) {
		bad("the disks differ")
	}
	// Network cards: the same MACs on the same bridges or networks, with
	// the same traffic filter.
	ifKey := func(n *xnode) string {
		mac, src, filt := "", "", ""
		if m := n.child("mac"); m != nil {
			mac = strings.ToLower(m.Attrs["address"])
		}
		if s := n.child("source"); s != nil {
			src = s.Attrs["bridge"] + "|" + s.Attrs["network"]
		}
		if f := n.child("filterref"); f != nil {
			filt = f.Attrs["filter"]
		}
		model := ""
		if m := n.child("model"); m != nil {
			model = m.Attrs["type"]
		}
		return n.Attrs["type"] + "|" + mac + "|" + src + "|" + filt + "|" + model
	}
	var ii, ei []string
	for _, n := range in.all("interface") {
		ii = append(ii, ifKey(n))
		if n.child("script") != nil || n.child("backend") != nil && n.child("backend").Attrs["tap"] != "" {
			bad("a network card runs a script or another tap device")
		}
	}
	for _, n := range ex.all("interface") {
		ei = append(ei, ifKey(n))
	}
	slices.Sort(ii)
	slices.Sort(ei)
	if !slices.Equal(ii, ei) {
		bad("the network cards differ")
	}
	// The console only on a socket (or none).
	for _, g := range in.all("graphics") {
		if g.Attrs["type"] != "vnc" {
			bad("unexpected %s display", g.Attrs["type"])
		}
		for _, l := range g.all("listen") {
			if l.Attrs["type"] != "socket" && l.Attrs["type"] != "none" {
				bad("the console listens on the network")
			}
		}
		if g.Attrs["listen"] != "" || g.Attrs["port"] != "" && g.Attrs["port"] != "-1" && g.Attrs["port"] != "0" {
			bad("the console listens on the network")
		}
	}
	if len(in.all("graphics")) != len(ex.all("graphics")) {
		bad("the console differs")
	}
	for _, ch := range in.all("channel") {
		if ch.Attrs["type"] != "unix" {
			bad("unexpected %s channel", ch.Attrs["type"])
		}
		if src := ch.child("source"); src != nil && src.Attrs["path"] != "" && !strings.HasPrefix(path.Clean(src.Attrs["path"]), "/var/lib/libvirt/qemu/") && !strings.HasPrefix(path.Clean(src.Attrs["path"]), "/run/libvirt/qemu/") {
			bad("a channel's socket is outside libvirt's folders")
		}
	}
	if len(in.all("channel")) != len(ex.all("channel")) {
		bad("the guest agent channel differs")
	}
	for _, name := range []string{"serial", "console"} {
		for _, s := range in.all(name) {
			if s.Attrs["type"] != "pty" {
				bad("unexpected %s %s", s.Attrs["type"], name)
			}
		}
	}
	for _, t := range in.all("tpm") {
		if b := t.child("backend"); b == nil || b.Attrs["type"] != "emulator" {
			bad("the TPM isn't the emulator")
		}
	}
	if len(in.all("tpm")) != len(ex.all("tpm")) {
		bad("the TPM differs")
	}
	for _, r := range in.all("rng") {
		if b := r.child("backend"); b == nil || b.Attrs["model"] != "random" || strings.TrimSpace(b.Text) != "/dev/urandom" {
			bad("the random number source differs")
		}
	}
	for _, a := range in.all("audio") {
		if a.Attrs["type"] != "none" {
			bad("unexpected audio backend")
		}
	}
}
