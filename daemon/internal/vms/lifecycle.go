package vms

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/devices"
)

// domStats is one domain's line from `virsh domstats`.
type domStats struct {
	State        string
	CPUTime      uint64 // ns
	VCPUs        int
	MemoryUsedMB int
	CPUPercent   float64
}

type sample struct {
	at  time.Time
	cpu uint64
}

// libvirt's domain states (virDomainState).
var stateNames = map[int]string{
	0: "unknown", 1: "running", 2: "running", 3: "paused", 4: "shutting-down",
	5: "stopped", 6: "crashed", 7: "suspended",
}

// parseDomStats reads `virsh domstats --raw` output.
func parseDomStats(out string) map[string]domStats {
	res := map[string]domStats{}
	var name string
	var cur domStats
	var balloonCur, balloonRSS, balloonUnused, balloonAvail int
	flush := func() {
		if name == "" {
			return
		}
		switch {
		case balloonAvail > 0 && balloonUnused > 0:
			cur.MemoryUsedMB = (balloonAvail - balloonUnused) / 1024
		case balloonRSS > 0:
			cur.MemoryUsedMB = balloonRSS / 1024
		default:
			cur.MemoryUsedMB = balloonCur / 1024
		}
		if cur.State != "running" && cur.State != "paused" {
			cur.MemoryUsedMB = 0
		}
		res[name] = cur
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if n, ok := strings.CutPrefix(line, "Domain: "); ok {
			flush()
			name = strings.Trim(n, "'\"")
			cur = domStats{State: "unknown"}
			balloonCur, balloonRSS, balloonUnused, balloonAvail = 0, 0, 0, 0
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || name == "" {
			continue
		}
		n, _ := strconv.ParseUint(v, 10, 64)
		switch k {
		case "state.state":
			if s, ok := stateNames[int(n)]; ok {
				cur.State = s
			}
		case "cpu.time":
			cur.CPUTime = n
		case "vcpu.current":
			cur.VCPUs = int(n)
		case "balloon.current":
			balloonCur = int(n)
		case "balloon.rss":
			balloonRSS = int(n)
		case "balloon.unused":
			balloonUnused = int(n)
		case "balloon.available":
			balloonAvail = int(n)
		}
	}
	flush()
	return res
}

// stats reads every domain's state and computes CPU use since the last
// reading.
func (m *Manager) stats(ctx context.Context) map[string]domStats {
	out, err := m.virsh(ctx, "domstats", "--raw", "--state", "--cpu-total", "--balloon", "--vcpu")
	if err != nil {
		return map[string]domStats{}
	}
	res := parseDomStats(string(out))
	now := m.now()
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	if m.samples == nil {
		m.samples = map[string]sample{}
	}
	for name, ds := range res {
		if prev, ok := m.samples[name]; ok && ds.State == "running" && ds.CPUTime >= prev.cpu {
			dt := now.Sub(prev.at).Seconds()
			if dt > 0.2 && ds.VCPUs > 0 {
				pct := float64(ds.CPUTime-prev.cpu) / 1e9 / dt / float64(ds.VCPUs) * 100
				ds.CPUPercent = min(max(pct, 0), 100)
				res[name] = ds
			}
		}
		// Readings closer than a second apart measure from the older one.
		if prev, ok := m.samples[name]; !ok || now.Sub(prev.at) > time.Second || ds.CPUTime < prev.cpu {
			m.samples[name] = sample{at: now, cpu: ds.CPUTime}
		}
	}
	return res
}

// state is one VM's state ("stopped" when libvirt doesn't know it).
func (m *Manager) state(ctx context.Context, id string) string {
	out, err := m.virsh(ctx, "domstate", id)
	if err != nil {
		if notDefined(err) {
			return "stopped"
		}
		return "unknown"
	}
	switch s := strings.TrimSpace(string(out)); s {
	case "running", "idle", "blocked":
		return "running"
	case "paused":
		return "paused"
	case "shut off":
		return "stopped"
	case "in shutdown":
		return "shutting-down"
	case "crashed":
		return "crashed"
	case "pmsuspended":
		return "suspended"
	default:
		return "unknown"
	}
}

func (m *Manager) setRunning(id string, r bool) {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	if m.running == nil {
		m.running = map[string]bool{}
	}
	m.running[id] = r
	if !r {
		delete(m.restart, id)
		delete(m.addrs, id)
	}
}

// Start starts a VM: its files are checked, devices prepared and the
// domain defined afresh from the spec (a new boot environment has no
// libvirt definitions of its own).
func (m *Manager) Start(ctx context.Context, id string) (*Result, error) {
	unlock, err := m.lockValid(id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	st, err := m.find(ctx, id)
	if err != nil {
		return nil, err
	}
	switch m.state(ctx, id) {
	case "running":
		v, err := m.Get(ctx, id)
		return &Result{VM: v, Warnings: []string{}}, err
	case "paused":
		// A VM paused before its VLANs were checked (a start that was cut
		// short) only runs once they are.
		if err := m.tagVLANs(ctx, &st.spec); err != nil {
			return nil, fmt.Errorf("the VM's VLAN couldn't be set, so it stays paused: %w", err)
		}
		if _, err := m.virsh(ctx, "resume", id); err != nil {
			return nil, err
		}
		v, err := m.Get(ctx, id)
		return &Result{VM: v, Warnings: []string{}}, err
	}
	s := &st.spec
	if err := s.Validate(m.host(ctx)); err != nil {
		return nil, fmt.Errorf("the VM's settings need fixing first: %w", err)
	}
	if err := m.confined(ctx); err != nil {
		return nil, err
	}
	if s.NeedsFilter() && !m.hasFilter(ctx) {
		return nil, Problems{"the network filter that stops VMs on the home network from using other computers' addresses (libvirt's clean-traffic) isn't installed; turn on \"allow address spoofing\" for the VM's network cards, or reinstall HardyOS's virtualization packages"}
	}
	warnings := m.memoryWarnings(ctx, s, false)
	if s.NeedsBridge() && (m.Network == nil || m.Network.BridgeName() == "") {
		return nil, Problems{"the home network's bridge isn't set up; open the VM's settings to set it up or use NAT"}
	}
	if err := m.checkMedia(ctx, s); err != nil {
		return nil, err
	}
	if err := m.grantMedia(ctx, s); err != nil {
		return nil, err
	}
	if s.NeedsVirtio() {
		if _, err := m.virtioPath(ctx); err != nil {
			return nil, Problems{"the VirtIO drivers disc isn't downloaded yet"}
		}
	}
	if s.CloudInit != nil {
		seed := filepath.Join(m.sys(st.dir), seedFile)
		if _, err := os.Lstat(seed); err != nil {
			if err := m.writeSeed(ctx, st); err != nil {
				return nil, err
			}
		} else if err := m.ownSeed(seed); err != nil {
			return nil, err
		}
	}
	if s.Firmware.TPM {
		if err := m.restoreTPM(st); err != nil {
			m.log().Warn("vms: restoring the TPM state", "id", id, "err", err)
		}
	}
	var prepared []devices.Prepared
	if len(s.Devices) > 0 {
		if m.Devices == nil {
			return nil, Problems{"passing devices through to VMs isn't available on this server yet"}
		}
		if err := m.Devices.Check(ctx, id, s.Devices); err != nil {
			return nil, err
		}
		prepared, err = m.Devices.Prepare(ctx, id, s.Devices)
		if err != nil {
			_ = m.Devices.Release(context.Background(), id)
			return nil, err
		}
		m.statsMu.Lock()
		if m.prepared == nil {
			m.prepared = map[string]bool{}
		}
		m.prepared[id] = true
		m.statsMu.Unlock()
	}
	release := func() {
		if len(s.Devices) > 0 {
			if err := m.Devices.Release(context.Background(), id); err != nil {
				m.log().Warn("vms: giving devices back after a failed start", "id", id, "err", err)
			}
			m.statsMu.Lock()
			delete(m.prepared, id)
			m.statsMu.Unlock()
		}
	}
	if err := m.define(ctx, st, prepared); err != nil {
		release()
		return nil, err
	}
	// The definition kept for when the VM is off has no devices in it, so
	// devices never stay bound to a VM that isn't running.
	undefineDevices := func() {
		if len(prepared) > 0 {
			if err := m.define(context.Background(), st, nil); err != nil {
				m.log().Warn("vms: redefining without devices", "id", id, "err", err)
			}
		}
	}
	if s.NeedsBridge() {
		m.allowBridged(ctx)
	}
	if s.NeedsNAT() {
		if err := m.guardNAT(ctx); err != nil {
			undefineDevices()
			release()
			return nil, fmt.Errorf("closing the server to VMs on the private network: %w", err)
		}
	}
	// The discs are checked once more just before QEMU opens them: each
	// path must still be the file that was checked and granted.
	if err := m.verifyMedia(ctx, s); err != nil {
		undefineDevices()
		release()
		return nil, err
	}
	// A VM with VLAN cards starts paused: it only runs once its ports are
	// on their VLANs and checked, and is turned off if they can't be.
	vlans := s.HasVLAN()
	startArgs := []string{"start", id}
	if vlans {
		startArgs = append(startArgs, "--paused")
	}
	if _, err := m.virsh(ctx, startArgs...); err != nil {
		undefineDevices()
		release()
		return nil, fmt.Errorf("starting %s: %w", s.Name, err)
	}
	if vlans {
		err := m.tagVLANs(ctx, s)
		if err == nil {
			_, err = m.virsh(ctx, "resume", id)
		}
		if err != nil {
			m.log().Warn("vms: the VM's VLANs couldn't be set; turning it off", "id", id, "err", err)
			if _, derr := m.virsh(context.Background(), "destroy", id); derr != nil && !notRunning(derr) {
				m.log().Error("vms: turning off a VM whose VLANs failed", "id", id, "err", derr)
			}
			undefineDevices()
			release()
			return nil, fmt.Errorf("%s didn't start: its VLAN couldn't be set (%v)", s.Name, err)
		}
	}
	m.setRunning(id, true)
	undefineDevices()
	m.log().Info("vms: started", "id", id)
	v, err := m.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &Result{VM: v, Warnings: warnings}, nil
}

// grantMedia lets QEMU read the library files the VM uses.
func (m *Manager) grantMedia(ctx context.Context, s *Spec) error {
	files := s.Files()
	if s.NeedsVirtio() {
		files = append(files, VirtioFile)
	}
	if len(files) == 0 {
		return nil
	}
	f, err := m.folder(ctx, "", false)
	if err != nil || f == nil {
		return errors.New("the ISOs shared folder isn't available")
	}
	uid, err := m.qemuUID()
	if err != nil {
		return err
	}
	grant := grantQEMU
	if m.grant != nil {
		grant = m.grant
	}
	for _, name := range files {
		if err := grant(f, name, uid); err != nil {
			return err
		}
	}
	return nil
}

// verifyMedia checks, just before the VM starts, that every disc's path is
// still the file grantMedia checked. libvirt opens discs by path, and a
// share writer could swap one for a link in between; QEMU's AppArmor
// profile (only the paths libvirt was given) and user are what's left
// for the moment after this check.
func (m *Manager) verifyMedia(ctx context.Context, s *Spec) error {
	files := s.Files()
	if s.NeedsVirtio() {
		files = append(files, VirtioFile)
	}
	if len(files) == 0 {
		return nil
	}
	f, err := m.folder(ctx, "", false)
	if err != nil || f == nil {
		return errors.New("the ISOs shared folder isn't available")
	}
	if f.NFS {
		return Problems{nfsDiscs}
	}
	verify := verifyPath
	if m.verify != nil {
		verify = m.verify
	}
	for _, name := range files {
		if err := verify(f, name); err != nil {
			return err
		}
	}
	return nil
}

// nfsDiscs: NFS clients can do anything with files (their root isn't
// checked by HardyOS), so VMs don't use discs from a folder shared so.
const nfsDiscs = "the ISOs shared folder is shared over NFS; turn NFS off for it (Control Panel > Shared folders) to use its discs in VMs"

// allowBridged makes sure bridged VM traffic is forwarded: Docker sets
// the firewall's FORWARD policy to drop, and with br_netfilter loaded that
// catches frames crossing the bridge too.
func (m *Manager) allowBridged(ctx context.Context) {
	if m.Network == nil {
		return
	}
	br := m.Network.BridgeName()
	if br == "" {
		return
	}
	rule := []string{"FORWARD", "-i", br, "-o", br, "-j", "ACCEPT"}
	if _, err := m.run(ctx, "iptables", append([]string{"-C"}, rule...)...); err == nil {
		return
	}
	if _, err := m.run(ctx, "iptables", append([]string{"-I", "FORWARD", "1"}, rule[1:]...)...); err != nil {
		m.log().Debug("vms: allowing bridged traffic through the firewall", "err", err)
	}
}

// StopArgs stops a VM.
type StopArgs struct {
	ID string `json:"id"`
	// Force pulls the plug instead of asking the guest to shut down.
	Force bool `json:"force"`
}

// Stop asks the VM to shut down (ACPI and the guest agent), or turns it
// off at once with Force. A graceful stop returns once asked; the VM's
// devices go back when it's off (Watch).
func (m *Manager) Stop(ctx context.Context, a StopArgs) (*VM, error) {
	unlock, err := m.lockValid(a.ID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	st, err := m.find(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	switch m.state(ctx, a.ID) {
	case "stopped":
		m.afterStop(ctx, st)
		return m.Get(ctx, a.ID)
	case "paused", "crashed":
		a.Force = true
	}
	if a.Force {
		if _, err := m.virsh(ctx, "destroy", a.ID, "--graceful"); err != nil && !notRunning(err) {
			if _, err := m.virsh(ctx, "destroy", a.ID); err != nil && !notRunning(err) {
				return nil, err
			}
		}
		m.afterStop(ctx, st)
	} else {
		mode := "acpi"
		if st.spec.GuestAgent {
			mode = "agent,acpi"
		}
		if _, err := m.virsh(ctx, "shutdown", a.ID, "--mode", mode); err != nil && !notRunning(err) {
			return nil, err
		}
	}
	return m.Get(ctx, a.ID)
}

// RestartArgs restarts a VM.
type RestartArgs struct {
	ID    string `json:"id"`
	Force bool   `json:"force"` // reset instead of a guest reboot
}

// Restart reboots the guest, or resets it with Force. A restart after a
// hardware change stops and starts it, so the new hardware is used.
func (m *Manager) Restart(ctx context.Context, a RestartArgs) (*Result, error) {
	m.statsMu.Lock()
	cold := m.restart[a.ID]
	m.statsMu.Unlock()
	if cold {
		if _, err := m.Stop(ctx, StopArgs{ID: a.ID, Force: true}); err != nil {
			return nil, err
		}
		return m.Start(ctx, a.ID)
	}
	unlock, err := m.lockValid(a.ID)
	if err != nil {
		return nil, err
	}
	if _, err := m.find(ctx, a.ID); err != nil {
		unlock()
		return nil, err
	}
	if a.Force {
		_, err = m.virsh(ctx, "reset", a.ID)
	} else {
		_, err = m.virsh(ctx, "reboot", a.ID, "--mode", "acpi")
	}
	unlock()
	if err != nil {
		return nil, err
	}
	v, err := m.Get(ctx, a.ID)
	return &Result{VM: v, Warnings: []string{}}, err
}

func notRunning(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "domain is not running") || strings.Contains(err.Error(), "not running"))
}

// afterStop gives devices back and saves the TPM state once a VM is off.
// It's safe to call more than once.
func (m *Manager) afterStop(ctx context.Context, st *stored) {
	id := st.spec.ID
	m.setRunning(id, false)
	m.statsMu.Lock()
	was := m.prepared[id]
	delete(m.prepared, id)
	m.statsMu.Unlock()
	if m.Devices != nil && (was || len(st.spec.Devices) > 0) {
		if err := m.Devices.Release(ctx, id); err != nil {
			m.log().Warn("vms: giving a stopped VM's devices back", "id", id, "err", err)
		}
	}
	if st.spec.Firmware.TPM {
		if err := m.saveTPM(st); err != nil {
			m.log().Warn("vms: saving the TPM state", "id", id, "err", err)
		}
	}
}

// libvirt keeps swtpm's state in the boot environment; the copy on the
// pool is the one that lasts (updates, snapshots, rollbacks). Only a real
// UUID names a folder there.
func (m *Manager) libvirtTPM(uuid string) (string, error) {
	if !uuidRE.MatchString(uuid) {
		return "", fmt.Errorf("the VM's UUID %q isn't valid", uuid)
	}
	return m.sys(filepath.Join("/var/lib/libvirt/swtpm", uuid)), nil
}

func (m *Manager) saveTPM(st *stored) error {
	src, err := m.libvirtTPM(st.spec.UUID)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(src); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	dst := filepath.Join(m.sys(st.dir), tpmDir)
	tmp := dst + ".new"
	_ = os.RemoveAll(tmp)
	if err := copyTree(src, tmp); err != nil {
		return err
	}
	_ = os.RemoveAll(dst)
	return os.Rename(tmp, dst)
}

// restoreTPM puts the pool's copy back when libvirt has none (a new boot
// environment) or after a rollback.
func (m *Manager) restoreTPM(st *stored) error {
	src := filepath.Join(m.sys(st.dir), tpmDir)
	if _, err := os.Lstat(src); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	dst, err := m.libvirtTPM(st.spec.UUID)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(dst); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o711); err != nil {
		return err
	}
	return copyTree(src, dst)
}

// addresses asks the guest agent, then the neighbour table, for the VM's
// IP addresses.
func (m *Manager) addresses(ctx context.Context, st *stored) []string {
	var out []string
	for _, src := range []string{"agent", "arp", "lease"} {
		if src == "agent" && !st.spec.GuestAgent {
			continue
		}
		b, err := m.virsh(ctx, "domifaddr", st.spec.ID, "--source", src)
		if err != nil {
			continue
		}
		out = parseDomIfAddr(string(b))
		if len(out) > 0 {
			break
		}
	}
	if out == nil {
		out = []string{}
	}
	m.statsMu.Lock()
	if m.addrs == nil {
		m.addrs = map[string][]string{}
	}
	m.addrs[st.spec.ID] = out
	m.statsMu.Unlock()
	return out
}

// parseDomIfAddr reads `virsh domifaddr`: name, MAC, protocol, address.
func parseDomIfAddr(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || (f[2] != "ipv4" && f[2] != "ipv6") {
			continue
		}
		p, err := netip.ParsePrefix(f[3])
		if err != nil || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() {
			continue
		}
		a := p.Addr().String()
		dup := false
		for _, o := range out {
			dup = dup || o == a
		}
		if !dup {
			out = append(out, a)
		}
	}
	return out
}

// Watch notices VMs that stopped (shut down from inside, crashed) to give
// their devices back, and keeps addresses fresh. It returns when ctx ends.
func (m *Manager) Watch(ctx context.Context) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	tick := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		tick++
		m.check(ctx, tick%10 == 0)
	}
}

func (m *Manager) check(ctx context.Context, refreshAddrs bool) {
	stats := m.stats(ctx)
	if len(stats) == 0 {
		return
	}
	m.statsMu.Lock()
	var stopped, running []string
	for id, was := range m.running {
		if s, ok := stats[id]; was && (!ok || (s.State != "running" && s.State != "paused" && s.State != "shutting-down")) {
			stopped = append(stopped, id)
		}
	}
	for id, s := range stats {
		if s.State == "running" && ValidID(id) == nil {
			running = append(running, id)
			if m.running == nil {
				m.running = map[string]bool{}
			}
			m.running[id] = true
		}
	}
	m.statsMu.Unlock()
	for _, id := range stopped {
		if ValidID(id) != nil {
			continue
		}
		unlock := m.lock(id)
		if st, err := m.find(ctx, id); err == nil && m.state(ctx, id) != "running" {
			m.log().Info("vms: stopped", "id", id)
			m.afterStop(ctx, st)
		}
		unlock()
	}
	if refreshAddrs {
		for _, id := range running {
			if st, err := m.find(ctx, id); err == nil {
				m.addresses(ctx, st)
			}
		}
	}
}

// OnStart runs when hardyd-priv starts: it waits for libvirt, defines
// every VM afresh from its spec, gives back devices of VMs that are off,
// and starts the VMs set to start with the server, in order.
func (m *Manager) OnStart(ctx context.Context) {
	ready := false
	for i := 0; i < 60 && ctx.Err() == nil; i++ {
		if _, err := m.virsh(ctx, "version"); err == nil {
			ready = true
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
	if !ready {
		m.log().Warn("vms: libvirt isn't answering; VMs won't start by themselves")
		return
	}
	l, err := m.all(ctx)
	if err != nil {
		m.log().Warn("vms: listing VMs at start", "err", err)
		return
	}
	stats := m.stats(ctx)
	var auto []*stored
	for _, st := range l {
		s := stats[st.spec.ID]
		if s.State == "running" || s.State == "paused" {
			m.setRunning(st.spec.ID, true)
			continue
		}
		if err := m.define(ctx, st, nil); err != nil {
			// Not handed to libvirt, so nothing of it is touched (its TPM
			// state, devices) and it doesn't start.
			m.log().Warn("vms: defining a VM at start", "id", st.spec.ID, "err", err)
			continue
		}
		if err := m.setQuota(ctx, st.dataset, &st.spec, 0); err != nil {
			m.log().Warn("vms: setting the VM's space limit", "id", st.spec.ID, "err", err)
		}
		m.afterStop(ctx, st)
		if st.spec.Autostart.Enabled {
			auto = append(auto, st)
		}
	}
	sort.SliceStable(auto, func(i, j int) bool { return auto[i].spec.Autostart.Order < auto[j].spec.Autostart.Order })
	for _, st := range auto {
		if ctx.Err() != nil {
			return
		}
		if _, err := m.Start(ctx, st.spec.ID); err != nil {
			m.log().Warn("vms: starting a VM with the server", "id", st.spec.ID, "err", err)
			continue
		}
		if d := st.spec.Autostart.DelaySec; d > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(d) * time.Second):
			}
		}
	}
}
