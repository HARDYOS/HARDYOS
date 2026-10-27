package vms

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/devices"
	"github.com/hardyos/hardyos/daemon/internal/rootfile"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// ZFS properties on a VM's datasets.
const (
	PropVM    = "org.hardyos:vm"    // the VM's id, on its dataset and zvols
	PropKept  = "org.hardyos:kept"  // a deleted VM's id, on disks kept after it
	PropLabel = "org.hardyos:label" // a snapshot's description
	specFile  = "vm.json"
	seedFile  = "cloud-init.iso"
	tpmDir    = "tpm"
)

// ErrNotFound means there's no VM with that id.
var ErrNotFound = errors.New("there's no virtual machine with that name")

// Folder is the ISOs shared folder, verified (see shares.Share.Usable).
type Folder struct {
	Pool string
	Path string
	Dev  uint64
	// NFS: the folder is shared over NFS (VM discs aren't used from it).
	NFS bool
}

// Library finds (and creates) the ISOs shared folder.
type Library interface {
	// Folder returns the folder, or nil when there's none. With create
	// set, a missing folder is made on pool.
	Folder(ctx context.Context, pool string, create bool) (*Folder, error)
}

// Bridger sets up the home network's bridge (internal/network).
type Bridger interface {
	// BridgeName is the bridge VMs attach to, or "" when there's none.
	BridgeName() string
	// EnsureBridge creates it if needed, moving the server's address onto
	// it safely, and returns its name.
	EnsureBridge(ctx context.Context) (string, error)
}

// Manager runs VMs. It lives in hardyd-priv (root) and owns libvirt.
type Manager struct {
	Runner sysexec.Runner
	Log    *slog.Logger
	// Root prefixes system paths (tests); "/" in production.
	Root string
	// Devices hands PCI/USB/GPU devices to VMs (part D); nil: VMs can't
	// have devices.
	Devices devices.Manager
	// Library is the ISOs shared folder; nil: no ISO library.
	Library Library
	// Network sets up the bridge; nil: only NAT networking.
	Network Bridger
	// Arch overrides the server's architecture (tests).
	Arch *ArchInfo
	// Mounts verifies dataset mounts (default: /proc/self/mountinfo).
	Mounts shares.MountVerifier
	// HTTP downloads ISOs and images (default: guarded https client).
	HTTP *http.Client
	// AllowLocalDownloads lets downloads reach local addresses (tests).
	AllowLocalDownloads bool
	// Stream runs long commands with progress (default: real processes).
	Stream Streamer
	// QEMUUser is the user QEMU runs as (default libvirt-qemu).
	QEMUUser func() (uint32, error)
	// Now replaces time.Now (tests).
	Now func() time.Time
	// DevicesInfo adds part D's device overview to capabilities (optional).
	DevicesInfo func(ctx context.Context) (any, error)
	// ImportUser runs qemu-img and xz for imports (default hardyos-import);
	// ImportGID replaces looking its group up (tests).
	ImportUser string
	ImportGID  func() (int, error)

	// grant replaces grantQEMU in tests (some test file systems have no
	// POSIX ACLs); verify replaces verifyPath.
	grant  func(f *Folder, name string, uid uint32) error
	verify func(f *Folder, name string) error
	// onLink replaces hostPrefixes (tests).
	onLink func() []netip.Prefix

	mu     sync.Mutex // creates, deletes and renames
	vmMu   sync.Mutex
	vmLock map[string]*vmLockEntry

	tokens tokenTable
	tasks  taskTable

	statsMu  sync.Mutex
	samples  map[string]sample
	running  map[string]bool // last seen state, for stop detection
	restart  map[string]bool // hardware changed while running
	addrs    map[string][]string
	prepared map[string]bool // devices prepared and not yet released
}

func (m *Manager) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *Manager) root() string {
	if m.Root == "" {
		return "/"
	}
	return m.Root
}

// sys is a host path as this process sees it.
func (m *Manager) sys(p string) string { return filepath.Join(m.root(), p) }

func (m *Manager) arch() ArchInfo {
	if m.Arch != nil {
		return *m.Arch
	}
	a, _ := HostArch()
	return a
}

// vmLockEntry is one VM's lock and how many hold or wait for it.
type vmLockEntry struct {
	mu    sync.Mutex
	users int
}

// lock serializes changes to one VM. Callers check the id first (ValidID),
// and the entry goes when nobody holds or waits for it, so ids hardyd
// makes up don't pile up.
func (m *Manager) lock(id string) func() {
	m.vmMu.Lock()
	if m.vmLock == nil {
		m.vmLock = map[string]*vmLockEntry{}
	}
	l, ok := m.vmLock[id]
	if !ok {
		l = &vmLockEntry{}
		m.vmLock[id] = l
	}
	l.users++
	m.vmMu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		m.vmMu.Lock()
		l.users--
		if l.users == 0 {
			delete(m.vmLock, id)
		}
		m.vmMu.Unlock()
	}
}

// lockValid checks a VM id and takes its lock.
func (m *Manager) lockValid(id string) (func(), error) {
	if ValidID(id) != nil {
		return nil, ErrNotFound
	}
	return m.lock(id), nil
}

// lockCount is how many VM locks exist (tests).
func (m *Manager) lockCount() int {
	m.vmMu.Lock()
	defer m.vmMu.Unlock()
	return len(m.vmLock)
}

func (m *Manager) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return sysexec.Output(ctx, m.Runner, name, args...)
}

func (m *Manager) zfs(ctx context.Context, args ...string) ([]byte, error) {
	return m.run(ctx, "zfs", args...)
}

// virsh talks to the system libvirt.
func (m *Manager) virsh(ctx context.Context, args ...string) ([]byte, error) {
	return m.run(ctx, "virsh", append([]string{"-c", "qemu:///system", "-q"}, args...)...)
}

func (m *Manager) qemuUID() (uint32, error) {
	if m.QEMUUser != nil {
		return m.QEMUUser()
	}
	u, err := user.Lookup("libvirt-qemu")
	if err != nil {
		return 0, fmt.Errorf("QEMU's user (libvirt-qemu) doesn't exist; is libvirt installed? %w", err)
	}
	id, err := strconv.ParseUint(u.Uid, 10, 32)
	return uint32(id), err
}

func (m *Manager) mounts() shares.MountVerifier {
	if m.Mounts != nil {
		return m.Mounts
	}
	t, err := shares.ReadMountTable()
	if err != nil {
		return shares.MountFunc(func(string, string) (uint64, error) { return 0, err })
	}
	return t
}

// ---- finding VMs ----------------------------------------------------------

// stored is a VM as found on its pool.
type stored struct {
	spec    Spec
	dataset string
	dir     string // mountpoint (host path)
	dev     uint64 // verified mount
}

// datasets lists VM datasets: name -> mountpoint, for every pool.
func (m *Manager) datasets(ctx context.Context) (map[string]string, error) {
	out, err := m.zfs(ctx, "list", "-H", "-p", "-t", "filesystem", "-o", "name,mountpoint,"+PropVM)
	if err != nil {
		return nil, fmt.Errorf("listing VMs: %w", err)
	}
	res := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 || f[2] == "-" || f[2] == "" {
			continue
		}
		pool, _, _ := strings.Cut(f[0], "/")
		if ValidID(f[2]) != nil || f[0] != Dataset(pool, f[2]) {
			continue
		}
		res[f[0]] = f[1]
	}
	return res, nil
}

// all reads every VM's spec.
func (m *Manager) all(ctx context.Context) ([]*stored, error) {
	ds, err := m.datasets(ctx)
	if err != nil {
		return nil, err
	}
	var out []*stored
	names := make([]string, 0, len(ds))
	for n := range ds {
		names = append(names, n)
	}
	sort.Strings(names)
	seen := map[string]bool{}
	seenUUID := map[string]string{}
	for _, name := range names {
		st, err := m.read(name, ds[name])
		if err != nil {
			m.log().Warn("vms: skipping a VM that can't be read", "dataset", name, "err", err)
			continue
		}
		if seen[st.spec.ID] {
			m.log().Warn("vms: two pools have a VM with the same name; using the first", "id", st.spec.ID, "dataset", name)
			continue
		}
		if other, dup := seenUUID[st.spec.UUID]; dup {
			m.log().Warn("vms: skipping a VM with the same UUID as another", "id", st.spec.ID, "dataset", name, "uuid", st.spec.UUID, "other", other)
			continue
		}
		seen[st.spec.ID] = true
		seenUUID[st.spec.UUID] = st.spec.ID
		out = append(out, st)
	}
	return out, nil
}

func (m *Manager) read(dataset, mountpoint string) (*stored, error) {
	if !filepath.IsAbs(mountpoint) || filepath.Clean(mountpoint) != mountpoint {
		return nil, fmt.Errorf("%s isn't mounted", dataset)
	}
	dev, err := m.mounts().VerifyMount(mountpoint, dataset)
	if err != nil {
		return nil, err
	}
	b, err := rootfile.ReadFile(filepath.Join(m.sys(mountpoint), specFile))
	if err != nil {
		return nil, err
	}
	var s Spec
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", specFile, err)
	}
	pool, _, _ := strings.Cut(dataset, "/")
	if s.Pool != pool || Dataset(pool, s.ID) != dataset {
		return nil, fmt.Errorf("%s describes %s on %s, not this dataset", specFile, s.ID, s.Pool)
	}
	s.Normalize()
	if err := m.checkStored(&s); err != nil {
		return nil, fmt.Errorf("%s: %w", specFile, err)
	}
	return &stored{spec: s, dataset: dataset, dir: mountpoint, dev: dev}, nil
}

// checkStored checks a spec read from a pool as strictly as one from
// hardyd (a pool can come from another server, or a snapshot from before
// a check existed), except for limits of this server (memory, CPUs, which
// pools are imported, firmware packages): those stop the VM from
// starting, not from being listed.
func (m *Manager) checkStored(s *Spec) error {
	if !uuidRE.MatchString(s.UUID) {
		return fmt.Errorf("the VM's UUID %q isn't valid", s.UUID)
	}
	for i, n := range s.NICs {
		if n.MAC == "" {
			return fmt.Errorf("network card %d has no MAC address", i+1)
		}
	}
	return s.Validate(Host{Arch: m.arch(), TPM: true, SecureBoot: true})
}

func (m *Manager) find(ctx context.Context, id string) (*stored, error) {
	if ValidID(id) != nil {
		return nil, ErrNotFound
	}
	l, err := m.all(ctx)
	if err != nil {
		return nil, err
	}
	for _, st := range l {
		if st.spec.ID == id {
			return st, nil
		}
	}
	return nil, ErrNotFound
}

func (m *Manager) saveSpec(st *stored) error {
	b, err := json.MarshalIndent(st.spec, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(m.sys(st.dir), specFile), append(b, '\n'), 0o600)
}

func writeAtomic(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---- host -----------------------------------------------------------------

// bootPools are never offered for VM disks.
var bootPools = map[string]bool{"rpool": true, "bpool": true, "boot-pool": true, "hardyos-boot": true}

func (m *Manager) pools(ctx context.Context) []string {
	out, err := m.run(ctx, "zpool", "list", "-H", "-o", "name,health")
	if err != nil {
		return nil
	}
	var l []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 2 || bootPools[f[0]] || zfs.ValidPoolName(f[0]) != nil {
			continue
		}
		if f[1] == "ONLINE" || f[1] == "DEGRADED" {
			l = append(l, f[0])
		}
	}
	return l
}

func (m *Manager) memTotalMB() int {
	b, err := os.ReadFile(m.sys("/proc/meminfo"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "MemTotal:" {
			kb, _ := strconv.Atoi(f[1])
			return kb / 1024
		}
	}
	return 0
}

func (m *Manager) cpus() int {
	b, err := os.ReadFile(m.sys("/proc/cpuinfo"))
	if err == nil {
		n := strings.Count(string(b), "\nprocessor") + boolInt(strings.HasPrefix(string(b), "processor"))
		if n > 0 {
			return n
		}
	}
	return 0
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// firmwareFeatures reads QEMU's firmware descriptors (the standard
// /usr/share/qemu/firmware/*.json) for the server's architecture.
func (m *Manager) firmwareFeatures() (uefi, secureBoot bool) {
	files, _ := filepath.Glob(m.sys("/usr/share/qemu/firmware/*.json"))
	arch := m.arch().Arch
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var d struct {
			InterfaceTypes []string `json:"interface-types"`
			Targets        []struct {
				Architecture string `json:"architecture"`
			} `json:"targets"`
			Features []string `json:"features"`
		}
		if json.Unmarshal(b, &d) != nil || !slices.Contains(d.InterfaceTypes, "uefi") {
			continue
		}
		for _, t := range d.Targets {
			if t.Architecture == arch {
				uefi = true
				if slices.Contains(d.Features, "secure-boot") && slices.Contains(d.Features, "enrolled-keys") {
					secureBoot = true
				}
			}
		}
	}
	return uefi, secureBoot
}

func (m *Manager) hasFile(p string) bool {
	_, err := os.Stat(m.sys(p))
	return err == nil
}

func (m *Manager) host(ctx context.Context) Host {
	_, sb := m.firmwareFeatures()
	return Host{
		CPUs: m.cpus(), MemoryMB: m.memTotalMB(), Pools: m.pools(ctx), Arch: m.arch(),
		TPM: m.hasFile("/usr/bin/swtpm"), SecureBoot: sb,
	}
}

// Capabilities is what the New VM wizard needs to know about the server.
type Capabilities struct {
	Supported  bool     `json:"supported"`
	Problem    string   `json:"problem"`
	KVM        bool     `json:"kvm"`
	Arch       ArchInfo `json:"arch"`
	CPUs       int      `json:"cpus"`
	MemoryMB   int      `json:"memoryMB"`
	Pools      []string `json:"pools"`
	UEFI       bool     `json:"uefi"`
	SecureBoot bool     `json:"secureBoot"`
	TPM        bool     `json:"tpm"`
	Libvirt    string   `json:"libvirt"`
	// Bridge is the home network's bridge ("" until the first bridged VM
	// creates it).
	Bridge string `json:"bridge"`
	// Library: the ISOs shared folder's pool ("" when there's none yet).
	Library string `json:"library"`
	// Virtio: the VirtIO drivers disc is downloaded.
	Virtio bool `json:"virtio"`
	// Devices is part D's overview (IOMMU, GPUs), when it's installed.
	Devices any `json:"devices"`
	// Committed is the memory of running VMs, for the overcommit hint.
	CommittedMB int `json:"committedMB"`
	// Security is how libvirt confines QEMU (apparmor, or "" when it
	// doesn't, which makes VMs unsupported).
	Security string `json:"security"`
	// SpoofingFilter: libvirt's clean-traffic filter is there for cards
	// on the home network.
	SpoofingFilter bool `json:"spoofingFilter"`
}

// Capabilities reports what this server can do for VMs.
func (m *Manager) Capabilities(ctx context.Context) *Capabilities {
	a, ok := HostArch()
	if m.Arch != nil {
		a, ok = *m.Arch, true
	}
	c := &Capabilities{Arch: a, CPUs: m.cpus(), MemoryMB: m.memTotalMB(), Pools: m.pools(ctx), KVM: m.hasFile("/dev/kvm")}
	if c.Pools == nil {
		c.Pools = []string{}
	}
	c.UEFI, c.SecureBoot = m.firmwareFeatures()
	c.TPM = m.hasFile("/usr/bin/swtpm")
	if out, err := m.virsh(ctx, "version", "--daemon"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Running against daemon:"); ok {
				c.Libvirt = strings.TrimSpace(v)
			}
		}
		if c.Libvirt == "" {
			c.Libvirt = "running"
		}
	}
	var models []string
	if c.Libvirt != "" {
		models, _ = m.securityModels(ctx)
		for _, s := range models {
			if s == SecurityModel {
				c.Security = s
			}
		}
		c.SpoofingFilter = m.hasFilter(ctx)
	}
	switch {
	case !ok:
		c.Problem = "virtual machines aren't supported on this server's processor architecture yet"
	case !c.KVM:
		c.Problem = "the processor's virtualization (Intel VT-x or AMD-V) is off or missing: turn it on in the server's BIOS/UEFI setup"
	case c.Libvirt == "":
		c.Problem = "the virtualization service (libvirt) isn't running"
	case c.Security == "":
		c.Problem = noConfinement(models)
	}
	c.Supported = c.Problem == ""
	if m.Network != nil {
		c.Bridge = m.Network.BridgeName()
	}
	if f, err := m.folder(ctx, "", false); err == nil && f != nil {
		c.Library = f.Pool
		if _, err := m.virtioPath(ctx); err == nil {
			c.Virtio = true
		}
	}
	if m.DevicesInfo != nil {
		if d, err := m.DevicesInfo(ctx); err == nil {
			c.Devices = d
		}
	}
	m.statsMu.Lock()
	for id, run := range m.running {
		if run {
			if st, err := m.find(ctx, id); err == nil {
				c.CommittedMB += st.spec.Memory.MB
			}
		}
	}
	m.statsMu.Unlock()
	return c
}

// ---- views ----------------------------------------------------------------

// VM is a VM as hardyd sees it.
type VM struct {
	Spec
	Dataset string `json:"dataset"`
	// State: running, stopped, paused, shutting-down, crashed, starting,
	// suspended or unknown (libvirt doesn't know it yet).
	State      string  `json:"state"`
	CPUPercent float64 `json:"cpuPercent"`
	// MemoryUsedMB is what the guest uses (with the balloon) or what it has.
	MemoryUsedMB int      `json:"memoryUsedMB"`
	Addresses    []string `json:"addresses"`
	// PasswordSet: the cloud-init user has a password (its hash isn't sent).
	PasswordSet bool `json:"passwordSet"`
	// RestartNeeded: hardware changed while it ran.
	RestartNeeded bool `json:"restartNeeded"`
	// DiskUsage is how much of each disk is in use on the pool (bytes).
	DiskUsage map[string]int64 `json:"diskUsage"`
}

func (m *Manager) view(st *stored, stats map[string]domStats) VM {
	v := VM{Spec: st.spec, Dataset: st.dataset, State: "unknown", Addresses: []string{}, DiskUsage: map[string]int64{}}
	if v.CloudInit != nil {
		ci := *v.CloudInit
		v.PasswordSet = ci.PasswordHash != ""
		ci.PasswordHash = ""
		v.CloudInit = &ci
	}
	if ds, ok := stats[st.spec.ID]; ok {
		v.State = ds.State
		v.CPUPercent = ds.CPUPercent
		v.MemoryUsedMB = ds.MemoryUsedMB
	}
	m.statsMu.Lock()
	v.RestartNeeded = m.restart[st.spec.ID] && v.State == "running"
	if a := m.addrs[st.spec.ID]; a != nil && v.State == "running" {
		v.Addresses = append(v.Addresses, a...)
	}
	m.statsMu.Unlock()
	return v
}

// Overview is the list the Virtual Machines app shows.
type Overview struct {
	VMs  []VM       `json:"vms"`
	Kept []KeptDisk `json:"kept"`
}

// KeptDisk is a deleted VM's disks, kept on request.
type KeptDisk struct {
	Dataset string `json:"dataset"`
	VM      string `json:"vm"`
	Pool    string `json:"pool"`
	Bytes   int64  `json:"bytes"`
}

// List returns every VM with its state.
func (m *Manager) List(ctx context.Context) (*Overview, error) {
	l, err := m.all(ctx)
	if err != nil {
		return nil, err
	}
	stats := m.stats(ctx)
	o := &Overview{VMs: []VM{}, Kept: m.kept(ctx)}
	for _, st := range l {
		o.VMs = append(o.VMs, m.view(st, stats))
	}
	return o, nil
}

// Get returns one VM, with its addresses and disk use.
func (m *Manager) Get(ctx context.Context, id string) (*VM, error) {
	st, err := m.find(ctx, id)
	if err != nil {
		return nil, err
	}
	stats := m.stats(ctx)
	v := m.view(st, stats)
	if v.State == "running" {
		v.Addresses = m.addresses(ctx, st)
	}
	if out, err := m.zfs(ctx, "list", "-H", "-p", "-t", "volume", "-o", "name,used", "-r", st.dataset); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			f := strings.Split(line, "\t")
			if len(f) == 2 {
				n, _ := strconv.ParseInt(f[1], 10, 64)
				v.DiskUsage[filepath.Base(f[0])] = n
			}
		}
	}
	return &v, nil
}

func (m *Manager) kept(ctx context.Context) []KeptDisk {
	out := []KeptDisk{}
	b, err := m.zfs(ctx, "list", "-H", "-p", "-t", "filesystem", "-o", "name,used,"+PropKept)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 || f[2] == "-" || ValidID(f[2]) != nil {
			continue
		}
		pool, rest, _ := strings.Cut(f[0], "/")
		if !strings.HasPrefix(rest, "vms/"+f[2]+"-kept-") || strings.Count(rest, "/") != 1 {
			continue
		}
		n, _ := strconv.ParseInt(f[1], 10, 64)
		out = append(out, KeptDisk{Dataset: f[0], VM: f[2], Pool: pool, Bytes: n})
	}
	return out
}

// ---- create, update, delete ----------------------------------------------

// CreateArgs makes a VM. Password is the cloud-init user's password; it's
// hashed here and never stored.
type CreateArgs struct {
	Spec     Spec   `json:"spec"`
	Password string `json:"password,omitempty"`
	// AllowOvercommit makes the VM even when its disks are bigger than
	// the pool's free space (they're thin).
	AllowOvercommit bool `json:"allowOvercommit,omitempty"`
}

// Result is a change's outcome with anything worth telling the person.
type Result struct {
	VM       *VM      `json:"vm"`
	Warnings []string `json:"warnings"`
}

func (m *Manager) hashPassword(ctx context.Context, pw string) (string, error) {
	if len(pw) < 8 || len(pw) > 256 || strings.ContainsAny(pw, "\x00\n\r") {
		return "", Problems{"the cloud-init password must be 8 to 256 characters on one line"}
	}
	res, err := m.Runner.Run(ctx, []byte(pw+"\n"), "openssl", "passwd", "-6", "-stdin")
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("hashing the password failed: %s", strings.TrimSpace(string(res.Stderr)))
	}
	h := strings.TrimSpace(string(res.Stdout))
	if !cryptRE.MatchString(h) {
		return "", errors.New("hashing the password gave something unexpected")
	}
	return h, nil
}

// prepareSpec fills in what a new or changed spec needs from root: UUID,
// MAC addresses, the password hash.
func (m *Manager) prepareSpec(ctx context.Context, s *Spec, password string, prev *Spec) error {
	s.Normalize()
	if prev != nil {
		s.UUID = prev.UUID
	} else {
		s.UUID = NewUUID()
	}
	used := map[string]bool{}
	for _, n := range s.NICs {
		used[n.MAC] = true
	}
	for i := range s.NICs {
		if s.NICs[i].MAC == "" {
			mac := NewMAC()
			for used[mac] {
				mac = NewMAC()
			}
			used[mac] = true
			s.NICs[i].MAC = mac
		}
	}
	if s.CloudInit != nil {
		switch {
		case password != "":
			h, err := m.hashPassword(ctx, password)
			if err != nil {
				return err
			}
			s.CloudInit.PasswordHash = h
		case prev != nil && prev.CloudInit != nil:
			s.CloudInit.PasswordHash = prev.CloudInit.PasswordHash
		default:
			// A hash can only come from root.
			s.CloudInit.PasswordHash = ""
		}
	}
	return nil
}

// checkMedia makes sure the discs and images a spec names exist.
func (m *Manager) checkMedia(ctx context.Context, s *Spec) error {
	var p Problems
	files := s.Files()
	for _, d := range s.Disks {
		if d.Import != nil {
			files = append(files, d.Import.File)
		}
	}
	if len(files) == 0 {
		return nil
	}
	f, err := m.folder(ctx, "", false)
	if err != nil {
		return err
	}
	if f == nil {
		return Problems{"there's no ISOs shared folder yet: download a disc or copy one into it first"}
	}
	if f.NFS && (len(s.Files()) > 0 || s.NeedsVirtio()) {
		return Problems{nfsDiscs}
	}
	for _, name := range files {
		file, err := openFile(f, name)
		if err != nil {
			p = append(p, err.Error())
			continue
		}
		file.Close()
	}
	if len(p) > 0 {
		return p
	}
	return nil
}

func (m *Manager) checkDevices(ctx context.Context, s *Spec) error {
	if len(s.Devices) == 0 {
		return nil
	}
	if m.Devices == nil {
		return Problems{"passing devices through to VMs isn't available on this server yet"}
	}
	return m.Devices.Check(ctx, s.ID, s.Devices)
}

// Create makes a VM: its datasets and disks, cloud-init seed and libvirt
// definition. Disks to import are filled afterwards (Import).
func (m *Manager) Create(ctx context.Context, a CreateArgs) (*Result, error) {
	s := a.Spec
	if err := m.prepareSpec(ctx, &s, a.Password, nil); err != nil {
		return nil, err
	}
	if err := s.Validate(m.host(ctx)); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.find(ctx, s.ID); err == nil {
		return nil, Problems{fmt.Sprintf("there's already a VM called %s", s.ID)}
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	ds := Dataset(s.Pool, s.ID)
	if _, err := m.zfs(ctx, "list", "-H", "-o", "name", ds); err == nil {
		return nil, Problems{fmt.Sprintf("%s already exists on %s (kept disks of a deleted VM?); choose another name", ds, s.Pool)}
	}
	if err := m.checkMedia(ctx, &s); err != nil {
		return nil, err
	}
	if err := m.checkDevices(ctx, &s); err != nil {
		return nil, err
	}
	if s.NeedsBridge() && (m.Network == nil || m.Network.BridgeName() == "") {
		return nil, Problems{"the home network's bridge isn't set up yet"}
	}
	if err := m.checkSpace(ctx, s.Pool, diskBytes(&s), a.AllowOvercommit); err != nil {
		return nil, err
	}

	cleanup := func() {
		if _, err := m.zfs(context.Background(), "destroy", "-r", ds); err != nil {
			m.log().Warn("vms: removing a VM that couldn't be created", "dataset", ds, "err", err)
		}
	}
	parent := s.Pool + "/vms"
	if _, err := m.zfs(ctx, "list", "-H", "-o", "name", parent); err != nil {
		if _, err := m.zfs(ctx, "create", parent); err != nil {
			return nil, fmt.Errorf("creating %s: %w", parent, err)
		}
	}
	if _, err := m.zfs(ctx, "create", "-o", PropVM+"="+s.ID, "-o", "canmount=on", "-o", "devices=off", "-o", "setuid=off", "-o", "exec=off",
		"-o", "quota="+strconv.FormatInt(quotaBytes(&s), 10), ds); err != nil {
		return nil, fmt.Errorf("creating the VM's dataset: %w", err)
	}
	st, err := m.mounted(ctx, ds)
	if err != nil {
		cleanup()
		return nil, err
	}
	st.spec = s
	for _, d := range s.Disks {
		if err := m.createDisk(ctx, &s, d); err != nil {
			cleanup()
			return nil, err
		}
	}
	if err := m.saveSpec(st); err != nil {
		cleanup()
		return nil, err
	}
	if s.CloudInit != nil {
		if err := m.writeSeed(ctx, st); err != nil {
			cleanup()
			return nil, err
		}
	}
	if err := m.define(ctx, st, nil); err != nil {
		cleanup()
		return nil, err
	}
	m.log().Info("vms: created", "id", s.ID, "pool", s.Pool, "template", s.Template)
	v, err := m.Get(ctx, s.ID)
	if err != nil {
		return nil, err
	}
	return &Result{VM: v, Warnings: m.memoryWarnings(ctx, &s, false)}, nil
}

// mounted checks a VM dataset's mount and prepares its folder.
func (m *Manager) mounted(ctx context.Context, ds string) (*stored, error) {
	out, err := m.zfs(ctx, "get", "-H", "-p", "-o", "value", "mountpoint", ds)
	if err != nil {
		return nil, err
	}
	mp := strings.TrimSpace(string(out))
	if !filepath.IsAbs(mp) || filepath.Clean(mp) != mp {
		return nil, fmt.Errorf("%s has no mountpoint", ds)
	}
	dev, err := m.mounts().VerifyMount(mp, ds)
	if err != nil {
		return nil, fmt.Errorf("%s isn't mounted: %w", ds, err)
	}
	// Root only: the spec and the TPM state. QEMU needs to reach the
	// cloud-init seed and NVRAM, which libvirt hands it by file.
	if err := os.Chmod(m.sys(mp), 0o711); err != nil {
		return nil, err
	}
	return &stored{dataset: ds, dir: mp, dev: dev}, nil
}

func (m *Manager) createDisk(ctx context.Context, s *Spec, d Disk) error {
	ds := DiskDataset(s.Pool, s.ID, d.Name)
	// Thin (sparse) zvols with 16K blocks: a good default for VM disks.
	if _, err := m.zfs(ctx, "create", "-s", "-V", strconv.Itoa(d.SizeGB)+"G", "-o", "volblocksize=16K", "-o", PropVM+"="+s.ID, ds); err != nil {
		return fmt.Errorf("creating %s: %w", d.Name, err)
	}
	return nil
}

// UpdateArgs replaces a VM's spec. Disks missing from the new spec are
// destroyed only when named in RemoveDisks, with the VM's name typed in
// Confirm (and the VM is off).
type UpdateArgs struct {
	Spec        Spec     `json:"spec"`
	Password    string   `json:"password,omitempty"`
	RemoveDisks []string `json:"removeDisks,omitempty"`
	Confirm     string   `json:"confirm,omitempty"`
	// AllowOvercommit: see CreateArgs.
	AllowOvercommit bool `json:"allowOvercommit,omitempty"`
}

// Update changes a VM. Most hardware changes apply at the next start.
func (m *Manager) Update(ctx context.Context, a UpdateArgs) (*Result, error) {
	id := a.Spec.ID
	unlock, err := m.lockValid(id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	st, err := m.find(ctx, id)
	if err != nil {
		return nil, err
	}
	prev := st.spec
	s := a.Spec
	if err := m.prepareSpec(ctx, &s, a.Password, &prev); err != nil {
		return nil, err
	}
	var p Problems
	if s.Pool != prev.Pool {
		p = append(p, "a VM can't move to another pool")
	}
	if s.Template != prev.Template {
		s.Template = prev.Template // the template is history, not a setting
	}
	if err := s.Validate(m.host(ctx)); err != nil {
		var vp Problems
		if errors.As(err, &vp) {
			p = append(p, vp...)
		} else {
			return nil, err
		}
	}
	state := m.state(ctx, id)
	running := state == "running" || state == "paused"
	old := map[string]Disk{}
	for _, d := range prev.Disks {
		old[d.Name] = d
	}
	var add []Disk
	var grow []Disk
	keep := map[string]bool{}
	for _, d := range s.Disks {
		o, ok := old[d.Name]
		keep[d.Name] = true
		switch {
		case !ok:
			if d.Import != nil {
				p = append(p, fmt.Sprintf("%s: images can only be imported into a new VM's disks", d.Name))
			}
			add = append(add, d)
		case d.SizeGB < o.SizeGB:
			p = append(p, fmt.Sprintf("%s can't shrink (from %d GB to %d GB)", d.Name, o.SizeGB, d.SizeGB))
		case d.SizeGB > o.SizeGB:
			grow = append(grow, d)
		}
		if ok {
			d.Import = o.Import
		}
	}
	var remove []string
	for _, d := range prev.Disks {
		if keep[d.Name] {
			continue
		}
		if !slices.Contains(a.RemoveDisks, d.Name) {
			p = append(p, fmt.Sprintf("%s is missing; confirm that it should be deleted", d.Name))
			continue
		}
		if running {
			p = append(p, fmt.Sprintf("stop the VM to delete %s", d.Name))
		}
		remove = append(remove, d.Name)
	}
	if len(remove) > 0 && !Confirms(a.Confirm, &prev) {
		p = append(p, fmt.Sprintf("type the VM's name (%s) to confirm deleting %s", prev.Name, strings.Join(remove, ", ")))
	}
	for _, name := range a.RemoveDisks {
		if !slices.Contains(remove, name) {
			p = append(p, fmt.Sprintf("%s isn't a disk being removed", name))
		}
	}
	if len(p) > 0 {
		return nil, p
	}
	if err := m.checkMedia(ctx, &s); err != nil {
		return nil, err
	}
	if !slices.EqualFunc(s.Devices, prev.Devices, func(a, b devices.Device) bool { return a == b }) {
		if err := m.checkDevices(ctx, &s); err != nil {
			return nil, err
		}
	}
	if s.NeedsBridge() && (m.Network == nil || m.Network.BridgeName() == "") {
		return nil, Problems{"the home network's bridge isn't set up yet"}
	}
	var more int64
	for _, d := range add {
		more += int64(d.SizeGB) << 30
	}
	for _, d := range grow {
		more += int64(d.SizeGB-old[d.Name].SizeGB) << 30
	}
	if err := m.checkSpace(ctx, s.Pool, more, a.AllowOvercommit); err != nil {
		return nil, err
	}
	// The space limit grows before the disks do, and shrinks after.
	if more > 0 {
		if err := m.setQuota(ctx, st.dataset, &s, 0); err != nil {
			return nil, err
		}
	}
	for _, d := range add {
		if err := m.createDisk(ctx, &s, d); err != nil {
			return nil, err
		}
	}
	for _, d := range grow {
		if _, err := m.zfs(ctx, "set", "volsize="+strconv.Itoa(d.SizeGB)+"G", DiskDataset(s.Pool, s.ID, d.Name)); err != nil {
			return nil, fmt.Errorf("growing %s: %w", d.Name, err)
		}
	}
	for _, name := range remove {
		if _, err := m.zfs(ctx, "destroy", "-r", DiskDataset(s.Pool, s.ID, name)); err != nil {
			return nil, fmt.Errorf("deleting %s: %w", name, err)
		}
	}
	// Disks keep their import record, so the restored history is honest.
	for i, d := range s.Disks {
		if o, ok := old[d.Name]; ok {
			s.Disks[i].Import = o.Import
		}
	}
	st.spec = s
	if err := m.saveSpec(st); err != nil {
		return nil, err
	}
	if more <= 0 && len(remove) > 0 {
		if err := m.setQuota(ctx, st.dataset, &s, 0); err != nil {
			m.log().Warn("vms: lowering the VM's space limit", "id", id, "err", err)
		}
	}
	if s.CloudInit != nil && !sameCloudInit(prev.CloudInit, s.CloudInit) {
		if err := m.writeSeed(ctx, st); err != nil {
			return nil, err
		}
	}
	if err := m.define(ctx, st, nil); err != nil {
		return nil, err
	}
	var warnings []string
	if running && hardwareChanged(&prev, &s) {
		m.statsMu.Lock()
		if m.restart == nil {
			m.restart = map[string]bool{}
		}
		m.restart[id] = true
		m.statsMu.Unlock()
		warnings = append(warnings, "Restart the VM for the hardware changes to take effect.")
	}
	m.log().Info("vms: updated", "id", id)
	v, err := m.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &Result{VM: v, Warnings: append(warnings, m.memoryWarnings(ctx, &s, running)...)}, nil
}

func sameCloudInit(a, b *CloudInit) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.User == b.User && a.Hostname == b.Hostname && a.PasswordHash == b.PasswordHash &&
		a.InstallAgent == b.InstallAgent && slices.Equal(a.SSHKeys, b.SSHKeys)
}

// hardwareChanged reports changes that only apply when the VM next starts.
func hardwareChanged(a, b *Spec) bool {
	ja, _ := json.Marshal([]any{a.CPU, a.Memory, a.Firmware, a.Disks, a.Media, a.NICs, a.Video, a.GuestAgent, a.Boot, a.Devices})
	jb, _ := json.Marshal([]any{b.CPU, b.Memory, b.Firmware, b.Disks, b.Media, b.NICs, b.Video, b.GuestAgent, b.Boot, b.Devices})
	return string(ja) != string(jb)
}

// DeleteArgs deletes a VM. Confirm repeats its name (id or display name).
type DeleteArgs struct {
	ID      string `json:"id"`
	Confirm string `json:"confirm"`
	// KeepDisks keeps the disks (renamed <pool>/vms/<id>-kept-<when>).
	KeepDisks bool `json:"keepDisks"`
}

// Confirms reports whether typed names the VM.
func Confirms(typed string, s *Spec) bool {
	typed = strings.TrimSpace(typed)
	return typed != "" && (typed == s.ID || strings.EqualFold(typed, s.Name))
}

// Delete removes a VM. It must be off.
func (m *Manager) Delete(ctx context.Context, a DeleteArgs) error {
	unlock, err := m.lockValid(a.ID)
	if err != nil {
		return err
	}
	defer unlock()
	st, err := m.find(ctx, a.ID)
	if err != nil {
		return err
	}
	if !Confirms(a.Confirm, &st.spec) {
		return Problems{fmt.Sprintf("type the VM's name (%s) to confirm", st.spec.Name)}
	}
	if s := m.state(ctx, a.ID); s != "stopped" && s != "unknown" && s != "crashed" {
		return Problems{"stop the VM before deleting it"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.afterStop(ctx, st)
	if _, err := m.virsh(ctx, "undefine", a.ID, "--nvram", "--tpm"); err != nil && !notDefined(err) {
		// Older libvirt without --tpm.
		if _, err2 := m.virsh(ctx, "undefine", a.ID, "--nvram"); err2 != nil && !notDefined(err2) {
			return fmt.Errorf("removing the VM from libvirt: %w", err)
		}
	}
	if a.KeepDisks {
		kept := fmt.Sprintf("%s/vms/%s-kept-%s", st.spec.Pool, st.spec.ID, m.now().Format("20060102-150405"))
		if _, err := m.zfs(ctx, "rename", st.dataset, kept); err != nil {
			return fmt.Errorf("keeping the disks: %w", err)
		}
		if _, err := m.zfs(ctx, "set", PropKept+"="+st.spec.ID, kept); err != nil {
			m.log().Warn("vms: marking kept disks", "dataset", kept, "err", err)
		}
		if _, err := m.zfs(ctx, "inherit", "-r", PropVM, kept); err != nil {
			m.log().Warn("vms: unmarking kept disks", "dataset", kept, "err", err)
		}
		m.log().Info("vms: deleted, disks kept", "id", a.ID, "kept", kept)
	} else {
		if _, err := m.zfs(ctx, "destroy", "-r", st.dataset); err != nil {
			return fmt.Errorf("deleting the VM's disks: %w", err)
		}
		m.log().Info("vms: deleted", "id", a.ID)
	}
	m.forget(a.ID)
	return nil
}

// DeleteKeptArgs deletes disks kept from a deleted VM.
type DeleteKeptArgs struct {
	Dataset string `json:"dataset"`
	Confirm string `json:"confirm"` // the deleted VM's id
}

// DeleteKept destroys kept disks.
func (m *Manager) DeleteKept(ctx context.Context, a DeleteKeptArgs) error {
	for _, k := range m.kept(ctx) {
		if k.Dataset == a.Dataset {
			if strings.TrimSpace(a.Confirm) != k.VM {
				return Problems{fmt.Sprintf("type %s to confirm", k.VM)}
			}
			_, err := m.zfs(ctx, "destroy", "-r", k.Dataset)
			return err
		}
	}
	return Problems{"there are no kept disks called " + a.Dataset}
}

func (m *Manager) forget(id string) {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	delete(m.samples, id)
	delete(m.running, id)
	delete(m.restart, id)
	delete(m.addrs, id)
	delete(m.prepared, id)
}

func notDefined(err error) bool {
	var ce *sysexec.CommandError
	if errors.As(err, &ce) {
		msg := string(ce.Result.Stderr) + string(ce.Result.Stdout)
		return strings.Contains(msg, "failed to get domain") || strings.Contains(msg, "Domain not found")
	}
	return false
}

// define (re)defines the libvirt domain from the spec; devs are prepared
// devices (only when starting).
func (m *Manager) define(ctx context.Context, st *stored, devs []devices.Prepared) error {
	p, err := m.paths(ctx, st)
	if err != nil {
		return err
	}
	x, err := DomainXML(&st.spec, m.arch(), p, devs)
	if err != nil {
		return err
	}
	dir := m.sys("/run/hardyos/vms")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f := filepath.Join(dir, st.spec.ID+".xml")
	if err := writeAtomic(f, x, 0o600); err != nil {
		return err
	}
	defer os.Remove(f)
	if _, err := m.virsh(ctx, "define", "--validate", filepath.Join("/run/hardyos/vms", st.spec.ID+".xml")); err != nil {
		return fmt.Errorf("libvirt refused the VM's definition: %w", err)
	}
	// HardyOS starts VMs itself, in order (Autostart).
	if _, err := m.virsh(ctx, "autostart", "--disable", st.spec.ID); err != nil {
		m.log().Debug("vms: turning off libvirt's autostart", "id", st.spec.ID, "err", err)
	}
	return nil
}

// paths resolves the files a VM's domain uses.
func (m *Manager) paths(ctx context.Context, st *stored) (Paths, error) {
	p := Paths{StateDir: st.dir, ISOs: map[string]string{}, NATNetwork: "default"}
	if m.Network != nil {
		p.Bridge = m.Network.BridgeName()
	}
	if st.spec.CloudInit != nil {
		p.CloudInit = filepath.Join(st.dir, seedFile)
	}
	if files := st.spec.Files(); len(files) > 0 || st.spec.NeedsVirtio() {
		f, err := m.folder(ctx, "", false)
		if err != nil {
			return p, err
		}
		if f == nil {
			return p, errors.New("the ISOs shared folder is missing (is its pool imported?)")
		}
		for _, name := range files {
			p.ISOs[name] = filepath.Join(f.Path, name)
		}
		if st.spec.NeedsVirtio() {
			if v, err := m.virtioPath(ctx); err == nil {
				p.Virtio = v
			}
		}
	}
	return p, nil
}

// memoryWarnings says when running VMs would want more memory than the
// server has.
func (m *Manager) memoryWarnings(ctx context.Context, s *Spec, alreadyRunning bool) []string {
	total := m.memTotalMB()
	if total == 0 {
		return []string{}
	}
	committed := 0
	if !alreadyRunning {
		committed = s.Memory.MB
	}
	m.statsMu.Lock()
	ids := []string{}
	for id, r := range m.running {
		if r {
			ids = append(ids, id)
		}
	}
	m.statsMu.Unlock()
	for _, id := range ids {
		if st, err := m.find(ctx, id); err == nil {
			committed += st.spec.Memory.MB
		}
	}
	// Leave room for ZFS, Docker apps and HardyOS itself.
	if committed > total*85/100 {
		return []string{fmt.Sprintf("Running VMs would use %d GB of the server's %d GB of memory; the server, its storage cache and apps may slow down.", (committed+512)/1024, (total+512)/1024)}
	}
	return []string{}
}

// readFileLimited returns at most n bytes from the end of a file.
func readTail(path string, n int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	off := fi.Size() - n
	if off < 0 {
		off = 0
	}
	buf := make([]byte, fi.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && len(buf) > 0 {
		return "", err
	}
	s := string(buf)
	if off > 0 {
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			s = s[i+1:]
		}
	}
	return s, nil
}

// Logs returns the end of QEMU's log for the VM.
func (m *Manager) Logs(ctx context.Context, id string, lines int) (string, error) {
	if _, err := m.find(ctx, id); err != nil {
		return "", err
	}
	if lines < 1 || lines > 5000 {
		lines = 300
	}
	s, err := readTail(m.sys(filepath.Join("/var/log/libvirt/qemu", id+".log")), 512<<10)
	if err != nil {
		return "", err
	}
	l := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(l) > lines {
		l = l[len(l)-lines:]
	}
	return strings.Join(l, "\n"), nil
}

// Assignments lists every VM's configured devices, running or not
// (devices.AssignmentsFunc: the Devices view shows "assigned to …").
func (m *Manager) Assignments(ctx context.Context) (map[string][]devices.Device, error) {
	l, err := m.all(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string][]devices.Device{}
	for _, st := range l {
		if len(st.spec.Devices) > 0 {
			out[st.spec.ID] = append([]devices.Device{}, st.spec.Devices...)
		}
	}
	return out, nil
}
