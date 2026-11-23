package san

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/nfs"
	"github.com/hardyos/hardyos/daemon/internal/rootfile"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// StateDir is root's cluster state folder (on the shared dataset).
const StateDir = rootfile.RootStateDir + "/cluster"

// ZFS properties on cluster datasets and zvols.
const (
	PropVM   = "org.hardyos:vm"
	PropApp  = "org.hardyos:app"
	PropRole = "org.hardyos:role"
	// RoleCluster marks a dataset or zvol as cluster storage: only those
	// can be exported, and local engines leave them alone.
	RoleCluster = "cluster"
)

// Index kinds root keeps a high-water mark for.
const (
	markLIO      = "lio"
	markExports  = "exports"
	markFirewall = "firewall"
)

// rootState is root's own record (StateDir/san.json): the desired LIO
// state, the firewall, the exports, root's pins of the compute nodes, and
// the fences root has put in place. A fence recorded here is only lifted
// by Unfence with the same epoch and the node's own signed statement: no
// later Apply, export or firewall change can give a fenced node access
// back (pins.go).
type rootState struct {
	Desired  Desired             `json:"desired"`
	Firewall *FirewallSpec       `json:"firewall,omitempty"`
	Exports  []nfs.ClusterExport `json:"exports,omitempty"`
	// Addresses is the earlier format's storage addresses (read only;
	// Pins replace it).
	Addresses map[cluster.NodeID]netip.Addr `json:"addresses,omitempty"`
	// Subnet is the storage network root pinned.
	Subnet netip.Prefix                   `json:"subnet,omitempty"`
	Pins   map[cluster.NodeID]*Pin        `json:"pins,omitempty"`
	Fences map[cluster.NodeID]FenceRecord `json:"fences,omitempty"`
	// Epochs is each node's highest fence epoch (kept after an unfence).
	Epochs map[cluster.NodeID]uint64 `json:"epochs,omitempty"`
	Marks  map[string]IndexMark      `json:"marks,omitempty"`
	// MACs are members' link-layer addresses root pinned (H2), Neigh the
	// static neighbour entries it made from them.
	MACs  map[netip.Addr]string `json:"macs,omitempty"`
	Neigh []netip.Addr          `json:"neigh,omitempty"`
	// Migrations are a compute node's live-migration allowances (M6).
	Migrations []MigrationAllow `json:"migrations,omitempty"`
	// Holders: which nodes each backstore was mapped to, and before them
	// (H5: a node checks a block file system someone else wrote).
	Holders  map[string]*Holders `json:"holders,omitempty"`
	Resolved map[string]Resolved `json:"resolved,omitempty"`
	Applied  time.Time           `json:"applied"`
	Problem  string              `json:"problem,omitempty"`
	Problems map[string]string   `json:"problems,omitempty"`
}

// Holders records a backstore's writers. Nodes are its current (or last)
// holders, Prev the holders before them; StorageWriter ("") stands for
// the storage node itself (it formats volumes and moves app data). Seq
// changes whenever the holders change.
type Holders struct {
	Nodes []cluster.NodeID `json:"nodes"`
	Prev  []cluster.NodeID `json:"prev,omitempty"`
	Seq   uint64           `json:"seq"`
}

// StorageWriter is the storage node in Holders.
const StorageWriter = cluster.NodeID("")

// OthersWrote reports whether anyone but node wrote the volume in its
// last two holder sets.
func (h *Holders) OthersWrote(node cluster.NodeID) bool {
	if h == nil {
		return true
	}
	for _, l := range [][]cluster.NodeID{h.Nodes, h.Prev} {
		for _, n := range l {
			if n != node {
				return true
			}
		}
	}
	return false
}

func (st *rootState) setHolders(name string, nodes []cluster.NodeID) {
	if len(nodes) == 0 {
		return
	}
	nodes = slices.Clone(nodes)
	slices.Sort(nodes)
	if st.Holders == nil {
		st.Holders = map[string]*Holders{}
	}
	h := st.Holders[name]
	if h == nil {
		st.Holders[name] = &Holders{Nodes: nodes, Seq: 1}
		return
	}
	if slices.Equal(h.Nodes, nodes) {
		return
	}
	h.Prev, h.Nodes = h.Nodes, nodes
	h.Seq++
}

func (st *rootState) mark(kind string) IndexMark { return st.Marks[kind] }

func (st *rootState) advance(kind string, idx uint64, now time.Time) {
	if st.Marks == nil {
		st.Marks = map[string]IndexMark{}
	}
	m := st.Marks[kind]
	m.advance(idx, now)
	st.Marks[kind] = m
}

func (st *rootState) setProblem(kind, msg string) {
	if msg == "" {
		delete(st.Problems, kind)
		return
	}
	if st.Problems == nil {
		st.Problems = map[string]string{}
	}
	st.Problems[kind] = msg
}

// pinArgs are the addresses and keys of root's pins (to apply the saved
// state again: at boot, after a CHAP rotation).
func (st *rootState) pinArgs() (map[cluster.NodeID]netip.Addr, map[cluster.NodeID][]byte) {
	addrs := map[cluster.NodeID]netip.Addr{}
	keys := map[cluster.NodeID][]byte{}
	for n, p := range st.Pins {
		addrs[n], keys[n] = p.Address, p.Key
	}
	return addrs, keys
}

// Root is the storage node's root side: hardyd-priv's san.* operations.
type Root struct {
	Runner sysexec.Runner
	// FS is LIO's configfs (OSFS{ConfigFSRoot} in production).
	FS FS
	// NFS writes the cluster exports.
	NFS *nfs.ClusterManager
	// Dir is root's state folder (StateDir).
	Dir string
	// Sys prefixes system paths (/etc, /dev, /run); "/" in production.
	Sys string
	Log *slog.Logger
	// DeviceWait bounds waiting for a new zvol's device (default 15 s).
	DeviceWait time.Duration
	// Now is root's clock (tests).
	Now func() time.Time

	mu sync.Mutex
}

func (r *Root) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Root) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

func (r *Root) sys(p string) string {
	if r.Sys == "" || r.Sys == "/" {
		return p
	}
	return filepath.Join(r.Sys, p)
}

func (r *Root) statePath() string { return filepath.Join(r.Dir, "san.json") }
func (r *Root) chapPath() string  { return filepath.Join(r.Dir, "chap.json") }

func (r *Root) load() (*rootState, error) {
	b, err := rootfile.ReadFile(r.statePath())
	if errors.Is(err, fs.ErrNotExist) {
		return &rootState{}, nil
	}
	if err != nil {
		return nil, err
	}
	var st rootState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("reading %s: %w", r.statePath(), err)
	}
	return &st, nil
}

func (r *Root) save(st *rootState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return rootfile.WriteInRootDir(r.statePath(), b, 0o600, 0o700)
}

func (r *Root) loadCHAP() (chapFile, error) {
	b, err := rootfile.ReadFile(r.chapPath())
	if errors.Is(err, fs.ErrNotExist) {
		return chapFile{}, nil
	}
	if err != nil {
		return nil, err
	}
	return parseCHAP(b)
}

func (r *Root) saveCHAP(c chapFile) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return rootfile.WriteInRootDir(r.chapPath(), b, 0o600, 0o700)
}

// ensureCHAP returns every node's secrets, generating missing ones (and
// the discovery credential under node "").
func (r *Root) ensureCHAP(nodes []cluster.NodeID) (chapFile, error) {
	c, err := r.loadCHAP()
	if err != nil {
		return nil, err
	}
	changed := false
	for _, n := range append([]cluster.NodeID{""}, nodes...) {
		if s, ok := c[n]; ok && s.Validate() == nil {
			continue
		}
		name := n
		if n == "" {
			name = "discovery"
		}
		s, err := NewSecrets(name)
		if err != nil {
			return nil, err
		}
		c[n] = s
		changed = true
	}
	if changed {
		if err := r.saveCHAP(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// ---- operations -------------------------------------------------------------

// Operation names (hardyd-priv's allowlist; priv/san_ops.go).
const (
	OpStatus         = "san.status"
	OpApply          = "san.apply"
	OpFence          = "san.fence"
	OpUnfence        = "san.unfence"
	OpFirewallApply  = "san.firewall.apply"
	OpMigrationAllow = "san.firewall.migration"
	OpCHAP           = "san.chap.get"
	OpCHAPRotate     = "san.chap.rotate"
	OpVolumeCreate   = "san.volume.create"
	OpVolumeResize   = "san.volume.resize"
	OpVolumeInfo     = "san.volume.info"
	OpVolumeDestroy  = "san.volume.destroy"
	OpDatasetCreate  = "san.dataset.create"
	OpDatasetDestroy = "san.dataset.destroy"
	OpDatasetInfo    = "san.dataset.info"
	OpShareInfo      = "san.share.info"
	OpSnapshotCreate = "san.snapshot.create"
	OpSnapshotList   = "san.snapshot.list"
	OpSnapshotRoll   = "san.snapshot.rollback"
	OpSnapshotDelete = "san.snapshot.destroy"
	OpAppMigrate     = "san.app.migrate"
	OpNFSClusterSet  = "nfs.cluster.apply"
	// Root-only (hardyctl as root on the storage node; never hardyd).
	OpPinReset = "san.pin.reset"
	OpForget   = "san.forget"
)

// PinStatus is one pin as san.status reports it.
type PinStatus struct {
	Address netip.Addr `json:"address"`
	KeyPin  string     `json:"keyPin"`
	MAC     string     `json:"mac,omitempty"`
	Pinned  time.Time  `json:"pinned"`
}

// Status is san.status's answer.
type Status struct {
	// Loaded: LIO's configfs is there.
	Loaded   bool                           `json:"loaded"`
	Desired  Desired                        `json:"desired"`
	Current  map[cluster.NodeID]Target      `json:"current"`
	Sessions map[cluster.NodeID]int         `json:"sessions"`
	Fences   map[cluster.NodeID]uint64      `json:"fences"`
	Exports  map[string][]netip.Addr        `json:"exports"`
	Resolved map[string]Resolved            `json:"resolved"`
	Pins     map[cluster.NodeID]PinStatus   `json:"pins"`
	Subnet   netip.Prefix                   `json:"subnet"`
	Holders  map[string]*Holders            `json:"holders,omitempty"`
	Problem  string                         `json:"problem,omitempty"`
	Applied  time.Time                      `json:"applied"`
	Drift    map[cluster.NodeID]DriftReport `json:"drift,omitempty"`
}

// DriftReport says how a node's live target differs from the desired one.
type DriftReport struct {
	Missing []string `json:"missing,omitempty"`
	Extra   []string `json:"extra,omitempty"`
	Enabled bool     `json:"enabled"`
}

// Status reports LIO's state against the desired one.
func (r *Root) Status(ctx context.Context) (*Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil {
		return nil, err
	}
	out := &Status{
		Loaded: r.FS.Exists("core"), Desired: st.Desired, Fences: map[cluster.NodeID]uint64{}, Resolved: st.Resolved,
		Applied: st.Applied, Current: map[cluster.NodeID]Target{}, Sessions: map[cluster.NodeID]int{},
		Pins: map[cluster.NodeID]PinStatus{}, Subnet: st.Subnet, Holders: st.Holders,
	}
	for n, f := range st.Fences {
		out.Fences[n] = f.Epoch
	}
	for n, p := range st.Pins {
		out.Pins[n] = PinStatus{Address: p.Address, KeyPin: p.KeyPin, MAC: st.MACs[p.Address], Pinned: p.Pinned}
	}
	probs := []string{}
	if st.Problem != "" {
		probs = append(probs, st.Problem)
	}
	for _, k := range []string{markLIO, markExports, markFirewall, "pins"} {
		if p := st.Problems[k]; p != "" {
			probs = append(probs, p)
		}
	}
	out.Problem = strings.Join(probs, "; ")
	if r.NFS != nil {
		out.Exports = r.NFS.Current()
	}
	if out.Loaded && st.Desired.Cluster != "" {
		out.Current = Current(r.FS, st.Desired.Cluster)
		out.Sessions = Sessions(r.FS, st.Desired.Cluster)
		for _, t := range st.Desired.Targets {
			cur := out.Current[t.Node]
			want := t.LUNs
			if !t.Enabled {
				want = nil
			}
			var dr DriftReport
			for _, l := range want {
				if !slices.Contains(cur.LUNs, l) {
					dr.Missing = append(dr.Missing, l)
				}
			}
			for _, l := range cur.LUNs {
				if !slices.Contains(want, l) {
					dr.Extra = append(dr.Extra, l)
				}
			}
			dr.Enabled = cur.Enabled
			if len(dr.Missing)+len(dr.Extra) > 0 || dr.Enabled != t.Enabled {
				if out.Drift == nil {
					out.Drift = map[cluster.NodeID]DriftReport{}
				}
				out.Drift[t.Node] = dr
			}
		}
	}
	return out, nil
}

// ApplyArgs is san.apply.
type ApplyArgs struct {
	Desired Desired `json:"desired"`
	// Addresses and Keys are the compute nodes' storage addresses and
	// cluster keys (SPKI): pinned the first time, checked afterwards.
	Addresses map[cluster.NodeID]netip.Addr `json:"addresses"`
	Keys      map[cluster.NodeID][]byte     `json:"keys,omitempty"`
	// Subnet is the cluster's storage network (pinned the first time).
	Subnet netip.Prefix `json:"subnet,omitempty"`
}

// Apply validates a desired state, checks every backstore's zvol itself,
// enforces root's fences and pins, saves it and reconciles LIO.
func (r *Root) Apply(ctx context.Context, a ApplyArgs) (*Status, error) {
	if err := r.apply(ctx, a); err != nil {
		return nil, err
	}
	return r.Status(ctx)
}

func (r *Root) apply(ctx context.Context, a ApplyArgs) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := a.Desired
	d.Normalize()
	if err := d.Validate(); err != nil {
		return &ValidationError{err}
	}
	st, err := r.load()
	if err != nil {
		return err
	}
	if st.Desired.Cluster != "" && st.Desired.Cluster != d.Cluster {
		return &ValidationError{fmt.Errorf("this storage node serves cluster %s, not %s", st.Desired.Cluster, d.Cluster)}
	}
	now := r.now()
	if err := st.mark(markLIO).check("the desired state", d.Index, now); err != nil {
		return err
	}
	if st.Desired.Index > d.Index {
		return &ValidationError{fmt.Errorf("the desired state from index %d is older than the applied one (%d)", d.Index, st.Desired.Index)}
	}
	if err := st.pinSubnet(a.Subnet); err != nil {
		return err
	}
	own := make([]netip.Addr, 0, len(d.Portals))
	for _, p := range d.Portals {
		own = append(own, p.Addr())
	}
	// Root's fences and pins hold whatever hardyd sends: a fenced node's
	// target, or one whose address or key isn't the pinned one, is
	// disabled with nothing mapped (only that target; M2).
	var pinProbs []string
	for i, t := range d.Targets {
		if fr, fenced := st.Fences[t.Node]; fenced {
			d.Targets[i] = Target{Node: t.Node, Enabled: false, FenceEpoch: fr.Epoch, LUNs: []string{}}
			continue
		}
		if why := st.pinNode(t.Node, a.Addresses[t.Node], a.Keys[t.Node], own, now); why != "" {
			d.Targets[i] = Target{Node: t.Node, Enabled: false, LUNs: []string{}}
			pinProbs = append(pinProbs, fmt.Sprintf("%s's target is off: %s", t.Node, why))
		}
	}
	st.setProblem("pins", strings.Join(pinProbs, "; "))
	resolved := map[string]Resolved{}
	for _, b := range d.Backstores {
		res, err := r.resolveZvol(ctx, d.Cluster, b)
		if err != nil {
			return err
		}
		resolved[b.Name] = res
	}
	nodes := make([]cluster.NodeID, 0, len(d.Targets))
	for _, t := range d.Targets {
		nodes = append(nodes, t.Node)
	}
	chap, err := r.ensureCHAP(nodes)
	if err != nil {
		return err
	}
	// Forget secrets of nodes that left (a rejoin gets new ones).
	for n := range chap {
		if n != "" && !slices.Contains(nodes, n) {
			delete(chap, n)
			if err := r.saveCHAP(chap); err != nil {
				return err
			}
		}
	}
	for _, b := range d.Backstores {
		st.setHolders(b.Name, d.Mapped(b.Name))
	}
	st.Desired = d
	st.Resolved = resolved
	st.Addresses = nil
	st.Applied = now.UTC()
	st.advance(markLIO, d.Index, now)
	plan := Plan{Desired: d, Resolved: resolved, CHAP: map[cluster.NodeID]Secrets{}, Discovery: chap[""]}
	for _, n := range nodes {
		plan.CHAP[n] = chap[n]
	}
	r.loadModules(ctx)
	r.ensureFSBlacklist()
	var rerr error
	if err := r.lockConfigFS(); err != nil {
		// LIO's attributes hold the CHAP secrets: they are only written
		// while the target folder is root's alone (M3).
		rerr = err
	} else {
		rerr = Reconcile(r.FS, plan)
	}
	st.Problem = ""
	if rerr != nil {
		st.Problem = rerr.Error()
	}
	if err := r.save(st); err != nil {
		return err
	}
	return rerr
}

// pinSubnet pins the storage subnet the first time (M1).
func (st *rootState) pinSubnet(s netip.Prefix) error {
	if !s.IsValid() {
		return nil
	}
	s = s.Masked()
	if !s.Addr().Is4() || s.Bits() < 8 || s.Bits() > 30 {
		return &ValidationError{fmt.Errorf("storage subnet %s must be an IPv4 network from /8 to /30", s)}
	}
	if !st.Subnet.IsValid() {
		st.Subnet = s
		return nil
	}
	if st.Subnet != s {
		return &ValidationError{fmt.Errorf("the storage network changed from %s to %s; an administrator confirms that on the storage server with: hardyctl cluster-storage repin --subnet", st.Subnet, s)}
	}
	return nil
}

// targetModules are LIO's core, its block backstore and the iSCSI fabric.
var targetModules = []string{"target_core_mod", "target_core_iblock", "iscsi_target_mod"}

// loadModules loads LIO when its configfs group isn't there yet (a
// storage node's first apply after boot).
func (r *Root) loadModules(ctx context.Context) {
	if r.FS.Exists("core") && r.FS.Exists("iscsi") {
		return
	}
	if _, err := sysexec.Output(ctx, r.Runner, "modprobe", append([]string{"-a"}, targetModules...)...); err != nil {
		r.log().Warn("san: loading the iSCSI target modules", "err", err)
	}
}

// Lockable is a configfs that can be made root's alone.
type Lockable interface {
	// Lockdown makes the target folder 0700 and checks it is.
	Lockdown() error
}

// lockConfigFS makes LIO's configfs folder root's alone (its attributes,
// CHAP secrets among them, are world-readable by default).
func (r *Root) lockConfigFS() error {
	l, ok := r.FS.(Lockable)
	if !ok {
		return nil
	}
	if err := l.Lockdown(); err != nil {
		return fmt.Errorf("LIO's configfs folder can't be made root's alone: %w", err)
	}
	return nil
}

// FSBlacklistFile keeps file system modules the storage node never needs
// from loading (H4: it never mounts what a node wrote with an
// auto-detected type, and these parsers stay out of its kernel).
const FSBlacklistFile = "/etc/modprobe.d/hardyos-cluster-storage.conf"

// blacklistedFS are file systems no HardyOS storage node uses.
var blacklistedFS = []string{"adfs", "affs", "befs", "bfs", "cramfs", "efs", "erofs", "f2fs", "freevxfs", "gfs2", "hfs", "hfsplus",
	"hpfs", "jffs2", "jfs", "minix", "nilfs2", "ocfs2", "omfs", "qnx4", "qnx6", "reiserfs", "romfs", "sysv", "udf", "ufs"}

func (r *Root) ensureFSBlacklist() {
	var b strings.Builder
	b.WriteString("# Generated by HardyOS (hardyd-priv): file systems a cluster storage server never mounts.\n")
	for _, m := range blacklistedFS {
		fmt.Fprintf(&b, "install %s /bin/false\n", m)
	}
	p := r.sys(FSBlacklistFile)
	if cur, err := os.ReadFile(p); err == nil && string(cur) == b.String() {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err == nil {
		err = rootfile.WriteAtomic(p, []byte(b.String()), 0o644)
		if err != nil {
			r.log().Warn("san: writing the file system blacklist", "err", err)
		}
	}
}

// ValidationError is a refused request (bad_args).
type ValidationError struct{ Err error }

func (e *ValidationError) Error() string { return e.Err.Error() }
func (e *ValidationError) Unwrap() error { return e.Err }

func (r *Root) zfs(ctx context.Context, args ...string) ([]byte, error) {
	return sysexec.Output(ctx, r.Runner, "zfs", args...)
}

// props reads local and received properties of one dataset (-p values).
func (r *Root) props(ctx context.Context, ds string, names ...string) (map[string]string, error) {
	out, err := r.zfs(ctx, "get", "-H", "-p", "-o", "property,value", strings.Join(names, ","), ds)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ds, err)
	}
	m := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		k, v, ok := strings.Cut(l, "\t")
		if ok {
			m[k] = v
		}
	}
	return m, nil
}

// ownerProp is the property naming a workload's id on its datasets.
func ownerProp(k cluster.WorkloadKind) string {
	if k == cluster.KindApp {
		return PropApp
	}
	return PropVM
}

// resolveZvol checks that a backstore's dataset is a cluster zvol of that
// workload and returns its device, GUID-derived serial and cache mode.
func (r *Root) resolveZvol(ctx context.Context, c cluster.ClusterID, b Backstore) (Resolved, error) {
	p, err := r.props(ctx, b.Dataset, "type", "guid", "sync", PropRole, ownerProp(b.Workload.Kind))
	if err != nil {
		return Resolved{}, err
	}
	if p["type"] != "volume" {
		return Resolved{}, &ValidationError{fmt.Errorf("%s isn't a zvol", b.Dataset)}
	}
	if p[PropRole] != RoleCluster || p[ownerProp(b.Workload.Kind)] != b.Workload.ID {
		return Resolved{}, &ValidationError{fmt.Errorf("%s isn't %s %s's cluster volume", b.Dataset, b.Workload.Kind, b.Workload.ID)}
	}
	if !guidRE.MatchString(p["guid"]) {
		return Resolved{}, fmt.Errorf("%s: no GUID", b.Dataset)
	}
	serial := Serial(c, p["guid"])
	return Resolved{
		Device: "/dev/zvol/" + b.Dataset, GUID: p["guid"], Serial: serial, WWN: WWN(serial),
		WriteCache: p["sync"] != "always",
	}, nil
}

// OnStart rebuilds LIO, the exports and the firewall from root's state at
// boot. Pools may be imported (and unlocked) after hardyd-priv starts, so
// it retries for a while; fences are put back first.
func (r *Root) OnStart(ctx context.Context) {
	for i := 0; i < 40; i++ {
		err := r.rebuild(ctx)
		if err == nil {
			return
		}
		r.log().Warn("san: rebuilding the cluster storage", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Second):
		}
	}
}

func (r *Root) rebuild(ctx context.Context) error {
	r.mu.Lock()
	st, err := r.load()
	if err == nil && st.Firewall != nil {
		err = r.applyFirewall(ctx, *st.Firewall, st)
		if err == nil {
			err = r.save(st)
		}
	}
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if st.Desired.Cluster == "" {
		return nil // a compute node: only its firewall
	}
	var errs []error
	addrs, keys := st.pinArgs()
	if err := r.apply(ctx, ApplyArgs{Desired: st.Desired, Addresses: addrs, Keys: keys}); err != nil {
		errs = append(errs, err)
	}
	if r.NFS != nil && st.Exports != nil {
		if err := r.NFS.Apply(ctx, r.withoutFenced(st, st.Exports)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// reconcileSaved runs LIO from the saved state (fence, unfence, CHAP
// rotation), making secrets for targets that have none yet.
func (r *Root) reconcileSaved(st *rootState) error {
	if st.Desired.Cluster == "" {
		return nil
	}
	chap, err := r.loadCHAP()
	if err != nil {
		return err
	}
	plan := Plan{Desired: st.Desired, Resolved: st.Resolved, CHAP: map[cluster.NodeID]Secrets{}, Discovery: chap[""]}
	changed := false
	for _, t := range st.Desired.Targets {
		s, ok := chap[t.Node]
		if !ok || s.Validate() != nil {
			if s, err = NewSecrets(t.Node); err != nil {
				return err
			}
			chap[t.Node] = s
			changed = true
		}
		plan.CHAP[t.Node] = s
	}
	if changed {
		if err := r.saveCHAP(chap); err != nil {
			return err
		}
	}
	if err := r.lockConfigFS(); err != nil {
		return err
	}
	return Reconcile(r.FS, plan)
}

// FenceArgs is san.fence. Confirm must be the node id.
type FenceArgs struct {
	Node    cluster.NodeID `json:"node"`
	Epoch   uint64         `json:"epoch"`
	Confirm string         `json:"confirm"`
}

// FenceResult says what was cut.
type FenceResult struct {
	Node            cluster.NodeID `json:"node"`
	Epoch           uint64         `json:"epoch"`
	TargetDisabled  bool           `json:"targetDisabled"`
	ExportsRemoved  int            `json:"exportsRemoved"`
	ClientsExpired  int            `json:"clientsExpired"`
	AddressBlocked  bool           `json:"addressBlocked"`
	SessionsDropped int            `json:"sessionsDropped"`
}

// Fence cuts a node off: its target disabled with nothing mapped (sessions
// dropped), its address removed from every cluster export, its NFSv4
// clients expired and its address dropped by the firewall. It is recorded
// first, so even a partial failure leaves the fence in root's state, and
// it is idempotent (the agent retries until all steps succeed). A fence's
// epoch must be newer than any root had for the node, except to retry
// the current one. It is only complete (no error) once the node's pinned
// address is blocked (L2).
func (r *Root) Fence(ctx context.Context, a FenceArgs) (*FenceResult, error) {
	if err := ValidNode(a.Node); err != nil {
		return nil, &ValidationError{err}
	}
	if a.Confirm != string(a.Node) {
		return nil, &ValidationError{errors.New("type the server's name to fence it")}
	}
	if a.Epoch == 0 {
		return nil, &ValidationError{errors.New("a fence needs an epoch")}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil {
		return nil, err
	}
	if st.Fences == nil {
		st.Fences = map[cluster.NodeID]FenceRecord{}
	}
	if st.Epochs == nil {
		st.Epochs = map[cluster.NodeID]uint64{}
	}
	cur, fenced := st.Fences[a.Node]
	switch {
	case fenced && cur.Epoch > a.Epoch:
		return nil, &ValidationError{fmt.Errorf("%s is already fenced at a later epoch (%d)", a.Node, cur.Epoch)}
	case !fenced && a.Epoch <= st.Epochs[a.Node]:
		return nil, &ValidationError{fmt.Errorf("%s was already fenced and let back in at epoch %d; a new fence needs a newer epoch", a.Node, st.Epochs[a.Node])}
	}
	rec := FenceRecord{Epoch: a.Epoch}
	if p := st.Pins[a.Node]; p != nil {
		rec.KeyPin = p.KeyPin
	}
	if fenced && cur.Epoch == a.Epoch && cur.KeyPin != "" {
		rec.KeyPin = cur.KeyPin
	}
	st.Fences[a.Node] = rec
	if a.Epoch > st.Epochs[a.Node] {
		st.Epochs[a.Node] = a.Epoch
	}
	res := &FenceResult{Node: a.Node, Epoch: a.Epoch}
	if st.Desired.Cluster != "" {
		res.SessionsDropped = Sessions(r.FS, st.Desired.Cluster)[a.Node]
	}
	found := false
	for i, t := range st.Desired.Targets {
		if t.Node == a.Node {
			st.Desired.Targets[i] = Target{Node: a.Node, Enabled: false, FenceEpoch: a.Epoch, LUNs: []string{}}
			found = true
		}
	}
	if !found && st.Desired.Cluster != "" {
		st.Desired.Targets = append(st.Desired.Targets, Target{Node: a.Node, Enabled: false, FenceEpoch: a.Epoch, LUNs: []string{}})
		st.Desired.Normalize()
	}
	if err := r.save(st); err != nil {
		return nil, err
	}
	var errs []error
	if st.Desired.Cluster != "" {
		// Disable straight away, then reconcile the rest.
		tpg := tpgDir(TargetIQN(st.Desired.Cluster, a.Node))
		if r.FS.Exists(tpg) {
			if err := setAttr(r.FS, tpg+"/enable", "0"); err != nil {
				errs = append(errs, err)
			}
		}
		if err := r.reconcileSaved(st); err != nil {
			errs = append(errs, err)
		}
		cur := Current(r.FS, st.Desired.Cluster)[a.Node]
		res.TargetDisabled = !cur.Enabled && len(cur.LUNs) == 0
	} else {
		res.TargetDisabled = true
	}
	addr, haveAddr := st.pinnedAddr(a.Node)
	if !haveAddr {
		// The earlier format's address, if root had one.
		addr, haveAddr = st.Addresses[a.Node]
	}
	if r.NFS != nil && st.Exports != nil {
		filtered := r.withoutFenced(st, st.Exports)
		for _, e := range st.Exports {
			if haveAddr && slices.Contains(e.Clients, addr) {
				res.ExportsRemoved++
			}
		}
		if err := r.NFS.Apply(ctx, filtered); err != nil {
			errs = append(errs, err)
		}
	}
	if r.NFS != nil && haveAddr {
		n, err := r.NFS.ExpireClients(ctx, []netip.Addr{addr})
		res.ClientsExpired = n
		if err != nil {
			errs = append(errs, err)
		}
	}
	switch {
	case !haveAddr:
		// Root never pinned an address for the node: no export, firewall
		// rule or target of root's ever admitted it.
		res.AddressBlocked = true
	case st.Firewall == nil:
		errs = append(errs, fmt.Errorf("the storage firewall isn't set up, so %s's address %s isn't blocked yet", a.Node, addr))
	default:
		if err := r.applyFirewall(ctx, *st.Firewall, st); err != nil {
			errs = append(errs, err)
		} else {
			res.AddressBlocked = true
		}
	}
	if !res.TargetDisabled {
		errs = append(errs, fmt.Errorf("%s's target is still enabled or maps volumes", a.Node))
	}
	if err := r.save(st); err != nil {
		errs = append(errs, err)
	}
	r.log().Warn("san: node fenced", "node", a.Node, "epoch", a.Epoch, "ok", len(errs) == 0)
	return res, errors.Join(errs...)
}

// UnfenceArgs is san.unfence.
type UnfenceArgs struct {
	Node  cluster.NodeID `json:"node"`
	Epoch uint64         `json:"epoch"`
	// Statement is the node's own signed rejoin for this epoch (needed
	// whenever root pinned the node's key).
	Statement *RejoinStatement `json:"statement,omitempty"`
}

// Unfence lifts root's fence of a node at that epoch: its target is
// enabled again with nothing mapped and new CHAP secrets (L3); the next
// apply, exports and firewall changes may include it again. The node must
// have signed its rejoin with the key root pinned for it (H3).
func (r *Root) Unfence(ctx context.Context, a UnfenceArgs) error {
	if err := ValidNode(a.Node); err != nil {
		return &ValidationError{err}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil {
		return err
	}
	fr, ok := st.Fences[a.Node]
	if !ok {
		return nil
	}
	if fr.Epoch != a.Epoch {
		return &ValidationError{fmt.Errorf("%s is fenced at epoch %d, not %d", a.Node, fr.Epoch, a.Epoch)}
	}
	pin := st.Pins[a.Node]
	if pin != nil || fr.KeyPin != "" {
		if pin == nil || (fr.KeyPin != "" && pin.KeyPin != fr.KeyPin) {
			return &ValidationError{fmt.Errorf("%s's pinned key changed since it was fenced; an administrator decides on the storage server (hardyctl cluster-storage forget %s)", a.Node, a.Node)}
		}
		s := a.Statement
		switch {
		case s == nil:
			return &ValidationError{fmt.Errorf("waiting for %s's signed rejoin", a.Node)}
		case s.Cluster != st.Desired.Cluster || s.Node != a.Node || s.Epoch != fr.Epoch:
			return &ValidationError{fmt.Errorf("%s's rejoin statement is for another cluster, node or epoch", a.Node)}
		}
		if err := s.Verify(pin.Key); err != nil {
			return &ValidationError{fmt.Errorf("%s: %w", a.Node, err)}
		}
	}
	delete(st.Fences, a.Node)
	for i, t := range st.Desired.Targets {
		if t.Node == a.Node {
			st.Desired.Targets[i] = Target{Node: a.Node, Enabled: true, LUNs: []string{}}
		}
	}
	// New CHAP secrets: whatever the node had before its fence is void.
	chap, err := r.loadCHAP()
	if err != nil {
		return err
	}
	if s, err := NewSecrets(a.Node); err == nil {
		chap[a.Node] = s
		if err := r.saveCHAP(chap); err != nil {
			return err
		}
	} else {
		return err
	}
	if err := r.save(st); err != nil {
		return err
	}
	if err := r.reconcileSaved(st); err != nil {
		r.log().Warn("san: reconciling after an unfence", "err", err)
	}
	if st.Firewall != nil {
		if err := r.applyFirewall(ctx, *st.Firewall, st); err != nil {
			return err
		}
		_ = r.save(st)
	}
	r.log().Info("san: node unfenced", "node", a.Node, "epoch", a.Epoch)
	return nil
}

// fencedAddrs are the addresses of fenced nodes.
func (st *rootState) fencedAddrs() []netip.Addr {
	var out []netip.Addr
	for n := range st.Fences {
		if a, ok := st.pinnedAddr(n); ok {
			out = append(out, a)
		} else if a, ok := st.Addresses[n]; ok {
			out = append(out, a)
		}
	}
	return out
}

// withoutFenced drops fenced nodes' addresses from exports (and exports
// left without clients).
func (r *Root) withoutFenced(st *rootState, exports []nfs.ClusterExport) []nfs.ClusterExport {
	blocked := st.fencedAddrs()
	out := []nfs.ClusterExport{}
	for _, e := range exports {
		var cl []netip.Addr
		for _, c := range e.Clients {
			if !slices.Contains(blocked, c) {
				cl = append(cl, c)
			}
		}
		if len(cl) == 0 {
			continue
		}
		e.Clients = cl
		out = append(out, e)
	}
	return out
}

// FirewallApply renders and loads the storage firewall: fenced nodes'
// addresses are forced into the drop set, on the storage node only
// pinned addresses can be members, members' MAC addresses are pinned
// (learned from the neighbour table the first time) and set as static
// neighbour entries.
func (r *Root) FirewallApply(ctx context.Context, s FirewallSpec) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil {
		return err
	}
	now := r.now()
	if err := st.mark(markFirewall).check("the firewall", s.Index, now); err != nil {
		return err
	}
	if err := s.Validate(); err != nil {
		return &ValidationError{err}
	}
	if s.Role == cluster.RoleStorage {
		if st.Subnet.IsValid() && s.Subnet.Masked() != st.Subnet {
			return &ValidationError{fmt.Errorf("the firewall's storage network %s isn't the pinned %s", s.Subnet, st.Subnet)}
		}
		var dropped []string
		s.Members = slices.DeleteFunc(slices.Clone(s.Members), func(a netip.Addr) bool {
			if _, ok := st.nodeOfAddr(a); !ok {
				dropped = append(dropped, a.String())
				return true
			}
			return false
		})
		if len(dropped) > 0 {
			st.setProblem(markFirewall, "the storage firewall left out addresses root hasn't pinned for a server: "+strings.Join(dropped, ", "))
		} else {
			st.setProblem(markFirewall, "")
		}
	}
	r.learnMACs(ctx, s, st)
	if err := r.applyFirewall(ctx, s, st); err != nil {
		return err
	}
	st.Firewall = &s
	st.advance(markFirewall, s.Index, now)
	return r.save(st)
}

func (r *Root) applyFirewall(ctx context.Context, s FirewallSpec, st *rootState) error {
	for _, a := range st.fencedAddrs() {
		s.Members = slices.DeleteFunc(slices.Clone(s.Members), func(x netip.Addr) bool { return x == a })
		if !slices.Contains(s.Fenced, a) {
			s.Fenced = append(slices.Clone(s.Fenced), a)
		}
	}
	now := r.now()
	st.Migrations = slices.DeleteFunc(st.Migrations, func(m MigrationAllow) bool {
		return !m.Expires.After(now) || !slices.Contains(s.Members, m.Source)
	})
	x := FirewallExtra{MACs: map[netip.Addr]string{}, Shared: r.lanShared(ctx, s.Interface)}
	if s.Role == cluster.RoleCompute {
		x.Migrations = st.Migrations
	}
	for _, a := range s.Members {
		if mac, ok := st.MACs[a]; ok && s.Subnet.Contains(a) {
			x.MACs[a] = mac
		}
	}
	content, err := RenderFirewallWith(s, x, now)
	if err != nil {
		return &ValidationError{err}
	}
	p := r.sys(FirewallFile)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := rootfile.WriteAtomic(p, []byte(content), 0o600); err != nil {
		return err
	}
	if _, err := sysexec.Output(ctx, r.Runner, "nft", "-c", "-f", FirewallFile); err != nil {
		return fmt.Errorf("the storage firewall was refused: %w", err)
	}
	if _, err := sysexec.Output(ctx, r.Runner, "nft", "-f", FirewallFile); err != nil {
		return fmt.Errorf("loading the storage firewall: %w", err)
	}
	r.syncNeighbours(ctx, s.Interface, x.MACs, st)
	return nil
}

// neighbour is one entry of `ip -j neigh show`.
type neighbour struct {
	Dst    string   `json:"dst"`
	LLAddr string   `json:"lladdr"`
	State  []string `json:"state"`
}

// learnMACs pins the link-layer address of each member that has none yet,
// from the neighbour table (trust on first use, like the address pins).
func (r *Root) learnMACs(ctx context.Context, s FirewallSpec, st *rootState) {
	need := false
	for _, a := range s.Members {
		if _, ok := st.MACs[a]; !ok {
			need = true
		}
	}
	if !need || !ifRE.MatchString(s.Interface) {
		return
	}
	out, err := sysexec.Output(ctx, r.Runner, "ip", "-j", "neigh", "show", "dev", s.Interface)
	if err != nil {
		return
	}
	var ns []neighbour
	if json.Unmarshal(out, &ns) != nil {
		return
	}
	for _, n := range ns {
		a, err := netip.ParseAddr(n.Dst)
		if err != nil || !slices.Contains(s.Members, a) {
			continue
		}
		if _, ok := st.MACs[a]; ok {
			continue
		}
		mac := strings.ToLower(n.LLAddr)
		usable := false
		for _, x := range n.State {
			switch x {
			case "REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT":
				usable = true
			}
		}
		if !usable || !macRE.MatchString(mac) || mac == "00:00:00:00:00:00" {
			continue
		}
		if st.MACs == nil {
			st.MACs = map[netip.Addr]string{}
		}
		st.MACs[a] = mac
		r.log().Info("san: pinned a member's MAC address", "address", a, "mac", mac)
	}
}

// syncNeighbours makes the pinned MACs static neighbour entries and
// removes the ones root made for addresses that aren't members any more.
func (r *Root) syncNeighbours(ctx context.Context, iface string, macs map[netip.Addr]string, st *rootState) {
	var keep []netip.Addr
	for a, mac := range macs {
		if _, err := sysexec.Output(ctx, r.Runner, "ip", "neigh", "replace", a.String(), "lladdr", mac, "dev", iface, "nud", "permanent"); err != nil {
			r.log().Warn("san: setting a static neighbour entry", "address", a, "err", err)
			continue
		}
		keep = append(keep, a)
	}
	for _, a := range st.Neigh {
		if _, ok := macs[a]; !ok {
			_, _ = sysexec.Output(ctx, r.Runner, "ip", "neigh", "del", a.String(), "dev", iface)
		}
	}
	slices.SortFunc(keep, func(a, b netip.Addr) int { return a.Compare(b) })
	st.Neigh = keep
}

// lanShared reports whether the storage interface carries the default
// route (the storage network is the LAN itself). Unknown is false.
func (r *Root) lanShared(ctx context.Context, iface string) bool {
	if iface == "" {
		return false
	}
	out, err := sysexec.Output(ctx, r.Runner, "ip", "-j", "route", "show", "default")
	if err != nil {
		return false
	}
	var routes []struct {
		Dev string `json:"dev"`
	}
	if json.Unmarshal(out, &routes) != nil {
		return false
	}
	for _, rt := range routes {
		if rt.Dev == iface {
			return true
		}
	}
	return false
}

// MigrationArgs is san.firewall.migration: let one source reach this
// compute node's migration ports for a while (M6). Port 0 opens the
// whole range to that source; Revoke ends the source's allowances.
type MigrationArgs struct {
	Source  netip.Addr `json:"source"`
	Port    int        `json:"port,omitempty"`
	Seconds int        `json:"seconds,omitempty"`
	Revoke  bool       `json:"revoke,omitempty"`
}

// Migration allowance bounds.
const (
	MigrationDefaultSeconds = 120
	MigrationMaxSeconds     = 600
)

// AllowMigration adds (or revokes) a live-migration allowance and reloads
// the firewall. Only a member's storage address on a compute node.
func (r *Root) AllowMigration(ctx context.Context, a MigrationArgs) error {
	if a.Port != 0 && (a.Port < MigrateFirst || a.Port > MigrateLast) {
		return &ValidationError{fmt.Errorf("migration port %d isn't in %d-%d", a.Port, MigrateFirst, MigrateLast)}
	}
	if a.Seconds == 0 {
		a.Seconds = MigrationDefaultSeconds
	}
	if a.Seconds < 1 || a.Seconds > MigrationMaxSeconds {
		return &ValidationError{fmt.Errorf("a migration allowance lasts 1-%d s", MigrationMaxSeconds)}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil {
		return err
	}
	if st.Firewall == nil || st.Firewall.Role != cluster.RoleCompute {
		return &ValidationError{errors.New("this server has no compute firewall for live migrations yet")}
	}
	if !slices.Contains(st.Firewall.Members, a.Source) || slices.Contains(st.fencedAddrs(), a.Source) {
		return &ValidationError{fmt.Errorf("%s isn't a member's storage address", a.Source)}
	}
	st.Migrations = slices.DeleteFunc(st.Migrations, func(m MigrationAllow) bool {
		return m.Source == a.Source && (a.Revoke || a.Port == 0 || m.Port == a.Port)
	})
	if !a.Revoke {
		exp := r.now().Add(time.Duration(a.Seconds) * time.Second)
		if a.Port != 0 {
			st.Migrations = append(st.Migrations, MigrationAllow{Source: a.Source, Port: a.Port, Expires: exp})
		} else {
			for p := MigrateFirst; p <= MigrateLast; p++ {
				st.Migrations = append(st.Migrations, MigrationAllow{Source: a.Source, Port: p, Expires: exp})
			}
		}
	}
	if err := r.applyFirewall(ctx, *st.Firewall, st); err != nil {
		return err
	}
	return r.save(st)
}

// CHAPArgs names a node.
type CHAPArgs struct {
	Node cluster.NodeID `json:"node"`
}

// CHAP returns one node's secrets (for hardyd to hand to that node only;
// the peer handler checks the caller is the node). Only a pinned node
// with an enabled target gets them.
func (r *Root) CHAP(ctx context.Context, a CHAPArgs) (*Secrets, error) {
	if err := ValidNode(a.Node); err != nil {
		return nil, &ValidationError{err}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil {
		return nil, err
	}
	t, ok := st.Desired.Target(a.Node)
	if !ok {
		return nil, &ValidationError{fmt.Errorf("%s has no target on this storage node", a.Node)}
	}
	if _, fenced := st.Fences[a.Node]; fenced {
		return nil, &ValidationError{fmt.Errorf("%s is fenced", a.Node)}
	}
	if st.Pins[a.Node] == nil || !t.Enabled {
		return nil, &ValidationError{fmt.Errorf("%s's target is off", a.Node)}
	}
	c, err := r.ensureCHAP([]cluster.NodeID{a.Node})
	if err != nil {
		return nil, err
	}
	s := c[a.Node]
	return &s, nil
}

// RotateCHAP replaces a node's secrets and drops its sessions, so the old
// secrets stop working at once (L3). Only for a node with nothing mapped
// (its running VMs would lose their disks); it logs in again with the new
// secrets on its next attach.
func (r *Root) RotateCHAP(ctx context.Context, a CHAPArgs) error {
	if err := ValidNode(a.Node); err != nil {
		return &ValidationError{err}
	}
	r.mu.Lock()
	st, err := r.load()
	if err != nil {
		r.mu.Unlock()
		return err
	}
	if t, ok := st.Desired.Target(a.Node); ok && len(t.LUNs) > 0 {
		r.mu.Unlock()
		return &ValidationError{fmt.Errorf("%s still has volumes mapped; move its workloads off (or stop them) before rotating its secrets", a.Node)}
	}
	c, err := r.loadCHAP()
	if err == nil {
		delete(c, a.Node)
		err = r.saveCHAP(c)
	}
	if err == nil && st.Desired.Cluster != "" {
		tpg := tpgDir(TargetIQN(st.Desired.Cluster, a.Node))
		if r.FS.Exists(tpg) {
			err = setAttr(r.FS, tpg+"/enable", "0")
		}
	}
	r.mu.Unlock()
	if err != nil {
		return err
	}
	addrs, keys := st.pinArgs()
	return r.apply(ctx, ApplyArgs{Desired: st.Desired, Addresses: addrs, Keys: keys})
}

// PinResetArgs is san.pin.reset (root only): forget a node's pinned
// address, key and MAC (the next apply pins what the cluster state says
// then), or the pinned storage subnet. Confirm is the node's id, or
// "subnet".
type PinResetArgs struct {
	Node    cluster.NodeID `json:"node,omitempty"`
	Subnet  bool           `json:"subnet,omitempty"`
	Confirm string         `json:"confirm"`
}

// PinReset is an administrator's confirmation of a changed storage
// address, key or network (M1), given as root on the storage node.
func (r *Root) PinReset(ctx context.Context, a PinResetArgs) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil {
		return err
	}
	switch {
	case a.Subnet:
		if a.Confirm != "subnet" {
			return &ValidationError{errors.New(`type "subnet" to confirm`)}
		}
		st.Subnet = netip.Prefix{}
	default:
		if err := ValidNode(a.Node); err != nil {
			return &ValidationError{err}
		}
		if a.Confirm != string(a.Node) {
			return &ValidationError{errors.New("type the server's name to confirm")}
		}
		if p := st.Pins[a.Node]; p != nil {
			delete(st.MACs, p.Address)
		}
		delete(st.Pins, a.Node)
	}
	r.log().Warn("san: pin reset by an administrator", "node", a.Node, "subnet", a.Subnet)
	return r.save(st)
}

// ForgetArgs is san.forget (root only). Confirm is the node's id.
type ForgetArgs struct {
	Node    cluster.NodeID `json:"node"`
	Confirm string         `json:"confirm"`
}

// Forget clears everything root keeps of a removed node: its pin, MAC,
// fence, epoch and CHAP secrets (M2: hardyd can't clear a fence; a
// removed node's fence stays until an administrator does this as root).
func (r *Root) Forget(ctx context.Context, a ForgetArgs) error {
	if err := ValidNode(a.Node); err != nil {
		return &ValidationError{err}
	}
	if a.Confirm != string(a.Node) {
		return &ValidationError{errors.New("type the server's name to confirm")}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil {
		return err
	}
	if t, ok := st.Desired.Target(a.Node); ok && (len(t.LUNs) > 0 || t.Enabled) {
		return &ValidationError{fmt.Errorf("%s is still a server of the cluster with a target; remove it from the cluster first", a.Node)}
	}
	if p := st.Pins[a.Node]; p != nil {
		delete(st.MACs, p.Address)
	}
	delete(st.Pins, a.Node)
	delete(st.Fences, a.Node)
	delete(st.Epochs, a.Node)
	if c, err := r.loadCHAP(); err == nil {
		delete(c, a.Node)
		_ = r.saveCHAP(c)
	}
	if err := r.save(st); err != nil {
		return err
	}
	r.log().Warn("san: node forgotten by an administrator", "node", a.Node)
	if st.Firewall != nil {
		return r.applyFirewall(ctx, *st.Firewall, st)
	}
	return nil
}

// NFSApplyArgs is nfs.cluster.apply.
type NFSApplyArgs struct {
	Exports []nfs.ClusterExport `json:"exports"`
	// Index is the Raft index the exports were built from.
	Index uint64 `json:"index,omitempty"`
}

// NFSApply checks each export's dataset itself (its role, owner, GUID and
// mountpoint), keeps only clients root can account for (the pinned
// address of a node with an enabled target; for a VM or app also one its
// volumes are mapped to), refuses owner-only exports (no_root_squash) when
// the storage network is the LAN (H2), drops fenced nodes and writes the
// cluster exports.
func (r *Root) NFSApply(ctx context.Context, a NFSApplyArgs) ([]nfs.ClusterExport, error) {
	if r.NFS == nil {
		return nil, errors.New("NFS isn't available here")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil {
		return nil, err
	}
	now := r.now()
	if err := st.mark(markExports).check("the exports", a.Index, now); err != nil {
		return nil, err
	}
	shared := st.Firewall != nil && r.lanShared(ctx, st.Firewall.Interface)
	checked := make([]nfs.ClusterExport, 0, len(a.Exports))
	var probs []string
	for _, e := range a.Exports {
		e, err := r.checkExport(ctx, e)
		if err != nil {
			return nil, err
		}
		if shared && e.Kind != nfs.KindShare {
			probs = append(probs, fmt.Sprintf("%s isn't exported: the storage network is the LAN, and a VM's or app's own data is only exported on a dedicated storage network or VLAN", e.Dataset))
			continue
		}
		var bad []string
		e.Clients, bad = st.allowedClients(e)
		for _, b := range bad {
			probs = append(probs, fmt.Sprintf("%s isn't exported to %s", e.Dataset, b))
		}
		if len(e.Clients) == 0 {
			continue
		}
		checked = append(checked, e)
	}
	final := r.withoutFenced(st, checked)
	if err := r.NFS.Apply(ctx, final); err != nil {
		return nil, err
	}
	st.Exports = checked
	st.advance(markExports, a.Index, now)
	st.setProblem(markExports, strings.Join(probs, "; "))
	if err := r.save(st); err != nil {
		return nil, err
	}
	return final, nil
}

// allowedClients splits an export's clients into those root accounts for
// and the rest (with the reason).
func (st *rootState) allowedClients(e nfs.ClusterExport) ([]netip.Addr, []string) {
	var owners []cluster.NodeID
	ownLUNs := false
	parts := strings.Split(e.Dataset, "/")
	if e.Kind != nfs.KindShare && len(parts) == 3 {
		w := cluster.WorkloadRef{Kind: cluster.KindVM, ID: parts[2]}
		if parts[1] == "apps" {
			w.Kind = cluster.KindApp
		}
		for _, b := range st.Desired.Backstores {
			if b.Workload == w {
				ownLUNs = true
				for _, n := range st.Desired.Mapped(b.Name) {
					if !slices.Contains(owners, n) {
						owners = append(owners, n)
					}
				}
			}
		}
	}
	var ok []netip.Addr
	var bad []string
	for _, c := range e.Clients {
		n, pinned := st.nodeOfAddr(c)
		t, hasT := st.Desired.Target(n)
		switch {
		case !pinned:
			bad = append(bad, c.String()+" (no server has that pinned storage address)")
		case !hasT || !t.Enabled:
			bad = append(bad, fmt.Sprintf("%s (%s's target is off)", c, n))
		case ownLUNs && !slices.Contains(owners, n):
			bad = append(bad, fmt.Sprintf("%s (%s doesn't hold its volumes)", c, n))
		default:
			ok = append(ok, c)
		}
	}
	return ok, bad
}

func (r *Root) checkExport(ctx context.Context, e nfs.ClusterExport) (nfs.ClusterExport, error) {
	parts := strings.Split(e.Dataset, "/")
	if len(parts) != 3 || !poolRE.MatchString(parts[0]) {
		return e, &ValidationError{fmt.Errorf("%q can't be a cluster export", e.Dataset)}
	}
	names := []string{"type", "guid", "mountpoint", "mounted"}
	var owner string
	switch e.Kind {
	case nfs.KindVMState:
		owner = PropVM
		if parts[1] != "vms" {
			return e, &ValidationError{fmt.Errorf("%q isn't a VM's dataset", e.Dataset)}
		}
	case nfs.KindAppData:
		owner = PropApp
		if parts[1] != "apps" {
			return e, &ValidationError{fmt.Errorf("%q isn't an app's dataset", e.Dataset)}
		}
	case nfs.KindShare:
		owner = "org.hardyos:share"
		if parts[1] != "shares" {
			return e, &ValidationError{fmt.Errorf("%q isn't a shared folder", e.Dataset)}
		}
	default:
		return e, &ValidationError{fmt.Errorf("export kind %q isn't valid", e.Kind)}
	}
	names = append(names, owner, PropRole)
	p, err := r.props(ctx, e.Dataset, names...)
	if err != nil {
		return e, err
	}
	if p["type"] != "filesystem" || p["mounted"] != "yes" {
		return e, &ValidationError{fmt.Errorf("%s isn't a mounted file system", e.Dataset)}
	}
	if p[owner] != parts[2] || (e.Kind != nfs.KindShare && p[PropRole] != RoleCluster) {
		return e, &ValidationError{fmt.Errorf("%s isn't a cluster dataset of %s", e.Dataset, parts[2])}
	}
	e.Path = p["mountpoint"]
	e.GUID = p["guid"]
	return e, nil
}

var guidRE = regexp.MustCompile(`^[0-9]{1,20}$`)

// markStorageWriter records that the storage node itself wrote a
// backstore's volume (formatting it, moving app data into it).
func (r *Root) markStorageWriter(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil {
		return
	}
	if st.Holders == nil {
		st.Holders = map[string]*Holders{}
	}
	h := st.Holders[name]
	if h == nil {
		st.Holders[name] = &Holders{Nodes: []cluster.NodeID{StorageWriter}, Seq: 1}
	} else {
		h.Prev, h.Nodes = h.Nodes, []cluster.NodeID{StorageWriter}
		h.Seq++
	}
	if err := r.save(st); err != nil {
		r.log().Warn("san: recording the storage node as a volume's writer", "err", err)
	}
}
