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

// rootState is root's own record (StateDir/san.json): the desired LIO
// state, the firewall, the storage addresses of nodes and the fences root
// has put in place. A fence recorded here is only lifted by Unfence with
// the same epoch: no later Apply, export or firewall change can give a
// fenced node access back.
type rootState struct {
	Desired   Desired                       `json:"desired"`
	Firewall  *FirewallSpec                 `json:"firewall,omitempty"`
	Exports   []nfs.ClusterExport           `json:"exports,omitempty"`
	Addresses map[cluster.NodeID]netip.Addr `json:"addresses,omitempty"`
	Fences    map[cluster.NodeID]uint64     `json:"fences,omitempty"`
	Resolved  map[string]Resolved           `json:"resolved,omitempty"`
	Applied   time.Time                     `json:"applied"`
	Problem   string                        `json:"problem,omitempty"`
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

	mu sync.Mutex
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
)

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
		Loaded: r.FS.Exists("core"), Desired: st.Desired, Fences: st.Fences, Resolved: st.Resolved,
		Problem: st.Problem, Applied: st.Applied, Current: map[cluster.NodeID]Target{}, Sessions: map[cluster.NodeID]int{},
	}
	if out.Fences == nil {
		out.Fences = map[cluster.NodeID]uint64{}
	}
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
	// Addresses are the compute nodes' storage addresses (for fences).
	Addresses map[cluster.NodeID]netip.Addr `json:"addresses"`
}

// Apply validates a desired state, checks every backstore's zvol itself,
// enforces root's fences, saves it and reconciles LIO.
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
	if d.Index < st.Desired.Index {
		return &ValidationError{fmt.Errorf("desired state from index %d is older than the applied one (%d)", d.Index, st.Desired.Index)}
	}
	// Root's fences hold whatever hardyd sends.
	for i, t := range d.Targets {
		if ep, fenced := st.Fences[t.Node]; fenced {
			if t.Enabled || len(t.LUNs) > 0 {
				return &ValidationError{fmt.Errorf("%s is fenced (epoch %d); it must be unfenced first", t.Node, ep)}
			}
			d.Targets[i].FenceEpoch = ep
		}
	}
	for n, addr := range a.Addresses {
		if ValidNode(n) != nil || !addr.Is4() {
			return &ValidationError{fmt.Errorf("storage address of %s isn't valid", n)}
		}
	}
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
	st.Desired = d
	st.Resolved = resolved
	if st.Addresses == nil {
		st.Addresses = map[cluster.NodeID]netip.Addr{}
	}
	for n, addr := range a.Addresses {
		st.Addresses[n] = addr
	}
	st.Applied = time.Now().UTC()
	plan := Plan{Desired: d, Resolved: resolved, CHAP: map[cluster.NodeID]Secrets{}, Discovery: chap[""]}
	for _, n := range nodes {
		plan.CHAP[n] = chap[n]
	}
	r.loadModules(ctx)
	rerr := Reconcile(r.FS, plan)
	st.Problem = ""
	if rerr != nil {
		st.Problem = rerr.Error()
	}
	if err := r.save(st); err != nil {
		return err
	}
	return rerr
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
	r.mu.Unlock()
	if err != nil {
		return err
	}
	var errs []error
	if st.Firewall != nil {
		if err := r.applyFirewall(ctx, *st.Firewall, st); err != nil {
			errs = append(errs, err)
		}
	}
	if st.Desired.Cluster == "" {
		return errors.Join(errs...) // a compute node: only its firewall
	}
	if err := r.apply(ctx, ApplyArgs{Desired: st.Desired}); err != nil {
		errs = append(errs, err)
	}
	if r.NFS != nil && st.Exports != nil {
		if err := r.NFS.Apply(ctx, r.withoutFenced(st, st.Exports)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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
// it is idempotent (the agent retries until all steps succeed).
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
		st.Fences = map[cluster.NodeID]uint64{}
	}
	if ep := st.Fences[a.Node]; ep > a.Epoch {
		return nil, &ValidationError{fmt.Errorf("%s is already fenced at a later epoch (%d)", a.Node, ep)}
	}
	st.Fences[a.Node] = a.Epoch
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
		chap, err := r.loadCHAP()
		if err == nil {
			plan := Plan{Desired: st.Desired, Resolved: st.Resolved, CHAP: map[cluster.NodeID]Secrets{}, Discovery: chap[""]}
			for _, t := range st.Desired.Targets {
				s, ok := chap[t.Node]
				if !ok {
					s, _ = NewSecrets(t.Node) // a target without secrets yet: disabled anyway
					chap[t.Node] = s
					_ = r.saveCHAP(chap)
				}
				plan.CHAP[t.Node] = s
			}
			if err := Reconcile(r.FS, plan); err != nil {
				errs = append(errs, err)
			}
		} else {
			errs = append(errs, err)
		}
		cur := Current(r.FS, st.Desired.Cluster)[a.Node]
		res.TargetDisabled = !cur.Enabled && len(cur.LUNs) == 0
	} else {
		res.TargetDisabled = true
	}
	addr, haveAddr := st.Addresses[a.Node]
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
	if st.Firewall != nil {
		if err := r.applyFirewall(ctx, *st.Firewall, st); err != nil {
			errs = append(errs, err)
		} else {
			res.AddressBlocked = haveAddr
		}
	} else {
		res.AddressBlocked = !haveAddr
	}
	r.log().Warn("san: node fenced", "node", a.Node, "epoch", a.Epoch, "ok", len(errs) == 0)
	return res, errors.Join(errs...)
}

// UnfenceArgs is san.unfence.
type UnfenceArgs struct {
	Node  cluster.NodeID `json:"node"`
	Epoch uint64         `json:"epoch"`
}

// Unfence lifts root's fence of a node at that epoch: its target is
// enabled again with nothing mapped; the next apply, exports and firewall
// changes may include it again.
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
	ep, ok := st.Fences[a.Node]
	if !ok {
		return nil
	}
	if ep != a.Epoch {
		return &ValidationError{fmt.Errorf("%s is fenced at epoch %d, not %d", a.Node, ep, a.Epoch)}
	}
	delete(st.Fences, a.Node)
	for i, t := range st.Desired.Targets {
		if t.Node == a.Node {
			st.Desired.Targets[i] = Target{Node: a.Node, Enabled: true, LUNs: []string{}}
		}
	}
	if err := r.save(st); err != nil {
		return err
	}
	if st.Firewall != nil {
		if err := r.applyFirewall(ctx, *st.Firewall, st); err != nil {
			return err
		}
	}
	r.log().Info("san: node unfenced", "node", a.Node, "epoch", a.Epoch)
	return nil
}

// withoutFenced drops fenced nodes' addresses from exports (and exports
// left without clients).
func (r *Root) withoutFenced(st *rootState, exports []nfs.ClusterExport) []nfs.ClusterExport {
	var blocked []netip.Addr
	for n := range st.Fences {
		if a, ok := st.Addresses[n]; ok {
			blocked = append(blocked, a)
		}
	}
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

// FirewallApply renders and loads the storage firewall (fenced nodes'
// addresses are forced into the drop set).
func (r *Root) FirewallApply(ctx context.Context, s FirewallSpec) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil {
		return err
	}
	if err := r.applyFirewall(ctx, s, st); err != nil {
		return err
	}
	st.Firewall = &s
	return r.save(st)
}

func (r *Root) applyFirewall(ctx context.Context, s FirewallSpec, st *rootState) error {
	for n := range st.Fences {
		if a, ok := st.Addresses[n]; ok {
			s.Members = slices.DeleteFunc(slices.Clone(s.Members), func(x netip.Addr) bool { return x == a })
			if !slices.Contains(s.Fenced, a) {
				s.Fenced = append(slices.Clone(s.Fenced), a)
			}
		}
	}
	content, err := RenderFirewall(s)
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
	return nil
}

// CHAPArgs names a node.
type CHAPArgs struct {
	Node cluster.NodeID `json:"node"`
}

// CHAP returns one node's secrets (for hardyd to hand to that node only;
// the peer handler checks the caller is the node).
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
	if _, ok := st.Desired.Target(a.Node); !ok {
		return nil, &ValidationError{fmt.Errorf("%s has no target on this storage node", a.Node)}
	}
	if _, fenced := st.Fences[a.Node]; fenced {
		return nil, &ValidationError{fmt.Errorf("%s is fenced", a.Node)}
	}
	c, err := r.ensureCHAP([]cluster.NodeID{a.Node})
	if err != nil {
		return nil, err
	}
	s := c[a.Node]
	return &s, nil
}

// RotateCHAP replaces a node's secrets (the node must log in again with
// the new ones; its current sessions keep running).
func (r *Root) RotateCHAP(ctx context.Context, a CHAPArgs) error {
	if err := ValidNode(a.Node); err != nil {
		return &ValidationError{err}
	}
	r.mu.Lock()
	c, err := r.loadCHAP()
	if err == nil {
		delete(c, a.Node)
		err = r.saveCHAP(c)
	}
	st, lerr := r.load()
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if lerr != nil {
		return lerr
	}
	return r.apply(ctx, ApplyArgs{Desired: st.Desired})
}

// NFSApplyArgs is nfs.cluster.apply.
type NFSApplyArgs struct {
	Exports []nfs.ClusterExport `json:"exports"`
}

// NFSApply checks each export's dataset itself (its role, owner, GUID and
// mountpoint), drops fenced nodes and writes the cluster exports.
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
	checked := make([]nfs.ClusterExport, 0, len(a.Exports))
	for _, e := range a.Exports {
		e, err := r.checkExport(ctx, e)
		if err != nil {
			return nil, err
		}
		checked = append(checked, e)
	}
	final := r.withoutFenced(st, checked)
	if err := r.NFS.Apply(ctx, final); err != nil {
		return nil, err
	}
	st.Exports = checked
	if err := r.save(st); err != nil {
		return nil, err
	}
	return final, nil
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
	case nfs.KindAppData:
		owner = PropApp
	case nfs.KindShare:
		owner = "org.hardyos:share"
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
