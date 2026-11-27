// Package hacopy is root's side of "Make highly available" and "Make local
// again" (docs/plans/make-ha.md, decisions 480-483): it lists, snapshots,
// sends and receives a workload's datasets (a VM's state folder and disks,
// an app's folder) between a server's own pool and the storage server's
// cluster pool, adopts what arrived, and parks a copy that is kept for a
// grace period.
//
// Every operation names a workload (kind, id, pool) and a side: "local"
// (a server's own VM or app: <pool>/vms/<id>, <pool>/apps/<id>, never
// cluster storage) or "cluster" (the storage server's cluster datasets,
// org.hardyos:role=cluster). Root checks each dataset's properties itself;
// the side only picks the rules, it never loosens them.
//
// Streams are single-dataset streams only (never zfs send -R packages,
// which carry properties and other datasets); every existing snapshot is
// sent as a full stream of the oldest and one increment per later one.
// A receive lands in a dataset marked org.hardyos:ha-incoming=<conv> that
// is neither exported nor a VM or app until Adopt; an interrupted receive
// keeps its resume token (zfs receive -s) and the sender accepts a token
// only for a snapshot of exactly the dataset it sends.
package hacopy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/replica"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Operation names (hardyd-priv).
const (
	OpTree          = "ha.tree"
	OpSnapshot      = "ha.snapshot"
	OpSnapDestroy   = "ha.snapshot.destroy"
	OpSend          = "ha.send"
	OpRecv          = "ha.recv"
	OpStream        = "ha.stream"
	OpCancel        = "ha.cancel"
	OpAdopt         = "ha.adopt"
	OpAbort         = "ha.abort"
	OpPark          = "ha.park"
	OpUnpark        = "ha.unpark"
	OpParkedList    = "ha.parked.list"
	OpParkedDestroy = "ha.parked.destroy"
	OpParkedKeep    = "ha.parked.keep"
)

// ZFS properties.
const (
	// PropIncoming marks a conversion's incoming folder
	// (<pool>/hardyos-ha-incoming/<conv>) with "<kind>:<id>".
	PropIncoming = "org.hardyos:ha-incoming"
	// IncomingDir holds what conversions are receiving, one folder per
	// conversion, on each pool.
	IncomingDir = "hardyos-ha-incoming"
	// PropParked marks a parked copy: "<kind>:<id>:<side>".
	PropParked = "org.hardyos:ha-parked"
	// ParkedDir is the folder of parked copies on each pool.
	ParkedDir = "hardyos-ha-parked"
	// RoleParked is ParkedDir's org.hardyos:role.
	RoleParked = "ha-parked"
	// SnapPrefix starts the snapshots conversions take.
	SnapPrefix = "hardyos-ha-"
	// propVM is the VM engine's own id property (vms.PropVM, on local
	// VMs too); propApp and propRole are cluster storage's.
	propVM   = san.PropVM
	propApp  = san.PropApp
	propRole = san.PropRole
)

// Side says whose datasets an operation works on.
type Side string

// Sides.
const (
	SideLocal   Side = "local"
	SideCluster Side = "cluster"
)

var (
	idRE     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)
	poolRE   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.:-]{0,63}$`)
	diskRE   = regexp.MustCompile(`^disk[0-9]$`)
	convRE   = regexp.MustCompile(`^[a-z0-9]{8,32}$`)
	snapRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)
	ownSnap  = regexp.MustCompile(`^` + SnapPrefix + `[a-z0-9-]{1,48}$`)
	parkedRE = regexp.MustCompile(`^(vm|app)-([a-z][a-z0-9-]{0,30}[a-z0-9])-([0-9]{1,12})$`)
	guidRE   = regexp.MustCompile(`^[0-9]{1,20}$`)
)

// nodeLocalApps are apps that are one server's by design (decision 472).
var nodeLocalApps = san.NodeLocalApps

// ErrInvalid marks a refused argument or state (CodeBadArgs).
type ErrInvalid struct{ Err error }

func (e *ErrInvalid) Error() string { return e.Err.Error() }
func (e *ErrInvalid) Unwrap() error { return e.Err }

func invalid(format string, a ...any) error { return &ErrInvalid{fmt.Errorf(format, a...)} }

// Ref names a workload's datasets on one side.
type Ref struct {
	Kind cluster.WorkloadKind `json:"kind"`
	ID   string               `json:"id"`
	Pool string               `json:"pool"`
	Side Side                 `json:"side"`
}

// Validate checks the names.
func (r Ref) Validate() error {
	if r.Kind != cluster.KindVM && r.Kind != cluster.KindApp {
		return invalid("kind %q isn't vm or app", r.Kind)
	}
	if !idRE.MatchString(r.ID) || strings.Contains(r.ID, "--") || strings.Contains(r.ID, "-kept-") {
		return invalid("%q isn't a workload id", r.ID)
	}
	if r.Kind == cluster.KindApp && slices.Contains(nodeLocalApps, r.ID) {
		return invalid("%s belongs to one server and can't move to cluster storage", r.ID)
	}
	if !poolRE.MatchString(r.Pool) || strings.Contains(r.Pool, "/") {
		return invalid("%q isn't a pool name", r.Pool)
	}
	if r.Side != SideLocal && r.Side != SideCluster {
		return invalid("side %q isn't local or cluster", r.Side)
	}
	return nil
}

// parent is <pool>/vms or <pool>/apps.
func (r Ref) parent() string {
	if r.Kind == cluster.KindApp {
		return r.Pool + "/apps"
	}
	return r.Pool + "/vms"
}

// Dataset is the workload's top dataset.
func (r Ref) Dataset() string { return r.parent() + "/" + r.ID }

// dataset of a child ("" is the top one).
func (r Ref) dataset(child string) (string, error) {
	if child == "" {
		return r.Dataset(), nil
	}
	if r.Kind != cluster.KindVM || !diskRE.MatchString(child) {
		return "", invalid("%q isn't one of the workload's datasets", child)
	}
	return r.Dataset() + "/" + child, nil
}

func (r Ref) ownerProp() string {
	if r.Kind == cluster.KindApp {
		return propApp
	}
	return propVM
}

func (r Ref) parkedValue() string { return string(r.Kind) + ":" + r.ID + ":" + string(r.Side) }

func (r Ref) incomingValue() string { return string(r.Kind) + ":" + r.ID }

// incomingDir is conversion conv's folder; incomingTop the workload's top
// dataset in it. What a conversion receives is its own by its path: an
// interrupted receive may not carry the properties it was started with.
func (r Ref) incomingDir(conv string) string { return r.Pool + "/" + IncomingDir + "/" + conv }

func (r Ref) incomingTop(conv string) string {
	return r.incomingDir(conv) + "/" + string(r.Kind) + "-" + r.ID
}

func (r Ref) incomingDataset(conv, child string) (string, error) {
	if _, err := r.dataset(child); err != nil {
		return "", err
	}
	if child == "" {
		return r.incomingTop(conv), nil
	}
	return r.incomingTop(conv) + "/" + child, nil
}

// checkIncoming verifies conversion conv's folder is ref's (it may not
// exist yet).
func (r *Root) checkIncoming(ctx context.Context, ref Ref, conv string) (exists bool, err error) {
	if err := ref.Validate(); err != nil {
		return false, err
	}
	if !convRE.MatchString(conv) {
		return false, invalid("bad conversion id")
	}
	dir := ref.incomingDir(conv)
	if _, ok := r.exists(ctx, dir); !ok {
		return false, nil
	}
	if r.localProp(ctx, dir, PropIncoming) != ref.incomingValue() {
		return false, invalid("%s isn't %s %s's incoming copy", dir, ref.Kind, ref.ID)
	}
	return true, nil
}

// Root is the operations' implementation.
type Root struct {
	Runner  sysexec.Runner
	Starter replica.Starter
	Log     *slog.Logger
	// Busy refuses parking cluster storage that is still mapped or
	// exported (the storage server's san.Root.InUse).
	Busy func(ctx context.Context, kind cluster.WorkloadKind, id, pool string) (bool, error)
	// EnsureParent makes <pool>/vms or <pool>/apps on the cluster side
	// with its quota (san.Root.EnsureParent).
	EnsureParent func(ctx context.Context, pool, parent string) error
	// Now is root's clock (tests).
	Now func() time.Time

	mu      sync.Mutex
	streams streams
}

func (r *Root) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

func (r *Root) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Root) starter() replica.Starter {
	if r.Starter != nil {
		return r.Starter
	}
	return replica.ExecStarter{}
}

func (r *Root) zfs(ctx context.Context, args ...string) ([]byte, error) {
	return sysexec.Output(ctx, r.Runner, "zfs", args...)
}

// props reads properties (-p values; "-" for unset).
func (r *Root) props(ctx context.Context, ds string, names ...string) (map[string]string, error) {
	out, err := r.zfs(ctx, "get", "-H", "-p", "-o", "property,value", strings.Join(names, ","), ds)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ds, err)
	}
	m := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		k, v, ok := strings.Cut(l, "\t")
		if ok {
			if v == "-" {
				v = ""
			}
			m[k] = v
		}
	}
	return m, nil
}

// localProp reads a property only when it is set on the dataset itself
// (not inherited): a mark root put there.
func (r *Root) localProp(ctx context.Context, ds, name string) string {
	out, err := r.zfs(ctx, "get", "-H", "-p", "-s", "local,received", "-o", "value", name, ds)
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(out))
	if v == "-" {
		return ""
	}
	return v
}

func (r *Root) exists(ctx context.Context, ds string) (string, bool) {
	out, err := r.zfs(ctx, "list", "-H", "-o", "type", ds)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

// children lists a top dataset's descendants (child names relative to it)
// with their types; anything that isn't one of the workload's own
// datasets is refused.
func (r *Root) children(ctx context.Context, ref Ref, top string) (map[string]string, error) {
	out, err := r.zfs(ctx, "list", "-H", "-r", "-o", "name,type", "-t", "filesystem,volume", top)
	if err != nil {
		return nil, err
	}
	res := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		name, typ, ok := strings.Cut(l, "\t")
		if !ok {
			continue
		}
		if name == top {
			if typ != "filesystem" {
				return nil, invalid("%s isn't a file system", top)
			}
			continue
		}
		child := strings.TrimPrefix(name, top+"/")
		if child == name || ref.Kind != cluster.KindVM || !diskRE.MatchString(child) || typ != "volume" {
			return nil, invalid("%s holds %s, which isn't one of its disks; it can't be moved as it is", top, name)
		}
		res[child] = typ
	}
	return res, nil
}

// checkSource verifies the workload's live datasets on its side.
func (r *Root) checkSource(ctx context.Context, ref Ref) (map[string]string, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	top := ref.Dataset()
	typ, ok := r.exists(ctx, top)
	if !ok {
		return nil, invalid("%s doesn't exist", top)
	}
	if typ != "filesystem" {
		return nil, invalid("%s isn't a file system", top)
	}
	p, err := r.props(ctx, top, propRole, ref.ownerProp(), PropIncoming, PropParked)
	if err != nil {
		return nil, err
	}
	if p[PropIncoming] != "" || p[PropParked] != "" {
		return nil, invalid("%s is being received or is parked", top)
	}
	switch ref.Side {
	case SideLocal:
		if p[propRole] == san.RoleCluster {
			return nil, invalid("%s is cluster storage, not this server's own", top)
		}
		if ref.Kind == cluster.KindVM && p[propVM] != ref.ID {
			return nil, invalid("%s isn't VM %s's", top, ref.ID)
		}
	case SideCluster:
		if p[propRole] != san.RoleCluster || p[ref.ownerProp()] != ref.ID {
			return nil, invalid("%s isn't %s %s's cluster storage", top, ref.Kind, ref.ID)
		}
	}
	kids, err := r.children(ctx, ref, top)
	if err != nil {
		return nil, err
	}
	for child := range kids {
		ds := top + "/" + child
		cp, err := r.props(ctx, ds, propRole, ref.ownerProp())
		if err != nil {
			return nil, err
		}
		if ref.Side == SideCluster && (cp[propRole] != san.RoleCluster || cp[ref.ownerProp()] != ref.ID) {
			return nil, invalid("%s isn't %s's cluster storage", ds, ref.ID)
		}
		if ref.Side == SideLocal && cp[propRole] == san.RoleCluster {
			return nil, invalid("%s is cluster storage", ds)
		}
	}
	return kids, nil
}

// ---- listing ----------------------------------------------------------------------

// Snap is one snapshot of a dataset.
type Snap struct {
	Name string `json:"name"`
	GUID string `json:"guid"`
	TXG  uint64 `json:"txg"`
}

// TreeDataset is one dataset of a workload with its snapshots, oldest
// first.
type TreeDataset struct {
	Child string `json:"child"`
	Type  string `json:"type"`
	Snaps []Snap `json:"snaps"`
	// Token resumes an interrupted receive (incoming datasets only).
	Token string `json:"token,omitempty"`
	Used  int64  `json:"used"`
}

// Tree is a workload's datasets.
type Tree struct {
	Exists   bool          `json:"exists"`
	Datasets []TreeDataset `json:"datasets"`
}

// TreeArgs is ha.tree: the live datasets, or (Conv set) what a
// conversion received so far.
type TreeArgs struct {
	Ref
	Conv string `json:"conv,omitempty"`
}

// Tree lists a workload's datasets and snapshots.
func (r *Root) Tree(ctx context.Context, a TreeArgs) (*Tree, error) {
	t := &Tree{Datasets: []TreeDataset{}}
	var kids map[string]string
	if a.Conv == "" {
		k, err := r.checkSource(ctx, a.Ref)
		if err != nil {
			return nil, err
		}
		kids = k
	} else {
		ok, err := r.checkIncoming(ctx, a.Ref, a.Conv)
		if err != nil {
			return nil, err
		}
		top := a.Ref.incomingTop(a.Conv)
		if _, there := r.exists(ctx, top); !ok || !there {
			return t, nil
		}
		k, err := r.children(ctx, a.Ref, top)
		if err != nil {
			return nil, err
		}
		kids = k
	}
	t.Exists = true
	names := []string{""}
	for c := range kids {
		names = append(names, c)
	}
	slices.Sort(names)
	for _, child := range names {
		ds, _ := a.Ref.dataset(child)
		if a.Conv != "" {
			ds, _ = a.Ref.incomingDataset(a.Conv, child)
		}
		td := TreeDataset{Child: child, Type: "filesystem", Snaps: []Snap{}}
		if child != "" {
			td.Type = "volume"
		}
		snaps, err := r.snaps(ctx, ds)
		if err != nil {
			return nil, err
		}
		td.Snaps = snaps
		p, err := r.props(ctx, ds, "receive_resume_token", "used")
		if err == nil {
			if a.Conv != "" && replica.ValidToken(p["receive_resume_token"]) == nil {
				td.Token = p["receive_resume_token"]
			}
			td.Used, _ = strconv.ParseInt(p["used"], 10, 64)
		}
		t.Datasets = append(t.Datasets, td)
	}
	return t, nil
}

func (r *Root) snaps(ctx context.Context, ds string) ([]Snap, error) {
	out, err := r.zfs(ctx, "list", "-H", "-p", "-t", "snapshot", "-o", "name,guid,createtxg", "-s", "createtxg", "-d", "1", ds)
	if err != nil {
		return nil, err
	}
	l := []Snap{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			continue
		}
		_, name, ok := strings.Cut(f[0], "@")
		if !ok || !snapRE.MatchString(name) || !guidRE.MatchString(f[1]) {
			continue
		}
		txg, _ := strconv.ParseUint(f[2], 10, 64)
		l = append(l, Snap{Name: name, GUID: f[1], TXG: txg})
	}
	return l, nil
}

// ---- snapshots ----------------------------------------------------------------------

// SnapArgs is ha.snapshot and ha.snapshot.destroy.
type SnapArgs struct {
	Ref
	Name string `json:"name"`
}

// Snapshot takes a recursive snapshot of the workload's live datasets
// (its name starts with hardyos-ha-).
func (r *Root) Snapshot(ctx context.Context, a SnapArgs) error {
	if !ownSnap.MatchString(a.Name) {
		return invalid("a conversion's snapshot is named %s<…>", SnapPrefix)
	}
	if _, err := r.checkSource(ctx, a.Ref); err != nil {
		return err
	}
	if a.Side == SideCluster {
		// The storage server's per-workload snapshot limit (M4).
		snaps, err := r.snaps(ctx, a.Dataset())
		if err == nil && len(snaps) >= san.MaxSnapshots {
			return invalid("%s already has %d snapshots", a.ID, len(snaps))
		}
	}
	_, err := r.zfs(ctx, "snapshot", "-r", a.Dataset()+"@"+a.Name)
	return err
}

// SnapshotDestroy removes one of the conversion's own snapshots
// (recursively) from the live datasets.
func (r *Root) SnapshotDestroy(ctx context.Context, a SnapArgs) error {
	if !ownSnap.MatchString(a.Name) {
		return invalid("only a conversion's own snapshots are removed here")
	}
	if _, err := r.checkSource(ctx, a.Ref); err != nil {
		return err
	}
	if _, ok := r.exists(ctx, a.Dataset()+"@"+a.Name); !ok {
		return nil
	}
	_, err := r.zfs(ctx, "destroy", "-r", a.Dataset()+"@"+a.Name)
	return err
}

// ---- adopt, abort --------------------------------------------------------------------

// AdoptArgs is ha.adopt: what conversion Conv received becomes the
// workload's storage on its side.
type AdoptArgs struct {
	Ref
	Conv string `json:"conv"`
	// Cluster names the LUNs' serials (cluster side).
	Cluster cluster.ClusterID `json:"cluster,omitempty"`
}

// VolumeInfo is an adopted zvol.
type VolumeInfo struct {
	Dataset string `json:"dataset"`
	Disk    string `json:"disk"`
	GUID    string `json:"guid"`
	WWN     string `json:"wwn,omitempty"`
	SizeGB  int    `json:"sizeGB"`
}

// AdoptResult describes the adopted storage.
type AdoptResult struct {
	Dataset    string       `json:"dataset"`
	Mountpoint string       `json:"mountpoint"`
	GUID       string       `json:"guid"`
	Volumes    []VolumeInfo `json:"volumes"`
}

// Adopt turns a finished receive into the workload's storage.
func (r *Root) Adopt(ctx context.Context, a AdoptArgs) (*AdoptResult, error) {
	if err := a.Ref.Validate(); err != nil {
		return nil, err
	}
	if !convRE.MatchString(a.Conv) {
		return nil, invalid("bad conversion id")
	}
	if a.Side == SideCluster {
		if err := san.ValidCluster(a.Cluster); err != nil {
			return nil, invalid("%v", err)
		}
	}
	ok, err := r.checkIncoming(ctx, a.Ref, a.Conv)
	if err != nil {
		return nil, err
	}
	src := a.incomingTop(a.Conv)
	top := a.Dataset()
	if _, there := r.exists(ctx, src); !ok || !there {
		if a.Side == SideCluster {
			// Adopted already (a conversion resumed after its answer was
			// lost): describe what is there, if it is the workload's
			// cluster storage.
			if kids, err := r.checkSource(ctx, a.Ref); err == nil {
				return r.describe(ctx, a.Ref, top, kids, a.Cluster)
			}
		}
		return nil, invalid("nothing was received for %s", a.ID)
	}
	if _, there := r.exists(ctx, top); there {
		return nil, invalid("%s exists already; it isn't replaced", top)
	}
	kids, err := r.children(ctx, a.Ref, src)
	if err != nil {
		return nil, err
	}
	all := []string{src}
	for c := range kids {
		all = append(all, src+"/"+c)
	}
	slices.Sort(all)
	for _, ds := range all {
		if p, err := r.props(ctx, ds, "receive_resume_token"); err != nil || p["receive_resume_token"] != "" {
			return nil, invalid("%s is only partly received", ds)
		}
	}
	parent := a.parent()
	if _, there := r.exists(ctx, parent); !there {
		if err := r.makeParent(ctx, a.Ref, parent); err != nil {
			return nil, err
		}
	}
	if _, err := r.zfs(ctx, "rename", src, top); err != nil {
		return nil, err
	}
	if err := r.applyProps(ctx, a.Ref, top, kids); err != nil {
		return nil, err
	}
	if err := r.mount(ctx, top); err != nil {
		return nil, err
	}
	if _, err := r.zfs(ctx, "destroy", a.incomingDir(a.Conv)); err != nil {
		r.log().Warn("ha: removing an empty incoming folder", "conv", a.Conv, "err", err)
	}
	r.log().Info("ha: adopted", "dataset", top, "side", a.Side)
	return r.describe(ctx, a.Ref, top, kids, a.Cluster)
}

// applyProps gives a workload's datasets their side's properties.
func (r *Root) applyProps(ctx context.Context, ref Ref, top string, kids map[string]string) error {
	set := func(ds string, kv ...string) error {
		if len(kv) == 0 {
			return nil
		}
		_, err := r.zfs(ctx, append(append([]string{"set"}, kv...), ds)...)
		return err
	}
	// As the engines make them: a VM's state folder as vms.Manager does
	// (canmount, no devices, setuid or exec), a local app's folder as
	// apps.Manager does (plain), a cluster app's as san.DatasetCreate.
	fs := []string{"canmount=on"}
	if ref.Kind == cluster.KindVM || ref.Side == SideCluster {
		fs = append(fs, "devices=off", "setuid=off")
	}
	if ref.Kind == cluster.KindVM {
		fs = append(fs, "exec=off", propVM+"="+ref.ID)
	}
	if ref.Side == SideCluster {
		fs = append(fs, propRole+"="+san.RoleCluster)
		if ref.Kind == cluster.KindApp {
			fs = append(fs, propApp+"="+ref.ID)
		}
		if ref.Kind == cluster.KindVM {
			// A VM's state folder: settings, firmware variables, TPM,
			// cloud-init disc. Room for what it holds and a gigabyte.
			p, err := r.props(ctx, top, "usedbydataset")
			if err != nil {
				return err
			}
			used, _ := strconv.ParseInt(p["usedbydataset"], 10, 64)
			q := max(int64(1), used>>30+2)
			fs = append(fs, "quota="+strconv.FormatInt(q, 10)+"G")
		}
	}
	if err := set(top, fs...); err != nil {
		return err
	}
	for c := range kids {
		vol := []string{propVM + "=" + ref.ID}
		if ref.Side == SideCluster {
			vol = append(vol, propRole+"="+san.RoleCluster, "volmode=dev")
		} else {
			vol = append(vol, "volmode=default")
		}
		if err := set(top+"/"+c, vol...); err != nil {
			return err
		}
	}
	return nil
}

func (r *Root) mount(ctx context.Context, ds string) error {
	p, err := r.props(ctx, ds, "mounted")
	if err != nil {
		return err
	}
	if p["mounted"] == "yes" {
		return nil
	}
	_, err = r.zfs(ctx, "mount", ds)
	return err
}

func (r *Root) describe(ctx context.Context, ref Ref, top string, kids map[string]string, c cluster.ClusterID) (*AdoptResult, error) {
	p, err := r.props(ctx, top, "mountpoint", "guid")
	if err != nil {
		return nil, err
	}
	res := &AdoptResult{Dataset: top, Mountpoint: p["mountpoint"], GUID: p["guid"], Volumes: []VolumeInfo{}}
	names := make([]string, 0, len(kids))
	for k := range kids {
		names = append(names, k)
	}
	slices.Sort(names)
	for _, d := range names {
		ds := top + "/" + d
		vp, err := r.props(ctx, ds, "guid", "volsize")
		if err != nil {
			return nil, err
		}
		size, _ := strconv.ParseInt(vp["volsize"], 10, 64)
		v := VolumeInfo{Dataset: ds, Disk: d, GUID: vp["guid"], SizeGB: int((size + 1<<30 - 1) >> 30)}
		if ref.Side == SideCluster {
			v.WWN = san.WWN(san.Serial(c, vp["guid"]))
		}
		res.Volumes = append(res.Volumes, v)
	}
	return res, nil
}

// AbortArgs is ha.abort.
type AbortArgs struct {
	Ref
	Conv string `json:"conv"`
}

// Abort destroys what a conversion received (never adopted storage).
func (r *Root) Abort(ctx context.Context, a AbortArgs) error {
	ok, err := r.checkIncoming(ctx, a.Ref, a.Conv)
	if err != nil || !ok {
		return err
	}
	dir := a.incomingDir(a.Conv)
	r.streams.cancelTarget(dir)
	if _, err := r.zfs(ctx, "destroy", "-r", dir); err != nil {
		return err
	}
	r.log().Warn("ha: incoming copy destroyed", "dataset", dir)
	return nil
}

// ---- parking ------------------------------------------------------------------------

// ParkArgs is ha.park: Confirm is the workload's id. KeepUntil (unix
// seconds) is when hardyd may destroy it; 0 keeps it until an
// administrator does.
type ParkArgs struct {
	Ref
	Confirm   string `json:"confirm"`
	KeepUntil int64  `json:"keepUntil,omitempty"`
}

// PropKeepUntil is a parked copy's expiry (unix seconds; unset: kept).
const PropKeepUntil = "org.hardyos:ha-keep-until"

// ParkedKeepArgs is ha.parked.keep: a parked copy's new expiry (0: kept).
type ParkedKeepArgs struct {
	Pool      string `json:"pool"`
	Name      string `json:"name"`
	KeepUntil int64  `json:"keepUntil"`
}

// ParkedKeep sets a parked copy's expiry.
func (r *Root) ParkedKeep(ctx context.Context, a ParkedKeepArgs) error {
	ds, err := r.parked(ctx, a.Pool, a.Name, Ref{})
	if err != nil {
		return err
	}
	if a.KeepUntil < 0 {
		return invalid("bad expiry")
	}
	if a.KeepUntil == 0 {
		_, err = r.zfs(ctx, "inherit", PropKeepUntil, ds)
		return err
	}
	_, err = r.zfs(ctx, "set", PropKeepUntil+"="+strconv.FormatInt(a.KeepUntil, 10), ds)
	return err
}

// ParkResult names the parked copy.
type ParkResult struct {
	Pool string `json:"pool"`
	Name string `json:"name"`
}

// ErrBusy: the storage is still in use.
var ErrBusy = errors.New("the workload's storage is still in use")

// Park moves a workload's datasets out of the way: they are no longer a
// VM, an app or cluster storage, and are kept until destroyed. The caller
// (the VM or app engine) has stopped it and dropped its definition.
func (r *Root) Park(ctx context.Context, a ParkArgs) (*ParkResult, error) {
	if a.Confirm != a.ID {
		return nil, invalid("type the name to confirm")
	}
	kids, err := r.checkSource(ctx, a.Ref)
	if err != nil {
		return nil, err
	}
	if a.Side == SideCluster {
		if r.Busy == nil {
			return nil, invalid("the storage server's state isn't known")
		}
		busy, err := r.Busy(ctx, a.Kind, a.ID, a.Pool)
		if err != nil {
			return nil, err
		}
		if busy {
			return nil, fmt.Errorf("%w: %s is still mapped or exported", ErrBusy, a.ID)
		}
	}
	parent := a.Pool + "/" + ParkedDir
	if _, ok := r.exists(ctx, parent); !ok {
		if _, err := r.zfs(ctx, "create", "-o", "canmount=off", "-o", propRole+"="+RoleParked, parent); err != nil {
			return nil, err
		}
	}
	top := a.Dataset()
	name := string(a.Kind) + "-" + a.ID + "-" + strconv.FormatInt(r.now().Unix(), 10)
	if _, err := r.zfs(ctx, "set", "canmount=noauto", top); err != nil {
		return nil, err
	}
	if p, _ := r.props(ctx, top, "mounted"); p["mounted"] == "yes" {
		if _, err := r.zfs(ctx, "unmount", top); err != nil {
			_, _ = r.zfs(context.WithoutCancel(ctx), "set", "canmount=on", top)
			return nil, fmt.Errorf("unmounting %s: %w", top, err)
		}
	}
	dst := parent + "/" + name
	if _, err := r.zfs(ctx, "rename", top, dst); err != nil {
		_, _ = r.zfs(context.WithoutCancel(ctx), "set", "canmount=on", top)
		_ = r.mount(context.WithoutCancel(ctx), top)
		return nil, err
	}
	if _, err := r.zfs(ctx, "set", PropParked+"="+a.parkedValue(), dst); err != nil {
		return nil, err
	}
	if a.KeepUntil > 0 {
		if _, err := r.zfs(ctx, "set", PropKeepUntil+"="+strconv.FormatInt(a.KeepUntil, 10), dst); err != nil {
			return nil, err
		}
	}
	// Nothing parked is a VM, an app or cluster storage any more.
	all := []string{dst}
	for c := range kids {
		all = append(all, dst+"/"+c)
	}
	for _, ds := range all {
		for _, prop := range []string{propVM, propApp, propRole} {
			if v := r.localProp(ctx, ds, prop); v != "" {
				if _, err := r.zfs(ctx, "inherit", prop, ds); err != nil {
					return nil, err
				}
			}
		}
		if ds != dst {
			if _, err := r.zfs(ctx, "set", "volmode=none", ds); err != nil {
				r.log().Warn("ha: hiding a parked disk", "dataset", ds, "err", err)
			}
		}
	}
	r.log().Warn("ha: parked", "from", top, "to", dst)
	return &ParkResult{Pool: a.Pool, Name: name}, nil
}

// UnparkArgs is ha.unpark.
type UnparkArgs struct {
	Ref
	Name string `json:"name"`
}

// Unpark puts a parked copy back as the workload's storage.
func (r *Root) Unpark(ctx context.Context, a UnparkArgs) error {
	if err := a.Ref.Validate(); err != nil {
		return err
	}
	src, err := r.parked(ctx, a.Pool, a.Name, a.Ref)
	if err != nil {
		return err
	}
	top := a.Dataset()
	if _, ok := r.exists(ctx, top); ok {
		return invalid("%s exists; it can't be put back over it", top)
	}
	if _, ok := r.exists(ctx, a.parent()); !ok {
		return invalid("%s doesn't exist", a.parent())
	}
	kids, err := r.children(ctx, a.Ref, src)
	if err != nil {
		return err
	}
	if _, err := r.zfs(ctx, "rename", src, top); err != nil {
		return err
	}
	for _, p := range []string{PropParked, PropKeepUntil} {
		if _, err := r.zfs(ctx, "inherit", p, top); err != nil {
			return err
		}
	}
	if err := r.applyProps(ctx, a.Ref, top, kids); err != nil {
		return err
	}
	r.log().Warn("ha: put back", "from", src, "to", top)
	return r.mount(ctx, top)
}

// parked finds a parked copy of ref.
func (r *Root) parked(ctx context.Context, pool, name string, ref Ref) (string, error) {
	m := parkedRE.FindStringSubmatch(name)
	if m == nil || !poolRE.MatchString(pool) || strings.Contains(pool, "/") {
		return "", invalid("%q isn't a parked copy", name)
	}
	ds := pool + "/" + ParkedDir + "/" + name
	if _, ok := r.exists(ctx, ds); !ok {
		return "", invalid("%s doesn't exist", ds)
	}
	v := r.localProp(ctx, ds, PropParked)
	if v == "" || (ref.ID != "" && v != ref.parkedValue()) {
		return "", invalid("%s isn't a parked copy of %s %s", ds, ref.Kind, ref.ID)
	}
	if m[1] != strings.SplitN(v, ":", 2)[0] || m[2] != strings.SplitN(v, ":", 3)[1] {
		return "", invalid("%s's name and mark disagree", ds)
	}
	return ds, nil
}

// Parked is one parked copy.
type Parked struct {
	Pool    string               `json:"pool"`
	Name    string               `json:"name"`
	Kind    cluster.WorkloadKind `json:"kind"`
	ID      string               `json:"id"`
	Side    Side                 `json:"side"`
	Used    int64                `json:"used"`
	Created time.Time            `json:"created"`
	// KeepUntil is when it may be destroyed (zero: kept until an
	// administrator deletes it).
	KeepUntil time.Time `json:"keepUntil,omitzero"`
}

// ParkedList lists the parked copies on every pool.
func (r *Root) ParkedList(ctx context.Context) ([]Parked, error) {
	out, err := sysexec.Output(ctx, r.Runner, "zpool", "list", "-H", "-o", "name")
	if err != nil {
		return nil, err
	}
	l := []Parked{}
	for _, pool := range strings.Fields(string(out)) {
		if !poolRE.MatchString(pool) {
			continue
		}
		dir := pool + "/" + ParkedDir
		if _, ok := r.exists(ctx, dir); !ok {
			continue
		}
		o, err := r.zfs(ctx, "list", "-H", "-p", "-d", "1", "-t", "filesystem", "-o", "name,"+PropParked+",used,creation,"+PropKeepUntil, dir)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(o)), "\n") {
			f := strings.Split(line, "\t")
			if len(f) != 5 || f[0] == dir {
				continue
			}
			name := strings.TrimPrefix(f[0], dir+"/")
			parts := strings.Split(f[1], ":")
			if !parkedRE.MatchString(name) || len(parts) != 3 {
				continue
			}
			used, _ := strconv.ParseInt(f[2], 10, 64)
			cr, _ := strconv.ParseInt(f[3], 10, 64)
			p := Parked{Pool: pool, Name: name, Kind: cluster.WorkloadKind(parts[0]), ID: parts[1], Side: Side(parts[2]),
				Used: used, Created: time.Unix(cr, 0).UTC()}
			if ku, err := strconv.ParseInt(f[4], 10, 64); err == nil && ku > 0 {
				p.KeepUntil = time.Unix(ku, 0).UTC()
			}
			l = append(l, p)
		}
	}
	return l, nil
}

// ParkedDestroyArgs is ha.parked.destroy: Confirm is the workload's id.
type ParkedDestroyArgs struct {
	Pool    string `json:"pool"`
	Name    string `json:"name"`
	Confirm string `json:"confirm"`
}

// ParkedDestroy destroys a parked copy with its snapshots.
func (r *Root) ParkedDestroy(ctx context.Context, a ParkedDestroyArgs) error {
	m := parkedRE.FindStringSubmatch(a.Name)
	if m == nil {
		return invalid("%q isn't a parked copy", a.Name)
	}
	if a.Confirm != m[2] {
		return invalid("type the name (%s) to delete its kept copy", m[2])
	}
	ds, err := r.parked(ctx, a.Pool, a.Name, Ref{})
	if err != nil {
		return err
	}
	if _, err := r.zfs(ctx, "destroy", "-r", ds); err != nil {
		return err
	}
	r.log().Warn("ha: parked copy destroyed", "dataset", ds)
	return nil
}
