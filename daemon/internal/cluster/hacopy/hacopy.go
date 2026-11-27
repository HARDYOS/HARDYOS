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
	"github.com/hardyos/hardyos/daemon/internal/shares"
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
	// propHAHold is a local app's conversion hold (apps.PropHAHold), and
	// propHAHoldRunning the state it recorded (apps.PropHAHoldRunning).
	propHAHold        = "org.hardyos:ha-hold"
	propHAHoldRunning = "org.hardyos:ha-hold-running"
	propVM            = san.PropVM
	propApp           = san.PropApp
	propRole          = san.PropRole
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
	parkedRE = regexp.MustCompile(`^(vm|app|share)-([a-z0-9][a-z0-9-]{0,31})-([0-9]{1,12})$`)
	guidRE   = regexp.MustCompile(`^[0-9]{1,20}$`)
)

// KindShare is a shared folder that moves with an app made highly
// available (decision 500): <pool>/shares/<id> on this server (local) or
// on the storage server (cluster), where it is the storage server's own
// shared folder, used in the cluster. It is never a cluster workload.
const KindShare cluster.WorkloadKind = "share"

// propShare marks a shared folder's dataset (shares.PropShare = "1").
const propShare = shares.PropShare

// AppBlockChild is a cluster app's block volume below its folder
// (san.AppBlock).
const AppBlockChild = "block"

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
	switch r.Kind {
	case cluster.KindVM, cluster.KindApp:
		if !idRE.MatchString(r.ID) || strings.Contains(r.ID, "--") || strings.Contains(r.ID, "-kept-") {
			return invalid("%q isn't a workload id", r.ID)
		}
	case KindShare:
		if shares.ValidID(r.ID) != nil {
			return invalid("%q isn't a shared folder id", r.ID)
		}
	default:
		return invalid("kind %q isn't vm, app or share", r.Kind)
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
	switch r.Kind {
	case cluster.KindApp:
		return r.Pool + "/apps"
	case KindShare:
		return shares.SharesDataset(r.Pool)
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
	switch r.Kind {
	case cluster.KindApp:
		return propApp
	case KindShare:
		return propShare
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
	// Shared folders (KindShare): ShareRelease lets the file services go
	// of one before it is parked (priv's share hooks, as before a delete),
	// ShareChanged has them take up a change (a folder adopted, parked or
	// put back), ShareTaken refuses adopting a folder whose id or name this
	// server has already, and ShareBusy reports a cluster share still
	// exported to compute servers (the storage server's NFS exports).
	// ShareRelease's answer is called once the park is over, whatever it
	// did (file sharing's own holds end then, as after a delete).
	ShareRelease func(ctx context.Context, id string) (done func())
	ShareChanged func(ctx context.Context)
	ShareTaken   func(ctx context.Context, id, name string) error
	ShareBusy    func(ctx context.Context, pool, id string) (bool, error)
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
		switch {
		case child != name && ref.Kind == cluster.KindVM && diskRE.MatchString(child) && typ == "volume":
		case child == AppBlockChild && ref.Kind == cluster.KindApp && ref.Side == SideCluster && typ == "volume":
			// A cluster app's block volume (block mode): parked with its
			// copy, never sent (Tree leaves it out: "make local" moves
			// its data back into the app's folder first).
		default:
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
	if ref.Kind == KindShare {
		// A shared folder is the server's own on either side (on the
		// storage server it is one of its shared folders, used in the
		// cluster): never cluster workload storage, always marked as a
		// shared folder, and nothing below it.
		if p[propRole] == san.RoleCluster || p[propShare] != "1" {
			return nil, invalid("%s isn't a shared folder", top)
		}
		return r.children(ctx, ref, top)
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

// MaxSnaps is the most snapshots of one dataset a conversion carries (a
// stream each, and the lists between the servers stay bounded).
const MaxSnaps = 512

// TooManySnaps names a dataset of t with more than MaxSnaps snapshots.
func TooManySnaps(t *Tree) (child string, n int, over bool) {
	for _, d := range t.Datasets {
		if len(d.Snaps) > MaxSnaps {
			return d.Child, len(d.Snaps), true
		}
	}
	return "", 0, false
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
		if c == AppBlockChild {
			continue // never sent (children)
		}
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
	// Share is a shared folder's settings (KindShare, cluster side only):
	// checked like a person's input and written as its properties.
	Share *shares.Settings `json:"share,omitempty"`
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
	if a.Side == SideCluster && a.Kind != KindShare {
		if err := san.ValidCluster(a.Cluster); err != nil {
			return nil, invalid("%v", err)
		}
	}
	var set *shares.Settings
	if a.Kind == KindShare {
		// A shared folder only ever moves to the storage server (with its
		// app); it comes back by Undo, which puts this server's copy back.
		if a.Side != SideCluster || a.Share == nil {
			return nil, invalid("a shared folder is adopted on the storage server, with its settings")
		}
		s, err := a.Share.Check()
		if err != nil {
			return nil, invalid("the shared folder's settings: %v", err)
		}
		set = &s
	}
	ok, err := r.checkIncoming(ctx, a.Ref, a.Conv)
	if err != nil {
		return nil, err
	}
	src := a.incomingTop(a.Conv)
	top := a.Dataset()
	if _, there := r.exists(ctx, src); !ok || !there {
		// Adopted already by this conversion (resumed after root's answer
		// was lost): describe what is there, if it is the workload's
		// storage on this side and carries this conversion's mark.
		// An adopt cut short after the rename is finished here.
		if r.localProp(ctx, top, PropParkedConv) == a.Conv {
			kids, err := r.children(ctx, a.Ref, top)
			if err != nil {
				return nil, err
			}
			if err := r.applyProps(ctx, a.Ref, top, kids); err != nil {
				return nil, err
			}
			if err := r.applyShare(ctx, top, set); err != nil {
				return nil, err
			}
			if set != nil && r.localProp(ctx, top, propHAHold) != "" {
				// Still held for this conversion (see below).
				if err := r.holdShare(ctx, top, a.Conv); err != nil {
					return nil, err
				}
				return r.describe(ctx, a.Ref, top, kids, a.Cluster)
			}
			if err := r.mount(ctx, top); err != nil {
				return nil, err
			}
			r.shareChanged(ctx, a.Ref)
			return r.describe(ctx, a.Ref, top, kids, a.Cluster)
		}
		return nil, invalid("nothing was received for %s", a.ID)
	}
	if _, there := r.exists(ctx, top); there {
		return nil, invalid("%s exists already; it isn't replaced", top)
	}
	if set != nil {
		if r.ShareTaken == nil {
			return nil, invalid("this server's shared folders aren't known here")
		}
		if err := r.ShareTaken(ctx, a.ID, set.Name); err != nil {
			return nil, invalid("%v", err)
		}
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
	// The conversion's mark first: a retry finishes what this started,
	// and Abandon finds it.
	if _, err := r.zfs(ctx, "set", PropParkedConv+"="+a.Conv, top); err != nil {
		return nil, err
	}
	if err := r.applyProps(ctx, a.Ref, top, kids); err != nil {
		return nil, err
	}
	if err := r.applyShare(ctx, top, set); err != nil {
		return nil, err
	}
	if set != nil {
		// A shared folder is adopted held (read-only, unmounted, out of
		// file sharing) until the server it came from has put its own copy
		// aside: never two copies anyone can write (decision 501). The
		// conversion lets go of it then (shares.ha.hold, its own mark).
		if err := r.holdShare(ctx, top, a.Conv); err != nil {
			return nil, err
		}
	} else if err := r.mount(ctx, top); err != nil {
		return nil, err
	}
	if _, err := r.zfs(ctx, "destroy", a.incomingDir(a.Conv)); err != nil {
		r.log().Warn("ha: removing an empty incoming folder", "conv", a.Conv, "err", err)
	}
	r.shareChanged(ctx, a.Ref)
	r.log().Info("ha: adopted", "dataset", top, "side", a.Side)
	return r.describe(ctx, a.Ref, top, kids, a.Cluster)
}

// holdShare holds an adopted shared folder for its conversion, as
// shares.HAHold does (that releases it).
func (r *Root) holdShare(ctx context.Context, top, conv string) error {
	if _, err := r.zfs(ctx, "set", "canmount=noauto", "readonly=on", propHAHold+"="+conv, top); err != nil {
		return err
	}
	if p, _ := r.props(ctx, top, "mounted"); p["mounted"] == "yes" {
		if _, err := r.zfs(ctx, "unmount", top); err != nil {
			return err
		}
	}
	return nil
}

// applyShare writes a moved shared folder's checked settings (nil: not a
// shared folder).
func (r *Root) applyShare(ctx context.Context, top string, set *shares.Settings) error {
	if set == nil {
		return nil
	}
	_, err := r.zfs(ctx, append(append([]string{"set"}, set.Props()...), top)...)
	return err
}

// shareChanged has the file services take up a shared folder's change.
func (r *Root) shareChanged(ctx context.Context, ref Ref) {
	if ref.Kind == KindShare && r.ShareChanged != nil {
		r.ShareChanged(context.WithoutCancel(ctx))
	}
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
	if ref.Kind == KindShare {
		// As shares.Manager makes a shared folder (POSIX ACLs kept with
		// the files, which the stream carries).
		return set(top, "canmount=on", "devices=off", "setuid=off", "acltype=posixacl", "xattr=sa", "aclinherit=passthrough")
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
		vol := []string{ref.ownerProp() + "=" + ref.ID}
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
		if k != AppBlockChild { // an app's block volume isn't one of its disks
			names = append(names, k)
		}
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
	// Conv marks the parked copy with the conversion that parked it, and
	// makes parking idempotent: when the workload's datasets are gone and
	// a copy this conversion parked is there, that copy is the answer (a
	// conversion resumed after root's answer was lost).
	Conv string `json:"conv,omitempty"`
	// Since is a snapshot the datasets are compared with: ParkResult
	// says whether anything was written after it (a missing snapshot
	// counts as written), and RefuseChanged refuses to park then.
	Since         string `json:"since,omitempty"`
	RefuseChanged bool   `json:"refuseChanged,omitempty"`
	// Expect parks only a copy carrying this conversion mark (what that
	// conversion adopted): a copy a conversion puts aside or lost track of
	// is always its own, never another server's conversion's.
	Expect string `json:"expect,omitempty"`
}

// PropKeepUntil is a parked copy's expiry (unix seconds; unset: kept).
const PropKeepUntil = "org.hardyos:ha-keep-until"

// PropParkedConv is the conversion that parked a copy.
const PropParkedConv = "org.hardyos:ha-conv"

// MinKeep is the shortest expiry ha.parked.keep sets: a kept copy is
// never made to expire sooner than this from now.
const MinKeep = time.Hour

// ErrChanged: the datasets were written since the snapshot they were
// compared with.
var ErrChanged = errors.New("it changed after the conversion's final snapshot")

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
	if a.KeepUntil > 0 {
		// Never sooner than an hour from now, nor sooner than it was set
		// to expire already: an expiry is only ever pushed back.
		if a.KeepUntil < r.now().Add(MinKeep).Unix() {
			return invalid("a kept copy's expiry is at least %s from now", MinKeep)
		}
		if cur, err := strconv.ParseInt(r.localProp(ctx, ds, PropKeepUntil), 10, 64); err == nil && cur > 0 && a.KeepUntil < cur {
			return invalid("a kept copy's expiry isn't brought forward")
		}
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
	// Changed: something was written after ParkArgs.Since.
	Changed bool `json:"changed,omitempty"`
	// Existing: the conversion had parked it already.
	Existing bool `json:"existing,omitempty"`
}

// ErrBusy: the storage is still in use.
var ErrBusy = errors.New("the workload's storage is still in use")

// ParkedBy finds the copy of ref that conversion conv parked, when ref's
// own datasets are gone (ok false otherwise, or when there is none).
func (r *Root) ParkedBy(ctx context.Context, ref Ref, conv string) (*ParkResult, bool) {
	if conv == "" || !convRE.MatchString(conv) || ref.Validate() != nil {
		return nil, false
	}
	if _, there := r.exists(ctx, ref.Dataset()); there {
		return nil, false
	}
	dir := ref.Pool + "/" + ParkedDir
	if _, ok := r.exists(ctx, dir); !ok {
		return nil, false
	}
	o, err := r.zfs(ctx, "list", "-H", "-p", "-d", "1", "-t", "filesystem", "-o", "name,"+PropParked+","+PropParkedConv, dir)
	if err != nil {
		return nil, false
	}
	for _, line := range strings.Split(strings.TrimSpace(string(o)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 || f[0] == dir || f[1] != ref.parkedValue() || f[2] != conv {
			continue
		}
		name := strings.TrimPrefix(f[0], dir+"/")
		if parkedRE.MatchString(name) {
			return &ParkResult{Pool: ref.Pool, Name: name, Existing: true}, true
		}
	}
	return nil, false
}

// MetadataSlack is what a VM's state folder may have written after a
// snapshot without counting as changed: access times (pools with atime or
// relatime on) when vm.json and the firmware files are only read, as
// letting go of the VM does (its definition is removed, its files read).
// Nothing in that folder is the guest's data: a guest that ran writes its
// disks, and disks (zvols) get no slack. An app's folder is its data: it
// gets none either, and is kept read-only from its final snapshot until it
// is parked (apps.HAHold), so nothing writes there, access times included.
const MetadataSlack = 128 << 10

// writtenSince says whether any of the datasets was written after their
// snapshot since (one without it counts as written).
func (r *Root) writtenSince(ctx context.Context, kind cluster.WorkloadKind, all []string, since string) bool {
	for _, ds := range all {
		p, err := r.props(ctx, ds, "written@"+since, "type")
		if err != nil {
			return true
		}
		n, err := strconv.ParseInt(p["written@"+since], 10, 64)
		if err != nil {
			return true
		}
		slack := int64(0)
		if kind == cluster.KindVM && p["type"] == "filesystem" {
			slack = MetadataSlack
		}
		if n > slack {
			return true
		}
	}
	return false
}

// Park moves a workload's datasets out of the way: they are no longer a
// VM, an app or cluster storage, and are kept until destroyed. The caller
// (the VM or app engine) has stopped it and dropped its definition. On a
// failure after the move, everything is put back where it was.
func (r *Root) Park(ctx context.Context, a ParkArgs) (*ParkResult, error) {
	if a.Confirm != a.ID {
		return nil, invalid("type the name to confirm")
	}
	if a.Conv != "" && !convRE.MatchString(a.Conv) {
		return nil, invalid("bad conversion id")
	}
	if a.Since != "" && !ownSnap.MatchString(a.Since) {
		return nil, invalid("bad snapshot name")
	}
	if a.KeepUntil < 0 {
		return nil, invalid("bad expiry")
	}
	if pr, ok := r.ParkedBy(ctx, a.Ref, a.Conv); ok {
		return pr, nil
	}
	if a.Expect != "" && (!convRE.MatchString(a.Expect) || r.localProp(ctx, a.Dataset(), PropParkedConv) != a.Expect) {
		return nil, invalid("%s isn't what this conversion set up", a.Dataset())
	}
	kids, err := r.checkSource(ctx, a.Ref)
	if err != nil {
		return nil, err
	}
	if a.Kind == KindShare && a.Side == SideLocal && (a.Conv == "" || r.localProp(ctx, a.Dataset(), propHAHold) != a.Conv) {
		// This server's shared folder is put aside only while its own
		// conversion holds it (unmounted, read-only, out of file sharing).
		return nil, invalid("%s isn't held by this conversion", a.ID)
	}
	if a.Kind == KindShare && a.Side == SideCluster {
		// The storage server's own shared folder: only one a conversion
		// adopted (its mark), and only once no compute server mounts it.
		if a.Expect == "" {
			return nil, invalid("only a shared folder a conversion moved here is put aside")
		}
		if r.ShareBusy == nil {
			return nil, invalid("the storage server's state isn't known")
		}
		busy, err := r.ShareBusy(ctx, a.Pool, a.ID)
		if err != nil {
			return nil, err
		}
		if busy {
			return nil, fmt.Errorf("%w: %s is still used in the cluster", ErrBusy, a.ID)
		}
	} else if a.Side == SideCluster {
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
	top := a.Dataset()
	res := &ParkResult{Pool: a.Pool}
	if a.Since != "" {
		all := []string{top}
		for c := range kids {
			all = append(all, top+"/"+c)
		}
		slices.Sort(all)
		res.Changed = r.writtenSince(ctx, a.Kind, all, a.Since)
		if res.Changed && a.RefuseChanged {
			return nil, &ErrInvalid{fmt.Errorf("%w (%s); it wasn't put aside", ErrChanged, a.Since)}
		}
	}
	parent := a.Pool + "/" + ParkedDir
	if _, ok := r.exists(ctx, parent); !ok {
		if _, err := r.zfs(ctx, "create", "-o", "canmount=off", "-o", propRole+"="+RoleParked, parent); err != nil {
			return nil, err
		}
	}
	name := string(a.Kind) + "-" + a.ID + "-" + strconv.FormatInt(r.now().Unix(), 10)
	if a.Kind == KindShare && r.ShareRelease != nil {
		// SMB, NFS and SFTP let go of it, as before a delete, and take the
		// change up after.
		done := r.ShareRelease(ctx, a.ID)
		defer r.shareChanged(ctx, a.Ref)
		if done != nil {
			defer done()
		}
	}
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
	if err := r.parkMarks(ctx, a, dst, kids); err != nil {
		// Back where it was, as it was: the caller still has its workload.
		r.unpark(context.WithoutCancel(ctx), a.Ref, dst, top, kids)
		return nil, err
	}
	r.log().Warn("ha: parked", "from", top, "to", dst)
	res.Name = name
	return res, nil
}

// parkMarks marks a moved copy parked and takes its workload marks away.
func (r *Root) parkMarks(ctx context.Context, a ParkArgs, dst string, kids map[string]string) error {
	set := []string{"set", PropParked + "=" + a.parkedValue()}
	if a.Conv != "" {
		set = append(set, PropParkedConv+"="+a.Conv)
	}
	if a.KeepUntil > 0 {
		set = append(set, PropKeepUntil+"="+strconv.FormatInt(a.KeepUntil, 10))
	}
	if _, err := r.zfs(ctx, append(set, dst)...); err != nil {
		return err
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
					return err
				}
			}
		}
		if ds != dst {
			if _, err := r.zfs(ctx, "set", "volmode=none", ds); err != nil {
				r.log().Warn("ha: hiding a parked disk", "dataset", ds, "err", err)
			}
		}
	}
	return nil
}

// unpark puts a copy moved to src back at top with its workload's marks.
func (r *Root) unpark(ctx context.Context, ref Ref, src, top string, kids map[string]string) {
	if _, err := r.zfs(ctx, "rename", src, top); err != nil {
		r.log().Error("ha: putting a copy back after a failed park", "from", src, "to", top, "err", err)
		return
	}
	for _, p := range []string{PropParked, PropKeepUntil, PropParkedConv} {
		_, _ = r.zfs(ctx, "inherit", p, top)
	}
	if err := r.applyProps(ctx, ref, top, kids); err != nil {
		r.log().Error("ha: marking a copy put back after a failed park", "dataset", top, "err", err)
	}
	if err := r.mount(ctx, top); err != nil {
		r.log().Error("ha: mounting a copy put back after a failed park", "dataset", top, "err", err)
	}
	r.log().Warn("ha: park failed; put back", "dataset", top)
}

// UnparkArgs is ha.unpark.
type UnparkArgs struct {
	Ref
	Name string `json:"name"`
}

// UnparkResult says what putting a copy back found: a local app held by
// its conversion, and whether it ran before that (the hold's record).
type UnparkResult struct {
	Held       bool `json:"held,omitempty"`
	WasRunning bool `json:"wasRunning,omitempty"`
}

// Unpark puts a parked copy back as the workload's storage.
func (r *Root) Unpark(ctx context.Context, a UnparkArgs) error {
	_, err := r.UnparkState(ctx, a)
	return err
}

// UnparkState is Unpark, reporting the hold it ended.
func (r *Root) UnparkState(ctx context.Context, a UnparkArgs) (*UnparkResult, error) {
	res := &UnparkResult{}
	if err := a.Ref.Validate(); err != nil {
		return nil, err
	}
	src, err := r.parked(ctx, a.Pool, a.Name, a.Ref)
	if err != nil {
		return nil, err
	}
	top := a.Dataset()
	if _, ok := r.exists(ctx, top); ok {
		return nil, invalid("%s exists; it can't be put back over it", top)
	}
	if _, ok := r.exists(ctx, a.parent()); !ok {
		return nil, invalid("%s doesn't exist", a.parent())
	}
	kids, err := r.children(ctx, a.Ref, src)
	if err != nil {
		return nil, err
	}
	if a.Side == SideLocal && a.Kind == cluster.KindApp {
		res.Held = r.localProp(ctx, src, propHAHold) != ""
		res.WasRunning = res.Held && r.localProp(ctx, src, propHAHoldRunning) == "on"
	}
	if _, err := r.zfs(ctx, "rename", src, top); err != nil {
		return nil, err
	}
	props := []string{PropParked, PropKeepUntil, PropParkedConv}
	if a.Side == SideLocal {
		// A local app's or shared folder's hold (apps.HAHold,
		// shares.HAHold) ends with its copy put back.
		props = append(props, "readonly", propHAHold, propHAHoldRunning)
	}
	for _, p := range props {
		if _, err := r.zfs(ctx, "inherit", p, top); err != nil {
			return nil, err
		}
	}
	if err := r.applyProps(ctx, a.Ref, top, kids); err != nil {
		return nil, err
	}
	r.log().Warn("ha: put back", "from", src, "to", top)
	if err := r.mount(ctx, top); err != nil {
		return nil, err
	}
	r.shareChanged(ctx, a.Ref)
	return res, nil
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
	// Conv is the conversion that parked it.
	Conv string `json:"conv,omitempty"`
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
		o, err := r.zfs(ctx, "list", "-H", "-p", "-d", "1", "-t", "filesystem", "-o", "name,"+PropParked+",used,creation,"+PropKeepUntil+","+PropParkedConv, dir)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(o)), "\n") {
			f := strings.Split(line, "\t")
			if len(f) != 6 || f[0] == dir {
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
			if convRE.MatchString(f[5]) {
				p.Conv = f[5]
			}
			l = append(l, p)
		}
	}
	return l, nil
}

// ParkedDestroyArgs is ha.parked.destroy: Confirm is the workload's id;
// LastCopy confirms deleting a copy that has no expiry.
type ParkedDestroyArgs struct {
	Pool     string `json:"pool"`
	Name     string `json:"name"`
	Confirm  string `json:"confirm"`
	LastCopy bool   `json:"lastCopy,omitempty"`
}

// ErrLastCopy: a copy without an expiry is deleted only when confirmed as
// possibly the last one.
var ErrLastCopy = errors.New("this kept copy has no expiry: its workload hasn't run from its other copy, so this may be its only good copy; confirm deleting the last copy to delete it")

// ParkedDestroy destroys a parked copy with its snapshots. A copy gets
// its expiry only once its workload ran from its other copy; one without
// is deleted only with LastCopy.
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
	if r.localProp(ctx, ds, PropKeepUntil) == "" && !a.LastCopy {
		return &ErrInvalid{ErrLastCopy}
	}
	if _, err := r.zfs(ctx, "destroy", "-r", ds); err != nil {
		return err
	}
	r.log().Warn("ha: parked copy destroyed", "dataset", ds)
	return nil
}
