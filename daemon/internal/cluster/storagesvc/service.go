package storagesvc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/cluster/sanclient"
	"github.com/hardyos/hardyos/daemon/internal/network"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// Priv is the part of priv.Client the service uses.
type Priv interface {
	Call(ctx context.Context, op string, args, out any) error
}

// Auditor records what the storage node did for whom (the person and the
// node they used): hardyd's audit log.
type Auditor func(ctx context.Context, actor cluster.Actor, action, target string, err error)

// Service is cluster storage on this node: StorageService (forwarded to
// the storage node when this isn't it), StorageAttacher (compute nodes)
// and the storage node's Agent.
type Service struct {
	// M is the cluster membership (part A); nil outside a cluster.
	M     cluster.Membership
	Peers cluster.PeerClient
	Priv  Priv
	Store *Store
	Audit Auditor
	Log   *slog.Logger
	// Network reads this server's network status (interfaces, addresses).
	Network func(ctx context.Context) (*network.Status, error)

	holdMu sync.Mutex
	holds  map[cluster.WorkloadRef]bool
	// reconcile runs the storage agent's pass now (set by NewAgent).
	reconcile func(ctx context.Context) error
}

// hold takes a workload's storage offline on the storage node (unmapped,
// unexported) until the returned release is called; both reconcile.
func (s *Service) hold(ctx context.Context, w cluster.WorkloadRef) (func(), error) {
	s.holdMu.Lock()
	if s.holds == nil {
		s.holds = map[cluster.WorkloadRef]bool{}
	}
	if s.holds[w] {
		s.holdMu.Unlock()
		return nil, fmt.Errorf("%s %s's storage is already being worked on", w.Kind, w.ID)
	}
	s.holds[w] = true
	s.holdMu.Unlock()
	release := func() {
		s.holdMu.Lock()
		delete(s.holds, w)
		s.holdMu.Unlock()
		if s.reconcile != nil {
			if err := s.reconcile(context.WithoutCancel(ctx)); err != nil {
				s.log().Warn("storage: reconciling after an offline change", "err", err)
			}
		}
	}
	if s.reconcile != nil {
		if err := s.reconcile(ctx); err != nil {
			release()
			return nil, fmt.Errorf("taking %s's storage offline: %w", w.ID, err)
		}
	}
	return release, nil
}

func (s *Service) held() []cluster.WorkloadRef {
	s.holdMu.Lock()
	defer s.holdMu.Unlock()
	out := make([]cluster.WorkloadRef, 0, len(s.holds))
	for w := range s.holds {
		out = append(out, w)
	}
	return out
}

// detachOnOwner asks a stopped workload's owner to detach its storage
// before the storage node works on it offline.
func (s *Service) detachOnOwner(ctx context.Context, p *cluster.Placement) error {
	if p.Owner == "" {
		return nil
	}
	if s.Peers == nil {
		return cluster.ErrStorageUnavailable
	}
	return s.Peers.Call(ctx, p.Owner, "POST", "storage/detach", detachReq{Workload: p.Workload}, nil)
}

type detachReq struct {
	Workload cluster.WorkloadRef `json:"workload"`
}

var (
	_ cluster.StorageService  = (*Service)(nil)
	_ cluster.StorageAttacher = (*Service)(nil)
	_ cluster.StorageFencer   = (*Service)(nil)
	_ cluster.Freezer         = (*Service)(nil)
)

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) audit(ctx context.Context, a cluster.Actor, action, target string, err error) {
	if s.Audit != nil {
		s.Audit(ctx, a, action, target, err)
	}
}

// ErrNoStorageNode: the cluster has no storage node.
var ErrNoStorageNode = errors.New("the cluster has no storage server")

// self returns this node and the state, or ErrNotMember.
func (s *Service) self() (cluster.Node, *cluster.Snapshot, error) {
	if s.M == nil {
		return cluster.Node{}, nil, cluster.ErrNotMember
	}
	me, err := s.M.Self()
	if err != nil {
		return cluster.Node{}, nil, err
	}
	return me, s.M.State().Snapshot(), nil
}

// StorageNode finds the storage node in a state.
func StorageNode(snap *cluster.Snapshot) (*cluster.Node, bool) {
	for _, n := range snap.Nodes {
		if n.Role == cluster.RoleStorage && n.State != cluster.NodeRemoved {
			return n, true
		}
	}
	return nil, false
}

// onStorage runs local when this node is the storage node, else remote
// (the same request on the storage node's peer API).
func (s *Service) onStorage(ctx context.Context, path string, in, out any, local func(snap *cluster.Snapshot, self cluster.Node) error) error {
	me, snap, err := s.self()
	if err != nil {
		return err
	}
	if me.Role == cluster.RoleStorage {
		return local(snap, me)
	}
	sn, ok := StorageNode(snap)
	if !ok {
		return ErrNoStorageNode
	}
	if s.Peers == nil {
		return cluster.ErrStorageUnavailable
	}
	return s.Peers.Call(ctx, sn.ID, "POST", path, in, out)
}

var (
	idRE   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)
	poolRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.:-]{0,63}$`)
)

// ---- StorageService ------------------------------------------------------------

type provisionVMReq struct {
	Request cluster.VMStorageRequest `json:"request"`
	Actor   cluster.Actor            `json:"actor"`
}

// ProvisionVM implements cluster.StorageService.
func (s *Service) ProvisionVM(ctx context.Context, r cluster.VMStorageRequest, actor cluster.Actor) (*cluster.WorkloadStorage, error) {
	var out cluster.WorkloadStorage
	err := s.onStorage(ctx, "storage/provision/vm", provisionVMReq{r, actor}, &out, func(snap *cluster.Snapshot, _ cluster.Node) error {
		ws, err := s.provisionVM(ctx, snap.Cluster, r)
		s.audit(ctx, actor, "cluster.storage.provision", "vm "+r.VM, err)
		if err == nil {
			out = *ws
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Service) provisionVM(ctx context.Context, c cluster.ClusterID, r cluster.VMStorageRequest) (*cluster.WorkloadStorage, error) {
	if !idRE.MatchString(r.VM) || !poolRE.MatchString(r.Pool) {
		return nil, fmt.Errorf("VM %q on pool %q isn't valid", r.VM, r.Pool)
	}
	if len(r.Disks) == 0 || len(r.Disks) > 10 {
		return nil, errors.New("a VM has 1 to 10 disks")
	}
	w := san.WorkloadArgs{Kind: cluster.KindVM, ID: r.VM, Pool: r.Pool}
	var info san.DatasetInfo
	if err := s.Priv.Call(ctx, san.OpDatasetCreate, san.DatasetCreateArgs{WorkloadArgs: w}, &info); err != nil {
		return nil, err
	}
	ws := &cluster.WorkloadStorage{Pool: r.Pool, Exports: []cluster.Export{{
		Kind: cluster.ExportVMState, Dataset: info.Dataset, Path: info.Mountpoint,
		MountPath: cluster.RemoteMountRoot + "/" + info.Dataset, FSID: info.GUID,
	}}}
	for _, d := range r.Disks {
		var v san.VolumeInfo
		err := s.Priv.Call(ctx, san.OpVolumeCreate, priv.VolumeCreateArgs{Cluster: c, VolumeArgs: san.VolumeArgs{WorkloadArgs: w, Disk: d.Name, SizeGB: d.SizeGB}}, &v)
		if err != nil {
			_ = s.Priv.Call(context.WithoutCancel(ctx), san.OpDatasetDestroy, san.DestroyArgs{WorkloadArgs: w, Confirm: r.VM}, nil)
			return nil, err
		}
		ws.Volumes = append(ws.Volumes, cluster.Volume{Dataset: v.Dataset, Disk: d.Name, SizeGB: v.SizeGB, WWN: v.WWN})
	}
	return ws, nil
}

type provisionAppReq struct {
	Request cluster.AppStorageRequest `json:"request"`
	Actor   cluster.Actor             `json:"actor"`
}

// ProvisionApp implements cluster.StorageService.
func (s *Service) ProvisionApp(ctx context.Context, r cluster.AppStorageRequest, actor cluster.Actor) (*cluster.WorkloadStorage, error) {
	var out cluster.WorkloadStorage
	err := s.onStorage(ctx, "storage/provision/app", provisionAppReq{r, actor}, &out, func(snap *cluster.Snapshot, _ cluster.Node) error {
		if u, ok := snap.AppUIDs[r.App]; !ok || u != r.UID {
			return fmt.Errorf("app %s's user id %d isn't the one the cluster gave it", r.App, r.UID)
		}
		ws, err := s.provisionApp(ctx, snap.Cluster, r)
		s.audit(ctx, actor, "cluster.storage.provision", "app "+r.App, err)
		if err == nil {
			out = *ws
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Service) provisionApp(ctx context.Context, c cluster.ClusterID, r cluster.AppStorageRequest) (*cluster.WorkloadStorage, error) {
	if !idRE.MatchString(r.App) || !poolRE.MatchString(r.Pool) {
		return nil, fmt.Errorf("app %q on pool %q isn't valid", r.App, r.Pool)
	}
	w := san.WorkloadArgs{Kind: cluster.KindApp, ID: r.App, Pool: r.Pool}
	var info san.DatasetInfo
	if err := s.Priv.Call(ctx, san.OpDatasetCreate, san.DatasetCreateArgs{WorkloadArgs: w, UID: r.UID}, &info); err != nil {
		return nil, err
	}
	ws := &cluster.WorkloadStorage{Pool: r.Pool}
	switch r.Mode {
	case "", cluster.StorageNFS:
		ws.Mode = cluster.StorageNFS
		ws.Exports = []cluster.Export{{Kind: cluster.ExportAppData, Dataset: info.Dataset, Path: info.Mountpoint,
			MountPath: cluster.RemoteMountRoot + "/" + info.Dataset, FSID: info.GUID}}
	case cluster.StorageBlock:
		size := r.BlockSizeGB
		if size == 0 {
			size = DefaultBlockGB
		}
		var v san.VolumeInfo
		err := s.Priv.Call(ctx, san.OpVolumeCreate, priv.VolumeCreateArgs{Cluster: c, VolumeArgs: san.VolumeArgs{
			WorkloadArgs: w, Disk: "block", SizeGB: size, FS: r.BlockFS}}, &v)
		if err != nil {
			_ = s.Priv.Call(context.WithoutCancel(ctx), san.OpDatasetDestroy, san.DestroyArgs{WorkloadArgs: w, Confirm: r.App}, nil)
			return nil, err
		}
		ws.Mode, ws.BlockFS = cluster.StorageBlock, r.BlockFS
		ws.Volumes = []cluster.Volume{{Dataset: v.Dataset, Disk: "block", SizeGB: v.SizeGB, WWN: v.WWN}}
	default:
		return nil, fmt.Errorf("data mode %q isn't nfs or block", r.Mode)
	}
	return ws, nil
}

// DefaultBlockGB is a new block volume's size when none is asked for
// (sparse: only what is written uses space).
const DefaultBlockGB = 64

type resizeReq struct {
	Workload cluster.WorkloadRef `json:"workload"`
	Disk     string              `json:"disk"`
	SizeGB   int                 `json:"sizeGB"`
	Actor    cluster.Actor       `json:"actor"`
}

func placementOf(snap *cluster.Snapshot, w cluster.WorkloadRef) (*cluster.Placement, error) {
	p := snap.Placements[w]
	if p == nil {
		return nil, fmt.Errorf("%s %s isn't a cluster workload", w.Kind, w.ID)
	}
	return p, nil
}

// ResizeDisk implements cluster.StorageService.
func (s *Service) ResizeDisk(ctx context.Context, w cluster.WorkloadRef, disk string, sizeGB int, actor cluster.Actor) error {
	return s.onStorage(ctx, "storage/resize", resizeReq{w, disk, sizeGB, actor}, nil, func(snap *cluster.Snapshot, _ cluster.Node) error {
		p, err := placementOf(snap, w)
		if err != nil {
			return err
		}
		err = s.Priv.Call(ctx, san.OpVolumeResize, priv.VolumeCreateArgs{Cluster: snap.Cluster, VolumeArgs: san.VolumeArgs{
			WorkloadArgs: san.WorkloadArgs{Kind: w.Kind, ID: w.ID, Pool: p.Storage.Pool}, Disk: disk, SizeGB: sizeGB}}, nil)
		s.audit(ctx, actor, "cluster.storage.resize", fmt.Sprintf("%s %s %s %d GB", w.Kind, w.ID, disk, sizeGB), err)
		return err
	})
}

type destroyReq struct {
	Workload cluster.WorkloadRef `json:"workload"`
	Pool     string              `json:"pool,omitempty"`
	Confirm  string              `json:"confirm"`
	Actor    cluster.Actor       `json:"actor"`
}

// Destroy implements cluster.StorageService: the workload must be gone
// from the cluster state (or have no grant holder) first.
func (s *Service) Destroy(ctx context.Context, w cluster.WorkloadRef, confirm string, actor cluster.Actor) error {
	return s.onStorage(ctx, "storage/destroy", destroyReq{Workload: w, Confirm: confirm, Actor: actor}, nil, func(snap *cluster.Snapshot, _ cluster.Node) error {
		if confirm != w.ID {
			return errors.New("type the name to destroy its storage")
		}
		pool := ""
		if p := snap.Placements[w]; p != nil {
			if g := snap.Grants[w]; g != nil && len(g.Nodes) > 0 {
				return fmt.Errorf("%s is still granted to %v; remove it from the cluster first", w.ID, g.Nodes)
			}
			pool = p.Storage.Pool
		}
		if pool == "" {
			return fmt.Errorf("%s %s isn't a cluster workload any more; its storage is destroyed with the workload", w.Kind, w.ID)
		}
		err := s.Priv.Call(ctx, san.OpDatasetDestroy, san.DestroyArgs{WorkloadArgs: san.WorkloadArgs{Kind: w.Kind, ID: w.ID, Pool: pool}, Confirm: confirm}, nil)
		s.audit(ctx, actor, "cluster.storage.destroy", string(w.Kind)+" "+w.ID, err)
		return err
	})
}

type snapReq struct {
	Workload cluster.WorkloadRef `json:"workload"`
	Name     string              `json:"name,omitempty"`
	Confirm  string              `json:"confirm,omitempty"`
	Actor    cluster.Actor       `json:"actor"`
}

func (s *Service) snapArgs(snap *cluster.Snapshot, w cluster.WorkloadRef, name, confirm string) (san.SnapshotArgs, error) {
	p, err := placementOf(snap, w)
	if err != nil {
		return san.SnapshotArgs{}, err
	}
	return san.SnapshotArgs{WorkloadArgs: san.WorkloadArgs{Kind: w.Kind, ID: w.ID, Pool: p.Storage.Pool}, Name: name, Confirm: confirm}, nil
}

// Snapshots implements cluster.StorageService.
func (s *Service) Snapshots(ctx context.Context, w cluster.WorkloadRef) ([]cluster.SnapshotInfo, error) {
	out := []cluster.SnapshotInfo{}
	err := s.onStorage(ctx, "storage/snapshots", snapReq{Workload: w}, &out, func(snap *cluster.Snapshot, _ cluster.Node) error {
		a, err := s.snapArgs(snap, w, "", "")
		if err != nil {
			return err
		}
		var l []san.SnapshotInfo
		if err := s.Priv.Call(ctx, san.OpSnapshotList, a, &l); err != nil {
			return err
		}
		for _, x := range l {
			out = append(out, cluster.SnapshotInfo{Name: x.Name, Created: x.Created, Used: x.Used})
		}
		return nil
	})
	return out, err
}

// Snapshot implements cluster.StorageService: a running VM is frozen by
// its owner's guest agent around the snapshot, a running app's backup dump
// runs on its owner first.
func (s *Service) Snapshot(ctx context.Context, w cluster.WorkloadRef, name string, actor cluster.Actor) (*cluster.SnapshotInfo, error) {
	var out cluster.SnapshotInfo
	err := s.onStorage(ctx, "storage/snapshot", snapReq{Workload: w, Name: name, Actor: actor}, &out, func(snap *cluster.Snapshot, _ cluster.Node) error {
		a, err := s.snapArgs(snap, w, name, "")
		if err != nil {
			return err
		}
		take := func(ctx context.Context) error {
			var si san.SnapshotInfo
			if err := s.Priv.Call(ctx, san.OpSnapshotCreate, a, &si); err != nil {
				return err
			}
			out = cluster.SnapshotInfo{Name: si.Name, Created: si.Created, Used: si.Used, Reason: "manual"}
			return nil
		}
		switch w.Kind {
		case cluster.KindVM:
			_, err = s.Frozen(ctx, w.ID, take)
		default:
			if derr := s.dumpOnOwner(ctx, snap, w.ID); derr != nil {
				s.log().Warn("storage: the app's backup dump didn't run; the snapshot is crash-consistent", "app", w.ID, "err", derr)
			}
			err = take(ctx)
		}
		s.audit(ctx, actor, "cluster.storage.snapshot", string(w.Kind)+" "+w.ID+"@"+name, err)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func stopped(p *cluster.Placement) bool {
	return p.State == cluster.PlacementStopped && p.Requested == cluster.RequestStopped
}

// Rollback implements cluster.StorageService (the workload must be
// stopped).
func (s *Service) Rollback(ctx context.Context, w cluster.WorkloadRef, snapshot, confirm string, actor cluster.Actor) error {
	return s.onStorage(ctx, "storage/rollback", snapReq{Workload: w, Name: snapshot, Confirm: confirm, Actor: actor}, nil, func(snap *cluster.Snapshot, _ cluster.Node) error {
		p, err := placementOf(snap, w)
		if err != nil {
			return err
		}
		if !stopped(p) {
			return fmt.Errorf("stop %s first", w.ID)
		}
		a, err := s.snapArgs(snap, w, snapshot, confirm)
		if err != nil {
			return err
		}
		if a.Confirm != a.Name {
			return errors.New("type the snapshot's name to roll back to it")
		}
		// The owner lets go first, then nothing of it is mapped or
		// exported while ZFS rolls back under it.
		if err := s.detachOnOwner(ctx, p); err != nil {
			return fmt.Errorf("asking %s to let go of %s: %w", p.Owner, w.ID, err)
		}
		release, err := s.hold(ctx, w)
		if err != nil {
			return err
		}
		defer release()
		err = s.Priv.Call(ctx, san.OpSnapshotRoll, a, nil)
		s.audit(ctx, actor, "cluster.storage.rollback", string(w.Kind)+" "+w.ID+"@"+snapshot, err)
		return err
	})
}

// DeleteSnapshot implements cluster.StorageService.
func (s *Service) DeleteSnapshot(ctx context.Context, w cluster.WorkloadRef, snapshot, confirm string, actor cluster.Actor) error {
	return s.onStorage(ctx, "storage/snapshot/delete", snapReq{Workload: w, Name: snapshot, Confirm: confirm, Actor: actor}, nil, func(snap *cluster.Snapshot, _ cluster.Node) error {
		a, err := s.snapArgs(snap, w, snapshot, confirm)
		if err != nil {
			return err
		}
		err = s.Priv.Call(ctx, san.OpSnapshotDelete, a, nil)
		s.audit(ctx, actor, "cluster.storage.snapshot.delete", string(w.Kind)+" "+w.ID+"@"+snapshot, err)
		return err
	})
}

// Health implements cluster.StorageService.
func (s *Service) Health(ctx context.Context) (*cluster.StorageHealth, error) {
	var out cluster.StorageHealth
	err := s.onStorage(ctx, "storage/health", struct{}{}, &out, func(snap *cluster.Snapshot, me cluster.Node) error {
		var st san.Status
		out = cluster.StorageHealth{Node: me.ID, Reachable: true, Sessions: map[cluster.NodeID]int{}}
		if err := s.Priv.Call(ctx, san.OpStatus, nil, &st); err != nil {
			out.Problem = err.Error()
			return nil
		}
		out.Sessions = st.Sessions
		for n := range st.Fences {
			out.Fenced = append(out.Fenced, n)
		}
		slices.Sort(out.Fenced)
		out.Problem = st.Problem
		if !st.Loaded {
			out.Problem = "the iSCSI target (LIO) isn't loaded"
		}
		for _, b := range st.Desired.Backstores {
			out.Pool = b.Pool()
			break
		}
		return nil
	})
	if err != nil {
		var pe *cluster.PeerError
		if errors.As(err, &pe) || errors.Is(err, cluster.ErrStorageUnavailable) {
			return &cluster.StorageHealth{Reachable: false, Problem: err.Error()}, nil
		}
		return nil, err
	}
	return &out, nil
}

// ---- StorageFencer (storage node) ----------------------------------------------

// FenceNode implements cluster.StorageFencer on the storage node.
func (s *Service) FenceNode(ctx context.Context, node cluster.NodeID, epoch uint64) error {
	var res san.FenceResult
	return s.Priv.Call(ctx, san.OpFence, san.FenceArgs{Node: node, Epoch: epoch, Confirm: string(node)}, &res)
}

// UnfenceNode implements cluster.StorageFencer on the storage node.
func (s *Service) UnfenceNode(ctx context.Context, node cluster.NodeID, epoch uint64) error {
	return s.Priv.Call(ctx, san.OpUnfence, san.UnfenceArgs{Node: node, Epoch: epoch}, nil)
}

// ---- local storage network -----------------------------------------------------

// StorageInterface returns this server's storage interface and address:
// the saved plan's interface, else whichever interface holds an address in
// the cluster's storage subnet.
func (s *Service) StorageInterface(ctx context.Context, subnet netip.Prefix) (string, netip.Addr, error) {
	if s.Network == nil {
		return "", netip.Addr{}, errors.New("the network status isn't available")
	}
	st, err := s.Network(ctx)
	if err != nil {
		return "", netip.Addr{}, err
	}
	if s.Store != nil {
		if p, err := s.Store.StorageNet(ctx); err == nil && p != nil {
			if pre, err := netip.ParsePrefix(p.Address); err == nil {
				return p.StorageInterface(), pre.Addr(), nil
			}
		}
	}
	if !subnet.IsValid() {
		return "", netip.Addr{}, errors.New("the cluster has no storage network yet")
	}
	a, iface, ok := network.StorageAddress(*st, subnet)
	if !ok {
		return "", netip.Addr{}, fmt.Errorf("this server has no address on the storage network %s", subnet)
	}
	return iface, a, nil
}

// NodeStatus is one node's storage status (the Cluster app's per-node view).
type NodeStatus struct {
	Node      cluster.NodeID    `json:"node"`
	Role      cluster.Role      `json:"role"`
	Reachable bool              `json:"reachable"`
	Healthy   bool              `json:"healthy"`
	Problem   string            `json:"problem,omitempty"`
	Sessions  int               `json:"sessions"`
	Attached  []sanclient.Record `json:"attached"`
	Shares    map[string]string `json:"shares"`
	Interface string            `json:"interface,omitempty"`
	Address   string            `json:"address,omitempty"`
	Checked   time.Time         `json:"checked"`
}

// LocalStatus reports this compute node's storage client.
func (s *Service) LocalStatus(ctx context.Context) (*NodeStatus, error) {
	out := &NodeStatus{Reachable: true, Attached: []sanclient.Record{}, Shares: map[string]string{}, Checked: time.Now().UTC()}
	if me, snap, err := s.self(); err == nil {
		out.Node, out.Role = me.ID, me.Role
		if iface, a, err := s.StorageInterface(ctx, snap.StorageSubnet); err == nil {
			out.Interface, out.Address = iface, a.String()
		}
		if me.Role == cluster.RoleStorage {
			h, err := s.Health(ctx)
			if err != nil {
				return nil, err
			}
			out.Healthy = h.Problem == ""
			out.Problem = h.Problem
			for _, n := range h.Sessions {
				out.Sessions += n
			}
			return out, nil
		}
	}
	var st sanclient.Status
	if err := s.Priv.Call(ctx, sanclient.OpStatus, nil, &st); err != nil {
		return nil, err
	}
	out.Healthy, out.Problem, out.Sessions = st.Healthy, st.Problem, len(st.Sessions)
	out.Attached, out.Shares = st.Attached, st.Shares
	return out, nil
}
