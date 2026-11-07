package storagesvc

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/cluster/sanclient"
)

// CheckGrant is the attach rule (decision 326): the applied state's grant
// for the workload names this node, at the caller's generation, and the
// storage node has acknowledged it; this node isn't fenced.
func CheckGrant(snap *cluster.Snapshot, self cluster.NodeID, g cluster.Grant) error {
	n := snap.Nodes[self]
	if n == nil {
		return cluster.ErrNotMember
	}
	if _, fenced := snap.Fences[self]; fenced || n.State == cluster.NodeFenced || n.State == cluster.NodeDead || n.State == cluster.NodeRejoining {
		return cluster.ErrFenced
	}
	cur := snap.Grants[g.Workload]
	if cur == nil || !slices.Contains(cur.Nodes, self) {
		return fmt.Errorf("%w: %s %s isn't granted to this server", cluster.ErrStorageUnavailable, g.Workload.Kind, g.Workload.ID)
	}
	if cur.Generation != g.Generation {
		return cluster.ErrStaleGeneration
	}
	if !cur.Applied {
		return fmt.Errorf("%w: the storage server hasn't applied the grant yet", cluster.ErrStorageUnavailable)
	}
	return nil
}

// storagePath is where this node reaches the storage node.
type storagePath struct {
	cluster   cluster.ClusterID
	self      cluster.NodeID
	server    netip.Addr
	portals   []netip.AddrPort
	iface     string
	multipath bool
}

func (s *Service) path(ctx context.Context, snap *cluster.Snapshot, me cluster.Node) (*storagePath, error) {
	sn, ok := StorageNode(snap)
	if !ok {
		return nil, ErrNoStorageNode
	}
	if !sn.Addresses.Storage.IsValid() {
		return nil, errors.New("the storage server has no storage network address")
	}
	iface, _, err := s.StorageInterface(ctx, snap.StorageSubnet)
	if err != nil {
		return nil, err
	}
	p := &storagePath{cluster: snap.Cluster, self: me.ID, server: sn.Addresses.Storage, iface: iface, portals: sn.Addresses.Portals}
	if len(p.portals) == 0 {
		p.portals = []netip.AddrPort{netip.AddrPortFrom(sn.Addresses.Storage, san.ISCSIPort)}
	}
	p.multipath = len(p.portals) > 1
	return p, nil
}

// ensureLogin logs this node in to its target, fetching its CHAP secrets
// from the storage node the first time (and again once if the login is
// refused, after a rotation).
func (s *Service) ensureLogin(ctx context.Context, p *storagePath) error {
	sa := sanclient.SessionArgs{Cluster: p.cluster, Node: p.self}
	for attempt := 0; attempt < 2; attempt++ {
		sec, err := s.chap(ctx, p.self, attempt > 0)
		if err != nil {
			return err
		}
		err = s.Priv.Call(ctx, sanclient.OpLogin, sanclient.LoginArgs{SessionArgs: sa, Portals: p.portals, Interface: p.iface, CHAP: *sec}, nil)
		if err == nil {
			return nil
		}
		if attempt == 1 {
			return err
		}
		s.log().Info("storage: login refused; fetching the CHAP secrets again", "err", err)
	}
	return nil
}

func (s *Service) chap(ctx context.Context, self cluster.NodeID, refresh bool) (*san.Secrets, error) {
	if s.Store != nil && !refresh {
		if sec, err := s.Store.CHAP(ctx, self); err == nil && sec != nil {
			return sec, nil
		}
	}
	_, snap, err := s.self()
	if err != nil {
		return nil, err
	}
	sn, ok := StorageNode(snap)
	if !ok {
		return nil, ErrNoStorageNode
	}
	if s.Peers == nil {
		return nil, cluster.ErrStorageUnavailable
	}
	var sec san.Secrets
	if err := s.Peers.Call(ctx, sn.ID, "POST", "storage/chap", struct{}{}, &sec); err != nil {
		return nil, fmt.Errorf("getting this server's CHAP secrets from the storage server: %w", err)
	}
	if err := sec.Validate(); err != nil {
		return nil, err
	}
	if s.Store != nil {
		if err := s.Store.SaveCHAP(ctx, self, sec); err != nil {
			return nil, err
		}
	}
	return &sec, nil
}

// Attach implements cluster.StorageAttacher.
func (s *Service) Attach(ctx context.Context, ws cluster.WorkloadStorage, g cluster.Grant) (*cluster.Attachment, error) {
	me, snap, err := s.self()
	if err != nil {
		return nil, err
	}
	if me.Role != cluster.RoleCompute {
		return nil, errors.New("only compute servers attach cluster storage")
	}
	if err := CheckGrant(snap, me.ID, g); err != nil {
		return nil, err
	}
	p := snap.Placements[g.Workload]
	if p == nil {
		return nil, fmt.Errorf("%w: %s isn't placed", cluster.ErrNotOwner, g.Workload.ID)
	}
	// What is attached is the committed storage, never the caller's copy.
	ws = p.Storage
	path, err := s.path(ctx, snap, me)
	if err != nil {
		return nil, err
	}
	if len(ws.Volumes) > 0 {
		if err := s.ensureLogin(ctx, path); err != nil {
			return nil, err
		}
		if err := s.Priv.Call(ctx, sanclient.OpRescan, sanclient.SessionArgs{Cluster: path.cluster, Node: path.self}, nil); err != nil {
			return nil, err
		}
		if path.multipath {
			if err := s.syncMultipath(ctx, snap, me.ID); err != nil {
				return nil, err
			}
		}
	}
	// Who wrote a block volume before (its file system is checked before
	// it is mounted when it wasn't only this node; H5). Unknown when the
	// storage node can't say: root checks it then.
	var writers VolumeWriters
	if ws.Mode == cluster.StorageBlock && s.Peers != nil {
		if sn, ok := StorageNode(snap); ok {
			if err := s.Peers.Call(ctx, sn.ID, "POST", "storage/writers", writersReq{Workload: g.Workload}, &writers); err != nil {
				s.log().Info("storage: the storage server didn't say who wrote the volume; it is checked", "workload", g.Workload.ID, "err", err)
				writers = nil
			}
		}
	}
	var rec sanclient.Record
	err = s.Priv.Call(ctx, sanclient.OpAttach, sanclient.AttachArgs{
		Workload: g.Workload, Generation: g.Generation, Storage: ws, Server: path.server, Interface: path.iface,
		Multipath: path.multipath, GrowFS: ws.Mode == cluster.StorageBlock, Writers: writers,
	}, &rec)
	if err != nil {
		return nil, err
	}
	return &rec.Attachment, nil
}

// syncMultipath allows the WWNs of everything granted to this node.
func (s *Service) syncMultipath(ctx context.Context, snap *cluster.Snapshot, self cluster.NodeID) error {
	var wwns []string
	for w, g := range snap.Grants {
		if !slices.Contains(g.Nodes, self) {
			continue
		}
		if p := snap.Placements[w]; p != nil {
			for _, v := range p.Storage.Volumes {
				wwns = append(wwns, v.WWN)
			}
		}
	}
	return s.Priv.Call(ctx, sanclient.OpMultipathApply, sanclient.MultipathArgs{WWNs: wwns}, nil)
}

// Detach implements cluster.StorageAttacher.
func (s *Service) Detach(ctx context.Context, w cluster.WorkloadRef, force bool) error {
	return s.Priv.Call(ctx, sanclient.OpDetach, sanclient.DetachArgs{Workload: w, Force: force}, nil)
}

// Attached implements cluster.StorageAttacher.
func (s *Service) Attached(ctx context.Context) ([]cluster.Attachment, error) {
	var st sanclient.Status
	if err := s.Priv.Call(ctx, sanclient.OpStatus, nil, &st); err != nil {
		return nil, err
	}
	out := make([]cluster.Attachment, 0, len(st.Attached))
	for _, r := range st.Attached {
		out = append(out, r.Attachment)
	}
	return out, nil
}

// Healthy implements cluster.StorageAttacher.
func (s *Service) Healthy(ctx context.Context) (bool, string) {
	var st sanclient.Status
	if err := s.Priv.Call(ctx, sanclient.OpStatus, nil, &st); err != nil {
		return false, err.Error()
	}
	return st.Healthy, st.Problem
}

// SyncShares mounts every cluster share on this compute node and unmounts
// those taken out of the cluster.
func (s *Service) SyncShares(ctx context.Context) error {
	me, snap, err := s.self()
	if err != nil || me.Role != cluster.RoleCompute || me.State != cluster.NodeActive {
		return err
	}
	path, err := s.path(ctx, snap, me)
	if err != nil {
		return err
	}
	var st sanclient.Status
	if err := s.Priv.Call(ctx, sanclient.OpStatus, nil, &st); err != nil {
		return err
	}
	var errs []error
	for id, sh := range snap.ClusterShares {
		if _, ok := st.Shares[id]; ok {
			continue
		}
		err := s.Priv.Call(ctx, sanclient.OpNFSMount, sanclient.MountArgs{Server: path.server, Interface: path.iface,
			Dataset: sh.Dataset, ExportPath: sh.Path, Share: id}, nil)
		if err != nil {
			errs = append(errs, err)
		}
	}
	for id, mp := range st.Shares {
		if _, ok := snap.ClusterShares[id]; ok {
			continue
		}
		ds := mp[len(cluster.RemoteMountRoot)+1:]
		if err := s.Priv.Call(ctx, sanclient.OpNFSUmount, sanclient.UmountArgs{Dataset: ds, Share: id}, nil); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
