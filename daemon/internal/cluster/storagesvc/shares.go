package storagesvc

import (
	"context"
	"errors"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
)

// ShareRequest puts a shared folder of the storage node in or out of the
// cluster ("Use in the cluster").
type ShareRequest struct {
	Pool  string        `json:"pool"`
	ID    string        `json:"id"`
	In    bool          `json:"in"`
	Actor cluster.Actor `json:"actor"`
}

// SetShareCluster commits storage.share (signed by the storage node, which
// reads the folder's dataset itself).
func (s *Service) SetShareCluster(ctx context.Context, r ShareRequest) error {
	return s.onStorage(ctx, "storage/share", r, nil, func(snap *cluster.Snapshot, me cluster.Node) error {
		sh := cluster.ClusterShare{ID: r.ID, Pool: r.Pool, Dataset: r.Pool + "/shares/" + r.ID,
			MountPath: cluster.RemoteMountRoot + "/" + r.Pool + "/shares/" + r.ID}
		if r.In {
			var info san.DatasetInfo
			if err := s.Priv.Call(ctx, san.OpShareInfo, san.ShareArgs{Pool: r.Pool, ID: r.ID}, &info); err != nil {
				return err
			}
			sh.Path, sh.FSID = info.Mountpoint, info.GUID
			if err := state.ValidClusterShare(sh); err != nil {
				return err
			}
		} else if _, ok := snap.ClusterShares[r.ID]; !ok {
			return errors.New("that shared folder isn't used in the cluster")
		}
		idx, err := s.M.Propose(ctx, cluster.CmdShareCluster, state.ShareClusterBody{Share: sh, In: r.In}, r.Actor)
		if err == nil {
			err = s.M.WaitApplied(ctx, idx)
		}
		action := "cluster.storage.share.add"
		if !r.In {
			action = "cluster.storage.share.remove"
		}
		s.audit(ctx, r.Actor, action, r.Pool+"/"+r.ID, err)
		return err
	})
}

// RotateCHAP gives a compute node new CHAP secrets (storage node only; the
// node fetches them on its next login).
func (s *Service) RotateCHAP(ctx context.Context, node cluster.NodeID, actor cluster.Actor) error {
	me, snap, err := s.self()
	if err != nil {
		return err
	}
	if me.Role != cluster.RoleStorage {
		return errors.New("CHAP secrets are rotated on the storage server")
	}
	if n := snap.Nodes[node]; n == nil || n.Role != cluster.RoleCompute {
		return errors.New("that isn't a compute server of the cluster")
	}
	err = s.Priv.Call(ctx, san.OpCHAPRotate, san.CHAPArgs{Node: node}, nil)
	s.audit(ctx, actor, "cluster.storage.chap.rotate", string(node), err)
	return err
}
