package storagesvc

import (
	"context"
	"errors"
	"fmt"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// ModeRequest switches a stopped cluster app between NFS and block mode
// (decision 341). Confirm must be the app's id.
type ModeRequest struct {
	App string              `json:"app"`
	To  cluster.StorageMode `json:"to"`
	// FS and SizeGB for a new block volume (ext4 default, 64 GB sparse).
	FS     string `json:"fs,omitempty"`
	SizeGB int    `json:"sizeGB,omitempty"`
	// RemoveOld clears the copy the data moved away from (a snapshot of
	// it is kept either way).
	RemoveOld bool          `json:"removeOld,omitempty"`
	Confirm   string        `json:"confirm"`
	Actor     cluster.Actor `json:"actor"`
}

// ModeResult reports a switch.
type ModeResult struct {
	App        string                  `json:"app"`
	Mode       cluster.StorageMode     `json:"mode"`
	Snapshot   string                  `json:"snapshot"`
	Removed    bool                    `json:"removed"`
	Generation uint64                  `json:"generation"`
	Storage    cluster.WorkloadStorage `json:"storage"`
}

// SwitchAppMode moves a stopped app's data into its other mode on the
// storage node: the owner detaches, the storage is taken offline, the data
// is copied (a snapshot of the source first), and the new layout is
// committed (storage.layout), which bumps the placement's generation so
// the app's next start attaches the new layout.
func (s *Service) SwitchAppMode(ctx context.Context, r ModeRequest) (*ModeResult, error) {
	var out ModeResult
	err := s.onStorage(ctx, "storage/mode", r, &out, r.Actor, func(snap *cluster.Snapshot, me cluster.Node) error {
		res, err := s.switchMode(ctx, snap, me, r)
		s.audit(ctx, r.Actor, "cluster.storage.mode", "app "+r.App+" -> "+string(r.To), err)
		if err == nil {
			out = *res
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Service) switchMode(ctx context.Context, snap *cluster.Snapshot, me cluster.Node, r ModeRequest) (*ModeResult, error) {
	if r.Confirm != r.App {
		return nil, errors.New("type the app's name to move its data")
	}
	w := cluster.WorkloadRef{Kind: cluster.KindApp, ID: r.App}
	p, err := placementOf(snap, w)
	if err != nil {
		return nil, err
	}
	if !stopped(p) {
		return nil, fmt.Errorf("stop %s first; its data can only move while it is stopped", r.App)
	}
	cur := p.Storage.Mode
	if cur == "" {
		cur = cluster.StorageNFS
	}
	if cur == r.To {
		return nil, fmt.Errorf("%s's data is already in %s mode", r.App, r.To)
	}
	fs := r.FS
	if fs == "" {
		fs = p.Storage.BlockFS
	}
	if fs == "" {
		fs = san.BlockExt4
	}
	if r.To == cluster.StorageBlock && fs != san.BlockExt4 && fs != san.BlockXFS {
		return nil, errors.New("the block volume's file system is ext4 or xfs")
	}
	if err := s.detachOnOwner(ctx, p); err != nil {
		return nil, fmt.Errorf("asking %s to let go of %s: %w", p.Owner, r.App, err)
	}
	release, err := s.hold(ctx, w)
	if err != nil {
		return nil, err
	}
	defer release()
	wa := san.WorkloadArgs{Kind: cluster.KindApp, ID: r.App, Pool: p.Storage.Pool}
	var vol *san.VolumeInfo
	if r.To == cluster.StorageBlock {
		size := r.SizeGB
		if size == 0 {
			size = DefaultBlockGB
		}
		var v san.VolumeInfo
		err := s.Priv.Call(ctx, san.OpVolumeCreate, priv.VolumeCreateArgs{Cluster: snap.Cluster,
			VolumeArgs: san.VolumeArgs{WorkloadArgs: wa, Disk: "block", SizeGB: size, FS: fs}}, &v)
		if err != nil {
			// A volume left from an earlier switch back to NFS is reused
			// (Migrate copies with --delete, so nothing stale survives).
			if e2 := s.Priv.Call(ctx, san.OpVolumeInfo, priv.VolumeCreateArgs{Cluster: snap.Cluster,
				VolumeArgs: san.VolumeArgs{WorkloadArgs: wa, Disk: "block"}}, &v); e2 != nil {
				return nil, err
			}
		}
		vol = &v
	}
	var mr san.MigrateResult
	if err := s.Priv.Call(ctx, san.OpAppMigrate, san.MigrateArgs{App: r.App, Pool: p.Storage.Pool, To: r.To, FS: fs, Confirm: r.App, RemoveOld: r.RemoveOld}, &mr); err != nil {
		return nil, err
	}
	ns := cluster.WorkloadStorage{Pool: p.Storage.Pool, Mode: r.To, Shares: p.Storage.Shares}
	if r.To == cluster.StorageBlock {
		ns.BlockFS = fs
		ns.Volumes = []cluster.Volume{{Dataset: vol.Dataset, Disk: "block", SizeGB: vol.SizeGB, WWN: vol.WWN}}
	} else {
		var info san.DatasetInfo
		if err := s.Priv.Call(ctx, san.OpDatasetInfo, wa, &info); err != nil {
			return nil, err
		}
		ns.Exports = []cluster.Export{{Kind: cluster.ExportAppData, Dataset: info.Dataset, Path: info.Mountpoint,
			MountPath: cluster.RemoteMountRoot + "/" + info.Dataset, FSID: info.GUID}}
	}
	if err := state.ValidWorkloadStorage(w, ns); err != nil {
		return nil, err
	}
	body := state.StorageLayoutBody{Workload: w, Generation: p.Generation, Storage: ns}
	idx, err := s.M.Propose(ctx, cluster.CmdStorageLayout, body, systemActor(me.ID))
	if err != nil {
		return nil, fmt.Errorf("the data was copied (snapshot %s) but the cluster didn't take the new layout: %w", mr.Snapshot, err)
	}
	if err := s.M.WaitApplied(ctx, idx); err != nil {
		return nil, err
	}
	np, _ := s.M.State().Placement(w)
	res := &ModeResult{App: r.App, Mode: r.To, Snapshot: mr.Snapshot, Removed: mr.Removed, Storage: ns}
	if np != nil {
		res.Generation = np.Generation
		if np.Storage.Mode != r.To {
			return nil, fmt.Errorf("the cluster refused the new layout (the placement changed meanwhile); the data copy is in place, snapshot %s", mr.Snapshot)
		}
	}
	return res, nil
}
