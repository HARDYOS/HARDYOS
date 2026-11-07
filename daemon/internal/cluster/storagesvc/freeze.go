package storagesvc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/sanclient"
)

// ThawAfter is how long a forwarded freeze may last before the owner
// thaws the guest by itself.
const ThawAfter = 60 * time.Second

type freezeReq struct {
	VM string `json:"vm"`
}

type freezeResp struct {
	Frozen bool `json:"frozen"`
}

type dumpReq struct {
	App string `json:"app"`
}

// Frozen implements cluster.Freezer on the storage node: a running cluster
// VM's guest file systems are frozen by its owner (over the peer API, with
// an automatic thaw after ThawAfter on the owner's side) around fn.
// consistent is false when the guest couldn't be frozen.
func (s *Service) Frozen(ctx context.Context, vm string, fn func(ctx context.Context) error) (bool, error) {
	_, snap, err := s.self()
	if err != nil {
		return false, err
	}
	p := snap.Placements[cluster.WorkloadRef{Kind: cluster.KindVM, ID: vm}]
	if p == nil || p.Owner == "" || p.State != cluster.PlacementRunning || s.Peers == nil {
		return p == nil || p.State == cluster.PlacementStopped, fn(ctx)
	}
	var fr freezeResp
	fctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	ferr := s.Peers.Call(fctx, p.Owner, "POST", "storage/freeze", freezeReq{VM: vm}, &fr)
	cancel()
	if ferr != nil {
		s.log().Info("storage: the owner couldn't freeze the VM; the snapshot is crash-consistent", "vm", vm, "owner", p.Owner, "err", ferr)
	}
	err = fn(ctx)
	if ferr == nil && fr.Frozen {
		tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		if terr := s.Peers.Call(tctx, p.Owner, "POST", "storage/thaw", freezeReq{VM: vm}, nil); terr != nil {
			s.log().Warn("storage: thawing the VM on its owner failed; it thaws by itself shortly", "vm", vm, "err", terr)
		}
		cancel()
	}
	return ferr == nil && fr.Frozen, err
}

// dumpOnOwner runs a running app's backup dump on its owner.
func (s *Service) dumpOnOwner(ctx context.Context, snap *cluster.Snapshot, app string) error {
	p := snap.Placements[cluster.WorkloadRef{Kind: cluster.KindApp, ID: app}]
	if p == nil || p.Owner == "" || p.State != cluster.PlacementRunning {
		return nil
	}
	if s.Peers == nil {
		return cluster.ErrStorageUnavailable
	}
	return s.Peers.Call(ctx, p.Owner, "POST", "storage/dump", dumpReq{App: app}, nil)
}

// AppDump is the cloud backup's and replication's PreBackup for a cluster
// app, run from the storage node (the app runs elsewhere).
func (s *Service) AppDump(ctx context.Context, app string) (bool, error) {
	_, snap, err := s.self()
	if err != nil {
		return false, err
	}
	if err := s.dumpOnOwner(ctx, snap, app); err != nil {
		return false, err
	}
	return true, nil
}

// ownerFreeze is the owner's side of storage/freeze: only the storage node
// may ask, and only for a VM the state places here.
func (s *Service) ownerFreeze(ctx context.Context, caller cluster.Node, vm string) (bool, error) {
	if err := s.callerIsStorage(caller); err != nil {
		return false, err
	}
	if err := s.placedHere(cluster.WorkloadRef{Kind: cluster.KindVM, ID: vm}); err != nil {
		return false, err
	}
	var res map[string]bool
	if err := s.Priv.Call(ctx, sanclient.OpFreeze, sanclient.FreezeArgs{VM: vm}, &res); err != nil {
		return false, err
	}
	return res["frozen"], nil
}

func (s *Service) ownerThaw(ctx context.Context, caller cluster.Node, vm string) error {
	if err := s.callerIsStorage(caller); err != nil {
		return err
	}
	return s.Priv.Call(ctx, sanclient.OpThaw, sanclient.FreezeArgs{VM: vm}, nil)
}

func (s *Service) ownerDump(ctx context.Context, caller cluster.Node, app string) error {
	if err := s.callerIsStorage(caller); err != nil {
		return err
	}
	if err := s.placedHere(cluster.WorkloadRef{Kind: cluster.KindApp, ID: app}); err != nil {
		return err
	}
	return s.Priv.Call(ctx, sanclient.OpAppDump, sanclient.DumpArgs{App: app}, nil)
}

func (s *Service) callerIsStorage(caller cluster.Node) error {
	if caller.Role != cluster.RoleStorage {
		return errors.New("only the storage server may ask for this")
	}
	return nil
}

func (s *Service) placedHere(w cluster.WorkloadRef) error {
	me, snap, err := s.self()
	if err != nil {
		return err
	}
	p := snap.Placements[w]
	if p == nil || p.Owner != me.ID {
		return fmt.Errorf("%w: %s %s", cluster.ErrNotOwner, w.Kind, w.ID)
	}
	return nil
}
