package priv

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/replica"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// Replication operation names (internal/replica). Streams travel as file
// descriptors handed to hardyd (SCM_RIGHTS): a send hands over the read
// end of zfs send's output, a receive the write end of what zfs receive
// reads, after root has checked the stream's first record. hardyd follows
// each stream with repl.stream and can end it with repl.cancel.
const (
	OpReplItems          = "repl.items"
	OpReplSnapshot       = "repl.snapshot"
	OpReplLocalSnapshots = "repl.snapshots.local"
	OpReplSend           = "repl.send"
	OpReplPrune          = "repl.prune"
	OpReplStream         = "repl.stream"
	OpReplCancel         = "repl.cancel"
	// Receiving side: everything under <pool>/replicas/<source>/.
	OpReplRecv             = "repl.recv"
	OpReplRecvState        = "repl.recv.state"
	OpReplRecvAbort        = "repl.recv.abort"
	OpReplRecvPrune        = "repl.recv.prune"
	OpReplReplicas         = "repl.replicas"
	OpReplReplicaSnapshots = "repl.replica.snapshots"
	OpReplReplicaChildren  = "repl.replica.children"
	OpReplReplicaSend      = "repl.replica.send"
	OpReplReplicaBrowse    = "repl.replica.browse"
	OpReplSourceDelete     = "repl.source.delete"
	// Restoring a replica back onto this (the source) server.
	OpReplRestoreRecv   = "repl.restore.recv"
	OpReplRestoreFinish = "repl.restore.finish"
	OpReplRestoreAbort  = "repl.restore.abort"
)

// ReplItemsResult lists what can be replicated.
type ReplItemsResult struct {
	Items []replica.LocalItem `json:"items"`
}

// ReplSnapshotsResult lists snapshots.
type ReplSnapshotsResult struct {
	Snapshots []replica.SnapInfo `json:"snapshots"`
}

// ReplChildrenResult lists an item's datasets.
type ReplChildrenResult struct {
	Children []replica.Child `json:"children"`
}

// ReplReplicasResult lists the replicas kept on this server.
type ReplReplicasResult struct {
	Sources []replica.ReplicaSource `json:"sources"`
}

// ReplSnapshotTarget names a replica's snapshot.
type ReplSnapshotTarget struct {
	replica.Target
	Snapshot string `json:"snapshot"`
}

// RegisterReplication adds the replication operations.
func RegisterReplication(s *Server, m *replica.Manager) {
	s.Handle(OpReplItems, typed(func(ctx context.Context, _ struct{}) (any, error) {
		l, err := m.ListItems(ctx)
		return ReplItemsResult{Items: l}, replErr(err)
	}))
	s.Handle(OpReplSnapshot, typed(func(ctx context.Context, a replica.SnapshotArgs) (any, error) {
		r, err := m.Snapshot(ctx, a)
		return r, replErr(err)
	}))
	s.Handle(OpReplLocalSnapshots, typed(func(ctx context.Context, a replica.LocalSnapshotsArgs) (any, error) {
		l, err := m.LocalSnapshots(ctx, a)
		return ReplSnapshotsResult{Snapshots: l}, replErr(err)
	}))
	s.Handle(OpReplSend, typed(func(ctx context.Context, a replica.SendArgs) (any, error) {
		st, f, err := m.Send(ctx, a)
		if err != nil {
			return nil, replErr(err)
		}
		return &FileResult{Data: st, File: f}, nil
	}))
	s.Handle(OpReplPrune, typed(func(ctx context.Context, a replica.PruneArgs) (any, error) {
		r, err := m.Prune(ctx, a)
		return r, replErr(err)
	}))
	s.Handle(OpReplStream, typed(func(ctx context.Context, a replica.StreamArgs) (any, error) {
		st, err := m.Stream(a.Stream)
		return st, replErr(err)
	}))
	s.Handle(OpReplCancel, typed(func(ctx context.Context, a replica.StreamArgs) (any, error) {
		return map[string]bool{"cancelled": true}, replErr(m.Cancel(a.Stream))
	}))
	s.Handle(OpReplRecv, typed(func(ctx context.Context, a replica.RecvArgs) (any, error) {
		st, f, err := m.Recv(ctx, a)
		if err != nil {
			return nil, replErr(err)
		}
		return &FileResult{Data: st, File: f}, nil
	}))
	s.Handle(OpReplRecvState, typed(func(ctx context.Context, a replica.Target) (any, error) {
		st, err := m.State(ctx, a)
		return st, replErr(err)
	}))
	s.Handle(OpReplRecvAbort, typed(func(ctx context.Context, a replica.Target) (any, error) {
		return map[string]bool{"aborted": true}, replErr(m.Abort(ctx, a))
	}))
	s.Handle(OpReplRecvPrune, typed(func(ctx context.Context, a replica.RecvPruneArgs) (any, error) {
		r, err := m.PruneReplica(ctx, a)
		return r, replErr(err)
	}))
	s.Handle(OpReplReplicas, typed(func(ctx context.Context, _ struct{}) (any, error) {
		l, err := m.Replicas(ctx)
		return ReplReplicasResult{Sources: l}, replErr(err)
	}))
	s.Handle(OpReplReplicaSnapshots, typed(func(ctx context.Context, a replica.Target) (any, error) {
		l, err := m.ReplicaSnapshots(ctx, a)
		return ReplSnapshotsResult{Snapshots: l}, replErr(err)
	}))
	s.Handle(OpReplReplicaChildren, typed(func(ctx context.Context, a ReplSnapshotTarget) (any, error) {
		l, err := m.ReplicaChildren(ctx, a.Target, a.Snapshot)
		return ReplChildrenResult{Children: l}, replErr(err)
	}))
	s.Handle(OpReplReplicaSend, typed(func(ctx context.Context, a replica.ReplicaSendArgs) (any, error) {
		st, f, err := m.SendReplica(ctx, a)
		if err != nil {
			return nil, replErr(err)
		}
		return &FileResult{Data: st, File: f}, nil
	}))
	s.Handle(OpReplReplicaBrowse, typed(func(ctx context.Context, a replica.BrowseArgs) (any, error) {
		r, err := m.Browse(ctx, a)
		return r, replErr(err)
	}))
	s.Handle(OpReplSourceDelete, typed(func(ctx context.Context, a replica.DeleteSourceArgs) (any, error) {
		return map[string]bool{"deleted": true}, replErr(m.DeleteSource(ctx, a))
	}))
	s.Handle(OpReplRestoreRecv, typed(func(ctx context.Context, a replica.RestoreArgs) (any, error) {
		st, f, err := m.RestoreRecv(ctx, a)
		if err != nil {
			return nil, replErr(err)
		}
		return &FileResult{Data: st, File: f}, nil
	}))
	s.Handle(OpReplRestoreFinish, typed(func(ctx context.Context, a replica.RestoreFinishArgs) (any, error) {
		r, err := m.RestoreFinish(ctx, a)
		return r, replErr(err)
	}))
	s.Handle(OpReplRestoreAbort, typed(func(ctx context.Context, a replica.RestoreFinishArgs) (any, error) {
		return map[string]bool{"aborted": true}, replErr(m.RestoreAbort(ctx, a))
	}))
}

// CodeBusy: a transfer into that replica is already running.
const CodeBusy = "busy"

func replErr(err error) error {
	if err == nil {
		return nil
	}
	var pe *Error
	if errors.As(err, &pe) {
		return pe
	}
	switch {
	case errors.Is(err, replica.ErrNotFound), errors.Is(err, replica.ErrNoStream), errors.Is(err, shares.ErrNotFound),
		errors.Is(err, vms.ErrNotFound), errors.Is(err, apps.ErrNotInstalled):
		return Errorf(CodeNotFound, "%v", err)
	case errors.Is(err, replica.ErrBusy):
		return Errorf(CodeBusy, "%v", err)
	case errors.Is(err, replica.ErrInvalid), errors.Is(err, apps.ErrNoEngine):
		return Errorf(CodeBadArgs, "%v", err)
	}
	var ve *shares.ValidationError
	var vp vms.Problems
	var ap apps.Problems
	if errors.As(err, &ve) || errors.As(err, &vp) || errors.As(err, &ap) {
		return Errorf(CodeBadArgs, "%v", err)
	}
	return Errorf(CodeFailed, "%v", err)
}

// ReplicationItems finds shared folders, apps and VMs for replication and
// adopts what a restore brings back, through their own managers.
type ReplicationItems struct {
	Shares *shares.Manager
	Apps   *apps.Manager
	VMs    *vms.Manager
}

// List implements replica.Items.
func (r *ReplicationItems) List(ctx context.Context) ([]replica.LocalItem, error) {
	out := []replica.LocalItem{}
	if r.Shares != nil {
		l, err := r.Shares.List(ctx)
		if err != nil {
			return nil, err
		}
		for _, sh := range l {
			out = append(out, replica.LocalItem{Kind: replica.KindShare, ID: sh.ID, Name: sh.Name, Pool: sh.Pool, Dataset: sh.Dataset, UsedBytes: sh.UsedBytes})
		}
	}
	if r.Apps != nil && r.Apps.Available() {
		if o, err := r.Apps.Status(ctx); err == nil {
			for _, a := range o.Apps {
				out = append(out, replica.LocalItem{Kind: replica.KindApp, ID: a.ID, Name: a.Name, Pool: o.Pool, Dataset: a.Dataset})
			}
		}
	}
	if r.VMs != nil {
		if o, err := r.VMs.List(ctx); err == nil {
			for _, v := range o.VMs {
				var used uint64
				for _, n := range v.DiskUsage {
					used += uint64(max(n, 0))
				}
				name := v.Name
				if name == "" {
					name = v.ID
				}
				out = append(out, replica.LocalItem{Kind: replica.KindVM, ID: v.ID, Name: name, Pool: v.Pool, Dataset: v.Dataset, UsedBytes: used})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind > out[j].Kind // shares, then VMs, then apps
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// Resolve implements replica.Items: the dataset comes from the item's own
// manager (what it found and checked on the pool), never from hardyd.
func (r *ReplicationItems) Resolve(ctx context.Context, kind, id string) (string, error) {
	switch kind {
	case replica.KindShare:
		if r.Shares == nil {
			return "", replica.ErrNotFound
		}
		sh, err := r.Shares.Get(ctx, id)
		if err != nil {
			return "", err
		}
		if sh.Dataset != shares.Dataset(sh.Pool, sh.ID) {
			return "", fmt.Errorf("%s: %w", id, replica.ErrNotFound)
		}
		return sh.Dataset, nil
	case replica.KindVM:
		if r.VMs == nil {
			return "", replica.ErrNotFound
		}
		v, err := r.VMs.Get(ctx, id)
		if err != nil {
			return "", err
		}
		if v.Dataset != vms.Dataset(v.Pool, v.ID) {
			return "", fmt.Errorf("%s: %w", id, replica.ErrNotFound)
		}
		return v.Dataset, nil
	case replica.KindApp:
		if r.Apps == nil || !r.Apps.Available() {
			return "", replica.ErrNotFound
		}
		o, err := r.Apps.Status(ctx)
		if err != nil {
			return "", err
		}
		for _, a := range o.Apps {
			if a.ID == id && a.Dataset == o.Pool+"/apps/"+id {
				return a.Dataset, nil
			}
		}
		return "", fmt.Errorf("app %s: %w", id, replica.ErrNotFound)
	}
	return "", replica.ErrNotFound
}

// ShareProps implements replica.Restorer.
func (r *ReplicationItems) ShareProps(ctx context.Context, pool, id, name string) ([]string, error) {
	if r.Shares == nil {
		return nil, errors.New("shared folders aren't available")
	}
	return r.Shares.RestoreProps(ctx, pool, id, name)
}

// ShareAdopt implements replica.Restorer.
func (r *ReplicationItems) ShareAdopt(ctx context.Context, pool, id string) error {
	_, err := r.Shares.AdoptRestored(ctx, pool, id)
	return err
}

// VMFree implements replica.Restorer.
func (r *ReplicationItems) VMFree(ctx context.Context, id string) error {
	if r.VMs == nil {
		return errors.New("virtual machines aren't available")
	}
	return r.VMs.Free(ctx, id)
}

// VMAdopt implements replica.Restorer.
func (r *ReplicationItems) VMAdopt(ctx context.Context, id string) ([]string, error) {
	_, notes, err := r.VMs.Adopt(ctx, id)
	return notes, err
}

// AppsPool implements replica.Restorer.
func (r *ReplicationItems) AppsPool(ctx context.Context) (string, error) {
	if r.Apps == nil {
		return "", apps.ErrNoEngine
	}
	return r.Apps.EnginePool()
}

// AppAdopt implements replica.Restorer.
func (r *ReplicationItems) AppAdopt(ctx context.Context, id string) error {
	return r.Apps.AdoptRestored(ctx, id)
}
