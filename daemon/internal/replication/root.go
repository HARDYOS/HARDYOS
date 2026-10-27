// Package replication is hardyd's side of replication between HardyOS
// servers: pairing (one-time codes, pinned keys), replication tasks and
// their schedule, the HTTPS transport (mutual TLS between two hardyds)
// that carries zfs send streams from hardyd-priv on one server to
// hardyd-priv on the other, history, alerts and restores. The streams
// themselves are made and consumed by root (internal/replica); hardyd
// only moves bytes, with a bandwidth limit, and keeps count.
package replication

import (
	"context"
	"io"

	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/replica"
)

// Root is what replication asks of hardyd-priv.
type Root interface {
	Items(ctx context.Context) ([]replica.LocalItem, error)
	Snapshot(ctx context.Context, a replica.SnapshotArgs) (*replica.SnapshotResult, error)
	LocalSnapshots(ctx context.Context, a replica.LocalSnapshotsArgs) ([]replica.SnapInfo, error)
	Send(ctx context.Context, a replica.SendArgs) (*replica.SendStart, io.ReadCloser, error)
	Prune(ctx context.Context, a replica.PruneArgs) (*replica.PruneResult, error)
	Stream(ctx context.Context, id string) (*replica.StreamState, error)
	Cancel(ctx context.Context, id string) error

	Recv(ctx context.Context, a replica.RecvArgs) (*replica.RecvStart, io.WriteCloser, error)
	RecvState(ctx context.Context, t replica.Target) (*replica.RecvState, error)
	RecvAbort(ctx context.Context, t replica.Target) error
	RecvPrune(ctx context.Context, a replica.RecvPruneArgs) (*replica.PruneResult, error)
	Replicas(ctx context.Context) ([]replica.ReplicaSource, error)
	ReplicaSnapshots(ctx context.Context, t replica.Target) ([]replica.SnapInfo, error)
	ReplicaChildren(ctx context.Context, t replica.Target, snapshot string) ([]replica.Child, error)
	ReplicaSend(ctx context.Context, a replica.ReplicaSendArgs) (*replica.SendStart, io.ReadCloser, error)
	Browse(ctx context.Context, a replica.BrowseArgs) (*replica.BrowseResult, error)
	DeleteSource(ctx context.Context, a replica.DeleteSourceArgs) error

	RestoreRecv(ctx context.Context, a replica.RestoreArgs) (*replica.RecvStart, io.WriteCloser, error)
	RestoreFinish(ctx context.Context, a replica.RestoreFinishArgs) (*replica.RestoreFinishResult, error)
	RestoreAbort(ctx context.Context, a replica.RestoreFinishArgs) error
}

// PrivRoot is Root over hardyd-priv's socket.
type PrivRoot struct {
	Priv *priv.Client
}

func (p *PrivRoot) call(ctx context.Context, op string, args, out any) error {
	return p.Priv.Call(ctx, op, args, out)
}

// Items implements Root.
func (p *PrivRoot) Items(ctx context.Context) ([]replica.LocalItem, error) {
	var r priv.ReplItemsResult
	err := p.call(ctx, priv.OpReplItems, struct{}{}, &r)
	return r.Items, err
}

// Snapshot implements Root.
func (p *PrivRoot) Snapshot(ctx context.Context, a replica.SnapshotArgs) (*replica.SnapshotResult, error) {
	var r replica.SnapshotResult
	if err := p.call(ctx, priv.OpReplSnapshot, a, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// LocalSnapshots implements Root.
func (p *PrivRoot) LocalSnapshots(ctx context.Context, a replica.LocalSnapshotsArgs) ([]replica.SnapInfo, error) {
	var r priv.ReplSnapshotsResult
	err := p.call(ctx, priv.OpReplLocalSnapshots, a, &r)
	return r.Snapshots, err
}

// Send implements Root.
func (p *PrivRoot) Send(ctx context.Context, a replica.SendArgs) (*replica.SendStart, io.ReadCloser, error) {
	var r replica.SendStart
	f, err := p.Priv.CallFile(ctx, priv.OpReplSend, a, &r)
	if err != nil {
		return nil, nil, err
	}
	return &r, f, nil
}

// Prune implements Root.
func (p *PrivRoot) Prune(ctx context.Context, a replica.PruneArgs) (*replica.PruneResult, error) {
	var r replica.PruneResult
	if err := p.call(ctx, priv.OpReplPrune, a, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Stream implements Root.
func (p *PrivRoot) Stream(ctx context.Context, id string) (*replica.StreamState, error) {
	var r replica.StreamState
	if err := p.call(ctx, priv.OpReplStream, replica.StreamArgs{Stream: id}, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Cancel implements Root.
func (p *PrivRoot) Cancel(ctx context.Context, id string) error {
	return p.call(ctx, priv.OpReplCancel, replica.StreamArgs{Stream: id}, nil)
}

// Recv implements Root.
func (p *PrivRoot) Recv(ctx context.Context, a replica.RecvArgs) (*replica.RecvStart, io.WriteCloser, error) {
	var r replica.RecvStart
	f, err := p.Priv.CallFile(ctx, priv.OpReplRecv, a, &r)
	if err != nil {
		return nil, nil, err
	}
	return &r, f, nil
}

// RecvState implements Root.
func (p *PrivRoot) RecvState(ctx context.Context, t replica.Target) (*replica.RecvState, error) {
	var r replica.RecvState
	if err := p.call(ctx, priv.OpReplRecvState, t, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// RecvAbort implements Root.
func (p *PrivRoot) RecvAbort(ctx context.Context, t replica.Target) error {
	return p.call(ctx, priv.OpReplRecvAbort, t, nil)
}

// RecvPrune implements Root.
func (p *PrivRoot) RecvPrune(ctx context.Context, a replica.RecvPruneArgs) (*replica.PruneResult, error) {
	var r replica.PruneResult
	if err := p.call(ctx, priv.OpReplRecvPrune, a, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Replicas implements Root.
func (p *PrivRoot) Replicas(ctx context.Context) ([]replica.ReplicaSource, error) {
	var r priv.ReplReplicasResult
	err := p.call(ctx, priv.OpReplReplicas, struct{}{}, &r)
	return r.Sources, err
}

// ReplicaSnapshots implements Root.
func (p *PrivRoot) ReplicaSnapshots(ctx context.Context, t replica.Target) ([]replica.SnapInfo, error) {
	var r priv.ReplSnapshotsResult
	err := p.call(ctx, priv.OpReplReplicaSnapshots, t, &r)
	return r.Snapshots, err
}

// ReplicaChildren implements Root.
func (p *PrivRoot) ReplicaChildren(ctx context.Context, t replica.Target, snapshot string) ([]replica.Child, error) {
	var r priv.ReplChildrenResult
	err := p.call(ctx, priv.OpReplReplicaChildren, priv.ReplSnapshotTarget{Target: t, Snapshot: snapshot}, &r)
	return r.Children, err
}

// ReplicaSend implements Root.
func (p *PrivRoot) ReplicaSend(ctx context.Context, a replica.ReplicaSendArgs) (*replica.SendStart, io.ReadCloser, error) {
	var r replica.SendStart
	f, err := p.Priv.CallFile(ctx, priv.OpReplReplicaSend, a, &r)
	if err != nil {
		return nil, nil, err
	}
	return &r, f, nil
}

// Browse implements Root.
func (p *PrivRoot) Browse(ctx context.Context, a replica.BrowseArgs) (*replica.BrowseResult, error) {
	var r replica.BrowseResult
	if err := p.call(ctx, priv.OpReplReplicaBrowse, a, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// DeleteSource implements Root.
func (p *PrivRoot) DeleteSource(ctx context.Context, a replica.DeleteSourceArgs) error {
	return p.call(ctx, priv.OpReplSourceDelete, a, nil)
}

// RestoreRecv implements Root.
func (p *PrivRoot) RestoreRecv(ctx context.Context, a replica.RestoreArgs) (*replica.RecvStart, io.WriteCloser, error) {
	var r replica.RecvStart
	f, err := p.Priv.CallFile(ctx, priv.OpReplRestoreRecv, a, &r)
	if err != nil {
		return nil, nil, err
	}
	return &r, f, nil
}

// RestoreFinish implements Root.
func (p *PrivRoot) RestoreFinish(ctx context.Context, a replica.RestoreFinishArgs) (*replica.RestoreFinishResult, error) {
	var r replica.RestoreFinishResult
	if err := p.call(ctx, priv.OpReplRestoreFinish, a, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// RestoreAbort implements Root.
func (p *PrivRoot) RestoreAbort(ctx context.Context, a replica.RestoreFinishArgs) error {
	return p.call(ctx, priv.OpReplRestoreAbort, a, nil)
}

// LocalRoot is Root calling a replica.Manager in the same process (tests
// and the integration test with two pools on one machine).
type LocalRoot struct {
	M *replica.Manager
}

// Items implements Root.
func (l *LocalRoot) Items(ctx context.Context) ([]replica.LocalItem, error) {
	return l.M.ListItems(ctx)
}

// Snapshot implements Root.
func (l *LocalRoot) Snapshot(ctx context.Context, a replica.SnapshotArgs) (*replica.SnapshotResult, error) {
	return l.M.Snapshot(ctx, a)
}

// LocalSnapshots implements Root.
func (l *LocalRoot) LocalSnapshots(ctx context.Context, a replica.LocalSnapshotsArgs) ([]replica.SnapInfo, error) {
	return l.M.LocalSnapshots(ctx, a)
}

// Send implements Root.
func (l *LocalRoot) Send(ctx context.Context, a replica.SendArgs) (*replica.SendStart, io.ReadCloser, error) {
	st, f, err := l.M.Send(ctx, a)
	if err != nil {
		return nil, nil, err
	}
	return st, f, nil
}

// Prune implements Root.
func (l *LocalRoot) Prune(ctx context.Context, a replica.PruneArgs) (*replica.PruneResult, error) {
	return l.M.Prune(ctx, a)
}

// Stream implements Root.
func (l *LocalRoot) Stream(_ context.Context, id string) (*replica.StreamState, error) {
	return l.M.Stream(id)
}

// Cancel implements Root.
func (l *LocalRoot) Cancel(_ context.Context, id string) error { return l.M.Cancel(id) }

// Recv implements Root.
func (l *LocalRoot) Recv(ctx context.Context, a replica.RecvArgs) (*replica.RecvStart, io.WriteCloser, error) {
	st, f, err := l.M.Recv(ctx, a)
	if err != nil {
		return nil, nil, err
	}
	return st, f, nil
}

// RecvState implements Root.
func (l *LocalRoot) RecvState(ctx context.Context, t replica.Target) (*replica.RecvState, error) {
	return l.M.State(ctx, t)
}

// RecvAbort implements Root.
func (l *LocalRoot) RecvAbort(ctx context.Context, t replica.Target) error { return l.M.Abort(ctx, t) }

// RecvPrune implements Root.
func (l *LocalRoot) RecvPrune(ctx context.Context, a replica.RecvPruneArgs) (*replica.PruneResult, error) {
	return l.M.PruneReplica(ctx, a)
}

// Replicas implements Root.
func (l *LocalRoot) Replicas(ctx context.Context) ([]replica.ReplicaSource, error) {
	return l.M.Replicas(ctx)
}

// ReplicaSnapshots implements Root.
func (l *LocalRoot) ReplicaSnapshots(ctx context.Context, t replica.Target) ([]replica.SnapInfo, error) {
	return l.M.ReplicaSnapshots(ctx, t)
}

// ReplicaChildren implements Root.
func (l *LocalRoot) ReplicaChildren(ctx context.Context, t replica.Target, snapshot string) ([]replica.Child, error) {
	return l.M.ReplicaChildren(ctx, t, snapshot)
}

// ReplicaSend implements Root.
func (l *LocalRoot) ReplicaSend(ctx context.Context, a replica.ReplicaSendArgs) (*replica.SendStart, io.ReadCloser, error) {
	st, f, err := l.M.SendReplica(ctx, a)
	if err != nil {
		return nil, nil, err
	}
	return st, f, nil
}

// Browse implements Root.
func (l *LocalRoot) Browse(ctx context.Context, a replica.BrowseArgs) (*replica.BrowseResult, error) {
	return l.M.Browse(ctx, a)
}

// DeleteSource implements Root.
func (l *LocalRoot) DeleteSource(ctx context.Context, a replica.DeleteSourceArgs) error {
	return l.M.DeleteSource(ctx, a)
}

// RestoreRecv implements Root.
func (l *LocalRoot) RestoreRecv(ctx context.Context, a replica.RestoreArgs) (*replica.RecvStart, io.WriteCloser, error) {
	st, f, err := l.M.RestoreRecv(ctx, a)
	if err != nil {
		return nil, nil, err
	}
	return st, f, nil
}

// RestoreFinish implements Root.
func (l *LocalRoot) RestoreFinish(ctx context.Context, a replica.RestoreFinishArgs) (*replica.RestoreFinishResult, error) {
	return l.M.RestoreFinish(ctx, a)
}

// RestoreAbort implements Root.
func (l *LocalRoot) RestoreAbort(ctx context.Context, a replica.RestoreFinishArgs) error {
	return l.M.RestoreAbort(ctx, a)
}
