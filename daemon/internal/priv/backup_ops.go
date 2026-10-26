package priv

import (
	"context"
	"encoding/json"

	"github.com/hardyos/hardyos/daemon/internal/backup"
)

// Backup operation names.
const (
	OpBackupCollect = "backup.collect"
	OpBackupStore   = "backup.store"
	OpBackupList    = "backup.list"
	OpBackupFetch   = "backup.fetch"
	OpBackupStage   = "backup.stage"
	OpBackupUnstage = "backup.unstage"
	OpBackupStatus  = "backup.status"
)

// BackupCollectArgs asks for the system files of a backup.
type BackupCollectArgs struct {
	Secrets bool `json:"secrets"`
}

// BackupCollectResult carries them.
type BackupCollectResult struct {
	Files []backup.File `json:"files"`
}

// BackupStoreArgs keeps a backup (made by hardyd in its work directory) on a pool.
type BackupStoreArgs struct {
	Pool string `json:"pool"`
	Path string `json:"path"`
	Keep int    `json:"keep"`
}

// BackupRef names a backup on a pool.
type BackupRef struct {
	Pool string `json:"pool"`
	Name string `json:"name"`
}

// BackupStageArgs stages a backup file from hardyd's work directory.
type BackupStageArgs struct {
	Path     string `json:"path"`
	Password string `json:"password,omitempty"`
}

// BackupStatus is the restore state.
type BackupStatus struct {
	Pending    *backup.Staged `json:"pending"`
	LastResult *backup.Result `json:"lastResult"`
}

// BackupListResult lists data pools and the backups kept on them.
type BackupListResult struct {
	Pools   []string            `json:"pools"`
	Backups []backup.PoolBackup `json:"backups"`
}

// BackupFetchResult is the path of a fetched copy.
type BackupFetchResult struct {
	Path string `json:"path"`
}

// RegisterBackup adds the backup operations.
func RegisterBackup(s *Server, r *backup.Root) {
	s.Handle(OpBackupCollect, typed(func(ctx context.Context, a BackupCollectArgs) (any, error) {
		files, err := r.Collect(a.Secrets)
		if err != nil {
			return nil, Errorf(CodeFailed, "%v", err)
		}
		return BackupCollectResult{Files: files}, nil
	}))
	s.Handle(OpBackupStore, typed(func(ctx context.Context, a BackupStoreArgs) (any, error) {
		pb, err := r.Store(ctx, a.Pool, a.Path, a.Keep)
		if err != nil {
			return nil, Errorf(CodeFailed, "%v", err)
		}
		return pb, nil
	}))
	s.Handle(OpBackupList, func(ctx context.Context, _ json.RawMessage) (any, error) {
		pools, err := r.DataPools(ctx)
		if err != nil {
			return nil, Errorf(CodeFailed, "%v", err)
		}
		list, err := r.List(ctx)
		if err != nil {
			return nil, Errorf(CodeFailed, "%v", err)
		}
		if pools == nil {
			pools = []string{}
		}
		return BackupListResult{Pools: pools, Backups: list}, nil
	})
	s.Handle(OpBackupFetch, typed(func(ctx context.Context, a BackupRef) (any, error) {
		p, err := r.Fetch(ctx, a.Pool, a.Name)
		if err != nil {
			return nil, Errorf(CodeBadArgs, "%v", err)
		}
		return BackupFetchResult{Path: p}, nil
	}))
	s.Handle(OpBackupStage, typed(func(ctx context.Context, a BackupStageArgs) (any, error) {
		st, err := r.Stage(a.Path, a.Password)
		if err != nil {
			return nil, Errorf(CodeBadArgs, "%v", err)
		}
		return st, nil
	}))
	s.Handle(OpBackupUnstage, func(ctx context.Context, _ json.RawMessage) (any, error) {
		if err := r.Unstage(); err != nil {
			return nil, Errorf(CodeFailed, "%v", err)
		}
		return map[string]bool{"cancelled": true}, nil
	})
	s.Handle(OpBackupStatus, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return BackupStatus{Pending: r.PendingRestore(), LastResult: r.LastResult()}, nil
	})
}
