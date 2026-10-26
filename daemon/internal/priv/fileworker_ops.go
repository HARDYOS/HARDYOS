package priv

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/fileworker"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// File access operations (docs/plans/file-sharing.md section 3). Each runs
// in a short-lived worker that is the person, never root; see
// internal/fileworker. files.open, files.create and files.openwrite hand an
// open file to hardyd (CallFile).
const (
	OpFilesShares    = "files.shares"
	OpFilesList      = "files.list"
	OpFilesStat      = "files.stat"
	OpFilesOpen      = "files.open"
	OpFilesCreate    = "files.create"
	OpFilesOpenWrite = "files.openwrite"
	OpFilesMkdir     = "files.mkdir"
	OpFilesRename    = "files.rename"
	OpFilesDelete    = "files.delete"
	OpFilesSetTime   = "files.settime"
	OpFilesVersions  = "files.versions"
)

// File access error codes (beside the shared ones).
const (
	CodeNotFound    = fileworker.CodeNotFound
	CodeNoAccess    = fileworker.CodeNoAccess
	CodeExists      = fileworker.CodeExists
	CodeNotAllowed  = fileworker.CodeNotAllowed
	CodeFull        = fileworker.CodeFull
	CodeCrossDevice = fileworker.CodeCrossDevice
)

var fileOps = map[string]string{
	OpFilesShares:    fileworker.OpShares,
	OpFilesList:      fileworker.OpList,
	OpFilesStat:      fileworker.OpStat,
	OpFilesOpen:      fileworker.OpOpen,
	OpFilesCreate:    fileworker.OpCreate,
	OpFilesOpenWrite: fileworker.OpOpenWrite,
	OpFilesMkdir:     fileworker.OpMkdir,
	OpFilesRename:    fileworker.OpRename,
	OpFilesDelete:    fileworker.OpDelete,
	OpFilesSetTime:   fileworker.OpSetTime,
	OpFilesVersions:  fileworker.OpVersions,
}

// RegisterFileWorker adds the files.* operations, run by w.
func RegisterFileWorker(s *Server, w *fileworker.Server) {
	for name, op := range fileOps {
		s.Handle(name, typed(func(ctx context.Context, a fileworker.Args) (any, error) {
			data, file, err := w.Do(ctx, op, a)
			if err != nil {
				var fe *fileworker.Error
				if errors.As(err, &fe) {
					return nil, &Error{Code: fe.Code, Message: fe.Message}
				}
				return nil, Errorf(CodeFailed, "%v", err)
			}
			if file != nil {
				return &FileResult{Data: data, File: file}, nil
			}
			return data, nil
		}))
	}
}

// StartFiles sets up file access in hardyd-priv: the files.* operations,
// and hardyos-files' access to every shared folder (now and every 10
// minutes, so folders on imported pools get it too).
func StartFiles(ctx context.Context, s *Server, m *shares.Manager, log *slog.Logger) error {
	w, err := fileworker.NewServer(m, sysexec.Exec{}, log)
	if err != nil {
		return err
	}
	w.FilesUser = func(ctx context.Context) {
		if err := m.EnsureFilesUser(ctx); err != nil {
			log.Warn("giving hardyos-files the shared folders", "err", err)
		}
	}
	RegisterFileWorker(s, w)
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			w.FilesUser(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return nil
}
