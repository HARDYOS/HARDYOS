package priv

import (
	"context"
	"log/slog"
)

// ShareHook lets file sharing (NFS, SMB, ...) follow shared folder changes
// made through the shares ops, so its configuration never lags behind the
// folders' settings. Either function may be nil.
type ShareHook struct {
	// BeforeDelete runs before a shared folder is destroyed (stop serving
	// it: a file system a server holds can't be unmounted). An error is
	// logged; the delete goes ahead.
	BeforeDelete func(ctx context.Context, id string) error
	// Changed runs after every create, update, delete and starter set,
	// whether it worked or not (a failed change may have done part of it).
	Changed func(ctx context.Context)
}

func runChanged(ctx context.Context, hooks []ShareHook) {
	for _, h := range hooks {
		if h.Changed != nil {
			h.Changed(ctx)
		}
	}
}

func runBeforeDelete(ctx context.Context, hooks []ShareHook, id string) {
	for _, h := range hooks {
		if h.BeforeDelete == nil {
			continue
		}
		if err := h.BeforeDelete(ctx, id); err != nil {
			slog.Default().Warn("shared folder delete: a file service couldn't let go of it first", "share", id, "err", err)
		}
	}
}

// OnRelease adds a function that lets go of a dataset (a pool, or a
// dataset and everything below it) before the storage operations export
// or destroy it: file services holding mounts of it (SFTP's bind mounts)
// would keep it busy.
func (s *Server) OnRelease(fn func(ctx context.Context, dataset string) error) {
	s.relMu.Lock()
	defer s.relMu.Unlock()
	s.releasers = append(s.releasers, fn)
}

func (s *Server) releaseDataset(ctx context.Context, ds string) {
	if s == nil {
		return
	}
	s.relMu.Lock()
	fns := append([]func(context.Context, string) error(nil), s.releasers...)
	s.relMu.Unlock()
	for _, fn := range fns {
		if err := fn(ctx, ds); err != nil {
			s.logger().Warn("a file service couldn't let go of a dataset", "dataset", ds, "err", err)
		}
	}
}
