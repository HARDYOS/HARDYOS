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
	// AfterDelete runs once the delete is over, whether it worked or not
	// (a service that held back from the folder may use it again).
	AfterDelete func(ctx context.Context, id string) error
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

func runAfterDelete(ctx context.Context, hooks []ShareHook, id string) {
	for _, h := range hooks {
		if h.AfterDelete == nil {
			continue
		}
		if err := h.AfterDelete(ctx, id); err != nil {
			slog.Default().Warn("shared folder delete: a file service couldn't take up the folder again", "share", id, "err", err)
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

type releaser struct {
	release func(ctx context.Context, dataset string) error
	done    func(dataset string)
}

// OnRelease adds a function that lets go of a dataset (a pool, or a
// dataset and everything below it) before the storage operations export
// or destroy it: file services holding mounts of it (SFTP's bind mounts)
// would keep it busy. done (may be nil) runs when the operation is over,
// whether it worked or not; until then the service must not take the
// dataset up again (SFTP's watch would bind it again otherwise).
func (s *Server) OnRelease(release func(ctx context.Context, dataset string) error, done func(dataset string)) {
	s.relMu.Lock()
	defer s.relMu.Unlock()
	s.releasers = append(s.releasers, releaser{release, done})
}

// releaseDataset lets go of ds everywhere; the caller runs the returned
// function when its operation is over (defer).
func (s *Server) releaseDataset(ctx context.Context, ds string) func() {
	if s == nil {
		return func() {}
	}
	s.relMu.Lock()
	rs := append([]releaser(nil), s.releasers...)
	s.relMu.Unlock()
	for _, r := range rs {
		if err := r.release(ctx, ds); err != nil {
			s.logger().Warn("a file service couldn't let go of a dataset", "dataset", ds, "err", err)
		}
	}
	return func() {
		for _, r := range rs {
			if r.done != nil {
				r.done(ds)
			}
		}
	}
}
