package priv

import (
	"context"

	"github.com/hardyos/hardyos/daemon/internal/cluster/hacopy"
	"github.com/hardyos/hardyos/daemon/internal/shares"
)

// OpSharesHAHold holds (or lets go of) a shared folder that moves to the
// storage server with an app made highly available (decision 501):
// file sharing lets go of it, then it is read-only, unmounted and marked
// until its conversion parks it or gives up.
const OpSharesHAHold = "shares.ha.hold"

// HACopyShares gives root's copy the shared folders' own rules: file
// sharing lets go of a folder before it is parked and takes up every
// change (the share hooks, as for a delete), and a folder whose id or
// name this server has is never adopted over it.
func HACopyShares(r *hacopy.Root, m *shares.Manager, hooks []ShareHook) {
	if r == nil || m == nil {
		return
	}
	r.ShareRelease = func(ctx context.Context, id string) func() {
		runBeforeDelete(ctx, hooks, id)
		return func() { runAfterDelete(context.WithoutCancel(ctx), hooks, id) }
	}
	r.ShareChanged = func(ctx context.Context) { runChanged(ctx, hooks) }
	r.ShareTaken = m.Taken
}

// RegisterShareHold adds shares.ha.hold.
func RegisterShareHold(s *Server, m *shares.Manager, hooks []ShareHook) {
	if m == nil {
		return
	}
	s.Handle(OpSharesHAHold, typed(func(ctx context.Context, a shares.HAHoldArgs) (any, error) {
		if err := shares.ValidID(a.ID); err != nil {
			return nil, sharesErr(err)
		}
		if !a.Release {
			// SMB closes it (its open files too), NFS stops exporting it,
			// SFTP lets go: an unmount of a folder in use fails.
			runBeforeDelete(ctx, hooks, a.ID)
		}
		err := m.HAHold(ctx, a)
		if !a.Release {
			// File sharing's own holds end (as after a delete): a held
			// folder lists as not mounted, so nothing serves it, and one
			// that wasn't held is taken up again as it was.
			runAfterDelete(ctx, hooks, a.ID)
		}
		runChanged(ctx, hooks)
		return map[string]bool{"ok": err == nil}, sharesErr(err)
	}))
}
