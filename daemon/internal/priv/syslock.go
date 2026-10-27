package priv

import (
	"context"

	"github.com/hardyos/hardyos/daemon/internal/syslock"
)

// withSystemLock runs fn holding the system lock (syslock): boot menu
// changes, updates and GPU driver tasks never overlap. It waits for the
// lock as long as the operation may run.
func withSystemLock[A any](what string, fn func(context.Context, A) (any, error)) func(context.Context, A) (any, error) {
	return func(ctx context.Context, a A) (any, error) {
		release, err := syslock.Acquire(ctx, what)
		if err != nil {
			return nil, Errorf(CodeFailed, "%v", err)
		}
		defer release()
		return fn(ctx, a)
	}
}
