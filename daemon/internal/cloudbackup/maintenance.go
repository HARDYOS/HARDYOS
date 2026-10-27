package cloudbackup

import (
	"context"
)

// StartPrune removes data no version needs any more (after retention
// forgot old versions).
func (r *Root) StartPrune(target string) (*Task, error) {
	repo, err := r.repo(target)
	if err != nil {
		return nil, err
	}
	return r.tasks.start(TaskPrune, target, func(ctx context.Context, tc taskCtx) (any, error) {
		tc.progress(5, "Freeing space no version needs")
		defer snapshotCache.drop(target)
		return map[string]bool{"pruned": true}, r.Restic.Prune(ctx, repo)
	})
}

// MaxCheckPercent bounds how much a check reads back.
const MaxCheckPercent = 100

// StartCheck checks the repository and reads back percent% of its data.
func (r *Root) StartCheck(target string, percent int) (*Task, error) {
	if percent < 0 || percent > MaxCheckPercent {
		return nil, problemf("read back 0-100%% of the data")
	}
	repo, err := r.repo(target)
	if err != nil {
		return nil, err
	}
	return r.tasks.start(TaskCheck, target, func(ctx context.Context, tc taskCtx) (any, error) {
		tc.progress(5, "Checking the backups")
		return map[string]int{"percent": percent}, r.Restic.Check(ctx, repo, percent)
	})
}
