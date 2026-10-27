package priv

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/snapshots"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func TestShareHooksFollowChanges(t *testing.T) {
	f := &sysexec.Fake{}
	f.OnPrefix("zfs list -Hp -t filesystem", sysexec.Result{}) // no shared folders
	m := &shares.Manager{Runner: f, Root: t.TempDir()}
	var mu sync.Mutex
	var got []string
	s := &Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	RegisterShares(s, m, ShareHook{
		BeforeDelete: func(_ context.Context, id string) error {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, "before "+id)
			return nil
		},
		Changed: func(context.Context) {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, "changed")
		},
	})
	RegisterSnapshots(s, &snapshots.Manager{Runner: f, Shares: m})
	c := NewClient(startServer(t, s))
	ctx := context.Background()
	guest := true
	// Both fail (there's no such folder), and the hooks still run.
	_ = c.Call(ctx, OpSharesUpdate, shares.ShareUpdate{ID: "media", Guest: &guest}, nil)
	_ = c.Call(ctx, OpSharesDelete, ShareDeleteArgs{ID: "media", Confirm: "Media"}, nil)
	_ = c.Call(ctx, OpSharesList, nil, nil) // reading changes nothing
	if want := []string{"changed", "before media", "changed"}; !slices.Equal(got, want) {
		t.Errorf("hooks ran %v, want %v", got, want)
	}

	var res SnapshotsResult
	err := c.Call(ctx, OpSnapshotsList, SnapshotsListArgs{Share: "media"}, &res)
	var pe *Error
	if err == nil || !strings.Contains(err.Error(), "no shared folder") {
		t.Errorf("list of a missing folder = %v", err)
	} else if !errors.As(err, &pe) || pe.Code != CodeBadArgs {
		t.Errorf("code = %v", err)
	}
	if err := c.Call(ctx, OpSnapshotsDelete, map[string]any{"share": "media", "snapshot": "x", "confirm": "x", "recursive": true}, nil); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("unknown arguments accepted: %v", err)
	}
}
