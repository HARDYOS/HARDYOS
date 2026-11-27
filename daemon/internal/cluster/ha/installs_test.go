package ha_test

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha/clustertest"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// An unattended install that ends on a cluster VM keeps it starting
// (decision 486): its owner records exactly root's own change of the
// settings as approved - only when the placement still has the hash from
// before it and the stored settings hash as root said after it.
func TestInstallCompletionIsApproved(t *testing.T) {
	w := clustertest.New(t, "c1", "c2")
	vm := w.AddVM("win", "c1", true, 50)
	before := w.Snapshot().Placements[vm].SpecHash
	after := "sha256:" + strings.Repeat("b", 64)
	var mu sync.Mutex
	stored := after
	pending := []map[string]string{{"id": "win", "before": before, "after": after}}
	// The test's own user may connect (CI doesn't run unit tests as root).
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	ps.Handle(priv.OpVMsClusterInstall, func(_ context.Context, raw json.RawMessage) (any, error) {
		var a struct {
			Ack []string `json:"ack"`
		}
		_ = json.Unmarshal(raw, &a)
		mu.Lock()
		defer mu.Unlock()
		if len(a.Ack) > 0 {
			pending = nil
		}
		return map[string]any{"done": pending}, nil
	})
	ps.Handle(priv.OpVMsClusterHash, func(context.Context, json.RawMessage) (any, error) {
		mu.Lock()
		defer mu.Unlock()
		return priv.SpecHashResult{Hash: stored}, nil
	})
	dir, err := os.MkdirTemp("", "hi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "p.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ps.Serve(ctx, ln.(*net.UnixListener)) }()
	svc := &ha.Service{Priv: priv.NewClient(filepath.Join(dir, "p.sock")), Parts: ha.Parts{Membership: w.Nodes["c1"]}}

	// Settings changed by something else since: not approved.
	mu.Lock()
	stored = "sha256:" + strings.Repeat("e", 64)
	mu.Unlock()
	svc.ApproveInstallsOnce(ctx)
	if got := w.Snapshot().Placements[vm].SpecHash; got != before {
		t.Fatalf("approved settings that aren't root's own change: %s", got)
	}
	// Root's own change: approved, and acknowledged.
	mu.Lock()
	stored = after
	pending = []map[string]string{{"id": "win", "before": before, "after": after}}
	mu.Unlock()
	svc.ApproveInstallsOnce(ctx)
	if got := w.Snapshot().Placements[vm].SpecHash; got != after {
		t.Fatalf("the install's change wasn't approved: %s", got)
	}
	mu.Lock()
	left := len(pending)
	mu.Unlock()
	if left != 0 {
		t.Fatal("the approved record wasn't acknowledged")
	}
	// Another server's VM is never approved here.
	svc2 := &ha.Service{Priv: svc.Priv, Parts: ha.Parts{Membership: w.Nodes["c2"]}}
	mu.Lock()
	pending = []map[string]string{{"id": "win", "before": after, "after": before}}
	stored = before
	mu.Unlock()
	svc2.ApproveInstallsOnce(ctx)
	if got := w.Snapshot().Placements[vm].SpecHash; got != after {
		t.Fatalf("a server approved settings of a VM placed elsewhere: %s", got)
	}
	_ = cluster.KindVM
}
