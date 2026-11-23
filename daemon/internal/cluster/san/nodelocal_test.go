package san

import (
	"context"
	"errors"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// The NetBird standby and the webmail are one server's apps: root never
// makes, snapshots, exports or destroys cluster storage under their names
// (decision 472), and nothing runs before the refusal.
func TestNodeLocalAppsAreNeverClusterStorage(t *testing.T) {
	r, _, fx := newRoot(t)
	ctx := context.Background()
	for _, id := range NodeLocalApps {
		w := WorkloadArgs{Kind: cluster.KindApp, ID: id, Pool: "tank"}
		var ve *ValidationError
		if _, err := r.DatasetCreate(ctx, DatasetCreateArgs{WorkloadArgs: w, UID: 30001}); !errors.As(err, &ve) {
			t.Errorf("%s: dataset create = %v", id, err)
		}
		if err := w.check(); !errors.As(err, &ve) {
			t.Errorf("%s: check = %v", id, err)
		}
	}
	if l := fx.Lines(); len(l) != 0 {
		t.Fatalf("commands ran: %v", l)
	}
	// A VM may still be called that, and other apps are fine.
	if err := (WorkloadArgs{Kind: cluster.KindVM, ID: "roundcube", Pool: "tank"}).check(); err != nil {
		t.Fatal(err)
	}
	if err := (WorkloadArgs{Kind: cluster.KindApp, ID: "nextcloud", Pool: "tank"}).check(); err != nil {
		t.Fatal(err)
	}
}
