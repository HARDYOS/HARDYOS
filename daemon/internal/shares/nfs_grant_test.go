package shares

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func TestNFSGrantAndRevoke(t *testing.T) {
	m, f, root, calls := newManager(t)
	ctx := context.Background()
	media := filepath.Join(root, "mnt/tank/shares/media")
	mkdir(t, media)
	onList(f, "", rows(
		row{ds: "tank/shares/media", name: "Media", mounted: true},
		row{ds: "tank/shares/offline", name: "Offline", mounted: false},
	))
	f.OnPrefix("setfacl ", sysexec.Result{})

	for _, uid := range []int{0, 30001, 30999, 32000} {
		if err := m.GrantNFS(ctx, "media", uid, true); !isValidation(err) {
			t.Errorf("GrantNFS(%d) = %v", uid, err)
		}
	}
	if err := m.GrantNFS(ctx, "offline", 31000, false); err == nil || !strings.Contains(err.Error(), "isn't available") {
		t.Errorf("unmounted: %v", err)
	}
	if err := m.GrantNFS(ctx, "ghost", 31000, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
	if err := m.GrantNFS(ctx, "media", 31000, false); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if err := m.GrantNFS(ctx, "media", 31000, true); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if err := m.RevokeNFS(ctx, "media", 31000); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	lines := f.Lines()
	for _, want := range []string{
		"setfacl -m u:31000:r-X,d:u:31000:r-X -- " + media,
		"setfacl -m u:31000:rwX,d:u:31000:rwX -- " + media,
		"setfacl -x u:31000,d:u:31000 -- " + media,
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("missing %s\ngot %s", want, strings.Join(lines, "\n    "))
		}
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "zfs set") {
			t.Errorf("NFS access isn't recorded as an app: %s", l)
		}
	}
	want := []treeCall{{media, 31000, false, false}, {media, 31000, true, false}, {media, 31000, false, true}}
	if !slices.Equal(*calls, want) {
		t.Errorf("background walks = %+v", *calls)
	}
}
