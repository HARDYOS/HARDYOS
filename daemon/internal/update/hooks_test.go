package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStageRunsHooksBeforeTheBootMenu(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	var gotRoot string
	syncedBefore := false
	w.u.Hooks = []Hook{{Name: "Rebuilding the NVIDIA driver", Run: func(_ context.Context, newRoot string) error {
		gotRoot = newRoot
		syncedBefore = w.has("grub-editenv")
		// The new system is unpacked and finished when the hook runs.
		if _, err := os.Stat(filepath.Join(w.root, newRoot, "boot/initrd.img-6.12.2")); err != nil {
			t.Errorf("hook ran before the system was finished: %v", err)
		}
		return nil
	}}}
	if _, err := w.u.Stage(ctx, w.upload("0.2.0")); err != nil {
		t.Fatal(err)
	}
	if gotRoot != "/run/hardyos/update/root" || syncedBefore {
		t.Fatalf("hook root %q, boot menu already changed: %v", gotRoot, syncedBefore)
	}
}

func TestFailingHookKeepsCurrentVersion(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.u.Hooks = []Hook{{Name: "Rebuilding the NVIDIA driver", Run: func(context.Context, string) error {
		return errors.New("the NVIDIA driver couldn't be built for the new version's kernel 6.12.2")
	}}}
	_, err := w.u.Stage(ctx, w.upload("0.2.0"))
	if err == nil || !strings.Contains(err.Error(), "Rebuilding the NVIDIA driver: the NVIDIA driver couldn't be built for the new version's kernel 6.12.2; HardyOS stays on the current version") {
		t.Fatalf("stage: %v", err)
	}
	if !w.has("zfs destroy -r rpool/ROOT/hardyos-0.2.0") {
		t.Error("the new boot environment wasn't removed")
	}
	if w.has("grub-editenv") {
		t.Error("the failed version was chosen for the next boot")
	}
	if p, _ := w.u.PendingUpdate(); p != nil {
		t.Fatalf("pending = %+v", p)
	}
}
