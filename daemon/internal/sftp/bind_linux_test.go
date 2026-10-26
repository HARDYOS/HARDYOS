//go:build linux

package sftp

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/shares"
)

// A view is only ever bound from a verified mount: no device (unverified)
// or another device means no bind mount at all.
func TestBindNeedsTheVerifiedMount(t *testing.T) {
	d := t.TempDir()
	src, dst := filepath.Join(d, "src"), filepath.Join(d, "dst")
	os.Mkdir(src, 0o755)
	os.Mkdir(dst, 0o755)
	var st syscall.Stat_t
	syscall.Stat(src, &st)
	for _, dev := range []uint64{0, uint64(st.Dev) + 1} {
		if err := (SysMounter{}).Bind(src, dev, dst, true); !errors.Is(err, shares.ErrUnverified) {
			t.Errorf("Bind with device %d = %v", dev, err)
		}
	}
	os.Symlink(src, filepath.Join(d, "link"))
	if err := (SysMounter{}).Bind(filepath.Join(d, "link"), uint64(st.Dev), dst, true); err == nil {
		t.Error("bound through a link")
	}
	if ok, _ := (SysMounter{}).IsMount(dst); ok {
		t.Error("something was mounted")
	}
}
