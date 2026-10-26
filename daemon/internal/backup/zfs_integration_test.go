package backup

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// TestZFSBackupIntegration keeps backups on a real (file-backed) pool. It
// writes to /var/lib/hardyos/backups, so like the other ZFS tests it only
// runs as root on a throwaway machine (CI's "ZFS integration" job).
func TestZFSBackupIntegration(t *testing.T) {
	if os.Getenv("HARDYOS_ZFS_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_ZFS_INTEGRATION=1 to run against real ZFS (needs root)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dir := t.TempDir()
	vdev := filepath.Join(dir, "vdev")
	f, err := os.Create(vdev)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Truncate(256 << 20)
	f.Close()
	const pool = "hardyosbak"
	_ = exec.Command("zpool", "destroy", "-f", pool).Run()
	if out, err := exec.Command("zpool", "create", "-m", filepath.Join(dir, "mnt"), pool, vdev).CombinedOutput(); err != nil {
		t.Fatalf("zpool create: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("zpool", "destroy", "-f", pool).Run() })

	r := &Root{Runner: sysexec.Exec{}, Root: "/", UID: -1, GID: -1}
	pools, err := r.DataPools(ctx)
	if err != nil || !strings.Contains(strings.Join(pools, " "), pool) {
		t.Fatalf("pools = %v %v", pools, err)
	}
	work := "/" + WorkDir
	_ = os.MkdirAll(work, 0o750)
	src := filepath.Join(work, "made-integration.hbak")
	defer os.Remove(src)

	c := sample()
	for i := 0; i < 3; i++ {
		c.Manifest.CreatedAt = c.Manifest.CreatedAt.Add(time.Hour)
		b, _ := Pack(c, "")
		if err := os.WriteFile(src, b, 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Store(ctx, pool, src, 2); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
	}
	// The dataset was created and mounted under the pool.
	if out, _ := exec.Command("zfs", "get", "-H", "-o", "value", "mounted", pool+"/"+PoolDataset).Output(); strings.TrimSpace(string(out)) != "yes" {
		t.Fatalf("%s/%s mounted = %q", pool, PoolDataset, out)
	}
	list, err := r.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var mine []PoolBackup
	for _, b := range list {
		if b.Pool == pool {
			mine = append(mine, b)
		}
	}
	if len(mine) != 2 || mine[0].Manifest.Hostname != "nas" {
		t.Fatalf("kept = %+v", mine)
	}
	path, err := r.Fetch(ctx, pool, mine[0].Name)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	b, _ := os.ReadFile(path)
	if got, err := Unpack(b, ""); err != nil || !got.Manifest.CreatedAt.Equal(mine[0].Manifest.CreatedAt) {
		t.Fatalf("fetched = %+v %v", got, err)
	}
}
