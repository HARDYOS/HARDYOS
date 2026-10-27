package cloudbackup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// Volumes is the ZFS work a backup or restore does: snapshots mounted
// read-only at a stable folder (so restic finds the previous version of
// each file by its path), clones of disk snapshots read as streams, and
// private staging datasets restores unpack into.
type Volumes interface {
	// Snapshot takes dataset@name.
	Snapshot(ctx context.Context, dataset, name string) error
	// DestroySnapshot removes dataset@name (only that one).
	DestroySnapshot(ctx context.Context, dataset, name string) error
	// MountSnapshot mounts dataset@name read-only at dir (made, root 0700
	// parents).
	MountSnapshot(ctx context.Context, dataset, name, dir string) error
	// Unmount unmounts dir.
	Unmount(ctx context.Context, dir string) error
	// OpenZvolSnapshot opens a zvol snapshot's contents for reading; close
	// the reader when done (it also removes the clone behind it).
	OpenZvolSnapshot(ctx context.Context, dataset, name string) (io.ReadCloser, error)
	// CreateStaging makes a private dataset on pool for a restore and
	// returns its mounted folder and that mount's device.
	CreateStaging(ctx context.Context, pool, name string) (dir string, dev uint64, err error)
	// DestroyStaging removes it.
	DestroyStaging(ctx context.Context, pool, name string) error
	// VerifyMount returns the device of dataset's own mount at dir
	// (shares.MountVerifier).
	VerifyMount(dir, dataset string) (uint64, error)
}

// DefaultRunDir is where snapshots are mounted and staging datasets live:
// root only.
const DefaultRunDir = "/run/hardyos-backup"

// Datasets HardyOS makes on a pool for backups.
const (
	StagingParent = "hardyos-restore"    // <pool>/hardyos-restore/<id>
	CloneParent   = "hardyos-backup-tmp" // <pool>/hardyos-backup-tmp/<id>
)

var snapLabelRE = regexp.MustCompile(`^hardyos-(cloud|manual)-[a-z0-9-]{1,60}$`)
var stageNameRE = regexp.MustCompile(`^[a-z0-9-]{1,48}$`)

// ZFS is the real Volumes.
type ZFS struct {
	Runner sysexec.Runner
	RunDir string
}

func (z *ZFS) runDir() string {
	if z.RunDir != "" {
		return z.RunDir
	}
	return DefaultRunDir
}

func (z *ZFS) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return sysexec.Output(ctx, z.Runner, name, args...)
}

func checkDataset(ds string) error {
	pool, rest, ok := strings.Cut(ds, "/")
	if !ok || zfs.ValidPoolName(pool) != nil || rest == "" || strings.ContainsAny(ds, "@ \t\n") || strings.Contains(ds, "..") {
		return fmt.Errorf("bad dataset %q", ds)
	}
	return nil
}

// Snapshot implements Volumes.
func (z *ZFS) Snapshot(ctx context.Context, dataset, name string) error {
	if checkDataset(dataset) != nil || !snapLabelRE.MatchString(name) {
		return fmt.Errorf("bad snapshot %s@%s", dataset, name)
	}
	_, err := z.run(ctx, "zfs", "snapshot", dataset+"@"+name)
	return err
}

// DestroySnapshot implements Volumes.
func (z *ZFS) DestroySnapshot(ctx context.Context, dataset, name string) error {
	if checkDataset(dataset) != nil || !strings.HasPrefix(name, "hardyos-cloud-") || !snapLabelRE.MatchString(name) {
		return fmt.Errorf("bad snapshot %s@%s", dataset, name)
	}
	_, err := z.run(ctx, "zfs", "destroy", dataset+"@"+name)
	return err
}

// ensureRunDir makes the root-only folder everything is mounted below.
func ensureRunDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s isn't a folder", dir)
	}
	return os.Chmod(dir, 0o700)
}

func (z *ZFS) under(dir string) error {
	base := z.runDir()
	if !strings.HasPrefix(filepath.Clean(dir), base+"/") || filepath.Clean(dir) != dir {
		return fmt.Errorf("%s isn't below %s", dir, base)
	}
	return ensureRunDir(base)
}

// MountSnapshot implements Volumes.
func (z *ZFS) MountSnapshot(ctx context.Context, dataset, name, dir string) error {
	if checkDataset(dataset) != nil || !snapLabelRE.MatchString(name) {
		return fmt.Errorf("bad snapshot %s@%s", dataset, name)
	}
	if err := z.under(dir); err != nil {
		return err
	}
	// A mount left over from a run that was killed goes first.
	_ = z.Unmount(ctx, dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	_, err := z.run(ctx, "mount", "-t", "zfs", "-o", "ro,nodev,nosuid,noexec", dataset+"@"+name, dir)
	return err
}

// Unmount implements Volumes.
func (z *ZFS) Unmount(ctx context.Context, dir string) error {
	if !strings.HasPrefix(filepath.Clean(dir), z.runDir()+"/") {
		return fmt.Errorf("%s isn't below %s", dir, z.runDir())
	}
	t, err := shares.ReadMountTable()
	if err != nil {
		return err
	}
	mounted := false
	for _, e := range t {
		mounted = mounted || e.Mountpoint == dir
	}
	if !mounted {
		return nil
	}
	_, err = z.run(ctx, "umount", dir)
	return err
}

// OpenZvolSnapshot implements Volumes: a read-only clone of the snapshot,
// whose device node is opened and read; closing removes the clone.
func (z *ZFS) OpenZvolSnapshot(ctx context.Context, dataset, name string) (io.ReadCloser, error) {
	if checkDataset(dataset) != nil || !snapLabelRE.MatchString(name) {
		return nil, fmt.Errorf("bad snapshot %s@%s", dataset, name)
	}
	pool, _, _ := strings.Cut(dataset, "/")
	parent := pool + "/" + CloneParent
	if _, err := z.run(ctx, "zfs", "list", "-H", "-o", "name", parent); err != nil {
		if _, err := z.run(ctx, "zfs", "create", "-o", "canmount=off", parent); err != nil {
			return nil, fmt.Errorf("creating %s: %w", parent, err)
		}
	}
	clone := parent + "/" + randomID(8)
	if _, err := z.run(ctx, "zfs", "clone", "-o", "readonly=on", dataset+"@"+name, clone); err != nil {
		return nil, fmt.Errorf("cloning %s: %w", dataset, err)
	}
	drop := func() {
		for i := 0; i < 10; i++ {
			if _, err := z.run(context.Background(), "zfs", "destroy", clone); err == nil {
				return
			}
			time.Sleep(time.Second) // udev may still hold the device
		}
	}
	dev := "/dev/zvol/" + clone
	var f *os.File
	var err error
	for i := 0; i < 120; i++ {
		f, err = os.Open(dev)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			drop()
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	if err != nil {
		drop()
		return nil, fmt.Errorf("the disk snapshot's device didn't appear: %w", err)
	}
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeDevice == 0 {
		f.Close()
		drop()
		return nil, errors.New("the disk snapshot isn't a block device")
	}
	return &zvolReader{File: f, drop: drop}, nil
}

type zvolReader struct {
	*os.File
	drop func()
}

func (z *zvolReader) Close() error {
	err := z.File.Close()
	z.drop()
	return err
}

// CreateStaging implements Volumes.
func (z *ZFS) CreateStaging(ctx context.Context, pool, name string) (string, uint64, error) {
	if zfs.ValidPoolName(pool) != nil || !stageNameRE.MatchString(name) {
		return "", 0, fmt.Errorf("bad staging %s/%s", pool, name)
	}
	parent := pool + "/" + StagingParent
	if _, err := z.run(ctx, "zfs", "list", "-H", "-o", "name", parent); err != nil {
		if _, err := z.run(ctx, "zfs", "create", "-o", "canmount=off", "-o", "mountpoint=none", parent); err != nil {
			return "", 0, fmt.Errorf("creating %s: %w", parent, err)
		}
	}
	base := filepath.Join(z.runDir(), "restore")
	if err := ensureRunDir(z.runDir()); err != nil {
		return "", 0, err
	}
	if err := ensureRunDir(base); err != nil {
		return "", 0, err
	}
	dir := filepath.Join(base, name)
	ds := parent + "/" + name
	if _, err := z.run(ctx, "zfs", "create", "-o", "mountpoint="+dir, "-o", "devices=off", "-o", "setuid=off", "-o", "exec=off",
		"-o", "acltype=posixacl", "-o", "xattr=sa", ds); err != nil {
		return "", 0, fmt.Errorf("creating the restore's work space: %w", err)
	}
	dev, err := z.VerifyMount(dir, ds)
	if err != nil {
		_, _ = z.run(context.Background(), "zfs", "destroy", "-r", ds)
		return "", 0, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", 0, err
	}
	return dir, dev, nil
}

// DestroyStaging implements Volumes.
func (z *ZFS) DestroyStaging(ctx context.Context, pool, name string) error {
	if zfs.ValidPoolName(pool) != nil || !stageNameRE.MatchString(name) {
		return fmt.Errorf("bad staging %s/%s", pool, name)
	}
	_, err := z.run(ctx, "zfs", "destroy", "-r", pool+"/"+StagingParent+"/"+name)
	return err
}

// VerifyMount implements Volumes.
func (z *ZFS) VerifyMount(dir, dataset string) (uint64, error) {
	t, err := shares.ReadMountTable()
	if err != nil {
		return 0, err
	}
	return t.VerifyMount(dir, dataset)
}
