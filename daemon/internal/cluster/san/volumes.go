package san

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Limits on cluster volumes.
const (
	MaxVolumeGB = 64 * 1024
	// BlockFSs are the file systems an app's block volume may have.
	BlockExt4 = "ext4"
	BlockXFS  = "xfs"
)

var snapRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

// MaxSnapshots is the most snapshots a cluster workload's dataset may
// have (M4: a node asking for snapshots of its own workloads can't pile
// them up on the storage node).
const MaxSnapshots = 512

// WorkloadArgs names a workload's storage on a pool.
type WorkloadArgs struct {
	Kind cluster.WorkloadKind `json:"kind"`
	ID   string               `json:"id"`
	Pool string               `json:"pool"`
}

func (a WorkloadArgs) check() error {
	if a.Kind != cluster.KindVM && a.Kind != cluster.KindApp {
		return &ValidationError{fmt.Errorf("kind %q isn't vm or app", a.Kind)}
	}
	if !idRE.MatchString(a.ID) {
		return &ValidationError{fmt.Errorf("%q isn't a valid workload id", a.ID)}
	}
	if !poolRE.MatchString(a.Pool) {
		return &ValidationError{fmt.Errorf("%q isn't a valid pool name", a.Pool)}
	}
	return nil
}

// Dataset is the workload's dataset: <pool>/vms/<id> or <pool>/apps/<id>.
func (a WorkloadArgs) Dataset() string {
	if a.Kind == cluster.KindApp {
		return a.Pool + "/apps/" + a.ID
	}
	return a.Pool + "/vms/" + a.ID
}

func (a WorkloadArgs) ref() cluster.WorkloadRef { return cluster.WorkloadRef{Kind: a.Kind, ID: a.ID} }

// DatasetCreateArgs is san.dataset.create.
type DatasetCreateArgs struct {
	WorkloadArgs
	// UID owns an app's data folder (its cluster-wide app user id).
	UID int `json:"uid,omitempty"`
	// QuotaGB caps a VM's state dataset (0: 1 GB).
	QuotaGB int `json:"quotaGB,omitempty"`
}

// DatasetInfo describes a workload's dataset.
type DatasetInfo struct {
	Dataset    string `json:"dataset"`
	Mountpoint string `json:"mountpoint"`
	GUID       string `json:"guid"`
	Used       int64  `json:"used"`
}

// DatasetCreate makes a workload's dataset, marked as cluster storage.
func (r *Root) DatasetCreate(ctx context.Context, a DatasetCreateArgs) (*DatasetInfo, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	if a.Kind == cluster.KindApp && (a.UID < 30000 || a.UID > 30999) {
		return nil, &ValidationError{errors.New("an app's data needs its app user id (30000-30999)")}
	}
	parent := a.Pool + "/vms"
	prop := PropVM
	if a.Kind == cluster.KindApp {
		parent, prop = a.Pool+"/apps", PropApp
	}
	if _, err := r.zfs(ctx, "list", "-H", "-o", "name", parent); err != nil {
		if _, err := r.zfs(ctx, "create", parent); err != nil {
			return nil, fmt.Errorf("creating %s: %w", parent, err)
		}
	}
	if err := r.ensureParentQuota(ctx, a.Pool, parent); err != nil {
		return nil, err
	}
	ds := a.Dataset()
	if _, err := r.zfs(ctx, "list", "-H", "-o", "name", ds); err == nil {
		return nil, &ValidationError{fmt.Errorf("%s already exists", ds)}
	}
	args := []string{"create", "-o", prop + "=" + a.ID, "-o", PropRole + "=" + RoleCluster,
		"-o", "canmount=on", "-o", "devices=off", "-o", "setuid=off"}
	if a.Kind == cluster.KindVM {
		q := a.QuotaGB
		if q <= 0 {
			q = 1
		}
		args = append(args, "-o", "exec=off", "-o", "quota="+strconv.Itoa(q)+"G")
	}
	args = append(args, ds)
	if _, err := r.zfs(ctx, args...); err != nil {
		return nil, fmt.Errorf("creating %s: %w", ds, err)
	}
	info, err := r.datasetInfo(ctx, ds)
	if err != nil {
		return nil, err
	}
	if a.Kind == cluster.KindApp {
		if err := os.Chown(r.sys(info.Mountpoint), a.UID, a.UID); err != nil {
			return nil, fmt.Errorf("giving the app its folder: %w", err)
		}
		if err := os.Chmod(r.sys(info.Mountpoint), 0o750); err != nil {
			return nil, err
		}
	}
	r.log().Info("san: dataset created", "dataset", ds)
	return info, nil
}

// ParentQuotaPercent is the share of a pool that <pool>/vms and
// <pool>/apps may each use at most (L5): cluster zvols are sparse, so a
// compute node writing its volumes full can't fill the storage node's
// pool and stop everything else on it (shares, the system, backups).
const ParentQuotaPercent = 90

// ensureParentQuota caps <pool>/vms or <pool>/apps when it has no quota
// yet (an administrator's own quota is kept).
func (r *Root) ensureParentQuota(ctx context.Context, pool, parent string) error {
	p, err := r.props(ctx, parent, "quota")
	if err != nil {
		return err
	}
	if q := p["quota"]; q != "" && q != "0" && q != "-" && q != "none" {
		return nil
	}
	pp, err := r.props(ctx, pool, "used", "available")
	if err != nil {
		return err
	}
	used, _ := strconv.ParseUint(pp["used"], 10, 64)
	avail, _ := strconv.ParseUint(pp["available"], 10, 64)
	total := used + avail
	if total == 0 {
		r.log().Warn("san: can't read the pool's size; the cluster datasets stay uncapped", "pool", pool)
		return nil
	}
	q := total / 100 * ParentQuotaPercent
	if _, err := r.zfs(ctx, "set", "quota="+strconv.FormatUint(q, 10), parent); err != nil {
		return fmt.Errorf("capping %s: %w", parent, err)
	}
	return nil
}

func (r *Root) datasetInfo(ctx context.Context, ds string) (*DatasetInfo, error) {
	p, err := r.props(ctx, ds, "mountpoint", "guid", "used")
	if err != nil {
		return nil, err
	}
	used, _ := strconv.ParseInt(p["used"], 10, 64)
	return &DatasetInfo{Dataset: ds, Mountpoint: p["mountpoint"], GUID: p["guid"], Used: used}, nil
}

// DatasetInfo reports a cluster workload's dataset (checked like an
// export).
func (r *Root) DatasetInfo(ctx context.Context, a WorkloadArgs) (*DatasetInfo, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	if err := r.checkOwned(ctx, a, a.Dataset()); err != nil {
		return nil, err
	}
	return r.datasetInfo(ctx, a.Dataset())
}

// ShareArgs names a shared folder on this storage node.
type ShareArgs struct {
	Pool string `json:"pool"`
	ID   string `json:"id"`
}

// ShareInfo reports a shared folder's dataset, mountpoint and GUID (for
// "Use in the cluster"); the dataset must be the folder's own.
func (r *Root) ShareInfo(ctx context.Context, a ShareArgs) (*DatasetInfo, error) {
	if !poolRE.MatchString(a.Pool) || !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`).MatchString(a.ID) {
		return nil, &ValidationError{fmt.Errorf("shared folder %s/%s isn't valid", a.Pool, a.ID)}
	}
	ds := a.Pool + "/shares/" + a.ID
	p, err := r.props(ctx, ds, "type", "org.hardyos:share", "mounted")
	if err != nil {
		return nil, err
	}
	if p["type"] != "filesystem" || p["org.hardyos:share"] != a.ID || p["mounted"] != "yes" {
		return nil, &ValidationError{fmt.Errorf("%s isn't a mounted shared folder", ds)}
	}
	return r.datasetInfo(ctx, ds)
}

// checkOwned verifies that ds is a cluster dataset or zvol of the workload.
func (r *Root) checkOwned(ctx context.Context, a WorkloadArgs, ds string) error {
	prop := ownerProp(a.Kind)
	p, err := r.props(ctx, ds, prop, PropRole)
	if err != nil {
		return err
	}
	if p[prop] != a.ID || p[PropRole] != RoleCluster {
		return &ValidationError{fmt.Errorf("%s isn't %s %s's cluster storage", ds, a.Kind, a.ID)}
	}
	return nil
}

// inUse reports whether root currently maps or exports anything of the
// workload (destroy and rollback refuse then).
func (r *Root) inUse(a WorkloadArgs) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil {
		return false, err
	}
	if st.Desired.UsesDataset(a.Dataset()) {
		return true, nil
	}
	for _, e := range st.Exports {
		if e.Dataset == a.Dataset() {
			return true, nil
		}
	}
	return false, nil
}

// DestroyArgs is san.dataset.destroy and san.volume.destroy: Confirm must
// be the workload's id.
type DestroyArgs struct {
	WorkloadArgs
	Disk    string `json:"disk,omitempty"`
	Confirm string `json:"confirm"`
}

// DatasetDestroy destroys a workload's dataset with everything under it
// (its zvols and snapshots). Refused while anything of it is mapped or
// exported.
func (r *Root) DatasetDestroy(ctx context.Context, a DestroyArgs) error {
	if err := a.check(); err != nil {
		return err
	}
	if a.Confirm != a.ID {
		return &ValidationError{errors.New("type the name to destroy its storage")}
	}
	if err := r.checkOwned(ctx, a.WorkloadArgs, a.Dataset()); err != nil {
		return err
	}
	if busy, err := r.inUse(a.WorkloadArgs); err != nil || busy {
		if err == nil {
			err = &ValidationError{fmt.Errorf("%s is still granted to a server; stop and remove it from the cluster first", a.ID)}
		}
		return err
	}
	if _, err := r.zfs(ctx, "destroy", "-r", a.Dataset()); err != nil {
		return fmt.Errorf("destroying %s: %w", a.Dataset(), err)
	}
	r.log().Warn("san: dataset destroyed", "dataset", a.Dataset())
	return nil
}

// VolumeArgs is san.volume.create and san.volume.resize.
type VolumeArgs struct {
	WorkloadArgs
	// Disk: disk0..disk9 for VMs, "block" for an app's block volume.
	Disk   string `json:"disk"`
	SizeGB int    `json:"sizeGB"`
	// FS formats an app's block volume (ext4 or xfs) on create.
	FS string `json:"fs,omitempty"`
}

func (a VolumeArgs) dataset() (string, error) {
	switch a.Kind {
	case cluster.KindVM:
		if !diskRE.MatchString(a.Disk) {
			return "", &ValidationError{fmt.Errorf("disk %q must be disk0 to disk9", a.Disk)}
		}
		return VMDisk(a.Pool, a.ID, a.Disk), nil
	case cluster.KindApp:
		if a.Disk != "block" {
			return "", &ValidationError{errors.New("an app's volume is its block volume")}
		}
		return AppBlock(a.Pool, a.ID), nil
	}
	return "", &ValidationError{errors.New("bad kind")}
}

// VolumeInfo describes a zvol.
type VolumeInfo struct {
	Dataset string `json:"dataset"`
	GUID    string `json:"guid"`
	WWN     string `json:"wwn"`
	SizeGB  int    `json:"sizeGB"`
}

// VolumeCreate makes a sparse zvol under the workload's dataset, marked as
// cluster storage, and formats an app's block volume here on the storage
// node (it has never been mapped anywhere yet).
func (r *Root) VolumeCreate(ctx context.Context, c cluster.ClusterID, a VolumeArgs) (*VolumeInfo, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	if err := ValidCluster(c); err != nil {
		return nil, &ValidationError{err}
	}
	if a.SizeGB < 1 || a.SizeGB > MaxVolumeGB {
		return nil, &ValidationError{fmt.Errorf("size must be 1-%d GB", MaxVolumeGB)}
	}
	ds, err := a.dataset()
	if err != nil {
		return nil, err
	}
	if a.Kind == cluster.KindApp && a.FS != BlockExt4 && a.FS != BlockXFS {
		return nil, &ValidationError{errors.New("a block volume's file system must be ext4 or xfs")}
	}
	if err := r.checkOwned(ctx, a.WorkloadArgs, a.Dataset()); err != nil {
		return nil, err
	}
	if _, err := r.zfs(ctx, "list", "-H", "-o", "name", ds); err == nil {
		return nil, &ValidationError{fmt.Errorf("%s already exists", ds)}
	}
	vbs := "16K"
	if a.Kind == cluster.KindApp {
		vbs = "8K" // databases write small pages
	}
	if _, err := r.zfs(ctx, "create", "-s", "-V", strconv.Itoa(a.SizeGB)+"G", "-o", "volblocksize="+vbs,
		"-o", ownerProp(a.Kind)+"="+a.ID, "-o", PropRole+"="+RoleCluster, "-o", "volmode=dev", ds); err != nil {
		return nil, fmt.Errorf("creating %s: %w", ds, err)
	}
	dev := "/dev/zvol/" + ds
	if err := r.waitDevice(ctx, dev); err != nil {
		return nil, err
	}
	if a.Kind == cluster.KindApp {
		if err := r.mkfs(ctx, a.FS, a.ID, dev, false); err != nil {
			_, _ = r.zfs(ctx, "destroy", ds)
			return nil, fmt.Errorf("formatting the block volume: %w", err)
		}
		r.markStorageWriter(BackstoreName(a.ref(), "block"))
	}
	return r.volumeInfo(ctx, c, ds)
}

// mkfs formats an app's block volume; discard gives a used volume's
// blocks back to the pool (a new sparse one has none).
func (r *Root) mkfs(ctx context.Context, fsType, app, dev string, discard bool) error {
	label := "hc-" + app
	if len(label) > 12 && fsType == BlockXFS {
		label = label[:12] // xfs labels are at most 12 characters
	}
	var err error
	switch fsType {
	case BlockExt4:
		args := []string{"-q", "-F", "-L", label}
		if !discard {
			args = append(args, "-E", "nodiscard")
		}
		_, err = sysexec.Output(ctx, r.Runner, "mkfs.ext4", append(args, dev)...)
	case BlockXFS:
		args := []string{"-q", "-f", "-L", label}
		if !discard {
			args = append(args, "-K")
		}
		_, err = sysexec.Output(ctx, r.Runner, "mkfs.xfs", append(args, dev)...)
	default:
		err = &ValidationError{fmt.Errorf("file system %q isn't ext4 or xfs", fsType)}
	}
	return err
}

func (r *Root) volumeInfo(ctx context.Context, c cluster.ClusterID, ds string) (*VolumeInfo, error) {
	p, err := r.props(ctx, ds, "guid", "volsize")
	if err != nil {
		return nil, err
	}
	size, _ := strconv.ParseInt(p["volsize"], 10, 64)
	return &VolumeInfo{Dataset: ds, GUID: p["guid"], WWN: WWN(Serial(c, p["guid"])), SizeGB: int(size >> 30)}, nil
}

func (r *Root) waitDevice(ctx context.Context, dev string) error {
	wait := r.DeviceWait
	if wait == 0 {
		wait = 15 * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		if _, err := os.Stat(r.sys(dev)); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s didn't appear", dev)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// VolumeInfo describes an existing cluster volume of the workload.
func (r *Root) VolumeInfo(ctx context.Context, c cluster.ClusterID, a VolumeArgs) (*VolumeInfo, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	ds, err := a.dataset()
	if err != nil {
		return nil, err
	}
	if err := r.checkOwned(ctx, a.WorkloadArgs, ds); err != nil {
		return nil, err
	}
	return r.volumeInfo(ctx, c, ds)
}

// VolumeResize grows a zvol (never shrinks it). A block volume's file
// system is grown by the owner after its next attach.
func (r *Root) VolumeResize(ctx context.Context, c cluster.ClusterID, a VolumeArgs) (*VolumeInfo, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	ds, err := a.dataset()
	if err != nil {
		return nil, err
	}
	if err := r.checkOwned(ctx, a.WorkloadArgs, ds); err != nil {
		return nil, err
	}
	cur, err := r.volumeInfo(ctx, c, ds)
	if err != nil {
		return nil, err
	}
	if a.SizeGB <= cur.SizeGB || a.SizeGB > MaxVolumeGB {
		return nil, &ValidationError{fmt.Errorf("a disk can only grow (it is %d GB)", cur.SizeGB)}
	}
	if _, err := r.zfs(ctx, "set", "volsize="+strconv.Itoa(a.SizeGB)+"G", ds); err != nil {
		return nil, err
	}
	return r.volumeInfo(ctx, c, ds)
}

// VolumeDestroy destroys one zvol (confirm = the workload's id); refused
// while it is mapped.
func (r *Root) VolumeDestroy(ctx context.Context, a DestroyArgs) error {
	if err := a.check(); err != nil {
		return err
	}
	if a.Confirm != a.ID {
		return &ValidationError{errors.New("type the name to destroy the volume")}
	}
	ds, err := VolumeArgs{WorkloadArgs: a.WorkloadArgs, Disk: a.Disk}.dataset()
	if err != nil {
		return err
	}
	if err := r.checkOwned(ctx, a.WorkloadArgs, ds); err != nil {
		return err
	}
	r.mu.Lock()
	st, err := r.load()
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if st.Desired.UsesDataset(ds) {
		return &ValidationError{fmt.Errorf("%s is mapped to a server", ds)}
	}
	if _, err := r.zfs(ctx, "destroy", "-r", ds); err != nil {
		return err
	}
	r.log().Warn("san: volume destroyed", "dataset", ds)
	return nil
}

// SnapshotArgs is san.snapshot.*.
type SnapshotArgs struct {
	WorkloadArgs
	Name string `json:"name"`
	// Confirm: the snapshot's name, for rollback and destroy.
	Confirm string `json:"confirm,omitempty"`
}

// SnapshotInfo is one snapshot of a workload.
type SnapshotInfo struct {
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	Used    int64     `json:"used"`
}

func (a SnapshotArgs) checkName() error {
	if !snapRE.MatchString(a.Name) {
		return &ValidationError{fmt.Errorf("snapshot name %q isn't valid", a.Name)}
	}
	return nil
}

// SnapshotCreate snapshots a workload's dataset and its zvols atomically
// (zfs snapshot -r). The VM freeze or app dump has been done by its owner.
func (r *Root) SnapshotCreate(ctx context.Context, a SnapshotArgs) (*SnapshotInfo, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	if err := a.checkName(); err != nil {
		return nil, err
	}
	if err := r.checkOwned(ctx, a.WorkloadArgs, a.Dataset()); err != nil {
		return nil, err
	}
	have, err := r.SnapshotList(ctx, a)
	if err != nil {
		return nil, err
	}
	if len(have) >= MaxSnapshots {
		return nil, &ValidationError{fmt.Errorf("%s %s already has %d snapshots; delete some first", a.Kind, a.ID, len(have))}
	}
	if _, err := r.zfs(ctx, "snapshot", "-r", a.Dataset()+"@"+a.Name); err != nil {
		return nil, err
	}
	l, err := r.SnapshotList(ctx, a)
	if err != nil {
		return nil, err
	}
	for _, s := range l {
		if s.Name == a.Name {
			return &s, nil
		}
	}
	return &SnapshotInfo{Name: a.Name, Created: time.Now().UTC()}, nil
}

// SnapshotList lists the workload dataset's snapshots.
func (r *Root) SnapshotList(ctx context.Context, a SnapshotArgs) ([]SnapshotInfo, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	out, err := r.zfs(ctx, "list", "-H", "-p", "-t", "snapshot", "-d", "1", "-o", "name,creation,used", a.Dataset())
	if err != nil {
		return nil, err
	}
	res := []SnapshotInfo{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(l, "\t")
		if len(f) != 3 {
			continue
		}
		_, name, ok := strings.Cut(f[0], "@")
		if !ok {
			continue
		}
		sec, _ := strconv.ParseInt(f[1], 10, 64)
		used, _ := strconv.ParseInt(f[2], 10, 64)
		res = append(res, SnapshotInfo{Name: name, Created: time.Unix(sec, 0).UTC(), Used: used})
	}
	return res, nil
}

// SnapshotRollback rolls the dataset and every zvol under it back. The
// workload must be stopped: nothing of it may be mapped or exported.
func (r *Root) SnapshotRollback(ctx context.Context, a SnapshotArgs) error {
	if err := a.check(); err != nil {
		return err
	}
	if err := a.checkName(); err != nil {
		return err
	}
	if a.Confirm != a.Name {
		return &ValidationError{errors.New("type the snapshot's name to roll back to it")}
	}
	if err := r.checkOwned(ctx, a.WorkloadArgs, a.Dataset()); err != nil {
		return err
	}
	if busy, err := r.inUse(a.WorkloadArgs); err != nil || busy {
		if err == nil {
			err = &ValidationError{errors.New("stop it first: its storage is still attached to a server")}
		}
		return err
	}
	out, err := r.zfs(ctx, "list", "-H", "-o", "name", "-r", "-t", "filesystem,volume", a.Dataset())
	if err != nil {
		return err
	}
	for _, ds := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if ds == "" {
			continue
		}
		if _, err := r.zfs(ctx, "list", "-H", "-o", "name", ds+"@"+a.Name); err != nil {
			continue // a disk added after the snapshot keeps its data
		}
		if _, err := r.zfs(ctx, "rollback", "-r", ds+"@"+a.Name); err != nil {
			return fmt.Errorf("rolling %s back: %w", ds, err)
		}
	}
	return nil
}

// SnapshotDestroy destroys one snapshot (recursively).
func (r *Root) SnapshotDestroy(ctx context.Context, a SnapshotArgs) error {
	if err := a.check(); err != nil {
		return err
	}
	if err := a.checkName(); err != nil {
		return err
	}
	if a.Confirm != a.Name {
		return &ValidationError{errors.New("type the snapshot's name to delete it")}
	}
	if err := r.checkOwned(ctx, a.WorkloadArgs, a.Dataset()); err != nil {
		return err
	}
	_, err := r.zfs(ctx, "destroy", "-r", a.Dataset()+"@"+a.Name)
	return err
}

// MigrateArgs is san.app.migrate: copy an app's data between its NFS
// dataset and its block volume, on the storage node, with the app stopped
// everywhere. Confirm must be the app's id.
type MigrateArgs struct {
	App  string              `json:"app"`
	Pool string              `json:"pool"`
	To   cluster.StorageMode `json:"to"`
	// FS is the block volume's file system (ext4 or xfs): the volume is
	// checked and mounted as exactly that, never auto-detected (H4).
	FS      string `json:"fs"`
	Confirm string `json:"confirm"`
	// RemoveOld clears the copy it moved away from once the copy succeeded
	// (the NFS dataset's files after a snapshot, or the block volume).
	RemoveOld bool `json:"removeOld,omitempty"`
}

// CheckBlockFS runs the file system's own read-only checker on a block
// volume (e2fsck -fn, xfs_repair -n) and refuses it on any finding: the
// kernel never parses a node-written file system that its checker
// doesn't accept (H4, H5). A file system with an unreplayed journal is
// refused too (mount it on its owner once to replay it).
func CheckBlockFS(ctx context.Context, run sysexec.Runner, fsType, dev string) error {
	var res sysexec.Result
	var err error
	switch fsType {
	case BlockExt4:
		res, err = run.Run(ctx, nil, "e2fsck", "-f", "-n", dev)
	case BlockXFS:
		res, err = run.Run(ctx, nil, "xfs_repair", "-n", dev)
	default:
		return &ValidationError{fmt.Errorf("file system %q isn't ext4 or xfs", fsType)}
	}
	if err != nil {
		return fmt.Errorf("checking %s: %w", dev, err)
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(string(res.Stderr) + "\n" + string(res.Stdout))
		if len(msg) > 400 {
			msg = msg[len(msg)-400:]
		}
		return &ValidationError{fmt.Errorf("the %s file system on %s didn't pass its check (exit %d), so it isn't mounted: %s", fsType, dev, res.ExitCode, msg)}
	}
	return nil
}

// noReplay is the mount option that keeps a read-only mount from
// replaying the journal.
func noReplay(fsType string) string {
	if fsType == BlockXFS {
		return "norecovery"
	}
	return "noload"
}

// MigrateResult reports a data move.
type MigrateResult struct {
	To       cluster.StorageMode `json:"to"`
	Snapshot string              `json:"snapshot"`
	Removed  bool                `json:"removed"`
}

// Migrate copies an app's data into its other storage mode. A snapshot of
// the source is taken first (named hc-before-<mode>-<time>), so nothing is
// lost even when RemoveOld clears the source afterwards.
func (r *Root) Migrate(ctx context.Context, a MigrateArgs) (*MigrateResult, error) {
	w := WorkloadArgs{Kind: cluster.KindApp, ID: a.App, Pool: a.Pool}
	if err := w.check(); err != nil {
		return nil, err
	}
	if a.Confirm != a.App {
		return nil, &ValidationError{errors.New("type the app's name to move its data")}
	}
	if a.To != cluster.StorageBlock && a.To != cluster.StorageNFS {
		return nil, &ValidationError{errors.New("the data can move to block or nfs")}
	}
	if a.FS != BlockExt4 && a.FS != BlockXFS {
		return nil, &ValidationError{errors.New("the block volume's file system must be named (ext4 or xfs)")}
	}
	if err := r.checkOwned(ctx, w, w.Dataset()); err != nil {
		return nil, err
	}
	blk := AppBlock(a.Pool, a.App)
	if err := r.checkOwned(ctx, w, blk); err != nil {
		return nil, err
	}
	if busy, err := r.inUse(w); err != nil || busy {
		if err == nil {
			err = &ValidationError{errors.New("stop the app first: its storage is still attached to a server")}
		}
		return nil, err
	}
	info, err := r.datasetInfo(ctx, w.Dataset())
	if err != nil {
		return nil, err
	}
	snap := fmt.Sprintf("hc-before-%s-%s", a.To, time.Now().UTC().Format("20060102-150405"))
	if _, err := r.zfs(ctx, "snapshot", "-r", w.Dataset()+"@"+snap); err != nil {
		return nil, err
	}
	mnt := r.sys(filepath.Join("/run/hardyos/cluster/migrate", a.App))
	if err := os.MkdirAll(mnt, 0o700); err != nil {
		return nil, err
	}
	dev := "/dev/zvol/" + blk
	// The volume was last written by a compute node: its file system is
	// checked read-only by the userspace checker first and mounted only
	// as the named type, read-only when it is the source (H4).
	if err := CheckBlockFS(ctx, r.Runner, a.FS, dev); err != nil {
		return nil, err
	}
	opts := "nosuid,nodev,noexec"
	if a.To == cluster.StorageNFS {
		opts += ",ro," + noReplay(a.FS)
	}
	if _, err := sysexec.Output(ctx, r.Runner, "mount", "-t", a.FS, "-o", opts, dev, mnt); err != nil {
		return nil, fmt.Errorf("mounting the block volume: %w", err)
	}
	if a.To == cluster.StorageBlock {
		defer r.markStorageWriter(BackstoreName(w.ref(), "block"))
	}
	mounted := true
	defer func() {
		if mounted {
			_, _ = sysexec.Output(context.WithoutCancel(ctx), r.Runner, "umount", mnt)
		}
		_ = os.Remove(mnt)
	}()
	src, dst := info.Mountpoint, mnt
	if a.To == cluster.StorageNFS {
		src, dst = mnt, info.Mountpoint
	}
	// Keep the destination's root folder (lost+found on ext4 stays), copy
	// everything with owners, modes, links, ACLs and extended attributes.
	if _, err := sysexec.Output(ctx, r.Runner, "rsync", "-aHAX", "--numeric-ids", "--delete", "--exclude=/lost+found",
		"--exclude=/.zfs", src+"/", dst+"/"); err != nil {
		return nil, fmt.Errorf("copying the app's data: %w", err)
	}
	res := &MigrateResult{To: a.To, Snapshot: snap}
	if a.RemoveOld {
		if a.To == cluster.StorageNFS {
			// The block volume was mounted read-only: it is cleared by
			// formatting it afresh (which discards its blocks, giving them
			// back to the pool), never by writing through the node-written
			// file system. The snapshot keeps the old contents.
			if _, err := sysexec.Output(ctx, r.Runner, "umount", mnt); err != nil {
				return res, fmt.Errorf("the data was copied, but the block volume couldn't be unmounted to clear it: %w", err)
			}
			mounted = false
			if err := r.mkfs(ctx, a.FS, a.App, dev, true); err != nil {
				return res, fmt.Errorf("the data was copied, but clearing the block volume failed: %w", err)
			}
			r.markStorageWriter(BackstoreName(w.ref(), "block"))
		} else if _, err := sysexec.Output(ctx, r.Runner, "find", src, "-mindepth", "1", "-maxdepth", "1",
			"!", "-name", "lost+found", "!", "-name", ".zfs", "-exec", "rm", "-rf", "--one-file-system", "{}", "+"); err != nil {
			return res, fmt.Errorf("the data was copied, but clearing the old copy failed: %w", err)
		}
		res.Removed = true
	}
	r.log().Info("san: app data moved", "app", a.App, "to", a.To, "snapshot", snap)
	return res, nil
}
