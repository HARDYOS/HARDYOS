package priv

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// Storage operation names.
const (
	OpHWDisks          = "hw.disks"
	OpHWSystem         = "hw.system"
	OpHWSmart          = "hw.smart"
	OpPools            = "zfs.pools"
	OpPoolStatus       = "zfs.pool.status"
	OpPoolImportable   = "zfs.pool.importable"
	OpPoolCreate       = "zfs.pool.create"
	OpPoolAdd          = "zfs.pool.add"
	OpPoolAttach       = "zfs.pool.attach"
	OpPoolReplace      = "zfs.pool.replace"
	OpPoolRemove       = "zfs.pool.remove"
	OpPoolOnline       = "zfs.pool.online"
	OpPoolOffline      = "zfs.pool.offline"
	OpPoolClear        = "zfs.pool.clear"
	OpPoolScrub        = "zfs.pool.scrub"
	OpPoolImport       = "zfs.pool.import"
	OpPoolExport       = "zfs.pool.export"
	OpPoolDestroy      = "zfs.pool.destroy"
	OpDatasets         = "zfs.datasets"
	OpDatasetCreate    = "zfs.dataset.create"
	OpDatasetSet       = "zfs.dataset.set"
	OpDatasetDestroy   = "zfs.dataset.destroy"
	OpSnapshots        = "zfs.snapshots"
	OpSnapshotCreate   = "zfs.snapshot.create"
	OpSnapshotDestroy  = "zfs.snapshot.destroy"
	OpSnapshotRollback = "zfs.snapshot.rollback"
	OpARCSet           = "zfs.arc.set"
)

// StorageEnv is what storage operations need from the host.
type StorageEnv struct {
	Runner sysexec.Runner
	Root   fs.FS  // filesystem rooted at "/" for /sys, /proc and /dev/disk/by-id
	KeyDir string // where pool encryption keys live (zfs.KeyDir on a real system)
	// ARCConf is the modprobe file that persists the ARC limit; ARCParam the live sysfs knob.
	ARCConf, ARCParam string
}

// Arguments ---------------------------------------------------------------

// DeviceArgs names one disk device.
type DeviceArgs struct {
	Device string `json:"device"`
}

// PoolArgs names a pool.
type PoolArgs struct {
	Pool string `json:"pool"`
}

// PoolCreateArgs creates a pool. ConfirmWipe must be true: every disk is erased.
type PoolCreateArgs struct {
	Spec        zfs.PoolSpec `json:"spec"`
	ConfirmWipe bool         `json:"confirmWipe"`
}

// PoolAddArgs adds vdevs (data, special, log, cache, spare) to a pool.
type PoolAddArgs struct {
	Pool        string       `json:"pool"`
	Spec        zfs.PoolSpec `json:"spec"`
	ConfirmWipe bool         `json:"confirmWipe"`
}

// PoolAttachArgs attaches Disk to Target: widens a RAIDZ vdev (expansion) or a mirror.
type PoolAttachArgs struct {
	Pool        string `json:"pool"`
	Target      string `json:"target"` // vdev name (raidz2-0) or a member disk for mirrors
	Disk        string `json:"disk"`
	ConfirmWipe bool   `json:"confirmWipe"`
}

// PoolReplaceArgs replaces Old (path or GUID) with the new Disk.
type PoolReplaceArgs struct {
	Pool        string `json:"pool"`
	Old         string `json:"old"`
	Disk        string `json:"disk"`
	ConfirmWipe bool   `json:"confirmWipe"`
}

// PoolDeviceArgs names a device inside a pool.
type PoolDeviceArgs struct {
	Pool   string `json:"pool"`
	Device string `json:"device"`
}

// PoolScrubArgs starts, pauses or stops a scrub.
type PoolScrubArgs struct {
	Pool   string `json:"pool"`
	Action string `json:"action"` // start, pause, stop
}

// PoolImportArgs imports a pool by name or numeric ID.
type PoolImportArgs struct {
	Pool  string `json:"pool"`
	Force bool   `json:"force"` // import a pool last used by another system
}

// PoolDestroyArgs destroys a pool; ConfirmName must repeat the pool name.
type PoolDestroyArgs struct {
	Pool        string `json:"pool"`
	ConfirmName string `json:"confirmName"`
}

// DatasetListArgs optionally limits listing to one dataset and its children.
type DatasetListArgs struct {
	Root string `json:"root"`
}

// DatasetCreateArgs creates a filesystem, or a volume when VolSize is set.
type DatasetCreateArgs struct {
	Name    string            `json:"name"`
	VolSize string            `json:"volSize,omitempty"`
	Props   map[string]string `json:"props,omitempty"`
}

// DatasetSetArgs changes properties.
type DatasetSetArgs struct {
	Name  string            `json:"name"`
	Props map[string]string `json:"props"`
}

// DatasetDestroyArgs destroys a dataset; ConfirmName must repeat its name.
type DatasetDestroyArgs struct {
	Name        string `json:"name"`
	Recursive   bool   `json:"recursive"`
	ConfirmName string `json:"confirmName"`
}

// SnapshotCreateArgs snapshots a dataset.
type SnapshotCreateArgs struct {
	Dataset   string `json:"dataset"`
	Label     string `json:"label"`
	Recursive bool   `json:"recursive"`
}

// SnapshotArgs names a snapshot.
type SnapshotArgs struct {
	Name string `json:"name"`
}

// SnapshotRollbackArgs rolls a dataset back. DestroyNewer allows rolling back
// past later snapshots (they are destroyed); Confirm must be true.
type SnapshotRollbackArgs struct {
	Name         string `json:"name"`
	DestroyNewer bool   `json:"destroyNewer"`
	Confirm      bool   `json:"confirm"`
}

// ARCSetArgs sets the ZFS ARC size limit in bytes (0 = ZFS default).
type ARCSetArgs struct {
	MaxBytes uint64 `json:"maxBytes"`
}

// Registration -------------------------------------------------------------

// RegisterStorage adds the hardware and ZFS operations.
func RegisterStorage(s *Server, env StorageEnv) {
	if env.KeyDir == "" {
		env.KeyDir = zfs.KeyDir
	}
	if env.ARCConf == "" {
		env.ARCConf = "/etc/modprobe.d/hardyos-zfs.conf"
	}
	if env.ARCParam == "" {
		env.ARCParam = "/sys/module/zfs/parameters/zfs_arc_max"
	}
	st := &storageOps{env: env, srv: s}

	s.Handle(OpHWDisks, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return hw.ListDisks(ctx, env.Runner, env.Root)
	})
	s.Handle(OpHWSystem, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return hw.ReadSystem(env.Root), nil
	})
	s.Handle(OpHWSmart, typed(func(ctx context.Context, a DeviceArgs) (any, error) {
		return hw.ReadSMART(ctx, env.Runner, a.Device)
	}))
	s.Handle(OpPools, func(ctx context.Context, _ json.RawMessage) (any, error) {
		out, err := st.zpool(ctx, zfs.PoolListArgs...)
		if err != nil {
			return nil, err
		}
		return zfs.ParsePoolList(out)
	})
	s.Handle(OpPoolStatus, typed(func(ctx context.Context, a PoolArgs) (any, error) {
		if err := existingPool(a.Pool); err != nil {
			return nil, err
		}
		return st.status(ctx, a.Pool)
	}))
	s.Handle(OpPoolImportable, func(ctx context.Context, _ json.RawMessage) (any, error) {
		res, err := env.Runner.Run(ctx, nil, "zpool", "import", "-d", "/dev/disk/by-id")
		if err != nil {
			return nil, err
		}
		// "no pools available" exits non-zero; treat any output as the answer.
		return zfs.ParseImportable(append(res.Stdout, res.Stderr...)), nil
	})
	s.Handle(OpPoolCreate, typed(st.createPool))
	s.Handle(OpPoolAdd, typed(st.addVdevs))
	s.Handle(OpPoolAttach, typed(st.attach))
	s.Handle(OpPoolReplace, typed(st.replace))
	s.Handle(OpPoolRemove, typed(st.simpleDevice("remove")))
	s.Handle(OpPoolOnline, typed(st.simpleDevice("online")))
	s.Handle(OpPoolOffline, typed(st.simpleDevice("offline")))
	s.Handle(OpPoolClear, typed(func(ctx context.Context, a PoolArgs) (any, error) {
		if err := dataPool(a.Pool); err != nil {
			return nil, err
		}
		if _, err := st.zpool(ctx, "clear", a.Pool); err != nil {
			return nil, err
		}
		return st.status(ctx, a.Pool)
	}))
	s.Handle(OpPoolScrub, typed(st.scrub))
	s.Handle(OpPoolImport, typed(st.importPool))
	s.Handle(OpPoolExport, typed(func(ctx context.Context, a PoolArgs) (any, error) {
		if err := dataPool(a.Pool); err != nil {
			return nil, err
		}
		st.srv.releaseDataset(ctx, a.Pool)
		_, err := st.zpool(ctx, "export", a.Pool)
		return map[string]string{"exported": a.Pool}, err
	}))
	s.Handle(OpPoolDestroy, typed(st.destroyPool))
	s.Handle(OpDatasets, typed(st.listDatasets))
	s.Handle(OpDatasetCreate, typed(st.createDataset))
	s.Handle(OpDatasetSet, typed(st.setDataset))
	s.Handle(OpDatasetDestroy, typed(st.destroyDataset))
	s.Handle(OpSnapshots, typed(st.listSnapshots))
	s.Handle(OpSnapshotCreate, typed(st.createSnapshot))
	s.Handle(OpSnapshotDestroy, typed(st.destroySnapshot))
	s.Handle(OpSnapshotRollback, typed(st.rollback))
	s.Handle(OpARCSet, typed(st.setARC))
}

// typed adapts a handler with a decoded argument struct, rejecting unknown fields.
func typed[A any](fn func(ctx context.Context, a A) (any, error)) HandlerFunc {
	return func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a A
		if len(raw) > 0 {
			dec := json.NewDecoder(strings.NewReader(string(raw)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&a); err != nil {
				return nil, Errorf(CodeBadArgs, "invalid arguments: %v", err)
			}
		}
		return fn(ctx, a)
	}
}

type storageOps struct {
	env StorageEnv
	srv *Server
}

func (st *storageOps) zpool(ctx context.Context, args ...string) ([]byte, error) {
	out, err := sysexec.Output(ctx, st.env.Runner, "zpool", args...)
	return out, wrapCmd(err)
}

func (st *storageOps) zfs(ctx context.Context, args ...string) ([]byte, error) {
	out, err := sysexec.Output(ctx, st.env.Runner, "zfs", args...)
	return out, wrapCmd(err)
}

func wrapCmd(err error) error {
	var ce *sysexec.CommandError
	if errors.As(err, &ce) {
		return Errorf(CodeFailed, "%s", ce.Error())
	}
	return err
}

func (st *storageOps) status(ctx context.Context, pool string) (*zfs.Status, error) {
	out, err := st.zpool(ctx, zfs.StatusArgs(pool)...)
	if err != nil {
		return nil, err
	}
	return zfs.ParseStatus(out)
}

// existingPool checks a name for read-only use (boot pools allowed).
func existingPool(name string) error {
	if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`).MatchString(name) {
		return Errorf(CodeBadArgs, "invalid pool name %q", name)
	}
	return nil
}

// dataPool checks a name for changes: boot pools are off limits.
func dataPool(name string) error {
	if err := existingPool(name); err != nil {
		return err
	}
	switch strings.ToLower(name) {
	case "rpool", "bpool", "hardyos-boot":
		return Errorf(CodeForbidden, "the boot pool %q can't be changed here", name)
	}
	return nil
}

func datasetPool(name string) string {
	p, _, _ := strings.Cut(name, "/")
	p, _, _ = strings.Cut(p, "@")
	return p
}

// prepareDisks re-scans disks and checks every requested path is a known,
// unused whole disk; then wipes old signatures so ZFS can take it.
func (st *storageOps) prepareDisks(ctx context.Context, paths []string, confirm bool) error {
	if len(paths) == 0 {
		return nil
	}
	if !confirm {
		return Errorf(CodeBadArgs, "confirmWipe must be true: these disks will be erased")
	}
	disks, err := hw.ListDisks(ctx, st.env.Runner, st.env.Root)
	if err != nil {
		return err
	}
	byID := map[string]hw.Disk{}
	for _, d := range disks {
		byID[d.ByID] = d
	}
	var toWipe []hw.Disk
	for _, p := range paths {
		if err := zfs.ValidDiskPath(p); err != nil {
			return Errorf(CodeBadArgs, "%v", err)
		}
		d, ok := byID[p]
		if !ok {
			return Errorf(CodeBadArgs, "disk %s not found (was it removed?)", p)
		}
		if !d.Usage.Usable() || d.Removable {
			return Errorf(CodeForbidden, "disk %s can't be used: %s", p, d.UsageDetail)
		}
		toWipe = append(toWipe, d)
	}
	partRE := regexp.MustCompile(`^[a-z0-9]{2,32}$`)
	for _, d := range toWipe {
		// Clear old ZFS labels (fails harmlessly when there are none), then all signatures.
		_, _ = st.env.Runner.Run(ctx, nil, "zpool", "labelclear", "-f", d.ByID)
		for _, p := range d.Partitions {
			if partRE.MatchString(p.Name) {
				_, _ = st.env.Runner.Run(ctx, nil, "wipefs", "-a", "/dev/"+p.Name)
			}
		}
		if _, err := sysexec.Output(ctx, st.env.Runner, "wipefs", "-a", d.ByID); err != nil {
			return wrapCmd(err)
		}
	}
	return nil
}

func (st *storageOps) createPool(ctx context.Context, a PoolCreateArgs) (any, error) {
	if err := a.Spec.Validate(true); err != nil {
		return nil, Errorf(CodeBadArgs, "%v", err)
	}
	if err := st.prepareDisks(ctx, a.Spec.Disks(), a.ConfirmWipe); err != nil {
		return nil, err
	}
	createdKey := ""
	if a.Spec.Encrypt {
		path := filepath.Join(st.env.KeyDir, a.Spec.Name+".key")
		if err := writeKey(path); err != nil {
			return nil, Errorf(CodeFailed, "create encryption key: %v", err)
		}
		createdKey = path
	}
	args := a.Spec.CreateArgs()
	if a.Spec.Encrypt && st.env.KeyDir != zfs.KeyDir {
		// Tests and non-standard layouts: point keylocation at the actual key dir.
		for i, v := range args {
			if strings.HasPrefix(v, "keylocation=") {
				args[i] = "keylocation=file://" + filepath.Join(st.env.KeyDir, a.Spec.Name+".key")
			}
		}
	}
	if _, err := st.zpool(ctx, args...); err != nil {
		if createdKey != "" {
			_ = os.Remove(createdKey)
		}
		return nil, err
	}
	return st.status(ctx, a.Spec.Name)
}

func writeKey(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	return os.WriteFile(path, key, 0o400)
}

func (st *storageOps) addVdevs(ctx context.Context, a PoolAddArgs) (any, error) {
	if err := dataPool(a.Pool); err != nil {
		return nil, err
	}
	if err := a.Spec.Validate(false); err != nil {
		return nil, Errorf(CodeBadArgs, "%v", err)
	}
	if err := st.prepareDisks(ctx, a.Spec.Disks(), a.ConfirmWipe); err != nil {
		return nil, err
	}
	if _, err := st.zpool(ctx, a.Spec.AddArgs(a.Pool)...); err != nil {
		return nil, err
	}
	return st.status(ctx, a.Pool)
}

func (st *storageOps) attach(ctx context.Context, a PoolAttachArgs) (any, error) {
	if err := dataPool(a.Pool); err != nil {
		return nil, err
	}
	if err := zfs.ValidVdevRef(a.Target); err != nil {
		return nil, Errorf(CodeBadArgs, "%v", err)
	}
	if err := st.prepareDisks(ctx, []string{a.Disk}, a.ConfirmWipe); err != nil {
		return nil, err
	}
	if _, err := st.zpool(ctx, "attach", "-f", a.Pool, a.Target, a.Disk); err != nil {
		return nil, err
	}
	return st.status(ctx, a.Pool)
}

func (st *storageOps) replace(ctx context.Context, a PoolReplaceArgs) (any, error) {
	if err := dataPool(a.Pool); err != nil {
		return nil, err
	}
	if err := zfs.ValidVdevRef(a.Old); err != nil {
		return nil, Errorf(CodeBadArgs, "%v", err)
	}
	if err := st.prepareDisks(ctx, []string{a.Disk}, a.ConfirmWipe); err != nil {
		return nil, err
	}
	if _, err := st.zpool(ctx, "replace", "-f", a.Pool, a.Old, a.Disk); err != nil {
		return nil, err
	}
	return st.status(ctx, a.Pool)
}

func (st *storageOps) simpleDevice(verb string) func(ctx context.Context, a PoolDeviceArgs) (any, error) {
	return func(ctx context.Context, a PoolDeviceArgs) (any, error) {
		if err := dataPool(a.Pool); err != nil {
			return nil, err
		}
		if err := zfs.ValidVdevRef(a.Device); err != nil {
			return nil, Errorf(CodeBadArgs, "%v", err)
		}
		if _, err := st.zpool(ctx, verb, a.Pool, a.Device); err != nil {
			return nil, err
		}
		return st.status(ctx, a.Pool)
	}
}

func (st *storageOps) scrub(ctx context.Context, a PoolScrubArgs) (any, error) {
	if err := dataPool(a.Pool); err != nil {
		return nil, err
	}
	args := []string{"scrub"}
	switch a.Action {
	case "start", "":
	case "pause":
		args = append(args, "-p")
	case "stop":
		args = append(args, "-s")
	default:
		return nil, Errorf(CodeBadArgs, "action must be start, pause or stop")
	}
	if _, err := st.zpool(ctx, append(args, a.Pool)...); err != nil {
		return nil, err
	}
	return st.status(ctx, a.Pool)
}

func (st *storageOps) importPool(ctx context.Context, a PoolImportArgs) (any, error) {
	isID := regexp.MustCompile(`^[0-9]{1,20}$`).MatchString(a.Pool)
	if !isID {
		if err := dataPool(a.Pool); err != nil {
			return nil, err
		}
	}
	args := []string{"import", "-d", "/dev/disk/by-id"}
	if a.Force {
		args = append(args, "-f")
	}
	if _, err := st.zpool(ctx, append(args, a.Pool)...); err != nil {
		return nil, err
	}
	pools, err := st.zpool(ctx, zfs.PoolListArgs...)
	if err != nil {
		return nil, err
	}
	return zfs.ParsePoolList(pools)
}

func (st *storageOps) destroyPool(ctx context.Context, a PoolDestroyArgs) (any, error) {
	if err := dataPool(a.Pool); err != nil {
		return nil, err
	}
	if a.ConfirmName != a.Pool {
		return nil, Errorf(CodeBadArgs, "confirmName must repeat the pool name exactly")
	}
	st.srv.releaseDataset(ctx, a.Pool)
	if _, err := st.zpool(ctx, "destroy", a.Pool); err != nil {
		return nil, err
	}
	_ = os.Remove(filepath.Join(st.env.KeyDir, a.Pool+".key"))
	return map[string]string{"destroyed": a.Pool}, nil
}

func (st *storageOps) listDatasets(ctx context.Context, a DatasetListArgs) (any, error) {
	args := append([]string{}, zfs.DatasetListArgs...)
	if a.Root != "" {
		if err := zfs.ValidDatasetName(a.Root); err != nil {
			return nil, Errorf(CodeBadArgs, "%v", err)
		}
		args = append(args, "-r", a.Root)
	}
	out, err := st.zfs(ctx, args...)
	if err != nil {
		return nil, err
	}
	return zfs.ParseDatasets(out)
}

func propArgs(props map[string]string) ([]string, error) {
	keys := make([]string, 0, len(props))
	for k := range props {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var args []string
	for _, k := range keys {
		if err := zfs.ValidateProperty(k, props[k]); err != nil {
			return nil, Errorf(CodeBadArgs, "%v", err)
		}
		args = append(args, k+"="+props[k])
	}
	return args, nil
}

func (st *storageOps) createDataset(ctx context.Context, a DatasetCreateArgs) (any, error) {
	if err := zfs.ValidDatasetName(a.Name); err != nil || !strings.Contains(a.Name, "/") {
		return nil, Errorf(CodeBadArgs, "dataset name must be pool/name: %v", err)
	}
	if err := dataPool(datasetPool(a.Name)); err != nil {
		return nil, err
	}
	props, err := propArgs(a.Props)
	if err != nil {
		return nil, err
	}
	args := []string{"create"}
	for _, p := range props {
		args = append(args, "-o", p)
	}
	if a.VolSize != "" {
		if err := zfs.ValidateProperty("volsize", a.VolSize); err != nil {
			return nil, Errorf(CodeBadArgs, "%v", err)
		}
		args = append(args, "-s", "-V", a.VolSize) // sparse volume
	}
	if _, err := st.zfs(ctx, append(args, a.Name)...); err != nil {
		return nil, err
	}
	return st.listDatasets(ctx, DatasetListArgs{Root: a.Name})
}

func (st *storageOps) setDataset(ctx context.Context, a DatasetSetArgs) (any, error) {
	if err := zfs.ValidDatasetName(a.Name); err != nil {
		return nil, Errorf(CodeBadArgs, "%v", err)
	}
	if err := dataPool(datasetPool(a.Name)); err != nil {
		return nil, err
	}
	if len(a.Props) == 0 {
		return nil, Errorf(CodeBadArgs, "no properties given")
	}
	props, err := propArgs(a.Props)
	if err != nil {
		return nil, err
	}
	if _, err := st.zfs(ctx, append(append([]string{"set"}, props...), a.Name)...); err != nil {
		return nil, err
	}
	return st.listDatasets(ctx, DatasetListArgs{Root: a.Name})
}

func (st *storageOps) destroyDataset(ctx context.Context, a DatasetDestroyArgs) (any, error) {
	if err := zfs.ValidDatasetName(a.Name); err != nil || !strings.Contains(a.Name, "/") {
		return nil, Errorf(CodeBadArgs, "only child datasets can be destroyed (destroy the pool instead)")
	}
	if err := dataPool(datasetPool(a.Name)); err != nil {
		return nil, err
	}
	if a.ConfirmName != a.Name {
		return nil, Errorf(CodeBadArgs, "confirmName must repeat the dataset name exactly")
	}
	st.srv.releaseDataset(ctx, a.Name)
	args := []string{"destroy"}
	if a.Recursive {
		args = append(args, "-r")
	}
	if _, err := st.zfs(ctx, append(args, a.Name)...); err != nil {
		return nil, err
	}
	return map[string]string{"destroyed": a.Name}, nil
}

func (st *storageOps) listSnapshots(ctx context.Context, a DatasetListArgs) (any, error) {
	args := append([]string{}, zfs.SnapshotListArgs...)
	if a.Root != "" {
		if err := zfs.ValidDatasetName(a.Root); err != nil {
			return nil, Errorf(CodeBadArgs, "%v", err)
		}
		args = append(args, "-r", a.Root)
	}
	out, err := st.zfs(ctx, args...)
	if err != nil {
		return nil, err
	}
	return zfs.ParseSnapshots(out)
}

func (st *storageOps) createSnapshot(ctx context.Context, a SnapshotCreateArgs) (any, error) {
	name := a.Dataset + "@" + a.Label
	if err := zfs.ValidSnapshotName(name); err != nil {
		return nil, Errorf(CodeBadArgs, "%v", err)
	}
	args := []string{"snapshot"}
	if a.Recursive {
		args = append(args, "-r")
	}
	if _, err := st.zfs(ctx, append(args, name)...); err != nil {
		return nil, err
	}
	return map[string]string{"created": name}, nil
}

func (st *storageOps) destroySnapshot(ctx context.Context, a SnapshotArgs) (any, error) {
	if err := zfs.ValidSnapshotName(a.Name); err != nil {
		return nil, Errorf(CodeBadArgs, "%v", err)
	}
	if err := dataPool(datasetPool(a.Name)); err != nil {
		return nil, err
	}
	if _, err := st.zfs(ctx, "destroy", a.Name); err != nil {
		return nil, err
	}
	return map[string]string{"destroyed": a.Name}, nil
}

func (st *storageOps) rollback(ctx context.Context, a SnapshotRollbackArgs) (any, error) {
	if err := zfs.ValidSnapshotName(a.Name); err != nil {
		return nil, Errorf(CodeBadArgs, "%v", err)
	}
	if err := dataPool(datasetPool(a.Name)); err != nil {
		return nil, err
	}
	if !a.Confirm {
		return nil, Errorf(CodeBadArgs, "confirm must be true: changes made after this snapshot will be lost")
	}
	args := []string{"rollback"}
	if a.DestroyNewer {
		args = append(args, "-r")
	}
	if _, err := st.zfs(ctx, append(args, a.Name)...); err != nil {
		return nil, err
	}
	return map[string]string{"rolledBack": a.Name}, nil
}

func (st *storageOps) setARC(ctx context.Context, a ARCSetArgs) (any, error) {
	if a.MaxBytes != 0 && a.MaxBytes < 512<<20 {
		return nil, Errorf(CodeBadArgs, "ARC limit below 512 MiB isn't useful")
	}
	val := fmt.Sprint(a.MaxBytes)
	if err := os.WriteFile(st.env.ARCParam, []byte(val), 0o644); err != nil {
		return nil, Errorf(CodeFailed, "apply ARC limit: %v", err)
	}
	conf := fmt.Sprintf("# Managed by HardyOS\noptions zfs zfs_arc_max=%s\n", val)
	if a.MaxBytes == 0 {
		conf = "# Managed by HardyOS: ZFS default ARC size\n"
	}
	if err := os.WriteFile(st.env.ARCConf, []byte(conf), 0o644); err != nil {
		return nil, Errorf(CodeFailed, "persist ARC limit: %v", err)
	}
	return map[string]uint64{"maxBytes": a.MaxBytes}, nil
}
