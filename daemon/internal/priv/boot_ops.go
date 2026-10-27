package priv

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/boot"
	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/install"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// Boot disk repair operations: replace a failed disk of the boot mirror, add
// a disk to make (or widen) the mirror, or drop a dead one.
const (
	OpBootDisks   = "boot.disks"
	OpBootReplace = "boot.replace"
	OpBootAttach  = "boot.attach"
	OpBootDetach  = "boot.detach"
)

// BootDisksResult is the boot pool with its disks and the disks that could
// join it.
type BootDisksResult struct {
	Pool       string      `json:"pool"`
	Status     *zfs.Status `json:"status"`
	Disks      []boot.Disk `json:"disks"`
	Candidates []hw.Disk   `json:"candidates"`
	// MinBytes is the smallest disk that can join: the largest current boot
	// disk, since the new one gets the same partitions.
	MinBytes uint64 `json:"minBytes"`
}

// BootReplaceArgs replaces Old (a device of the boot pool) with Disk.
type BootReplaceArgs struct {
	Old         string `json:"old"`
	Disk        string `json:"disk"`
	ConfirmWipe bool   `json:"confirmWipe"`
}

// BootAttachArgs adds Disk to the boot mirror.
type BootAttachArgs struct {
	Disk        string `json:"disk"`
	ConfirmWipe bool   `json:"confirmWipe"`
}

// BootDetachArgs removes Device from the boot mirror.
type BootDetachArgs struct {
	Device string `json:"device"`
}

type bootOps struct {
	st         *storageOps
	root       string // "/" on a real system
	configPath string
	settle     time.Duration
	// sync is boot.Sync; tests replace it.
	sync func(context.Context, boot.Env, *boot.Config, boot.SyncOptions) ([]boot.MenuEntry, error)
}

// RegisterBootRepair adds the boot disk operations. root is "/" and
// configPath boot.ConfigPath on a real system.
func RegisterBootRepair(s *Server, env StorageEnv, root, configPath string) {
	b := &bootOps{st: &storageOps{env: env}, root: root, configPath: configPath, settle: 30 * time.Second, sync: boot.Sync}
	s.Handle(OpBootDisks, func(ctx context.Context, _ json.RawMessage) (any, error) { return b.disks(ctx) })
	s.Handle(OpBootReplace, typed(withSystemLock("Replacing a boot disk", b.replace)))
	s.Handle(OpBootAttach, typed(withSystemLock("Adding a boot disk", b.attach)))
	s.Handle(OpBootDetach, typed(withSystemLock("Removing a boot disk", b.detach)))
}

func (b *bootOps) env() boot.Env {
	return boot.Env{Runner: b.st.env.Runner, Root: b.root}
}

func (b *bootOps) config() (*boot.Config, error) {
	cfg, err := boot.LoadConfig(b.configPath)
	if errors.Is(err, boot.ErrNoConfig) {
		return nil, Errorf(CodeForbidden, "this system wasn't installed by the HardyOS installer, so its boot disks can't be managed here")
	}
	if err != nil {
		return nil, Errorf(CodeFailed, "%v", err)
	}
	return cfg, nil
}

// leaves lists the boot pool's data devices (not log, cache or spare).
func leaves(st *zfs.Status) []*zfs.Vdev {
	var out []*zfs.Vdev
	var walk func(v *zfs.Vdev)
	walk = func(v *zfs.Vdev) {
		if len(v.Children) == 0 && v.Type != "root" {
			out = append(out, v)
			return
		}
		for _, c := range v.Children {
			walk(c)
		}
	}
	for _, v := range st.Groups {
		if v.Class == zfs.ClassData {
			walk(v)
		}
	}
	return out
}

// wholeDisk is the by-id disk a boot pool device lives on: its Disk field, or
// for a missing device the path in "was /dev/disk/by-id/...-part3".
func wholeDisk(v *zfs.Vdev) string {
	// A missing device shows as a number with the old path in its note.
	if p, ok := strings.CutPrefix(v.Note, "was "); ok {
		if p = strings.TrimSpace(p); strings.HasPrefix(p, "/dev/") {
			return zfs.DiskOf(p)
		}
	}
	if strings.HasPrefix(v.Disk, "/dev/") {
		return v.Disk
	}
	return ""
}

func (b *bootOps) disks(ctx context.Context) (any, error) {
	cfg, err := b.config()
	if err != nil {
		return nil, err
	}
	st, err := b.st.status(ctx, cfg.Pool)
	if err != nil {
		return nil, err
	}
	all, err := hw.ListDisks(ctx, b.st.env.Runner, b.st.env.Root)
	if err != nil {
		return nil, err
	}
	res := BootDisksResult{Pool: cfg.Pool, Status: st, Disks: cfg.Disks, Candidates: []hw.Disk{}}
	sizes := map[string]uint64{}
	for _, d := range all {
		sizes[d.ByID] = d.SizeBytes
	}
	for _, d := range cfg.Disks {
		if sizes[d.ByID] > res.MinBytes {
			res.MinBytes = sizes[d.ByID]
		}
	}
	for _, d := range all {
		if d.Usage.Usable() && !d.Removable && d.SizeBytes >= res.MinBytes {
			res.Candidates = append(res.Candidates, d)
		}
	}
	return res, nil
}

// prepare wipes the new disk and gives it the same partitions as a healthy
// boot disk: BIOS boot, EFI system and ZFS. It returns the ZFS partition.
func (b *bootOps) prepare(ctx context.Context, cfg *boot.Config, st *zfs.Status, disk string, confirm bool) (string, error) {
	var healthy string
	for _, v := range leaves(st) {
		if v.State == "ONLINE" {
			if w := wholeDisk(v); w != "" && w != disk {
				healthy = w
				break
			}
		}
	}
	if healthy == "" {
		return "", Errorf(CodeForbidden, "no working boot disk to copy the layout from")
	}
	for _, d := range cfg.Disks {
		if d.ByID == disk {
			return "", Errorf(CodeBadArgs, "%s is already a boot disk", disk)
		}
	}
	all, err := hw.ListDisks(ctx, b.st.env.Runner, b.st.env.Root)
	if err != nil {
		return "", err
	}
	var newSize, healthySize uint64
	for _, d := range all {
		switch d.ByID {
		case disk:
			newSize = d.SizeBytes
		case healthy:
			healthySize = d.SizeBytes
		}
	}
	if newSize < healthySize {
		return "", Errorf(CodeBadArgs, "%s is smaller than the boot disks; it needs at least %d GB", disk, healthySize>>30)
	}
	if err := b.st.prepareDisks(ctx, []string{disk}, confirm); err != nil {
		return "", err
	}
	run := func(name string, args ...string) error {
		_, err := sysexec.Output(ctx, b.st.env.Runner, name, args...)
		return wrapCmd(err)
	}
	if err := run("sgdisk", "--zap-all", disk); err != nil {
		return "", err
	}
	// Copy the partition table, then give the copy its own GUIDs.
	if err := run("sgdisk", "--replicate="+disk, healthy); err != nil {
		return "", err
	}
	if err := run("sgdisk", "--randomize-guids", disk); err != nil {
		return "", err
	}
	_, _ = b.st.env.Runner.Run(ctx, nil, "partprobe", disk)
	_, _ = b.st.env.Runner.Run(ctx, nil, "udevadm", "settle", "--timeout=30")
	for _, n := range []int{2, 3} {
		if err := b.waitFor(ctx, install.Partition(disk, n)); err != nil {
			return "", err
		}
	}
	if err := run("mkfs.vfat", "-F", "32", "-n", "HARDYOS-EFI", install.Partition(disk, 2)); err != nil {
		return "", err
	}
	return install.Partition(disk, 3), nil
}

func (b *bootOps) waitFor(ctx context.Context, dev string) error {
	deadline := time.Now().Add(b.settle)
	for {
		if _, err := os.Stat(filepath.Join(b.env().Root, dev)); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return Errorf(CodeFailed, "partition %s did not appear", dev)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// finish records the new disk list, puts the boot loader and kernels on every
// disk and refreshes the firmware's boot entries.
func (b *bootOps) finish(ctx context.Context, cfg *boot.Config, newDisk string) error {
	if newDisk != "" {
		out, err := sysexec.Output(ctx, b.st.env.Runner, "blkid", "-s", "PARTUUID", "-o", "value", install.Partition(newDisk, 2))
		if err != nil {
			return Errorf(CodeFailed, "read the new EFI partition's ID: %v", wrapCmd(err))
		}
		cfg.Disks = append(cfg.Disks, boot.Disk{ByID: newDisk, ESPPartUUID: strings.TrimSpace(string(out))})
	}
	if err := cfg.Save(b.configPath); err != nil {
		return err
	}
	if newDisk != "" {
		if _, err := b.sync(ctx, b.env(), cfg, boot.SyncOptions{InstallGRUB: true}); err != nil {
			var pe *boot.PartialError
			if !errors.As(err, &pe) {
				return Errorf(CodeFailed, "the disk joined, but the boot loader couldn't be installed: %v", err)
			}
		}
	}
	ids := make([]string, len(cfg.Disks))
	for i, d := range cfg.Disks {
		ids[i] = d.ByID
	}
	boot.SetFirmwareEntries(ctx, b.env(), ids)
	return nil
}

func (b *bootOps) findLeaf(st *zfs.Status, ref string) *zfs.Vdev {
	for _, v := range leaves(st) {
		if v.Name == ref {
			return v
		}
	}
	return nil
}

func dropDisk(cfg *boot.Config, whole string) {
	if whole == "" {
		return
	}
	kept := cfg.Disks[:0]
	for _, d := range cfg.Disks {
		if d.ByID != whole {
			kept = append(kept, d)
		}
	}
	cfg.Disks = kept
}

func (b *bootOps) replace(ctx context.Context, a BootReplaceArgs) (any, error) {
	cfg, err := b.config()
	if err != nil {
		return nil, err
	}
	if err := zfs.ValidVdevRef(a.Old); err != nil {
		return nil, Errorf(CodeBadArgs, "%v", err)
	}
	if err := zfs.ValidDiskPath(a.Disk); err != nil {
		return nil, Errorf(CodeBadArgs, "%v", err)
	}
	st, err := b.st.status(ctx, cfg.Pool)
	if err != nil {
		return nil, err
	}
	old := b.findLeaf(st, a.Old)
	if old == nil {
		return nil, Errorf(CodeBadArgs, "%s isn't a disk of the boot pool", a.Old)
	}
	part, err := b.prepare(ctx, cfg, st, a.Disk, a.ConfirmWipe)
	if err != nil {
		return nil, err
	}
	if _, err := b.st.zpool(ctx, "replace", "-f", cfg.Pool, a.Old, part); err != nil {
		return nil, err
	}
	dropDisk(cfg, wholeDisk(old))
	if err := b.finish(ctx, cfg, a.Disk); err != nil {
		return nil, err
	}
	return b.st.status(ctx, cfg.Pool)
}

func (b *bootOps) attach(ctx context.Context, a BootAttachArgs) (any, error) {
	cfg, err := b.config()
	if err != nil {
		return nil, err
	}
	if err := zfs.ValidDiskPath(a.Disk); err != nil {
		return nil, Errorf(CodeBadArgs, "%v", err)
	}
	st, err := b.st.status(ctx, cfg.Pool)
	if err != nil {
		return nil, err
	}
	var target string
	for _, v := range leaves(st) {
		if v.State == "ONLINE" {
			target = v.Name
			break
		}
	}
	if target == "" {
		return nil, Errorf(CodeForbidden, "no working boot disk to mirror")
	}
	if len(cfg.Disks) >= install.MaxBootDisks {
		return nil, Errorf(CodeBadArgs, "the boot mirror already has %d disks", len(cfg.Disks))
	}
	part, err := b.prepare(ctx, cfg, st, a.Disk, a.ConfirmWipe)
	if err != nil {
		return nil, err
	}
	if _, err := b.st.zpool(ctx, "attach", "-f", cfg.Pool, target, part); err != nil {
		return nil, err
	}
	if err := b.finish(ctx, cfg, a.Disk); err != nil {
		return nil, err
	}
	return b.st.status(ctx, cfg.Pool)
}

func (b *bootOps) detach(ctx context.Context, a BootDetachArgs) (any, error) {
	cfg, err := b.config()
	if err != nil {
		return nil, err
	}
	if err := zfs.ValidVdevRef(a.Device); err != nil {
		return nil, Errorf(CodeBadArgs, "%v", err)
	}
	st, err := b.st.status(ctx, cfg.Pool)
	if err != nil {
		return nil, err
	}
	dev := b.findLeaf(st, a.Device)
	if dev == nil {
		return nil, Errorf(CodeBadArgs, "%s isn't a disk of the boot pool", a.Device)
	}
	online := 0
	for _, v := range leaves(st) {
		if v.State == "ONLINE" && v != dev {
			online++
		}
	}
	if online == 0 {
		return nil, Errorf(CodeForbidden, "%s is the only working boot disk; the server couldn't start without it", a.Device)
	}
	if _, err := b.st.zpool(ctx, "detach", cfg.Pool, a.Device); err != nil {
		return nil, err
	}
	dropDisk(cfg, wholeDisk(dev))
	if err := b.finish(ctx, cfg, ""); err != nil {
		return nil, err
	}
	return b.st.status(ctx, cfg.Pool)
}
