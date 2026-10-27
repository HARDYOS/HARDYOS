package vms

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
)

// Cloud backups (internal/cloudbackup) back a VM up from a recursive
// snapshot of its dataset and disks taken like a VM snapshot (the guest's
// file systems frozen through the agent when it runs one), and restore a
// VM in place or onto a rebuilt server.

// BackupSnapPrefix starts the snapshots cloud backups take; they never
// show among the VM's own snapshots (snapNameRE) and are removed after the
// backup.
const BackupSnapPrefix = "hardyos-cloud-"

var backupSnapRE = regexp.MustCompile(`^hardyos-cloud-[a-z0-9-]{1,48}$`)

// BackupDisk is one disk in a backup snapshot.
type BackupDisk struct {
	Name    string `json:"name"`
	Dataset string `json:"dataset"`
	Bytes   int64  `json:"bytes"`
}

// BackupSnap is a VM's snapshot for a backup.
type BackupSnap struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	Pool       string       `json:"pool"`
	Dataset    string       `json:"dataset"`
	Snapshot   string       `json:"snapshot"`
	Consistent bool         `json:"consistent"`
	Running    bool         `json:"running"`
	Spec       Spec         `json:"spec"`
	Disks      []BackupDisk `json:"disks"`
}

// BackupIDs lists every VM's id (for backing up all of them).
func (m *Manager) BackupIDs(ctx context.Context) ([]string, error) {
	l, err := m.all(ctx)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, st := range l {
		out = append(out, st.spec.ID)
	}
	return out, nil
}

// BackupSnapshot takes the recursive snapshot snap (BackupSnapPrefix...)
// of a VM for a backup.
func (m *Manager) BackupSnapshot(ctx context.Context, id, snap string) (*BackupSnap, error) {
	if !backupSnapRE.MatchString(snap) {
		return nil, fmt.Errorf("bad backup snapshot name %q", snap)
	}
	unlock, err := m.lockValid(id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	st, err := m.find(ctx, id)
	if err != nil {
		return nil, err
	}
	running := m.state(ctx, id) == "running"
	frozen := false
	if running && st.spec.GuestAgent {
		fctx, cancel := context.WithTimeout(ctx, FreezeTimeout)
		if _, err := m.virsh(fctx, "domfsfreeze", id); err == nil {
			frozen = true
		} else {
			m.log().Info("vms: the guest agent didn't freeze the file systems; the backup is crash-consistent", "id", id, "err", err)
			m.thaw(id)
		}
		cancel()
	}
	consistent := frozen || !running
	_, serr := m.zfs(ctx, "snapshot", "-r", "-o", "org.hardyos:consistent="+strconv.FormatBool(consistent), st.dataset+"@"+snap)
	if frozen {
		m.thaw(id)
	}
	if serr != nil {
		return nil, fmt.Errorf("taking the snapshot for the backup: %w", serr)
	}
	pool, _, _ := strings.Cut(st.dataset, "/")
	b := &BackupSnap{ID: id, Name: st.spec.Name, Pool: pool, Dataset: st.dataset, Snapshot: snap, Consistent: consistent, Running: running, Spec: st.spec}
	for _, d := range st.spec.Disks {
		ds := DiskDataset(pool, id, d.Name)
		out, err := m.zfs(ctx, "get", "-H", "-p", "-o", "value", "volsize", ds+"@"+snap)
		if err != nil {
			_ = m.ReleaseBackupSnapshot(context.WithoutCancel(ctx), id, snap)
			return nil, fmt.Errorf("reading %s's size: %w", d.Name, err)
		}
		n, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
		if err != nil || n <= 0 {
			_ = m.ReleaseBackupSnapshot(context.WithoutCancel(ctx), id, snap)
			return nil, fmt.Errorf("%s has no size", d.Name)
		}
		b.Disks = append(b.Disks, BackupDisk{Name: d.Name, Dataset: ds, Bytes: n})
	}
	return b, nil
}

// ReleaseBackupSnapshot removes a backup snapshot (all datasets).
func (m *Manager) ReleaseBackupSnapshot(ctx context.Context, id, snap string) error {
	if !backupSnapRE.MatchString(snap) || ValidID(id) != nil {
		return fmt.Errorf("bad backup snapshot")
	}
	l, err := m.datasets(ctx)
	if err != nil {
		return err
	}
	for ds := range l {
		if strings.HasSuffix(ds, "/vms/"+id) {
			if _, err := m.zfs(ctx, "destroy", "-r", ds+"@"+snap); err != nil && !strings.Contains(err.Error(), "could not find any snapshots") {
				return err
			}
		}
	}
	return nil
}

// RestoreFill writes a VM's files and disks from a backup.
type RestoreFill struct {
	// Spec is the VM as the backup describes it (its vm.json).
	Spec Spec
	// DiskBytes is each disk's size in the backup.
	DiskBytes map[string]int64
	// Files writes the VM folder's files (NVRAM, TPM state, cloud-init
	// seed; vm.json is written by the manager) into dir, the VM dataset's
	// verified mount with device dev.
	Files func(ctx context.Context, dir string, dev uint64) error
	// Disk writes one disk's image onto its block device.
	Disk func(ctx context.Context, name, device string) error
}

// RestoreFromBackup puts a VM back to a version from a backup. It must be
// off and confirm must be its name. A VM snapshot is taken first (so the
// restore can be undone from the VM's snapshots); disks not in the
// version are destroyed, disks it has are resized to it and overwritten.
func (m *Manager) RestoreFromBackup(ctx context.Context, id, confirm string, f RestoreFill) (*VM, error) {
	check := func() (*stored, error) {
		st, err := m.find(ctx, id)
		if err != nil {
			return nil, err
		}
		if !Confirms(confirm, &st.spec) {
			return nil, Problems{fmt.Sprintf("type the VM's name (%s) to confirm", st.spec.Name)}
		}
		if s := m.state(ctx, id); s != "stopped" && s != "crashed" {
			return nil, Problems{"stop the VM before restoring it"}
		}
		return st, nil
	}
	if _, err := check(); err != nil {
		return nil, err
	}
	if _, err := m.TakeSnapshot(ctx, SnapshotArgs{ID: id, Label: "Before restoring from a backup"}); err != nil {
		return nil, err
	}
	unlock, err := m.lockValid(id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	st, err := check()
	if err != nil {
		return nil, err
	}
	spec := f.Spec
	pool, _, _ := strings.Cut(st.dataset, "/")
	if spec.ID != id || spec.UUID != st.spec.UUID {
		return nil, Problems{"that backup is of another VM"}
	}
	spec.Pool = pool
	return m.fillFromBackup(ctx, st, &spec, f, false)
}

// RestoreNewFromBackup creates a VM from a backup on pool (a rebuilt
// server). A VM with that id must not exist.
func (m *Manager) RestoreNewFromBackup(ctx context.Context, pool string, f RestoreFill) (*VM, error) {
	s := f.Spec
	s.Pool = pool
	s.Normalize()
	if err := m.checkStored(&s); err != nil {
		return nil, Problems{"the VM in the backup isn't valid here: " + err.Error()}
	}
	if ValidID(s.ID) != nil {
		return nil, Problems{"the VM in the backup has an invalid id"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.find(ctx, s.ID); err == nil {
		return nil, Problems{fmt.Sprintf("there's already a VM called %s", s.ID)}
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	ds := Dataset(pool, s.ID)
	if _, err := m.zfs(ctx, "list", "-H", "-o", "name", ds); err == nil {
		return nil, Problems{fmt.Sprintf("%s already exists on %s", ds, pool)}
	}
	parent := pool + "/vms"
	if _, err := m.zfs(ctx, "list", "-H", "-o", "name", parent); err != nil {
		if _, err := m.zfs(ctx, "create", parent); err != nil {
			return nil, fmt.Errorf("creating %s: %w", parent, err)
		}
	}
	if _, err := m.zfs(ctx, "create", "-o", PropVM+"="+s.ID, "-o", "canmount=on", "-o", "devices=off", "-o", "setuid=off", "-o", "exec=off",
		"-o", "quota="+strconv.FormatInt(quotaBytes(&s), 10), ds); err != nil {
		return nil, fmt.Errorf("creating the VM's dataset: %w", err)
	}
	st, err := m.mounted(ctx, ds)
	if err != nil {
		_, _ = m.zfs(context.WithoutCancel(ctx), "destroy", "-r", ds)
		return nil, err
	}
	st.spec = s
	v, err := m.fillFromBackup(ctx, st, &s, f, true)
	if err != nil {
		m.log().Warn("vms: a VM restored from a backup is incomplete", "id", s.ID, "err", err)
	}
	return v, err
}

func (m *Manager) fillFromBackup(ctx context.Context, st *stored, spec *Spec, f RestoreFill, fresh bool) (*VM, error) {
	pool, _, _ := strings.Cut(st.dataset, "/")
	if f.Files != nil {
		if err := f.Files(ctx, st.dir, st.dev); err != nil {
			return nil, fmt.Errorf("restoring the VM's files: %w", err)
		}
	}
	// Disks: the version's set, at the version's sizes.
	want := map[string]bool{}
	for _, d := range spec.Disks {
		want[d.Name] = true
	}
	if !fresh {
		for _, d := range st.spec.Disks {
			if !want[d.Name] {
				if _, err := m.zfs(ctx, "destroy", "-r", DiskDataset(pool, spec.ID, d.Name)); err != nil {
					return nil, fmt.Errorf("removing %s, which the version doesn't have: %w", d.Name, err)
				}
			}
		}
	}
	for _, d := range spec.Disks {
		ds := DiskDataset(pool, spec.ID, d.Name)
		size := f.DiskBytes[d.Name]
		if size <= 0 {
			return nil, fmt.Errorf("the backup has no image of %s", d.Name)
		}
		if _, err := m.zfs(ctx, "list", "-H", "-o", "name", ds); err != nil {
			if _, err := m.zfs(ctx, "create", "-s", "-V", strconv.FormatInt(size, 10), "-o", "volblocksize=16K", "-o", PropVM+"="+spec.ID, ds); err != nil {
				return nil, fmt.Errorf("creating %s: %w", d.Name, err)
			}
		} else if _, err := m.zfs(ctx, "set", "volsize="+strconv.FormatInt(size, 10), ds); err != nil {
			return nil, fmt.Errorf("resizing %s: %w", d.Name, err)
		}
		dev, err := m.waitZvol(ctx, pool, spec.ID, d.Name)
		if err != nil {
			return nil, err
		}
		if err := f.Disk(ctx, d.Name, dev); err != nil {
			return nil, fmt.Errorf("restoring %s: %w", d.Name, err)
		}
	}
	st.spec = *spec
	if err := m.saveSpec(st); err != nil {
		return nil, err
	}
	back, err := m.read(st.dataset, st.dir)
	if err != nil {
		return nil, fmt.Errorf("reading the restored VM: %w", err)
	}
	if back.spec.Firmware.TPM {
		if dir, err := m.libvirtTPM(back.spec.UUID); err == nil {
			_ = os.RemoveAll(dir)
			if err := m.restoreTPM(back); err != nil {
				m.log().Warn("vms: restoring the TPM state from a backup", "id", spec.ID, "err", err)
			}
		}
	}
	if err := m.setQuota(ctx, back.dataset, &back.spec, 0); err != nil {
		m.log().Warn("vms: setting the VM's space limit after a restore", "id", spec.ID, "err", err)
	}
	if err := m.define(ctx, back, nil); err != nil {
		return nil, err
	}
	m.log().Info("vms: restored from a backup", "id", spec.ID)
	return m.Get(ctx, spec.ID)
}

// waitZvol waits for a zvol's device node (udev makes it).
func (m *Manager) waitZvol(ctx context.Context, pool, id, disk string) (string, error) {
	p := ZvolPath(pool, id, disk)
	for i := 0; i < 120; i++ {
		if fi, err := os.Stat(m.sys(p)); err == nil && fi.Mode()&os.ModeDevice != 0 {
			return m.sys(p), nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return "", fmt.Errorf("%s didn't appear", filepath.Base(p))
}
