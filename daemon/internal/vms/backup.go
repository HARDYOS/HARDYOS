package vms

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
	// Note, when set, is told what the restore did besides the version
	// (disks it kept, the safety snapshot).
	Note func(msg string)
}

func (f *RestoreFill) note(format string, args ...any) {
	if f.Note != nil {
		f.Note(fmt.Sprintf(format, args...))
	}
}

// RestoreFromBackup puts a VM back to a version from a backup. It must be
// off and confirm must be its name. The version's spec is checked as
// strictly as one read from a pool before anything changes. A VM snapshot
// is taken first (so the restore can be undone from the VM's snapshots);
// the disks the version has are resized to it and overwritten. Disks the
// VM has now and the version doesn't are never destroyed: they stay
// attached, after the version's, so the safety snapshot keeps every
// dataset it was taken of (decision 225).
func (m *Manager) RestoreFromBackup(ctx context.Context, id, confirm string, f RestoreFill) (*VM, error) {
	spec := f.Spec
	spec.Normalize()
	if spec.ID != id {
		return nil, Problems{"that backup is of another VM"}
	}
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
	prepare := func(st *stored) error {
		pool, _, _ := strings.Cut(st.dataset, "/")
		if spec.UUID != st.spec.UUID {
			return Problems{"that backup is of another VM"}
		}
		spec.Pool = pool
		if err := m.checkStored(&spec); err != nil {
			return Problems{"the VM in the backup isn't valid here: " + err.Error()}
		}
		for _, d := range spec.Disks {
			if f.DiskBytes[d.Name] <= 0 {
				return fmt.Errorf("the backup has no image of %s", d.Name)
			}
		}
		return nil
	}
	st, err := check()
	if err != nil {
		return nil, err
	}
	if err := prepare(st); err != nil {
		return nil, err
	}
	snap, err := m.TakeSnapshot(ctx, SnapshotArgs{ID: id, Label: "Before restoring from a backup"})
	if err != nil {
		return nil, err
	}
	unlock, err := m.lockValid(id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if st, err = check(); err != nil {
		return nil, err
	}
	if err := prepare(st); err != nil {
		return nil, err
	}
	// Disks the version doesn't have stay, attached after its own.
	have := map[string]bool{}
	for _, d := range spec.Disks {
		have[d.Name] = true
	}
	var kept []string
	for _, d := range st.spec.Disks {
		if !have[d.Name] {
			spec.Disks = append(spec.Disks, d)
			kept = append(kept, d.Name)
		}
	}
	if len(kept) > 0 {
		if err := m.checkStored(&spec); err != nil {
			return nil, Problems{fmt.Sprintf("the version doesn't have %s, which can't stay attached: %v; remove it first", strings.Join(kept, ", "), err)}
		}
		f.note("kept %s, which the version doesn't have, attached after its disks", strings.Join(kept, ", "))
	}
	f.note("the VM's snapshot %s has it as it was before the restore", snap.Name)
	v, err := m.fillFromBackup(ctx, st, &spec, f, kept)
	if err != nil {
		return nil, fmt.Errorf("%w (the VM's snapshot %s has it as it was)", err, snap.Name)
	}
	return v, nil
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
	v, err := m.fillFromBackup(ctx, st, &s, f, nil)
	if err != nil {
		m.log().Warn("vms: a VM restored from a backup is incomplete", "id", s.ID, "err", err)
	}
	return v, err
}

// fillFromBackup writes the files and the version's disks; kept are disks
// already there that the version doesn't have (left as they are).
func (m *Manager) fillFromBackup(ctx context.Context, st *stored, spec *Spec, f RestoreFill, kept []string) (*VM, error) {
	pool, _, _ := strings.Cut(st.dataset, "/")
	if f.Files != nil {
		if err := f.Files(ctx, st.dir, st.dev); err != nil {
			return nil, fmt.Errorf("restoring the VM's files: %w", err)
		}
	}
	// Disks: the version's, at the version's sizes; nothing is destroyed.
	for _, d := range spec.Disks {
		if slices.Contains(kept, d.Name) {
			continue
		}
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

// zvolReady says whether a zvol's node is there (a device; tests use files).
var zvolReady = func(fi os.FileInfo) bool { return fi.Mode()&os.ModeDevice != 0 }

// waitZvol waits for a zvol's device node (udev makes it).
func (m *Manager) waitZvol(ctx context.Context, pool, id, disk string) (string, error) {
	p := ZvolPath(pool, id, disk)
	for i := 0; i < 120; i++ {
		if fi, err := os.Stat(m.sys(p)); err == nil && zvolReady(fi) {
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
