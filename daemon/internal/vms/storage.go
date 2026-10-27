package vms

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Snapshot is a snapshot of a whole VM: its spec, firmware variables,
// saved TPM state and every disk, taken together.
type Snapshot struct {
	Name    string    `json:"name"`
	Label   string    `json:"label"`
	Created time.Time `json:"created"`
	// Bytes is the space the snapshot alone holds on the pool.
	Bytes int64 `json:"bytes"`
	// Consistent: the guest's file systems were frozen first (guest agent).
	Consistent bool `json:"consistent"`
}

var (
	snapLabelRE = regexp.MustCompile(`^[^\x00-\x1f\x7f]{0,80}$`)
	snapNameRE  = regexp.MustCompile(`^vm-[0-9]{8}-[0-9]{6}(-[0-9]{1,3})?$`)
)

// SnapshotArgs takes a snapshot.
type SnapshotArgs struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// TakeSnapshot snapshots a VM. A running VM with the guest agent has its
// file systems frozen for the moment it takes; otherwise the snapshot is
// like pulling the plug (crash-consistent), which journaling file systems
// and databases recover from.
func (m *Manager) TakeSnapshot(ctx context.Context, a SnapshotArgs) (*Snapshot, error) {
	if !snapLabelRE.MatchString(a.Label) {
		return nil, Problems{"the snapshot's description must be at most 80 characters on one line"}
	}
	unlock := m.lock(a.ID)
	defer unlock()
	st, err := m.find(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	name := "vm-" + m.now().Format("20060102-150405")
	existing, _ := m.snapshots(ctx, st)
	for i := 1; ; i++ {
		taken := false
		for _, s := range existing {
			taken = taken || s.Name == name
		}
		if !taken {
			break
		}
		name = fmt.Sprintf("vm-%s-%d", m.now().Format("20060102-150405"), i)
	}
	running := m.state(ctx, a.ID) == "running"
	frozen := false
	if running && st.spec.GuestAgent {
		fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if _, err := m.virsh(fctx, "domfsfreeze", a.ID); err == nil {
			frozen = true
		} else {
			m.log().Info("vms: the guest agent didn't freeze the file systems; the snapshot is crash-consistent", "id", a.ID, "err", err)
		}
		cancel()
	}
	if running && st.spec.Firmware.TPM {
		// The TPM copy on the pool is from the last stop; keep it as is.
		m.log().Debug("vms: snapshot of a running VM keeps the TPM state from its last stop", "id", a.ID)
	}
	consistent := strconv.FormatBool(frozen || !running)
	_, serr := m.zfs(ctx, "snapshot", "-r", "-o", PropLabel+"="+a.Label, "-o", "org.hardyos:consistent="+consistent, st.dataset+"@"+name)
	if frozen {
		if _, err := m.virsh(context.Background(), "domfsthaw", a.ID); err != nil {
			m.log().Error("vms: thawing the guest's file systems", "id", a.ID, "err", err)
		}
	}
	if serr != nil {
		return nil, fmt.Errorf("taking the snapshot: %w", serr)
	}
	m.log().Info("vms: snapshot", "id", a.ID, "snapshot", name, "consistent", consistent)
	return &Snapshot{Name: name, Label: a.Label, Created: m.now(), Consistent: frozen || !running}, nil
}

// Snapshots lists a VM's snapshots, newest first.
func (m *Manager) Snapshots(ctx context.Context, id string) ([]Snapshot, error) {
	st, err := m.find(ctx, id)
	if err != nil {
		return nil, err
	}
	return m.snapshots(ctx, st)
}

func (m *Manager) snapshots(ctx context.Context, st *stored) ([]Snapshot, error) {
	out, err := m.zfs(ctx, "list", "-H", "-p", "-t", "snapshot", "-o", "name,creation,used,"+PropLabel+",org.hardyos:consistent", "-d", "1", st.dataset)
	if err != nil {
		return nil, fmt.Errorf("listing snapshots: %w", err)
	}
	res := []Snapshot{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 5 {
			continue
		}
		ds, name, ok := strings.Cut(f[0], "@")
		if !ok || ds != st.dataset || !snapNameRE.MatchString(name) {
			continue
		}
		s := Snapshot{Name: name, Consistent: f[4] == "true"}
		if secs, err := strconv.ParseInt(f[1], 10, 64); err == nil {
			s.Created = time.Unix(secs, 0).UTC()
		}
		s.Bytes, _ = strconv.ParseInt(f[2], 10, 64)
		if f[3] != "-" {
			s.Label = f[3]
		}
		res = append(res, s)
	}
	// Disk snapshots hold most of the space.
	if out, err := m.zfs(ctx, "list", "-H", "-p", "-t", "snapshot", "-o", "name,used", "-r", st.dataset); err == nil {
		used := map[string]int64{}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			f := strings.Split(line, "\t")
			if len(f) == 2 {
				_, name, _ := strings.Cut(f[0], "@")
				n, _ := strconv.ParseInt(f[1], 10, 64)
				used[name] += n
			}
		}
		for i := range res {
			if n, ok := used[res[i].Name]; ok {
				res[i].Bytes = n
			}
		}
	}
	sort.SliceStable(res, func(i, j int) bool { return res[i].Created.After(res[j].Created) })
	return res, nil
}

// RollbackArgs puts a VM back to a snapshot. Confirm repeats its name.
type RollbackArgs struct {
	ID       string `json:"id"`
	Snapshot string `json:"snapshot"`
	Confirm  string `json:"confirm"`
}

// Rollback puts the VM's disks, settings, firmware variables and TPM back
// to a snapshot. Snapshots after it are deleted. The VM must be off.
func (m *Manager) Rollback(ctx context.Context, a RollbackArgs) (*VM, error) {
	unlock := m.lock(a.ID)
	defer unlock()
	st, err := m.find(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	if !Confirms(a.Confirm, &st.spec) {
		return nil, Problems{fmt.Sprintf("type the VM's name (%s) to confirm", st.spec.Name)}
	}
	if !snapNameRE.MatchString(a.Snapshot) {
		return nil, Problems{fmt.Sprintf("%q isn't a snapshot of this VM", a.Snapshot)}
	}
	if s := m.state(ctx, a.ID); s != "stopped" && s != "crashed" {
		return nil, Problems{"stop the VM before going back to a snapshot"}
	}
	snaps, err := m.snapshots(ctx, st)
	if err != nil {
		return nil, err
	}
	found := false
	for _, s := range snaps {
		found = found || s.Name == a.Snapshot
	}
	if !found {
		return nil, Problems{fmt.Sprintf("%s has no snapshot called %s", st.spec.Name, a.Snapshot)}
	}
	// zfs rollback isn't recursive: each dataset (the VM's and its disks')
	// goes back on its own. Disks added after the snapshot have no such
	// snapshot and are destroyed, so the VM matches it exactly.
	out, err := m.zfs(ctx, "list", "-H", "-o", "name", "-r", st.dataset)
	if err != nil {
		return nil, err
	}
	have, err := m.zfs(ctx, "list", "-H", "-o", "name", "-t", "snapshot", "-r", st.dataset)
	if err != nil {
		return nil, err
	}
	snapped := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(string(have)), "\n") {
		if ds, name, ok := strings.Cut(l, "@"); ok && name == a.Snapshot {
			snapped[ds] = true
		}
	}
	for _, ds := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if ds == "" {
			continue
		}
		if !snapped[ds] {
			if ds == st.dataset {
				return nil, errors.New("the VM's own dataset has no such snapshot")
			}
			if _, err := m.zfs(ctx, "destroy", "-r", ds); err != nil {
				return nil, fmt.Errorf("removing %s, added after the snapshot: %w", ds, err)
			}
			continue
		}
		if _, err := m.zfs(ctx, "rollback", "-r", ds+"@"+a.Snapshot); err != nil {
			return nil, fmt.Errorf("rolling back %s: %w", ds, err)
		}
	}
	back, err := m.read(st.dataset, st.dir)
	if err != nil {
		return nil, fmt.Errorf("reading the VM after the rollback: %w", err)
	}
	// libvirt's TPM state goes back too, from the pool's copy.
	if back.spec.Firmware.TPM {
		_ = os.RemoveAll(m.libvirtTPM(back.spec.UUID))
		if err := m.restoreTPM(back); err != nil {
			m.log().Warn("vms: restoring the TPM after a rollback", "id", a.ID, "err", err)
		}
	}
	if err := m.define(ctx, back, nil); err != nil {
		return nil, err
	}
	m.log().Info("vms: rolled back", "id", a.ID, "snapshot", a.Snapshot)
	return m.Get(ctx, a.ID)
}

// DeleteSnapshotArgs deletes a snapshot.
type DeleteSnapshotArgs struct {
	ID       string `json:"id"`
	Snapshot string `json:"snapshot"`
}

// DeleteSnapshot destroys one snapshot of the VM (all its datasets).
func (m *Manager) DeleteSnapshot(ctx context.Context, a DeleteSnapshotArgs) error {
	unlock := m.lock(a.ID)
	defer unlock()
	st, err := m.find(ctx, a.ID)
	if err != nil {
		return err
	}
	if !snapNameRE.MatchString(a.Snapshot) {
		return Problems{fmt.Sprintf("%q isn't a snapshot of this VM", a.Snapshot)}
	}
	if _, err := m.zfs(ctx, "destroy", "-r", st.dataset+"@"+a.Snapshot); err != nil {
		return fmt.Errorf("deleting the snapshot: %w", err)
	}
	return nil
}

// ---- disk image import ------------------------------------------------------

// image formats qemu-img may read, by what it reports.
var importFormats = map[string]bool{"qcow2": true, "raw": true, "vmdk": true, "vdi": true, "vhdx": true, "vpc": true}

// formatFor guesses a format from the file name; "" lets qemu-img look
// (.img files are often qcow2).
func formatFor(name string) string {
	l := strings.TrimSuffix(strings.ToLower(name), ".xz")
	switch filepath.Ext(l) {
	case ".qcow2":
		return "qcow2"
	case ".vmdk":
		return "vmdk"
	case ".vdi":
		return "vdi"
	case ".vhdx":
		return "vhdx"
	case ".raw":
		return "raw"
	}
	return ""
}

// imageInfo is the part of `qemu-img info --output=json` used here.
type imageInfo struct {
	Format          string `json:"format"`
	VirtualSize     int64  `json:"virtual-size"`
	BackingFilename string `json:"backing-filename"`
	FullBacking     string `json:"full-backing-filename"`
	FormatSpecific  struct {
		Type string `json:"type"`
		Data struct {
			DataFile   string `json:"data-file"`
			CreateType string `json:"create-type"`
			Extents    []struct {
				Filename string `json:"filename"`
			} `json:"extents"`
		} `json:"data"`
	} `json:"format-specific"`
}

// checkImage refuses images that would make qemu-img (running as root)
// read other files: backing files, external data files, multi-file VMDKs.
func checkImage(info imageInfo, self string) error {
	if !importFormats[info.Format] {
		return fmt.Errorf("%q images can't be imported", info.Format)
	}
	if info.BackingFilename != "" || info.FullBacking != "" {
		return errors.New("the image depends on another file (a backing file); export it as one file first")
	}
	if info.FormatSpecific.Data.DataFile != "" {
		return errors.New("the image keeps its data in another file; export it as one file first")
	}
	if info.Format == "vmdk" {
		switch info.FormatSpecific.Data.CreateType {
		case "monolithicSparse", "streamOptimized", "monolithicFlat":
		default:
			return fmt.Errorf("this VMDK (%s) is split into several files; export it as one file (OVA or stream-optimized) first", info.FormatSpecific.Data.CreateType)
		}
		for _, e := range info.FormatSpecific.Data.Extents {
			if e.Filename != self {
				return errors.New("this VMDK points to other files; export it as one file first")
			}
		}
	}
	if info.VirtualSize <= 0 {
		return errors.New("the image's size couldn't be read")
	}
	return nil
}

// ImportArgs fills a new VM's disk from its import image.
type ImportArgs struct {
	ID   string `json:"id"`
	Disk string `json:"disk"`
}

// StartImport copies the disk's image into its zvol in the background and
// returns the task to follow.
func (m *Manager) StartImport(ctx context.Context, a ImportArgs) (*Task, error) {
	st, err := m.find(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	var disk *Disk
	for i := range st.spec.Disks {
		if st.spec.Disks[i].Name == a.Disk {
			disk = &st.spec.Disks[i]
		}
	}
	if disk == nil || disk.Import == nil {
		return nil, Problems{fmt.Sprintf("%s has no disk %s to import into", st.spec.Name, a.Disk)}
	}
	if m.state(ctx, a.ID) != "stopped" {
		return nil, Problems{"the VM must be off while its disk is imported"}
	}
	f, err := m.folder(ctx, "", false)
	if err != nil || f == nil {
		return nil, Problems{"the ISOs shared folder isn't available"}
	}
	src, err := openFile(f, disk.Import.File)
	if err != nil {
		return nil, err
	}
	t, err := m.tasks.start("import", a.ID, disk.Import.File)
	if err != nil {
		src.Close()
		return nil, err
	}
	go func() {
		defer src.Close()
		bg, cancel := context.WithTimeout(context.Background(), 12*time.Hour)
		defer cancel()
		err := m.importDisk(bg, t, st, *disk, src)
		m.tasks.finish(t.ID, err)
		if err != nil {
			m.log().Warn("vms: import failed", "id", a.ID, "disk", a.Disk, "err", err)
		} else {
			m.log().Info("vms: imported", "id", a.ID, "disk", a.Disk, "file", disk.Import.File)
		}
	}()
	return m.tasks.get(t.ID), nil
}

func (m *Manager) importDisk(ctx context.Context, t *Task, st *stored, d Disk, src *os.File) error {
	unlock := m.lock(st.spec.ID)
	defer unlock()
	name := d.Import.File
	input := src
	// .xz images (Home Assistant) are unpacked into the VM's own folder
	// first: qemu-img needs to seek.
	if strings.HasSuffix(strings.ToLower(name), ".xz") {
		m.tasks.progress(t.ID, 1, "Unpacking "+name)
		tmp := filepath.Join(m.sys(st.dir), "import.tmp")
		_ = os.Remove(tmp)
		out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		defer os.Remove(tmp)
		size := int64(0)
		if fi, err := src.Stat(); err == nil {
			size = fi.Size()
		}
		err = m.stream().Pipe(ctx, src, out, func(read int64) {
			if size > 0 {
				m.tasks.progress(t.ID, 1+29*float64(read)/float64(size), "Unpacking "+name)
			}
		}, "xz", "--decompress", "--stdout", "--threads=0")
		out.Close()
		if err != nil {
			return fmt.Errorf("unpacking %s: %w", name, err)
		}
		in, err := os.Open(tmp)
		if err != nil {
			return err
		}
		defer in.Close()
		input = in
	}
	// qemu-img reads the image through a descriptor, never by its path in
	// the shared folder.
	fdPath := "/dev/fd/3"
	format := formatFor(name)
	infoArgs := []string{"info", "--output=json"}
	if format != "" {
		infoArgs = append(infoArgs, "-f", format)
	}
	out, err := m.stream().RunWithFile(ctx, input, "qemu-img", append(infoArgs, fdPath)...)
	if err != nil {
		return fmt.Errorf("reading %s: %w", name, err)
	}
	var info imageInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return fmt.Errorf("reading %s: %w", name, err)
	}
	if err := checkImage(info, fdPath); err != nil {
		return err
	}
	// A disk smaller than the image grows to fit it.
	need := int((info.VirtualSize + (1 << 30) - 1) >> 30)
	if need > d.SizeGB {
		if _, err := m.zfs(ctx, "set", "volsize="+strconv.Itoa(need)+"G", DiskDataset(st.spec.Pool, st.spec.ID, d.Name)); err != nil {
			return fmt.Errorf("growing %s to the image's %d GB: %w", d.Name, need, err)
		}
		cur, err := m.read(st.dataset, st.dir)
		if err == nil {
			for i := range cur.spec.Disks {
				if cur.spec.Disks[i].Name == d.Name {
					cur.spec.Disks[i].SizeGB = need
				}
			}
			if err := m.saveSpec(cur); err != nil {
				return err
			}
		}
	}
	dev := ZvolPath(st.spec.Pool, st.spec.ID, d.Name)
	if err := m.waitDevice(ctx, dev); err != nil {
		return err
	}
	m.tasks.progress(t.ID, 30, "Copying the image into "+d.Name)
	err = m.stream().Progress(ctx, input, func(pct float64) {
		m.tasks.progress(t.ID, 30+pct*0.7, fmt.Sprintf("Copying the image into %s (%.0f%%)", d.Name, pct))
	}, "qemu-img", "convert", "-p", "-n", "-f", info.Format, "-O", "raw", "-W", fdPath, dev)
	if err != nil {
		return fmt.Errorf("copying %s into %s: %w", name, d.Name, err)
	}
	return nil
}

// waitDevice waits for a zvol's device node (udev makes it shortly after
// the zvol is created).
func (m *Manager) waitDevice(ctx context.Context, dev string) error {
	for i := 0; i < 60; i++ {
		if _, err := os.Stat(m.sys(dev)); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("the disk %s didn't appear", dev)
}
