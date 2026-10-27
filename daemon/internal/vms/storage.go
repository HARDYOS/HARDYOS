package vms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
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
	unlock, err := m.lockValid(a.ID)
	if err != nil {
		return nil, err
	}
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
		fctx, cancel := context.WithTimeout(ctx, FreezeTimeout)
		if _, err := m.virsh(fctx, "domfsfreeze", a.ID); err == nil {
			frozen = true
		} else {
			m.log().Info("vms: the guest agent didn't freeze the file systems; the snapshot is crash-consistent", "id", a.ID, "err", err)
			// A freeze that timed out may still happen in the guest.
			m.thaw(a.ID)
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
		m.thaw(a.ID)
	}
	if serr != nil {
		return nil, fmt.Errorf("taking the snapshot: %w", serr)
	}
	m.log().Info("vms: snapshot", "id", a.ID, "snapshot", name, "consistent", consistent)
	return &Snapshot{Name: name, Label: a.Label, Created: m.now(), Consistent: frozen || !running}, nil
}

// FreezeTimeout bounds asking the guest agent to freeze or thaw.
const FreezeTimeout = 30 * time.Second

// thaw lets the guest's file systems go again, retrying a few times: a
// guest left frozen stops writing altogether.
func (m *Manager) thaw(id string) {
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), FreezeTimeout)
		_, err := m.virsh(ctx, "domfsthaw", id)
		cancel()
		if err == nil {
			return
		}
		m.log().Error("vms: thawing the guest's file systems", "id", id, "try", i+1, "err", err)
	}
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
	unlock, err := m.lockValid(a.ID)
	if err != nil {
		return nil, err
	}
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
		dir, err := m.libvirtTPM(back.spec.UUID)
		if err != nil {
			return nil, err
		}
		_ = os.RemoveAll(dir)
		if err := m.restoreTPM(back); err != nil {
			m.log().Warn("vms: restoring the TPM after a rollback", "id", a.ID, "err", err)
		}
	}
	if err := m.setQuota(ctx, back.dataset, &back.spec, 0); err != nil {
		m.log().Warn("vms: setting the VM's space limit after a rollback", "id", a.ID, "err", err)
	}
	if err := m.define(ctx, back, nil); err != nil {
		return nil, err
	}
	m.log().Info("vms: rolled back", "id", a.ID, "snapshot", a.Snapshot)
	return m.Get(ctx, a.ID)
}

// DeleteSnapshotArgs deletes a snapshot. Confirm repeats the VM's name.
type DeleteSnapshotArgs struct {
	ID       string `json:"id"`
	Snapshot string `json:"snapshot"`
	Confirm  string `json:"confirm"`
}

// DeleteSnapshot destroys one snapshot of the VM (all its datasets).
func (m *Manager) DeleteSnapshot(ctx context.Context, a DeleteSnapshotArgs) error {
	unlock, err := m.lockValid(a.ID)
	if err != nil {
		return err
	}
	defer unlock()
	st, err := m.find(ctx, a.ID)
	if err != nil {
		return err
	}
	if !Confirms(a.Confirm, &st.spec) {
		return Problems{fmt.Sprintf("type the VM's name (%s) to confirm", st.spec.Name)}
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

// Imports (decision 134). The image is a file in a shared folder, which its
// writers can change at any time, so root copies it once, through the
// descriptor it opened, into a private file in the VM's folder (unpacking
// .xz on the way, both with a size limit). qemu-img then only ever sees that
// copy: as the unprivileged import user, in a sandbox with no network and
// none of the pools or shares, with backing files turned off, reading the
// copy and writing the one zvol it's allowed to.

// image formats qemu-img may read, by what it reports.
var importFormats = map[string]bool{"qcow2": true, "raw": true, "vmdk": true, "vdi": true, "vhdx": true, "vpc": true}

// backingFormats are the importable formats that can have a backing file.
var backingFormats = map[string]bool{"qcow2": true, "vmdk": true}

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

// imageSpec is a qemu block "json:" filename for the copy: the format
// given (or probed when ""), the file by its path, and no backing file.
func imageSpec(format, path string) string {
	o := map[string]any{"file": map[string]string{"driver": "file", "filename": path}}
	if format != "" {
		o["driver"] = format
		if backingFormats[format] {
			o["backing"] = nil
		}
	}
	b, _ := json.Marshal(o)
	return "json:" + string(b)
}

// infoArgs and convertArgs are qemu-img's arguments for the copy at image.
func infoArgs(format, image string) []string {
	return []string{"info", "--output=json", imageSpec(format, image)}
}

func convertArgs(format, image, target string) []string {
	return []string{"convert", "-p", "-n", "-W", "-O", "raw", imageSpec(format, image), target}
}

// imageInfo is the part of `qemu-img info --output=json` used here.
type imageInfo struct {
	Format          string `json:"format"`
	Filename        string `json:"filename"`
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

// checkImage refuses images that would make qemu-img read other files:
// backing files, external data files, multi-file VMDKs.
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
		case "monolithicSparse", "streamOptimized":
		default:
			return fmt.Errorf("this VMDK (%s) is split into several files; export it as one file (OVA or stream-optimized) first", info.FormatSpecific.Data.CreateType)
		}
		ext := info.FormatSpecific.Data.Extents
		if len(ext) != 1 || (ext[0].Filename != self && ext[0].Filename != info.Filename) {
			return errors.New("this VMDK points to other files; export it as one file first")
		}
	}
	if info.VirtualSize <= 0 {
		return errors.New("the image's size couldn't be read")
	}
	if info.VirtualSize > int64(MaxDiskGB)<<30 {
		return fmt.Errorf("the image is a %d GB disk; VM disks can be at most %d TB", info.VirtualSize>>30, MaxDiskGB>>10)
	}
	return nil
}

// checkMagic looks at the copy's first bytes: VMDKs must be one binary
// file (a text descriptor names other files), and a file that says it's
// something else is refused before qemu-img opens it.
func checkMagic(f *os.File, format string) error {
	head := make([]byte, 512)
	n, err := f.ReadAt(head, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	head = head[:n]
	if bytes.Contains(head, []byte("DescriptorFile")) || bytes.HasPrefix(bytes.TrimLeft(head, " \t\r\n"), []byte("#")) && bytes.Contains(head, []byte("createType")) {
		return errors.New("this VMDK is a descriptor that points to other files; export it as one file first")
	}
	if format == "vmdk" && !bytes.HasPrefix(head, []byte("KDMV")) {
		return errors.New("this isn't a single-file VMDK; export it as one file (OVA or stream-optimized) first")
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

func (m *Manager) importGID() (int, error) {
	if m.ImportGID != nil {
		return m.ImportGID()
	}
	g, err := user.LookupGroup(m.importUser())
	if err != nil {
		return 0, fmt.Errorf("the import user (%s) doesn't exist; reinstall HardyOS's package: %w", m.importUser(), err)
	}
	id, err := strconv.Atoi(g.Gid)
	return id, err
}

// stageImport copies src (unpacking .xz) into a new private file in the
// VM's folder, at most limit bytes, and makes it readable to the import
// group only. The caller removes it.
func (m *Manager) stageImport(ctx context.Context, t *Task, st *stored, name string, src *os.File, limit int64) (string, error) {
	gid, err := m.importGID()
	if err != nil {
		return "", err
	}
	host := filepath.Join(st.dir, "import-"+randomHex(8)+".img")
	out, err := os.OpenFile(m.sys(host), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		out.Close()
		if !ok {
			_ = os.Remove(m.sys(host))
		}
	}()
	size := int64(0)
	if fi, err := src.Stat(); err == nil {
		size = fi.Size()
	}
	w := &capWriter{w: out, n: limit}
	tooBig := fmt.Errorf("%s is bigger than the space there is for it (%s); free up space on the pool or use a smaller image", name, human(limit))
	if strings.HasSuffix(strings.ToLower(name), ".xz") {
		m.tasks.progress(t.ID, 1, "Unpacking "+name)
		err = m.stream().Unpack(ctx, src, w, func(read int64) {
			if size > 0 {
				m.tasks.progress(t.ID, 1+29*float64(read)/float64(size), "Unpacking "+name)
			}
		})
		if w.done >= limit || errors.Is(err, errTooBig) {
			return "", tooBig
		}
		if err != nil {
			return "", fmt.Errorf("unpacking %s: %w", name, err)
		}
	} else {
		if size > limit {
			return "", tooBig
		}
		m.tasks.progress(t.ID, 1, "Reading "+name)
		cr := &countingReader{r: src, on: func(read int64) {
			if size > 0 {
				m.tasks.progress(t.ID, 1+29*float64(read)/float64(size), "Reading "+name)
			}
		}}
		if _, err := io.Copy(w, cr); err != nil {
			if errors.Is(err, errTooBig) {
				return "", tooBig
			}
			return "", fmt.Errorf("reading %s: %w", name, err)
		}
	}
	if err := out.Sync(); err != nil {
		return "", err
	}
	if err := out.Chown(-1, gid); err != nil {
		return "", err
	}
	if err := out.Chmod(0o440); err != nil {
		return "", err
	}
	ok = true
	return host, nil
}

// zvolDevice is the zvol's real device node (/dev/zdN), the one path the
// sandbox gets.
func (m *Manager) zvolDevice(link string) (string, error) {
	p, err := filepath.EvalSymlinks(m.sys(link))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(m.root(), p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("%s isn't a device", link)
	}
	dev := "/" + rel
	if !strings.HasPrefix(dev, "/dev/") {
		return "", fmt.Errorf("%s isn't a device", link)
	}
	return dev, nil
}

func (m *Manager) importDisk(ctx context.Context, t *Task, st *stored, d Disk, src *os.File) error {
	unlock := m.lock(st.spec.ID)
	defer unlock()
	name := d.Import.File
	// 1. A private copy, within the pool's free space (the VM's space limit
	// leaves room for it while it lasts).
	free, err := m.available(ctx, st.spec.Pool)
	if err != nil {
		return err
	}
	limit := min(int64(MaxDiskGB)<<30, free-spaceReserve)
	if limit <= 0 {
		return Problems{fmt.Sprintf("the pool %s is full", st.spec.Pool)}
	}
	if err := m.setQuota(ctx, st.dataset, &st.spec, limit); err != nil {
		return err
	}
	defer func() {
		cur, err := m.read(st.dataset, st.dir)
		if err != nil {
			cur = st
		}
		if err := m.setQuota(context.Background(), st.dataset, &cur.spec, 0); err != nil {
			m.log().Warn("vms: setting the VM's space limit after an import", "id", st.spec.ID, "err", err)
		}
	}()
	image, err := m.stageImport(ctx, t, st, name, src, limit)
	if err != nil {
		return err
	}
	defer os.Remove(m.sys(image))
	copyFile, err := os.Open(m.sys(image))
	if err != nil {
		return err
	}
	format := formatFor(name)
	err = checkMagic(copyFile, format)
	copyFile.Close()
	if err != nil {
		return err
	}
	// 2. What it is, without opening anything it refers to.
	out, err := m.stream().QemuImg(ctx, ImgJob{Args: infoArgs(format, image), Image: image})
	if err != nil {
		return fmt.Errorf("reading %s: %w", name, err)
	}
	var info imageInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return fmt.Errorf("reading %s: %w", name, err)
	}
	if err := checkImage(info, image); err != nil {
		return err
	}
	if format == "" && info.Format == "vmdk" {
		// A probed VMDK is checked like a named one.
		f, err := os.Open(m.sys(image))
		if err != nil {
			return err
		}
		err = checkMagic(f, info.Format)
		f.Close()
		if err != nil {
			return err
		}
	}
	// 3. A disk smaller than the image grows to fit it.
	need := int((info.VirtualSize + (1 << 30) - 1) >> 30)
	if need > MaxDiskGB {
		return fmt.Errorf("the image is a %d GB disk; VM disks can be at most %d TB", need, MaxDiskGB>>10)
	}
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
	link := ZvolPath(st.spec.Pool, st.spec.ID, d.Name)
	if err := m.waitDevice(ctx, link); err != nil {
		return err
	}
	dev, err := m.zvolDevice(link)
	if err != nil {
		return err
	}
	// 4. The copy into the zvol, in the sandbox.
	m.tasks.progress(t.ID, 30, "Copying the image into "+d.Name)
	_, err = m.stream().QemuImg(ctx, ImgJob{Args: convertArgs(info.Format, image, dev), Image: image, Target: dev, OnPct: func(pct float64) {
		m.tasks.progress(t.ID, 30+pct*0.7, fmt.Sprintf("Copying the image into %s (%.0f%%)", d.Name, pct))
	}})
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
