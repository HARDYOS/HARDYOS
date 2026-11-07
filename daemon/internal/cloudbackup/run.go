package cloudbackup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"golang.org/x/sys/unix"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/backup"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// SystemMeta describes hardyd's database copy for the settings item.
type SystemMeta struct {
	Version  string `json:"version"`
	Hostname string `json:"hostname"`
	Schema   int    `json:"schema"`
	Users    int    `json:"users"`
}

// BackupArgs starts a backup run.
type BackupArgs struct {
	Target    string     `json:"target"`
	Task      string     `json:"task"`
	Run       string     `json:"run"`
	Items     []Item     `json:"items"`
	Retention Retention  `json:"retention"`
	SystemDB  string     `json:"systemDb,omitempty"` // hardyd's database copy (system item)
	System    SystemMeta `json:"system"`
}

// ItemResult is how one item's backup went.
type ItemResult struct {
	Item       string   `json:"item"`
	Name       string   `json:"name"`
	Snapshots  []string `json:"snapshots"`
	Files      int64    `json:"files"`
	Bytes      int64    `json:"bytes"`
	Added      int64    `json:"added"`
	Consistent bool     `json:"consistent"`
	Error      string   `json:"error,omitempty"`
	Warning    string   `json:"warning,omitempty"`
}

// RunResult is a finished run.
type RunResult struct {
	Run      string       `json:"run"`
	Items    []ItemResult `json:"items"`
	Manifest string       `json:"manifest"` // the manifest's snapshot
	Failed   int          `json:"failed"`
}

// ShareRecord is a shared folder's settings in a run manifest, enough to
// make it again on a rebuilt server.
type ShareRecord struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Pool        string          `json:"pool"`
	QuotaBytes  uint64          `json:"quotaBytes"`
	Recycle     bool            `json:"recycle"`
	Guest       bool            `json:"guest"`
	Access      []shares.Rule   `json:"access"`
	Services    shares.Services `json:"services"`
}

// VMRecord is a VM in a run manifest.
type VMRecord struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Pool       string           `json:"pool"`
	Consistent bool             `json:"consistent"`
	Disks      []vms.BackupDisk `json:"disks"`
}

// Manifest describes one run; it goes into the repository with the run.
type Manifest struct {
	Format   int                 `json:"format"`
	Run      string              `json:"run"`
	Task     string              `json:"task"`
	Time     time.Time           `json:"time"`
	Hostname string              `json:"hostname"`
	Version  string              `json:"version"`
	Items    []ItemResult        `json:"items"`
	Shares   []ShareRecord       `json:"shares"`
	Apps     []apps.BackupSource `json:"apps"`
	VMs      []VMRecord          `json:"vms"`
}

// ManifestName is the manifest's file name in the repository.
const ManifestName = "hardyos-run.json"

// SettingsName is the settings archive's file name in the repository.
const SettingsName = "hardyos-settings.hbak"

// Excludes are left out of folder backups: the recycle bin and uploads
// in progress (snapshots aren't visible in a mounted snapshot anyway).
var Excludes = []string{".recycle", ".hardyos-upload-*"}

var excludeRE = regexp.MustCompile(`^[A-Za-z0-9._*-]{1,64}$`)

// StartBackup checks a run and starts it as a task.
func (r *Root) StartBackup(a BackupArgs) (*Task, error) {
	if err := ValidID(a.Task); err != nil {
		return nil, err
	}
	if err := ValidRunID(a.Run); err != nil {
		return nil, err
	}
	if err := a.Retention.Check(); err != nil {
		return nil, err
	}
	if len(a.Items) == 0 || len(a.Items) > 256 {
		return nil, problemf("choose what to back up")
	}
	seen := map[string]bool{}
	for _, it := range a.Items {
		if err := it.Check(); err != nil {
			return nil, err
		}
		if seen[it.Key()] {
			return nil, problemf("%s is listed twice", it.Key())
		}
		seen[it.Key()] = true
	}
	repo, err := r.repo(a.Target)
	if err != nil {
		return nil, err
	}
	return r.tasks.start(TaskBackup, a.Target, func(ctx context.Context, tc taskCtx) (any, error) {
		return r.runBackup(ctx, tc, repo, a)
	})
}

func (r *Root) runDir() string {
	if z, ok := r.Vol.(*ZFS); ok {
		return z.runDir()
	}
	if d, ok := r.Vol.(interface{ BaseDir() string }); ok {
		return d.BaseDir()
	}
	return DefaultRunDir
}

// mountDir is an item's stable folder: restic finds each file's previous
// version by this path.
func (r *Root) mountDir(it Item) string {
	return filepath.Join(r.runDir(), "mnt", it.Kind, it.ID)
}

func (r *Root) runBackup(ctx context.Context, tc taskCtx, repo *Repo, a BackupArgs) (*RunResult, error) {
	defer snapshotCache.drop(repo.Target.ID)
	res := &RunResult{Run: a.Run}
	m := Manifest{Format: 1, Run: a.Run, Task: a.Task, Time: r.now(), Hostname: a.System.Hostname, Version: a.System.Version,
		Shares: []ShareRecord{}, Apps: []apps.BackupSource{}, VMs: []VMRecord{}}
	snap := "hardyos-cloud-" + a.Run
	server := "server=" + r.ServerID()
	tags := func(it Item, extra ...string) []string {
		return append([]string{"task=" + a.Task, "run=" + a.Run, "item=" + it.Key(), server}, extra...)
	}
	var shareList []shares.Share
	if r.Shares != nil {
		for _, it := range a.Items {
			if it.Kind == ItemShare {
				l, err := r.Shares.List(ctx)
				if err != nil {
					return nil, err
				}
				shareList = l
				break
			}
		}
	}
	n := float64(len(a.Items))
	for i, it := range a.Items {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		base := float64(i) / n * 95
		step := func(p Progress, what string) {
			tc.progress(base+p.Percent*95/n, what)
		}
		ir := ItemResult{Item: it.Key(), Snapshots: []string{}}
		var err error
		switch it.Kind {
		case ItemShare:
			err = r.backupShare(ctx, repo, it, snap, tags(it), shareList, &ir, &m, step)
		case ItemApp:
			err = r.backupApp(ctx, repo, it, snap, tags(it), &ir, &m, step)
		case ItemVM:
			err = r.backupVM(ctx, repo, it, snap, tags, &ir, &m, step)
		case ItemSystem:
			err = r.backupSystem(ctx, repo, a, tags(it), &ir, step)
		}
		if err != nil {
			if ctx.Err() != nil {
				_ = r.Restic.ForgetSnapshots(context.WithoutCancel(ctx), repo, ir.Snapshots)
				return res, ctx.Err()
			}
			ir.Error = err.Error()
			res.Failed++
			r.log().Warn("cloud backup: item failed", "target", a.Target, "task", a.Task, "item", it.Key(), "err", err)
		}
		res.Items = append(res.Items, ir)
	}
	m.Items = res.Items
	tc.progress(96, "Recording what this version holds")
	mb, _ := json.MarshalIndent(m, "", "  ")
	sum, err := r.Restic.Backup(ctx, repo, ResticBackup{Stdin: bytes.NewReader(mb), StdinName: ManifestName,
		Tags: []string{"task=" + a.Task, "run=" + a.Run, "item=manifest", server}}, nil)
	if err != nil {
		return res, fmt.Errorf("saving the run's manifest: %w", err)
	}
	res.Manifest = sum.SnapshotID
	tc.progress(98, "Removing versions older than the task keeps")
	if err := r.Restic.Forget(ctx, repo, a.Task, a.Retention); err != nil {
		r.log().Warn("cloud backup: applying retention", "task", a.Task, "err", err)
	}
	if res.Failed > 0 {
		return res, &PartialError{Failed: res.Failed, Total: len(a.Items)}
	}
	return res, nil
}

// PartialError: some items of a run failed (the others are backed up).
type PartialError struct{ Failed, Total int }

func (e *PartialError) Error() string {
	return fmt.Sprintf("%d of %d items couldn't be backed up", e.Failed, e.Total)
}

// folderBackup snapshots dataset, mounts the snapshot at the item's
// stable folder, backs it up and cleans up.
func (r *Root) folderBackup(ctx context.Context, repo *Repo, it Item, dataset, snap string, tags []string, ir *ItemResult, step func(Progress, string), what string) error {
	dir := r.mountDir(it)
	unlock := r.itemLock(dir)
	defer unlock()
	if err := r.Vol.Snapshot(ctx, dataset, snap); err != nil {
		return fmt.Errorf("taking the snapshot: %w", err)
	}
	defer func() {
		if err := r.Vol.DestroySnapshot(context.WithoutCancel(ctx), dataset, snap); err != nil {
			r.log().Warn("cloud backup: removing the snapshot", "dataset", dataset, "err", err)
		}
	}()
	return r.backupMounted(ctx, repo, dataset, snap, dir, tags, ir, step, what)
}

func (r *Root) backupMounted(ctx context.Context, repo *Repo, dataset, snap, dir string, tags []string, ir *ItemResult, step func(Progress, string), what string) error {
	if err := r.Vol.MountSnapshot(ctx, dataset, snap, dir); err != nil {
		return fmt.Errorf("mounting the snapshot: %w", err)
	}
	defer func() {
		if err := r.Vol.Unmount(context.WithoutCancel(ctx), dir); err != nil {
			r.log().Warn("cloud backup: unmounting the snapshot", "dir", dir, "err", err)
		}
	}()
	sum, err := r.Restic.Backup(ctx, repo, ResticBackup{Path: dir, Tags: tags, Excludes: Excludes}, func(p Progress) {
		step(Progress{Percent: p.Percent}, what)
	})
	if sum != nil {
		ir.Snapshots = append(ir.Snapshots, sum.SnapshotID)
		ir.Files += sum.TotalFiles
		ir.Bytes += sum.TotalBytes
		ir.Added += sum.DataAdded
	}
	if err != nil && sum != nil {
		ir.Warning = err.Error()
		return nil
	}
	return err
}

func (r *Root) backupShare(ctx context.Context, repo *Repo, it Item, snap string, tags []string, l []shares.Share, ir *ItemResult, m *Manifest, step func(Progress, string)) error {
	var sh *shares.Share
	for i := range l {
		if l[i].ID == it.ID {
			sh = &l[i]
		}
	}
	if sh == nil {
		return fmt.Errorf("the shared folder %s doesn't exist any more", it.ID)
	}
	ir.Name, ir.Consistent = sh.Name, true
	if !sh.Usable() {
		return fmt.Errorf("%s isn't available (its pool is locked or not imported)", sh.Name)
	}
	m.Shares = append(m.Shares, ShareRecord{ID: sh.ID, Name: sh.Name, Description: sh.Description, Pool: sh.Pool, QuotaBytes: sh.QuotaBytes,
		Recycle: sh.Recycle, Guest: sh.Guest, Access: sh.Access, Services: sh.Services})
	return r.folderBackup(ctx, repo, it, sh.Dataset, snap, tags, ir, step, "Backing up "+sh.Name)
}

func (r *Root) backupApp(ctx context.Context, repo *Repo, it Item, snap string, tags []string, ir *ItemResult, m *Manifest, step func(Progress, string)) error {
	if r.Apps == nil {
		return errors.New("apps aren't available on this server")
	}
	src, err := r.Apps.BackupSource(ctx, it.ID)
	if err != nil {
		return err
	}
	ir.Name, ir.Consistent = src.Name, true
	// A database dump into the app's folders first, so the version holds
	// a consistent copy next to the (crash-consistent) database files. A
	// failed dump doesn't stop the backup: the files are still there.
	step(Progress{}, "Preparing "+src.Name+"'s data")
	if _, err := r.Apps.PreBackup(ctx, it.ID); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		ir.Warning = "the app's own database dump didn't run (" + err.Error() + "); its database files are crash-consistent"
		r.log().Warn("cloud backup: app dump", "app", it.ID, "err", err)
	}
	m.Apps = append(m.Apps, *src)
	return r.folderBackup(ctx, repo, it, src.Dataset, snap, tags, ir, step, "Backing up "+src.Name)
}

// DiskName is a VM disk's file name in the repository.
func DiskName(vm, disk string) string { return "vm-" + vm + "-" + disk + ".raw" }

func (r *Root) backupVM(ctx context.Context, repo *Repo, it Item, snap string, tags func(Item, ...string) []string, ir *ItemResult, m *Manifest, step func(Progress, string)) error {
	if r.VMs == nil {
		return errors.New("virtual machines aren't available on this server")
	}
	dir := r.mountDir(it)
	unlock := r.itemLock(dir)
	defer unlock()
	bs, err := r.VMs.BackupSnapshot(ctx, it.ID, snap)
	if err != nil {
		return err
	}
	defer func() {
		if err := r.VMs.ReleaseBackupSnapshot(context.WithoutCancel(ctx), it.ID, snap); err != nil {
			r.log().Warn("cloud backup: removing the VM's snapshot", "vm", it.ID, "err", err)
		}
	}()
	ir.Name, ir.Consistent = bs.Name, bs.Consistent
	if !bs.Consistent {
		ir.Warning = "the guest agent didn't freeze the VM's file systems, so this version is like pulling the plug (crash-consistent)"
	}
	m.VMs = append(m.VMs, VMRecord{ID: bs.ID, Name: bs.Name, Pool: bs.Pool, Consistent: bs.Consistent, Disks: bs.Disks})
	// Settings, firmware variables, TPM state.
	parts := float64(1 + len(bs.Disks))
	sub := func(i int) func(Progress, string) {
		return func(p Progress, what string) { step(Progress{Percent: (float64(i) + p.Percent) / parts}, what) }
	}
	if err := r.backupMounted(ctx, repo, bs.Dataset, snap, dir, tags(it, "part=files"), ir, sub(0), "Backing up "+bs.Name+"'s settings"); err != nil {
		return err
	}
	for i, d := range bs.Disks {
		rd, err := r.Vol.OpenZvolSnapshot(ctx, d.Dataset, snap)
		if err != nil {
			return fmt.Errorf("reading %s: %w", d.Name, err)
		}
		sum, err := r.Restic.Backup(ctx, repo, ResticBackup{Stdin: rd, StdinName: DiskName(it.ID, d.Name), Tags: tags(it, "part=disk:"+d.Name)}, func(p Progress) {
			pct := p.Percent
			if d.Bytes > 0 && p.BytesDone > 0 {
				pct = float64(p.BytesDone) / float64(d.Bytes)
			}
			sub(i+1)(Progress{Percent: pct}, "Backing up "+bs.Name+"'s disk "+d.Name)
		})
		rd.Close()
		if err != nil {
			return fmt.Errorf("backing up %s: %w", d.Name, err)
		}
		ir.Snapshots = append(ir.Snapshots, sum.SnapshotID)
		ir.Bytes += sum.TotalBytes
		ir.Added += sum.DataAdded
	}
	return nil
}

var dbNameRE = regexp.MustCompile(`^cloud-[0-9a-f]{16}\.db$`)

// systemDB reads hardyd's database copy from its work directory: a plain
// file directly in it, never through a link.
func (r *Root) systemDB(path string) ([]byte, error) {
	work := r.WorkDir
	if work == "" {
		work = "/" + backup.WorkDir
	}
	if filepath.Dir(path) != work || !dbNameRE.MatchString(filepath.Base(path)) {
		return nil, fmt.Errorf("the database copy must be in %s", work)
	}
	// hardyd owns the folder: no link anywhere on the way is followed.
	fd, err := openNoLinks(path)
	if err != nil {
		return nil, err
	}
	// A regular file hardyd made, with one name (not a hard link to a file
	// hardyd can't read, such as root's keys).
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		closeFD(fd)
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || (r.DBOwner > 0 && int(st.Uid) != r.DBOwner) {
		closeFD(fd)
		return nil, errors.New("the database copy isn't hardyd's own file")
	}
	return readAllFD(fd, backup.MaxBytes)
}

func (r *Root) backupSystem(ctx context.Context, repo *Repo, a BackupArgs, tags []string, ir *ItemResult, step func(Progress, string)) error {
	ir.Name, ir.Consistent = "Settings and domain", true
	if r.System == nil {
		return errors.New("settings can't be backed up here")
	}
	db, err := r.systemDB(a.SystemDB)
	if err != nil {
		return err
	}
	step(Progress{Percent: 0.1}, "Collecting the settings and the domain")
	files, err := r.System.Collect(ctx, true)
	if err != nil {
		return fmt.Errorf("collecting the settings: %w", err)
	}
	host := a.System.Hostname
	if host == "" {
		host, _ = os.Hostname()
	}
	// Everything a rebuilt server needs, keys included: the repository is
	// encrypted, and the archive is sealed with the repository key too.
	archive, err := backup.Pack(backup.Contents{Manifest: backup.Manifest{CreatedAt: r.now().Truncate(time.Second), Version: a.System.Version,
		Hostname: host, Schema: a.System.Schema, Users: a.System.Users, Note: "cloud"}, DB: db, Files: files}, repo.Creds.RepoPassword)
	if err != nil {
		return err
	}
	sum, err := r.Restic.Backup(ctx, repo, ResticBackup{Stdin: bytes.NewReader(archive), StdinName: SettingsName, Tags: tags}, func(p Progress) {
		step(Progress{Percent: 0.2 + p.Percent*0.8}, "Backing up the settings")
	})
	if err != nil {
		return err
	}
	ir.Snapshots = append(ir.Snapshots, sum.SnapshotID)
	ir.Files, ir.Bytes, ir.Added = 1, sum.TotalBytes, sum.DataAdded
	return nil
}
