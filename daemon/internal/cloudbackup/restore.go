package cloudbackup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/backup"
	"github.com/hardyos/hardyos/daemon/internal/fileworker"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// Restore modes.
const (
	// ModeCopy restores into a new folder at the top of the shared folder.
	ModeCopy = "copy"
	// ModeInPlace puts the chosen files back where they were, replacing
	// what's there now.
	ModeInPlace = "in_place"
	// ModeRollback puts a whole shared folder, app or VM back to the
	// version (the item's name typed in Confirm); for the settings item,
	// it stages a settings restore for the next restart.
	ModeRollback = "rollback"
)

// RestoreArgs restores from a version.
type RestoreArgs struct {
	Target   string   `json:"target"`
	Snapshot string   `json:"snapshot"` // the item's snapshot (a VM: its settings' one)
	Paths    []string `json:"paths,omitempty"`
	Mode     string   `json:"mode"`
	Folder   string   `json:"folder,omitempty"`
	Confirm  string   `json:"confirm,omitempty"`
	// Who: a person restoring their own files (not an administrator).
	Who *fileworker.Who `json:"who,omitempty"`
	// MaxSchema is the newest settings database hardyd can open (settings
	// restores).
	MaxSchema int `json:"maxSchema,omitempty"`
}

// RestoreResult says what a restore did.
type RestoreResult struct {
	Item     string   `json:"item"`
	Files    int      `json:"files"`
	Folders  int      `json:"folders"`
	Bytes    int64    `json:"bytes"`
	Skipped  int      `json:"skipped"`
	Folder   string   `json:"folder,omitempty"`
	Safety   string   `json:"safety,omitempty"` // snapshot with the state before
	Notes    []string `json:"notes"`
	Restart  bool     `json:"restart,omitempty"` // settings: applies at the next restart
	Snapshot string   `json:"snapshot"`
}

// MaxUserEntries bounds a person's own restore.
const MaxUserEntries = 20000

// StartRestore checks a restore and starts it as a task.
func (r *Root) StartRestore(ctx context.Context, a RestoreArgs) (*Task, error) {
	repo, err := r.repo(a.Target)
	if err != nil {
		return nil, err
	}
	snap, it, err := r.findSnapshot(ctx, repo, a.Snapshot)
	if err != nil {
		return nil, err
	}
	if snap.Tag("part") != "" && snap.Tag("part") != "files" {
		return nil, problemf("choose the version itself, not one of its disks")
	}
	if err := r.checkWho(ctx, a.Who, it); err != nil {
		return nil, err
	}
	if a.Who != nil && !r.ours(snap) {
		return nil, problemf("that version was made by another server")
	}
	if a.Who != nil && len(a.Paths) == 0 {
		return nil, problemf("choose the files and folders to restore")
	}
	if len(a.Paths) > 1000 {
		return nil, problemf("choose at most 1000 files and folders")
	}
	var rels [][]string
	for _, p := range a.Paths {
		parts, err := cleanRel(p)
		if err != nil {
			return nil, err
		}
		if len(parts) == 0 {
			rels = nil
			break
		}
		rels = append(rels, parts)
	}
	switch a.Mode {
	case ModeCopy, ModeInPlace:
		if it.Kind != ItemShare {
			return nil, problemf("apps, VMs and settings are restored as a whole")
		}
		if a.Mode == ModeCopy {
			if err := fileworker.CleanName(a.Folder); err != nil {
				return nil, problemf("give the new folder a name")
			}
		}
		if a.Mode == ModeInPlace && len(rels) == 0 && a.Who == nil {
			return nil, problemf("to put the whole folder back, roll it back to the version")
		}
	case ModeRollback:
		if a.Who != nil {
			return nil, problemf("only administrators can roll a folder back")
		}
		if len(rels) > 0 {
			return nil, problemf("a rollback restores everything")
		}
		if strings.TrimSpace(a.Confirm) == "" {
			return nil, problemf("type the name to confirm")
		}
		if it.Kind == ItemSystem && !strings.EqualFold(strings.TrimSpace(a.Confirm), "settings") {
			return nil, problemf("type settings to confirm replacing this server's settings")
		}
	default:
		return nil, problemf("choose how to restore")
	}
	var release func()
	if a.Who != nil {
		if release, err = r.startPersonRestore(a.Who); err != nil {
			return nil, err
		}
	}
	t, err := r.tasks.start(TaskRestore, a.Target, func(ctx context.Context, tc taskCtx) (any, error) {
		if release != nil {
			defer release()
		}
		res, err := r.restore(ctx, tc, repo, snap, it, rels, a)
		if res != nil {
			res.Snapshot, res.Item = snap.ID, it.Key()
		}
		return res, err
	})
	if err != nil && release != nil {
		release()
	}
	return t, err
}

func (r *Root) restore(ctx context.Context, tc taskCtx, repo *Repo, snap *Snapshot, it Item, rels [][]string, a RestoreArgs) (*RestoreResult, error) {
	switch it.Kind {
	case ItemShare:
		return r.restoreShare(ctx, tc, repo, snap, it, rels, a)
	case ItemApp:
		return r.restoreApp(ctx, tc, repo, snap, it, a)
	case ItemVM:
		return r.restoreVM(ctx, tc, repo, snap, it, a.Confirm, "")
	case ItemSystem:
		return r.restoreSettings(ctx, tc, repo, snap, a.MaxSchema)
	}
	return nil, problemf("that can't be restored")
}

func (r *Root) findShare(ctx context.Context, id string) (*shares.Share, error) {
	l, err := r.Shares.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range l {
		if l[i].ID == id {
			if !l[i].Usable() {
				return nil, fmt.Errorf("%s isn't available (its pool is locked or not imported)", l[i].Name)
			}
			return &l[i], nil
		}
	}
	return nil, fmt.Errorf("the shared folder %s doesn't exist (any more); rebuild it from the backup instead", id)
}

// staged is a version unpacked into a private staging dataset.
type staged struct {
	pool, name string
	dir        string // the staging dataset's folder
	dev        uint64
	root       string // the item's folder inside it
	fd         int    // open on root
}

// stage restores snap (the given paths below its item folder, or all of
// it) into a new staging dataset on pool, at most the version's size with
// headroom, and at most limit bytes when limit > 0 (a person's restore).
func (r *Root) stage(ctx context.Context, tc taskCtx, repo *Repo, snap *Snapshot, pool string, rels [][]string, limit int64) (*staged, error) {
	name := "r-" + randomID(6)
	quota := stagingQuota(snap)
	if limit > 0 && quota > limit {
		quota = limit
	}
	dir, dev, err := r.Vol.CreateStaging(ctx, pool, name, quota)
	if err != nil {
		return nil, err
	}
	st := &staged{pool: pool, name: name, dir: dir, dev: dev, fd: -1}
	base := snap.Paths[0]
	var includes []string
	for _, parts := range rels {
		includes = append(includes, path.Join(append([]string{base}, parts...)...))
	}
	tc.progress(5, "Downloading the version")
	err = r.Restic.Restore(ctx, repo, snap.ID, "", dir, includes, func(p Progress) {
		tc.progress(5+p.Percent*60, "Downloading the version")
	})
	if err != nil {
		r.unstage(st)
		if limit > 0 && strings.Contains(err.Error(), "quota") {
			return nil, problemf("that's more than %s; choose fewer files or ask an administrator", humanBytes(limit))
		}
		if strings.Contains(err.Error(), "quota") {
			return nil, fmt.Errorf("the version unpacked to more than expected (%s): %w", humanBytes(quota), err)
		}
		return nil, err
	}
	st.root = filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(base, "/")))
	sfd, err := openFolder(dir, dev)
	if err != nil {
		r.unstage(st)
		return nil, err
	}
	fd, err := openBeneath(sfd, strings.Split(strings.TrimPrefix(base, "/"), "/"), oRDONLY|oDIRECTORY)
	closeFD(sfd)
	if err != nil {
		r.unstage(st)
		return nil, fmt.Errorf("the version is empty: %w", err)
	}
	st.fd = fd
	return st, nil
}

func (r *Root) unstage(st *staged) {
	if st.fd >= 0 {
		closeFD(st.fd)
	}
	if err := r.Vol.DestroyStaging(context.Background(), st.pool, st.name); err != nil {
		r.log().Warn("cloud backup: removing a restore's work space", "pool", st.pool, "name", st.name, "err", err)
	}
}

func (r *Root) restoreShare(ctx context.Context, tc taskCtx, repo *Repo, snap *Snapshot, it Item, rels [][]string, a RestoreArgs) (*RestoreResult, error) {
	sh, err := r.findShare(ctx, it.ID)
	if err != nil {
		return nil, err
	}
	res := &RestoreResult{Notes: []string{}}
	if a.Mode == ModeRollback && !strings.EqualFold(strings.TrimSpace(a.Confirm), sh.Name) && a.Confirm != sh.ID {
		return nil, problemf("type the shared folder's name (%s) to confirm", sh.Name)
	}
	if a.Who != nil {
		if err := r.checkWho(ctx, a.Who, it); err != nil {
			return nil, err
		}
	}
	var limit int64
	if a.Who != nil {
		limit = MaxUserBytes
	}
	st, err := r.stage(ctx, tc, repo, snap, sh.Pool, rels, limit)
	if err != nil {
		return nil, err
	}
	defer r.unstage(st)
	if len(rels) == 0 {
		names, err := readNames(st.fd)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			if !fileworker.Hidden(n) {
				rels = append(rels, []string{n})
			}
		}
	}
	tc.progress(70, "Restoring the files")
	if a.Who != nil {
		return res, r.restoreAsPerson(ctx, tc, *a.Who, sh, st, rels, a, res)
	}
	cs := &copyStats{keepOwner: true, mapManaged: true}
	shareFD, err := openFolder(sh.Path, sh.RootDev)
	if err != nil {
		return nil, err
	}
	defer closeFD(shareFD)
	switch a.Mode {
	case ModeRollback:
		safety := "hardyos-manual-" + r.now().Format("20060102-150405")
		if err := r.Vol.Snapshot(ctx, sh.Dataset, safety); err != nil {
			return nil, fmt.Errorf("taking a snapshot of %s first: %w", sh.Name, err)
		}
		res.Safety = safety
		for _, parts := range rels {
			if err := copyEntry(ctx, st.fd, parts[0], shareFD, parts[0], true, cs); err != nil {
				cs.note("%s: %v", parts[0], err)
			}
		}
		if err := prune(ctx, st.fd, shareFD, true, fileworker.Hidden, cs); err != nil {
			return nil, err
		}
	case ModeCopy:
		res.Folder = a.Folder
		if err := mkdirAt(shareFD, a.Folder); err != nil {
			return nil, err
		}
		dst, err := openBeneath(shareFD, []string{a.Folder}, oRDONLY|oDIRECTORY)
		if err != nil {
			return nil, err
		}
		defer closeFD(dst)
		for _, parts := range rels {
			if err := r.copyRel(ctx, st.fd, dst, parts, false, cs); err != nil {
				cs.note("%s: %v", strings.Join(parts, "/"), err)
			}
		}
	case ModeInPlace:
		for _, parts := range rels {
			if err := r.copyRel(ctx, st.fd, shareFD, parts, true, cs); err != nil {
				cs.note("%s: %v", strings.Join(parts, "/"), err)
			}
		}
	}
	res.Files, res.Folders, res.Bytes, res.Skipped = cs.Files+cs.Links, cs.Dirs, cs.Bytes, cs.Skipped
	res.Notes = append(res.Notes, cs.Notes...)
	return res, nil
}

// copyRel copies the entry parts (below the staged item root) to the same
// place below dst, making its parent folders.
func (r *Root) copyRel(ctx context.Context, src, dst int, parts []string, replace bool, cs *copyStats) error {
	dir := parts[:len(parts)-1]
	name := parts[len(parts)-1]
	sp, err := openBeneath(src, dir, oRDONLY|oDIRECTORY)
	if err != nil {
		return fmt.Errorf("not in this version")
	}
	defer closeFD(sp)
	dp, err := mkdirBeneath(dst, dir)
	if err != nil {
		return err
	}
	defer closeFD(dp)
	return copyEntry(ctx, sp, name, dp, name, replace, cs)
}

// restoreAsPerson copies the staged files into the shared folder as the
// person: each file is opened in the staged copy by a file worker running
// as them (so the permissions it had in the backup apply) and created in
// the shared folder by another (so their access today applies).
func (r *Root) restoreAsPerson(ctx context.Context, tc taskCtx, who fileworker.Who, sh *shares.Share, st *staged, rels [][]string, a RestoreArgs, res *RestoreResult) error {
	if r.Files == nil {
		return problemf("restoring your own files isn't available")
	}
	level, err := r.Files.RulesLevel(ctx, who, sh.ID)
	if err != nil {
		return err
	}
	if level != shares.LevelWrite {
		return problemf("you can only read %s, so nothing can be restored into it", sh.Name)
	}
	in := fileworker.Root{Name: sh.Name + " (backup)", Path: st.root, Dev: st.dev}
	prefix := ""
	if a.Mode == ModeCopy {
		if _, _, err := r.Files.Do(ctx, fileworker.OpMkdir, fileworker.Args{Who: who, Share: sh.ID, Path: a.Folder}); err != nil {
			return err
		}
		prefix = a.Folder + "/"
		res.Folder = a.Folder
	}
	count := 0
	readable := map[string]bool{}
	var walk func(rel string) error
	walk = func(rel string) error {
		if count++; count > MaxUserEntries {
			return problemf("that's more than %d files; ask an administrator to restore it", MaxUserEntries)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		raw, _, err := r.Files.DoIn(ctx, fileworker.OpStat, who, in, fileworker.Args{Path: rel})
		if err != nil {
			res.Skipped++
			addNote(res, "%s: %v", rel, err)
			return nil
		}
		var e fileworker.Entry
		if json.Unmarshal(raw, &e) != nil {
			return errors.New("file worker: bad answer")
		}
		dest := prefix + rel
		// Their access today: they must be able to read what is there now
		// (or the nearest folder that exists), so a restore never puts
		// files where they couldn't look, or over what they can't read.
		if err := r.personCanRead(ctx, who, sh.ID, dest, readable); err != nil {
			res.Skipped++
			addNote(res, "%s: %v", rel, err)
			return nil
		}
		if e.Dir {
			_, _, err := r.Files.Do(ctx, fileworker.OpMkdir, fileworker.Args{Who: who, Share: sh.ID, Path: dest})
			var fe *fileworker.Error
			if err != nil && !(errors.As(err, &fe) && fe.Code == fileworker.CodeExists) {
				res.Skipped++
				addNote(res, "%s: %v", rel, err)
				return nil
			}
			raw, _, err := r.Files.DoIn(ctx, fileworker.OpList, who, in, fileworker.Args{Path: rel})
			if err != nil {
				res.Skipped++
				addNote(res, "%s: %v", rel, err)
				return nil
			}
			var l fileworker.Listing
			if json.Unmarshal(raw, &l) != nil {
				return errors.New("file worker: bad answer")
			}
			res.Folders++
			for _, c := range l.Entries {
				if err := walk(rel + "/" + c.Name); err != nil {
					return err
				}
			}
			return nil
		}
		_, src, err := r.Files.DoIn(ctx, fileworker.OpOpen, who, in, fileworker.Args{Path: rel})
		if err != nil {
			res.Skipped++
			addNote(res, "%s: %v", rel, err)
			return nil
		}
		defer src.Close()
		_, dst, err := r.Files.Do(ctx, fileworker.OpCreate, fileworker.Args{Who: who, Share: sh.ID, Path: dest, Overwrite: a.Mode == ModeInPlace})
		if err != nil {
			res.Skipped++
			addNote(res, "%s: %v", rel, err)
			return nil
		}
		n, err := io.Copy(dst, src)
		if cerr := dst.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			res.Skipped++
			addNote(res, "%s: %v", rel, err)
			return nil
		}
		_, _, _ = r.Files.Do(ctx, fileworker.OpSetTime, fileworker.Args{Who: who, Share: sh.ID, Path: dest, Modified: e.Modified})
		res.Files++
		res.Bytes += n
		return nil
	}
	for i, parts := range rels {
		tc.progress(70+float64(i)/float64(len(rels))*29, "Restoring the files")
		if err := walk(strings.Join(parts, "/")); err != nil {
			return err
		}
	}
	return nil
}

// personCanRead checks that who can read dest in the live shared folder if
// it exists (a folder listed, a file opened), or else the nearest folder
// above it that exists. ok caches folders already checked.
func (r *Root) personCanRead(ctx context.Context, who fileworker.Who, share, dest string, ok map[string]bool) error {
	notFound := func(err error) bool {
		var fe *fileworker.Error
		return errors.As(err, &fe) && fe.Code == fileworker.CodeNotFound
	}
	raw, _, err := r.Files.Do(ctx, fileworker.OpStat, fileworker.Args{Who: who, Share: share, Path: dest})
	if err == nil {
		var e fileworker.Entry
		if json.Unmarshal(raw, &e) != nil {
			return errors.New("file worker: bad answer")
		}
		if e.Dir {
			if ok[dest] {
				return nil
			}
			if _, _, err := r.Files.Do(ctx, fileworker.OpList, fileworker.Args{Who: who, Share: share, Path: dest}); err != nil {
				return fmt.Errorf("you can't open the folder that is there now: %w", err)
			}
			ok[dest] = true
			return nil
		}
		_, f, err := r.Files.Do(ctx, fileworker.OpOpen, fileworker.Args{Who: who, Share: share, Path: dest})
		if err != nil {
			return fmt.Errorf("you can't read the file that is there now: %w", err)
		}
		if f != nil {
			f.Close()
		}
		return nil
	}
	if !notFound(err) {
		return err
	}
	for p := path.Dir(dest); ; p = path.Dir(p) {
		if p == "." || p == "/" {
			p = ""
		}
		if ok[p] {
			return nil
		}
		_, _, err := r.Files.Do(ctx, fileworker.OpList, fileworker.Args{Who: who, Share: share, Path: p})
		if err == nil {
			ok[p] = true
			return nil
		}
		if !notFound(err) || p == "" {
			return fmt.Errorf("you can't open the folder it goes into: %w", err)
		}
	}
}

func addNote(res *RestoreResult, format string, a ...any) {
	if len(res.Notes) < 20 {
		res.Notes = append(res.Notes, fmt.Sprintf(format, a...))
	}
}

// fillFrom copies a staged item folder over a dataset's folder (all of
// it, removing what the version doesn't have; hidden names at the top
// are kept unless keepHidden is false).
func (r *Root) fillFrom(ctx context.Context, st *staged, dir string, dev uint64, keepHidden bool, allowLink func([]string) bool, mapManaged bool) (*copyStats, error) {
	dfd, err := openFolder(dir, dev)
	if err != nil {
		return nil, err
	}
	defer closeFD(dfd)
	cs := &copyStats{keepOwner: true, allowLink: allowLink, mapManaged: mapManaged}
	names, err := readNames(st.fd)
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		if err := copyEntry(ctx, st.fd, n, dfd, n, true, cs); err != nil {
			return cs, fmt.Errorf("%s: %w", n, err)
		}
	}
	hidden := func(string) bool { return false }
	if keepHidden {
		hidden = fileworker.Hidden
	}
	return cs, prune(ctx, st.fd, dfd, true, hidden, cs)
}

func (r *Root) restoreApp(ctx context.Context, tc taskCtx, repo *Repo, snap *Snapshot, it Item, a RestoreArgs) (*RestoreResult, error) {
	if r.Apps == nil {
		return nil, errors.New("apps aren't available on this server")
	}
	src, err := r.Apps.BackupSource(ctx, it.ID)
	if err != nil {
		return nil, err
	}
	st, err := r.stage(ctx, tc, repo, snap, src.Pool, nil, 0)
	if err != nil {
		return nil, err
	}
	defer r.unstage(st)
	res := &RestoreResult{Notes: []string{}}
	tc.progress(70, "Putting "+src.Name+" back")
	err = r.Apps.RestoreData(ctx, it.ID, a.Confirm, func(ctx context.Context, dir, dataset string) error {
		dev, err := r.Vol.VerifyMount(dir, dataset)
		if err != nil {
			return err
		}
		cs, err := r.fillFrom(ctx, st, dir, dev, false, linksOnlyInData, false)
		if cs != nil {
			res.Files, res.Folders, res.Bytes, res.Skipped = cs.Files+cs.Links, cs.Dirs, cs.Bytes, cs.Skipped
			res.Notes = append(res.Notes, cs.Notes...)
		}
		return err
	})
	return res, err
}

// vmFill builds the VM manager's restore callbacks from a version.
func (r *Root) vmFill(ctx context.Context, tc taskCtx, repo *Repo, snap *Snapshot, it Item, st *staged) (vms.RestoreFill, error) {
	var f vms.RestoreFill
	specFD, err := openBeneath(st.fd, []string{"vm.json"}, oRDONLY)
	if err != nil {
		return f, errors.New("the version has no VM settings")
	}
	b, err := readAllFD(specFD, 1<<20)
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f.Spec); err != nil {
		return f, fmt.Errorf("the version's VM settings can't be read: %w", err)
	}
	if f.Spec.ID != it.ID {
		return f, errors.New("the version holds another VM")
	}
	all, err := r.snapshots(ctx, repo)
	if err != nil {
		return f, err
	}
	disks := map[string]string{}
	f.DiskBytes = map[string]int64{}
	for _, s := range all {
		// The disks of this very run of this server (decision 238): a disk
		// snapshot another server, or someone with the key, put in the same
		// run is never written to this VM, and two for one disk stop it.
		if s.Tag("run") == snap.Tag("run") && s.Tag("item") == it.Key() && s.Tag("server") == snap.Tag("server") {
			if d, ok := strings.CutPrefix(s.Tag("part"), "disk:"); ok {
				if disks[d] != "" {
					return f, fmt.Errorf("the version has two images of %s", d)
				}
				if s.Paths == nil || len(s.Paths) != 1 || s.Paths[0] != "/"+DiskName(it.ID, d) {
					return f, fmt.Errorf("the version's image of %s isn't one HardyOS made", d)
				}
				disks[d] = s.ID
				if s.Summary != nil {
					f.DiskBytes[d] = s.Summary.TotalBytes
				}
			}
		}
	}
	for _, d := range f.Spec.Disks {
		if disks[d.Name] == "" {
			return f, fmt.Errorf("the version has no image of %s", d.Name)
		}
	}
	f.Files = func(ctx context.Context, dir string, dev uint64) error {
		dfd, err := openFolder(dir, dev)
		if err != nil {
			return err
		}
		defer closeFD(dfd)
		cs := &copyStats{keepOwner: true, allowLink: noLinks}
		names, err := readNames(st.fd)
		if err != nil {
			return err
		}
		for _, n := range names {
			if n == "vm.json" {
				continue // the manager writes it
			}
			if err := copyEntry(ctx, st.fd, n, dfd, n, true, cs); err != nil {
				return fmt.Errorf("%s: %w", n, err)
			}
		}
		return nil
	}
	i := 0
	f.Disk = func(ctx context.Context, name, device string) error {
		i++
		tc.progress(70+float64(i)/float64(len(f.Spec.Disks)+1)*28, "Writing disk "+name)
		pr, pw := io.Pipe()
		go func() {
			pw.CloseWithError(r.Restic.Dump(ctx, repo, disks[name], "/"+DiskName(it.ID, name), pw))
		}()
		_, err := writeDevice(device, pr)
		pr.CloseWithError(err)
		return err
	}
	return f, nil
}

func (r *Root) restoreVM(ctx context.Context, tc taskCtx, repo *Repo, snap *Snapshot, it Item, confirm, newPool string) (*RestoreResult, error) {
	if r.VMs == nil {
		return nil, errors.New("virtual machines aren't available on this server")
	}
	pool := newPool
	if pool == "" {
		v, err := r.VMs.Get(ctx, it.ID)
		if err != nil {
			return nil, err
		}
		pool = v.Spec.Pool
	}
	st, err := r.stage(ctx, tc, repo, snap, pool, nil, 0)
	if err != nil {
		return nil, err
	}
	defer r.unstage(st)
	f, err := r.vmFill(ctx, tc, repo, snap, it, st)
	if err != nil {
		return nil, err
	}
	res := &RestoreResult{Notes: []string{}}
	f.Note = func(msg string) { res.Notes = append(res.Notes, msg) }
	if newPool != "" {
		_, err = r.VMs.RestoreNewFromBackup(ctx, newPool, f)
	} else {
		_, err = r.VMs.RestoreFromBackup(ctx, it.ID, confirm, f)
	}
	return res, err
}

// readSettings dumps and opens a version's settings archive.
func (r *Root) readSettings(ctx context.Context, repo *Repo, snap *Snapshot) (*backup.Contents, error) {
	var buf bytes.Buffer
	lw := &limitWriter{w: &buf, n: backup.MaxBytes + 1}
	if err := r.Restic.Dump(ctx, repo, snap.ID, "/"+SettingsName, lw); err != nil {
		return nil, err
	}
	if buf.Len() > backup.MaxBytes {
		return nil, errors.New("the settings archive is too large")
	}
	return backup.Unpack(buf.Bytes(), repo.Creds.RepoPassword)
}

func (r *Root) restoreSettings(ctx context.Context, tc taskCtx, repo *Repo, snap *Snapshot, maxSchema int) (*RestoreResult, error) {
	if r.System == nil {
		return nil, errors.New("settings can't be restored here")
	}
	tc.progress(10, "Downloading the settings")
	c, err := r.readSettings(ctx, repo, snap)
	if err != nil {
		return nil, err
	}
	if maxSchema > 0 && c.Manifest.Schema > maxSchema {
		return nil, fmt.Errorf("these settings were saved by a newer HardyOS (%s); update this server first", c.Manifest.Version)
	}
	if c.Manifest.Users == 0 {
		return nil, errors.New("the settings have no user accounts, so nobody could sign in after restoring them")
	}
	if _, err := r.System.StageContents(c); err != nil {
		return nil, err
	}
	// The restored server carries on as the one that made the versions.
	if err := r.adoptServerID(snap.Tag("server")); err != nil {
		return nil, err
	}
	return &RestoreResult{Restart: true, Notes: []string{"The settings are restored when the server restarts."}}, nil
}
