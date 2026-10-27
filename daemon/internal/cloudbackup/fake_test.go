package cloudbackup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/backup"
	"github.com/hardyos/hardyos/daemon/internal/fileworker"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// Test doubles: datasets are folders, snapshots are copies, a "mounted"
// snapshot is a copy at the stable folder, and zvols are files.

func needRestic(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("HARDYOS_RESTIC"); p != "" {
		return p
	}
	p, err := exec.LookPath("restic")
	if err != nil {
		t.Skip("restic isn't installed (set HARDYOS_RESTIC)")
	}
	return p
}

// tmp is a temp dir under TMPDIR (tests run non-root with TMPDIR=/dev/shm/...).
func tmp(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "cb-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err == nil && e.IsDir() {
				_ = os.Chmod(p, 0o700)
			}
			return nil
		})
		os.RemoveAll(d)
	})
	return d
}

func devOf(t testing.TB, p string) uint64 {
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil {
		t.Fatal(err)
	}
	return uint64(st.Dev)
}

func copyTreeFS(src, dst string) error {
	return filepath.WalkDir(src, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		to := filepath.Join(dst, rel)
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case fi.IsDir():
			if err := os.MkdirAll(to, 0o700); err != nil {
				return err
			}
			return os.Chmod(to, fi.Mode().Perm())
		case fi.Mode()&os.ModeSymlink != 0:
			l, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(l, to)
		default:
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if err := os.WriteFile(to, b, fi.Mode().Perm()); err != nil {
				return err
			}
			return os.Chtimes(to, fi.ModTime(), fi.ModTime())
		}
	})
}

type fakeVol struct {
	t     *testing.T
	base  string
	mu    sync.Mutex
	ds    map[string]string // dataset -> folder (or zvol file)
	snaps map[string]string // ds@name -> copy
	calls []string
}

func newFakeVol(t *testing.T, base string) *fakeVol {
	return &fakeVol{t: t, base: base, ds: map[string]string{}, snaps: map[string]string{}}
}

func (f *fakeVol) BaseDir() string { return filepath.Join(f.base, "run") }

func (f *fakeVol) log(s string, a ...any) {
	f.mu.Lock()
	f.calls = append(f.calls, fmt.Sprintf(s, a...))
	f.mu.Unlock()
}

func (f *fakeVol) Snapshot(_ context.Context, ds, name string) error {
	f.log("snapshot %s@%s", ds, name)
	src, ok := f.ds[ds]
	if !ok {
		return fmt.Errorf("no dataset %s", ds)
	}
	dst := filepath.Join(f.base, "snaps", strings.ReplaceAll(ds, "/", "_")+"@"+name)
	if err := copyTreeFS(src, dst); err != nil {
		return err
	}
	f.mu.Lock()
	f.snaps[ds+"@"+name] = dst
	f.mu.Unlock()
	return nil
}

func (f *fakeVol) DestroySnapshot(_ context.Context, ds, name string) error {
	f.log("destroy %s@%s", ds, name)
	f.mu.Lock()
	p := f.snaps[ds+"@"+name]
	delete(f.snaps, ds+"@"+name)
	f.mu.Unlock()
	return os.RemoveAll(p)
}

func (f *fakeVol) MountSnapshot(_ context.Context, ds, name, dir string) error {
	f.log("mount %s@%s %s", ds, name, dir)
	f.mu.Lock()
	p, ok := f.snaps[ds+"@"+name]
	f.mu.Unlock()
	if !ok {
		return fmt.Errorf("no snapshot %s@%s", ds, name)
	}
	_ = os.RemoveAll(dir)
	return copyTreeFS(p, dir)
}

func (f *fakeVol) Unmount(_ context.Context, dir string) error {
	f.log("umount %s", dir)
	_ = filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err == nil && e.IsDir() {
			_ = os.Chmod(p, 0o700)
		}
		return nil
	})
	return os.RemoveAll(dir)
}

func (f *fakeVol) OpenZvolSnapshot(_ context.Context, ds, name string) (io.ReadCloser, error) {
	f.log("zvol %s@%s", ds, name)
	f.mu.Lock()
	p, ok := f.snaps[ds+"@"+name]
	f.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no snapshot %s@%s", ds, name)
	}
	return os.Open(p)
}

func (f *fakeVol) CreateStaging(_ context.Context, pool, name string) (string, uint64, error) {
	dir := filepath.Join(f.base, "staging", pool, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", 0, err
	}
	f.log("stage %s/%s", pool, name)
	return dir, devOf(f.t, dir), nil
}

func (f *fakeVol) DestroyStaging(_ context.Context, pool, name string) error {
	f.log("unstage %s/%s", pool, name)
	dir := filepath.Join(f.base, "staging", pool, name)
	_ = filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err == nil && e.IsDir() {
			_ = os.Chmod(p, 0o700)
		}
		return nil
	})
	return os.RemoveAll(dir)
}

func (f *fakeVol) VerifyMount(dir, _ string) (uint64, error) { return devOf(f.t, dir), nil }

type fakeShares struct {
	t    *testing.T
	list []shares.Share
	made []shares.NewShare
	vol  *fakeVol
	root string
}

func (f *fakeShares) add(id, name, dir string) {
	f.list = append(f.list, shares.Share{ID: id, Name: name, Pool: "tank", Dataset: "tank/shares/" + id, Path: dir, Mounted: true, RootDev: devOf(f.t, dir)})
	f.vol.ds["tank/shares/"+id] = dir
}

func (f *fakeShares) List(context.Context) ([]shares.Share, error) { return f.list, nil }

func (f *fakeShares) Create(_ context.Context, a shares.NewShare) (*shares.Share, error) {
	f.made = append(f.made, a)
	dir := filepath.Join(f.root, "made-"+a.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	f.add(a.ID, a.Name, dir)
	return &f.list[len(f.list)-1], nil
}

type fakeSystem struct {
	staged *backup.Contents
}

func (f *fakeSystem) Collect(context.Context, bool) ([]backup.File, error) {
	return []backup.File{{Path: "var/lib/hardyos/network/settings.json", Mode: 0o644, Data: []byte(`{"x":1}`)}}, nil
}

func (f *fakeSystem) StageContents(c *backup.Contents) (*backup.Staged, error) {
	f.staged = c
	return &backup.Staged{Manifest: c.Manifest, StagedAt: time.Now()}, nil
}

type fakeVMs struct {
	vol   *fakeVol
	specs map[string]vms.Spec
	dirs  map[string]string
	disks map[string]string // vm/disk -> file
	got   []vms.RestoreFill
	gotID []string
}

func (f *fakeVMs) BackupIDs(context.Context) ([]string, error) {
	out := []string{}
	for id := range f.specs {
		out = append(out, id)
	}
	return out, nil
}

func (f *fakeVMs) BackupSnapshot(ctx context.Context, id, snap string) (*vms.BackupSnap, error) {
	s, ok := f.specs[id]
	if !ok {
		return nil, vms.ErrNotFound
	}
	ds := "tank/vms/" + id
	if err := f.vol.Snapshot(ctx, ds, snap); err != nil {
		return nil, err
	}
	b := &vms.BackupSnap{ID: id, Name: s.Name, Pool: "tank", Dataset: ds, Snapshot: snap, Consistent: true, Spec: s}
	for _, d := range s.Disks {
		dds := ds + "/" + d.Name
		if err := f.vol.Snapshot(ctx, dds, snap); err != nil {
			return nil, err
		}
		fi, _ := os.Stat(f.vol.ds[dds])
		b.Disks = append(b.Disks, vms.BackupDisk{Name: d.Name, Dataset: dds, Bytes: fi.Size()})
	}
	return b, nil
}

func (f *fakeVMs) ReleaseBackupSnapshot(ctx context.Context, id, snap string) error {
	return f.vol.DestroySnapshot(ctx, "tank/vms/"+id, snap)
}

func (f *fakeVMs) restore(ctx context.Context, id string, fl vms.RestoreFill) error {
	dir := f.dirs[id]
	if err := fl.Files(ctx, dir, devOf(f.vol.t, dir)); err != nil {
		return err
	}
	for _, d := range fl.Spec.Disks {
		p := f.disks[id+"/"+d.Name]
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			return err
		}
		if err := fl.Disk(ctx, d.Name, p); err != nil {
			return err
		}
	}
	f.got = append(f.got, fl)
	f.gotID = append(f.gotID, id)
	return nil
}

func (f *fakeVMs) RestoreFromBackup(ctx context.Context, id, confirm string, fl vms.RestoreFill) (*vms.VM, error) {
	if confirm != f.specs[id].Name {
		return nil, vms.Problems{"type the VM's name"}
	}
	return &vms.VM{Spec: fl.Spec}, f.restore(ctx, id, fl)
}

func (f *fakeVMs) RestoreNewFromBackup(ctx context.Context, pool string, fl vms.RestoreFill) (*vms.VM, error) {
	return &vms.VM{Spec: fl.Spec}, f.restore(ctx, fl.Spec.ID, fl)
}

func (f *fakeVMs) Get(_ context.Context, id string) (*vms.VM, error) {
	s, ok := f.specs[id]
	if !ok {
		return nil, vms.ErrNotFound
	}
	return &vms.VM{Spec: s}, nil
}

type fakeApps struct {
	vol    *fakeVol
	srcs   map[string]apps.BackupSource
	dirs   map[string]string
	filled []string
}

func (f *fakeApps) BackupSource(_ context.Context, id string) (*apps.BackupSource, error) {
	s, ok := f.srcs[id]
	if !ok {
		return nil, apps.ErrNotInstalled
	}
	return &s, nil
}

func (f *fakeApps) BackupSources(context.Context) ([]apps.BackupSource, error) {
	out := []apps.BackupSource{}
	for _, s := range f.srcs {
		out = append(out, s)
	}
	return out, nil
}

func (f *fakeApps) RestoreData(ctx context.Context, id, confirm string, fill apps.Fill) error {
	if confirm != f.srcs[id].Name {
		return apps.Problems{"type the app's name"}
	}
	f.filled = append(f.filled, id)
	return fill(ctx, f.dirs[id], f.srcs[id].Dataset)
}

func (f *fakeApps) RestoreNew(ctx context.Context, id, pool string, fill apps.Fill) error {
	f.filled = append(f.filled, "new:"+id)
	return fill(ctx, f.dirs[id], "tank/apps/"+id)
}

// fakeFiles acts as the person with the test's own identity, enforcing
// the folder rule level and reading/writing beneath the roots.
type fakeFiles struct {
	shares *fakeShares
	level  string
	ops    []string
}

func (f *fakeFiles) RulesLevel(_ context.Context, who fileworker.Who, share string) (string, error) {
	return f.level, nil
}

func (f *fakeFiles) sharePath(id string) string {
	for _, s := range f.shares.list {
		if s.ID == id {
			return s.Path
		}
	}
	return ""
}

func (f *fakeFiles) Do(_ context.Context, op string, a fileworker.Args) (json.RawMessage, *os.File, error) {
	f.ops = append(f.ops, op+" "+a.Path)
	p := filepath.Join(f.sharePath(a.Share), filepath.FromSlash(a.Path))
	switch op {
	case fileworker.OpMkdir:
		err := os.Mkdir(p, 0o755)
		if os.IsExist(err) {
			return nil, nil, &fileworker.Error{Code: fileworker.CodeExists, Message: "exists"}
		}
		return nil, nil, err
	case fileworker.OpCreate:
		fl := os.O_WRONLY | os.O_CREATE | os.O_EXCL
		if a.Overwrite {
			fl = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		}
		fh, err := os.OpenFile(p, fl, 0o644)
		return nil, fh, err
	case fileworker.OpSetTime:
		return nil, nil, os.Chtimes(p, a.Modified, a.Modified)
	}
	return nil, nil, fmt.Errorf("unexpected op %s", op)
}

func (f *fakeFiles) DoIn(_ context.Context, op string, who fileworker.Who, in fileworker.Root, a fileworker.Args) (json.RawMessage, *os.File, error) {
	f.ops = append(f.ops, "in:"+op+" "+a.Path)
	p := filepath.Join(in.Path, filepath.FromSlash(a.Path))
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, nil, err
	}
	if fi.Mode()&0o004 == 0 {
		return nil, nil, &fileworker.Error{Code: fileworker.CodeNoAccess, Message: "no access"}
	}
	switch op {
	case fileworker.OpStat:
		b, _ := json.Marshal(fileworker.Entry{Name: fi.Name(), Dir: fi.IsDir(), Size: fi.Size(), Modified: fi.ModTime()})
		return b, nil, nil
	case fileworker.OpList:
		es, err := os.ReadDir(p)
		if err != nil {
			return nil, nil, err
		}
		l := fileworker.Listing{}
		for _, e := range es {
			l.Entries = append(l.Entries, fileworker.Entry{Name: e.Name(), Dir: e.IsDir()})
		}
		b, _ := json.Marshal(l)
		return b, nil, nil
	case fileworker.OpOpen:
		fh, err := os.Open(p)
		return nil, fh, err
	}
	return nil, nil, fmt.Errorf("unexpected op %s", op)
}

// env is a Root over local repositories and the fakes.
type env struct {
	t      *testing.T
	base   string
	root   *Root
	vol    *fakeVol
	shares *fakeShares
	system *fakeSystem
	vms    *fakeVMs
	apps   *fakeApps
	files  *fakeFiles
	work   string
}

func newEnv(t *testing.T) *env {
	bin := needRestic(t)
	base := tmp(t)
	vol := newFakeVol(t, base)
	sh := &fakeShares{t: t, vol: vol, root: base}
	work := filepath.Join(base, "work")
	_ = os.MkdirAll(work, 0o750)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	e := &env{t: t, base: base, vol: vol, shares: sh, system: &fakeSystem{}, work: work,
		vms: &fakeVMs{vol: vol, specs: map[string]vms.Spec{}, dirs: map[string]string{}, disks: map[string]string{}},
		apps: &fakeApps{vol: vol, srcs: map[string]apps.BackupSource{}, dirs: map[string]string{}}}
	e.files = &fakeFiles{shares: sh, level: shares.LevelWrite}
	e.root = &Root{
		Restic:     &Restic{Binary: bin, CacheDir: filepath.Join(base, "cache")},
		Vol:        vol,
		Shares:     sh,
		System:     e.system,
		VMs:        e.vms,
		Apps:       e.apps,
		Files:      e.files,
		Dir:        filepath.Join(base, "state"),
		WorkDir:    work,
		Key:        func() ([]byte, error) { return key, nil },
		AllowLocal: true,
	}
	return e
}

func (e *env) target(id string) Target {
	e.t.Helper()
	res, err := e.root.Save(context.Background(), SaveArgs{Target: Target{ID: id, Name: "Test " + id, Kind: KindLocal, Path: filepath.Join(e.base, "repo-"+id)}})
	if err != nil {
		e.t.Fatal(err)
	}
	if !res.Created {
		e.t.Fatal("expected a new repository")
	}
	return res.Target
}

// wait follows a task to its end.
func (e *env) wait(task *Task, err error) *Task {
	e.t.Helper()
	if err != nil {
		e.t.Fatal(err)
	}
	for i := 0; i < 1200; i++ {
		x, err := e.root.TaskStatus(task.ID)
		if err != nil {
			e.t.Fatal(err)
		}
		if x.Done {
			return x
		}
		time.Sleep(50 * time.Millisecond)
	}
	e.t.Fatal("task didn't finish")
	return nil
}

func write(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func appSource(id, name string) apps.BackupSource {
	return apps.BackupSource{ID: id, Name: name, Version: "1.0", Pool: "tank", Dataset: "tank/apps/" + id}
}
