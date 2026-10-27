package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/files"
	"github.com/hardyos/hardyos/daemon/internal/fileworker"
)

// fakeFiles is a files.Service over plain folders (one per share), with
// no privilege drop: enough to test the API.
type fakeFiles struct {
	mu       sync.Mutex
	dirs     map[string]string // share -> folder
	readOnly map[string]bool
	recycle  map[string]bool
	calls    []string
}

var _ files.Service = (*fakeFiles)(nil)

func (f *fakeFiles) note(s string) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
}

func ferr(kind error, msg string) error { return &files.Error{Kind: kind, Msg: msg} }

func mapOS(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrNotExist):
		return ferr(files.ErrNotFound, "there's no such file or folder")
	case errors.Is(err, fs.ErrExist):
		return ferr(files.ErrExists, "something with that name is already there")
	case errors.Is(err, fs.ErrPermission):
		return ferr(files.ErrNoAccess, "you don't have access to that")
	}
	return err
}

func (f *fakeFiles) resolve(who files.Who, share, p, snap string, write bool) (string, error) {
	if who.Local && !who.Admin {
		return "", ferr(files.ErrNoAccess, "no")
	}
	dir, ok := f.dirs[share]
	if !ok {
		return "", ferr(files.ErrNotFound, "no such shared folder")
	}
	if write && (f.readOnly[share] || snap != "") {
		return "", ferr(files.ErrNoAccess, "you can only read this shared folder")
	}
	parts, err := fileworker.CleanPath(p)
	if err != nil {
		return "", ferr(files.ErrNotAllowed, err.Error())
	}
	if snap != "" {
		if !fileworker.SnapshotRE.MatchString(snap) {
			return "", ferr(files.ErrNotFound, "no such version")
		}
		dir = filepath.Join(dir, ".zfs/snapshot", snap)
	}
	return filepath.Join(dir, filepath.FromSlash(fileworker.Join(parts))), nil
}

func entryOf(p, rel string, fi os.FileInfo, writable bool) files.Entry {
	e := files.Entry{Name: path.Base(rel), Path: rel, Dir: fi.IsDir(), Modified: fi.ModTime().UTC(), Writable: writable}
	if rel == "" {
		e.Name = ""
	}
	if !e.Dir {
		e.Size = fi.Size()
	}
	return e
}

func (f *fakeFiles) Shares(_ context.Context, who files.Who) ([]files.ShareInfo, error) {
	if who.Local && !who.Admin {
		return nil, ferr(files.ErrNoAccess, "no")
	}
	var out []files.ShareInfo
	for id := range f.dirs {
		out = append(out, files.ShareInfo{ID: id, Name: strings.ToUpper(id[:1]) + id[1:], Writable: !f.readOnly[id], Recycle: f.recycle[id]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (f *fakeFiles) ListDir(_ context.Context, who files.Who, share, p, snap string) (*files.Listing, error) {
	full, err := f.resolve(who, share, p, snap, false)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(full)
	if err != nil {
		return nil, mapOS(err)
	}
	if !fi.IsDir() {
		return nil, ferr(files.ErrNotFound, "not a folder")
	}
	rel := strings.Trim(p, "/")
	l := &files.Listing{Folder: entryOf(full, rel, fi, !f.readOnly[share] && snap == ""), Entries: []files.Entry{}}
	des, _ := os.ReadDir(full)
	for _, de := range des {
		if fileworker.Hidden(de.Name()) {
			continue
		}
		cfi, err := de.Info()
		if err != nil || (!cfi.IsDir() && !cfi.Mode().IsRegular()) {
			continue
		}
		l.Entries = append(l.Entries, entryOf(full, strings.TrimPrefix(rel+"/"+de.Name(), "/"), cfi, l.Folder.Writable))
	}
	return l, nil
}

func (f *fakeFiles) List(ctx context.Context, who files.Who, share, p string) ([]files.Entry, error) {
	l, err := f.ListDir(ctx, who, share, p, "")
	if err != nil {
		return nil, err
	}
	return l.Entries, nil
}

func (f *fakeFiles) StatVersion(_ context.Context, who files.Who, share, p, snap string) (*files.Entry, error) {
	full, err := f.resolve(who, share, p, snap, false)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(full)
	if err != nil {
		return nil, mapOS(err)
	}
	e := entryOf(full, strings.Trim(p, "/"), fi, !f.readOnly[share] && snap == "")
	return &e, nil
}

func (f *fakeFiles) Stat(ctx context.Context, who files.Who, share, p string) (*files.Entry, error) {
	return f.StatVersion(ctx, who, share, p, "")
}

func (f *fakeFiles) OpenVersion(ctx context.Context, who files.Who, share, p, snap string) (*os.File, *files.Entry, error) {
	e, err := f.StatVersion(ctx, who, share, p, snap)
	if err != nil {
		return nil, nil, err
	}
	if e.Dir {
		return nil, nil, ferr(files.ErrNotAllowed, "that's a folder")
	}
	full, _ := f.resolve(who, share, p, snap, false)
	fl, err := os.Open(full)
	return fl, e, mapOS(err)
}

func (f *fakeFiles) Open(ctx context.Context, who files.Who, share, p string) (*os.File, *files.Entry, error) {
	return f.OpenVersion(ctx, who, share, p, "")
}

func (f *fakeFiles) Create(_ context.Context, who files.Who, share, p string, overwrite bool) (*os.File, error) {
	full, err := f.resolve(who, share, p, "", true)
	if err != nil {
		return nil, err
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if overwrite {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	fl, err := os.OpenFile(full, flags, 0o644)
	return fl, mapOS(err)
}

func (f *fakeFiles) OpenWrite(_ context.Context, who files.Who, share, p string) (*os.File, *files.Entry, error) {
	full, err := f.resolve(who, share, p, "", true)
	if err != nil {
		return nil, nil, err
	}
	// The file's own write permission decides, even for root (it stands in
	// for an ACL that lets the person read only).
	if fi, err := os.Stat(full); err == nil && fi.Mode().Perm()&0o200 == 0 {
		return nil, nil, ferr(files.ErrNoAccess, "you may only read that file")
	}
	fl, err := os.OpenFile(full, os.O_WRONLY, 0)
	if err != nil {
		return nil, nil, mapOS(err)
	}
	return fl, &files.Entry{Name: path.Base(p), Path: p}, nil
}

func (f *fakeFiles) Mkdir(_ context.Context, who files.Who, share, p string) error {
	full, err := f.resolve(who, share, p, "", true)
	if err != nil {
		return err
	}
	f.note("mkdir " + share + ":" + p)
	return mapOS(os.Mkdir(full, 0o755))
}

func (f *fakeFiles) rename(who files.Who, share, from, toShare, to string, replace bool) error {
	a, err := f.resolve(who, share, from, "", true)
	if err != nil {
		return err
	}
	if toShare == "" {
		toShare = share
	}
	b, err := f.resolve(who, toShare, to, "", true)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(a); err != nil {
		return mapOS(err)
	}
	if _, err := os.Lstat(b); err == nil && !replace {
		return ferr(files.ErrExists, "already there")
	}
	return mapOS(os.Rename(a, b))
}

func (f *fakeFiles) Rename(_ context.Context, who files.Who, share, from, toShare, to string) error {
	f.note("rename " + share + ":" + from + " " + toShare + ":" + to)
	return f.rename(who, share, from, toShare, to, false)
}

func (f *fakeFiles) Replace(_ context.Context, who files.Who, share, from, to string) error {
	return f.rename(who, share, from, share, to, true)
}

func (f *fakeFiles) Copy(ctx context.Context, who files.Who, share, from, toShare, to string) error {
	_, err := f.CopyTree(ctx, who, files.Location{Share: share, Path: from}, files.Location{Share: toShare, Path: to}, files.CopyOptions{Conflict: files.ConflictFail})
	return err
}

func (f *fakeFiles) CopyTree(_ context.Context, who files.Who, src, dst files.Location, opt files.CopyOptions) (string, error) {
	a, err := f.resolve(who, src.Share, src.Path, src.Snapshot, false)
	if err != nil {
		return "", err
	}
	if dst.Share == "" {
		dst.Share = src.Share
	}
	target := strings.Trim(dst.Path, "/")
	b, err := f.resolve(who, dst.Share, target, "", true)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(b); err == nil {
		switch opt.Conflict {
		case files.ConflictSkip:
			return "", nil
		case files.ConflictRename:
			suffix := opt.Suffix
			if suffix == "" {
				suffix = "copy"
			}
			ext := path.Ext(target)
			target = strings.TrimSuffix(target, ext) + " (" + suffix + ")" + ext
			b, _ = f.resolve(who, dst.Share, target, "", true)
		case files.ConflictReplace:
		default:
			return "", ferr(files.ErrExists, "already there")
		}
	}
	f.note("copy " + src.Share + ":" + src.Path + " " + dst.Share + ":" + target)
	var n int64
	err = filepath.Walk(a, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(a, p)
		out := filepath.Join(b, rel)
		if fi.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		o, err := os.Create(out)
		if err != nil {
			return err
		}
		c, err := io.Copy(o, in)
		o.Close()
		n += c
		if opt.Progress != nil {
			opt.Progress(files.Progress{Files: 1, TotalFiles: 1, Bytes: n, TotalBytes: n, Current: fi.Name()})
		}
		return err
	})
	return target, mapOS(err)
}

func (f *fakeFiles) Delete(ctx context.Context, who files.Who, share, p string) error {
	_, err := f.DeleteItem(ctx, who, share, p, false)
	return err
}

func (f *fakeFiles) DeleteItem(_ context.Context, who files.Who, share, p string, permanent bool) (bool, error) {
	full, err := f.resolve(who, share, p, "", true)
	if err != nil {
		return false, err
	}
	if strings.Trim(p, "/") == "" {
		return false, ferr(files.ErrNotAllowed, "the top")
	}
	if _, err := os.Lstat(full); err != nil {
		return false, mapOS(err)
	}
	f.note(fmt.Sprintf("delete %s:%s permanent=%v", share, p, permanent))
	if f.recycle[share] && !permanent {
		// Into the bin, keeping the folders (the worker's layout, roughly).
		bin := filepath.Join(f.dirs[share], ".recycle", "bin", filepath.FromSlash(strings.Trim(p, "/")))
		if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
			return false, err
		}
		_ = os.RemoveAll(bin)
		return true, os.Rename(full, bin)
	}
	return false, os.RemoveAll(full)
}

func (f *fakeFiles) SetModified(_ context.Context, who files.Who, share, p string, t time.Time) error {
	full, err := f.resolve(who, share, p, "", true)
	if err != nil {
		return err
	}
	return mapOS(os.Chtimes(full, t, t))
}

func (f *fakeFiles) Versions(_ context.Context, who files.Who, share, p string) ([]files.Version, error) {
	if _, err := f.resolve(who, share, p, "", false); err != nil {
		return nil, err
	}
	out := []files.Version{}
	des, _ := os.ReadDir(filepath.Join(f.dirs[share], ".zfs/snapshot"))
	for i := len(des) - 1; i >= 0; i-- {
		taken, ok := fileworker.SnapshotTime(des[i].Name())
		if !ok {
			continue
		}
		fi, err := os.Stat(filepath.Join(f.dirs[share], ".zfs/snapshot", des[i].Name(), p))
		if err != nil {
			continue
		}
		out = append(out, files.Version{Snapshot: des[i].Name(), Taken: taken, Size: fi.Size(), Modified: fi.ModTime().UTC(), Dir: fi.IsDir()})
	}
	return out, nil
}

func (f *fakeFiles) Restore(ctx context.Context, who files.Who, share, p, snap string) (string, error) {
	return f.RestoreWith(ctx, who, share, p, snap, nil)
}

func (f *fakeFiles) RestoreWith(ctx context.Context, who files.Who, share, p, snap string, progress func(files.Progress)) (string, error) {
	taken, ok := fileworker.SnapshotTime(snap)
	if !ok {
		return "", ferr(files.ErrNotFound, "no such version")
	}
	return f.CopyTree(ctx, who, files.Location{Share: share, Path: p, Snapshot: snap}, files.Location{Share: share, Path: p},
		files.CopyOptions{Conflict: files.ConflictRename, Suffix: "restored " + taken.Format("2006-01-02"), Progress: progress})
}
