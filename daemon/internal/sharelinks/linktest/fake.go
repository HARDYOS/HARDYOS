// Package linktest has a fake files.Access for share link tests: shared
// folders are directories under a temp dir, and who may read or write each
// is a map. Nothing runs as anyone else; no real disks are touched.
package linktest

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/hardyos/hardyos/daemon/internal/files"
)

// Fake implements files.Access over directories in Root.
type Fake struct {
	Root string
	mu   sync.Mutex
	// Perms: share -> principal (lowercase) -> "read" or "write". Admins write everywhere.
	Perms map[string]map[string]string
	// Calls lists principals files were read or written as ("op who share/path").
	Calls []string
}

// New makes a fake with the given shares (created as directories).
func New(root string, shares ...string) *Fake {
	f := &Fake{Root: root, Perms: map[string]map[string]string{}}
	for _, s := range shares {
		_ = os.MkdirAll(filepath.Join(root, s), 0o755)
		f.Perms[s] = map[string]string{}
	}
	return f
}

// Grant sets a principal's level on a share ("" removes it).
func (f *Fake) Grant(share, principal, level string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if level == "" {
		delete(f.Perms[share], strings.ToLower(principal))
		return
	}
	f.Perms[share][strings.ToLower(principal)] = level
}

// Write puts a file in a share.
func (f *Fake) Write(share, path, content string) {
	p := filepath.Join(f.Root, share, filepath.FromSlash(path))
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, []byte(content), 0o644)
}

// Read returns a file's content ("" if missing).
func (f *Fake) Read(share, path string) string {
	b, _ := os.ReadFile(filepath.Join(f.Root, share, filepath.FromSlash(path)))
	return string(b)
}

func (f *Fake) level(who files.Who, share string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	perms, ok := f.Perms[share]
	if !ok {
		return ""
	}
	if who.Admin {
		return "write"
	}
	return perms[strings.ToLower(who.Principal)]
}

func (f *Fake) log(op string, who files.Who, share, path string) {
	f.mu.Lock()
	f.Calls = append(f.Calls, op+" "+who.Principal+" "+share+"/"+path)
	f.mu.Unlock()
}

func (f *Fake) resolve(who files.Who, share, path string, write bool) (string, error) {
	lvl := f.level(who, share)
	if lvl == "" || (write && lvl != "write") {
		return "", files.ErrNoAccess
	}
	if strings.Contains("/"+path+"/", "/../") {
		return "", files.ErrNotAllowed
	}
	return filepath.Join(f.Root, share, filepath.FromSlash(path)), nil
}

func (f *Fake) entry(who files.Who, share, path string, fi fs.FileInfo) files.Entry {
	name := fi.Name()
	if path == "" {
		name = ""
	}
	return files.Entry{Name: name, Path: path, Dir: fi.IsDir(), Size: fi.Size(), Modified: fi.ModTime(),
		Writable: f.level(who, share) == "write"}
}

func notFound(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return files.ErrNotFound
	}
	return err
}

// Shares implements files.Access.
func (f *Fake) Shares(_ context.Context, who files.Who) ([]files.ShareInfo, error) {
	var out []files.ShareInfo
	for s := range f.Perms {
		if lvl := f.level(who, s); lvl != "" {
			out = append(out, files.ShareInfo{ID: s, Name: strings.ToUpper(s[:1]) + s[1:], Writable: lvl == "write"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// List implements files.Access. Unlike the real one it shows hidden names,
// so tests prove the link pages leave them out themselves.
func (f *Fake) List(_ context.Context, who files.Who, share, path string) ([]files.Entry, error) {
	f.log("list", who, share, path)
	p, err := f.resolve(who, share, path, false)
	if err != nil {
		return nil, err
	}
	des, err := os.ReadDir(p)
	if err != nil {
		return nil, notFound(err)
	}
	out := []files.Entry{}
	for _, d := range des {
		fi, err := d.Info()
		if err != nil {
			continue
		}
		child := d.Name()
		if path != "" {
			child = path + "/" + d.Name()
		}
		out = append(out, f.entry(who, share, child, fi))
	}
	return out, nil
}

// Stat implements files.Access.
func (f *Fake) Stat(_ context.Context, who files.Who, share, path string) (*files.Entry, error) {
	f.log("stat", who, share, path)
	p, err := f.resolve(who, share, path, false)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(p)
	if err != nil {
		return nil, notFound(err)
	}
	e := f.entry(who, share, path, fi)
	return &e, nil
}

// Open implements files.Access.
func (f *Fake) Open(_ context.Context, who files.Who, share, path string) (*os.File, *files.Entry, error) {
	f.log("open", who, share, path)
	p, err := f.resolve(who, share, path, false)
	if err != nil {
		return nil, nil, err
	}
	fh, err := os.Open(p)
	if err != nil {
		return nil, nil, notFound(err)
	}
	fi, _ := fh.Stat()
	e := f.entry(who, share, path, fi)
	return fh, &e, nil
}

// Create implements files.Access.
func (f *Fake) Create(_ context.Context, who files.Who, share, path string, overwrite bool) (*os.File, error) {
	f.log("create", who, share, path)
	p, err := f.resolve(who, share, path, true)
	if err != nil {
		return nil, err
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !overwrite {
		flags |= os.O_EXCL
	}
	fh, err := os.OpenFile(p, flags, 0o644)
	if errors.Is(err, fs.ErrExist) {
		return nil, files.ErrExists
	}
	return fh, notFound(err)
}

// Mkdir implements files.Access.
func (f *Fake) Mkdir(_ context.Context, who files.Who, share, path string) error {
	p, err := f.resolve(who, share, path, true)
	if err != nil {
		return err
	}
	return os.Mkdir(p, 0o755)
}

// Delete implements files.Access.
func (f *Fake) Delete(_ context.Context, who files.Who, share, path string) error {
	f.log("delete", who, share, path)
	p, err := f.resolve(who, share, path, true)
	if err != nil {
		return err
	}
	return notFound(os.RemoveAll(p))
}

// Rename implements files.Access (not used by links).
func (f *Fake) Rename(context.Context, files.Who, string, string, string, string) error {
	return files.ErrNotImplemented
}

// Copy implements files.Access (not used by links).
func (f *Fake) Copy(context.Context, files.Who, string, string, string, string) error {
	return files.ErrNotImplemented
}

// Versions implements files.Access. Links never ask for snapshots; a call fails the test's expectations.
func (f *Fake) Versions(_ context.Context, who files.Who, share, path string) ([]files.Version, error) {
	f.log("versions", who, share, path)
	return nil, files.ErrNotImplemented
}

// OpenVersion implements files.Access.
func (f *Fake) OpenVersion(_ context.Context, who files.Who, share, path, _ string) (*os.File, *files.Entry, error) {
	f.log("openversion", who, share, path)
	return nil, nil, files.ErrNotImplemented
}

// Restore implements files.Access.
func (f *Fake) Restore(context.Context, files.Who, string, string, string) (string, error) {
	return "", files.ErrNotImplemented
}

var _ files.Access = (*Fake)(nil)
