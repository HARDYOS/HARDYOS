// Package dav serves the shared folders over WebDAV (docs/plans/file-sharing.md
// section 5): a golang.org/x/net/webdav FileSystem over internal/files, so
// every read and write happens as the person signed in, in a child of
// hardyd-priv that is that person (part C). hardyd mounts it at /dav/ (see
// api/handlers_dav.go for sign-in).
//
// The top of the tree lists the person's folders that have WebDAV on, and
// Home; nothing can be made there. Hidden names (.recycle, .zfs,
// .hardyos*) are never listed and can't be reached; snapshots aren't
// offered. Uploads are streamed into a temporary file next to the target
// and renamed into place only once the whole body arrived, so a broken
// upload never replaces a file. Deletes go to the recycle bin. Dead
// properties (PROPPATCH) are never stored: they're answered as accepted
// and dropped, except Windows' Win32LastModifiedTime, which sets the file's
// modification time.
package dav

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/files"
	"github.com/hardyos/hardyos/daemon/internal/fileworker"
	"golang.org/x/net/webdav"
)

// Root is a folder at the top of the tree.
type Root struct {
	// Name is what the folder is called at the top ("Media", "Home").
	Name string
	// Share is its id (files.HomeShare for Home).
	Share string
	// Recycle: the folder has a recycle bin (a file a PUT replaces goes
	// there first).
	Recycle bool
}

// HomeName is the home folder's name at the top.
const HomeName = "Home"

// Roots names the person's folders at the top: Home first (when they have
// one), then the shared folders in on, by name. A shared folder named like
// another one (or Home) gets " (shared folder)" after its name.
func Roots(list []files.ShareInfo, on func(id string) bool) []Root {
	var out []Root
	taken := map[string]bool{}
	for _, s := range list {
		if s.ID == files.HomeShare {
			out = append(out, Root{Name: HomeName, Share: s.ID, Recycle: s.Recycle})
			taken[strings.ToLower(HomeName)] = true
		}
	}
	for _, s := range list {
		if s.ID == files.HomeShare || !on(s.ID) {
			continue
		}
		n := strings.TrimSpace(s.Name)
		if n == "" || n == "." || n == ".." || strings.ContainsAny(n, "/\\\x00") || fileworker.Hidden(n) {
			continue
		}
		if taken[strings.ToLower(n)] {
			n += " (shared folder)"
			if taken[strings.ToLower(n)] {
				continue
			}
		}
		taken[strings.ToLower(n)] = true
		out = append(out, Root{Name: n, Share: s.ID, Recycle: s.Recycle})
	}
	return out
}

// FS is one person's view for one request. It's not meant to outlive the
// request (it caches what it has looked up).
type FS struct {
	Files files.Service
	Who   files.Who
	Roots []Root
	// BodyFailed reports whether the request's body broke off; an upload
	// whose body broke off is thrown away.
	BodyFailed func() bool
	// Changed is told about uploads ("put", with the size), deletes and
	// moves, for the audit log. Optional.
	Changed func(op, target, detail string, size int64)

	mu         sync.Mutex
	cache      map[string]*info
	readFailed bool
}

var _ webdav.FileSystem = (*FS)(nil)

// where is a path in a share.
type where struct {
	root  *Root  // nil: the top
	share string // root.Share
	path  string // inside the share, "" for its top
}

func (w where) top() bool { return w.root == nil }

// resolve maps a WebDAV name ("/Media/Films/a.mkv") to a share path. Hidden
// names, "." and ".." don't exist here.
func (d *FS) resolve(name string) (where, error) {
	name = strings.Trim(path.Clean("/"+name), "/")
	if name == "" {
		return where{}, nil
	}
	parts := strings.Split(name, "/")
	var r *Root
	for i := range d.Roots {
		if d.Roots[i].Name == parts[0] {
			r = &d.Roots[i]
			break
		}
	}
	if r == nil {
		return where{}, os.ErrNotExist
	}
	for _, p := range parts[1:] {
		if p == "" || p == "." || p == ".." || fileworker.Hidden(p) || strings.ContainsRune(p, 0) {
			return where{}, os.ErrNotExist
		}
	}
	return where{root: r, share: r.Share, path: strings.Join(parts[1:], "/")}, nil
}

// osErr turns internal/files errors into the os errors webdav understands.
func osErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, files.ErrNotFound):
		return os.ErrNotExist
	case errors.Is(err, files.ErrExists):
		return os.ErrExist
	case errors.Is(err, files.ErrNoAccess), errors.Is(err, files.ErrNotAllowed):
		return os.ErrPermission
	}
	return err
}

func (d *FS) cached(name string) *info {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cache[name]
}

func (d *FS) remember(name string, fi *info) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cache == nil {
		d.cache = map[string]*info{}
	}
	if len(d.cache) < 100000 {
		d.cache[name] = fi
	}
}

func (d *FS) forget() {
	d.mu.Lock()
	d.cache = nil
	d.mu.Unlock()
}

func (d *FS) failed() bool {
	d.mu.Lock()
	rf := d.readFailed
	d.mu.Unlock()
	return rf || (d.BodyFailed != nil && d.BodyFailed())
}

var started = time.Now().UTC()

func (d *FS) stat(ctx context.Context, name string) (*info, where, error) {
	w, err := d.resolve(name)
	if err != nil {
		return nil, w, err
	}
	if w.top() {
		return &info{name: "/", dir: true, mod: started}, w, nil
	}
	key := path.Clean("/" + name)
	if fi := d.cached(key); fi != nil {
		return fi, w, nil
	}
	e, err := d.Files.Stat(ctx, d.Who, w.share, w.path)
	if err != nil {
		return nil, w, osErr(err)
	}
	fi := infoOf(*e)
	if w.path == "" {
		fi.name = w.root.Name
	}
	d.remember(key, fi)
	return fi, w, nil
}

// Stat implements webdav.FileSystem.
func (d *FS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	fi, _, err := d.stat(ctx, name)
	if err != nil {
		return nil, err
	}
	return fi, nil
}

// Mkdir implements webdav.FileSystem.
func (d *FS) Mkdir(ctx context.Context, name string, _ os.FileMode) error {
	w, err := d.resolve(name)
	if err != nil {
		return err
	}
	if w.top() || w.path == "" {
		return os.ErrPermission
	}
	d.forget()
	if err := d.Files.Mkdir(ctx, d.Who, w.share, w.path); err != nil {
		return osErr(err)
	}
	d.changed("mkdir", w, "", 0)
	return nil
}

// RemoveAll implements webdav.FileSystem: to the recycle bin when the
// folder has one.
func (d *FS) RemoveAll(ctx context.Context, name string) error {
	w, err := d.resolve(name)
	if err != nil {
		return err
	}
	if w.top() || w.path == "" {
		return os.ErrPermission
	}
	d.forget()
	if _, err := d.Files.DeleteItem(ctx, d.Who, w.share, w.path, false); err != nil {
		return osErr(err)
	}
	d.changed("delete", w, "", 0)
	return nil
}

// Rename implements webdav.FileSystem (MOVE); between shared folders it's
// a copy and a delete.
func (d *FS) Rename(ctx context.Context, oldName, newName string) error {
	from, err := d.resolve(oldName)
	if err != nil {
		return err
	}
	to, err := d.resolve(newName)
	if err != nil {
		return err
	}
	if from.top() || from.path == "" || to.top() || to.path == "" {
		return os.ErrPermission
	}
	d.forget()
	if err := d.Files.Rename(ctx, d.Who, from.share, from.path, to.share, to.path); err != nil {
		return osErr(err)
	}
	d.changed("move", from, "to "+to.share+":/"+to.path, 0)
	return nil
}

func (d *FS) changed(op string, w where, detail string, size int64) {
	if d.Changed != nil {
		d.Changed(op, w.share+":/"+w.path, detail, size)
	}
}

// Name is how the audit log names a WebDAV path ("media:/Films/a.mkv").
func (d *FS) Name(name string) string {
	w, err := d.resolve(name)
	if err != nil || w.top() {
		return path.Clean("/" + name)
	}
	return w.share + ":/" + w.path
}

// Same reports whether two WebDAV names are the same file or folder here
// (after cleaning; "" and "/" are the top).
func (d *FS) Same(a, b string) bool {
	wa, erra := d.resolve(a)
	wb, errb := d.resolve(b)
	if erra != nil || errb != nil {
		return path.Clean("/"+a) == path.Clean("/"+b)
	}
	return wa.share == wb.share && wa.path == wb.path
}

// Inside reports whether b is strictly inside a (a folder copied into
// itself would never end).
func (d *FS) Inside(a, b string) bool {
	wa, erra := d.resolve(a)
	wb, errb := d.resolve(b)
	if erra != nil || errb != nil || wa.top() {
		return false
	}
	return wa.share == wb.share && (wa.path == "" && wb.path != "" || strings.HasPrefix(wb.path, wa.path+"/"))
}

// CheckReplace is what replacing name (PUT over it, COPY or MOVE with
// Overwrite) needs: when it is a file, the person must be allowed to
// write that file itself, not just its folder (a rename into place would
// only ask the folder). os.ErrPermission when they may not.
func (d *FS) CheckReplace(ctx context.Context, name string) error {
	w, err := d.resolve(name)
	if err != nil || w.top() || w.path == "" {
		return nil // nothing there to replace, or refused later anyway
	}
	e, err := d.Files.Stat(ctx, d.Who, w.share, w.path)
	if err != nil || e.Dir {
		return nil
	}
	wf, _, err := d.Files.OpenWrite(ctx, d.Who, w.share, w.path)
	if err != nil {
		if errors.Is(err, files.ErrNotFound) {
			return nil
		}
		return osErr(err)
	}
	_ = wf.Close()
	return nil
}

// OpenFile implements webdav.FileSystem.
func (d *FS) OpenFile(ctx context.Context, name string, flag int, _ os.FileMode) (webdav.File, error) {
	if flag&(os.O_CREATE|os.O_TRUNC) != 0 {
		return d.create(ctx, name, flag)
	}
	fi, w, err := d.stat(ctx, name)
	if err != nil {
		return nil, err
	}
	if fi.dir {
		return &dirFile{fs: d, ctx: ctx, name: path.Clean("/" + name), w: w, fi: fi}, nil
	}
	// Opened on first read: listings open every file for its properties.
	return &readFile{fs: d, ctx: ctx, w: w, fi: fi}, nil
}

func newTempName() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return fileworker.UploadPrefix + hex.EncodeToString(b)
}

func (d *FS) create(ctx context.Context, name string, flag int) (webdav.File, error) {
	w, err := d.resolve(name)
	if err != nil {
		return nil, err
	}
	if w.top() || w.path == "" {
		return nil, os.ErrPermission
	}
	exists := false
	if e, err := d.Files.Stat(ctx, d.Who, w.share, w.path); err == nil {
		if e.Dir {
			return nil, os.ErrPermission
		}
		if flag&os.O_EXCL != 0 {
			return nil, os.ErrExist
		}
		// Replacing a file needs write access to that file itself, not
		// just its folder (a rename into place would only check the
		// folder): try opening it for writing as the person.
		wf, _, err := d.Files.OpenWrite(ctx, d.Who, w.share, w.path)
		if err != nil {
			return nil, osErr(err)
		}
		_ = wf.Close()
		exists = true
	} else if !errors.Is(err, files.ErrNotFound) {
		return nil, osErr(err)
	}
	dir := path.Dir(w.path)
	if dir == "." {
		dir = ""
	}
	tmp := path.Join(dir, newTempName())
	f, err := d.Files.Create(ctx, d.Who, w.share, tmp, false)
	if err != nil {
		return nil, osErr(err)
	}
	d.forget()
	return &writeFile{fs: d, ctx: ctx, w: w, tmp: tmp, f: f, name: path.Base(w.path), replaces: exists}, nil
}

// ---- file info -------------------------------------------------------------

type info struct {
	name string
	size int64
	mod  time.Time
	dir  bool
}

func infoOf(e files.Entry) *info {
	return &info{name: e.Name, size: e.Size, mod: e.Modified, dir: e.Dir}
}

func (i *info) Name() string       { return i.name }
func (i *info) Size() int64        { return i.size }
func (i *info) ModTime() time.Time { return i.mod }
func (i *info) IsDir() bool        { return i.dir }
func (i *info) Sys() any           { return nil }
func (i *info) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0o755
	}
	return 0o644
}

// ContentType implements webdav.ContentTyper: by the name only, so a
// listing doesn't open every file to sniff it.
func (i *info) ContentType(context.Context) (string, error) {
	if i.dir {
		return "", webdav.ErrNotImplemented
	}
	if t := mime.TypeByExtension(path.Ext(i.name)); t != "" {
		return t, nil
	}
	return "application/octet-stream", nil
}

// ---- dead properties ---------------------------------------------------------

// noDeadProps keeps nothing: PROPPATCH is answered as done (Windows and
// macOS give up on a file whose properties they can't set) and dropped.
type noDeadProps struct {
	setTime func(time.Time)
}

func (noDeadProps) DeadProps() (map[xml.Name]webdav.Property, error) {
	return map[xml.Name]webdav.Property{}, nil
}

var win32Modified = xml.Name{Space: "urn:schemas-microsoft-com:", Local: "Win32LastModifiedTime"}

func (n noDeadProps) Patch(patches []webdav.Proppatch) ([]webdav.Propstat, error) {
	st := webdav.Propstat{Status: http.StatusOK}
	for _, p := range patches {
		for _, pr := range p.Props {
			st.Props = append(st.Props, webdav.Property{XMLName: pr.XMLName})
			if !p.Remove && pr.XMLName == win32Modified && n.setTime != nil {
				if t, err := http.ParseTime(strings.TrimSpace(string(pr.InnerXML))); err == nil {
					n.setTime(t)
				}
			}
		}
	}
	return []webdav.Propstat{st}, nil
}

// ---- folders -----------------------------------------------------------------

type dirFile struct {
	noDeadProps
	fs   *FS
	ctx  context.Context
	name string
	w    where
	fi   *info
	list []os.FileInfo
	pos  int
	read bool
}

func (f *dirFile) Close() error                   { return nil }
func (f *dirFile) Read([]byte) (int, error)       { return 0, os.ErrInvalid }
func (f *dirFile) Write([]byte) (int, error)      { return 0, os.ErrPermission }
func (f *dirFile) Seek(int64, int) (int64, error) { return 0, os.ErrInvalid }
func (f *dirFile) Stat() (os.FileInfo, error)     { return f.fi, nil }

func (f *dirFile) load() error {
	if f.read {
		return nil
	}
	f.read = true
	if f.w.top() {
		for _, r := range f.fs.Roots {
			fi, _, err := f.fs.stat(f.ctx, "/"+r.Name)
			if err != nil {
				continue // gone, or no access now
			}
			f.list = append(f.list, fi)
		}
		return nil
	}
	l, err := f.fs.Files.ListDir(f.ctx, f.fs.Who, f.w.share, f.w.path, "")
	if err != nil {
		return osErr(err)
	}
	for _, e := range l.Entries {
		if e.Name == "" || fileworker.Hidden(e.Name) || strings.ContainsAny(e.Name, "/\x00") {
			continue
		}
		fi := infoOf(e)
		f.fs.remember(path.Join(f.name, e.Name), fi)
		f.list = append(f.list, fi)
	}
	return nil
}

func (f *dirFile) Readdir(count int) ([]os.FileInfo, error) {
	if err := f.load(); err != nil {
		return nil, err
	}
	rest := f.list[f.pos:]
	if count <= 0 {
		f.pos = len(f.list)
		return rest, nil
	}
	if len(rest) == 0 {
		return nil, io.EOF
	}
	if count > len(rest) {
		count = len(rest)
	}
	f.pos += count
	return rest[:count], nil
}

// ---- reading -----------------------------------------------------------------

type readFile struct {
	fs  *FS
	ctx context.Context
	w   where
	fi  *info
	f   *os.File
}

func (f *readFile) open() error {
	if f.f != nil {
		return nil
	}
	of, e, err := f.fs.Files.Open(f.ctx, f.fs.Who, f.w.share, f.w.path)
	if err != nil {
		return osErr(err)
	}
	f.f = of
	if e != nil {
		f.fi.size, f.fi.mod = e.Size, e.Modified
	}
	return nil
}

func (f *readFile) note(err error) error {
	if err != nil && err != io.EOF {
		f.fs.mu.Lock()
		f.fs.readFailed = true
		f.fs.mu.Unlock()
	}
	return err
}

func (f *readFile) Read(p []byte) (int, error) {
	if err := f.open(); err != nil {
		return 0, f.note(err)
	}
	n, err := f.f.Read(p)
	return n, f.note(err)
}

func (f *readFile) Seek(off int64, whence int) (int64, error) {
	if err := f.open(); err != nil {
		return 0, f.note(err)
	}
	return f.f.Seek(off, whence)
}

func (f *readFile) Close() error {
	if f.f != nil {
		return f.f.Close()
	}
	return nil
}

func (f *readFile) Readdir(int) ([]os.FileInfo, error) { return nil, os.ErrInvalid }
func (f *readFile) Stat() (os.FileInfo, error)         { return f.fi, nil }
func (f *readFile) Write([]byte) (int, error)          { return 0, os.ErrPermission }

func (f *readFile) DeadProps() (map[xml.Name]webdav.Property, error) {
	return noDeadProps{}.DeadProps()
}

func (f *readFile) Patch(p []webdav.Proppatch) ([]webdav.Propstat, error) {
	return noDeadProps{setTime: func(t time.Time) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(f.ctx), 15*time.Second)
		defer cancel()
		if err := f.fs.Files.SetModified(ctx, f.fs.Who, f.w.share, f.w.path, t); err == nil {
			f.fs.changed("settime", f.w, "modified "+t.UTC().Format(time.RFC3339), 0)
		}
	}}.Patch(p)
}

// ---- writing -----------------------------------------------------------------

// writeFile is an upload: written to tmp, renamed over the target on Close
// when everything arrived.
type writeFile struct {
	noDeadProps
	fs      *FS
	ctx     context.Context
	w       where
	tmp     string
	name    string
	f       *os.File
	n       int64
	werr    error
	closed  bool
	modTime time.Time
	// replaces: the target existed; its old version is recycled first.
	replaces bool
}

func (f *writeFile) Write(p []byte) (int, error) {
	n, err := f.f.Write(p)
	f.n += int64(n)
	if err != nil && f.werr == nil {
		f.werr = err
	}
	return n, err
}

// ReadFrom lets io.Copy stream the body straight into the file.
func (f *writeFile) ReadFrom(r io.Reader) (int64, error) {
	n, err := io.Copy(onlyWriter{f.f}, r)
	f.n += n
	if err != nil && f.werr == nil {
		f.werr = err
	}
	return n, err
}

type onlyWriter struct{ w io.Writer }

func (o onlyWriter) Write(p []byte) (int, error) { return o.w.Write(p) }

func (f *writeFile) Read([]byte) (int, error)           { return 0, os.ErrInvalid }
func (f *writeFile) Seek(int64, int) (int64, error)     { return 0, os.ErrInvalid }
func (f *writeFile) Readdir(int) ([]os.FileInfo, error) { return nil, os.ErrInvalid }

func (f *writeFile) Stat() (os.FileInfo, error) {
	mod := time.Now()
	if fi, err := f.f.Stat(); err == nil {
		mod = fi.ModTime()
	}
	return &info{name: f.name, size: f.n, mod: mod}, nil
}

// Close puts the upload in place, or throws it away when anything went
// wrong (a write failed, the body broke off, a copy's source failed).
func (f *writeFile) Close() error {
	if f.closed {
		return nil
	}
	f.closed = true
	cerr := f.f.Close()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(f.ctx), time.Minute)
	defer cancel()
	if f.werr != nil || cerr != nil || f.fs.failed() {
		_, _ = f.fs.Files.DeleteItem(ctx, f.fs.Who, f.w.share, f.tmp, true)
		if f.werr != nil {
			return f.werr
		}
		if cerr != nil {
			return cerr
		}
		return errors.New("the upload broke off; nothing was changed")
	}
	if f.replaces && f.w.root.Recycle {
		// The old version goes to the recycle bin, as a delete would put
		// it. Without a bin the rename below replaces it in one step (the
		// person may write that file: create checked), so the name is
		// never missing in between.
		if _, err := f.fs.Files.DeleteItem(ctx, f.fs.Who, f.w.share, f.w.path, false); err != nil && !errors.Is(err, files.ErrNotFound) {
			_, _ = f.fs.Files.DeleteItem(ctx, f.fs.Who, f.w.share, f.tmp, true)
			return osErr(err)
		}
	}
	if err := f.fs.Files.Replace(ctx, f.fs.Who, f.w.share, f.tmp, f.w.path); err != nil {
		_, _ = f.fs.Files.DeleteItem(ctx, f.fs.Who, f.w.share, f.tmp, true)
		return osErr(err)
	}
	f.fs.forget()
	f.fs.changed("put", f.w, "", f.n)
	return nil
}
