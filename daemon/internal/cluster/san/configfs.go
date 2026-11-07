package san

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
)

// ConfigFSRoot is LIO's configfs directory.
const ConfigFSRoot = "/sys/kernel/config/target"

// Entry is one name in a configfs directory.
type Entry struct {
	Name string
	Dir  bool
	Link bool
}

// FS is the part of configfs the reconciler uses. Paths are slash
// separated and relative to the target directory (core/…, iscsi/…).
// configfs differs from a normal file system: mkdir creates a directory's
// attribute files and default groups, attributes can be written but never
// created, rmdir works while those remain, and symlinks connect LUNs to
// backstores. FakeFS models exactly that for tests.
type FS interface {
	Mkdir(p string) error
	Rmdir(p string) error
	// Write sets an existing attribute (no create, no truncate semantics
	// beyond configfs's own).
	Write(p, value string) error
	Read(p string) (string, error)
	Symlink(target, link string) error
	Readlink(p string) (string, error)
	Unlink(p string) error
	List(p string) ([]Entry, error)
	Exists(p string) bool
}

// OSFS is configfs itself, rooted at Root (ConfigFSRoot).
type OSFS struct{ Root string }

func (o OSFS) abs(p string) string { return filepath.Join(o.Root, filepath.FromSlash(p)) }

// Mkdir implements FS.
func (o OSFS) Mkdir(p string) error { return os.Mkdir(o.abs(p), 0o755) }

// Rmdir implements FS.
func (o OSFS) Rmdir(p string) error { return os.Remove(o.abs(p)) }

// Write implements FS: configfs attributes are written in one write(2)
// to an existing file, never created.
func (o OSFS) Write(p, value string) error {
	f, err := os.OpenFile(o.abs(p), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err := f.Write([]byte(value)); err != nil {
		f.Close()
		return fmt.Errorf("writing %s: %w", p, err)
	}
	return f.Close()
}

// Read implements FS.
func (o OSFS) Read(p string) (string, error) {
	b, err := os.ReadFile(o.abs(p))
	return strings.TrimRight(string(b), "\n\x00"), err
}

// Symlink implements FS. target is relative to the target directory too
// and becomes an absolute link (as targetcli makes them).
func (o OSFS) Symlink(target, link string) error { return os.Symlink(o.abs(target), o.abs(link)) }

// Readlink implements FS; the answer is relative to the target directory.
func (o OSFS) Readlink(p string) (string, error) {
	t, err := os.Readlink(o.abs(p))
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(t) {
		t = filepath.Join(filepath.Dir(o.abs(p)), t)
	}
	rel, err := filepath.Rel(o.Root, filepath.Clean(t))
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
}

// Unlink implements FS.
func (o OSFS) Unlink(p string) error { return os.Remove(o.abs(p)) }

// List implements FS.
func (o OSFS) List(p string) ([]Entry, error) {
	des, err := os.ReadDir(o.abs(p))
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(des))
	for _, d := range des {
		out = append(out, Entry{Name: d.Name(), Dir: d.IsDir(), Link: d.Type()&fs.ModeSymlink != 0})
	}
	return out, nil
}

// Exists implements FS.
func (o OSFS) Exists(p string) bool {
	_, err := os.Lstat(o.abs(p))
	return err == nil
}

// ---- the fake ---------------------------------------------------------------

// FakeFS is an in-memory configfs for tests. It creates the attributes and
// default groups LIO creates, refuses to create attributes by writing,
// refuses rmdir while user-made children or links remain, refuses to remove
// a backstore or TPG LUN something links to, and refuses to change a
// backstore's unit serial while it is exported, like the kernel.
type FakeFS struct {
	mu    sync.Mutex
	nodes map[string]*fakeNode
	// Log records every change, in order.
	Log []string
	// Sessions: target IQN -> logged-in sessions; disabling a TPG drops
	// them (tests check fencing).
	Sessions map[string]int
}

type fakeNode struct {
	kind   byte // 'd' dir, 'f' file, 'l' link
	auto   bool
	value  string
	target string
}

// NewFakeFS returns a fake with the core and iscsi groups loaded.
func NewFakeFS() *FakeFS {
	f := &FakeFS{nodes: map[string]*fakeNode{}, Sessions: map[string]int{}}
	f.nodes["."] = &fakeNode{kind: 'd', auto: true}
	f.nodes["core"] = &fakeNode{kind: 'd', auto: true}
	f.nodes["iscsi"] = &fakeNode{kind: 'd', auto: true}
	f.nodes["iscsi/discovery_auth"] = &fakeNode{kind: 'd', auto: true}
	for _, a := range []string{"enforce_discovery_auth", "userid", "password", "userid_mut", "password_mut"} {
		f.nodes["iscsi/discovery_auth/"+a] = &fakeNode{kind: 'f', auto: true, value: "NULL"}
	}
	return f
}

func (f *FakeFS) autoChildren(p string) (dirs []string, files map[string]string) {
	parts := strings.Split(p, "/")
	n := len(parts)
	switch {
	case n == 2 && parts[0] == "core":
		return nil, nil // an HBA
	case n == 3 && parts[0] == "core":
		return []string{"attrib", "wwn", "pr", "alua", "statistics"}, map[string]string{
			"control": "", "enable": "0", "udev_path": "", "info": "",
			"attrib/emulate_tpu": "0", "attrib/emulate_write_cache": "0", "attrib/is_nonrot": "0", "attrib/block_size": "512",
			"wwn/vpd_unit_serial": "",
		}
	case n == 3 && parts[0] == "iscsi" && strings.HasPrefix(parts[2], "tpgt_"):
		return []string{"attrib", "auth", "param", "np", "acls", "lun"}, map[string]string{
			"enable": "0", "attrib/authentication": "0", "attrib/generate_node_acls": "0",
			"attrib/demo_mode_write_protect": "1", "attrib/cache_dynamic_acls": "0", "attrib/login_timeout": "15",
			"param/AuthMethod": "CHAP,None",
		}
	case n == 5 && parts[0] == "iscsi" && parts[3] == "acls":
		return []string{"auth"}, map[string]string{
			"auth/userid": "", "auth/password": "", "auth/userid_mut": "", "auth/password_mut": "",
		}
	}
	return nil, nil
}

func (f *FakeFS) parentOK(p string) error {
	d := path.Dir(p)
	if n := f.nodes[d]; n == nil || n.kind != 'd' {
		return &fs.PathError{Op: "mkdir", Path: p, Err: fs.ErrNotExist}
	}
	return nil
}

// Mkdir implements FS.
func (f *FakeFS) Mkdir(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nodes[p] != nil {
		return &fs.PathError{Op: "mkdir", Path: p, Err: fs.ErrExist}
	}
	if err := f.parentOK(p); err != nil {
		return err
	}
	f.nodes[p] = &fakeNode{kind: 'd'}
	dirs, files := f.autoChildren(p)
	for _, d := range dirs {
		f.nodes[p+"/"+d] = &fakeNode{kind: 'd', auto: true}
	}
	for k, v := range files {
		f.nodes[p+"/"+k] = &fakeNode{kind: 'f', auto: true, value: v}
	}
	f.Log = append(f.Log, "mkdir "+p)
	return nil
}

func (f *FakeFS) children(p string) []string {
	var out []string
	for k := range f.nodes {
		if k != p && path.Dir(k) == p {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func (f *FakeFS) linkedTo(p string) bool {
	for _, n := range f.nodes {
		if n.kind == 'l' && n.target == p {
			return true
		}
	}
	return false
}

// Rmdir implements FS.
func (f *FakeFS) Rmdir(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.nodes[p]
	if n == nil || n.kind != 'd' {
		return &fs.PathError{Op: "rmdir", Path: p, Err: fs.ErrNotExist}
	}
	if n.auto {
		return &fs.PathError{Op: "rmdir", Path: p, Err: errors.New("operation not permitted (default group)")}
	}
	var walk func(string) error
	walk = func(q string) error {
		for _, c := range f.children(q) {
			cn := f.nodes[c]
			if !cn.auto {
				return &fs.PathError{Op: "rmdir", Path: p, Err: errors.New("directory not empty")}
			}
			if cn.kind == 'd' {
				if err := walk(c); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(p); err != nil {
		return err
	}
	if f.linkedTo(p) {
		return &fs.PathError{Op: "rmdir", Path: p, Err: errors.New("device or resource busy (linked)")}
	}
	for k := range f.nodes {
		if k == p || strings.HasPrefix(k, p+"/") {
			delete(f.nodes, k)
		}
	}
	f.Log = append(f.Log, "rmdir "+p)
	return nil
}

// Write implements FS.
func (f *FakeFS) Write(p, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.nodes[p]
	if n == nil || n.kind != 'f' {
		return &fs.PathError{Op: "write", Path: p, Err: fs.ErrNotExist}
	}
	if strings.HasSuffix(p, "/wwn/vpd_unit_serial") && f.linkedTo(strings.TrimSuffix(p, "/wwn/vpd_unit_serial")) {
		return &fs.PathError{Op: "write", Path: p, Err: errors.New("unable to set the unit serial while exported")}
	}
	if strings.HasPrefix(p, "core/iblock_") && strings.HasSuffix(p, "/attrib/emulate_write_cache") && value == "1" {
		// iblock reports the block device's own write cache.
		return &fs.PathError{Op: "write", Path: p, Err: syscall.EINVAL}
	}
	switch {
	case strings.HasSuffix(p, "/control"):
		// control takes key=value settings; udev_path shows the device.
		if k, v, ok := strings.Cut(value, "="); ok && k == "udev_path" {
			f.nodes[path.Dir(p)+"/udev_path"].value = v
		}
	case path.Base(p) == "enable" && strings.Contains(p, "/tpgt_") && value == "0":
		iqn := strings.Split(p, "/")[1]
		delete(f.Sessions, iqn)
		n.value = value
	default:
		n.value = value
	}
	if strings.Contains(p, "password") {
		f.Log = append(f.Log, "write "+p+" <secret>")
	} else {
		f.Log = append(f.Log, "write "+p+" "+value)
	}
	return nil
}

// Read implements FS.
func (f *FakeFS) Read(p string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.nodes[p]
	if n == nil || n.kind != 'f' {
		return "", &fs.PathError{Op: "read", Path: p, Err: fs.ErrNotExist}
	}
	return n.value, nil
}

// Symlink implements FS.
func (f *FakeFS) Symlink(target, link string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nodes[link] != nil {
		return &fs.PathError{Op: "symlink", Path: link, Err: fs.ErrExist}
	}
	if t := f.nodes[target]; t == nil || t.kind != 'd' {
		return &fs.PathError{Op: "symlink", Path: target, Err: fs.ErrNotExist}
	}
	if err := f.parentOK(link); err != nil {
		return err
	}
	if strings.HasPrefix(target, "core/") {
		if v := f.nodes[target+"/enable"]; v == nil || v.value != "1" {
			return &fs.PathError{Op: "symlink", Path: link, Err: errors.New("backstore isn't enabled")}
		}
	}
	f.nodes[link] = &fakeNode{kind: 'l', target: target}
	f.Log = append(f.Log, "link "+link+" -> "+target)
	return nil
}

// Readlink implements FS.
func (f *FakeFS) Readlink(p string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.nodes[p]
	if n == nil || n.kind != 'l' {
		return "", &fs.PathError{Op: "readlink", Path: p, Err: fs.ErrNotExist}
	}
	return n.target, nil
}

// Unlink implements FS.
func (f *FakeFS) Unlink(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.nodes[p]
	if n == nil || n.kind != 'l' {
		return &fs.PathError{Op: "unlink", Path: p, Err: fs.ErrNotExist}
	}
	// A TPG LUN's link can't go while an ACL maps the LUN.
	if f.linkedTo(path.Dir(p)) {
		return &fs.PathError{Op: "unlink", Path: p, Err: errors.New("device or resource busy (mapped in an ACL)")}
	}
	delete(f.nodes, p)
	f.Log = append(f.Log, "unlink "+p)
	return nil
}

// List implements FS.
func (f *FakeFS) List(p string) ([]Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n := f.nodes[p]; n == nil || n.kind != 'd' {
		return nil, &fs.PathError{Op: "readdir", Path: p, Err: fs.ErrNotExist}
	}
	var out []Entry
	for _, c := range f.children(p) {
		n := f.nodes[c]
		out = append(out, Entry{Name: path.Base(c), Dir: n.kind == 'd', Link: n.kind == 'l'})
	}
	return out, nil
}

// Exists implements FS.
func (f *FakeFS) Exists(p string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nodes[p] != nil
}

// Value reads an attribute (tests).
func (f *FakeFS) Value(p string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n := f.nodes[p]; n != nil {
		if n.kind == 'l' {
			return "-> " + n.target
		}
		return n.value
	}
	return ""
}

// Paths lists every user-made path (tests).
func (f *FakeFS) Paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k, n := range f.nodes {
		if !n.auto {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
