//go:build linux

package fileworker

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// tree makes a share-like folder:
//
//	docs/a.txt, docs/sub/b.txt, top.txt
//	link -> /etc (a symlink), docs/esc -> ../.. , fifo (a named pipe)
//	.recycle/, .zfs/snapshot/<two automatic snapshots and a manual one>, .hardyos-meta
func tree(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, s string) {
		t.Helper()
		must(os.MkdirAll(filepath.Dir(filepath.Join(d, p)), 0o755))
		must(os.WriteFile(filepath.Join(d, p), []byte(s), 0o644))
	}
	write("docs/a.txt", "alpha")
	write("docs/sub/b.txt", "bravo")
	write("top.txt", "top")
	must(os.Symlink("/etc", filepath.Join(d, "link")))
	must(os.Symlink("../..", filepath.Join(d, "docs/esc")))
	must(unix.Mkfifo(filepath.Join(d, "fifo"), 0o644))
	must(os.Mkdir(filepath.Join(d, ".recycle"), 0o1777))
	write(".hardyos-meta", "x")
	// Snapshots: the newest has a.txt as now, the older a different one.
	old := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	write(".zfs/snapshot/hardyos-auto-daily_2026-10-25-0000/docs/a.txt", "alpha")
	write(".zfs/snapshot/hardyos-auto-daily_2026-10-24-0000/docs/a.txt", "old alpha")
	must(os.Chtimes(filepath.Join(d, ".zfs/snapshot/hardyos-auto-daily_2026-10-24-0000/docs/a.txt"), old, old))
	write(".zfs/snapshot/hardyos-auto-daily_2026-10-23-0000/docs/a.txt", "old alpha")
	must(os.Chtimes(filepath.Join(d, ".zfs/snapshot/hardyos-auto-daily_2026-10-23-0000/docs/a.txt"), old, old))
	write(".zfs/snapshot/manual/docs/a.txt", "manual")
	now := time.Now()
	must(os.Chtimes(filepath.Join(d, "docs/a.txt"), now, now))
	must(os.Chtimes(filepath.Join(d, ".zfs/snapshot/hardyos-auto-daily_2026-10-25-0000/docs/a.txt"), now, now))
	return d
}

func openRoot(t *testing.T, p string) int {
	t.Helper()
	fd, err := unix.Open(p, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd
}

// inproc runs an operation in this process (no privilege drop): path
// resolution and the operations themselves.
func inproc(t *testing.T, roots []int, req Request, out any) (*os.File, error) {
	t.Helper()
	w := &worker{req: req, roots: roots, sock: -1}
	data, err := w.run()
	if err != nil {
		return nil, asError(err)
	}
	if out != nil {
		b, _ := json.Marshal(data)
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatal(err)
		}
	}
	return w.sent, nil
}

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return "?" + err.Error()
}

func TestWorkerResolution(t *testing.T) {
	d := tree(t)
	root := openRoot(t, d)
	roots := []int{root}

	var l Listing
	if _, err := inproc(t, roots, Request{Op: OpList}, &l); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range l.Entries {
		names = append(names, e.Name)
	}
	// Folders first; links, pipes and hidden names never show.
	if strings.Join(names, ",") != "docs,top.txt" {
		t.Fatalf("listing = %v", names)
	}
	if !l.Folder.Writable || l.Entries[1].Size != 3 || !l.Entries[1].Writable {
		t.Fatalf("listing details = %+v", l)
	}

	refused := map[string]string{
		"link":                   CodeNotAllowed, // a symlink
		"link/passwd":            CodeNotAllowed,
		"docs/esc":               CodeNotAllowed, // a symlink pointing out
		"docs/esc/etc":           CodeNotAllowed,
		"../" + filepath.Base(d): CodeNotAllowed,
		".zfs/snapshot":          CodeNotAllowed,
		".recycle":               CodeNotAllowed,
		".hardyos-meta":          CodeNotAllowed,
		"nothing/here":           CodeNotFound,
		"top.txt/x":              CodeNotFound,
	}
	for p, want := range refused {
		for _, op := range []string{OpList, OpStat, OpOpen} {
			if _, err := inproc(t, roots, Request{Op: op, Path: p}, nil); code(err) != want {
				t.Errorf("%s %q = %v, want %s", op, p, err, want)
			}
		}
	}
	// A pipe is never opened (it would hang).
	if _, err := inproc(t, roots, Request{Op: OpOpen, Path: "fifo"}, nil); code(err) != CodeNotAllowed {
		t.Errorf("open fifo = %v", err)
	}
	if _, err := inproc(t, roots, Request{Op: OpOpen, Path: "docs"}, nil); code(err) != CodeNotAllowed {
		t.Errorf("open a folder = %v", err)
	}

	// Magic links (/proc/self/root and friends) aren't followed either.
	proc := openRoot(t, "/proc/self")
	for _, p := range []string{"root", "root/etc", "cwd", "exe"} {
		if _, err := inproc(t, []int{proc}, Request{Op: OpStat, Path: p}, nil); code(err) != CodeNotAllowed {
			t.Errorf("stat /proc/self/%s = %v", p, err)
		}
	}

	// Opening hands over the file.
	var e Entry
	f, err := inproc(t, roots, Request{Op: OpOpen, Path: "docs/sub/b.txt"}, &e)
	if err != nil || f == nil {
		t.Fatalf("open = %v %v", f, err)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	if string(b) != "bravo" || e.Path != "docs/sub/b.txt" || e.Name != "b.txt" || e.Size != 5 {
		t.Fatalf("opened %q %+v", b, e)
	}
}

func TestWorkerChanges(t *testing.T) {
	d := tree(t)
	roots := []int{openRoot(t, d)}
	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join(d, p))
		if err != nil {
			return "<" + err.Error() + ">"
		}
		return string(b)
	}

	// create: exclusive unless overwrite; never through a link.
	f, err := inproc(t, roots, Request{Op: OpCreate, Path: "docs/new.txt"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("new")
	f.Close()
	if read("docs/new.txt") != "new" {
		t.Fatal("create didn't write")
	}
	if _, err := inproc(t, roots, Request{Op: OpCreate, Path: "docs/new.txt"}, nil); code(err) != CodeExists {
		t.Errorf("create over a file = %v", err)
	}
	if _, err := inproc(t, roots, Request{Op: OpCreate, Path: "link/evil"}, nil); code(err) != CodeNotAllowed {
		t.Errorf("create through a link = %v", err)
	}
	if _, err := inproc(t, roots, Request{Op: OpCreate, Path: "link", Overwrite: true}, nil); code(err) != CodeExists {
		t.Errorf("create over a link = %v", err)
	}
	f, err = inproc(t, roots, Request{Op: OpCreate, Path: "docs/new.txt", Overwrite: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("2")
	f.Close()
	if read("docs/new.txt") != "2" {
		t.Fatal("overwrite didn't truncate")
	}
	// openwrite: no truncation (upload chunks).
	f, err = inproc(t, roots, Request{Op: OpOpenWrite, Path: "docs/new.txt"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.Seek(1, io.SeekStart)
	f.WriteString("34")
	f.Close()
	if read("docs/new.txt") != "234" {
		t.Fatalf("openwrite = %q", read("docs/new.txt"))
	}

	// mkdir, rename (no replacing), rename over a file with overwrite only.
	if _, err := inproc(t, roots, Request{Op: OpMkdir, Path: "docs/made"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := inproc(t, roots, Request{Op: OpMkdir, Path: "docs/made"}, nil); code(err) != CodeExists {
		t.Errorf("mkdir twice = %v", err)
	}
	if _, err := inproc(t, roots, Request{Op: OpRename, Path: "docs/new.txt", To: "top.txt"}, nil); code(err) != CodeExists {
		t.Errorf("rename over a file = %v", err)
	}
	if _, err := inproc(t, roots, Request{Op: OpRename, Path: "docs/new.txt", To: "docs/made", Overwrite: true}, nil); code(err) != CodeExists {
		t.Errorf("replace a folder = %v", err)
	}
	if _, err := inproc(t, roots, Request{Op: OpRename, Path: "docs/new.txt", To: "top.txt", Overwrite: true}, nil); err != nil {
		t.Fatal(err)
	}
	if read("top.txt") != "234" {
		t.Fatal("replace didn't happen")
	}
	if _, err := inproc(t, roots, Request{Op: OpRename, Path: "docs", To: "docs/made/docs"}, nil); code(err) != CodeNotAllowed {
		t.Errorf("move into itself = %v", err)
	}
	if _, err := inproc(t, roots, Request{Op: OpRename, Path: "top.txt", To: "../outside.txt"}, nil); code(err) != CodeNotAllowed {
		t.Errorf("rename out = %v", err)
	}
	if _, err := inproc(t, roots, Request{Op: OpRename, Path: "top.txt", To: ".recycle/x"}, nil); code(err) != CodeNotAllowed {
		t.Errorf("rename into the bin = %v", err)
	}

	// settime
	when := time.Date(2020, 5, 6, 7, 8, 9, 0, time.UTC)
	if _, err := inproc(t, roots, Request{Op: OpSetTime, Path: "top.txt", Modified: when}, nil); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(d, "top.txt")); !fi.ModTime().Equal(when) {
		t.Errorf("mtime = %v", fi.ModTime())
	}

	// delete to the recycle bin keeps the folders and never overwrites.
	var res map[string]any
	if _, err := inproc(t, roots, Request{Op: OpDelete, Path: "docs/sub/b.txt", Recycle: true, Bin: "alice"}, &res); err != nil {
		t.Fatal(err)
	}
	if res["binPath"] != "alice/docs/sub/b.txt" || read(".recycle/alice/docs/sub/b.txt") != "bravo" {
		t.Fatalf("recycled %v", res)
	}
	os.WriteFile(filepath.Join(d, "docs/sub/b.txt"), []byte("b2"), 0o644)
	if _, err := inproc(t, roots, Request{Op: OpDelete, Path: "docs/sub/b.txt", Recycle: true, Bin: "alice"}, &res); err != nil {
		t.Fatal(err)
	}
	if bp, _ := res["binPath"].(string); !strings.HasPrefix(bp, "alice/docs/sub/b (deleted ") || !strings.HasSuffix(bp, ").txt") || read(".recycle/"+bp) != "b2" {
		t.Fatalf("second recycle = %v", res)
	}
	if fi, err := os.Stat(filepath.Join(d, ".recycle/alice")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("bin mode = %v %v", fi, err)
	}
	// Permanent delete of a tree, links inside are removed, not followed.
	os.Symlink("/etc/passwd", filepath.Join(d, "docs/sub/pw"))
	if _, err := inproc(t, roots, Request{Op: OpDelete, Path: "docs"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(d, "docs")); !os.IsNotExist(err) {
		t.Fatal("docs still there")
	}
	if _, err := os.Stat("/etc/passwd"); err != nil {
		t.Fatal("followed a link while deleting!")
	}
	if _, err := inproc(t, roots, Request{Op: OpDelete, Path: ""}, nil); code(err) != CodeNotAllowed {
		t.Errorf("delete the top = %v", err)
	}

	// ReadOnly refuses changes.
	for _, op := range []string{OpCreate, OpMkdir, OpDelete, OpSetTime, OpOpenWrite} {
		if _, err := inproc(t, roots, Request{Op: op, Path: "top.txt2", ReadOnly: true}, nil); code(err) != CodeNoAccess {
			t.Errorf("read-only %s = %v", op, err)
		}
	}

	// Stale uploads are cleaned up when the folder is listed.
	stale := filepath.Join(d, ".hardyos-upload-0123456789abcdef01234567")
	fresh := filepath.Join(d, ".hardyos-upload-abcdefabcdefabcdefabcdef")
	os.WriteFile(stale, []byte("x"), 0o644)
	os.WriteFile(fresh, []byte("x"), 0o644)
	long := time.Now().Add(-72 * time.Hour)
	os.Chtimes(stale, long, long)
	if _, err := inproc(t, roots, Request{Op: OpList}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("stale upload left")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("fresh upload removed")
	}
}

func TestWorkerVersions(t *testing.T) {
	d := tree(t)
	roots := []int{openRoot(t, d)}
	var vs []Version
	if _, err := inproc(t, roots, Request{Op: OpVersions, Path: "docs/a.txt"}, &vs); err != nil {
		t.Fatal(err)
	}
	// The 25th is the same as now and the 23rd the same as the 24th: one
	// version; the manual snapshot isn't one of ours.
	if len(vs) != 1 || vs[0].Snapshot != "hardyos-auto-daily_2026-10-24-0000" || vs[0].Size != 9 {
		t.Fatalf("versions = %+v", vs)
	}
	var e Entry
	f, err := inproc(t, roots, Request{Op: OpOpen, Path: "docs/a.txt", Snapshot: vs[0].Snapshot}, &e)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	if string(b) != "old alpha" || e.Writable {
		t.Fatalf("old version = %q %+v", b, e)
	}
	var l Listing
	if _, err := inproc(t, roots, Request{Op: OpList, Path: "docs", Snapshot: vs[0].Snapshot}, &l); err != nil || len(l.Entries) != 1 || l.Folder.Writable {
		t.Fatalf("snapshot listing = %+v %v", l, err)
	}
	for _, op := range []string{OpCreate, OpMkdir, OpDelete, OpRename} {
		if _, err := inproc(t, roots, Request{Op: op, Path: "docs/x", To: "y", Snapshot: vs[0].Snapshot}, nil); code(err) != CodeNotAllowed {
			t.Errorf("%s in a snapshot = %v", op, err)
		}
	}
	for _, s := range []string{"manual", "../x", "hardyos-auto-daily_2026-10-24-0000/../.."} {
		if _, err := inproc(t, roots, Request{Op: OpList, Snapshot: s}, nil); code(err) != CodeBadArgs {
			t.Errorf("snapshot %q = %v", s, err)
		}
	}
	// A folder's versions are all listed (its contents may differ).
	if _, err := inproc(t, roots, Request{Op: OpVersions, Path: "docs"}, &vs); err != nil || len(vs) != 3 || !vs[0].Dir {
		t.Fatalf("folder versions = %+v %v", vs, err)
	}
	// A deleted file's versions are still there.
	os.Remove(filepath.Join(d, "docs/a.txt"))
	if _, err := inproc(t, roots, Request{Op: OpVersions, Path: "docs/a.txt"}, &vs); err != nil || len(vs) != 2 {
		t.Fatalf("deleted file versions = %+v %v", vs, err)
	}
}
