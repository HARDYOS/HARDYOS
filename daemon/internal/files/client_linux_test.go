//go:build linux

package files

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/fileworker"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/shares"
)

// The test binary doubles as hardyd-priv's file worker.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == fileworker.Subcommand {
		fileworker.ChildMain()
	}
	os.Exit(m.Run())
}

var (
	exeOnce sync.Once
	exePath string
	exeErr  error
)

func workerExe(t *testing.T) string {
	t.Helper()
	exeOnce.Do(func() {
		self, err := os.Executable()
		if err != nil || os.Geteuid() != 0 {
			exePath, exeErr = self, err
			return
		}
		dir, err := os.MkdirTemp("", "hardyos-files-test-")
		if err != nil {
			exeErr = err
			return
		}
		os.Chmod(dir, 0o755)
		src, err := os.Open(self)
		if err != nil {
			exeErr = err
			return
		}
		defer src.Close()
		exePath = filepath.Join(dir, "worker")
		dst, err := os.OpenFile(exePath, os.O_CREATE|os.O_WRONLY, 0o755)
		if err != nil {
			exeErr = err
			return
		}
		_, exeErr = io.Copy(dst, src)
		dst.Close()
	})
	if exeErr != nil {
		t.Fatal(exeErr)
	}
	return exePath
}

type fakeShares []shares.Share

func (f fakeShares) List(context.Context) ([]shares.Share, error) { return f, nil }

type env struct {
	c          *Client
	a, b       string // the two shares' folders
	uid        int
	who        Who
	crossShare bool // b is on another file system
}

// newEnv runs a real hardyd-priv (in this process) with two shares, a
// (recycle bin on) and b, and a client acting as HOME\alice (the test's
// own user, or user 100001 when running as root).
// devOf is a folder's device, standing in for its verified mount.
func devOf(p string) uint64 {
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil {
		return 0
	}
	return uint64(st.Dev)
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{a: t.TempDir(), who: Who{Principal: `HOME\alice`}}
	if d, err := os.MkdirTemp("/dev/shm", "hardyos-files-"); err == nil {
		t.Cleanup(func() { os.RemoveAll(d) })
		var sa, sb syscall.Stat_t
		syscall.Stat(e.a, &sa)
		syscall.Stat(d, &sb)
		e.b, e.crossShare = d, sa.Dev != sb.Dev
	} else {
		e.b = t.TempDir()
	}
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		uid, gid = 100001, 100513
		os.Chown(e.a, uid, gid)
		os.Chown(e.b, uid, gid)
	}
	e.uid = uid
	ctx, cancel := context.WithCancel(context.Background())
	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	fw := &fileworker.Server{
		Shares: fakeShares{
			{ID: "a", Name: "A", Mounted: true, Path: e.a, RootDev: devOf(e.a), Recycle: true, Access: []shares.Rule{{Kind: shares.KindEveryone, Level: shares.LevelWrite}}},
			{ID: "b", Name: "B", Mounted: true, Path: e.b, RootDev: devOf(e.b), Access: []shares.Rule{{Kind: shares.KindGroup, Name: `HOME\Family`, Level: shares.LevelWrite}}},
		},
		Exe: workerExe(t), Args: []string{fileworker.Subcommand},
		LookupUser: func(_ context.Context, name string) (*fileworker.Identity, error) {
			return &fileworker.Identity{UID: uid, GID: gid}, nil
		},
		AcceptID: func(int) bool { return true },
	}
	priv.RegisterFileWorker(ps, fw)
	go func() { _ = ps.Serve(ctx, ln) }()
	t.Cleanup(cancel)
	e.c = &Client{Priv: priv.NewClient(sock), Lookup: func(_ context.Context, w Who) (auth.Identity, error) {
		if w.Principal != `HOME\alice` {
			return nil, &Error{Kind: ErrNoAccess, Msg: "unknown"}
		}
		return &auth.User{Username: w.Principal, Principal: w.Principal, Source: auth.SourceDomain, Role: auth.RoleUser,
			Groups: []string{`HOME\Domain Users`, `HOME\Family`}}, nil
	}}
	return e
}

func (e *env) write(t *testing.T, root, p, s string) {
	t.Helper()
	full := filepath.Join(root, p)
	os.MkdirAll(filepath.Dir(full), 0o755)
	if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		for d := full; d != root; d = filepath.Dir(d) {
			os.Lchown(d, e.uid, 100513)
		}
	}
}

func readAll(t *testing.T, f *os.File) string {
	t.Helper()
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestClient(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c, who := e.c, e.who
	old := time.Date(2025, 3, 4, 5, 6, 7, 0, time.UTC)
	e.write(t, e.a, "Photos/2025/beach.jpg", "sand")
	e.write(t, e.a, "Photos/2025/sea.jpg", "water")
	e.write(t, e.a, "notes.txt", "hello")
	os.Chtimes(filepath.Join(e.a, "Photos/2025/beach.jpg"), old, old)

	sh, err := c.Shares(ctx, who)
	if err != nil || len(sh) != 2 || sh[0].ID != "a" || !sh[1].Writable {
		t.Fatalf("shares = %+v %v", sh, err)
	}
	l, err := c.List(ctx, who, "a", "")
	if err != nil || len(l) != 2 || l[0].Name != "Photos" || !l[0].Dir || l[1].Size != 5 {
		t.Fatalf("list = %+v %v", l, err)
	}
	f, en, err := c.Open(ctx, who, "a", "notes.txt")
	if err != nil || readAll(t, f) != "hello" || en.Name != "notes.txt" {
		t.Fatalf("open = %+v %v", en, err)
	}
	if _, err := c.Stat(ctx, who, "a", "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("stat missing = %v", err)
	}
	if _, err := c.List(ctx, who, "a", "../x"); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("escape = %v", err)
	}
	if _, err := c.List(ctx, Who{Principal: `HOME\mallory`}, "a", ""); !errors.Is(err, ErrNoAccess) {
		t.Errorf("unknown person = %v", err)
	}

	// Copy a folder with progress; the copy keeps modification times.
	var last Progress
	to, err := c.CopyTree(ctx, who, Location{Share: "a", Path: "Photos"}, Location{Share: "a", Path: "Photos"},
		CopyOptions{Conflict: ConflictRename, Progress: func(p Progress) { last = p }})
	if err != nil || to != "Photos (copy)" {
		t.Fatalf("copy = %q %v", to, err)
	}
	if last.Files != 2 || last.TotalFiles != 2 || last.Bytes != 9 || last.TotalBytes != 9 {
		t.Errorf("progress = %+v", last)
	}
	if fi, err := os.Stat(filepath.Join(e.a, "Photos (copy)/2025/beach.jpg")); err != nil || !fi.ModTime().Equal(old) {
		t.Errorf("copied file = %v %v", fi, err)
	}
	if _, err := c.CopyTree(ctx, who, Location{Share: "a", Path: "notes.txt"}, Location{Share: "a", Path: "notes.txt"}, CopyOptions{Conflict: ConflictRename}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.a, "notes (copy).txt")); err != nil {
		t.Error("no notes (copy).txt")
	}
	if err := c.Copy(ctx, who, "a", "notes.txt", "a", "Photos/notes.txt"); err != nil {
		t.Fatal(err)
	}
	if err := c.Copy(ctx, who, "a", "notes.txt", "a", "Photos/notes.txt"); !errors.Is(err, ErrExists) {
		t.Errorf("copy onto a file = %v", err)
	}
	if err := c.Copy(ctx, who, "a", "Photos", "a", "Photos/2025/inside"); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("copy into itself = %v", err)
	}
	// Replace merges folders and overwrites files.
	e.write(t, e.a, "Photos (copy)/2025/sea.jpg", "changed")
	if _, err := c.CopyTree(ctx, who, Location{Share: "a", Path: "Photos (copy)"}, Location{Share: "a", Path: "Photos"}, CopyOptions{Conflict: ConflictReplace}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(e.a, "Photos/2025/sea.jpg")); string(b) != "changed" {
		t.Errorf("replace didn't overwrite: %q", b)
	}
	if got, _ := c.CopyTree(ctx, who, Location{Share: "a", Path: "notes.txt"}, Location{Share: "a", Path: "Photos/notes.txt"}, CopyOptions{Conflict: ConflictSkip}); got != "" {
		t.Errorf("skip copied to %q", got)
	}

	// Move between shares (another file system: copy, then delete).
	moved, err := c.Move(ctx, who, "a", "Photos (copy)", "b", "Moved", nil)
	if err != nil {
		t.Fatal(err)
	}
	if moved == e.crossShare {
		t.Errorf("moved = %v on another file system = %v", moved, e.crossShare)
	}
	if b, _ := os.ReadFile(filepath.Join(e.b, "Moved/2025/sea.jpg")); string(b) != "changed" {
		t.Errorf("moved file = %q", b)
	}
	if _, err := os.Stat(filepath.Join(e.a, "Photos (copy)")); !os.IsNotExist(err) {
		t.Error("the original is still there")
	}
	// Within a share it's a rename.
	if err := c.Rename(ctx, who, "a", "notes (copy).txt", "", "Photos/renamed.txt"); err != nil {
		t.Fatal(err)
	}

	// Delete: share a has a recycle bin, b doesn't.
	if recycled, err := c.DeleteItem(ctx, who, "a", "Photos/renamed.txt", false); err != nil || !recycled {
		t.Fatalf("delete = %v %v", recycled, err)
	}
	if _, err := os.Stat(filepath.Join(e.a, ".recycle/home.alice/Photos/renamed.txt")); err != nil {
		t.Errorf("not in the bin: %v", err)
	}
	if recycled, err := c.DeleteItem(ctx, who, "b", "Moved", false); err != nil || recycled {
		t.Fatalf("delete in b = %v %v", recycled, err)
	}
	if err := c.Delete(ctx, who, "a", ""); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("delete the top = %v", err)
	}

	// Uploads: create, write in pieces, replace into place.
	tmp := ".hardyos-upload-0123456789abcdef01234567"
	w, err := c.Create(ctx, who, "a", tmp, false)
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString("ab")
	w.Close()
	w, _, err = c.OpenWrite(ctx, who, "a", tmp)
	if err != nil {
		t.Fatal(err)
	}
	w.Seek(2, io.SeekStart)
	w.WriteString("cd")
	w.Close()
	if err := c.Replace(ctx, who, "a", tmp, "notes.txt"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(e.a, "notes.txt")); string(b) != "abcd" {
		t.Errorf("uploaded = %q", b)
	}
	if err := c.SetModified(ctx, who, "a", "notes.txt", old); err != nil {
		t.Fatal(err)
	}
	if err := c.Mkdir(ctx, who, "a", "New"); err != nil {
		t.Fatal(err)
	}
	if err := c.Mkdir(ctx, who, "a", "New"); !errors.Is(err, ErrExists) {
		t.Errorf("mkdir twice = %v", err)
	}
}

func TestClientVersions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c, who := e.c, e.who
	snap := "hardyos-auto-daily_2026-10-24-0000"
	e.write(t, e.a, "docs/report.txt", "now")
	e.write(t, e.a, ".zfs/snapshot/"+snap+"/docs/report.txt", "then")
	e.write(t, e.a, ".zfs/snapshot/"+snap+"/docs/gone.txt", "gone")

	vs, err := c.Versions(ctx, who, "a", "docs/report.txt")
	if err != nil || len(vs) != 1 || vs[0].Snapshot != snap || vs[0].Size != 4 {
		t.Fatalf("versions = %+v %v", vs, err)
	}
	f, _, err := c.OpenVersion(ctx, who, "a", "docs/report.txt", snap)
	if err != nil || readAll(t, f) != "then" {
		t.Fatalf("open version = %v", err)
	}
	l, err := c.ListDir(ctx, who, "a", "docs", snap)
	if err != nil || len(l.Entries) != 2 {
		t.Fatalf("list version = %+v %v", l, err)
	}
	// Restoring next to the current file, or in place of a deleted one.
	to, err := c.Restore(ctx, who, "a", "docs/report.txt", snap)
	if err != nil || to != "docs/report (restored 2026-10-24).txt" {
		t.Fatalf("restore = %q %v", to, err)
	}
	if b, _ := os.ReadFile(filepath.Join(e.a, to)); string(b) != "then" {
		t.Errorf("restored = %q", b)
	}
	if to, err := c.Restore(ctx, who, "a", "docs/report.txt", snap); err != nil || to != "docs/report (restored 2026-10-24 2).txt" {
		t.Errorf("second restore = %q %v", to, err)
	}
	if to, err := c.Restore(ctx, who, "a", "docs/gone.txt", snap); err != nil || to != "docs/gone.txt" {
		t.Errorf("restore a deleted file = %q %v", to, err)
	}
	if to, err := c.Restore(ctx, who, "a", "docs", snap); err != nil || to != "docs (restored 2026-10-24)" {
		t.Errorf("restore a folder = %q %v", to, err)
	}
	if _, err := c.Restore(ctx, who, "a", "docs/report.txt", "manual"); !errors.Is(err, ErrNotFound) {
		t.Errorf("restore from a manual snapshot = %v", err)
	}
	if _, err := c.Create(ctx, who, "a", ".zfs/snapshot/"+snap+"/x", false); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("write into .zfs = %v", err)
	}
	if !strings.Contains(snap, "daily") {
		t.Fatal()
	}
}

func TestClientWho(t *testing.T) {
	c := &Client{Lookup: func(_ context.Context, w Who) (auth.Identity, error) {
		switch w.Principal {
		case "kid":
			return &auth.User{Username: "kid", Role: auth.RoleUser}, nil
		case "cade":
			return &auth.User{Username: "cade", Role: auth.RoleAdmin}, nil
		}
		return nil, &Error{Kind: ErrNoAccess, Msg: "no"}
	}}
	ctx := context.Background()
	if _, err := c.who(ctx, Who{Principal: "kid", Local: true}); !errors.Is(err, ErrNoAccess) {
		t.Errorf("local family member = %v", err)
	}
	// The account's current role counts, not what the caller says.
	if w, err := c.who(ctx, Who{Principal: "cade", Local: true}); err != nil || !w.Admin || !w.Local {
		t.Errorf("admin = %+v %v", w, err)
	}
	if _, err := c.who(ctx, Who{Principal: "ghost", Admin: true}); !errors.Is(err, ErrNoAccess) {
		t.Errorf("unknown = %v", err)
	}
	if _, err := c.who(ctx, Who{}); !errors.Is(err, ErrNoAccess) {
		t.Errorf("nobody = %v", err)
	}
}
