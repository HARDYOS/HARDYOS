//go:build linux

package fileworker

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/shares"
)

// The test binary doubles as the worker, like hardyd-priv does.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == Subcommand {
		ChildMain()
	}
	os.Exit(m.Run())
}

var (
	exeOnce sync.Once
	exePath string
	exeErr  error
)

// workerExe is this test binary where any user can run it (go test keeps
// it in a folder only its owner can enter).
func workerExe(t *testing.T) string {
	t.Helper()
	exeOnce.Do(func() {
		if os.Geteuid() != 0 {
			exePath, exeErr = os.Executable()
			return
		}
		dir, err := os.MkdirTemp("", "hardyos-fileworker-")
		if err != nil {
			exeErr = err
			return
		}
		os.Chmod(dir, 0o755)
		src, err := os.Open(os.Args[0])
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

func devOf(p string) uint64 {
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil {
		return 0
	}
	return uint64(st.Dev)
}

type fakeShares []shares.Share

func (f fakeShares) List(context.Context) ([]shares.Share, error) { return f, nil }

type ids map[string]Identity

func (m ids) lookup(_ context.Context, name string) (*Identity, error) {
	id, ok := m[name]
	if !ok {
		return nil, errorf(CodeNoAccess, "unknown user %s", name)
	}
	return &id, nil
}

func chownTree(t *testing.T, root string, uid, gid int) {
	t.Helper()
	filepath.Walk(root, func(p string, _ os.FileInfo, err error) error {
		if err == nil {
			os.Lchown(p, uid, gid)
		}
		return nil
	})
}

func owner(t *testing.T, p string) int {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return int(fi.Sys().(*syscall.Stat_t).Uid)
}

func doJSON(t *testing.T, s *Server, op string, a Args, out any) (*os.File, error) {
	t.Helper()
	raw, f, err := s.Do(context.Background(), op, a)
	if err == nil && out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s: %v (%s)", op, err, raw)
		}
	}
	return f, err
}

// TestSpawn runs real workers: as the test's own user without root, as a
// made-up domain user with root.
func TestSpawn(t *testing.T) {
	d := tree(t)
	ro := t.TempDir()
	os.WriteFile(filepath.Join(ro, "r.txt"), []byte("read me"), 0o644)
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		uid, gid = 100001, 100513
		chownTree(t, d, uid, gid)
		os.Chown(filepath.Join(d, ".recycle"), 0, 0)
		os.Remove(filepath.Join(d, ".recycle")) // made by the parent below
		os.Chmod(filepath.Dir(d), 0o755)
	} else {
		os.Remove(filepath.Join(d, ".recycle"))
	}
	alice := `HOME\alice`
	s := &Server{
		Shares: fakeShares{
			{ID: "docs", Name: "Docs", Mounted: true, Path: d, RootDev: devOf(d), Recycle: true,
				Access: []shares.Rule{{Kind: shares.KindUser, Name: alice, Level: shares.LevelWrite}}},
			{ID: "ro", Name: "Read Only", Mounted: true, Path: ro, RootDev: devOf(ro),
				Access: []shares.Rule{{Kind: shares.KindEveryone, Level: shares.LevelRead}}},
			{ID: "nobody", Name: "Nobody", Mounted: true, Path: ro, RootDev: devOf(ro)},
			{ID: "gone", Name: "Gone", Mounted: false},
		},
		Exe: workerExe(t), Args: []string{Subcommand},
		LookupUser: ids{alice: {UID: uid, GID: gid, Groups: []int{gid}}}.lookup,
		AcceptID:   func(int) bool { return true },
	}
	who := Who{Principal: alice}

	var sh []ShareAccess
	if _, err := doJSON(t, s, OpShares, Args{Who: who}, &sh); err != nil {
		t.Fatal(err)
	}
	if len(sh) != 2 || sh[0].ID != "docs" || !sh[0].Writable || !sh[0].Recycle || sh[1].ID != "ro" || sh[1].Writable {
		t.Fatalf("shares = %+v", sh)
	}

	// The opened file comes back over the socket.
	var e Entry
	f, err := doJSON(t, s, OpOpen, Args{Who: who, Share: "docs", Path: "docs/a.txt"}, &e)
	if err != nil || f == nil {
		t.Fatalf("open = %v %v", f, err)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	if string(b) != "alpha" || e.Size != 5 {
		t.Fatalf("read %q %+v", b, e)
	}
	// A created file belongs to the person.
	f, err = doJSON(t, s, OpCreate, Args{Who: who, Share: "docs", Path: "made.txt"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("hello")
	f.Close()
	if got := owner(t, filepath.Join(d, "made.txt")); got != uid {
		t.Fatalf("created file owned by %d, want %d", got, uid)
	}
	// Delete goes to the recycle bin, which the parent makes sticky.
	var res map[string]any
	if _, err := doJSON(t, s, OpDelete, Args{Who: who, Share: "docs", Path: "made.txt"}, &res); err != nil {
		t.Fatal(err)
	}
	if res["recycled"] != true {
		t.Fatalf("delete = %v", res)
	}
	if fi, err := os.Stat(filepath.Join(d, ".recycle")); err != nil || fi.Mode()&os.ModeSticky == 0 || fi.Mode().Perm() != 0o777 {
		t.Fatalf(".recycle = %v %v", fi, err)
	}
	if b, _ := os.ReadFile(filepath.Join(d, ".recycle/home.alice/made.txt")); string(b) != "hello" {
		t.Fatal("not in alice's bin")
	}
	if _, err := doJSON(t, s, OpDelete, Args{Who: who, Share: "docs", Path: "top.txt", Permanent: true}, &res); err != nil || res["recycled"] != false {
		t.Fatalf("permanent delete = %v %v", res, err)
	}

	// The folders' rules.
	if _, err := doJSON(t, s, OpMkdir, Args{Who: who, Share: "ro", Path: "x"}, nil); code(err) != CodeNoAccess {
		t.Errorf("mkdir in a read-only folder = %v", err)
	}
	var l Listing
	if _, err := doJSON(t, s, OpList, Args{Who: who, Share: "ro"}, &l); err != nil || l.Folder.Writable || len(l.Entries) != 1 || l.Entries[0].Writable {
		t.Errorf("read-only listing = %+v %v", l, err)
	}
	if _, err := doJSON(t, s, OpList, Args{Who: who, Share: "nobody"}, nil); code(err) != CodeNoAccess {
		t.Errorf("no rules = %v", err)
	}
	if _, err := doJSON(t, s, OpList, Args{Who: who, Share: "gone"}, nil); code(err) != CodeNotFound {
		t.Errorf("unmounted = %v", err)
	}
	if _, err := doJSON(t, s, OpList, Args{Who: who, Share: "ghost"}, nil); code(err) != CodeNotFound {
		t.Errorf("missing = %v", err)
	}
	if _, err := doJSON(t, s, OpRename, Args{Who: who, Share: "docs", Path: "docs", ToShare: "ro", To: "docs"}, nil); code(err) != CodeNoAccess {
		t.Errorf("move into a read-only folder = %v", err)
	}
	if _, err := doJSON(t, s, OpList, Args{Who: who, Share: "docs", Path: "../.."}, nil); code(err) != CodeNotAllowed {
		t.Errorf("escape = %v", err)
	}

	// Who may use files at all.
	for _, w := range []Who{{Principal: "kid", Local: true}, {Principal: "alice"}, {Principal: `HOME\stranger`}} {
		if _, err := doJSON(t, s, OpList, Args{Who: w, Share: "docs"}, nil); err == nil {
			t.Errorf("%+v listed files", w)
		}
	}
	// Never as root.
	s.LookupUser = ids{`HOME\root`: {UID: 0, GID: 0}}.lookup
	if _, err := doJSON(t, s, OpList, Args{Who: Who{Principal: `HOME\root`, Admin: true}, Share: "docs"}, nil); code(err) != CodeNoAccess {
		t.Errorf("acting as root = %v", err)
	}
}

// TestPrivilegeDrop checks that a worker can do exactly what its user can
// (needs root to set up files owned by other users).
func TestPrivilegeDrop(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to make files owned by other users")
	}
	d := t.TempDir()
	os.Chmod(filepath.Dir(d), 0o755)
	os.Chmod(d, 0o755)
	const alice, bob, carol, family = 100001, 100002, 100003, 100500
	mk := func(p string, mode os.FileMode, uid, gid int, dir bool) {
		t.Helper()
		full := filepath.Join(d, p)
		if dir {
			if err := os.Mkdir(full, mode); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(full, []byte(p), mode); err != nil {
			t.Fatal(err)
		}
		os.Chown(full, uid, gid)
		os.Chmod(full, mode)
	}
	mk("alice", 0o755, alice, alice, true)
	mk("alice/secret.txt", 0o600, alice, alice, false)
	mk("alice/open.txt", 0o644, alice, alice, false)
	mk("family", 0o750, alice, family, true)
	mk("family/plan.txt", 0o640, alice, family, false)
	mk("drop", 0o777, 0, 0, true)
	os.Chown(d, 0, 0)

	s := &Server{
		Shares: fakeShares{{ID: "s", Name: "S", Mounted: true, Path: d, RootDev: devOf(d),
			Access: []shares.Rule{{Kind: shares.KindEveryone, Level: shares.LevelWrite}}}},
		Exe: workerExe(t), Args: []string{Subcommand},
		LookupUser: ids{
			`HOME\alice`: {UID: alice, GID: 100513},
			`HOME\bob`:   {UID: bob, GID: 100513},
			`HOME\carol`: {UID: carol, GID: 100513, Groups: []int{100513, family, 0, 4}},
		}.lookup,
	}
	as := func(name string) Who { return Who{Principal: `HOME\` + name} }
	open := func(w Who, p string) string {
		f, err := doJSON(t, s, OpOpen, Args{Who: w, Share: "s", Path: p}, nil)
		if err != nil {
			return code(err)
		}
		b, _ := io.ReadAll(f)
		f.Close()
		return string(b)
	}
	cases := []struct {
		who  string
		path string
		want string
	}{
		{"alice", "alice/secret.txt", "alice/secret.txt"},
		{"bob", "alice/secret.txt", CodeNoAccess},
		{"bob", "alice/open.txt", "alice/open.txt"},
		{"bob", "family/plan.txt", CodeNoAccess},
		{"carol", "family/plan.txt", "family/plan.txt"}, // through her group
	}
	for _, c := range cases {
		if got := open(as(c.who), c.path); got != c.want {
			t.Errorf("%s opening %s = %q, want %q", c.who, c.path, got, c.want)
		}
	}
	// Writing: bob can't change or delete alice's files or make files in her folder.
	if _, err := doJSON(t, s, OpCreate, Args{Who: as("bob"), Share: "s", Path: "alice/bob.txt"}, nil); code(err) != CodeNoAccess {
		t.Errorf("bob created in alice's folder: %v", err)
	}
	if _, err := doJSON(t, s, OpOpenWrite, Args{Who: as("bob"), Share: "s", Path: "alice/open.txt"}, nil); code(err) != CodeNoAccess {
		t.Errorf("bob opened alice's file for writing: %v", err)
	}
	if _, err := doJSON(t, s, OpDelete, Args{Who: as("bob"), Share: "s", Path: "alice/open.txt", Permanent: true}, nil); code(err) != CodeNoAccess {
		t.Errorf("bob deleted alice's file: %v", err)
	}
	var l Listing
	if _, err := doJSON(t, s, OpList, Args{Who: as("bob"), Share: "s", Path: "alice"}, &l); err != nil || l.Folder.Writable || l.Entries[0].Writable {
		t.Errorf("bob's view of alice's folder = %+v %v", l, err)
	}
	// carol's root and disk groups (0, 4) were dropped: she's no more than
	// her domain groups.
	f, err := doJSON(t, s, OpCreate, Args{Who: as("carol"), Share: "s", Path: "drop/c.txt"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	fi, _ := os.Stat(filepath.Join(d, "drop/c.txt"))
	if st := fi.Sys().(*syscall.Stat_t); st.Uid != carol || st.Gid != 100513 {
		t.Fatalf("carol's file is %d:%d", st.Uid, st.Gid)
	}
	// Administrators act as hardyos-files, never root.
	f, err = doJSON(t, s, OpCreate, Args{Who: Who{Principal: "cade", Local: true, Admin: true}, Share: "s", Path: "drop/admin.txt"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if got := owner(t, filepath.Join(d, "drop/admin.txt")); got != FilesUID {
		t.Fatalf("admin's file owned by %d", got)
	}
	if got := open(Who{Principal: "cade", Local: true, Admin: true}, "alice/secret.txt"); got != CodeNoAccess {
		t.Errorf("hardyos-files read a private file: %q", got)
	}
	// Outside the domain's ID ranges nobody is acted as.
	s.AcceptID = nil
	s.ids = nil
	s.LookupUser = ids{`HOME\sys`: {UID: 998, GID: 998}}.lookup
	if got := open(as("sys"), "alice/open.txt"); got != CodeNoAccess {
		t.Errorf("a system account was acted as: %q", got)
	}
}
