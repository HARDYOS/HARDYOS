//go:build linux

package fileworker

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"golang.org/x/sys/unix"
)

func TestOpPathUploads(t *testing.T) {
	tmp := "docs/.hardyos-upload-0123456789abcdef01234567"
	for _, c := range []struct {
		op        string
		permanent bool
		ok        bool
	}{
		{OpCreate, false, true}, {OpOpenWrite, false, true}, {OpRename, false, true},
		{OpDelete, true, true}, {OpDelete, false, false},
		{OpList, false, false}, {OpStat, false, false}, {OpOpen, false, false}, {OpMkdir, false, false},
		{OpSetTime, false, false}, {OpVersions, false, false},
	} {
		_, err := OpPath(c.op, tmp, c.permanent)
		if (err == nil) != c.ok {
			t.Errorf("OpPath(%s, permanent=%v) = %v", c.op, c.permanent, err)
		}
	}
	if _, err := RenameTarget(tmp); err == nil {
		t.Error("an upload's name accepted as a rename's destination")
	}
	if err := CleanName(".hardyos-upload-0123456789abcdef01234567"); err == nil {
		t.Error("an upload's name accepted as a new name")
	}
	if _, err := OpPath(OpCreate, ".hardyos-upload-0123456789abcdef01234567/x", false); err == nil {
		t.Error("an upload's name accepted as a folder")
	}
	// The worker applies the same rules.
	d := tree(t)
	roots := []int{openRoot(t, d)}
	os.WriteFile(filepath.Join(d, ".hardyos-upload-0123456789abcdef01234567"), []byte("x"), 0o644)
	if _, err := inproc(t, roots, Request{Op: OpRename, Path: "top.txt", To: ".hardyos-upload-0123456789abcdef01234567", Overwrite: true}, nil); code(err) != CodeNotAllowed {
		t.Errorf("rename onto an upload = %v", err)
	}
	if _, err := inproc(t, roots, Request{Op: OpDelete, Path: ".hardyos-upload-0123456789abcdef01234567", Recycle: true, Bin: "home.alice"}, nil); code(err) != CodeNotAllowed {
		t.Errorf("recycling an upload = %v", err)
	}
	if _, err := inproc(t, roots, Request{Op: OpDelete, Path: ".hardyos-upload-0123456789abcdef01234567"}, nil); err != nil {
		t.Errorf("cancelling an upload = %v", err)
	}
}

// Someone else's folder with the person's bin name is refused; the
// person's own bin, if open to others, is closed up first.
func TestWorkerBinChecks(t *testing.T) {
	d := tree(t)
	roots := []int{openRoot(t, d)}
	bin := filepath.Join(d, ".recycle", "home.alice")
	os.Mkdir(bin, 0o777)
	os.Chmod(bin, 0o777)
	os.WriteFile(filepath.Join(d, "x.txt"), []byte("x"), 0o644)
	if _, err := inproc(t, roots, Request{Op: OpDelete, Path: "x.txt", Recycle: true, Bin: "home.alice"}, nil); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(bin); fi.Mode().Perm() != 0o700 {
		t.Errorf("own bin left %v", fi.Mode())
	}
	// Names that aren't a bin's.
	for _, b := range []string{"alice", "", "..", "home.", ".alice", "a/b", "HOME.alice"} {
		os.WriteFile(filepath.Join(d, "y.txt"), []byte("y"), 0o644)
		if _, err := inproc(t, roots, Request{Op: OpDelete, Path: "y.txt", Recycle: true, Bin: b}, nil); err == nil {
			t.Errorf("bin %q accepted", b)
		}
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to make a bin owned by someone else")
	}
	os.Chown(bin, 100777, 100777)
	os.Chmod(bin, 0o777)
	os.WriteFile(filepath.Join(d, "z.txt"), []byte("z"), 0o644)
	_, err := inproc(t, roots, Request{Op: OpDelete, Path: "z.txt", Recycle: true, Bin: "home.alice"}, nil)
	if code(err) != CodeNotAllowed || !strings.Contains(err.Error(), "home.alice") {
		t.Errorf("someone else's bin = %v", err)
	}
	if _, err := os.Stat(filepath.Join(d, "z.txt")); err != nil {
		t.Error("the file went into someone else's bin")
	}
	if fi, _ := os.Stat(bin); fi.Mode().Perm() != 0o777 {
		t.Errorf("someone else's bin was changed: %v", fi.Mode())
	}
}

// The parent only passes on a regular file opened for what the operation
// is for, on the folder's own file system.
func TestCheckHanded(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "f")
	os.WriteFile(p, []byte("x"), 0o644)
	dev := devOf(d)
	open := func(flags int) *os.File {
		fd, err := unix.Open(p, flags|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		f := os.NewFile(uintptr(fd), p)
		t.Cleanup(func() { f.Close() })
		return f
	}
	dir, _ := os.Open(d)
	defer dir.Close()
	for _, c := range []struct {
		f    *os.File
		op   string
		snap bool
		dev  uint64
		ok   bool
	}{
		{open(unix.O_RDONLY), OpOpen, false, dev, true},
		{open(unix.O_WRONLY), OpCreate, false, dev, true},
		{open(unix.O_WRONLY), OpOpenWrite, false, dev, true},
		{open(unix.O_RDONLY), OpOpen, true, dev + 1, true}, // older versions are on the snapshot's device
		{open(unix.O_RDWR), OpOpen, false, dev, false},
		{open(unix.O_WRONLY), OpOpen, false, dev, false},
		{open(unix.O_RDONLY), OpCreate, false, dev, false},
		{open(unix.O_RDWR), OpOpenWrite, false, dev, false},
		{open(unix.O_PATH), OpOpen, false, dev, false},
		{open(unix.O_RDONLY), OpOpen, false, dev + 1, false},
		{dir, OpOpen, false, dev, false},
	} {
		if err := checkHanded(c.f, c.op, c.dev, c.snap); (err == nil) != c.ok {
			t.Errorf("checkHanded(%s, snapshot=%v, dev ok=%v) = %v", c.op, c.snap, c.dev == dev, err)
		}
	}
}

func TestWorkerLimits(t *testing.T) {
	s := &Server{MaxWorkers: 2, MaxWorkersPerPerson: 1}
	ctx := context.Background()
	a, err := s.acquire(ctx, `HOME\alice`)
	if err != nil {
		t.Fatal(err)
	}
	// alice's one slot is taken: her next request waits until it's cancelled.
	short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := s.acquire(short, `home\ALICE`); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Errorf("alice's second = %v", err)
	}
	b, err := s.acquire(ctx, `HOME\bob`)
	if err != nil {
		t.Fatal(err)
	}
	// Both of the server's slots are taken.
	short2, cancel2 := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel2()
	if _, err := s.acquire(short2, `HOME\carol`); err == nil {
		t.Error("a third worker started")
	}
	done := make(chan error, 1)
	go func() {
		r, err := s.acquire(ctx, `HOME\carol`)
		if err == nil {
			r()
		}
		done <- err
	}()
	a()
	if err := <-done; err != nil {
		t.Errorf("carol after alice finished = %v", err)
	}
	b()
	s.limMu.Lock()
	left := len(s.per)
	s.limMu.Unlock()
	if left != 0 {
		t.Errorf("%d people still counted", left)
	}
}

func TestHomeLookup(t *testing.T) {
	home := t.TempDir()
	dev := devOf(home)
	f := &sysexec.Fake{}
	get := "zfs get -Hp -o property,value org.hardyos:home,mountpoint,mounted "
	f.On(get+"tank/homes/home.alice", "org.hardyos:home\tHOME\\alice\nmountpoint\t"+home+"\nmounted\tyes\n")
	// bob's dataset says it's alice's.
	f.On(get+"tank/homes/home.bob", "org.hardyos:home\tHOME\\alice\nmountpoint\t"+home+"\nmounted\tyes\n")
	// carol's mountpoint holds a line break.
	f.On(get+"tank/homes/home.carol", "org.hardyos:home\tHOME\\carol\nmountpoint\t/x\nmounted\tyes\n/etc\n")
	// dave's isn't mounted where it says.
	f.On(get+"tank/homes/home.dave", "org.hardyos:home\tHOME\\dave\nmountpoint\t/etc\nmounted\tyes\n")
	pool := "tank"
	s := &Server{Runner: f, HomesPool: func() string { return pool },
		Mounts: func() (shares.MountVerifier, error) {
			return shares.MountFunc(func(p, ds string) (uint64, error) {
				if p == home && ds == "tank/homes/home.alice" {
					return dev, nil
				}
				return 0, os.ErrNotExist
			}), nil
		}}
	r, err := s.home(context.Background(), `HOME\alice`)
	if err != nil || r.path != home || r.dev != dev {
		t.Fatalf("alice's home = %+v %v", r, err)
	}
	for _, who := range []string{`HOME\bob`, `HOME\carol`, `HOME\dave`, `HOME\erin`, `alice`} {
		if r, err := s.home(context.Background(), who); err == nil {
			t.Errorf("%s's home = %+v", who, r)
		}
	}
	// Only on the configured pool.
	pool = "vault"
	s.homes = nil
	if _, err := s.home(context.Background(), `HOME\alice`); err == nil {
		t.Error("home found on another pool")
	}
	pool = ""
	s.homes = nil
	n := len(f.Lines())
	if _, err := s.home(context.Background(), `HOME\alice`); err == nil {
		t.Error("home found with home folders off")
	}
	if len(f.Lines()) != n {
		t.Errorf("looked for homes with home folders off: %v", f.Lines()[n:])
	}
}

// A folder whose mount wasn't verified is never given to a worker, and
// every operation is logged with who asked and as whom it ran.
func TestUnverifiedAndAudit(t *testing.T) {
	d := tree(t)
	var logs bytes.Buffer
	uid, gid := os.Getuid(), os.Getgid()
	s := &Server{
		Shares: fakeShares{
			{ID: "docs", Name: "Docs", Mounted: true, Path: d, Access: []shares.Rule{{Kind: shares.KindEveryone, Level: shares.LevelRead}}},
			{ID: "ok", Name: "OK", Mounted: true, Path: d, RootDev: devOf(d), Access: []shares.Rule{{Kind: shares.KindEveryone, Level: shares.LevelRead}}},
			{ID: "wrongdev", Name: "Wrong", Mounted: true, Path: d, RootDev: devOf(d) + 1, Access: []shares.Rule{{Kind: shares.KindEveryone, Level: shares.LevelRead}}},
		},
		Exe: workerExe(t), Args: []string{Subcommand},
		LookupUser: ids{`HOME\alice`: {UID: uid, GID: gid}}.lookup,
		AcceptID:   func(int) bool { return true },
		Log:        slog.New(slog.NewJSONHandler(&logs, nil)),
	}
	if uid == 0 {
		s.LookupUser = ids{`HOME\alice`: {UID: 100001, GID: 100513}}.lookup
		chownTree(t, d, 100001, 100513)
		os.Chmod(filepath.Dir(d), 0o755)
	}
	who := Who{Principal: `HOME\alice`, Groups: []string{`HOME\Family`}}
	if _, err := doJSON(t, s, OpList, Args{Who: who, Share: "docs"}, nil); code(err) != CodeNotFound {
		t.Errorf("unverified folder = %v", err)
	}
	if _, err := doJSON(t, s, OpList, Args{Who: who, Share: "wrongdev"}, nil); code(err) != CodeNotFound {
		t.Errorf("folder on another device = %v", err)
	}
	var sh []ShareAccess
	if _, err := doJSON(t, s, OpShares, Args{Who: who}, &sh); err != nil || len(sh) != 1 || sh[0].ID != "ok" {
		t.Errorf("shares = %+v %v", sh, err)
	}
	if _, err := doJSON(t, s, OpList, Args{Who: Who{Principal: "kid", Local: true}, Share: "ok"}, nil); err == nil {
		t.Error("a local non-admin listed files")
	}
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && (m["msg"] == "file operation" || m["msg"] == "file operation refused") {
			lines = append(lines, m)
		}
	}
	if len(lines) != 4 {
		t.Fatalf("logged %d operations:\n%s", len(lines), logs.String())
	}
	want := float64(uid)
	if uid == 0 {
		want = 100001
	}
	for _, m := range lines[:3] {
		if m["principal"] != `HOME\alice` || m["uid"] != want || m["local"] != false || m["admin"] != false || m["op"] == nil {
			t.Errorf("log = %v", m)
		}
	}
	if lines[0]["ok"] != false || lines[0]["code"] != CodeNotFound || lines[2]["ok"] != true {
		t.Errorf("outcomes = %v / %v", lines[0], lines[2])
	}
	if m := lines[3]; m["msg"] != "file operation refused" || m["principal"] != "kid" || m["local"] != true {
		t.Errorf("refusal log = %v", m)
	}
}
