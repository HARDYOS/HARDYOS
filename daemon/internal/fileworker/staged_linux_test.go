//go:build linux

package fileworker

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/shares"
)

// TestDoInStaged reads a staged copy (a cloud backup restore) as the
// person: the permissions in the copy decide, writes are refused, and the
// folder's rules come from RulesLevel.
func TestDoInStaged(t *testing.T) {
	staged := t.TempDir()
	if err := os.WriteFile(filepath.Join(staged, "open.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staged, "private.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(staged, "link")); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		// The person is a made-up domain user; private.txt is someone else's.
		uid, gid = 100001, 100513
		os.Chmod(staged, 0o755)
		os.Chmod(filepath.Dir(staged), 0o755)
		os.Chown(filepath.Join(staged, "open.txt"), 100002, 100513)
		os.Chown(filepath.Join(staged, "private.txt"), 100002, 100513)
	}
	alice := `HOME\alice`
	share := t.TempDir()
	s := &Server{
		Shares: fakeShares{{ID: "fam", Name: "Family", Mounted: true, Path: share, RootDev: devOf(share),
			Access: []shares.Rule{{Kind: shares.KindUser, Name: alice, Level: shares.LevelRead}}}},
		Exe: workerExe(t), Args: []string{Subcommand},
		LookupUser: ids{alice: {UID: uid, GID: gid, Groups: []int{gid}}}.lookup,
		AcceptID:   func(int) bool { return true },
	}
	who := Who{Principal: alice}
	ctx := context.Background()
	in := Root{Name: "Family (backup)", Path: staged, Dev: devOf(staged)}

	_, f, err := s.DoIn(ctx, OpOpen, who, in, Args{Path: "open.txt"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	if string(b) != "hello" {
		t.Fatalf("read %q", b)
	}
	if os.Getuid() == 0 {
		if _, _, err := s.DoIn(ctx, OpOpen, who, in, Args{Path: "private.txt"}); code(err) != CodeNoAccess {
			t.Errorf("opened a file the person couldn't read: %v", err)
		}
	}
	if _, _, err := s.DoIn(ctx, OpOpen, who, in, Args{Path: "link"}); err == nil {
		t.Error("followed a link in the staged copy")
	}
	if _, _, err := s.DoIn(ctx, OpCreate, who, in, Args{Path: "new.txt"}); code(err) != CodeBadArgs {
		t.Errorf("wrote into the staged copy: %v", err)
	}
	if _, _, err := s.DoIn(ctx, OpList, who, in, Args{Path: "../.."}); code(err) != CodeNotAllowed {
		t.Errorf("escaped the staged copy: %v", err)
	}
	if _, _, err := s.DoIn(ctx, OpList, who, Root{Name: "x", Path: staged, Dev: 1}, Args{}); err == nil {
		t.Error("a root on another device was used")
	}
	if lv, err := s.RulesLevel(ctx, who, "fam"); err != nil || lv != shares.LevelRead {
		t.Errorf("rules level = %q %v", lv, err)
	}
	if lv, _ := s.RulesLevel(ctx, Who{Principal: `HOME\bob`}, "fam"); lv != shares.LevelNone {
		t.Errorf("bob's level = %q", lv)
	}
}
