//go:build linux

package shares

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func namedPerm(a acl, group bool, id uint32) (uint16, bool) {
	tag := uint16(tagUser)
	if group {
		tag = tagGroup
	}
	for _, e := range a {
		if e.Tag == tag && e.ID == id {
			return e.Perm, true
		}
	}
	return 0, false
}

func TestPeopleACL(t *testing.T) {
	root := t.TempDir()
	probe := filepath.Join(root, "probe")
	if err := os.WriteFile(probe, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(probe, xattrAccess, aclFromMode(0o644).withUser(30001, 4).encode(), 0); err != nil {
		t.Skipf("no POSIX ACLs here: %v", err)
	}
	share := filepath.Join(root, "share")
	outside := filepath.Join(root, "outside")
	for _, d := range []string{share + "/Photos", outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(share, "Photos", "a.jpg")
	_ = os.WriteFile(file, []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o600)
	_ = os.Symlink(outside, filepath.Join(share, "escape"))
	// An app's grant and an old person's entry are already there.
	if err := unix.Setxattr(file, xattrAccess, aclFromMode(0o644).withUser(30001, 4).withUser(100900, 6).encode(), 0); err != nil {
		t.Fatal(err)
	}
	managed := func(group bool, id uint32) bool { return id >= 100000 && id <= 999999 }
	p := PeopleACL{
		Entries: []PersonEntry{{Group: true, ID: 100513, Level: LevelRead}, {ID: 101103, Level: LevelWrite}, {ID: 101104, Level: LevelNone}},
		Managed: managed,
	}
	if ok, _ := PeopleRootMatches(share, p); ok {
		t.Fatal("matches before anything was set")
	}
	if _, err := SetPeopleRoot(share, p); err != nil {
		t.Fatal(err)
	}
	if ok, err := PeopleRootMatches(share, p); err != nil || !ok {
		t.Fatalf("root doesn't match after setting it: %v", err)
	}
	if changed, _ := SetPeopleRoot(share, p); changed {
		t.Error("setting again changed something")
	}
	ra := pathACL(t, share, xattrAccess)
	if i := ra.find(tagOther); i < 0 || ra[i].Perm != 0 {
		t.Errorf("root's other: %+v", ra)
	}
	if perm, ok := namedPerm(pathACL(t, share, xattrDefault), true, 100513); !ok || perm != 5 {
		t.Errorf("root default group entry %v %v", perm, ok)
	}
	st, err := ApplyPeopleTree(context.Background(), share, p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Seen != 2 || st.Skipped != 1 {
		t.Errorf("stats %+v", st)
	}
	fa := pathACL(t, file, xattrAccess)
	if perm, ok := namedPerm(fa, false, 101103); !ok || perm != 6 {
		t.Errorf("file write entry %v %v (%+v)", perm, ok, fa)
	}
	if perm, ok := namedPerm(fa, false, 101104); !ok || perm != 0 {
		t.Errorf("file none entry %v %v", perm, ok)
	}
	if perm, ok := namedPerm(fa, false, 30001); !ok || perm != 4 {
		t.Error("the app's entry was touched")
	}
	if _, ok := namedPerm(fa, false, 100900); ok {
		t.Error("an old person's entry stayed")
	}
	if perm, _ := namedPerm(pathACL(t, filepath.Join(share, "Photos"), xattrDefault), false, 101103); perm != 7 {
		t.Errorf("folder default entry %v", perm)
	}
	if a := pathACL(t, filepath.Join(outside, "secret"), xattrAccess); a != nil {
		t.Error("followed the link out of the share")
	}
	// Taking everyone away removes the entries again.
	if _, err := ApplyPeopleTree(context.Background(), share, PeopleACL{Managed: managed}); err != nil {
		t.Fatal(err)
	}
	fa = pathACL(t, file, xattrAccess)
	if _, ok := namedPerm(fa, false, 101103); ok {
		t.Error("entry kept after removal")
	}
	if _, ok := namedPerm(fa, false, 30001); !ok {
		t.Error("the app's entry went with them")
	}
}
