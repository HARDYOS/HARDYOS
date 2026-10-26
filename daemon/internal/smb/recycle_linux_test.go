//go:build linux

package smb

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"golang.org/x/sys/unix"
)

// A folder swapped into the bin between the cleaner's look and its open
// (a fresh one, with fresh files) is left alone.
func TestCleanRecycleInodeSwap(t *testing.T) {
	share := t.TempDir()
	rec := filepath.Join(share, ".recycle")
	old := filepath.Join(rec, "home.alice", "Docs")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(old, "a.txt"), []byte("x"), 0o644)
	sfd, err := unix.Open(rec, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	unix.Fstat(sfd, &st)
	swapped := false
	c := &recycleCleaner{dev: st.Dev, cutoff: time.Now().Add(time.Hour).Unix(),
		beforeOpen: func(dirfd int, name string) {
			if name != "home.alice" || swapped {
				return
			}
			swapped = true
			// What the cleaner looked at goes, a new folder takes its name.
			if err := os.Rename(filepath.Join(rec, name), filepath.Join(share, "moved")); err != nil {
				t.Fatal(err)
			}
			os.MkdirAll(filepath.Join(rec, name, "New"), 0o755)
			os.WriteFile(filepath.Join(rec, name, "New", "fresh.txt"), []byte("x"), 0o644)
		}}
	c.dir(sfd, 0)
	if !swapped {
		t.Fatal("no swap")
	}
	if _, err := os.Stat(filepath.Join(rec, "home.alice", "New", "fresh.txt")); err != nil {
		t.Errorf("the swapped-in folder was cleaned: %v", err)
	}
	if c.removed != 0 {
		t.Errorf("removed %d", c.removed)
	}
}

func TestCleanRecycleNeedsTheVerifiedMount(t *testing.T) {
	share := t.TempDir()
	os.MkdirAll(filepath.Join(share, ".recycle", "x"), 0o755)
	if _, err := cleanRecycleDir(share, devOf(share)+1, time.Now().Add(time.Hour)); !errors.Is(err, shares.ErrUnverified) {
		t.Errorf("wrong device = %v", err)
	}
	if _, err := cleanRecycleDir(share, 0, time.Now().Add(time.Hour)); !errors.Is(err, shares.ErrUnverified) {
		t.Errorf("unverified = %v", err)
	}
	if _, err := os.Stat(filepath.Join(share, ".recycle", "x")); err != nil {
		t.Error("cleaned anyway")
	}
}

type idNames map[string]uint32

func (n idNames) get(k string) (uint32, error) {
	if id, ok := n[strings.ToLower(k)]; ok {
		return id, nil
	}
	return 0, &ErrUnknownName{Name: k}
}
func (n idNames) UserID(s string) (uint32, error)       { return n.get(s) }
func (n idNames) GroupID(s string) (uint32, error)      { return n.get(s) }
func (n idNames) GroupIDBySID(s string) (uint32, error) { return n.get(s) }

func TestRangeCheckedNames(t *testing.T) {
	r := rangeChecked{idNames{`home\alice`: 101104, `home\root`: 0, `home\local`: 1000, `home\app`: 30001, `home\tdb`: 3001}}
	if id, err := r.UserID(`HOME\alice`); err != nil || id != 101104 {
		t.Errorf("alice = %d %v", id, err)
	}
	if id, err := r.GroupID(`HOME\tdb`); err != nil || id != 3001 {
		t.Errorf("tdb = %d %v", id, err)
	}
	for _, n := range []string{`HOME\root`, `HOME\local`, `HOME\app`} {
		_, err := r.UserID(n)
		var oor *ErrOutOfRange
		if !errors.As(err, &oor) || !unknownName(err) {
			t.Errorf("%s = %v", n, err)
		}
	}
	// A rule for a name the name service maps outside the domain's ranges
	// is skipped: no ACL entry for root or a local account.
	rules := []shares.Rule{{Kind: shares.KindUser, Name: `HOME\root`, Level: shares.LevelWrite}, {Kind: shares.KindUser, Name: `HOME\alice`, Level: shares.LevelRead}}
	p, skipped, err := shareACL("HOME", rules, false, "", rangeChecked{idNames{`home\domain admins`: 100512, `home\root`: 0, `home\alice`: 101104}})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range p.Entries {
		if !DomainID(e.ID) {
			t.Errorf("entry for %d", e.ID)
		}
	}
	if len(skipped) != 1 || skipped[0] != `HOME\root` || len(p.Entries) != 2 {
		t.Errorf("entries %+v skipped %v", p.Entries, skipped)
	}
	// Domain Admins itself out of range: nothing is changed.
	if _, _, err := shareACL("HOME", nil, false, "", rangeChecked{idNames{`home\domain admins`: 0}}); err == nil {
		t.Error("an out-of-range Domain Admins was used")
	}
}

// Bins someone else made are moved aside; one's own open bin is closed up.
func TestCheckBins(t *testing.T) {
	share := t.TempDir()
	m := newTestManager(t, okFake(), nil)
	me := uint32(os.Geteuid())
	rec := filepath.Join(share, ".recycle")
	os.MkdirAll(filepath.Join(rec, "home.alice"), 0o777)
	os.Chmod(filepath.Join(rec, "home.alice"), 0o777)
	os.MkdirAll(filepath.Join(rec, "home.bob"), 0o700)
	os.WriteFile(filepath.Join(rec, "home.carol"), nil, 0o644) // a file blocking carol's bin
	os.Symlink("/etc", filepath.Join(rec, "hardyos-files"))
	os.MkdirAll(filepath.Join(rec, "home.gone"), 0o777)
	os.MkdirAll(filepath.Join(rec, "legacy"), 0o777)
	names := idNames{`home\alice`: me, `home\bob`: me + 1, `home\carol`: me}
	rootfd, err := unix.Open(share, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootfd)
	m.checkBins(rootfd, "HOME", names, "s")

	if fi, err := os.Lstat(filepath.Join(rec, "home.alice")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("alice's own bin = %v %v", fi, err)
	}
	for _, n := range []string{"home.bob", "home.carol", "hardyos-files"} {
		if _, err := os.Lstat(filepath.Join(rec, n)); err == nil {
			t.Errorf("%s wasn't moved aside", n)
		}
	}
	for _, n := range []string{"home.gone", "legacy"} {
		if _, err := os.Lstat(filepath.Join(rec, n)); err != nil {
			t.Errorf("%s was touched: %v", n, err)
		}
	}
	ents, _ := os.ReadDir(rec)
	q := 0
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), quarantinePrefix) {
			q++
			if e.IsDir() {
				fi, _ := os.Lstat(filepath.Join(rec, e.Name()))
				if fi.Mode().Perm() != 0o700 {
					t.Errorf("quarantined %s is %v", e.Name(), fi.Mode())
				}
			}
		}
	}
	if q != 3 {
		t.Errorf("%d moved aside, want 3", q)
	}
	if fi, _ := os.Stat("/etc"); fi == nil || !fi.IsDir() {
		t.Error("followed the link")
	}
}

func TestEnsureRecycleInApply(t *testing.T) {
	share := t.TempDir()
	m := newTestManager(t, okFake(), nil)
	sh := shares.Share{ID: "s", Path: share, Mounted: true, RootDev: devOf(share), Recycle: true}
	os.Mkdir(filepath.Join(share, ".recycle"), 0o755)
	m.ensureRecycle(&home, sh, idNames{})
	fi, err := os.Lstat(filepath.Join(share, ".recycle"))
	if err != nil || fi.Mode().Perm() != 0o777 || fi.Mode()&os.ModeSticky == 0 {
		t.Errorf(".recycle = %v %v", fi, err)
	}
	// Not verified: nothing is done.
	other := t.TempDir()
	m.ensureRecycle(&home, shares.Share{ID: "x", Path: other, Mounted: true, Recycle: true}, idNames{})
	if _, err := os.Lstat(filepath.Join(other, ".recycle")); err == nil {
		t.Error("made a recycle bin in an unverified folder")
	}
}
