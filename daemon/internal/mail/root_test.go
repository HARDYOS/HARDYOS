package mail

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// testRoot is a Root on a temporary mail dataset (no ZFS, no system
// folders, no services).
func testRoot(t *testing.T) (*Root, Env) {
	t.Helper()
	dir := t.TempDir()
	e := Env{MailRoot: dir, VMailUID: os.Getuid(), VMailGID: os.Getgid()}
	for _, d := range []string{e.VMailDir(), filepath.Join(e.RadicaleDir(), "collections", "collection-root")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	r := &Root{
		Dataset:    func(context.Context, string) (string, error) { return dir, nil },
		LookupUser: func(string) (int, int, error) { return os.Getuid(), os.Getgid(), nil },
		LookupGrp:  func(string) (int, error) { return os.Getgid(), nil },
		Chown:      func(string, int, int) error { return nil },
		StateFile:  filepath.Join(dir, "state.json"),
		Runner:     &sysexec.Fake{},
	}
	return r, e
}

func mkfile(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

// Decision 306: a mailbox's mail and calendars are found by its key, and
// deleting it removes both, only once it's off the server.
func TestDeleteMailboxByKeyWithCalendars(t *testing.T) {
	r, e := testRoot(t)
	ctx := context.Background()
	mail := filepath.Join(e.VMailDir(), keyAlice, "Maildir", "cur", "1")
	cal := filepath.Join(e.RadicaleDir(), "collections", "collection-root", keyAlice, "calendar", "event.ics")
	bobs := filepath.Join(e.VMailDir(), keyBob, "Maildir", "cur", "1")
	for _, p := range []string{mail, cal, bobs} {
		mkfile(t, p)
	}
	// Still configured: refused.
	b, _ := json.Marshal(ApplyArgs{Config: RootConfig{Mailboxes: []RootMailbox{{Key: keyAlice, Address: "alice2@example.net"}}}})
	if err := os.WriteFile(r.StateFile, b, 0o600); err != nil {
		t.Fatal(err)
	}
	args := DeleteArgs{Pool: "tank", Key: keyAlice, Address: "alice@example.net", Confirm: "alice@example.net"}
	if err := r.DeleteMailbox(ctx, args); err == nil || !exists(mail) {
		t.Fatal("deleted a mailbox still on the server (by key)")
	}
	b, _ = json.Marshal(ApplyArgs{Config: RootConfig{Mailboxes: []RootMailbox{{Key: keyBob, Address: "bob@example.net"}}}})
	_ = os.WriteFile(r.StateFile, b, 0o600)
	if err := r.DeleteMailbox(ctx, DeleteArgs{Pool: "tank", Key: "not-a-key", Address: "alice@example.net", Confirm: "alice@example.net"}); err == nil {
		t.Fatal("a bad key was accepted")
	}
	if err := r.DeleteMailbox(ctx, args); err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Dir(filepath.Dir(filepath.Dir(mail)))) || exists(filepath.Dir(filepath.Dir(cal))) {
		t.Fatal("mail or calendars left behind")
	}
	if !exists(bobs) {
		t.Fatal("another mailbox's mail went too")
	}
}

// Decision 318: only a mailbox flagged as made under the old layout takes
// its address's folder, once; every other old folder is put aside for the
// administrator, never into a mailbox.
func TestMigrateLayoutToKeys(t *testing.T) {
	r, e := testRoot(t)
	r.Write = func(p string, b []byte, m os.FileMode) error { return os.WriteFile(p, b, m) }
	old := filepath.Join(e.VMailDir(), "example.net", "alice", "Maildir", "cur", "1")
	oldCal := filepath.Join(e.RadicaleDir(), "collections", "collection-root", "alice@example.net", "calendar", "e.ics")
	// A deleted person's leftovers under an address someone new has now.
	gone := filepath.Join(e.VMailDir(), "example.net", "bob", "Maildir", "cur", "1")
	goneCal := filepath.Join(e.RadicaleDir(), "collections", "collection-root", "bob@example.net", "calendar", "e.ics")
	family := filepath.Join(e.RadicaleDir(), "collections", "collection-root", "family", "calendar", "e.ics")
	for _, p := range []string{old, oldCal, gone, goneCal, family} {
		mkfile(t, p)
	}
	cfg := RootConfig{Mailboxes: []RootMailbox{
		{Key: keyAlice, Address: "alice@example.net", Legacy: true},
		{Key: keyBob, Address: "bob@example.net"}, // new owner of bob@
	}}
	if err := r.migrateLayout(e, cfg); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(e.VMailDir(), keyAlice, "Maildir", "cur", "1")) || exists(old) {
		t.Fatal("mail not moved to its key")
	}
	if !exists(filepath.Join(e.RadicaleDir(), "collections", "collection-root", keyAlice, "calendar", "e.ics")) {
		t.Fatal("calendars not moved to the key")
	}
	if exists(filepath.Join(e.VMailDir(), keyBob)) || exists(filepath.Join(e.RadicaleDir(), "collections", "collection-root", keyBob)) {
		t.Fatal("the new owner of an address got the old one's mail")
	}
	if exists(gone) || exists(goneCal) || !exists(family) {
		t.Fatal("old folders not put aside (or the family calendar was)")
	}
	aside, _ := filepath.Glob(filepath.Join(e.VMailDir(), OrphanedDir, "*", "example.net", "bob"))
	asideCal, _ := filepath.Glob(filepath.Join(e.RadicaleDir(), "collections", OrphanedDir, "*", "bob@example.net"))
	if len(aside) != 1 || len(asideCal) != 1 {
		t.Fatalf("put aside: %v %v", aside, asideCal)
	}
	if st, _ := os.Stat(filepath.Join(e.VMailDir(), OrphanedDir)); st.Mode().Perm() != 0o700 {
		t.Fatalf("orphaned folder mode %o", st.Mode().Perm())
	}
	if readLayout(e) != LayoutVersion {
		t.Fatal("layout version not recorded")
	}
	// Never again: a later old-looking folder stays where it is.
	later := filepath.Join(e.VMailDir(), "example.net", "carol", "x")
	mkfile(t, later)
	if err := r.migrateLayout(e, cfg); err != nil || !exists(later) {
		t.Fatalf("the move ran twice: %v", err)
	}
}

// Radicale's user owns its storage: a link it plants must not take root's
// mkdir, chown or write outside it.
func TestFamilyCollectionsStayInsideRadicale(t *testing.T) {
	r, e := testRoot(t)
	outside := t.TempDir()
	root := filepath.Join(e.RadicaleDir(), "collections", "collection-root")
	if err := os.Symlink(outside, filepath.Join(root, "family")); err != nil {
		t.Fatal(err)
	}
	var chowned []string
	r.Chown = func(p string, _, _ int) error { chowned = append(chowned, p); return nil }
	_ = r.familyCollections(e, 0)
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatalf("root wrote outside Radicale's storage: %v", entries)
	}
	// Without the link it works.
	_ = os.Remove(filepath.Join(root, "family"))
	if err := r.familyCollections(e, 0); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(root, "family", "calendar", ".Radicale.props")) {
		t.Fatal("no family calendar")
	}
}

func TestStorageLimit(t *testing.T) {
	c := RootConfig{Mailboxes: []RootMailbox{{QuotaMB: 1000}, {QuotaMB: 3000}}}
	if got := StorageLimitMB(c, 1<<20); got != 4000*5/4+5120 {
		t.Fatalf("from quotas: %d", got)
	}
	if got := StorageLimitMB(c, 5000); got != 4000 {
		t.Fatalf("capped at 80%% of the pool: %d", got)
	}
	c.Mailboxes = append(c.Mailboxes, RootMailbox{QuotaMB: 0})
	if got := StorageLimitMB(c, 100000); got != 80000 {
		t.Fatalf("a mailbox without a limit: %d", got)
	}
	if got := StorageLimitMB(c, 0); got != 0 {
		t.Fatalf("unknown pool, no limit: %d", got)
	}
	c.StorageLimitMB = 2048
	if got := StorageLimitMB(c, 100000); got != 2048 {
		t.Fatalf("set by hand: %d", got)
	}
}
