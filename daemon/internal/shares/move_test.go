package shares

import (
	"context"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// A shared folder held for its conversion (decision 501): read-only,
// unmounted and not mounted at boot, its settings unchangeable, and only
// its own conversion lets go of it, which mounts it again. A folder still
// in use can't be unmounted: no hold then, as it was.
func TestHAHold(t *testing.T) {
	m, f, _, _ := newManager(t)
	ctx := context.Background()
	onList(f, "", row{ds: "tank/shares/media", name: "Media", mounted: true}.String()+"\n")
	const held = "zfs get -H -p -s local -o value " + PropHAHold + " tank/shares/media"
	f.On(held, "-\n")
	f.On("zfs get -H -o value mounted tank/shares/media", "yes\n")
	f.OnPrefix("zfs set ", sysexec.Result{})
	f.OnPrefix("zfs inherit ", sysexec.Result{})
	f.OnPrefix("zfs mount ", sysexec.Result{})
	f.OnResult("zfs unmount tank/shares/media", sysexec.Result{Stderr: []byte("cannot unmount: target is busy"), ExitCode: 1})
	if err := m.HAHold(ctx, HAHoldArgs{ID: "media", Conv: "x"}); err == nil {
		t.Fatal("held for a bad conversion id")
	}
	if err := m.HAHold(ctx, HAHoldArgs{ID: "media", Conv: "abcdefgh12s0"}); err == nil || !strings.Contains(err.Error(), "still in use") {
		t.Fatalf("held while in use: %v", err)
	}
	lines := strings.Join(f.Lines(), "\n")
	if !strings.Contains(lines, "zfs set canmount=on tank/shares/media") || !strings.Contains(lines, "zfs inherit "+PropHAHold+" tank/shares/media") {
		t.Fatalf("the failed hold wasn't taken back:\n%s", lines)
	}
	f.On("zfs unmount tank/shares/media", "")
	if err := m.HAHold(ctx, HAHoldArgs{ID: "media", Conv: "abcdefgh12s0"}); err != nil {
		t.Fatal(err)
	}
	lines = strings.Join(f.Lines(), "\n")
	if !strings.Contains(lines, "zfs set canmount=noauto readonly=on "+PropHAHold+"=abcdefgh12s0 tank/shares/media") {
		t.Fatalf("not held:\n%s", lines)
	}
	f.On(held, "abcdefgh12s0\n")
	name := "Other"
	if _, err := m.Update(ctx, ShareUpdate{ID: "media", Name: &name}); err == nil || !strings.Contains(err.Error(), "being moved") {
		t.Fatalf("a held folder's settings changed: %v", err)
	}
	if err := m.Delete(ctx, "media", "Media"); err == nil || !strings.Contains(err.Error(), "being moved") {
		t.Fatalf("a held folder was deleted: %v", err)
	}
	if err := m.HAHold(ctx, HAHoldArgs{ID: "media", Conv: "otherconv12"}); err == nil {
		t.Fatal("another conversion took the hold")
	}
	if err := m.HAHold(ctx, HAHoldArgs{ID: "media", Conv: "otherconv12", Release: true}); err == nil {
		t.Fatal("another conversion let go")
	}
	f.On("zfs get -H -o value mounted tank/shares/media", "no\n")
	if err := m.HAHold(ctx, HAHoldArgs{ID: "media", Conv: "abcdefgh12s0", Release: true}); err != nil {
		t.Fatal(err)
	}
	lines = strings.Join(f.Lines(), "\n")
	if !strings.Contains(lines, "zfs inherit readonly tank/shares/media") || !strings.Contains(lines, "zfs mount tank/shares/media") {
		t.Fatalf("not let go of:\n%s", lines)
	}
}

// The storage server lets go of a folder it adopted only for the
// conversion holding it, marks it released first, and a release asked
// again (its answer lost) is fine only when that conversion released it
// (decision 507).
func TestHAHoldAdoptedRelease(t *testing.T) {
	m, f, _, _ := newManager(t)
	ctx := context.Background()
	onList(f, "", row{ds: "nas/shares/media", name: "Media"}.String()+"\n")
	f.On("zfs get -H -p -s local -o value "+PropHAHold+" nas/shares/media", "-\n")
	f.On("zfs get -H -p -s local -o value "+PropHAReleased+" nas/shares/media", "-\n")
	f.OnPrefix("zfs set ", sysexec.Result{})
	f.OnPrefix("zfs inherit ", sysexec.Result{})
	f.OnPrefix("zfs mount ", sysexec.Result{})
	f.On("zfs get -H -o value mounted nas/shares/media", "no\n")
	rel := HAHoldArgs{ID: "media", Conv: "abcdefgh12s0", Release: true, Adopted: true}
	if err := m.HAHold(ctx, rel); err == nil {
		t.Fatal("let go of a folder nobody held")
	}
	f.On("zfs get -H -p -s local -o value "+PropHAHold+" nas/shares/media", "abcdefgh12s0\n")
	if err := m.HAHold(ctx, rel); err != nil {
		t.Fatal(err)
	}
	lines := strings.Join(f.Lines(), "\n")
	mark, inh := strings.Index(lines, "zfs set "+PropHAReleased+"=abcdefgh12s0 nas/shares/media"), strings.Index(lines, "zfs inherit "+PropHAHold)
	if mark < 0 || inh < mark {
		t.Fatalf("not marked released before the hold ended:\n%s", lines)
	}
	f.On("zfs get -H -p -s local -o value "+PropHAHold+" nas/shares/media", "-\n")
	f.On("zfs get -H -p -s local -o value "+PropHAReleased+" nas/shares/media", "abcdefgh12s0\n")
	if err := m.HAHold(ctx, rel); err != nil {
		t.Fatalf("asked again: %v", err)
	}
}

// What moves with a shared folder is checked like a person's input.
func TestSettingsCheck(t *testing.T) {
	ok := Settings{Name: "Media", Access: []Rule{{Kind: KindEveryone, Level: LevelRead}}, Apps: []AppGrant{{App: "jellyfin", UID: 30001, Level: LevelRead}},
		Services: DefaultServices()}
	if _, err := ok.Check(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Settings){
		"untidy name": func(s *Settings) { s.Name = " Media" },
		"tab":         func(s *Settings) { s.Description = "a\tb" },
		"bad rule":    func(s *Settings) { s.Access = []Rule{{Kind: "root", Level: LevelWrite}} },
		"bad app":     func(s *Settings) { s.Apps = []AppGrant{{App: "x", UID: 1, Level: LevelRead}} },
		"bad level":   func(s *Settings) { s.Apps = []AppGrant{{App: "jellyfin", UID: 30001, Level: "all"}} },
		"tiny quota":  func(s *Settings) { s.QuotaBytes = 10 },
		"nfs everyone": func(s *Settings) {
			s.Services.NFS = NFS{Enabled: true, Clients: []NFSRule{{Client: "0.0.0.0/0", Access: LevelWrite}}}
		},
	} {
		s := ok
		mut(&s)
		if _, err := s.Check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	props := strings.Join(ok.Props(), " ")
	if !strings.Contains(props, PropShare+"=1") || !strings.Contains(props, PropName+"=Media") || !strings.Contains(props, "jellyfin") {
		t.Fatal(props)
	}
}
