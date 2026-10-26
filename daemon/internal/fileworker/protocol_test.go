package fileworker

import (
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/shares"
)

func TestCleanPath(t *testing.T) {
	good := map[string]string{
		"":              "",
		"/":             "",
		"Photos":        "Photos",
		"/Photos/2026/": "Photos/2026",
		"a b/c.d":       "a b/c.d",
		".bashrc":       ".bashrc",
		"Music/.hidden": "Music/.hidden",
		`back\slash`:    `back\slash`,
		"x/.hardyos-upload-0123456789abcdef01234567": "x/.hardyos-upload-0123456789abcdef01234567",
	}
	for in, want := range good {
		parts, err := CleanPath(in)
		if err != nil || Join(parts) != want {
			t.Errorf("CleanPath(%q) = %q, %v; want %q", in, Join(parts), err, want)
		}
	}
	bad := []string{
		"..", "a/../b", "./a", "a//b", "a/./b", "a\x00b", "\xff",
		".recycle", "a/.recycle/b", ".zfs/snapshot", "x/.zfs", ".hardyos", ".hardyos-meta/x",
		".hardyos-upload-0123456789abcdef01234567/x", ".hardyos-upload-nothex",
	}
	for _, in := range bad {
		if _, err := CleanPath(in); err == nil {
			t.Errorf("CleanPath(%q) accepted", in)
		}
	}
	if err := CleanName("a/b"); err == nil {
		t.Error("CleanName took a slash")
	}
	if err := CleanName("ok.txt"); err != nil {
		t.Error(err)
	}
}

func TestSnapshotTime(t *testing.T) {
	tm, ok := SnapshotTime("hardyos-auto-hourly_2026-10-26-1400")
	if !ok || !tm.Equal(time.Date(2026, 10, 26, 14, 0, 0, 0, time.UTC)) {
		t.Fatalf("got %v %v", tm, ok)
	}
	for _, n := range []string{"manual", "hardyos-auto-yearly_2026-10-26-1400", "hardyos-auto-daily_2026-10-26", "hardyos-auto-daily_2026-13-26-1400", "app-jellyfin_x"} {
		if _, ok := SnapshotTime(n); ok {
			t.Errorf("%s accepted", n)
		}
	}
}

func TestLevel(t *testing.T) {
	rules := []shares.Rule{
		{Kind: shares.KindGroup, Name: `HOME\Family`, Level: shares.LevelWrite},
		{Kind: shares.KindEveryone, Level: shares.LevelRead},
		{Kind: shares.KindUser, Name: `HOME\guest`, Level: shares.LevelNone},
	}
	cases := []struct {
		who  Who
		want string
	}{
		{Who{Principal: `HOME\alice`, Groups: []string{`HOME\Domain Users`, `home\family`}}, shares.LevelWrite},
		{Who{Principal: `HOME\bob`, Groups: []string{`HOME\Domain Users`}}, shares.LevelRead},
		{Who{Principal: `home\GUEST`, Groups: []string{`HOME\Family`}}, shares.LevelNone},
		{Who{Principal: "admin", Local: true, Admin: true}, shares.LevelWrite},
		{Who{Principal: "kid", Local: true}, shares.LevelNone},
		{Who{Principal: `HOME\boss`, Admin: true}, shares.LevelWrite},
	}
	for _, c := range cases {
		if got := Level(rules, c.who); got != c.want {
			t.Errorf("Level(%+v) = %s, want %s", c.who, got, c.want)
		}
	}
	// No rules: administrators only.
	if Level(nil, Who{Principal: `HOME\alice`}) != shares.LevelNone {
		t.Error("no rules let a domain user in")
	}
}
