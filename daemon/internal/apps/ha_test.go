package apps

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// A conversion's hold (M-A): from the final snapshot until the folder is
// parked, the app has no containers, its dataset is read-only, and nothing
// starts it (Up, Restart, an update) until its own conversion lets go.
func TestHAHoldRefusesStarts(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.install(PrepareArgs{Settings: map[string]string{"ADMIN_PASSWORD": "hunter2"}, Shares: map[string]ShareChoice{"MEDIA": {Share: "media"}},
		Source: SourceUpload}); err != nil {
		t.Fatal(err)
	}
	const get = "zfs get -H -p -s local -o value " + PropHAHold + " tank/apps/notes"
	e.fake.On(get, "-\n")
	e.fake.OnPrefix("zfs set ", sysexec.Result{})
	e.fake.OnPrefix("zfs inherit ", sysexec.Result{})
	if err := e.m.HAHold(ctx, HAHoldArgs{ID: "notes", Conv: "x"}); err == nil {
		t.Fatal("held for a bad conversion id")
	}
	if err := e.m.HAHold(ctx, HAHoldArgs{ID: "notes", Conv: "abcdefgh12"}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Join(e.fake.Lines(), "\n")
	down, ro := strings.Index(lines, "compose"), strings.Index(lines, "zfs set readonly=on "+PropHAHold+"=abcdefgh12 "+PropHAHoldRunning+"=off tank/apps/notes")
	if !strings.Contains(lines, " down --remove-orphans") || ro < 0 || down > ro {
		t.Fatalf("not held (containers removed, then read-only): %s", lines)
	}
	e.fake.On(get, "abcdefgh12\n")
	for name, start := range map[string]func() error{
		"start":   func() error { return e.m.Up(ctx, "notes") },
		"restart": func() error { return e.m.Restart(ctx, "notes") },
	} {
		if err := start(); err == nil || !strings.Contains(err.Error(), ErrHeld.Error()) {
			t.Fatalf("%s of a held app: %v", name, err)
		}
	}
	if err := e.m.HAHold(ctx, HAHoldArgs{ID: "notes", Conv: "otherconv12"}); err == nil {
		t.Fatal("another conversion took the hold")
	}
	if err := e.m.HAHold(ctx, HAHoldArgs{ID: "notes", Conv: "otherconv12", Release: true}); err == nil {
		t.Fatal("another conversion ended the hold")
	}
	if err := e.m.HAHold(ctx, HAHoldArgs{ID: "notes", Conv: "abcdefgh12", Release: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(e.fake.Lines(), "\n"), "zfs inherit readonly tank/apps/notes") {
		t.Fatal("the dataset stayed read-only")
	}
	e.fake.On(get, "-\n")
	if err := e.m.Up(ctx, "notes"); err != nil && strings.Contains(err.Error(), ErrHeld.Error()) {
		t.Fatalf("still refused after the hold ended: %v", err)
	}
	// Only a conversion id is a hold: anything else there isn't.
	e.fake.On(get, "/mnt/tank/apps/notes\n")
	if err := e.m.Up(ctx, "notes"); err != nil && strings.Contains(err.Error(), ErrHeld.Error()) {
		t.Fatalf("a stray value was taken for a hold: %v", err)
	}
}

// The hold records whether the app ran before its conversion stopped it
// (decision 504), and the release says so; a stray value isn't "on".
func TestHAHoldRecordsTheState(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.install(PrepareArgs{Settings: map[string]string{"ADMIN_PASSWORD": "hunter2"}, Shares: map[string]ShareChoice{"MEDIA": {Share: "media"}},
		Source: SourceUpload}); err != nil {
		t.Fatal(err)
	}
	e.fake.On("zfs get -H -p -s local -o value "+PropHAHold+" tank/apps/notes", "-\n")
	e.fake.OnPrefix("zfs set ", sysexec.Result{})
	e.fake.OnPrefix("zfs inherit ", sysexec.Result{})
	if err := e.m.HAHold(ctx, HAHoldArgs{ID: "notes", Conv: "abcdefgh12", WasRunning: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(e.fake.Lines(), "\n"), PropHAHoldRunning+"=on tank/apps/notes") {
		t.Fatal("the state it ran in wasn't recorded")
	}
	e.fake.On("zfs get -H -p -s local -o value "+PropHAHold+" tank/apps/notes", "abcdefgh12\n")
	for v, want := range map[string]bool{"on\n": true, "off\n": false, "yes\n": false} {
		e.fake.On("zfs get -H -p -s local -o value "+PropHAHoldRunning+" tank/apps/notes", v)
		res, err := e.m.HAHoldState(ctx, HAHoldArgs{ID: "notes", Conv: "abcdefgh12", Release: true})
		if err != nil || !res.Held || res.WasRunning != want {
			t.Fatalf("%q: %+v %v", v, res, err)
		}
	}
	e.fake.On("zfs get -H -p -s local -o value "+PropHAHold+" tank/apps/notes", "-\n")
	if res, err := e.m.HAHoldState(ctx, HAHoldArgs{ID: "notes", Conv: "abcdefgh12", Release: true}); err != nil || res.Held {
		t.Fatalf("not held: %+v %v", res, err)
	}
}

// The folders of the shared folders that moved with an app (decision 500)
// are only shares/<id> folders.
func TestValidSharePath(t *testing.T) {
	for p, ok := range map[string]bool{"/mnt/tank/shares/media": true, "/tank/shares/media": true, "/mnt/tank/apps/media": false,
		"/mnt/tank/shares/media/sub": false, "mnt/tank/shares/media": false, "/mnt/tank/shares/../shares/media": false, "/mnt/tank/shares/other": false} {
		if (validSharePath(p, "media") == nil) != ok {
			t.Errorf("%s: %v", p, !ok)
		}
	}
}

// A moved app's resolved compose file names its folder where it is now:
// the folder itself and paths below it, nothing that merely starts with
// the same letters (decision 483).
func TestRewriteDir(t *testing.T) {
	in := `{"services":{"web":{"volumes":[{"type":"bind","source":"/mnt/tank/apps/notes/data/db","target":"/db"},
		{"type":"bind","source":"/mnt/tank/apps/notes-old/x","target":"/x"}],"working_dir":"/mnt/tank/apps/notes"}}}`
	out, n, err := rewriteDir([]byte(in), "/mnt/tank/apps/notes", "/mnt/hc/nas/apps/notes")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("rewrote %d paths", n)
	}
	var v struct {
		Services map[string]struct {
			Volumes []struct {
				Source string `json:"source"`
			} `json:"volumes"`
			WorkingDir string `json:"working_dir"`
		} `json:"services"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatal(err)
	}
	web := v.Services["web"]
	if web.Volumes[0].Source != "/mnt/hc/nas/apps/notes/data/db" || web.Volumes[1].Source != "/mnt/tank/apps/notes-old/x" || web.WorkingDir != "/mnt/hc/nas/apps/notes" {
		t.Fatalf("rewritten %+v", web)
	}
	for _, d := range []string{"relative/apps/notes", "/mnt/tank/apps/other", "/mnt/tank/apps/notes/../x", "/mnt/tank/notes"} {
		if validDir(d, "notes") == nil {
			t.Errorf("%q passed as the app's folder", d)
		}
	}
	if err := validDir("/mnt/tank/apps/notes", "notes"); err != nil {
		t.Fatal(err)
	}
}
