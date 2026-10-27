package apps

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// tamperState rewrites the app's state.json as a hostile backup would have
// it: trusted source, extra grants and another app's user ID.
func tamperState(t *testing.T, dir string, uid int) {
	t.Helper()
	p := filepath.Join(dir, metaDir, stateFile)
	b, err := os.ReadFile(p)
	must(t, err)
	var st appState
	must(t, json.Unmarshal(b, &st))
	st.Source = SourceCatalog
	st.CatalogSHA256 = strings.Repeat("ab", 32)
	st.Grants = []string{"hostNetwork", "gpu"}
	st.UID = uid
	must(t, os.WriteFile(p, mustJSON(st), 0o600))
}

func TestRestoreDataKeepsLiveTrust(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.install(PrepareArgs{Source: SourceUpload, Shares: map[string]ShareChoice{"MEDIA": {Share: "media"}}}); err != nil {
		t.Fatal(err)
	}
	live := e.state("notes")
	e.fake.OnPrefix("zfs snapshot ", sysexec.Result{})
	data := filepath.Join(e.dir("notes"), dataDirName)
	secret := filepath.Join(t.TempDir(), "master.key")
	must(t, os.WriteFile(secret, []byte("TOP SECRET"), 0o600))
	fill := func(_ context.Context, dir, _ string) error {
		tamperState(t, dir, 30000)
		must(t, os.MkdirAll(filepath.Join(data, "db"), 0o755))
		must(t, os.WriteFile(filepath.Join(data, "db", "x"), []byte("x"), 0o644))
		if os.Getuid() == 0 {
			must(t, os.Chown(filepath.Join(data, "db", "x"), 30000, 30000))
		}
		return nil
	}
	if err := e.m.RestoreData(ctx, "notes", "Family Notes", fill); err != nil {
		t.Fatal(err)
	}
	st := e.state("notes")
	if st.Source != SourceUpload || st.CatalogSHA256 != "" || len(st.Grants) != 0 || st.UID != live.UID {
		t.Errorf("trust came from the backup: %+v (live %+v)", st, live)
	}
	if os.Getuid() == 0 {
		var sys syscall.Stat_t
		must(t, syscall.Lstat(filepath.Join(data, "db", "x"), &sys))
		if int(sys.Uid) != live.UID || int(sys.Gid) != live.UID {
			t.Errorf("restored file owned by %d:%d, want %d", sys.Uid, sys.Gid, live.UID)
		}
	}
	if err := e.m.RestoreData(ctx, "notes", "wrong", fill); err == nil {
		t.Error("restore without the confirmation")
	}
}

func TestRestoreNewDecidesTrustAgain(t *testing.T) {
	// The backup: notes installed on another server, catalog package.
	src := newTestEnv(t)
	pkg := enginePackage(t, "")
	src.shipInCatalog(pkg)
	if _, err := src.install(PrepareArgs{Package: pkg, Shares: map[string]ShareChoice{"MEDIA": {Share: "media"}}}); err != nil {
		t.Fatal(err)
	}
	if st := src.state("notes"); st.Source != SourceCatalog {
		t.Fatalf("source install: %+v", st)
	}
	for _, c := range []struct {
		name    string
		catalog bool
		want    Source
	}{{"shipped here", true, SourceCatalog}, {"not shipped here", false, SourceUpload}} {
		t.Run(c.name, func(t *testing.T) {
			e := newTestEnv(t)
			if c.catalog {
				e.shipInCatalog(pkg)
			}
			ctx := context.Background()
			e.fake.OnResult("zfs list -H -o name tank/apps/notes", sysexec.Result{ExitCode: 1, Stderr: []byte("does not exist")})
			e.fake.On("zfs get -Hp -o value mountpoint,mounted tank/apps/notes", e.dir("notes")+"\nyes\n")
			e.listApps("old", "notes")
			e.scriptCompose()
			fill := func(_ context.Context, dir, _ string) error {
				must(t, os.CopyFS(dir, os.DirFS(src.dir("notes"))))
				// UID 30000 is the kept app's here.
				tamperState(t, dir, 30000)
				e.dataset("notes")
				return nil
			}
			must(t, os.MkdirAll(e.dir("notes"), 0o755))
			err := e.m.RestoreNew(ctx, "notes", "tank", fill)
			st := e.state("notes")
			if st.Source != c.want || len(st.Grants) != 0 {
				t.Errorf("source/grants from the backup: %+v (%v)", st, err)
			}
			if st.UID == 30000 || st.UID < FirstAppUID {
				t.Errorf("user ID %d reused or invalid", st.UID)
			}
			if c.want == SourceCatalog && st.CatalogSHA256 != packageSum(pkg) {
				t.Errorf("catalog sum %q", st.CatalogSHA256)
			}
		})
	}
}

func TestReadMetaRefusesLinks(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "master.key")
	must(t, os.WriteFile(secret, []byte("TOP SECRET"), 0o600))
	link := filepath.Join(dir, "icon.png")
	must(t, os.Symlink(secret, link))
	if b, err := readMeta(link); err == nil {
		t.Errorf("read through a link: %q", b)
	}
	if _, err := readMeta(secret); err != nil {
		t.Errorf("regular file: %v", err)
	}
}
