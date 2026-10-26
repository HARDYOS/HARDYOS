package apps

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Tests for the security review fixes: who decides the source, nested
// binds, whole shared folders, folder creation that can't be redirected,
// and rollbacks that don't bring back permissions.

func TestSourceDecidedByRoot(t *testing.T) {
	if Source("").Trusted() || SourceUpload.Trusted() || !SourceCatalog.Trusted() {
		t.Fatal("only catalog is trusted")
	}
	shipped := enginePackage(t, "")
	other := enginePackage(t, `,"permissions":{"hostNetwork":true}`)
	m := &Manager{Root: t.TempDir(), CatalogDir: t.TempDir()}
	must(t, os.WriteFile(filepath.Join(m.CatalogDir, "notes.hardyapp"), shipped, 0o644))
	// A link in the catalog folder isn't a shipped package.
	ext := filepath.Join(t.TempDir(), "x.hardyapp")
	must(t, os.WriteFile(ext, other, 0o644))
	must(t, os.Symlink(ext, filepath.Join(m.CatalogDir, "linked.hardyapp")))

	for name, c := range map[string]struct {
		raw      []byte
		asked    Source
		askName  string
		prev     *appState
		want     Source
		wantName string
	}{
		"shipped, nothing said":     {raw: shipped, want: SourceCatalog},
		"shipped, said upload":      {raw: shipped, asked: SourceUpload, want: SourceCatalog},
		"upload claims catalog":     {raw: other, asked: SourceCatalog, want: SourceUpload},
		"upload says nothing":       {raw: other, want: SourceUpload},
		"linked into the catalog":   {raw: other, asked: SourceCatalog, want: SourceUpload},
		"imported keeps its label":  {raw: other, asked: SourceImported, askName: "Friends", want: SourceImported, wantName: "Friends"},
		"custom keeps its label":    {raw: other, asked: SourceCustom, want: SourceCustom},
		"update keeps the label":    {raw: other, prev: &appState{Source: SourceImported, SourceName: "Friends"}, want: SourceImported, wantName: "Friends"},
		"old state said catalog":    {raw: other, prev: &appState{Source: SourceCatalog}, want: SourceUpload},
		"old state said nothing":    {raw: other, prev: &appState{}, want: SourceUpload},
		"verified at install":       {raw: other, prev: &appState{Source: SourceCatalog, CatalogSHA256: packageSum(other)}, want: SourceCatalog},
		"verified hash of another":  {raw: other, prev: &appState{Source: SourceCatalog, CatalogSHA256: packageSum(shipped)}, want: SourceUpload},
		"no bytes (old install)":    {raw: nil, prev: &appState{Source: SourceCatalog}, want: SourceUpload},
		"no bytes, untrusted label": {raw: nil, prev: &appState{Source: SourceCustom}, want: SourceCustom},
	} {
		got, gotName, sum, err := m.deriveSource(c.raw, c.asked, c.askName, c.prev)
		if err != nil || got != c.want || gotName != c.wantName {
			t.Errorf("%s: got %q %q %v, want %q %q", name, got, gotName, err, c.want, c.wantName)
		}
		if (got == SourceCatalog) != (sum != "") {
			t.Errorf("%s: catalog hash %q for %s", name, sum, got)
		}
	}
	if _, _, _, err := m.deriveSource(other, "internet", "", nil); err == nil {
		t.Error("an unknown source was accepted")
	}
}

func TestInstallClaimingCatalogNeedsGrants(t *testing.T) {
	perms := `,"permissions":{"hostNetwork":true}`
	e := newTestEnv(t)
	e.compose = `{"services":{"app":{"image":"x","network_mode":"host"}}}`
	e.shipInCatalog(enginePackage(t, "")) // something else is shipped
	if _, err := e.install(PrepareArgs{Package: enginePackage(t, perms), Source: SourceCatalog}); !strings.Contains(problemText(err), "host network") {
		t.Fatalf("an upload claiming to be from the catalog: %v", err)
	}
	if _, err := e.install(PrepareArgs{Package: enginePackage(t, perms)}); !strings.Contains(problemText(err), "host network") {
		t.Fatalf("an upload saying nothing: %v", err)
	}
}

func TestReconfigureRederivesSource(t *testing.T) {
	ctx := context.Background()
	perms := `,"permissions":{"hostNetwork":true}`
	e := newTestEnv(t)
	e.compose = `{"services":{"app":{"image":"x","network_mode":"host"}}}`
	pkg := enginePackage(t, perms)
	e.shipInCatalog(pkg)
	if _, err := e.install(PrepareArgs{Package: pkg}); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(e.dir("notes"), metaDir, packageFile)); err != nil || string(b) != string(pkg) {
		t.Fatalf("the package isn't kept: %v", err)
	}
	// An OS update ships a newer package: the installed one root verified
	// stays a catalog app.
	must(t, os.RemoveAll(e.m.CatalogDir))
	if _, err := e.m.Reconfigure(ctx, ReconfigureArgs{ID: "notes", Limits: &Limits{MemoryMB: 256}}); err != nil {
		t.Fatalf("reconfigure of a verified catalog app: %v", err)
	}
	if st := e.state("notes"); st.Source != SourceCatalog || st.CatalogSHA256 != packageSum(pkg) {
		t.Errorf("after reconfigure: %+v", st)
	}

	// An app installed before root decided sources: state says catalog,
	// there are no package bytes. It's untrusted now.
	st := e.state("notes")
	st.CatalogSHA256 = ""
	must(t, os.WriteFile(filepath.Join(e.dir("notes"), metaDir, stateFile), mustJSON(st), 0o600))
	must(t, os.Remove(filepath.Join(e.dir("notes"), metaDir, packageFile)))
	if _, err := e.m.Reconfigure(ctx, ReconfigureArgs{ID: "notes"}); !strings.Contains(problemText(err), "host network") {
		t.Fatalf("reconfigure of an unverified app: %v", err)
	}
	g := []string{GrantHostNetwork}
	if _, err := e.m.Reconfigure(ctx, ReconfigureArgs{ID: "notes", Grants: &g}); err != nil {
		t.Fatal(err)
	}
	if st := e.state("notes"); st.Source != SourceUpload || strings.Join(st.Grants, ",") != GrantHostNetwork {
		t.Errorf("after granting: %+v", st)
	}
	o, _ := e.m.Status(ctx)
	if o.Apps[0].Source != SourceUpload {
		t.Errorf("view: %s", o.Apps[0].Source)
	}
}

func TestDescribeHostNetworkCapabilities(t *testing.T) {
	var m Manifest
	m.Permissions = Permissions{HostNetwork: true, Capabilities: []string{"NET_ADMIN", "NET_RAW"}}
	d := strings.Join(DescribePermissions(m), "\n")
	if !strings.Contains(d, "Change the server's own network settings") || !strings.Contains(d, "server's own network and capture") {
		t.Errorf("host network capabilities:\n%s", d)
	}
	m.Permissions.HostNetwork = false
	if d := strings.Join(DescribePermissions(m), "\n"); strings.Contains(d, "server's") {
		t.Errorf("without host network:\n%s", d)
	}
	if neededGrants(Manifest{Permissions: Permissions{HostNetwork: true, Capabilities: []string{"NET_ADMIN"}}})[1] != "cap:NET_ADMIN" {
		t.Error("NET_ADMIN needs its own grant")
	}
}

func TestNestedBindsRefused(t *testing.T) {
	plain := testMF(t, "")
	for name, c := range map[string]struct {
		vols, db string
		ok       bool
	}{
		"siblings":         {vols: `{"type":"bind","source":"` + dataDir + `/a","target":"/a"},{"type":"bind","source":"` + dataDir + `/b","target":"/b"}`, ok: true},
		"same folder":      {vols: `{"type":"bind","source":"` + dataDir + `/a","target":"/a"}`, db: `{"type":"bind","source":"` + dataDir + `/a/","target":"/a"}`, ok: true},
		"prefix not path":  {vols: `{"type":"bind","source":"` + dataDir + `/a","target":"/a"},{"type":"bind","source":"` + dataDir + `/ab","target":"/b"}`, ok: true},
		"data root":        {vols: `{"type":"bind","source":"` + dataDir + `","target":"/all"},{"type":"bind","source":"` + dataDir + `/db","target":"/db"}`},
		"other service":    {vols: `{"type":"bind","source":"` + dataDir + `/a","target":"/a"}`, db: `{"type":"bind","source":"` + dataDir + `/a/b","target":"/b"}`},
		"through dot-dots": {vols: `{"type":"bind","source":"` + dataDir + `/a","target":"/a"}`, db: `{"type":"bind","source":"` + dataDir + `/c/../a/b","target":"/b"}`},
	} {
		src := `{"name":"hardyos-notes","services":{"app":{"image":"x","volumes":[` + c.vols + `]},"db":{"image":"y","volumes":[` + c.db + `]}}}`
		r, err := ParseResolved([]byte(src))
		must(t, err)
		err = r.Check(plain, "hardyos-notes", dataDir, ports)
		if c.ok && err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if !c.ok && !strings.Contains(problemText(err), "a container could replace it") {
			t.Errorf("%s: got %v", name, err)
		}
	}
	// Shares too: the same share twice is fine, a folder in it isn't.
	shares := []shareBind{{Name: "MEDIA", Path: "/mnt/tank/shares/media", Write: true}}
	two := resolved(t, `"volumes":[{"type":"bind","source":"/mnt/tank/shares/media","target":"/a"},{"type":"bind","source":"/mnt/tank/shares/media","target":"/b"}]`, "")
	if err := two.check(plain, "hardyos-notes", dataDir, ports, shares); err != nil {
		t.Errorf("a share twice: %v", err)
	}
	in := resolved(t, `"volumes":[{"type":"bind","source":"/mnt/tank/shares/media","target":"/a"},{"type":"bind","source":"/mnt/tank/shares/media/x","target":"/b"}]`, "")
	if err := in.check(plain, "hardyos-notes", dataDir, ports, shares); err == nil {
		t.Error("a folder inside a share bind was allowed")
	}
}

func TestStartRefusesShareSubfolders(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.install(PrepareArgs{Shares: map[string]ShareChoice{"MEDIA": {Share: "media"}}}); err != nil {
		t.Fatal(err)
	}
	if e.state("notes").Shares["MEDIA"].Path != "" {
		t.Fatal("a share path was stored")
	}
	// An app installed when subfolders were allowed doesn't start.
	st := e.state("notes")
	st.Shares["MEDIA"] = ShareChoice{Share: "media", Path: "Movies", Access: AccessRead}
	must(t, os.WriteFile(filepath.Join(e.dir("notes"), metaDir, stateFile), mustJSON(st), 0o600))
	if err := e.m.Up(ctx, "notes"); err == nil || !strings.Contains(err.Error(), "whole shared folders") {
		t.Errorf("start with a share subfolder: %v", err)
	}
	// A resolved file binding a folder in the share (written before) doesn't either.
	st.Shares["MEDIA"] = ShareChoice{Share: "media", Access: AccessRead}
	must(t, os.WriteFile(filepath.Join(e.dir("notes"), metaDir, stateFile), mustJSON(st), 0o600))
	path := filepath.Join(e.dir("notes"), metaDir, resolvedFile)
	media := filepath.Join(e.shares.root, "media")
	b := strings.Replace(string(mustRead(t, path)), `"source": "`+media+`"`, `"source": "`+media+`/Movies"`, 1)
	must(t, os.WriteFile(path, []byte(b), 0o600))
	if err := e.m.Up(ctx, "notes"); err == nil || !strings.Contains(err.Error(), "instead of being the shared folder itself") {
		t.Errorf("start with a bind inside a share: %v", err)
	}
}

func TestMkdirStrictRefusesLinks(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	must(t, os.Chmod(outside, 0o755))
	// A link on the way and a link at the end are refused, and nothing
	// happens where they lead.
	must(t, os.Symlink(outside, filepath.Join(base, "via")))
	if err := mkdirStrict(base, "via/x", 0o700, keepOwner); err == nil {
		t.Error("followed a link on the way")
	}
	if _, err := os.Lstat(filepath.Join(outside, "x")); err == nil {
		t.Error("created a folder through a link")
	}
	if err := mkdirStrict(base, "via", 0o700, keepOwner); err == nil || !strings.Contains(err.Error(), "isn't a folder") {
		t.Errorf("a link at the end: %v", err)
	}
	if fi, _ := os.Stat(outside); fi.Mode().Perm() != 0o755 {
		t.Errorf("the link's target changed mode: %v", fi.Mode())
	}
	must(t, os.WriteFile(filepath.Join(base, "file"), nil, 0o644))
	if err := mkdirStrict(base, "file/x", 0o700, keepOwner); err == nil {
		t.Error("went through a file")
	}
	for _, bad := range []string{"../x", "a//b", "./a", ""} {
		if err := mkdirStrict(base, bad, 0o700, keepOwner); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	// Plain folders: created, mode set on the last one.
	must(t, mkdirStrict(base, "a/b/c", 0o750, keepOwner))
	if fi, err := os.Stat(filepath.Join(base, "a/b/c")); err != nil || fi.Mode().Perm() != 0o750 {
		t.Errorf("a/b/c: %v %v", fi, err)
	}
	must(t, mkdirStrict(base, "a/b/c", 0o700, keepOwner))
	if fi, _ := os.Stat(filepath.Join(base, "a/b/c")); fi.Mode().Perm() != 0o700 {
		t.Errorf("mode not changed: %v", fi.Mode())
	}

	// Owners (root only): OnlyIfNew leaves an existing folder's owner.
	if os.Geteuid() != 0 {
		return
	}
	must(t, mkdirStrict(base, "own", 0o755, dirOwner{UID: 30005, GID: 30005, OnlyIfNew: true}))
	if uid := ownerOf(t, filepath.Join(base, "own")); uid != 30005 {
		t.Errorf("new folder owner %d", uid)
	}
	must(t, os.Chown(filepath.Join(base, "own"), 999, 999))
	must(t, mkdirStrict(base, "own", 0o755, dirOwner{UID: 30005, GID: 30005, OnlyIfNew: true}))
	if uid := ownerOf(t, filepath.Join(base, "own")); uid != 999 {
		t.Errorf("existing folder's owner changed to %d", uid)
	}
	must(t, mkdirStrict(base, "own", 0o755, dirOwner{UID: 30005, GID: 30005}))
	if uid := ownerOf(t, filepath.Join(base, "own")); uid != 30005 {
		t.Errorf("explicit owner not set: %d", uid)
	}
	// A link planted where the folder goes: the target keeps its owner.
	must(t, os.Symlink(outside, filepath.Join(base, "evil")))
	_ = mkdirStrict(base, "evil", 0o777, dirOwner{UID: 30005, GID: 30005})
	if uid := ownerOf(t, outside); uid == 30005 {
		t.Error("chowned through a link")
	}
}

// hookRunner runs a function before commands starting with a prefix.
type hookRunner struct {
	sysexec.Runner
	before map[string]func()
}

func (h *hookRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) (sysexec.Result, error) {
	line := name + " " + strings.Join(args, " ")
	for p, f := range h.before {
		if strings.HasPrefix(line, p) {
			f()
		}
	}
	return h.Runner.Run(ctx, stdin, name, args...)
}

// copyDir copies the files in one folder to another (replacing them).
func copyDir(t *testing.T, from, to string) {
	t.Helper()
	must(t, os.RemoveAll(to))
	must(t, os.MkdirAll(to, 0o700))
	entries, err := os.ReadDir(from)
	must(t, err)
	for _, e := range entries {
		if e.Type().IsRegular() {
			must(t, os.WriteFile(filepath.Join(to, e.Name()), mustRead(t, filepath.Join(from, e.Name())), 0o600))
		}
	}
}

func TestRollbackKeepsPermissionsRemovedSince(t *testing.T) {
	ctx := context.Background()
	hostCompose := `{"services":{"app":{"image":"x","network_mode":"host",
	  "volumes":[{"type":"bind","source":"MEDIA","target":"/media"},{"type":"bind","source":"DL","target":"/downloads"}]}}}`
	plainCompose := `{"services":{"app":{"image":"x","volumes":[{"type":"bind","source":"MEDIA","target":"/media"}]}}}`
	setup := func(t *testing.T) (*testEnv, string) {
		e := newTestEnv(t)
		e.compose = hostCompose
		v1 := enginePackage(t, `,"permissions":{"hostNetwork":true}`)
		if _, err := e.install(PrepareArgs{Package: v1, Source: SourceUpload, Grants: []string{GrantHostNetwork},
			Shares: map[string]ShareChoice{"MEDIA": {Share: "media"}, "DOWNLOADS": {Share: "downloads"}}}); err != nil {
			t.Fatal(err)
		}
		// The "snapshot": a copy of the app's own files.
		meta := filepath.Join(e.dir("notes"), metaDir)
		snap := filepath.Join(t.TempDir(), "snap")
		copyDir(t, meta, snap)
		ds := "tank/apps/notes"
		e.fake.On("zfs list -H -p -t snapshot -o name,creation,org.hardyos:app-version -s creation -d 1 "+ds,
			ds+"@hardyos-update-20261026-120000\t1793016000\t1.0.0\n")
		e.fake.OnPrefix("zfs rollback ", sysexec.Result{})
		e.m.Runner = &hookRunner{Runner: e.fake, before: map[string]func(){
			"zfs rollback -r " + ds + "@": func() { copyDir(t, snap, meta) },
		}}
		e.shares.take()
		return e, "hardyos-update-20261026-120000"
	}
	upCount := func(e *testEnv) int {
		n := 0
		for _, l := range e.fake.Lines() {
			if strings.HasSuffix(l, "up -d --remove-orphans") {
				n++
			}
		}
		return n
	}

	t.Run("shares removed since stay removed", func(t *testing.T) {
		e, snap := setup(t)
		// Since the snapshot, the admin took Downloads away.
		if _, err := e.m.Reconfigure(ctx, ReconfigureArgs{ID: "notes", Shares: map[string]ShareChoice{"DOWNLOADS": {}}}); err != nil {
			t.Fatal(err)
		}
		e.shares.take()
		if err := e.m.Rollback(ctx, RollbackArgs{ID: "notes", Snapshot: snap, Confirm: "Family Notes"}); err != nil {
			t.Fatal(err)
		}
		st := e.state("notes")
		if _, ok := st.Shares["DOWNLOADS"]; ok || st.Shares["MEDIA"].Share != "media" || st.Blocked != "" ||
			strings.Join(st.Grants, ",") != GrantHostNetwork {
			t.Errorf("after rollback: %+v", st)
		}
		if env := e.env("notes"); !strings.HasSuffix(env["HARDY_SHARE_DOWNLOADS"], "/.unshared/DOWNLOADS") {
			t.Errorf("downloads after rollback: %v", env["HARDY_SHARE_DOWNLOADS"])
		}
		// The snapshot's ACL for Downloads isn't given back.
		for _, g := range e.shares.take() {
			if strings.Contains(g, "grant downloads") {
				t.Errorf("rollback granted downloads again: %v", g)
			}
		}
		if upCount(e) != 1 {
			t.Error("the app wasn't started after the rollback")
		}
	})

	t.Run("a grant removed since blocks the start", func(t *testing.T) {
		e, snap := setup(t)
		// Version 2 doesn't use the host network: the grant goes.
		e.compose = plainCompose
		e.scriptCompose()
		if _, err := e.m.Prepare(ctx, PrepareArgs{Package: enginePackage(t, ""), Source: SourceUpload, Grants: []string{}}); err != nil {
			t.Fatal(err)
		}
		if g := e.state("notes").Grants; len(g) != 0 {
			t.Fatalf("grants after v2: %v", g)
		}
		e.compose = hostCompose
		e.scriptCompose()
		err := e.m.Rollback(ctx, RollbackArgs{ID: "notes", Snapshot: snap, Confirm: "Family Notes"})
		if err == nil || !strings.Contains(err.Error(), "host network") || !strings.Contains(err.Error(), "stays stopped") {
			t.Fatalf("rollback needing a removed grant: %v", err)
		}
		if upCount(e) != 0 {
			t.Error("the app was started anyway")
		}
		st := e.state("notes")
		if !strings.Contains(st.Blocked, "host network") || len(st.Grants) != 0 {
			t.Errorf("state after a blocked rollback: %+v", st)
		}
		// Starting is refused until an admin allows it.
		if err := e.m.Up(ctx, "notes"); err == nil || !strings.Contains(err.Error(), "can't start") {
			t.Errorf("start of a blocked app: %v", err)
		}
		if err := e.m.Restart(ctx, "notes"); err == nil {
			t.Error("restart of a blocked app")
		}
		o, _ := e.m.Status(ctx)
		if o.Apps[0].Blocked == "" {
			t.Error("the view doesn't say the app is blocked")
		}
		g := []string{GrantHostNetwork}
		if _, err := e.m.Reconfigure(ctx, ReconfigureArgs{ID: "notes", Grants: &g}); err != nil {
			t.Fatal(err)
		}
		if st := e.state("notes"); st.Blocked != "" {
			t.Errorf("still blocked after allowing it: %+v", st)
		}
		must(t, e.m.Up(ctx, "notes"))
	})

	t.Run("a share that no longer exists", func(t *testing.T) {
		e, snap := setup(t)
		must(t, os.RemoveAll(filepath.Join(e.shares.root, "downloads")))
		if err := e.m.Rollback(ctx, RollbackArgs{ID: "notes", Snapshot: snap, Confirm: "Family Notes"}); err != nil {
			t.Fatal(err)
		}
		if _, ok := e.state("notes").Shares["DOWNLOADS"]; ok {
			t.Error("a share that's gone was kept")
		}
	})
}

func TestIntersectGrants(t *testing.T) {
	if got := intersectGrants([]string{"gpu", "hostNetwork", "gpu"}, []string{"hostNetwork", "gpu", "cap:NET_ADMIN"}); strings.Join(got, ",") != "gpu,hostNetwork" {
		t.Errorf("got %v", got)
	}
	if got := intersectGrants(nil, []string{"gpu"}); got == nil || len(got) != 0 {
		t.Errorf("got %#v", got)
	}
}
