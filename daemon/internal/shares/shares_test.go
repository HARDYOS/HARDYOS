package shares

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

var listAll = "zfs list -Hp -t filesystem -o " + strings.Join(listProps, ",")

type row struct {
	ds, name, desc, access, apps string
	services                     string // org.hardyos:services; "" = not set
	recycle, guest               bool
	quota, used                  string
	mounted                      bool
}

func (r row) String() string {
	mp := "/mnt/" + r.ds
	mounted := "no"
	if r.mounted {
		mounted = "yes"
	}
	q, u := r.quota, r.used
	if q == "" {
		q = "0"
	}
	if u == "" {
		u = "98304"
	}
	if r.access == "" {
		r.access = "[]"
	}
	if r.apps == "" {
		r.apps = "[]"
	}
	if r.desc == "" {
		r.desc = "-"
	}
	svc := r.services
	if svc == "" {
		svc = "-"
	}
	return strings.Join([]string{r.ds, "1", r.name, r.desc, r.access, r.apps, onOff(r.recycle), onOff(r.guest), q, u, mp, mounted, "1792000000", svc}, "\t")
}

// onList makes the fake answer zfs list for target ("" = everything): the
// rows, and the dataset names they belong to.
func onList(f *sysexec.Fake, target, out string) {
	main, names := listAll, "zfs list -H -o name -t filesystem"
	if target != "" {
		main = "zfs list -Hp -t filesystem -o " + strings.Join(listProps, ",") + " " + target
		names += " " + target
	}
	f.On(main, out)
	var ns []string
	for _, l := range splitLines([]byte(out)) {
		n, _, _ := strings.Cut(l, "\t")
		ns = append(ns, n)
	}
	f.On(names, strings.Join(ns, "\n")+"\n")
}

func devOf(p string) uint64 {
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil {
		return 0
	}
	return uint64(st.Dev)
}

func rows(rs ...row) string {
	lines := []string{
		"tank\t-\t-\t-\t-\t-\t-\t-\t0\t1000\t/mnt/tank\tyes\t1792000000\t-",
		"tank/apps\t-\t-\t-\t-\t-\t-\t-\t0\t1000\t/mnt/tank/apps\tyes\t1792000000\t-",
		"tank/shares\t-\t-\t-\t-\t-\t-\t-\t0\t1000\t/mnt/tank/shares\tyes\t1792000000\t-",
		// Not a shared folder: no org.hardyos:share=1.
		"tank/shares/stray\t-\t-\t-\t-\t-\t-\t-\t0\t1000\t/mnt/tank/shares/stray\tyes\t1792000000\t-",
	}
	for _, r := range rs {
		lines = append(lines, r.String())
	}
	return strings.Join(lines, "\n") + "\n"
}

type treeCall struct {
	root   string
	uid    int
	write  bool
	revoke bool
}

func newManager(t *testing.T) (*Manager, *sysexec.Fake, string, *[]treeCall) {
	t.Helper()
	root := t.TempDir()
	f := &sysexec.Fake{}
	var mu sync.Mutex
	calls := &[]treeCall{}
	m := &Manager{Runner: f, Root: root}
	// Every dataset is "mounted" where it says, on its folder's device (or a
	// made-up one when the test didn't make the folder).
	m.Mounts = func() (MountVerifier, error) {
		return MountFunc(func(p, _ string) (uint64, error) {
			if d := devOf(m.sys(p)); d != 0 {
				return d, nil
			}
			return 1, nil
		}), nil
	}
	m.tree = func(_ context.Context, r string, _ uint64, uid int, write, revoke bool) (treeStats, error) {
		mu.Lock()
		defer mu.Unlock()
		*calls = append(*calls, treeCall{r, uid, write, revoke})
		return treeStats{}, nil
	}
	t.Cleanup(m.Wait)
	return m, f, root, calls
}

func mkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func isValidation(err error) bool {
	var ve *ValidationError
	return errors.As(err, &ve)
}

func TestNamesAndRules(t *testing.T) {
	for in, want := range map[string]string{"Media": "media", "TV & Movies": "tv-movies", "  Kids' (old) photos ": "kids-old-photos", "Ünïcode": "n-code", "日本": ""} {
		if got := DeriveID(in); got != want {
			t.Errorf("DeriveID(%q) = %q, want %q", in, got, want)
		}
	}
	if n, err := CleanName("  Family   Photos "); err != nil || n != "Family Photos" {
		t.Errorf("CleanName = %q %v", n, err)
	}
	for _, bad := range []string{"", "   ", "a/b", "semi;colon", strings.Repeat("x", 41), "...", "Homes", "x\x00y"} {
		if _, err := CleanName(bad); !isValidation(err) {
			t.Errorf("CleanName(%q) = %v, want a validation error", bad, err)
		}
	}
	for _, bad := range []string{"Media", "-media", "media-", "a_b", strings.Repeat("a", 33), "global", ""} {
		if ValidID(bad) == nil {
			t.Errorf("ValidID(%q) accepted", bad)
		}
	}
	if _, err := CheckNew(NewShare{Pool: "tank", Name: "日本"}); err == nil || !strings.Contains(err.Error(), "short id") {
		t.Errorf("a name without an id asks for one: %v", err)
	}
	if _, err := CheckNew(NewShare{Pool: "rpool", Name: "Media"}); !isValidation(err) {
		t.Errorf("the boot pool was accepted: %v", err)
	}
	if _, err := CheckNew(NewShare{Pool: "tank", Name: "Media", QuotaBytes: 10}); err == nil || !strings.Contains(err.Error(), "too small") {
		t.Errorf("tiny quota: %v", err)
	}
	if _, err := CheckNew(NewShare{Pool: "tank", Name: "Media", Subfolders: []string{"Movies", "movies"}}); err == nil {
		t.Error("a duplicate subfolder was accepted")
	}
	if _, err := CheckNew(NewShare{Pool: "tank", Name: "Media", Subfolders: []string{"../etc"}}); err == nil {
		t.Error("a subfolder with a slash was accepted")
	}

	rules, err := CleanRules([]Rule{
		{Kind: KindEveryone, Name: "ignored", Level: LevelRead},
		{Kind: KindUser, Name: ` HOME\alice `, Level: LevelWrite},
		{Kind: KindGroup, Name: `HOME\Domain Users`, Level: LevelNone},
		{Kind: KindUser, Name: "bob", Level: LevelRead},
	})
	if err != nil || rules[0].Name != "" || rules[1].Name != `HOME\alice` {
		t.Fatalf("CleanRules = %+v %v", rules, err)
	}
	for _, bad := range [][]Rule{
		{{Kind: "robot", Level: LevelRead}},
		{{Kind: KindUser, Name: "alice", Level: "admin"}},
		{{Kind: KindUser, Level: LevelRead}},
		{{Kind: KindUser, Name: `HOME\alice`, Level: LevelRead}, {Kind: KindUser, Name: `home\ALICE`, Level: LevelWrite}},
		{{Kind: KindEveryone, Level: LevelRead}, {Kind: KindEveryone, Level: LevelWrite}},
		{{Kind: KindUser, Name: `a\b\c`, Level: LevelRead}},
	} {
		if _, err := CleanRules(bad); !isValidation(err) {
			t.Errorf("CleanRules(%+v) = %v", bad, err)
		}
	}

	for in, want := range map[string]string{"": "", "/": "", "Movies": "Movies", "/Movies/Kids/": "Movies/Kids"} {
		if got, err := CleanFolder(in); err != nil || got != want {
			t.Errorf("CleanFolder(%q) = %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"..", "Movies/../..", "a//b", "./a", "a\x00b"} {
		if _, err := CleanFolder(bad); err == nil {
			t.Errorf("CleanFolder(%q) accepted", bad)
		}
	}
}

func TestListParsesShares(t *testing.T) {
	m, f, _, _ := newManager(t)
	onList(f, "", rows(
		row{ds: "tank/shares/media", name: "Media", desc: "Films", access: `[{"kind":"everyone","level":"read"}]`,
			apps: `[{"app":"jellyfin","uid":30001,"level":"read"}]`, recycle: true, quota: "1073741824", used: "4096", mounted: true},
		row{ds: "vault/shares/backups", name: "Backups", access: "not json", mounted: false},
	))
	l, err := m.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 2 {
		t.Fatalf("got %d shares: %+v", len(l), l)
	}
	b, md := l[0], l[1] // sorted by name
	if md.ID != "media" || md.Pool != "tank" || md.Path != "/mnt/tank/shares/media" || !md.Mounted || md.QuotaBytes != 1<<30 ||
		md.UsedBytes != 4096 || !md.Recycle || md.Guest || md.Description != "Films" || len(md.Access) != 1 ||
		md.Apps[0].UID != 30001 || md.CreatedAt.Year() != 2026 {
		t.Errorf("media = %+v", md)
	}
	if b.ID != "backups" || b.Mounted || b.Description != "" || b.Access == nil || len(b.Access) != 0 {
		t.Errorf("backups = %+v", b)
	}
	if _, err := m.Get(context.Background(), "stray"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a dataset without the share property was found: %v", err)
	}
}

func TestCreate(t *testing.T) {
	m, f, root, _ := newManager(t)
	ctx := context.Background()
	ds := "tank/shares/family-photos"
	onList(f, "", rows(row{ds: "tank/shares/media", name: "Media", mounted: true}))
	f.On("zfs list -H -o name tank", "tank\n")
	f.OnResult("zfs list -H -o name tank/shares", sysexec.Result{ExitCode: 1, Stderr: []byte("dataset does not exist")})
	f.On("zfs create -o org.hardyos:role=shares tank/shares", "")
	f.On("zfs get -H -o source compression tank", "local\n")
	f.OnPrefix("zfs create -o acltype=posixacl", sysexec.Result{})
	onList(f, ds, row{ds: ds, name: "Family Photos", desc: "Everyone's photos", recycle: true, quota: "5368709120", mounted: true}.String()+"\n")
	mkdir(t, filepath.Join(root, "mnt", ds))

	sh, err := m.Create(ctx, NewShare{Pool: "tank", Name: " Family  Photos", Description: "Everyone's photos", QuotaBytes: 5 << 30, Recycle: true,
		Access: []Rule{{Kind: KindGroup, Name: `HOME\Family`, Level: LevelWrite}}, Subfolders: []string{"2025", "2026"}})
	if err != nil {
		t.Fatal(err)
	}
	if sh.ID != "family-photos" || sh.Name != "Family Photos" || sh.QuotaBytes != 5<<30 {
		t.Errorf("share = %+v", sh)
	}
	want := `zfs create -o acltype=posixacl -o xattr=sa -o aclinherit=passthrough -o devices=off -o setuid=off -o quota=5368709120 ` +
		`-o org.hardyos:share=1 -o org.hardyos:name=Family Photos -o org.hardyos:description=Everyone's photos ` +
		`-o org.hardyos:access=[{"kind":"group","name":"HOME\\Family","level":"write"}] -o org.hardyos:apps=[] ` +
		`-o org.hardyos:recycle=on -o org.hardyos:guest=off ` +
		`-o org.hardyos:services={"smb":{"enabled":true,"timeMachine":false,"timeMachineMaxBytes":0,"previousVersions":true},` +
		`"nfs":{"enabled":false,"clients":[]},"snapshots":{"hourly":24,"daily":14,"weekly":8,"monthly":6}} ` + ds
	if !slices.Contains(f.Lines(), want) {
		t.Errorf("create command missing:\nwant %s\ngot  %s", want, strings.Join(f.Lines(), "\n     "))
	}
	if !slices.Contains(f.Lines(), "zfs create -o org.hardyos:role=shares tank/shares") {
		t.Error("the shares parent dataset wasn't created")
	}
	for _, sub := range []string{"2025", "2026"} {
		if fi, err := os.Stat(filepath.Join(root, "mnt", ds, sub)); err != nil || !fi.IsDir() {
			t.Errorf("subfolder %s: %v", sub, err)
		}
	}

	// Duplicates by id and by name (any case), on any pool.
	onList(f, "", rows(row{ds: "tank/shares/media", name: "Media", mounted: true}, row{ds: "vault/shares/photos", name: "Photos", mounted: true}))
	for _, a := range []NewShare{{Pool: "tank", Name: "Media Two", ID: "media"}, {Pool: "tank", Name: "photos", ID: "pics"}} {
		if _, err := m.Create(ctx, a); !isValidation(err) || !strings.Contains(err.Error(), "already") {
			t.Errorf("Create(%+v) = %v", a, err)
		}
	}
	// A missing pool.
	f.OnResult("zfs list -H -o name nopool", sysexec.Result{ExitCode: 1})
	if _, err := m.Create(ctx, NewShare{Pool: "nopool", Name: "Docs"}); !isValidation(err) || !strings.Contains(err.Error(), "no pool called nopool") {
		t.Errorf("missing pool: %v", err)
	}
}

// listArgsLine is the command line rereading one dataset.
func (m *Manager) listArgsLine(ds string) string { return "zfs " + strings.Join(m.listArgs(ds), " ") }

func TestCreateUsesLZ4WhenThePoolHasNoCompression(t *testing.T) {
	m, f, _, _ := newManager(t)
	ds := "tank/shares/docs"
	onList(f, "", rows())
	f.On("zfs list -H -o name tank", "tank\n")
	f.On("zfs list -H -o name tank/shares", "tank/shares\n")
	f.On("zfs get -H -o source compression tank", "default\n")
	f.OnPrefix("zfs create ", sysexec.Result{})
	onList(f, ds, row{ds: ds, name: "Docs", mounted: true}.String())
	if _, err := m.Create(context.Background(), NewShare{Pool: "tank", Name: "Docs"}); err != nil {
		t.Fatal(err)
	}
	var create string
	for _, l := range f.Lines() {
		if strings.HasPrefix(l, "zfs create ") {
			create = l
		}
	}
	if !strings.Contains(create, "-o compression=lz4") || strings.Contains(create, "quota=") || strings.Contains(create, "description") {
		t.Errorf("create = %s", create)
	}
}

func TestUpdate(t *testing.T) {
	m, f, _, _ := newManager(t)
	ctx := context.Background()
	ds := "tank/shares/media"
	onList(f, "", rows(row{ds: ds, name: "Media", desc: "Films", used: "3221225472", mounted: true}, row{ds: "tank/shares/backups", name: "Backups", mounted: true}))
	f.OnPrefix("zfs set ", sysexec.Result{})
	f.On("zfs inherit org.hardyos:description "+ds, "")
	onList(f, ds, row{ds: ds, name: "Movies", mounted: true}.String())

	name, desc, quota, guest := "Movies", "", uint64(10<<30), true
	rules := []Rule{{Kind: KindUser, Name: `HOME\alice`, Level: LevelWrite}}
	if _, err := m.Update(ctx, ShareUpdate{ID: "media", Name: &name, Description: &desc, QuotaBytes: &quota, Guest: &guest, Access: &rules}); err != nil {
		t.Fatal(err)
	}
	want := `zfs set org.hardyos:name=Movies quota=10737418240 org.hardyos:guest=on org.hardyos:access=[{"kind":"user","name":"HOME\\alice","level":"write"}] ` + ds
	if !slices.Contains(f.Lines(), want) {
		t.Errorf("set missing:\nwant %s\ngot  %s", want, strings.Join(f.Lines(), "\n     "))
	}
	if !slices.Contains(f.Lines(), "zfs inherit org.hardyos:description "+ds) {
		t.Error("an empty description should be cleared with zfs inherit")
	}

	small := uint64(1 << 30)
	if _, err := m.Update(ctx, ShareUpdate{ID: "media", QuotaBytes: &small}); !isValidation(err) || !strings.Contains(err.Error(), "already holds 3.0 GB") {
		t.Errorf("quota below used: %v", err)
	}
	taken := "backups"
	if _, err := m.Update(ctx, ShareUpdate{ID: "media", Name: &taken}); !isValidation(err) {
		t.Errorf("name clash: %v", err)
	}
	none := uint64(0)
	if _, err := m.Update(ctx, ShareUpdate{ID: "media", QuotaBytes: &none}); err != nil || !slices.Contains(f.Lines(), "zfs set quota=none "+ds) {
		t.Errorf("removing the quota: %v", err)
	}
	if _, err := m.Update(ctx, ShareUpdate{ID: "ghost"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing share: %v", err)
	}
}

func TestDeleteNeedsTheNameAndNoApps(t *testing.T) {
	m, f, _, _ := newManager(t)
	ctx := context.Background()
	onList(f, "", rows(
		row{ds: "tank/shares/media", name: "Media", apps: `[{"app":"jellyfin","uid":30001,"level":"read"},{"app":"plex","uid":30002,"level":"read"}]`, mounted: true},
		row{ds: "tank/shares/old-stuff", name: "Old Stuff", mounted: true},
	))
	f.On("zfs destroy -r tank/shares/old-stuff", "")

	if err := m.Delete(ctx, "old-stuff", "Old"); !isValidation(err) || !strings.Contains(err.Error(), "(Old Stuff)") {
		t.Errorf("wrong confirmation: %v", err)
	}
	if err := m.Delete(ctx, "old-stuff", ""); !isValidation(err) {
		t.Errorf("no confirmation: %v", err)
	}
	if err := m.Delete(ctx, "media", "Media"); !isValidation(err) || !strings.Contains(err.Error(), "jellyfin and plex use Media") {
		t.Errorf("share used by apps: %v", err)
	}
	for _, l := range f.Lines() {
		if strings.HasPrefix(l, "zfs destroy") {
			t.Fatalf("destroyed without a valid confirmation: %s", l)
		}
	}
	if err := m.Delete(ctx, "old-stuff", " old  stuff "); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.Lines(), "zfs destroy -r tank/shares/old-stuff") {
		t.Error("not destroyed")
	}
	if err := m.Delete(ctx, "ghost", "Ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing share: %v", err)
	}
}

func TestStarter(t *testing.T) {
	m, f, root, _ := newManager(t)
	ctx := context.Background()
	onList(f, "", rows())
	f.On("zfs list -H -o name tank", "tank\n")
	f.On("zfs list -H -o name tank/shares", "tank/shares\n")
	f.On("zfs get -H -o source compression tank", "local\n")
	f.OnPrefix("zfs create ", sysexec.Result{})
	onList(f, "tank/shares/media", row{ds: "tank/shares/media", name: "Media", recycle: true, mounted: true}.String())
	onList(f, "tank/shares/backups", row{ds: "tank/shares/backups", name: "Backups", mounted: true}.String())
	mkdir(t, filepath.Join(root, "mnt/tank/shares/media"))

	if _, err := m.CreateStarter(ctx, StarterArgs{Pool: "tank"}); !isValidation(err) {
		t.Errorf("nothing chosen: %v", err)
	}
	made, err := m.CreateStarter(ctx, StarterArgs{Pool: "tank", Media: true, Backups: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(made) != 2 || made[0].ID != "media" || made[1].ID != "backups" {
		t.Fatalf("made = %+v", made)
	}
	for _, sub := range []string{"Movies", "TV", "Music", "Photos"} {
		if _, err := os.Stat(filepath.Join(root, "mnt/tank/shares/media", sub)); err != nil {
			t.Errorf("Media/%s: %v", sub, err)
		}
	}
	var creates []string
	for _, l := range f.Lines() {
		if strings.HasPrefix(l, "zfs create ") {
			creates = append(creates, l)
		}
	}
	if len(creates) != 2 || !strings.Contains(creates[0], `org.hardyos:access=[{"kind":"everyone","level":"read"}]`) ||
		!strings.Contains(creates[0], "org.hardyos:recycle=on") || !strings.Contains(creates[1], "org.hardyos:access=[] ") {
		t.Errorf("creates = %v", creates)
	}

	// Already there: only what's missing is made, and nothing at all is an error.
	onList(f, "", rows(row{ds: "tank/shares/media", name: "Media", mounted: true}))
	made, err = m.CreateStarter(ctx, StarterArgs{Pool: "tank", Media: true, Backups: true})
	if err != nil || len(made) != 1 || made[0].ID != "backups" {
		t.Errorf("second starter = %+v %v", made, err)
	}
	onList(f, "", rows(row{ds: "tank/shares/media", name: "Media", mounted: true}, row{ds: "vault/shares/backups", name: "Backups", mounted: true}))
	if _, err := m.CreateStarter(ctx, StarterArgs{Pool: "tank", Media: true, Backups: true}); !isValidation(err) || !strings.Contains(err.Error(), "Media and Backups already exist") {
		t.Errorf("everything exists: %v", err)
	}
}

func TestGrantAndRevoke(t *testing.T) {
	m, f, root, calls := newManager(t)
	ctx := context.Background()
	media := filepath.Join(root, "mnt/tank/shares/media")
	mkdir(t, media)
	onList(f, "", rows(
		row{ds: "tank/shares/media", name: "Media", apps: `[{"app":"plex","uid":30002,"level":"read"}]`, mounted: true},
		row{ds: "tank/shares/offline", name: "Offline", mounted: false},
	))
	f.OnPrefix("setfacl ", sysexec.Result{})
	f.OnPrefix("zfs set ", sysexec.Result{})

	for _, bad := range []struct {
		app string
		uid int
	}{{"Jellyfin", 30001}, {"jellyfin", 0}, {"jellyfin", 1000}, {"jellyfin", 31000}} {
		if err := m.GrantApp(ctx, "media", bad.app, bad.uid, false); !isValidation(err) {
			t.Errorf("GrantApp(%s, %d) = %v", bad.app, bad.uid, err)
		}
	}
	if err := m.GrantApp(ctx, "offline", "jellyfin", 30001, false); err == nil || !strings.Contains(err.Error(), "isn't available") {
		t.Errorf("unmounted share: %v", err)
	}
	if err := m.GrantApp(ctx, "ghost", "jellyfin", 30001, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing share: %v", err)
	}

	if err := m.GrantApp(ctx, "media", "jellyfin", 30001, false); err != nil {
		t.Fatal(err)
	}
	if err := m.GrantApp(ctx, "media", "sonarr", 30003, true); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	lines := f.Lines()
	for _, want := range []string{
		"setfacl -m u:30001:r-X,d:u:30001:r-X -- " + media,
		`zfs set org.hardyos:apps=[{"app":"jellyfin","uid":30001,"level":"read"},{"app":"plex","uid":30002,"level":"read"}] tank/shares/media`,
		"setfacl -m u:30003:rwX,d:u:30003:rwX -- " + media,
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("missing %s\ngot %s", want, strings.Join(lines, "\n    "))
		}
	}
	if !slices.Contains(*calls, treeCall{media, 30001, false, false}) || !slices.Contains(*calls, treeCall{media, 30003, true, false}) {
		t.Errorf("background walks = %+v", *calls)
	}

	// Revoke takes plex off every share that has it.
	onList(f, "", rows(
		row{ds: "tank/shares/media", name: "Media", apps: `[{"app":"jellyfin","uid":30001,"level":"read"},{"app":"plex","uid":30002,"level":"read"}]`, mounted: true},
		row{ds: "tank/shares/movies", name: "Movies", apps: `[{"app":"plex","uid":30002,"level":"write"}]`, mounted: true},
		row{ds: "tank/shares/docs", name: "Docs", mounted: true},
	))
	*calls = nil
	movies := filepath.Join(root, "mnt/tank/shares/movies")
	mkdir(t, movies)
	before := len(f.Lines())
	if err := m.RevokeApp(ctx, "plex"); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	lines = f.Lines()[before:]
	for _, want := range []string{
		"setfacl -x u:30002,d:u:30002 -- " + media,
		`zfs set org.hardyos:apps=[{"app":"jellyfin","uid":30001,"level":"read"}] tank/shares/media`,
		"setfacl -x u:30002,d:u:30002 -- " + movies,
		`zfs set org.hardyos:apps=[] tank/shares/movies`,
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("missing %s\ngot %s", want, strings.Join(lines, "\n    "))
		}
	}
	for _, l := range lines {
		if strings.Contains(l, "docs") {
			t.Errorf("a share without the app was touched: %s", l)
		}
	}
	if len(*calls) != 2 || !(*calls)[0].revoke {
		t.Errorf("background revokes = %+v", *calls)
	}
	if err := m.RevokeApp(ctx, "not an app"); !isValidation(err) {
		t.Errorf("bad app id: %v", err)
	}

	// An unmounted share keeps the record (its ACL is still on disk) ...
	onList(f, "", rows(row{ds: "tank/shares/offline", name: "Offline", apps: `[{"app":"plex","uid":30002,"level":"write"}]`, mounted: false}))
	before = len(f.Lines())
	if err := m.RevokeApp(ctx, "plex"); err != nil {
		t.Fatal(err)
	}
	for _, l := range f.Lines()[before:] {
		if strings.HasPrefix(l, "zfs set") || strings.HasPrefix(l, "setfacl") {
			t.Errorf("unmounted share changed: %s", l)
		}
	}
	// ... and the next app given that user ID takes the record over.
	onList(f, "", rows(row{ds: "tank/shares/offline", name: "Offline", apps: `[{"app":"plex","uid":30002,"level":"write"}]`, mounted: true}))
	mkdir(t, filepath.Join(root, "mnt/tank/shares/offline"))
	before = len(f.Lines())
	if err := m.GrantApp(ctx, "offline", "radarr", 30002, false); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if want := `zfs set org.hardyos:apps=[{"app":"radarr","uid":30002,"level":"read"}] tank/shares/offline`; !slices.Contains(f.Lines()[before:], want) {
		t.Errorf("missing %s\ngot %s", want, strings.Join(f.Lines()[before:], "\n    "))
	}
}

func TestResolveStaysInsideTheShare(t *testing.T) {
	m, f, root, _ := newManager(t)
	ctx := context.Background()
	onList(f, "", rows(row{ds: "tank/shares/media", name: "Media", mounted: true}, row{ds: "tank/shares/off", name: "Off"}))
	base := filepath.Join(root, "mnt/tank/shares/media")
	mkdir(t, filepath.Join(base, "Movies/Kids"))
	mkdir(t, filepath.Join(base, "TV"))
	mkdir(t, filepath.Join(base, ".recycle"))
	outside := t.TempDir()
	mkdir(t, filepath.Join(root, "mnt/tank/shares/media-other"))
	if err := os.WriteFile(filepath.Join(base, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		"escape":   outside,
		"etc":      "/etc",
		"sneaky":   "../media-other", // a sibling whose name starts like the share
		"Cartoons": "Movies/Kids",    // inside: fine
		"up":       "..",
	} {
		if err := os.Symlink(target, filepath.Join(base, link)); err != nil {
			t.Fatal(err)
		}
	}

	if p, err := m.Resolve(ctx, "media", ""); err != nil || p != "/mnt/tank/shares/media" {
		t.Errorf("share root = %q %v", p, err)
	}
	if p, err := m.Resolve(ctx, "media", "/Movies/Kids/"); err != nil || p != "/mnt/tank/shares/media/Movies/Kids" {
		t.Errorf("subfolder = %q %v", p, err)
	}
	if p, err := m.Resolve(ctx, "media", "Cartoons"); err != nil || p != "/mnt/tank/shares/media/Movies/Kids" {
		t.Errorf("a link inside the share resolves to its real path: %q %v", p, err)
	}
	for _, sub := range []string{"escape", "etc", "sneaky", "up", "escape/x", "../media-other", "Movies/../../media-other"} {
		if p, err := m.Resolve(ctx, "media", sub); err == nil {
			t.Errorf("Resolve(%q) = %q, want a refusal", sub, p)
		}
	}
	if _, err := m.Resolve(ctx, "media", "notes.txt"); err == nil || !strings.Contains(err.Error(), "is a file") {
		t.Errorf("file: %v", err)
	}
	if _, err := m.Resolve(ctx, "media", "Nope"); err == nil || !strings.Contains(err.Error(), "no folder Nope") {
		t.Errorf("missing folder: %v", err)
	}
	if _, err := m.Resolve(ctx, "off", ""); err == nil || !strings.Contains(err.Error(), "isn't available") {
		t.Errorf("unmounted: %v", err)
	}

	folders, err := m.Folders(ctx, "media", "")
	if err != nil || !slices.Equal(folders, []string{"Movies", "TV"}) {
		t.Errorf("folders = %v %v (no links, files or hidden folders)", folders, err)
	}
	if folders, err := m.Folders(ctx, "media", "Movies"); err != nil || !slices.Equal(folders, []string{"Kids"}) {
		t.Errorf("folders in Movies = %v %v", folders, err)
	}
	if _, err := m.Folders(ctx, "media", "escape"); err == nil {
		t.Error("listed a folder outside the share")
	}
}

func TestCheckServices(t *testing.T) {
	ok := DefaultServices()
	ok.NFS = NFS{Enabled: true, Clients: []NFSRule{{Client: " 192.168.1.7/24 ", Access: LevelWrite}, {Client: "fd00::5", Access: LevelRead}}}
	got, err := CheckServices(ok)
	if err != nil || got.NFS.Clients[0].Client != "192.168.1.0/24" || got.NFS.Clients[1].Client != "fd00::5" {
		t.Errorf("clean = %+v %v", got.NFS, err)
	}
	for name, s := range map[string]Services{
		"time machine without smb": {SMB: SMB{TimeMachine: true}},
		"nfs on, nobody allowed":   {NFS: NFS{Enabled: true}},
		"nfs to everyone":          {NFS: NFS{Clients: []NFSRule{{Client: "0.0.0.0/0", Access: LevelRead}}}},
		"nfs bad access":           {NFS: NFS{Clients: []NFSRule{{Client: "10.0.0.1", Access: "admin"}}}},
		"nfs twice":                {NFS: NFS{Clients: []NFSRule{{Client: "10.0.0.0/8", Access: LevelRead}, {Client: "10.1.2.3/8", Access: LevelRead}}}},
		"too many hourly":          {Snapshots: Snapshots{Hourly: 1000}},
		"negative":                 {Snapshots: Snapshots{Daily: -1}},
	} {
		if _, err := CheckServices(s); !isValidation(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
