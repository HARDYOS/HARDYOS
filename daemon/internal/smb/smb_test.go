package smb

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

var update = flag.Bool("update", false, "rewrite golden files")

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Errorf("%s differs (go test -run %s -update to accept):\n%s", name, t.Name(), got)
	}
}

var home = Domain{Domain: "home.example.net", Realm: "HOME.EXAMPLE.NET", NetBIOS: "HOME", DCs: []string{"192.168.1.20", "192.168.1.21"}}

func TestRenderConfGolden(t *testing.T) {
	in := confInput{
		Domain: home, ServerName: "HARDYOS", Port: 445, HomesPath: "/mnt/tank/homes",
		Dirs: Dirs{Private: "/var/lib/hardyos-files/samba/private", State: "/var/lib/hardyos-files/samba/state",
			Cache: "/var/lib/hardyos-files/samba/cache", Lock: "/var/lib/hardyos-files/samba/lock",
			Keytab: "/var/lib/hardyos-files/samba/krb5.keytab"},
		Shares: []shareConf{
			{
				Name: "Media", Path: "/mnt/tank/shares/media", Comment: "Movies, TV shows, music and photos",
				Valid: []string{`@HOME\Domain Admins`, `@HOME\Domain Users`, "nobody"}, Read: []string{`@HOME\Domain Users`, "nobody"},
				Write: []string{`@HOME\Domain Admins`}, Guest: true, Recycle: true, PreviousVersions: true,
			},
			{
				// Every character a shared folder's name may have, and a
				// description trying to break out of its line.
				Name: "Kids' Films & TV (2024) v.2_x-y", Path: "/mnt/tank/shares/kids-films-tv-2024-v-2-x-y",
				Comment: "50% off \"quotes\" back\\\nslash \\",
				Valid:   []string{`@HOME\Domain Admins`, `HOME\alice`, `@HOME\Family`}, Read: []string{`@HOME\Family`},
				Write: []string{`@HOME\Domain Admins`, `HOME\alice`}, Invalid: []string{`HOME\bob`},
				Recycle: true,
			},
			{
				Name: "Backups", Path: "/mnt/tank/shares/backups",
				Valid: []string{`@HOME\Domain Admins`, `@HOME\Domain Users`}, Write: []string{`@HOME\Domain Admins`, `@HOME\Domain Users`},
				Recycle: true, TimeMachine: true, TimeMachineMaxBytes: 500 << 30, PreviousVersions: true,
			},
		},
	}
	got := renderConf(in)
	golden(t, "smb.conf.golden", got)
	for _, bad := range []string{"50%", "\\\n", `"quotes"`} {
		if strings.Contains(got, bad) {
			t.Errorf("free text leaked %q into smb.conf", bad)
		}
	}
	// No line may end in a backslash (Samba would join it with the next).
	for _, l := range strings.Split(got, "\n") {
		if strings.HasSuffix(l, `\`) {
			t.Errorf("line continues: %q", l)
		}
	}
	// Recycle bin never on Time Machine folders.
	backups := got[strings.Index(got, "[Backups]"):]
	backups = backups[:strings.Index(backups, "\n\n")]
	if strings.Contains(backups, "recycle:") || strings.Contains(backups, " recycle\n") {
		t.Error("Time Machine folder has a recycle bin")
	}
	if !strings.Contains(got, "fruit:time machine max size = 512000M") {
		t.Error("Time Machine size missing")
	}
	// Without guest folders nobody may connect anonymously.
	in.Shares = in.Shares[1:]
	in.HomesPath = ""
	got2 := renderConf(in)
	if !strings.Contains(got2, "restrict anonymous = 2") || strings.Contains(got2, "[homes]") || !strings.Contains(got2, "template homedir = /nonexistent") {
		t.Error("no-guest, no-homes config wrong")
	}
	if globalSection(got) == globalSection(got2) {
		t.Error("global sections should differ")
	}
}

func TestMapLists(t *testing.T) {
	rules := []shares.Rule{
		{Kind: shares.KindEveryone, Level: shares.LevelRead},
		{Kind: shares.KindUser, Name: `home\alice`, Level: shares.LevelWrite},
		{Kind: shares.KindGroup, Name: `HOME\Family`, Level: shares.LevelWrite},
		{Kind: shares.KindUser, Name: `HOME\bob`, Level: shares.LevelNone},
		{Kind: shares.KindUser, Name: `admin`, Level: shares.LevelWrite},          // a HardyOS account
		{Kind: shares.KindUser, Name: `WORK\carol`, Level: shares.LevelRead},      // another domain
		{Kind: shares.KindGroup, Name: `HOME\Teenagers`, Level: shares.LevelNone}, // no access group
	}
	l := mapLists("home", rules, true, "S-1-5-21-1-2-3-1105")
	want := shareLists{
		Valid:   []string{`@HOME\Domain Admins`, "S-1-5-21-1-2-3-1105", `@HOME\Domain Users`, `HOME\alice`, `@HOME\Family`, "nobody"},
		Read:    []string{`@HOME\Domain Users`, "nobody"},
		Write:   []string{`@HOME\Domain Admins`, "S-1-5-21-1-2-3-1105", `HOME\alice`, `@HOME\Family`},
		Invalid: []string{`HOME\bob`, `@HOME\Teenagers`},
		Skipped: []string{"admin", `WORK\carol`},
	}
	if !reflect.DeepEqual(l, want) {
		t.Errorf("got  %#v\nwant %#v", l, want)
	}
	// No rules: administrators only.
	l = mapLists("HOME", nil, false, "")
	if !reflect.DeepEqual(l.Valid, []string{`@HOME\Domain Admins`}) || len(l.Read) != 0 {
		t.Errorf("admins only: %#v", l)
	}
}

type fakeNames map[string]uint32

func (f fakeNames) get(n string) (uint32, error) {
	if id, ok := f[strings.ToLower(n)]; ok {
		return id, nil
	}
	return 0, &ErrUnknownName{Name: n}
}
func (f fakeNames) UserID(n string) (uint32, error)       { return f.get("u:" + n) }
func (f fakeNames) GroupID(n string) (uint32, error)      { return f.get("g:" + n) }
func (f fakeNames) GroupIDBySID(s string) (uint32, error) { return f.get("s:" + s) }

var names = fakeNames{
	`g:home\domain admins`: 100512, `g:home\domain users`: 100513, `g:home\family`: 101110,
	`u:home\alice`: 101103, `u:home\bob`: 101104, "s:s-1-5-21-1-2-3-1105": 101105,
}

func TestShareACL(t *testing.T) {
	rules := []shares.Rule{
		{Kind: shares.KindEveryone, Level: shares.LevelRead},
		{Kind: shares.KindUser, Name: `HOME\alice`, Level: shares.LevelWrite},
		{Kind: shares.KindGroup, Name: `HOME\Family`, Level: shares.LevelWrite},
		{Kind: shares.KindUser, Name: `HOME\bob`, Level: shares.LevelNone},
		{Kind: shares.KindGroup, Name: `HOME\Family`, Level: shares.LevelRead}, // same ID twice: the generous one
		{Kind: shares.KindUser, Name: `HOME\gone`, Level: shares.LevelRead},    // deleted account
	}
	p, skipped, err := shareACL("HOME", rules, true, "S-1-5-21-1-2-3-1105", names)
	if err != nil {
		t.Fatal(err)
	}
	want := []shares.PersonEntry{
		{Group: true, ID: 100512, Level: "write"}, {Group: true, ID: 101105, Level: "write"},
		{Group: true, ID: 100513, Level: "read"}, {ID: 101103, Level: "write"},
		{Group: true, ID: 101110, Level: "write"}, {ID: 101104, Level: "none"}, {ID: NobodyUID, Level: "read"},
	}
	if !reflect.DeepEqual(p.Entries, want) {
		t.Errorf("entries %+v\nwant    %+v", p.Entries, want)
	}
	if !reflect.DeepEqual(skipped, []string{`HOME\gone`}) {
		t.Errorf("skipped %v", skipped)
	}
	for _, c := range []struct {
		group bool
		id    uint32
		want  bool
	}{{true, 100513, true}, {false, 30001, false}, {false, 31000, false}, {false, 29999, false}, {false, NobodyUID, true}, {true, 3001, true}, {false, 0, false}} {
		if got := p.Managed(c.group, c.id); got != c.want {
			t.Errorf("managed(%v, %d) = %v", c.group, c.id, got)
		}
	}
	// Winbind down: change nothing.
	if _, _, err := shareACL("HOME", rules, false, "", fakeNames{}); err == nil {
		t.Error("an unknown Domain Admins must stop the update")
	}
}

func TestAddWinbindNSS(t *testing.T) {
	in := "# comment passwd: files\npasswd:         files systemd\ngroup:          files systemd\nshadow:         files\n"
	out, changed := addWinbindNSS(in)
	if !changed || !strings.Contains(out, "passwd:         files systemd winbind\n") || !strings.Contains(out, "group:          files systemd winbind\n") ||
		!strings.Contains(out, "# comment passwd: files\n") {
		t.Errorf("got %q", out)
	}
	if _, again := addWinbindNSS(out); again {
		t.Error("not idempotent")
	}
	out, _ = addWinbindNSS("")
	if !strings.Contains(out, "passwd:         files winbind") || !strings.Contains(out, "files winbind\n") {
		t.Errorf("empty file: %q", out)
	}
}

type fakeShares struct{ l []shares.Share }

func (f *fakeShares) List(context.Context) ([]shares.Share, error) { return f.l, nil }

func newTestManager(t *testing.T, f *sysexec.Fake, l []shares.Share) *Manager {
	dir := t.TempDir()
	return &Manager{
		Runner: f, Shares: &fakeShares{l: l},
		DataDir: filepath.Join(dir, "data"), ConfPath: filepath.Join(dir, "smb.conf"),
		Krb5Conf: filepath.Join(dir, "krb5.conf"), NSSwitch: filepath.Join(dir, "nsswitch.conf"),
		AvahiService: filepath.Join(dir, "avahi", "hardyos-smb.service"),
		ServerName:   "hardyos", NoDataset: true, Installed: func() bool { return true },
		LocalDomain: func() *Domain { d := home; return &d },
		resolver:    names,
		walk: func(context.Context, string, shares.PeopleACL) (shares.PeopleStats, error) {
			return shares.PeopleStats{}, nil
		},
	}
}

func okFake() *sysexec.Fake {
	f := &sysexec.Fake{}
	for _, p := range []string{"testparm ", "systemctl ", "wbinfo ", "net ads join", "net ads leave", "smbcontrol "} {
		f.OnPrefix(p, sysexec.Result{})
	}
	return f
}

func TestJoinNeverPutsThePasswordInArgv(t *testing.T) {
	const pw = "S3cret-Passw0rd!"
	f := okFake()
	m := newTestManager(t, f, nil)
	st, err := m.Join(context.Background(), JoinArgs{AdminPassword: pw})
	if err != nil {
		t.Fatal(err)
	}
	if !st.Joined || st.Domain.NetBIOS != "HOME" || st.ServerName != "HARDYOS" {
		t.Errorf("status %+v", st)
	}
	joined := false
	for _, c := range f.Calls {
		if strings.Contains(c.Line, pw) {
			t.Errorf("password on a command line: %s", c.Line)
		}
		for _, e := range c.Env {
			if strings.Contains(e, pw) {
				t.Errorf("password in the environment: %s", e)
			}
		}
		if strings.HasPrefix(c.Line, "net ads join") {
			joined = true
			if string(c.Stdin) != pw+"\n" || !reflect.DeepEqual(c.Env, []string{"PASSWD_FD=0"}) || !strings.Contains(c.Line, "-U Administrator") {
				t.Errorf("join call: %q stdin %q env %v", c.Line, c.Stdin, c.Env)
			}
		}
	}
	if !joined {
		t.Fatal("net ads join never ran")
	}
	for _, p := range []string{m.confPath(), m.krb5Conf(), filepath.Join(m.dataDir(), "state.json")} {
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), pw) {
			t.Errorf("%s holds the password", p)
		}
	}
	krb, _ := os.ReadFile(m.krb5Conf())
	if !strings.Contains(string(krb), "default_realm = HOME.EXAMPLE.NET") || !strings.Contains(string(krb), "kdc = 192.168.1.20") {
		t.Errorf("krb5.conf:\n%s", krb)
	}
	conf, _ := os.ReadFile(m.confPath())
	if !strings.Contains(string(conf), "password server = 192.168.1.20 192.168.1.21 *") {
		t.Errorf("smb.conf:\n%s", conf)
	}
	if _, err := m.Join(context.Background(), JoinArgs{AdminPassword: pw}); err == nil {
		t.Error("joined twice")
	}
}

func TestJoinWrongPassword(t *testing.T) {
	f := &sysexec.Fake{}
	f.OnPrefix("testparm ", sysexec.Result{}).OnPrefix("systemctl ", sysexec.Result{})
	f.OnPrefix("net ads join", sysexec.Result{ExitCode: 255, Stderr: []byte("Failed to join domain: failed to lookup DC info for domain 'HOME.EXAMPLE.NET' over rpc: The attempted logon is invalid.")})
	m := newTestManager(t, f, nil)
	_, err := m.Join(context.Background(), JoinArgs{AdminPassword: "nope"})
	if _, ok := err.(*ValidationError); !ok || !strings.Contains(err.Error(), "isn't right") {
		t.Fatalf("err = %v", err)
	}
	if m.loadState().Joined {
		t.Error("marked joined after a failed join")
	}
	if _, err := m.Join(context.Background(), JoinArgs{AdminPassword: "a\nb"}); err == nil {
		t.Error("line break accepted")
	}
}

func TestJoinOtherDomainLooksUpShortName(t *testing.T) {
	f := okFake()
	f.OnPrefix("net ads lookup", sysexec.Result{Stdout: []byte("Domain: work.example.org\nPre-Win2k Domain: WORK\nPre-Win2k Hostname: DC1\n")})
	m := newTestManager(t, f, nil)
	st, err := m.Join(context.Background(), JoinArgs{Domain: "Work.Example.org.", AdminPassword: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Domain.NetBIOS != "WORK" || st.Domain.Realm != "WORK.EXAMPLE.ORG" || len(st.Domain.DCs) != 0 {
		t.Errorf("domain %+v", st.Domain)
	}
}

func TestApplySharesAndLeave(t *testing.T) {
	root := t.TempDir()
	media := filepath.Join(root, "media")
	backups := filepath.Join(root, "backups")
	_ = os.Mkdir(media, 0o755)
	_ = os.Mkdir(backups, 0o755)
	sv := shares.DefaultServices()
	tm := shares.DefaultServices()
	tm.SMB.TimeMachine = true
	off := shares.DefaultServices()
	off.SMB.Enabled = false
	l := []shares.Share{
		{ID: "media", Name: "Media", Dataset: "tank/shares/media", Path: media, Mounted: true, Recycle: true, Guest: true,
			Access: []shares.Rule{{Kind: shares.KindEveryone, Level: shares.LevelRead}}, Services: sv},
		{ID: "backups", Name: "Backups", Dataset: "tank/shares/backups", Path: backups, Mounted: true, Services: tm},
		{ID: "private", Name: "Private", Dataset: "tank/shares/private", Path: "/nowhere", Mounted: true, Services: off},
		{ID: "gone", Name: "Gone", Dataset: "tank2/shares/gone", Mounted: false, Services: sv},
	}
	f := okFake()
	m := newTestManager(t, f, l)
	var (
		walkMu sync.Mutex
		walked []string
	)
	m.walk = func(_ context.Context, root string, p shares.PeopleACL) (shares.PeopleStats, error) {
		walkMu.Lock()
		walked = append(walked, root)
		walkMu.Unlock()
		return shares.PeopleStats{}, nil
	}
	_ = os.MkdirAll(filepath.Dir(m.avahiPath()), 0o755)
	if _, err := m.Join(context.Background(), JoinArgs{AdminPassword: "x"}); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	conf, _ := os.ReadFile(m.confPath())
	for _, want := range []string{"[Media]", "[Backups]", "path = " + media, "guest ok = yes", "fruit:time machine = yes"} {
		if !strings.Contains(string(conf), want) {
			t.Errorf("smb.conf lacks %q:\n%s", want, conf)
		}
	}
	for _, not := range []string{"[Private]", "[Gone]", "[homes]"} {
		if strings.Contains(string(conf), not) {
			t.Errorf("smb.conf has %q", not)
		}
	}
	av, _ := os.ReadFile(m.avahiPath())
	if !strings.Contains(string(av), "_adisk._tcp") || !strings.Contains(string(av), "dk0=adVN=Backups,adVF=0x82") {
		t.Errorf("avahi:\n%s", av)
	}
	walkMu.Lock()
	nWalked := len(walked)
	walkMu.Unlock()
	if nWalked == 0 {
		t.Error("no permission walk")
	}
	// A second apply with nothing changed doesn't reload or walk again
	// (when the root already has the entries; on file systems without
	// ACLs it walks again, harmlessly).
	n := len(f.Lines())
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, l := range f.Lines()[n:] {
		if strings.HasPrefix(l, "systemctl reload") || strings.HasPrefix(l, "systemctl restart") {
			t.Errorf("unchanged config reloaded: %s", l)
		}
	}
	// SMB off: smbd stops, no advertisement.
	no := false
	if _, err := m.SetSettings(context.Background(), SettingsArgs{SMBEnabled: &no}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.avahiPath()); err == nil {
		t.Error("still advertised with SMB off")
	}
	// Leaving needs confirming, and forgets the secrets.
	if _, err := m.Leave(context.Background(), LeaveArgs{}); err == nil {
		t.Error("left without confirming")
	}
	_ = os.WriteFile(filepath.Join(m.dirs().Private, "secrets.tdb"), []byte("x"), 0o600)
	if _, err := m.Leave(context.Background(), LeaveArgs{Confirm: true, AdminPassword: "pw"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.dirs().Private, "secrets.tdb")); err == nil {
		t.Error("secrets kept after leaving")
	}
	if m.loadState().Joined {
		t.Error("still joined")
	}
	for _, c := range f.Calls {
		if strings.Contains(c.Line, " pw") {
			t.Errorf("leave password in argv: %s", c.Line)
		}
	}
}

func TestHomes(t *testing.T) {
	root := t.TempDir()
	f := okFake()
	f.On("zfs list -H -o name tank", "tank\n")
	f.OnResult("zfs list -H -o name tank/homes", sysexec.Result{ExitCode: 1})
	f.OnPrefix("zfs create -o acltype=posixacl", sysexec.Result{})
	f.On("zfs get -H -o value mounted,mountpoint tank/homes", "yes\t"+root+"\n")
	f.OnPrefix("net ads search", sysexec.Result{Stdout: []byte("Got 4 replies\n\nsAMAccountName: Alice\n\nsAMAccountName: krbtgt\n\nsAMAccountName: bob\n\nsAMAccountName: PC1$\n\nsAMAccountName: bad name\n")})
	f.On("zfs list -H -o name -d 1 -r tank/homes", "tank/homes\ntank/homes/home.bob\n")
	f.OnPrefix("zfs create -o org.hardyos:home=", sysexec.Result{})
	m := newTestManager(t, f, nil)
	if _, err := m.Join(context.Background(), JoinArgs{AdminPassword: "x"}); err != nil {
		t.Fatal(err)
	}
	_ = os.Mkdir(filepath.Join(root, "home.alice"), 0o755) // "mounted" by zfs create
	st, err := m.SetSettings(context.Background(), SettingsArgs{Homes: &HomesSettings{Enabled: true, Pool: "tank", QuotaBytes: 50 << 30}})
	if err != nil {
		t.Fatal(err)
	}
	if !st.Settings.Homes.Enabled {
		t.Error("homes not saved")
	}
	var created []string
	for _, l := range f.Lines() {
		if strings.HasPrefix(l, "zfs create -o org.hardyos:home=") {
			created = append(created, l)
		}
	}
	if !reflect.DeepEqual(created, []string{`zfs create -o org.hardyos:home=HOME\alice -o quota=53687091200 tank/homes/home.alice`}) {
		t.Errorf("created %v", created)
	}
	conf, _ := os.ReadFile(m.confPath())
	if !strings.Contains(string(conf), "[homes]") || !strings.Contains(string(conf), "template homedir = "+root+"/home.%U") {
		t.Errorf("smb.conf:\n%s", conf)
	}
	if os.Geteuid() == 0 {
		fi, _ := os.Stat(filepath.Join(root, "home.alice"))
		if fi.Mode().Perm() != 0o700 {
			t.Errorf("home mode %v", fi.Mode())
		}
	}
	if _, err := m.SetSettings(context.Background(), SettingsArgs{Homes: &HomesSettings{Enabled: true, Pool: "no/such"}}); err == nil {
		t.Error("bad pool accepted")
	}
}

func TestCleanRecycle(t *testing.T) {
	share := t.TempDir()
	rb := filepath.Join(share, ".recycle", "alice", "Docs")
	if err := os.MkdirAll(rb, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-40 * 24 * time.Hour)
	oldFile := filepath.Join(rb, "old.txt")
	newFile := filepath.Join(rb, "new.txt")
	_ = os.WriteFile(oldFile, []byte("x"), 0o644)
	_ = os.WriteFile(newFile, []byte("x"), 0o644)
	_ = os.Chtimes(oldFile, old, old)
	outside := filepath.Join(t.TempDir(), "keep.txt")
	_ = os.WriteFile(outside, []byte("x"), 0o644)
	_ = os.Chtimes(outside, old, old)
	link := filepath.Join(share, ".recycle", "alice", "escape")
	_ = os.Symlink(filepath.Dir(outside), link)
	emptyOld := filepath.Join(share, ".recycle", "bob")
	_ = os.Mkdir(emptyOld, 0o755)
	_ = os.Chtimes(emptyOld, old, old)

	// Today everything here just arrived in the bin (ctimes are now; old
	// access/modification times alone don't make something old), so the
	// nightly run keeps it all.
	m := newTestManager(t, okFake(), []shares.Share{{ID: "s", Path: share, Mounted: true, Recycle: true}})
	n, err := m.CleanRecycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{oldFile, newFile, emptyOld} {
		if _, err := os.Stat(p); err != nil || n != 0 {
			t.Errorf("%s removed too early (removed %d)", p, n)
		}
	}
	// Once the cutoff passes their arrival, everything in the bin goes,
	// and nothing a link points to outside it.
	n, err = cleanRecycleDir(share, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{oldFile, newFile, emptyOld, link} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s kept after its time", p)
		}
	}
	if _, err := os.Stat(outside); err != nil {
		t.Error("followed a link out of the recycle bin")
	}
	if n != 3 {
		t.Errorf("removed %d, want the two files and the link", n)
	}
}

func TestServerName(t *testing.T) {
	for in, want := range map[string]string{"hardyos": "HARDYOS", "my_nas.local": "MY-NAS", "a-very-long-server-name": "A-VERY-LONG-SER", "--": "HARDYOS"} {
		if got := (&Manager{ServerName: in}).serverName(); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}
