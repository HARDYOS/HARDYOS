package nfs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func share(id string, mounted bool, clients ...shares.NFSRule) shares.Share {
	sv := shares.DefaultServices()
	sv.NFS = shares.NFS{Enabled: len(clients) > 0, Clients: clients}
	if sv.NFS.Clients == nil {
		sv.NFS.Clients = []shares.NFSRule{}
	}
	return shares.Share{ID: id, Name: id, Pool: "tank", Dataset: "tank/shares/" + id, Path: "/mnt/tank/shares/" + id, Mounted: mounted, Services: sv}
}

func rule(c, a string) shares.NFSRule { return shares.NFSRule{Client: c, Access: a} }

func TestRender(t *testing.T) {
	got, err := Render([]Export{
		{Share: "media", Path: "/mnt/tank/shares/media", UID: 31000, Clients: []shares.NFSRule{
			rule("192.168.1.0/24", "read"), rule("2001:db8::/64", "write"), rule("192.168.1.50", "write"),
			rule("10.0.0.0/8", "read"), rule("fd00::7", "read"), rule("192.168.0.0/16", "read"),
		}},
		{Share: "backups", Path: "/mnt/tank/shares/backups", UID: 31001, Clients: []shares.NFSRule{rule("::ffff:192.168.1.9", "write")}},
		{Share: "empty", Path: "/mnt/tank/shares/empty", UID: 31002},
	})
	if err != nil {
		t.Fatal(err)
	}
	opts := func(mode string, uid string) string {
		return "(" + mode + ",sync,no_subtree_check,all_squash,anonuid=" + uid + ",anongid=" + uid + ",sec=sys,insecure)"
	}
	want := header +
		"/mnt/tank/shares/media 192.168.1.50" + opts("rw", "31000") + " fd00::7" + opts("ro", "31000") +
		" 2001:db8::/64" + opts("rw", "31000") + " 192.168.1.0/24" + opts("ro", "31000") +
		" 192.168.0.0/16" + opts("ro", "31000") + " 10.0.0.0/8" + opts("ro", "31000") + "\n" +
		"/mnt/tank/shares/backups 192.168.1.9" + opts("rw", "31001") + "\n"
	if got != want {
		t.Errorf("exports =\n%s\nwant\n%s", got, want)
	}
	if err := Validate(got); err != nil {
		t.Errorf("rendered file doesn't validate: %v", err)
	}

	for _, bad := range []Export{
		{Path: "/mnt/tank/shares/media", UID: 1000, Clients: []shares.NFSRule{rule("10.0.0.1", "read")}},
		{Path: "/mnt/tank/shares/my media", UID: 31000, Clients: []shares.NFSRule{rule("10.0.0.1", "read")}},
		{Path: "/mnt/tank/../etc", UID: 31000, Clients: []shares.NFSRule{rule("10.0.0.1", "read")}},
		{Path: "mnt/tank", UID: 31000, Clients: []shares.NFSRule{rule("10.0.0.1", "read")}},
		{Path: "/mnt/tank/shares/x", UID: 31000, Clients: []shares.NFSRule{rule("0.0.0.0/0", "read")}},
		{Path: "/mnt/tank/shares/x", UID: 31000, Clients: []shares.NFSRule{rule("::/0", "read")}},
		{Path: "/mnt/tank/shares/x", UID: 31000, Clients: []shares.NFSRule{rule("*", "read")}},
		{Path: "/mnt/tank/shares/x", UID: 31000, Clients: []shares.NFSRule{rule("host.example.com", "read")}},
		{Path: "/mnt/tank/shares/x", UID: 31000, Clients: []shares.NFSRule{rule("10.0.0.1(rw,no_root_squash)", "read")}},
		{Path: "/mnt/tank/shares/x", UID: 31000, Clients: []shares.NFSRule{rule("fe80::1%eth0", "read")}},
		{Path: "/mnt/tank/shares/x", UID: 31000, Clients: []shares.NFSRule{rule("10.0.0.1", "admin")}},
	} {
		if s, err := Render([]Export{bad}); err == nil {
			t.Errorf("rendered %+v:\n%s", bad, s)
		}
	}
}

func TestValidate(t *testing.T) {
	for _, bad := range []string{
		"/mnt/x 10.0.0.1(rw,sync,no_subtree_check,no_root_squash,sec=sys,insecure)\n",
		"/mnt/x 10.0.0.1(rw,sync,no_subtree_check,all_squash,anonuid=0,anongid=0,sec=sys,insecure)\n",
		"/mnt/x 10.0.0.1(rw,sync,no_subtree_check,all_squash,anonuid=31000,anongid=31001,sec=sys,insecure)\n",
		"/mnt/x *(rw,sync,no_subtree_check,all_squash,anonuid=31000,anongid=31000,sec=sys,insecure)\n",
		"/mnt/x\n",
		"/mnt/x y 10.0.0.1(ro,sync,no_subtree_check,all_squash,anonuid=31000,anongid=31000,sec=sys,insecure)\n",
	} {
		if err := Validate(bad); err == nil {
			t.Errorf("Validate accepted %q", bad)
		}
	}
}

func TestAssignUIDs(t *testing.T) {
	on := func(id string) shares.Share { return share(id, true, rule("10.0.0.0/24", "read")) }
	off := func(id string) shares.Share { return share(id, true) }
	l := []shares.Share{off("a-old"), on("b-new"), on("c-clash"), on("d-keep"), off("e-dup"), func() shares.Share {
		s := on("f-unmounted")
		s.Mounted = false
		return s
	}()}
	have := map[string]int{
		"tank/shares/a-old":   31000, // NFS off now; keeps its ID reserved
		"tank/shares/c-clash": 31002, // same as d-keep: c-clash comes first, keeps it
		"tank/shares/d-keep":  31002,
		"tank/shares/e-dup":   31003,
	}
	uids, set := AssignUIDs(l, have)
	want := map[string]int{
		"tank/shares/a-old": 31000, "tank/shares/c-clash": 31002, "tank/shares/e-dup": 31003,
		"tank/shares/b-new": 31001, "tank/shares/d-keep": 31004,
	}
	if !reflect.DeepEqual(uids, want) {
		t.Errorf("uids = %v", uids)
	}
	var ids []string
	for _, s := range set {
		ids = append(ids, s.ID)
	}
	if !slices.Equal(ids, []string{"b-new", "d-keep"}) {
		t.Errorf("set = %v", ids)
	}
	// A folder with NFS off never takes an ID from one with NFS on.
	l2 := []shares.Share{off("a"), on("b")}
	uids, set = AssignUIDs(l2, map[string]int{"tank/shares/a": 31000, "tank/shares/b": 31000})
	if uids["tank/shares/b"] != 31000 || len(set) != 0 {
		t.Errorf("uids = %v set = %v", uids, set)
	}
	// The range runs out.
	have = map[string]int{}
	var many []shares.Share
	for i := 0; i < 1001; i++ {
		s := on("s" + strings.Repeat("x", i%3) + string(rune('a'+i%26)))
		s.Dataset = "tank/shares/" + s.ID + "-" + strings.Repeat("0", i/26)
		many = append(many, s)
	}
	uids, set = AssignUIDs(many, have)
	if len(uids) != 1000 || len(set) != 1000 {
		t.Errorf("assigned %d", len(uids))
	}
}

type grant struct {
	id     string
	uid    int
	write  bool
	revoke bool
}

type fakeShares struct {
	list   []shares.Share
	grants []grant
	fail   error
}

func (f *fakeShares) List(context.Context) ([]shares.Share, error) { return f.list, nil }
func (f *fakeShares) GrantNFS(_ context.Context, id string, uid int, write bool) error {
	if f.fail != nil {
		return f.fail
	}
	f.grants = append(f.grants, grant{id, uid, write, false})
	return nil
}
func (f *fakeShares) RevokeNFS(_ context.Context, id string, uid int) error {
	f.grants = append(f.grants, grant{id, uid, false, true})
	return nil
}

const getUIDs = "zfs get -H -p -t filesystem -s local -o name,value org.hardyos:nfs-uid"

func TestSync(t *testing.T) {
	root := t.TempDir()
	fs := &fakeShares{list: []shares.Share{
		share("media", true, rule("192.168.1.0/24", "read"), rule("192.168.1.50", "write")),
		share("docs", true, rule("192.168.1.0/24", "read")),
		share("plain", true),
		share("offline", false, rule("10.0.0.1", "write")),
	}}
	f := &sysexec.Fake{}
	f.On(getUIDs, "tank/shares/media\t31000\ntank/shares/plain\t31001\n")
	f.OnPrefix("zfs set ", sysexec.Result{})
	f.OnResult("systemctl is-active --quiet nfs-server.service", sysexec.Result{ExitCode: 3})
	f.OnResult("systemctl is-enabled --quiet nfs-server.service", sysexec.Result{ExitCode: 1})
	f.OnPrefix("systemctl enable ", sysexec.Result{})
	m := &Manager{Runner: f, Shares: fs, Root: root, Log: quiet}
	ctx := context.Background()
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{
		getUIDs,
		"zfs set org.hardyos:nfs-uid=31002 tank/shares/docs",
		"systemctl is-active --quiet nfs-server.service",
		"systemctl enable --now --no-block nfs-server.service",
	}
	if got := f.Lines(); !reflect.DeepEqual(got, want) {
		t.Fatalf("commands:\n%s", strings.Join(got, "\n"))
	}
	if !reflect.DeepEqual(fs.grants, []grant{{"docs", 31002, false, false}, {"media", 31000, true, false}}) {
		t.Errorf("grants = %+v", fs.grants)
	}
	b, err := os.ReadFile(filepath.Join(root, ExportsFile))
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); !strings.Contains(s, "/mnt/tank/shares/docs 192.168.1.0/24(ro,") || !strings.Contains(s, "/mnt/tank/shares/media 192.168.1.50(rw,") ||
		strings.Contains(s, "offline") || strings.Contains(s, "plain") {
		t.Errorf("exports:\n%s", s)
	}
	if fi, _ := os.Stat(filepath.Join(root, ExportsFile)); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", fi.Mode())
	}
	if st := m.Status(ctx); st.UIDs["docs"] != 31002 || st.UIDs["plain"] != 31001 || len(st.Exports) != 2 {
		t.Errorf("status = %+v", st)
	}

	// Running now; nothing changed: no walks, no exportfs, no file write.
	f.Calls = nil
	fs.grants = nil
	f.On(getUIDs, "tank/shares/media\t31000\ntank/shares/plain\t31001\ntank/shares/docs\t31002\n")
	f.OnResult("systemctl is-active --quiet nfs-server.service", sysexec.Result{})
	f.OnResult("systemctl is-enabled --quiet nfs-server.service", sysexec.Result{})
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fs.grants) != 0 || slices.Contains(f.Lines(), "exportfs -ra") {
		t.Errorf("idle sync: grants %+v, commands %v", fs.grants, f.Lines())
	}

	// media goes read only, docs turns NFS off: access changes, exportfs runs.
	f.Calls = nil
	f.On("exportfs -ra", "")
	fs.list[0].Services.NFS.Clients = []shares.NFSRule{rule("192.168.1.0/24", "read")}
	fs.list[1].Services.NFS = shares.NFS{Clients: []shares.NFSRule{}}
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fs.grants, []grant{{"docs", 31002, false, true}, {"media", 31000, false, false}}) {
		t.Errorf("grants = %+v", fs.grants)
	}
	if !slices.Contains(f.Lines(), "exportfs -ra") {
		t.Errorf("exportfs didn't run: %v", f.Lines())
	}

	// Withdraw (before delete) drops the folder from the file; nothing is left,
	// so the server stops.
	f.Calls = nil
	f.OnPrefix("systemctl disable ", sysexec.Result{})
	if err := m.Withdraw(ctx, "media"); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(root, ExportsFile))
	if string(b) != header {
		t.Errorf("exports after withdraw:\n%s", b)
	}
	if l := f.Lines(); l[len(l)-1] != "systemctl disable --now --no-block nfs-server.service" {
		t.Errorf("commands: %v", l)
	}
}

func TestSyncFailures(t *testing.T) {
	root := t.TempDir()
	fs := &fakeShares{list: []shares.Share{share("media", true, rule("192.168.1.0/24", "write"))}, fail: errors.New("acl failed")}
	f := &sysexec.Fake{}
	f.On(getUIDs, "tank/shares/media\t31000\n")
	f.OnResult("systemctl is-active --quiet nfs-server.service", sysexec.Result{})
	f.OnResult("systemctl is-enabled --quiet nfs-server.service", sysexec.Result{})
	f.On("exportfs -ra", "")
	f.OnPrefix("systemctl disable ", sysexec.Result{})
	m := &Manager{Runner: f, Shares: fs, Root: root, Log: quiet}
	ctx := context.Background()
	// The grant fails: the folder isn't exported (its identity has no access yet).
	if err := m.Sync(ctx); err == nil || !strings.Contains(err.Error(), "acl failed") {
		t.Fatalf("sync = %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(root, ExportsFile))
	if strings.Contains(string(b), "media") {
		t.Errorf("exported without access:\n%s", b)
	}
	if st := m.Status(ctx); st.Problem == "" {
		t.Error("status has no problem")
	}
	// exportfs refuses the new file: the old one is put back.
	fs.fail = nil
	f.OnResult("exportfs -ra", sysexec.Result{ExitCode: 1, Stderr: []byte("exportfs: bad")})
	if err := m.Sync(ctx); err == nil || !strings.Contains(err.Error(), "exportfs") {
		t.Fatalf("sync = %v", err)
	}
	b, _ = os.ReadFile(filepath.Join(root, ExportsFile))
	if string(b) != header {
		t.Errorf("exports not restored:\n%s", b)
	}
	// Invalid settings stored on the dataset (edited by hand) are never exported.
	f.On("exportfs -ra", "")
	fs.list[0].Services.NFS.Clients = []shares.NFSRule{rule("0.0.0.0/0", "write")}
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(root, ExportsFile))
	if strings.Contains(string(b), "media") {
		t.Errorf("exported to everyone:\n%s", b)
	}
	if entries, _ := os.ReadDir(filepath.Join(root, "etc/exports.d")); len(entries) != 1 {
		t.Errorf("temporary files left: %v", entries)
	}
}
