package shares

import (
	"context"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// A pool from elsewhere can put anything in its user properties. A line
// break in one value must not become another shared folder.
func TestListHostileZFSOutput(t *testing.T) {
	m, f, _, _ := newManager(t)
	mounts := MountTable{
		{Mountpoint: "/mnt/tank/shares/media", Root: "/", FSType: "zfs", Source: "tank/shares/media", Dev: 41},
		{Mountpoint: "/mnt/tank/shares/docs", Root: "/", FSType: "zfs", Source: "tank/shares/docs", Dev: 42},
		{Mountpoint: "/etc", Root: "/", FSType: "ext4", Source: "/dev/sda1", Dev: 2049},
	}
	m.Mounts = func() (MountVerifier, error) { return mounts, nil }
	evil := strings.Join([]string{"tank/shares/evil", "1", "Evil", "-", `[{"kind":"everyone","level":"write"}]`, "[]", "on", "on",
		"0", "0", "/etc", "yes", "1792000000", "-"}, "\t")
	// The description of media ends its row early and adds a whole fake one.
	media := strings.Join([]string{"tank/shares/media", "1", "Media", "Films\n" + evil + "\nx", "[]", "[]", "on", "off",
		"0", "0", "/mnt/tank/shares/media", "yes", "1792000000", "-"}, "\t")
	docs := row{ds: "tank/shares/docs", name: "Docs", mounted: true}.String()
	f.On(listAll, media+"\n"+docs+"\n")
	f.On("zfs list -H -o name -t filesystem", "tank\ntank/shares\ntank/shares/docs\ntank/shares/media\n")
	props := strings.Join(listProps[1:], ",")
	// One by one: media's answer has more lines than properties, docs' is fine.
	getLines := func(vals []string) string {
		var b strings.Builder
		for i, p := range listProps[1:] {
			b.WriteString(p + "\t" + vals[i] + "\n")
		}
		return b.String()
	}
	f.On("zfs get -Hp -o property,value "+props+" tank/shares/media", getLines(strings.Split(media, "\t")[1:]))
	f.On("zfs get -Hp -o property,value "+props+" tank/shares/docs", getLines(strings.Split(docs, "\t")[1:]))

	l, err := m.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 1 || l[0].ID != "docs" || !l[0].Usable() || l[0].RootDev != 42 || l[0].Path != "/mnt/tank/shares/docs" {
		t.Fatalf("list = %+v", l)
	}
	for _, line := range f.Lines() {
		if strings.Contains(line, "evil") {
			t.Errorf("the fake folder was looked at: %s", line)
		}
	}

	// Without the line break trick, a folder claiming /etc is listed but
	// never usable: /etc isn't its mount.
	f2 := &sysexec.Fake{}
	m.Runner = f2
	onList(f2, "", evil+"\n"+docs+"\n")
	l, err = m.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, sh := range l {
		if sh.ID == "evil" && (sh.Mounted || sh.Path != "" || sh.RootDev != 0 || sh.Usable()) {
			t.Errorf("evil = %+v", sh)
		}
	}
	if len(l) != 2 {
		t.Errorf("list = %+v", l)
	}
	if _, err := m.Resolve(context.Background(), "evil", ""); err == nil {
		t.Error("resolved the folder claiming /etc")
	}
	if err := m.GrantApp(context.Background(), "evil", "plex", 30001, true); err == nil || !strings.Contains(err.Error(), "isn't available") {
		t.Errorf("grant on the folder claiming /etc = %v", err)
	}
	for _, line := range f2.Lines() {
		if strings.HasPrefix(line, "setfacl") {
			t.Errorf("ran %s", line)
		}
	}
}

// Values are checked again on the way in, as if a person had typed them.
func TestListRevalidates(t *testing.T) {
	m, f, _, _ := newManager(t)
	onList(f, "", rows(
		row{ds: "tank/shares/media", name: "Bad]Name", desc: "ctl\x01char",
			access:   `[{"kind":"user","name":"a\\b\\c","level":"write"}]`,
			apps:     `[{"app":"plex","uid":0,"level":"write"},{"app":"jellyfin","uid":30001,"level":"read"},{"app":"x","uid":30002,"level":"root"}]`,
			services: `{"smb":{"enabled":true},"nfs":{"enabled":true,"clients":[{"client":"0.0.0.0/0","access":"write"}]}}`,
			mounted:  true},
	))
	l, err := m.List(context.Background())
	if err != nil || len(l) != 1 {
		t.Fatalf("list = %+v %v", l, err)
	}
	sh := l[0]
	if sh.Name != "media" || sh.Description != "" || len(sh.Access) != 0 {
		t.Errorf("name %q, description %q, access %+v", sh.Name, sh.Description, sh.Access)
	}
	if len(sh.Apps) != 1 || sh.Apps[0].App != "jellyfin" {
		t.Errorf("apps = %+v", sh.Apps)
	}
	if sh.Services.NFS.Enabled || len(sh.Services.NFS.Clients) != 0 {
		t.Errorf("services = %+v", sh.Services)
	}
}

func TestParseGetOutput(t *testing.T) {
	props := []string{"a", "b"}
	if v, err := ParseGetOutput([]byte("b\t2\na\t1 x\n"), props); err != nil || v[0] != "1 x" || v[1] != "2" {
		t.Errorf("= %q %v", v, err)
	}
	for _, bad := range []string{"a\t1\n", "a\t1\nb\t2\nc\t3\n", "a\t1\na\t2\n", "a\t1\nb\t2\t3\n", "a\t1\nb\t2\nfake\n", "a\t1\nc\t2\n"} {
		if _, err := ParseGetOutput([]byte(bad), props); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestMountInfo(t *testing.T) {
	info := `22 1 0:21 / / rw,relatime shared:1 - zfs rpool/ROOT/hardyos rw,xattr,posixacl
40 22 0:40 / /mnt/tank rw shared:20 - zfs tank rw
41 40 0:41 / /mnt/tank/shares/media rw shared:21 - zfs tank/shares/media rw,posixacl
42 40 0:42 / /mnt/tank/shares/my\040photos rw shared:22 - zfs tank/shares/photos rw
43 40 0:41 /sub /mnt/tank/shares/bound rw - zfs tank/shares/media rw
44 40 8:1 / /mnt/tank/shares/usb rw - ext4 /dev/sdb1 rw
45 41 0:45 / /mnt/tank/shares/media rw - zfs tank/shares/other rw
46 40 0:46 / /mnt/tank/shares/docs rw shared:23 master:1 - zfs tank/shares/docs rw
`
	tab, err := ParseMountInfo([]byte(info))
	if err != nil {
		t.Fatal(err)
	}
	if d, err := tab.VerifyMount("/mnt/tank/shares/my photos", "tank/shares/photos"); err != nil || d != mkdev(0, 42) {
		t.Errorf("escaped space = %d %v", d, err)
	}
	if d, err := tab.VerifyMount("/mnt/tank/shares/docs", "tank/shares/docs"); err != nil || d != mkdev(0, 46) {
		t.Errorf("docs = %d %v", d, err)
	}
	for _, c := range []struct{ path, ds string }{
		{"/mnt/tank/shares/media", "tank/shares/media"}, // something else is mounted on top
		{"/mnt/tank/shares/bound", "tank/shares/media"}, // a bind mount of a subfolder
		{"/mnt/tank/shares/usb", "/dev/sdb1"},           // not ZFS
		{"/etc", "tank/shares/evil"},                    // nothing mounted there
		{"/mnt/tank/shares", "tank/shares"},             // nothing mounted there
		{"/mnt/tank", "tank/shares/media"},              // another dataset
	} {
		if _, err := tab.VerifyMount(c.path, c.ds); err == nil {
			t.Errorf("VerifyMount(%s, %s) accepted", c.path, c.ds)
		}
	}
	if d := mkdev(8, 1); d != 2049 {
		t.Errorf("mkdev(8, 1) = %d", d)
	}
	if d, want := mkdev(259, 70000), uint64(70000&0xffffff00)<<12|uint64(259)<<8|uint64(70000&0xff); d != want {
		t.Errorf("mkdev(259, 70000) = %x, want %x", d, want)
	}
	if _, err := ParseMountInfo([]byte("garbage\n")); err == nil {
		t.Error("parsed garbage")
	}
	if _, err := (MountTable{}).VerifyMount("/x", "y"); err == nil {
		t.Error("empty table verified")
	}
}

func TestBinName(t *testing.T) {
	for in, want := range map[[2]string]string{
		{"HOME", "Alice"}:        "home.alice",
		{"HOME", "john.smith"}:   "home.john.smith",
		{"", "alice"}:            "",
		{"HOME", ""}:             "",
		{"HO.ME", "alice"}:       "",
		{"HOME", "a/b"}:          "",
		{"HOME", `a\b`}:          "",
		{"hardyos", "files"}:     "hardyos.files",
		{"HOME", "x\x00"}:        "",
		{"HOME", "Ünïcode Name"}: "home.ünïcode name",
	} {
		if got := BinName(in[0], in[1]); got != want {
			t.Errorf("BinName(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}
