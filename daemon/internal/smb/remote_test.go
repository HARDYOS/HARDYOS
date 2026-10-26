package smb

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/fileworker"
	"github.com/hardyos/hardyos/daemon/internal/sftp"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// memMounter records bind mounts.
type memMounter struct {
	mu sync.Mutex
	m  map[string]sftp.MountPoint
}

func (f *memMounter) List(dir string) ([]sftp.MountPoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []sftp.MountPoint
	for t, m := range f.m {
		if strings.HasPrefix(t, dir+"/") {
			out = append(out, m)
		}
	}
	return out, nil
}
func (f *memMounter) IsMount(string) (bool, error) { return true, nil }
func (f *memMounter) MakePrivate(string) error     { return nil }
func (f *memMounter) Bind(src string, _ uint64, dst string, ro bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.m == nil {
		f.m = map[string]sftp.MountPoint{}
	}
	f.m[dst] = sftp.MountPoint{Target: dst, Source: src, ReadOnly: ro}
	return nil
}
func (f *memMounter) Unmount(dst string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, dst)
	return nil
}

func (f *memMounter) views(root string) []string {
	l, _ := f.List(root)
	var out []string
	for _, m := range l {
		ro := "rw"
		if m.ReadOnly {
			ro = "ro"
		}
		out = append(out, strings.TrimPrefix(m.Target, root+"/")+" "+ro)
	}
	sort.Strings(out)
	return out
}

func TestApplySFTP(t *testing.T) {
	dir := t.TempDir()
	media, private := filepath.Join(dir, "media"), filepath.Join(dir, "private")
	_ = os.Mkdir(media, 0o755)
	_ = os.Mkdir(private, 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "etc/ssh/sshd_config.d"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "etc/pam.d"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "etc/pam.d/sshd"), []byte("@include common-auth\n@include common-account\n@include common-session\n"), 0o644)
	on := shares.DefaultServices()
	on.SFTP = true
	l := []shares.Share{
		{ID: "media", Name: "Media", Dataset: "tank/shares/media", Path: media, Mounted: true, RootDev: devOf(media),
			Access: []shares.Rule{{Kind: shares.KindEveryone, Level: shares.LevelRead}, {Kind: shares.KindGroup, Name: `HOME\Family`, Level: shares.LevelWrite}}, Services: on},
		{ID: "private", Name: "Private", Dataset: "tank/shares/private", Path: private, Mounted: true, RootDev: devOf(private),
			Access: []shares.Rule{{Kind: shares.KindUser, Name: `HOME\alice`, Level: shares.LevelWrite}}, Services: on},
		{ID: "nosftp", Name: "No SFTP", Dataset: "tank/shares/nosftp", Path: media, Mounted: true, RootDev: devOf(media),
			Access: []shares.Rule{{Kind: shares.KindEveryone, Level: shares.LevelWrite}}, Services: shares.DefaultServices()},
		// SFTP on, but its mount wasn't verified: never in anyone's view.
		{ID: "fake", Name: "Fake", Dataset: "tank/shares/fake", Path: media, Mounted: true,
			Access: []shares.Rule{{Kind: shares.KindEveryone, Level: shares.LevelWrite}}, Services: on},
	}
	f := okFake()
	f.OnPrefix("net ads search", sysexec.Result{Stdout: []byte("sAMAccountName: Alice\n\nsAMAccountName: bob\n\nsAMAccountName: Administrator\n")})
	f.On("getent passwd 101103", `HOME\alice:*:101103:100513::/nonexistent:/usr/sbin/nologin`+"\n")
	f.On("getent passwd 101104", `HOME\bob:*:101104:100513::/nonexistent:/usr/sbin/nologin`+"\n")
	f.On("getent passwd 100500", `HOME\administrator:*:100500:100513::/nonexistent:/usr/sbin/nologin`+"\n")
	f.OnResult("getent group hardyos-sftp", sysexec.Result{ExitCode: 2})
	f.OnPrefix("groupadd ", sysexec.Result{})
	f.OnPrefix("gpasswd ", sysexec.Result{})
	f.On("sshd -t", "")
	m := newTestManager(t, f, l)
	mt := &memMounter{}
	m.SFTP = &sftp.Manager{Runner: f, Mounter: mt, Root: filepath.Join(dir, "views"), DropIn: filepath.Join(dir, "etc/ssh/sshd_config.d/hardyos-sftp.conf"),
		PAMPath: filepath.Join(dir, "etc/pam.d/sshd"), CommonAuth: filepath.Join(dir, "etc/pam.d/common-auth"), NoChown: os.Geteuid() != 0}
	ids := map[string]*fileworker.Identity{
		`home\alice`:         {UID: 101103, GID: 100513},
		`home\bob`:           {UID: 101104, GID: 100513, Groups: []int{101110}},
		`home\administrator`: {UID: 100500, GID: 100513, Groups: []int{100512}},
	}
	m.LookupUser = func(_ context.Context, n string) (*fileworker.Identity, error) {
		if id, ok := ids[strings.ToLower(n)]; ok {
			return id, nil
		}
		return nil, os.ErrNotExist
	}
	ctx := context.Background()
	if _, err := m.Join(ctx, JoinArgs{AdminPassword: "x"}); err != nil {
		t.Fatal(err)
	}
	if v := mt.views(m.SFTP.Root); len(v) != 0 {
		t.Errorf("views with SFTP off: %v", v)
	}
	yes := true
	st, err := m.SetSettings(ctx, SettingsArgs{SFTPEnabled: &yes})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"100500/Media rw", "100500/Private rw", "101103/Media ro", "101103/Private rw", "101104/Media rw"}
	if got := mt.views(m.SFTP.Root); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("views:\n got %v\nwant %v", got, want)
	}
	if st.SFTP == nil || !st.SFTP.Enabled || st.SFTP.Users != 3 {
		t.Errorf("status %+v", st.SFTP)
	}
	found := false
	for _, ln := range f.Lines() {
		if ln == `gpasswd -M HOME\administrator,HOME\alice,HOME\bob hardyos-sftp` {
			found = true
		}
	}
	if !found {
		t.Errorf("group: %v", f.Lines())
	}
	// A folder being deleted leaves the views first.
	if err := m.Release(ctx, "private"); err != nil {
		t.Fatal(err)
	}
	for _, v := range mt.views(m.SFTP.Root) {
		if strings.Contains(v, "Private") {
			t.Errorf("deleted folder still in a view: %v", v)
		}
	}
	// Leaving the domain takes SFTP away.
	if _, err := m.Leave(ctx, LeaveArgs{Confirm: true}); err != nil {
		t.Fatal(err)
	}
	if v := mt.views(m.SFTP.Root); len(v) != 0 {
		t.Errorf("views after leaving: %v", v)
	}
	b, _ := os.ReadFile(m.SFTP.DropIn)
	if !strings.Contains(string(b), "DenyGroups *") {
		t.Errorf("domain accounts not refused after leaving:\n%s", b)
	}
}
