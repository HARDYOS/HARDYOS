package priv

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// TestZFSIntegrationShares runs shared folders against real ZFS on a
// file-backed pool: create, the starter set, app ACLs (checked with
// getfacl), Resolve and delete. Like TestZFSIntegration it needs root and
// ZFS and only runs with HARDYOS_ZFS_INTEGRATION=1 (CI's "ZFS integration"
// job runs it with the same -test.run pattern).
func TestZFSIntegrationShares(t *testing.T) {
	if os.Getenv("HARDYOS_ZFS_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_ZFS_INTEGRATION=1 to run against real ZFS (needs root)")
	}
	if os.Geteuid() != 0 {
		t.Fatal("must run as root")
	}
	for _, tool := range []string{"setfacl", "getfacl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s isn't installed (Debian/Ubuntu package acl)", tool)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	dir := t.TempDir()
	vdev := filepath.Join(dir, "vdev")
	f, err := os.Create(vdev)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(512 << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	const pool = "hardyosshares"
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return string(out)
	}
	_ = exec.Command("zpool", "destroy", "-f", pool).Run()
	mnt := filepath.Join(dir, "mnt", pool)
	run("zpool", "create", "-o", "ashift=12", "-m", mnt,
		"-O", "compression=lz4", "-O", "xattr=sa", "-O", "acltype=posixacl", pool, vdev)
	t.Cleanup(func() { _ = exec.Command("zpool", "destroy", "-f", pool).Run() })

	m := &shares.Manager{Runner: sysexec.Exec{}, Root: "/"}
	t.Cleanup(m.Wait)
	find := func(id string) *shares.Share {
		t.Helper()
		sh, err := m.Get(ctx, id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		return sh
	}

	// Starter set: Media with its folders, and Backups.
	made, err := m.CreateStarter(ctx, shares.StarterArgs{Pool: pool, Media: true, Backups: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(made) != 2 {
		t.Fatalf("starter made %+v", made)
	}
	media := find("media")
	if !media.Mounted || media.Path != mnt+"/shares/media" || !media.Recycle || len(media.Access) != 1 || media.Dataset != pool+"/shares/media" {
		t.Errorf("media = %+v", media)
	}
	for _, sub := range []string{"Movies", "TV", "Music", "Photos"} {
		if fi, err := os.Stat(filepath.Join(media.Path, sub)); err != nil || !fi.IsDir() {
			t.Errorf("Media/%s: %v", sub, err)
		}
	}
	props := run("zfs", "get", "-H", "-o", "property,value,source", "acltype,xattr,devices,setuid,compression,quota", media.Dataset)
	for _, want := range []string{"acltype\tposix", "xattr\tsa", "devices\toff", "setuid\toff", "compression\tlz4\tinherited", "quota\tnone"} {
		if !strings.Contains(props, want) {
			t.Errorf("%s properties lack %q:\n%s", media.Dataset, want, props)
		}
	}
	if _, err := m.CreateStarter(ctx, shares.StarterArgs{Pool: pool, Media: true, Backups: true}); err == nil {
		t.Error("the starter set was created twice")
	}

	// A folder of our own, then changed.
	docs, err := m.Create(ctx, shares.NewShare{Pool: pool, Name: "Family Docs", Description: "Paperwork", QuotaBytes: 100 << 20, Guest: true,
		Access: []shares.Rule{{Kind: shares.KindGroup, Name: `HOME\Family`, Level: shares.LevelWrite}}})
	if err != nil {
		t.Fatal(err)
	}
	if docs.ID != "family-docs" || docs.QuotaBytes != 100<<20 || !docs.Guest || docs.Recycle || docs.Description != "Paperwork" || docs.Access[0].Name != `HOME\Family` || docs.CreatedAt.IsZero() {
		t.Errorf("docs = %+v", docs)
	}
	name, desc, quota := "Paperwork", "", uint64(0)
	docs, err = m.Update(ctx, shares.ShareUpdate{ID: "family-docs", Name: &name, Description: &desc, QuotaBytes: &quota})
	if err != nil {
		t.Fatal(err)
	}
	if docs.Name != "Paperwork" || docs.Description != "" || docs.QuotaBytes != 0 || !docs.Guest {
		t.Errorf("updated docs = %+v", docs)
	}
	l, err := m.List(ctx)
	if err != nil || len(l) != 3 {
		t.Fatalf("list = %+v %v", l, err)
	}

	// Files, a link out of the share, and a folder elsewhere it points to.
	outside := filepath.Join(dir, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	movies := filepath.Join(media.Path, "Movies")
	for p, body := range map[string]string{movies + "/film.mkv": "x", outside + "/secret": "s"} {
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(movies+"/Kids", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, movies+"/escape"); err != nil {
		t.Fatal(err)
	}

	// Resolve: real paths inside, nothing outside.
	if p, err := m.Resolve(ctx, "media", "Movies/Kids"); err != nil || p != movies+"/Kids" {
		t.Errorf("resolve = %q %v", p, err)
	}
	if p, err := m.Resolve(ctx, "media", "Movies/escape"); err == nil {
		t.Errorf("resolved a link out of the share: %q", p)
	}
	if fl, err := m.Folders(ctx, "media", ""); err != nil || strings.Join(fl, ",") != "Movies,Music,Photos,TV" {
		t.Errorf("folders = %v %v", fl, err)
	}

	// Grant: ACLs on the share, below it in the background, never behind the link.
	acl := func(p string) string {
		t.Helper()
		return run("getfacl", "-n", "-p", "--omit-header", p)
	}
	if err := m.GrantApp(ctx, "media", "jellyfin", 30001, false); err != nil {
		t.Fatal(err)
	}
	if err := m.GrantApp(ctx, "media", "sonarr", 30002, true); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	root := acl(media.Path)
	for _, want := range []string{"user:30001:r-x", "user:30002:rwx", "default:user:30001:r-x", "default:user:30002:rwx"} {
		if !strings.Contains(root, want) {
			t.Errorf("share root ACL lacks %s:\n%s", want, root)
		}
	}
	if a := acl(movies + "/film.mkv"); !strings.Contains(a, "user:30001:r--") || !strings.Contains(a, "user:30002:rw-") {
		t.Errorf("film ACL:\n%s", a)
	}
	if a := acl(movies + "/Kids"); !strings.Contains(a, "default:user:30002:rwx") {
		t.Errorf("Kids ACL:\n%s", a)
	}
	for _, p := range []string{outside, outside + "/secret"} {
		if a := acl(p); strings.Contains(a, "30001") || strings.Contains(a, "30002") {
			t.Errorf("%s behind a link was changed:\n%s", p, a)
		}
	}
	// New files inherit the default ACL.
	if err := os.WriteFile(movies+"/new.mkv", []byte("n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if a := acl(movies + "/new.mkv"); !strings.Contains(a, "user:30002:rwx") || !strings.Contains(a, "user:30001:r-x") {
		t.Errorf("a new file didn't inherit the default ACL:\n%s", a)
	}
	media = find("media")
	if len(media.Apps) != 2 || media.Apps[0].App != "jellyfin" || media.Apps[1].Level != shares.LevelWrite {
		t.Errorf("recorded apps = %+v", media.Apps)
	}

	// Deleting refuses while apps use it.
	var ve *shares.ValidationError
	if err := m.Delete(ctx, "media", "Media"); !errors.As(err, &ve) || !strings.Contains(err.Error(), "jellyfin and sonarr") {
		t.Errorf("delete while used: %v", err)
	}

	// Revoke takes the entries away everywhere.
	if err := m.RevokeApp(ctx, "jellyfin"); err != nil {
		t.Fatal(err)
	}
	if err := m.RevokeApp(ctx, "sonarr"); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	for _, p := range []string{media.Path, movies, movies + "/film.mkv", movies + "/Kids", movies + "/new.mkv"} {
		if a := acl(p); strings.Contains(a, "30001") || strings.Contains(a, "30002") {
			t.Errorf("%s still has an app's entry:\n%s", p, a)
		}
	}
	if len(find("media").Apps) != 0 {
		t.Error("apps still recorded")
	}

	// Delete needs the exact name, then destroys the dataset.
	if err := m.Delete(ctx, "media", "Medi"); err == nil {
		t.Fatal("deleted with the wrong name")
	}
	if err := m.Delete(ctx, "media", "Media"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(ctx, "media"); !errors.Is(err, shares.ErrNotFound) {
		t.Errorf("media still listed: %v", err)
	}
	if err := exec.Command("zfs", "list", pool+"/shares/media").Run(); err == nil {
		t.Error("the dataset still exists")
	}
	if _, err := os.Stat(outside + "/secret"); err != nil {
		t.Errorf("the file behind the link went with it: %v", err)
	}
}
