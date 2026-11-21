package mail

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// liveServer is a mail server applied on a temporary dataset (no programs,
// no system folders), with a mailbox's mail, calendars and Rspamd's data.
type liveServer struct {
	r      *Root
	e      Env
	runner *sysexec.Fake
	redis  string
	starts int
}

func newLiveServer(t *testing.T) *liveServer {
	t.Helper()
	dir := t.TempDir()
	ls := &liveServer{runner: (&sysexec.Fake{}).OnPrefix("", sysexec.Result{}), redis: t.TempDir()}
	ls.r = &Root{
		Runner:     ls.runner,
		Chown:      func(string, int, int) error { return nil },
		LookupUser: func(string) (int, int, error) { return os.Getuid(), os.Getgid(), nil },
		LookupGrp:  func(string) (int, error) { return os.Getgid(), nil },
		Dataset:    func(context.Context, string) (string, error) { return dir, nil },
		SkipChecks: true,
		StateFile:  filepath.Join(dir, "state.json"),
		RedisDir:   ls.redis,
		Now:        func() time.Time { return time.Date(2026, 11, 21, 15, 30, 0, 0, time.UTC) },
		StartServices: func(context.Context, RootConfig, *ApplyResult) error {
			ls.starts++
			return nil
		},
	}
	// Generated files outside the dataset (/etc) aren't written.
	ls.r.Write = func(p string, b []byte, m os.FileMode) error {
		if strings.HasPrefix(p, dir) {
			return os.WriteFile(p, b, m)
		}
		return nil
	}
	if _, err := ls.r.Apply(context.Background(), ApplyArgs{Config: sampleConfig(), Secrets: sampleSecrets()}); err != nil {
		t.Fatal(err)
	}
	ls.e = Env{MailRoot: dir, VMailUID: os.Getuid(), VMailGID: os.Getgid()}
	// Alice: two messages in INBOX, one in Sent, index files; a calendar.
	md := filepath.Join(ls.e.VMailDir(), keyAlice, "Maildir")
	write(t, filepath.Join(md, "cur", "1700000000.M1P1.host,S=5:2,S"), "one")
	write(t, filepath.Join(md, "new", "1700000001.M2P1.host,S=5"), "two")
	write(t, filepath.Join(md, ".Sent", "cur", "1700000002.M3P1.host:2,S"), "sent")
	write(t, filepath.Join(md, ".Sent", "maildirfolder"), "")
	write(t, filepath.Join(md, "dovecot.index"), "index")
	write(t, filepath.Join(md, "dovecot-uidlist"), "3 V1 N3\n")
	write(t, filepath.Join(md, "tmp", "partial"), "partial")
	cal := filepath.Join(ls.e.RadicaleDir(), "collections", "collection-root", keyAlice, "home")
	write(t, filepath.Join(cal, ".Radicale.props"), `{"D:displayname": "Home", "tag": "VCALENDAR"}`)
	write(t, filepath.Join(cal, "event.ics"), "BEGIN:VCALENDAR\nEND:VCALENDAR\n")
	write(t, filepath.Join(cal, ".Radicale.cache", "x"), "cache")
	write(t, filepath.Join(ls.redis, "dump.rdb"), "REDIS0011-learned")
	return ls
}

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// version prepares a backup and copies the dataset as a restore would see
// it (a staged restic version or a received replica).
func (ls *liveServer) version(t *testing.T) string {
	t.Helper()
	if _, err := ls.r.PrepareBackup(context.Background()); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if err := os.CopyFS(dst, os.DirFS(ls.e.MailRoot)); err != nil {
		t.Fatal(err)
	}
	return dst
}

func (ls *liveServer) ran(prefix string) bool {
	for _, l := range ls.runner.Lines() {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

func TestPrepareBackup(t *testing.T) {
	ls := newLiveServer(t)
	src, err := ls.r.PrepareBackup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if src.Dataset != "tank/mail" || src.Mountpoint != ls.e.MailRoot || !src.Bayes || src.Mailboxes != 2 || len(src.Domains) != 2 {
		t.Fatalf("source: %+v", src)
	}
	if !ls.ran("redis-cli -s " + RedisSocket + " SAVE") {
		t.Fatal("Rspamd's Redis wasn't saved first")
	}
	dir := filepath.Join(ls.e.MailRoot, BackupDir)
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("backup folder: %v %v", st, err)
	}
	if read(t, filepath.Join(dir, BackupBayesName)) != "REDIS0011-learned" {
		t.Fatal("Rspamd's data isn't in the dataset")
	}
	cfg := read(t, filepath.Join(dir, BackupConfigName))
	for _, s := range []string{sampleSecrets().SESPassword, sampleSecrets().AuthSecret, sampleSecrets().DAV[keyAlice]} {
		if strings.Contains(cfg, s) {
			t.Fatal("a secret is in the backup's configuration")
		}
	}
	c, err := ParseBackupConfig([]byte(cfg))
	if err != nil || len(c.Mailboxes) != 2 || c.Mailboxes[0].Key != keyAlice {
		t.Fatalf("configuration: %+v %v", c, err)
	}
	// A link planted where the dump goes isn't followed.
	_ = os.Remove(filepath.Join(ls.redis, "dump.rdb"))
	if err := os.Symlink("/etc/shadow", filepath.Join(ls.redis, "dump.rdb")); err != nil {
		t.Fatal(err)
	}
	src, err = ls.r.PrepareBackup(context.Background())
	if err != nil || src.Bayes || len(src.Warnings) == 0 {
		t.Fatalf("a link was copied: %+v %v", src, err)
	}

	// Not set up: nothing to back up.
	r := &Root{StateFile: filepath.Join(t.TempDir(), "none.json")}
	if _, err := r.PrepareBackup(context.Background()); !errors.Is(err, ErrNotSetUp) {
		t.Fatalf("not set up: %v", err)
	}
}

func TestRestoreArgsCheck(t *testing.T) {
	for _, a := range []RestoreArgs{
		{Scope: "mailbox", Key: "nope", Mode: RestoreCopy},
		{Scope: "mailbox", Key: keyAlice, Into: "../x", Mode: RestoreCopy},
		{Scope: "mailbox", Key: keyAlice, Mode: "merge"},
		{Scope: "domain", Domain: "Example.NET", Mode: RestoreCopy},
		{Scope: "domain", Domain: "example.net", Key: keyAlice, Mode: RestoreCopy},
		{Scope: "all", Confirm: "yes"},
		{Scope: "all", Confirm: "mail", Domain: "example.net"},
		{Scope: "everything", Confirm: "mail"},
	} {
		if err := a.Check(); err == nil {
			t.Errorf("accepted %+v", a)
		}
	}
	a := RestoreArgs{Scope: ScopeAll, Confirm: " Mail "}
	if err := a.Check(); err != nil || a.Mode != RestoreOverwrite {
		t.Fatalf("all: %v %+v", err, a)
	}
	a = RestoreArgs{Scope: ScopeMailbox, Key: keyAlice, Mode: RestoreCopy}
	if err := a.Check(); err != nil || a.Into != keyAlice {
		t.Fatalf("mailbox: %v %+v", err, a)
	}
}

// Decision 462: a mailbox comes back into a new folder (nothing current
// changes), or over what's there once its address is typed.
func TestRestoreMailbox(t *testing.T) {
	ls := newLiveServer(t)
	ver := ls.version(t)
	ctx := context.Background()
	md := filepath.Join(ls.e.VMailDir(), keyAlice, "Maildir")
	// Since the backup: a message deleted, another arrived.
	_ = os.Remove(filepath.Join(md, "cur", "1700000000.M1P1.host,S=5:2,S"))
	write(t, filepath.Join(md, "new", "1700000009.M9P1.host,S=5"), "later")

	res, err := ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeMailbox, Key: keyAlice, Mode: RestoreCopy})
	if err != nil {
		t.Fatal(err)
	}
	top := ".Restored 2026-11-21 1530"
	if res.Folder != "Restored 2026-11-21 1530" || res.Messages != 3 || res.Mailboxes != 1 || res.Safety != "" {
		t.Fatalf("result: %+v", res)
	}
	if read(t, filepath.Join(md, top, "cur", "1700000000.M1P1.host,S=5:2,S")) != "one" ||
		read(t, filepath.Join(md, top, "new", "1700000001.M2P1.host,S=5")) != "two" ||
		read(t, filepath.Join(md, top+".Sent", "cur", "1700000002.M3P1.host:2,S")) != "sent" {
		t.Fatal("the restored folders don't hold the version's mail")
	}
	for _, p := range []string{filepath.Join(md, top, "maildirfolder"), filepath.Join(md, top, "tmp")} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("not a Maildir++ folder: %v", err)
		}
	}
	for _, p := range []string{filepath.Join(md, top, "dovecot.index"), filepath.Join(md, top, "tmp", "partial")} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("%s was copied", p)
		}
	}
	if read(t, filepath.Join(md, "new", "1700000009.M9P1.host,S=5")) != "later" {
		t.Fatal("the current INBOX changed")
	}
	if !ls.ran(`doveadm mailbox subscribe -u alice@example.net Restored 2026-11-21 1530 Restored 2026-11-21 1530/Sent`) {
		t.Fatalf("not subscribed: %v", ls.runner.Lines())
	}
	if st, _ := os.Stat(filepath.Join(md, top, "cur", "1700000000.M1P1.host,S=5:2,S")); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	// No work folders left behind.
	names, _ := os.ReadDir(ls.e.VMailDir())
	for _, n := range names {
		if strings.HasPrefix(n.Name(), ".") {
			t.Fatalf("left %s", n.Name())
		}
	}
	// A second copy gets its own folder.
	res, err = ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeMailbox, Key: keyAlice, Mode: RestoreCopy})
	if err != nil || res.Folder != "Restored 2026-11-21 1530 (2)" {
		t.Fatalf("second copy: %+v %v", res, err)
	}

	// Overwrite: only with the address typed.
	if _, err := ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeMailbox, Key: keyAlice, Mode: RestoreOverwrite, Confirm: "bob@example.net"}); err == nil {
		t.Fatal("overwritten without the address")
	}
	res, err = ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeMailbox, Key: keyAlice, Mode: RestoreOverwrite, Confirm: "alice@example.net"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Safety != "hardyos-manual-20261121-153000" || !ls.ran("zfs snapshot tank/mail@hardyos-manual-20261121-153000") {
		t.Fatalf("no safety snapshot: %+v", res)
	}
	if read(t, filepath.Join(md, "cur", "1700000000.M1P1.host,S=5:2,S")) != "one" || read(t, filepath.Join(md, "dovecot.index")) != "index" {
		t.Fatal("the version isn't back")
	}
	if _, err := os.Stat(filepath.Join(md, "new", "1700000009.M9P1.host,S=5")); err == nil {
		t.Fatal("overwrite kept mail the version didn't have")
	}
	if _, err := os.Stat(filepath.Join(md, "tmp", "partial")); err == nil {
		t.Fatal("a delivery in progress was restored")
	}
	if !ls.ran("doveadm kick alice@example.net") || !ls.ran("doveadm force-resync -u alice@example.net *") || !ls.ran("doveadm quota recalc -u alice@example.net") {
		t.Fatalf("Dovecot wasn't told: %v", ls.runner.Lines())
	}
}

// Decision 461: mailboxes are matched by key, never by address; another
// mailbox only when it's chosen and its address typed.
func TestRestoreMatchesByKey(t *testing.T) {
	ls := newLiveServer(t)
	ver := ls.version(t)
	ctx := context.Background()
	// The version's alice, into bob: refused without bob's address.
	if _, err := ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeMailbox, Key: keyAlice, Into: keyBob, Mode: RestoreCopy}); err == nil {
		t.Fatal("restored into another mailbox without confirmation")
	}
	if _, err := ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeMailbox, Key: keyAlice, Into: keyBob, Mode: RestoreCopy, Confirm: "bob@example.net"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(ls.e.VMailDir(), keyBob, "Maildir", ".Restored 2026-11-21 1530", "new", "1700000001.M2P1.host,S=5")); err != nil {
		t.Fatal(err)
	}
	// A key the server doesn't have now.
	if _, err := ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeMailbox, Key: keyAlice, Into: "ffffffffffffffffffffffff", Mode: RestoreCopy, Confirm: "x@example.net"}); err == nil {
		t.Fatal("restored into a mailbox that doesn't exist")
	}
	// A version mailbox that doesn't exist.
	if _, err := ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeMailbox, Key: "ffffffffffffffffffffffff", Mode: RestoreCopy}); err == nil {
		t.Fatal("restored a mailbox the version doesn't have")
	}
}

// What a version holds is untrusted: links, FIFOs and devices never come
// back, and nothing outside the dataset is read or written.
func TestRestoreRefusesLinks(t *testing.T) {
	ls := newLiveServer(t)
	ver := ls.version(t)
	vmd := filepath.Join(ver, "vmail", keyAlice, "Maildir")
	secret := filepath.Join(t.TempDir(), "secret")
	write(t, secret, "root's secret")
	if err := os.Symlink(secret, filepath.Join(vmd, "cur", "1700000005.M5P1.host:2,S")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(vmd, "new", "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A whole folder that's a link out.
	if err := os.Symlink(t.TempDir(), filepath.Join(vmd, ".Evil")); err != nil {
		t.Fatal(err)
	}
	res, err := ls.r.RestoreFrom(context.Background(), ver, RestoreArgs{Scope: ScopeMailbox, Key: keyAlice, Mode: RestoreOverwrite, Confirm: "alice@example.net"})
	if err != nil {
		t.Fatal(err)
	}
	md := filepath.Join(ls.e.VMailDir(), keyAlice, "Maildir")
	for _, p := range []string{filepath.Join(md, "cur", "1700000005.M5P1.host:2,S"), filepath.Join(md, "new", "fifo"), filepath.Join(md, ".Evil")} {
		if _, err := os.Lstat(p); err == nil {
			t.Fatalf("%s came back", p)
		}
	}
	if len(res.Notes) == 0 {
		t.Fatal("what was left out isn't said")
	}
	// The configuration itself as a link: refused.
	cfg := filepath.Join(ver, BackupDir, BackupConfigName)
	_ = os.Remove(cfg)
	_ = os.Symlink(ls.r.StateFile, cfg)
	if _, err := ls.r.RestoreFrom(context.Background(), ver, RestoreArgs{Scope: ScopeMailbox, Key: keyAlice, Mode: RestoreCopy}); err == nil {
		t.Fatal("a linked configuration was read")
	}
}

func TestRestoreCalendars(t *testing.T) {
	ls := newLiveServer(t)
	ver := ls.version(t)
	ctx := context.Background()
	croot := filepath.Join(ls.e.RadicaleDir(), "collections", "collection-root", keyAlice)
	_ = os.RemoveAll(filepath.Join(croot, "home"))
	write(t, filepath.Join(croot, "work", "new.ics"), "new")
	res, err := ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeCalendars, Key: keyAlice, Mode: RestoreCopy})
	if err != nil || res.Collections != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	got := filepath.Join(croot, "home-restored-20261121-153000")
	if read(t, filepath.Join(got, "event.ics")) == "" {
		t.Fatal("the calendar isn't back")
	}
	var props map[string]string
	_ = json.Unmarshal([]byte(read(t, filepath.Join(got, ".Radicale.props"))), &props)
	if props["D:displayname"] != "Home (restored 2026-11-21)" || props["tag"] != "VCALENDAR" {
		t.Fatalf("props %v", props)
	}
	if _, err := os.Stat(filepath.Join(got, ".Radicale.cache")); err == nil {
		t.Fatal("Radicale's cache was copied")
	}
	if _, err := os.Stat(filepath.Join(croot, "work", "new.ics")); err != nil {
		t.Fatal("a current calendar went")
	}
	// Overwrite: exactly the version's.
	if _, err := ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeCalendars, Key: keyAlice, Mode: RestoreOverwrite}); err == nil {
		t.Fatal("overwritten without the address")
	}
	if _, err := ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeCalendars, Key: keyAlice, Mode: RestoreOverwrite, Confirm: "alice@example.net"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(croot, "home", "event.ics")); err != nil {
		t.Fatal("not restored")
	}
	if _, err := os.Stat(filepath.Join(croot, "work")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("overwrite kept a calendar the version didn't have")
	}
}

func TestRestoreDomainAndDKIM(t *testing.T) {
	ls := newLiveServer(t)
	ver := ls.version(t)
	ctx := context.Background()
	key := ls.e.DKIMKeyPath("example.net", "hardyos1")
	old := read(t, key)
	// The key was lost and made again (a new key, which DNS doesn't know).
	_ = os.Remove(key)
	if _, err := ls.r.DKIM(ctx, DKIMArgs{Pool: "tank", Domain: "example.net", Selector: "hardyos1"}); err != nil {
		t.Fatal(err)
	}
	if read(t, key) == old {
		t.Fatal("test setup: same key")
	}
	if _, err := ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeDomain, Domain: "example.net", Mode: RestoreOverwrite, Confirm: "family.example"}); err == nil {
		t.Fatal("overwritten without the domain typed")
	}
	if _, err := ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeDomain, Domain: "unknown.example", Mode: RestoreCopy}); err == nil {
		t.Fatal("a domain this server doesn't have")
	}
	res, err := ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeDomain, Domain: "example.net", Mode: RestoreOverwrite, Confirm: "example.net"})
	if err != nil {
		t.Fatal(err)
	}
	if read(t, key) != old || len(res.DKIM) != 1 || res.Mailboxes != 1 {
		t.Fatalf("DKIM key not back: %+v", res)
	}
	if st, _ := os.Stat(key); st.Mode().Perm() != 0o640 {
		t.Fatalf("key mode %v", st.Mode())
	}
	// An unusable key in the version is refused.
	write(t, filepath.Join(ver, "keys", "dkim", "example.net.hardyos1.key"), "not a key")
	if _, err := ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeDomain, Domain: "example.net", Mode: RestoreOverwrite, Confirm: "example.net"}); err == nil {
		t.Fatal("a broken DKIM key was installed")
	}
	if read(t, key) != old {
		t.Fatal("the key changed")
	}
}

func TestRestoreEverything(t *testing.T) {
	ls := newLiveServer(t)
	ver := ls.version(t)
	ctx := context.Background()
	_ = os.RemoveAll(filepath.Join(ls.e.VMailDir(), keyAlice))
	write(t, filepath.Join(ls.redis, "dump.rdb"), "forgotten")
	if _, err := ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeAll, Confirm: "alice@example.net"}); err == nil {
		t.Fatal("everything without typing mail")
	}
	starts := ls.starts
	res, err := ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeAll, Confirm: "mail"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Bayes || read(t, filepath.Join(ls.redis, "dump.rdb")) != "REDIS0011-learned" {
		t.Fatal("Rspamd's data isn't back")
	}
	if read(t, filepath.Join(ls.e.VMailDir(), keyAlice, "Maildir", "cur", "1700000000.M1P1.host,S=5:2,S")) != "one" {
		t.Fatal("mail isn't back")
	}
	if !ls.ran("systemctl stop") || ls.starts != starts+1 || res.Safety == "" || len(res.DKIM) != 2 {
		t.Fatalf("not stopped, snapshotted and started again: %+v %v", res, ls.runner.Lines())
	}
}

func TestRebuild(t *testing.T) {
	ls := newLiveServer(t)
	ver := ls.version(t)
	ctx := context.Background()
	if _, err := ls.r.RebuildFrom(ctx, "tank", ver); err == nil {
		t.Fatal("rebuilt over a mail server that is set up")
	}
	// A new server: nothing set up, an empty pool.
	dir := t.TempDir()
	redis := t.TempDir()
	r := &Root{
		Runner:     (&sysexec.Fake{}).OnPrefix("", sysexec.Result{}),
		Chown:      func(string, int, int) error { return nil },
		LookupUser: func(string) (int, int, error) { return os.Getuid(), os.Getgid(), nil },
		LookupGrp:  func(string) (int, error) { return os.Getgid(), nil },
		Dataset:    func(context.Context, string) (string, error) { return dir, nil },
		StateFile:  filepath.Join(dir, "state.json"),
		RedisDir:   redis,
		Write:      func(p string, b []byte, m os.FileMode) error { return os.WriteFile(p, b, m) },
	}
	res, err := r.RebuildFrom(ctx, "tank2", ver)
	if err != nil {
		t.Fatal(err)
	}
	e := Env{MailRoot: dir}
	if res.Mailboxes != 1 || read(t, filepath.Join(e.VMailDir(), keyAlice, "Maildir", ".Sent", "cur", "1700000002.M3P1.host:2,S")) != "sent" {
		t.Fatalf("mail: %+v", res)
	}
	if read(t, e.DKIMKeyPath("example.net", "hardyos1")) != read(t, ls.e.DKIMKeyPath("example.net", "hardyos1")) {
		t.Fatal("DKIM key")
	}
	if read(t, filepath.Join(e.RadicaleDir(), "collections", "collection-root", keyAlice, "home", "event.ics")) == "" {
		t.Fatal("calendar")
	}
	if read(t, e.TLSKey()) != read(t, ls.e.TLSKey()) || read(t, filepath.Join(redis, "dump.rdb")) != "REDIS0011-learned" {
		t.Fatal("TLS key or Rspamd's data")
	}
	if readLayout(e) != LayoutVersion {
		t.Fatal("layout version not recorded")
	}
	if _, err := r.RebuildFrom(ctx, "tank2", ver); err == nil {
		t.Fatal("rebuilt twice over the same mail")
	}
}
