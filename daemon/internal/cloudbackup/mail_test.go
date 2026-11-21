package cloudbackup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/mail"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

const (
	mailKeyA = "a11ce0000000000000000001"
	mailKeyB = "b0b000000000000000000002"
)

// mailRoot is the real mail root on a temporary dataset (no programs, no
// system folders), applied with two mailboxes.
func mailRoot(t *testing.T, dir string) *mail.Root {
	t.Helper()
	redis := filepath.Join(dir, "..", "redis-"+filepath.Base(dir))
	_ = os.MkdirAll(redis, 0o750)
	r := &mail.Root{
		Runner:     (&sysexec.Fake{}).OnPrefix("", sysexec.Result{}),
		Chown:      func(string, int, int) error { return nil },
		LookupUser: func(string) (int, int, error) { return os.Getuid(), os.Getgid(), nil },
		LookupGrp:  func(string) (int, error) { return os.Getgid(), nil },
		Dataset:    func(context.Context, string) (string, error) { return dir, nil },
		SkipChecks: true,
		StateFile:  filepath.Join(dir, "..", "mail-state-"+filepath.Base(dir)+".json"),
		RedisDir:   redis,
		Now:        func() time.Time { return time.Date(2026, 11, 21, 15, 30, 0, 0, time.UTC) },
		StartServices: func(context.Context, mail.RootConfig, *mail.ApplyResult) error {
			return nil
		},
	}
	r.Write = func(p string, b []byte, m os.FileMode) error {
		if strings.HasPrefix(p, dir) || strings.HasPrefix(p, filepath.Dir(dir)) {
			return os.WriteFile(p, b, m)
		}
		return nil
	}
	cfg := mail.RootConfig{
		Pool: "tank", Hostname: "mail.example.net", VPSPeer: "100.90.1.2", NetBirdNet: "100.90.0.0/16", NetBirdIface: "wt0",
		Domains: []mail.RootDomain{{Name: "example.net", Selector: "hardyos1"}},
		Mailboxes: []mail.RootMailbox{
			{Key: mailKeyA, Address: "alice@example.net"},
			{Key: mailKeyB, Address: "bob@example.net"},
		},
		Postmaster: "alice@example.net",
	}
	sec := mail.RootSecrets{AuthSecret: "0123456789abcdef0123456789abcdef0123456789abcdef"}
	if _, err := r.Apply(context.Background(), mail.ApplyArgs{Config: cfg, Secrets: sec}); err != nil {
		t.Fatal(err)
	}
	return r
}

// Decisions 460-462: the mail item is the mail dataset (with the
// configuration and Rspamd's data put in first) plus Roundcube's data;
// one mailbox comes back into a new folder, everything with "mail" typed.
func TestBackupRestoreMail(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tg := e.target("mailt")
	mailDir := filepath.Join(e.base, "mail")
	_ = os.MkdirAll(mailDir, 0o755)
	mr := mailRoot(t, mailDir)
	e.root.Mail = mr
	e.vol.ds["tank/mail"] = mailDir
	md := filepath.Join(mailDir, "vmail", mailKeyA, "Maildir")
	write(t, filepath.Join(md, "cur", "1700000000.M1P1.host,S=5:2,S"), "hello")
	write(t, filepath.Join(md, ".Sent", "cur", "1700000001.M2P1.host:2,S"), "sent")
	write(t, filepath.Join(mailDir, "radicale", "collections", "collection-root", mailKeyA, "home", "event.ics"), "BEGIN:VCALENDAR")
	write(t, filepath.Join(mailDir, "..", "redis-mail", "dump.rdb"), "REDIS-learned")
	// Webmail: Roundcube's preferences.
	rcDir := filepath.Join(e.base, "app-roundcube")
	write(t, filepath.Join(rcDir, "data", "db", "sqlite.db"), "prefs v1")
	e.vol.ds["tank/apps/roundcube"] = rcDir
	e.apps.srcs[WebmailApp] = appSource(WebmailApp, "Mail (Roundcube)")
	e.apps.dirs[WebmailApp] = rcDir

	x, res := e.backup(tg.ID, "all", "m1", Item{Kind: ItemMail})
	if x.Error != "" || res.Failed != 0 || len(res.Items) != 1 || len(res.Items[0].Snapshots) != 2 {
		t.Fatalf("%s %+v", x.Error, res)
	}
	versions, _ := e.root.Versions(ctx, tg.ID)
	var mi VersionItem
	for _, it := range versions[0].Items {
		if it.Item == ItemMail {
			mi = it
		}
	}
	if mi.Snapshot == "" || mi.Webmail == "" {
		t.Fatalf("items: %+v", versions[0].Items)
	}
	repo, _ := e.root.repo(tg.ID)
	m, err := e.root.readManifest(ctx, repo, versions[0].Manifest)
	if err != nil || m.Mail == nil || !m.Mail.Bayes || !m.Mail.Webmail || m.Mail.Mailboxes != 2 {
		t.Fatalf("manifest: %+v %v", m, err)
	}
	c, err := e.root.MailContents(ctx, MailContentsArgs{Target: tg.ID, Snapshot: mi.Snapshot})
	if err != nil || len(c.Mailboxes) != 2 || c.Mailboxes[0].Address != "alice@example.net" || !c.Webmail || c.Domains[0] != "example.net" {
		t.Fatalf("contents: %+v %v", c, err)
	}
	if _, err := e.root.MailContents(ctx, MailContentsArgs{Target: tg.ID, Snapshot: mi.Webmail}); err == nil {
		t.Fatal("the webmail part listed as mail")
	}

	// Mail is restored only as mail, and only the files part.
	if _, err := e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: mi.Snapshot, Mode: ModeRollback, Confirm: "Mail"}); err == nil {
		t.Fatal("rolled the mail back like a folder")
	}
	if _, err := e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: mi.Webmail, Mode: ModeMail, Mail: &mail.RestoreArgs{Scope: mail.ScopeAll, Confirm: "mail"}}); err == nil {
		t.Fatal("restored the webmail part on its own")
	}
	if _, err := e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: mi.Snapshot, Mode: ModeMail, Mail: &mail.RestoreArgs{Scope: mail.ScopeAll, Confirm: "yes"}}); err == nil {
		t.Fatal("everything without typing mail")
	}

	// One mailbox into a new folder.
	_ = os.Remove(filepath.Join(md, "cur", "1700000000.M1P1.host,S=5:2,S"))
	x = e.wait(e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: mi.Snapshot, Mode: ModeMail,
		Mail: &mail.RestoreArgs{Scope: mail.ScopeMailbox, Key: mailKeyA, Mode: mail.RestoreCopy}}))
	if x.Error != "" {
		t.Fatal(x.Error)
	}
	if got := read(t, filepath.Join(md, ".Restored 2026-11-21 1530", "cur", "1700000000.M1P1.host,S=5:2,S")); got != "hello" {
		t.Fatalf("restored %q", got)
	}
	if got := read(t, filepath.Join(md, ".Restored 2026-11-21 1530.Sent", "cur", "1700000001.M2P1.host:2,S")); got != "sent" {
		t.Fatalf("restored Sent %q", got)
	}

	// Everything, webmail included.
	write(t, filepath.Join(rcDir, "data", "db", "sqlite.db"), "prefs v2")
	_ = os.RemoveAll(filepath.Join(mailDir, "vmail", mailKeyA))
	write(t, filepath.Join(mailDir, "..", "redis-mail", "dump.rdb"), "forgotten")
	x = e.wait(e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: mi.Snapshot, Mode: ModeMail,
		Mail: &mail.RestoreArgs{Scope: mail.ScopeAll, Confirm: "mail"}}))
	if x.Error != "" {
		t.Fatal(x.Error)
	}
	if read(t, filepath.Join(md, "cur", "1700000000.M1P1.host,S=5:2,S")) != "hello" || read(t, filepath.Join(mailDir, "..", "redis-mail", "dump.rdb")) != "REDIS-learned" {
		t.Fatal("the mail server isn't back")
	}
	if read(t, filepath.Join(rcDir, "data", "db", "sqlite.db")) != "prefs v1" {
		t.Fatal("webmail settings aren't back")
	}
}

// On by default (decision 460): a server without a mail server backs the
// item up as nothing, without a failure.
func TestBackupMailNotSetUp(t *testing.T) {
	e := newEnv(t)
	tg := e.target("nomail")
	e.root.Mail = &mail.Root{StateFile: filepath.Join(e.base, "none.json")}
	x, res := e.backup(tg.ID, "all", "n1", Item{Kind: ItemMail})
	if x.Error != "" || res.Failed != 0 || res.Items[0].Warning == "" || len(res.Items[0].Snapshots) != 0 {
		t.Fatalf("%s %+v", x.Error, res)
	}
}

func TestMailItem(t *testing.T) {
	it, err := ParseItem("mail")
	if err != nil || it.Kind != ItemMail || it.Key() != "mail" {
		t.Fatalf("%+v %v", it, err)
	}
	for _, bad := range []string{"mail:x", "mail:"} {
		if _, err := ParseItem(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if (Item{Kind: ItemMail, ID: "x"}).Check() == nil {
		t.Fatal("a mail item with an id")
	}
}
