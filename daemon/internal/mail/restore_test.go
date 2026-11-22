package mail

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func TestCheckRDB(t *testing.T) {
	ok := []string{
		testRDB,
		"REDIS0012\xfe\x00",
		// An aux value as an integer and an LZF string.
		"REDIS0011\xfa\x05ctime\xc2\x01\x02\x03\x04\xfa\x01x\xc3\x02\x03ab\xff",
	}
	for _, s := range ok {
		if err := CheckRDB(strings.NewReader(s)); err != nil {
			t.Errorf("%q refused: %v", s, err)
		}
	}
	for name, s := range map[string]string{
		"functions":     "REDIS0011\xfa\x01a\x01b\xf5\x00",
		"old functions": "REDIS0010\xf6\x00",
		"module data":   "REDIS0011\xf7\x00",
		"not redis":     "SQLite format 3",
		"bad version":   "REDIS00ab\xff",
		"unknown":       "REDIS0011\x42",
		"truncated":     "REDIS0011\xfa\x09redis",
		"huge":          "REDIS0011\xfa\x81\x00\x00\x00\x01\x00\x00\x00\x00",
	} {
		if err := CheckRDB(strings.NewReader(s)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Decision 467: Rspamd's data never comes from a replica, and from a
// backup only a dump without functions; the previous dump stays until
// Redis is up with the restored one.
func TestRestoreBayesChecks(t *testing.T) {
	ls := newLiveServer(t)
	ver := ls.version(t)
	ctx := context.Background()
	write(t, filepath.Join(ls.redis, "dump.rdb"), "REDIS0011\xff-current")
	res, err := ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeAll, Confirm: "mail", FromReplica: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Bayes || read(t, filepath.Join(ls.redis, "dump.rdb")) != "REDIS0011\xff-current" || !strings.Contains(strings.Join(res.Notes, " "), "another server") {
		t.Fatalf("Rspamd's data taken from a replica: %+v", res)
	}
	write(t, filepath.Join(ver, BackupDir, BackupBayesName), "REDIS0011\xf5\x00evil")
	if res, err = ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeAll, Confirm: "mail"}); err != nil {
		t.Fatal(err)
	}
	if res.Bayes || read(t, filepath.Join(ls.redis, "dump.rdb")) != "REDIS0011\xff-current" {
		t.Fatalf("a dump with functions was restored: %+v", res)
	}
	// redis-check-rdb refuses it.
	write(t, filepath.Join(ver, BackupDir, BackupBayesName), testRDB)
	ls.runner.OnResult("setpriv --reuid=redis --regid=redis --clear-groups --no-new-privs --inh-caps=-all redis-check-rdb "+filepath.Join(ls.redis, "dump.rdb.restoring"),
		sysexec.Result{ExitCode: 1, Stderr: []byte("--- RDB ERROR DETECTED ---")})
	if res, err = ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeAll, Confirm: "mail"}); err != nil || res.Bayes {
		t.Fatalf("a dump redis-check-rdb refused: %+v %v", res, err)
	}
}

func TestRestoreBayesFallsBack(t *testing.T) {
	ls := newLiveServer(t)
	ver := ls.version(t)
	write(t, filepath.Join(ls.redis, "dump.rdb"), "REDIS0011\xff-current")
	// Redis doesn't come up with the restored data.
	f := &sysexec.Fake{}
	f.OnResult("systemctl is-active --quiet "+RedisUnit, sysexec.Result{ExitCode: 3})
	f.OnPrefix("", sysexec.Result{})
	ls.r.Runner, ls.runner = f, f
	res, err := ls.r.RestoreFrom(context.Background(), ver, RestoreArgs{Scope: ScopeAll, Confirm: "mail"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Bayes || read(t, filepath.Join(ls.redis, "dump.rdb")) != "REDIS0011\xff-current" || !ls.ran("systemctl restart "+RedisUnit) {
		t.Fatalf("not back to the previous data: %+v %v", res, f.Lines())
	}
}

// Decision 466: a cancelled restore of everything still starts the mail
// server again.
func TestRestoreEverythingCancelledStartsAgain(t *testing.T) {
	ls := newLiveServer(t)
	ver := ls.version(t)
	ctx, cancel := context.WithCancel(context.Background())
	starts := ls.starts
	ls.r.SafetySnapshot = func(context.Context, string, string) error { cancel(); return nil }
	if _, err := ls.r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeAll, Confirm: "mail"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("not cancelled: %v", err)
	}
	if !ls.ran("systemctl stop") || ls.starts != starts+1 {
		t.Fatal("the mail server wasn't started again")
	}
}

// H1: mail delivered while a mailbox is being restored stays in it.
func TestOverwriteKeepsMailArrivingDuringTheRestore(t *testing.T) {
	ls := newLiveServer(t)
	ver := ls.version(t)
	md := filepath.Join(ls.e.VMailDir(), keyAlice, "Maildir")
	// Right before the swap (the second snapshot) a message arrives, in a
	// folder the version doesn't have.
	n := 0
	ls.r.SafetySnapshot = func(context.Context, string, string) error {
		if n++; n == 2 {
			write(t, filepath.Join(md, ".Lists", "new", "1700009999.M1P1.host,S=4"), "late")
			write(t, filepath.Join(md, "cur", "1700009998.M1P1.host,S=4:2,S"), "read")
		}
		return nil
	}
	res, err := ls.r.RestoreFrom(context.Background(), ver, RestoreArgs{Scope: ScopeMailbox, Key: keyAlice, Mode: RestoreOverwrite, Confirm: "alice@example.net"})
	if err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(md, ".Lists", "new", "1700009999.M1P1.host,S=4")) != "late" || read(t, filepath.Join(md, "cur", "1700009998.M1P1.host,S=4:2,S")) != "read" || res.Kept != 2 {
		t.Fatalf("mail delivered during the restore was lost: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(md, ".Lists", "maildirfolder")); err != nil {
		t.Fatal("the folder made for kept mail isn't a Maildir++ folder")
	}
	// A message the version has (by base name, with other flags now) isn't
	// doubled.
	if _, err := os.Stat(filepath.Join(md, "new", "1700000001.M2P1.host,S=5")); err != nil {
		t.Fatal(err)
	}
}

// M4: an overwrite brings the Maildir's messages only: no Sieve scripts
// or other files of the home, which stay as they are.
func TestOverwriteOnlyMaildir(t *testing.T) {
	ls := newLiveServer(t)
	home := filepath.Join(ls.e.VMailDir(), keyAlice)
	write(t, filepath.Join(home, ".dovecot.sieve"), "keep \"live\";")
	ver := ls.version(t)
	write(t, filepath.Join(ver, "vmail", keyAlice, ".dovecot.sieve"), "redirect \"evil@example.org\";")
	write(t, filepath.Join(ver, "vmail", keyAlice, "sieve", "x.sieve"), "redirect \"evil@example.org\";")
	write(t, filepath.Join(ver, "vmail", keyAlice, "Maildir", ".Sent", ".dovecot.sieve"), "x")
	if _, err := ls.r.RestoreFrom(context.Background(), ver, RestoreArgs{Scope: ScopeMailbox, Key: keyAlice, Mode: RestoreOverwrite, Confirm: "alice@example.net"}); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(home, ".dovecot.sieve")) != "keep \"live\";" {
		t.Fatal("the live Sieve script was replaced")
	}
	for _, p := range []string{filepath.Join(home, "sieve"), filepath.Join(home, "Maildir", ".Sent", ".dovecot.sieve")} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("%s came back", p)
		}
	}
}

// M2: a domain's restore leaves out mailboxes that are at another domain
// now.
func TestDomainRestoreOnlyItsMailboxesNow(t *testing.T) {
	ls := newLiveServer(t)
	ver := ls.version(t)
	b, _ := os.ReadFile(ls.r.StateFile)
	b = bytes.Replace(b, []byte(`"address":"alice@example.net"`), []byte(`"address":"alice@family.example"`), 1)
	if err := os.WriteFile(ls.r.StateFile, b, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := ls.r.RestoreFrom(context.Background(), ver, RestoreArgs{Scope: ScopeDomain, Domain: "example.net", Mode: RestoreCopy})
	if err != nil {
		t.Fatal(err)
	}
	if res.Mailboxes != 0 || !strings.Contains(strings.Join(res.Notes, " "), "alice@family.example") {
		t.Fatalf("restored a mailbox of another domain: %+v", res)
	}
}

// Decision 469: a restore that clearly doesn't fit is refused up front.
func TestRestoreNeedsSpace(t *testing.T) {
	ls := newLiveServer(t)
	ver := ls.version(t)
	ls.r.Free = func(string) (int64, error) { return 1 << 20, nil }
	_, err := ls.r.RestoreFrom(context.Background(), ver, RestoreArgs{Scope: ScopeMailbox, Key: keyAlice, Mode: RestoreCopy})
	if err == nil || !strings.Contains(err.Error(), "is free") {
		t.Fatalf("restored without room: %v", err)
	}
	ls.r.Free = func(string) (int64, error) { return 1 << 40, nil }
	sp, err := ls.r.Space(context.Background())
	if err != nil || sp.FreeBytes != 1<<40 || sp.Pool != "tank" {
		t.Fatalf("%+v %v", sp, err)
	}
}

// What overwrites replaced goes after ReplacedDays, at the next apply.
func TestReplacedCopiesExpire(t *testing.T) {
	ls := newLiveServer(t)
	old := filepath.Join(ls.e.VMailDir(), keyAlice, ".replaced-20261001-120000")
	recent := filepath.Join(ls.e.VMailDir(), keyAlice, ".replaced-20261120-120000")
	oldCal := filepath.Join(ls.e.RadicaleDir(), "collections", "collection-root", ".replaced-"+keyAlice+"-20261001-120000")
	other := filepath.Join(ls.e.VMailDir(), keyAlice, ".replacedish")
	for _, d := range []string{old, recent, oldCal, other} {
		write(t, filepath.Join(d, "x"), "x")
	}
	if _, err := ls.r.Apply(context.Background(), ApplyArgs{Config: sampleConfig(), Secrets: sampleSecrets()}); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]bool{old: false, oldCal: false, recent: true, other: true} {
		if _, err := os.Stat(p); (err == nil) != want {
			t.Errorf("%s: exists=%v", p, err == nil)
		}
	}
}

// Decision 468: a rebuild needs an empty mail dataset and a TLS key that
// belongs to its certificate.
func TestRebuildRefusesExistingData(t *testing.T) {
	ls := newLiveServer(t)
	ver := ls.version(t)
	newRoot := func() (*Root, string) {
		dir := t.TempDir()
		return &Root{
			Runner:     (&sysexec.Fake{}).OnPrefix("", sysexec.Result{}),
			Chown:      func(string, int, int) error { return nil },
			LookupUser: func(string) (int, int, error) { return os.Getuid(), os.Getgid(), nil },
			LookupGrp:  func(string) (int, error) { return os.Getgid(), nil },
			Dataset:    func(context.Context, string) (string, error) { return dir, nil },
			StateFile:  filepath.Join(dir, "state.json"),
			RedisDir:   t.TempDir(),
			Write:      func(p string, b []byte, m os.FileMode) error { return os.WriteFile(p, b, m) },
		}, dir
	}
	r, dir := newRoot()
	write(t, filepath.Join(dir, "keys", "dkim", "example.net.old.key"), "x")
	if _, err := r.RebuildFrom(context.Background(), "tank2", ver); err == nil || !strings.Contains(err.Error(), "DKIM") {
		t.Fatalf("rebuilt over DKIM keys: %v", err)
	}
	r, dir = newRoot()
	write(t, filepath.Join(dir, "radicale", "collections", "collection-root", "x", "y.ics"), "x")
	if _, err := r.RebuildFrom(context.Background(), "tank2", ver); err == nil || !strings.Contains(err.Error(), "calendars") {
		t.Fatalf("rebuilt over calendars: %v", err)
	}
	// A key that doesn't belong to the certificate isn't installed.
	r, dir = newRoot()
	write(t, filepath.Join(ver, "keys", "tls", "key.pem"), read(t, filepath.Join(ver, "keys", "dkim", "example.net.hardyos1.key")))
	res, err := r.RebuildFrom(context.Background(), "tank2", ver)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "keys", "tls", "key.pem")); err == nil || !strings.Contains(strings.Join(res.Notes, " "), "TLS") {
		t.Fatalf("a mismatched TLS key was installed: %+v", res)
	}
}
