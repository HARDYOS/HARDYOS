//go:build mailintegration

package mail

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func fileOwner(st os.FileInfo) string {
	uid := st.Sys().(*syscall.Stat_t).Uid
	u, err := user.LookupId(strconv.Itoa(int(uid)))
	if err != nil {
		return strconv.Itoa(int(uid))
	}
	return u.Username
}

// doveadmCount counts a mailbox's messages as Dovecot sees them.
func doveadmCount(t *testing.T, user, mailbox string) int {
	t.Helper()
	out, err := exec.Command("doveadm", "search", "-u", user, "mailbox", mailbox, "all").CombinedOutput()
	if err != nil {
		t.Fatalf("doveadm search %s %s: %v %s", user, mailbox, err, out)
	}
	return len(strings.Fields(string(out))) / 2 // "<guid> <uid>" per message
}

// backupRoundTrip (decisions 460-463): the backup's preparation saves
// Rspamd's Redis into the dataset, and a copy of the dataset (as a staged
// version would be) gives a mailbox back to the real Dovecot: into a new,
// subscribed folder, then over the mailbox.
func backupRoundTrip(t *testing.T, r *Root) {
	ctx := context.Background()
	user := "alice@example.test"
	before := doveadmCount(t, user, "INBOX")
	if before == 0 {
		t.Fatal("alice has no mail to back up")
	}
	src, err := r.PrepareBackup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !src.Bayes {
		t.Fatalf("Rspamd's data isn't in the backup: %v", src.Warnings)
	}
	if st, err := os.Stat(filepath.Join(itMailRoot, BackupDir, BackupBayesName)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("rdb: %v %v", st, err)
	}
	// The real Redis's dump passes root's own check (decision 467).
	if f, err := os.Open(filepath.Join(itMailRoot, BackupDir, BackupBayesName)); err != nil {
		t.Fatal(err)
	} else {
		err := CheckRDB(f)
		f.Close()
		if err != nil {
			t.Fatalf("the real Redis dump was refused: %v", err)
		}
	}
	ver := t.TempDir()
	if out, err := exec.Command("cp", "-a", itMailRoot+"/.", ver).CombinedOutput(); err != nil {
		t.Fatalf("cp: %v %s", err, out)
	}
	// Alice loses her INBOX.
	for _, sub := range []string{"new", "cur"} {
		files, _ := filepath.Glob(filepath.Join(itMailRoot, "vmail", itKeyAlice, "Maildir", sub, "*"))
		for _, f := range files {
			_ = os.Remove(f)
		}
	}
	itRun(t, "doveadm", "force-resync", "-u", user, "INBOX")
	if n := doveadmCount(t, user, "INBOX"); n != 0 {
		t.Fatalf("still %d messages", n)
	}
	r.SafetySnapshot = func(context.Context, string, string) error { return nil }

	res, err := r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeMailbox, Key: itKeyAlice, Mode: RestoreCopy})
	if err != nil {
		t.Fatal(err)
	}
	if n := doveadmCount(t, user, res.Folder); n != before {
		t.Fatalf("the restored folder %q has %d messages, want %d", res.Folder, n, before)
	}
	subs, err := exec.Command("doveadm", "mailbox", "list", "-s", "-u", user).CombinedOutput()
	if err != nil || !strings.Contains(string(subs), res.Folder) {
		t.Fatalf("not subscribed: %v %s", err, subs)
	}

	if _, err := r.RestoreFrom(ctx, ver, RestoreArgs{Scope: ScopeMailbox, Key: itKeyAlice, Mode: RestoreOverwrite, Confirm: user}); err != nil {
		t.Fatal(err)
	}
	if n := doveadmCount(t, user, "INBOX"); n != before {
		t.Fatalf("INBOX has %d messages after overwriting, want %d", n, before)
	}
	// The restored mailbox belongs to the mail user, root-only parts stay
	// root's.
	st, err := os.Stat(filepath.Join(itMailRoot, "vmail", itKeyAlice, "Maildir"))
	if err != nil {
		t.Fatal(err)
	}
	if owner := fileOwner(st); owner != VMailUser {
		t.Fatalf("Maildir owned by %s", owner)
	}
	if !imapLogin(t, itLAN, PortIMAPS, "", user, itPasswords[user]) {
		t.Fatal("alice can't sign in after the restore")
	}
}
