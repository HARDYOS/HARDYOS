package replication

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/mail"
	"github.com/hardyos/hardyos/daemon/internal/replica"
)

// Decisions 460 and 466: the mail item replicates like any dataset, is
// skipped (not failed) on a server without a mail server, and comes back
// only as a mail restore under a new copy id.
func TestReplicateAndRestoreMail(t *testing.T) {
	ctx := context.Background()
	a, b := newNode(t, "alpha"), newNode(t, "bravo")
	b.serve(t)
	a.root.addItem(replica.KindShare, "media", "Media")
	tgt := pair(t, a, b)
	task := &Task{Name: "T", TargetID: tgt.ID, IntervalMinutes: 60, KeepLocal: 1, KeepRemote: 1, Enabled: true,
		Items: []replica.Item{{Kind: replica.KindShare, ID: "media"}, {Kind: replica.KindMail, ID: replica.MailItem}}}
	if _, err := a.svc.saveTask(ctx, task); err != nil {
		t.Fatal(err)
	}
	// No mail server here yet: the share is copied, the run succeeds.
	if j := a.run(t, task.ID); j.State != jobs.Succeeded {
		t.Fatal(j.Error)
	}
	a.root.addItem(replica.KindMail, replica.MailItem, "Mail")
	if j := a.run(t, task.ID); j.State != jobs.Succeeded {
		t.Fatal(j.Error)
	}
	mailRep := "tank/replicas/" + tgt.SourceID + "/mail/mail"
	b.root.mu.Lock()
	n := len(b.root.replicas[mailRep].snaps)
	b.root.mu.Unlock()
	if n != 1 {
		t.Fatalf("mail replica: %d snapshots", n)
	}
	snaps, err := a.svc.TargetSnapshots(ctx, tgt.ID, replica.KindMail, replica.MailItem)
	if err != nil || len(snaps) == 0 {
		t.Fatalf("%v %v", snaps, err)
	}
	// Without saying what of the mail, or with a bad request: refused.
	for _, p := range []RestoreParams{
		{Target: tgt.ID, Kind: replica.KindMail, ID: replica.MailItem, Snapshot: snaps[0].Name},
		{Target: tgt.ID, Kind: replica.KindMail, ID: replica.MailItem, Snapshot: snaps[0].Name, Mail: &mail.RestoreArgs{Scope: mail.ScopeAll, Confirm: "no"}},
		{Target: tgt.ID, Kind: replica.KindShare, ID: "media", Snapshot: snaps[0].Name, Pool: "tank", NewID: "m2", Name: "M2", Mail: &mail.RestoreArgs{Scope: mail.ScopeAll, Confirm: "mail"}},
	} {
		if j := a.submit(t, JobRestore, p); j.State != jobs.Failed {
			t.Fatalf("restored %+v", p)
		}
	}
	j := a.submit(t, JobRestore, RestoreParams{Target: tgt.ID, Kind: replica.KindMail, ID: replica.MailItem, Snapshot: snaps[0].Name,
		Pool: "evil", NewID: "../../etc", Mail: &mail.RestoreArgs{Scope: mail.ScopeMailbox, Key: "a11ce0000000000000000001", Mode: mail.RestoreCopy}})
	if j.State != jobs.Succeeded {
		t.Fatal(j.Error)
	}
	a.root.mu.Lock()
	defer a.root.mu.Unlock()
	fin := a.root.finished[len(a.root.finished)-1]
	if fin.Kind != replica.KindMail || fin.Pool != "" || !strings.HasPrefix(fin.NewID, "m") || replica.ValidItem(fin.NewID) != nil {
		t.Fatalf("finish: %+v", fin)
	}
	var got mail.RestoreArgs
	if err := json.Unmarshal(fin.Mail, &got); err != nil || got.Scope != mail.ScopeMailbox || got.Into != got.Key {
		t.Fatalf("mail args: %s %v", fin.Mail, err)
	}
	for _, r := range a.root.restored {
		if r.Kind == replica.KindMail && (r.NewID != fin.NewID || r.Pool != "") {
			t.Fatalf("receive: %+v", r)
		}
	}
}

// Decision 469: an existing task gets Mail only once the other server
// accepts it, visibly; an older server makes the mail item skipped, not
// a failed run.
func TestMailAddedOnceThePeerAcceptsIt(t *testing.T) {
	ctx := context.Background()
	a, b := newNode(t, "alpha"), newNode(t, "bravo")
	b.svc.acceptKinds = []string{replica.KindShare, replica.KindApp, replica.KindVM} // before this update
	b.serve(t)
	a.root.addItem(replica.KindShare, "media", "Media")
	a.root.addItem(replica.KindMail, replica.MailItem, "Mail")
	tgt := pair(t, a, b)
	task := &Task{Name: "Old", TargetID: tgt.ID, IntervalMinutes: 60, KeepLocal: 1, KeepRemote: 1, Enabled: true, Items: []replica.Item{{Kind: replica.KindShare, ID: "media"}}}
	if _, err := a.svc.saveTask(ctx, task); err != nil {
		t.Fatal(err)
	}
	if _, err := a.svc.Store().DB.ExecContext(ctx, `UPDATE repl_tasks SET mail_auto = 'pending' WHERE id = ?`, task.ID); err != nil {
		t.Fatal(err)
	}
	if j := a.run(t, task.ID); j.State != jobs.Succeeded {
		t.Fatal(j.Error)
	}
	got, _ := a.svc.Store().Task(ctx, task.ID)
	if got.MailAuto != "pending" || len(got.Items) != 1 {
		t.Fatalf("mail added for a server that doesn't take it: %+v", got)
	}
	// A task with Mail ticked: skipped with a note, the run succeeds.
	other := &Task{Name: "Mail", TargetID: tgt.ID, IntervalMinutes: 60, KeepLocal: 1, KeepRemote: 1, Enabled: true, Items: []replica.Item{{Kind: replica.KindMail, ID: replica.MailItem}}}
	if _, err := a.svc.saveTask(ctx, other); err != nil {
		t.Fatal(err)
	}
	j := a.run(t, other.ID)
	if j.State != jobs.Succeeded || !strings.Contains(string(j.Result), "doesn't accept") {
		t.Fatalf("%s %s %s", j.State, j.Error, j.Result)
	}
	if err := a.svc.deleteTask(ctx, TaskDeleteParams{Task: other.ID, Confirm: other.Name}); err != nil {
		t.Fatal(err)
	}

	// bravo is updated: Mail is added, and the administrators are told.
	b.svc.acceptKinds = nil
	if j := a.run(t, task.ID); j.State != jobs.Succeeded {
		t.Fatal(j.Error)
	}
	got, _ = a.svc.Store().Task(ctx, task.ID)
	if got.MailAuto != "added" || len(got.Items) != 2 || got.Items[1].Kind != replica.KindMail {
		t.Fatalf("mail not added: %+v", got)
	}
	if !strings.Contains(a.notes.kinds(), EventMailAdded+":warning") {
		t.Fatalf("not told: %s", a.notes.kinds())
	}
	b.root.mu.Lock()
	n := len(b.root.replicas["tank/replicas/"+tgt.SourceID+"/mail/mail"].snaps)
	b.root.mu.Unlock()
	if n != 1 {
		t.Fatalf("mail replica: %d", n)
	}
	// One click off: saving the task without Mail clears the mark for good.
	got.Items = got.Items[:1]
	if _, err := a.svc.saveTask(ctx, got); err != nil {
		t.Fatal(err)
	}
	got, _ = a.svc.Store().Task(ctx, task.ID)
	if got.MailAuto != "" || len(got.Items) != 1 {
		t.Fatalf("%+v", got)
	}
	if j := a.run(t, task.ID); j.State != jobs.Succeeded {
		t.Fatal(j.Error)
	}
	if got, _ = a.svc.Store().Task(ctx, task.ID); len(got.Items) != 1 {
		t.Fatal("mail came back after being turned off")
	}
}
