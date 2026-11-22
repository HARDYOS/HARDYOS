package replica

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func TestMailKind(t *testing.T) {
	if err := (Item{Kind: KindMail, ID: MailItem}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, it := range []Item{{Kind: KindMail, ID: "tank"}, {Kind: KindMail, ID: ""}, {Kind: "mails", ID: MailItem}} {
		if it.Validate() == nil {
			t.Errorf("%v accepted", it)
		}
	}
	tg := Target{Pool: "tank", Source: "a1b2c3d4", Kind: KindMail, Item: MailItem}
	if err := tg.Validate(); err != nil || tg.Dataset() != "tank/replicas/a1b2c3d4/mail/mail" {
		t.Fatalf("%s %v", tg.Dataset(), err)
	}
	tg.Child = "x"
	if tg.Validate() == nil {
		t.Fatal("a mail replica with a child dataset")
	}
	// The mail dataset's own marker never comes along.
	found := false
	for _, p := range serviceProps {
		found = found || p == "org.hardyos:mail"
	}
	if !found {
		t.Fatal("org.hardyos:mail isn't stripped on receive")
	}
}

// Decision 465: a mail replica holds DKIM and TLS keys; the receiving
// server never mounts it, so there's nothing to browse.
func TestMailReplicaNeverBrowsed(t *testing.T) {
	f := &sysexec.Fake{}
	m := &Manager{Runner: f, BrowseDir: t.TempDir()}
	_, err := m.Browse(context.Background(), BrowseArgs{Target: Target{Pool: "tank", Source: "a1b2c3d4", Kind: KindMail, Item: MailItem}, Snapshot: label})
	if !errors.Is(err, ErrInvalid) || len(f.Lines()) != 0 {
		t.Fatalf("browsed: %v %v", err, f.Lines())
	}
}

type mailItems struct{}

func (mailItems) List(context.Context) ([]LocalItem, error) { return nil, nil }
func (mailItems) Resolve(_ context.Context, kind, id string) (string, error) {
	if kind == KindMail {
		return "tank/mail", nil
	}
	return "", ErrNotFound
}

// Decision 463: the mail's configuration and Rspamd's data go into the
// dataset right before its snapshot.
func TestMailSnapshotPrepared(t *testing.T) {
	f := &sysexec.Fake{}
	f.On("zfs list -H -o name,type -r -t filesystem,volume tank/mail", "tank/mail\tfilesystem\n")
	f.OnPrefix("zfs snapshot -r tank/mail@", sysexec.Result{})
	var prepared []string
	m := &Manager{Runner: f, Items: mailItems{}, Prepare: func(_ context.Context, kind, id string) error {
		prepared = append(prepared, kind+"/"+id)
		if len(f.Lines()) > 1 && strings.HasPrefix(f.Lines()[len(f.Lines())-1], "zfs snapshot") {
			t.Error("prepared after the snapshot")
		}
		return nil
	}}
	res, err := m.Snapshot(context.Background(), SnapshotArgs{Task: "abc123", Kind: KindMail, ID: MailItem})
	if err != nil || !res.Consistent || len(prepared) != 1 || prepared[0] != "mail/mail" {
		t.Fatalf("%+v %v %v", res, err, prepared)
	}
	// A failed preparation still copies the mail, marked as such.
	m.Prepare = func(context.Context, string, string) error { return errors.New("redis down") }
	if res, err = m.Snapshot(context.Background(), SnapshotArgs{Task: "abc124", Kind: KindMail, ID: MailItem}); err != nil || res.Consistent {
		t.Fatalf("%+v %v", res, err)
	}
}

type mailRestorer struct {
	fakeRestorer
	dir  string
	args json.RawMessage
	err  error
}

func (r *mailRestorer) MailRestore(_ context.Context, dir string, args json.RawMessage) (json.RawMessage, []string, error) {
	r.dir, r.args = dir, args
	if r.err != nil {
		return nil, nil, r.err
	}
	return json.RawMessage(`{"scope":"mailbox"}`), []string{"done"}, nil
}

// Decision 466: a mail copy comes back read only into a dataset of its
// own, mounted only in a root-only folder, put into the mail server, and
// destroyed; when that fails it stays marked for RestoreAbort.
func TestMailRestoreFromReplica(t *testing.T) {
	dir := t.TempDir() + "/mr"
	f := &sysexec.Fake{}
	f.OnPrefix("zfs create ", sysexec.Result{})
	st := &fakeStarter{}
	rr := &mailRestorer{}
	m := &Manager{Runner: f, Starter: st, Restore: rr, MailRestoreDir: dir}
	ctx := context.Background()
	if _, _, err := m.RestoreRecv(ctx, RestoreArgs{Kind: KindMail, ID: MailItem, Snapshot: label, NewID: "../x"}); err == nil {
		t.Fatal("a bad copy id")
	}
	if _, _, err := m.RestoreRecv(ctx, RestoreArgs{Kind: KindMail, ID: MailItem, Child: "sub", Snapshot: label, NewID: "m123456"}); err == nil {
		t.Fatal("a child dataset for the mail")
	}
	rs, w, err := m.RestoreRecv(ctx, RestoreArgs{Kind: KindMail, ID: MailItem, Snapshot: label, NewID: "m123456", Pool: "evil"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(header(binary.LittleEndian, hdrSubstream, 0, ObjsetFilesystem, 0, 0, "x@"+label)); err != nil {
		t.Fatal(err)
	}
	w.Close()
	if res := waitDone(t, m, rs.Stream); !res.OK {
		t.Fatal(res.Error)
	}
	if !strings.Contains(strings.Join(f.Lines(), "\n"), "zfs create -o canmount=off -o mountpoint=none tank/mail-restores") {
		t.Fatalf("parent: %v", f.Lines())
	}
	line := strings.Join(st.Calls()[0], " ")
	for _, want := range []string{"-o canmount=noauto", "-o readonly=on", "-o exec=off", "-o setuid=off", "-o devices=off",
		"-o mountpoint=" + dir + "/m123456", "-x org.hardyos:mail", " tank/mail-restores/m123456@" + label} {
		if !strings.Contains(line, want) {
			t.Errorf("missing %q in %s", want, line)
		}
	}
	if strings.Contains(line, "-x mountpoint") {
		t.Errorf("mountpoint both set and excluded: %s", line)
	}

	top := "tank/mail-restores/m123456"
	finish := func(fail error) (*RestoreFinishResult, *sysexec.Fake, error) {
		f := &sysexec.Fake{}
		f.On("zfs get -H -p -o value org.hardyos:restoring "+top, "1\n")
		f.On("zfs list -H -o name,type -r -t filesystem,volume "+top, top+"\tfilesystem\n")
		f.On("zfs get -H -p -o value mounted "+top, "yes\n")
		f.On("zfs get -H -p -o value mountpoint "+top, dir+"/m123456\n")
		f.On("zfs get -H -p -o value readonly "+top, "on\n")
		f.OnPrefix("zfs ", sysexec.Result{})
		rr.err = fail
		m := &Manager{Runner: f, Restore: rr, MailRestoreDir: dir}
		res, err := m.RestoreFinish(ctx, RestoreFinishArgs{Kind: KindMail, ID: MailItem, NewID: "m123456", Mail: json.RawMessage(`{"scope":"mailbox"}`)})
		return res, f, err
	}
	res, f2, err := finish(nil)
	if err != nil || rr.dir != dir+"/m123456" || string(rr.args) != `{"scope":"mailbox"}` || string(res.Mail) != `{"scope":"mailbox"}` {
		t.Fatalf("%+v %v %s", res, err, rr.dir)
	}
	if !strings.Contains(strings.Join(f2.Lines(), "\n"), "zfs destroy -r "+top) {
		t.Fatal("the copy wasn't removed")
	}
	_, f3, err := finish(errors.New("no such mailbox"))
	if err == nil || strings.Contains(strings.Join(f3.Lines(), "\n"), "zfs destroy -r "+top) || strings.Contains(strings.Join(f3.Lines(), "\n"), "inherit") {
		t.Fatalf("failure: %v %v", err, f3.Lines())
	}
}
