package manage

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/mail"
	"github.com/hardyos/hardyos/daemon/internal/notify"
)

type fakeNotifier struct {
	mu     sync.Mutex
	events []notify.Event
}

func (f *fakeNotifier) Notify(_ context.Context, e notify.Event) {
	f.mu.Lock()
	f.events = append(f.events, e)
	f.mu.Unlock()
}

func (f *fakeNotifier) kinds() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, e := range f.events {
		out = append(out, e.Kind+": "+e.Title)
	}
	return out
}

// Decision 306: a mailbox belongs to the domain account itself. An account
// deleted and made again under the same name gets a new mailbox; the old
// one stays detached and is never handed to it.
func TestSyncTiesMailboxesToTheAccount(t *testing.T) {
	s, _ := newSvc(t)
	enable(t, s)
	ctx := context.Background()
	s.Dir = fakeDir{{Username: "alice", GivenName: "Alice", Enabled: true, GUID: "AAAA-1", SID: "S-1-5-21-1-1001"}}
	if _, err := s.SyncAccounts(ctx); err != nil {
		t.Fatal(err)
	}
	old, err := s.Store.MailboxByAccount(ctx, "alice")
	if err != nil || old.AccountGUID != "aaaa-1" || old.AccountSID != "S-1-5-21-1-1001" {
		t.Fatalf("%+v %v", old, err)
	}
	// Renamed in the domain? Not here: same name, a different account.
	s.Dir = fakeDir{{Username: "alice", GivenName: "Alice", Enabled: true, GUID: "BBBB-2", SID: "S-1-5-21-1-1002"}}
	res, err := s.SyncAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Created) != 1 || res.Created[0] == old.Address {
		t.Fatalf("the new account didn't get a mailbox of its own: %+v", res)
	}
	detached, _ := s.Store.GetMailbox(ctx, old.ID)
	if detached.Account == "alice" || detached.AccountState != "deleted" || detached.CanSignIn() {
		t.Fatalf("old mailbox %+v", detached)
	}
	cur, _ := s.Store.MailboxByAccount(ctx, "alice")
	if cur.ID == old.ID || cur.Key == old.Key || cur.AccountGUID != "bbbb-2" {
		t.Fatalf("new mailbox %+v", cur)
	}
	// Signing in with the address of the old mailbox doesn't reach the new
	// account's password, nor the other way round.
	s.Passwords = fakePasswords{"alice": "pw"}
	if err := s.CheckLogin(ctx, old.Address, "pw"); err == nil {
		t.Fatal("the new account opened the old mailbox")
	}
}

// A mailbox whose account was deleted, from before HardyOS knew GUIDs, is
// never restored to whoever takes the name next.
func TestSyncDoesntRestoreUnverifiedMailbox(t *testing.T) {
	s, _ := newSvc(t)
	enable(t, s)
	ctx := context.Background()
	m, _ := s.Store.CreateMailbox(ctx, Mailbox{Account: "bob", Address: "bob@example.net", AccountState: "deleted", Enabled: true})
	s.Dir = fakeDir{{Username: "bob", GivenName: "Bob", Enabled: true, GUID: "CCCC-3"}}
	if _, err := s.SyncAccounts(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Store.GetMailbox(ctx, m.ID)
	if got.AccountState != "deleted" || got.Account == "bob" {
		t.Fatalf("restored without proof it's the same account: %+v", got)
	}
	// A live one without a GUID yet adopts its account's.
	s2, _ := newSvc(t)
	enable(t, s2)
	m2, _ := s2.Store.CreateMailbox(ctx, Mailbox{Account: "carol", Address: "carol@example.net", AccountState: "active", Enabled: true})
	s2.Dir = fakeDir{{Username: "carol", Enabled: true, GUID: "DDDD-4"}}
	if _, err := s2.SyncAccounts(ctx); err != nil {
		t.Fatal(err)
	}
	got2, _ := s2.Store.GetMailbox(ctx, m2.ID)
	if got2.AccountGUID != "dddd-4" || !got2.CanSignIn() {
		t.Fatalf("%+v", got2)
	}
}

func TestNotifyFromAndReservedGroups(t *testing.T) {
	s, _ := newSvc(t)
	enable(t, s)
	ctx := context.Background()
	_, _ = s.Store.CreateMailbox(ctx, Mailbox{Account: "alice", Address: "alice@example.net", Aliases: []string{"mom@example.net"}, AccountState: "active", Enabled: true})
	_, _ = s.Store.SetGroup(ctx, Group{Address: "family@example.net", Targets: []string{"alice@example.net"}})
	for _, a := range []string{"alice@example.net", "mom@example.net", "family@example.net", "postmaster@example.net", "abuse@example.net"} {
		if err := s.Store.CheckNotifyFrom(ctx, a); err == nil {
			t.Errorf("notifications may send as %s", a)
		}
	}
	if err := s.Store.CheckNotifyFrom(ctx, "hardyos@example.net"); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"postmaster@example.net", "abuse@example.net"} {
		if _, err := s.Store.SetGroup(ctx, Group{Address: a, Targets: []string{"alice@example.net"}}); err == nil {
			t.Errorf("group %s accepted", a)
		}
	}
	// Once set, nobody else may take the notification address.
	st, _ := s.Store.LoadSettings(ctx)
	st.NotifyFrom = "hardyos@example.net"
	_ = s.Store.SaveSettings(ctx, st)
	if _, err := s.Store.SetGroup(ctx, Group{Address: "hardyos@example.net", Targets: []string{"alice@example.net"}}); err == nil {
		t.Error("a group took the notification address")
	}
	m, _ := s.Store.MailboxByAddress(ctx, "alice@example.net")
	al := []string{"hardyos@example.net"}
	if _, err := s.Store.UpdateMailbox(ctx, m.ID, MailboxUpdate{Aliases: &al}); err == nil {
		t.Error("an alias took the notification address")
	}
}

// Decision 303: blocked networks are gathered into one alert an hour.
func TestSigninAlertsAreGathered(t *testing.T) {
	s, _ := newSvc(t)
	enable(t, s)
	n := &fakeNotifier{}
	s.Notify = n
	for i := 0; i < 50; i++ {
		s.AuthEvent(mail.AuthEvent{Remote: "2001:db8:" + string(rune('a'+i%6)) + "::1", Blocked: true})
	}
	s.AuthEvent(mail.AuthEvent{Remote: "198.51.100.9", Blocked: false})
	if k := n.kinds(); len(k) != 1 {
		t.Fatalf("alerts: %v", k)
	}
	// An hour later the rest goes out as one.
	s.flushSigninAlert(context.Background(), time.Now().Add(2*time.Hour))
	k := n.kinds()
	if len(k) != 2 || !strings.Contains(k[1], "networks") {
		t.Fatalf("alerts: %v", k)
	}
	s.mu.Lock()
	s.conds = map[string]string{"dns:gone.example": "x", "dns:example.net": "y", "queue": "z"}
	s.mu.Unlock()
	s.pruneConds(func(k string) bool { return k != "dns:gone.example" })
	if _, ok := s.conds["dns:gone.example"]; ok || len(s.conds) != 2 {
		t.Fatalf("conds %v", s.conds)
	}
}

func TestMissingAuthSocketAlerts(t *testing.T) {
	s, _ := newSvc(t)
	enable(t, s)
	n := &fakeNotifier{}
	s.Notify = n
	s.SetAuthListener(errors.New("no socket"))
	s.CheckHealth(context.Background())
	found := false
	for _, k := range n.kinds() {
		if strings.HasPrefix(k, "mail.service: Nobody can sign in") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no alert: %v", n.kinds())
	}
}

// Decision 318: only mailboxes from before the key layout are flagged, root
// gets the flag once, and a successful apply clears it.
func TestLegacyLayoutFlag(t *testing.T) {
	s, _ := newSvc(t)
	enable(t, s)
	ctx := context.Background()
	old, _ := s.Store.CreateMailbox(ctx, Mailbox{Account: "alice", Address: "alice@example.net", AccountState: "active", Enabled: true})
	_, _ = s.Store.CreateMailbox(ctx, Mailbox{Account: "bob", Address: "bob@example.net", AccountState: "active", Enabled: true})
	if _, err := s.Store.DB.ExecContext(ctx, `UPDATE mail_mailboxes SET legacy_layout = 1 WHERE id = ?`, old.ID); err != nil {
		t.Fatal(err)
	}
	a, err := s.RootArgs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range a.Config.Mailboxes {
		if m.Legacy != (m.Address == "alice@example.net") {
			t.Fatalf("legacy flags: %+v", a.Config.Mailboxes)
		}
	}
	if _, err := s.Apply(ctx, func(float64, string) {}); err != nil {
		t.Fatal(err)
	}
	a, _ = s.RootArgs(ctx)
	for _, m := range a.Config.Mailboxes {
		if m.Legacy {
			t.Fatal("the flag survived the apply")
		}
	}
}
