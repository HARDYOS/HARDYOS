package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestDelayLimiterSlowsDownWithoutLockingOut(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := NewDelayLimiter()
	l.now = func() time.Time { return now }
	for i := range 3 {
		l.Fail("k")
		if ok, _ := l.Allowed("k"); !ok {
			t.Fatalf("free failure %d already slowed down", i+1)
		}
	}
	waits := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}
	for _, want := range waits {
		l.Fail("k")
		if ok, wait := l.Allowed("k"); ok || wait != want {
			t.Fatalf("wait %v, want %v", wait, want)
		}
		now = now.Add(want)
		if ok, _ := l.Allowed("k"); !ok {
			t.Fatal("still refused after the wait")
		}
	}
	for range 20 {
		l.Fail("k")
	}
	if _, wait := l.Allowed("k"); wait != l.MaxDelay {
		t.Fatalf("wait capped at %v, want %v", wait, l.MaxDelay)
	}
	// Other keys aren't touched; an hour later it's forgotten; success clears.
	if ok, _ := l.Allowed("other"); !ok {
		t.Fatal("another key slowed down")
	}
	now = now.Add(l.Window + l.MaxDelay + time.Second)
	l.Fail("k")
	if ok, _ := l.Allowed("k"); !ok {
		t.Fatal("old failures still counted")
	}
	l.Fail("k")
	l.Fail("k")
	l.Fail("k")
	l.Succeed("k")
	if ok, _ := l.Allowed("k"); !ok {
		t.Fatal("success didn't clear")
	}
}

type fakeAnchor struct {
	mu    sync.Mutex
	known map[int64]string
	calls []bool // interactive?
}

func (a *fakeAnchor) CheckAnchor(_ context.Context, u *User, anchor string, interactive bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, interactive)
	if cur, ok := a.known[u.ID]; ok && cur != anchor && !interactive {
		return ErrAccountReplaced
	}
	a.known[u.ID] = anchor
	return nil
}

func TestAnchorAndPasswordChecksAtSignInAndRefresh(t *testing.T) {
	ctx := context.Background()
	s, f := newSignIn(t)
	anchor := &fakeAnchor{known: map[int64]string{}}
	var setAt []time.Time
	s.Anchor = anchor
	s.PasswordSet = func(_ context.Context, _ *User, at time.Time) { setAt = append(setAt, at) }
	a := f.add("alice", "Al1ce-Passw0rd!")
	a.ObjectGUID = "6F9619FF-8B86-D011-B42D-00C04FC964FF"
	a.PasswordSetAt = time.Unix(1_700_000_000, 0)
	u, err := s.Authenticate(ctx, `HOME\alice`, "Al1ce-Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	if len(anchor.calls) != 1 || !anchor.calls[0] || anchor.known[u.ID] != "6f9619ff-8b86-d011-b42d-00c04fc964ff" {
		t.Fatalf("sign-in anchor: %v %v", anchor.calls, anchor.known)
	}
	if len(setAt) != 1 || !setAt[0].Equal(a.PasswordSetAt) {
		t.Fatalf("password set: %v", setAt)
	}
	// The name now belongs to another directory object: the session ends.
	a.ObjectGUID = "99999999-8888-7777-6666-555555555555"
	agedGroups(t, s, u.ID)
	u, _ = s.Users.Get(ctx, u.ID)
	if _, err := s.Refresh(ctx, u); !errors.Is(err, ErrAccountReplaced) || !errors.Is(err, ErrAccountGone) {
		t.Fatalf("refresh after the replacement: %v", err)
	}
	// The new person signs in with their own password: theirs now.
	f.pw["alice"] = "N3w-Alice-Passw0rd"
	if _, err := s.Authenticate(ctx, `HOME\alice`, "N3w-Alice-Passw0rd"); err != nil {
		t.Fatal(err)
	}
	if anchor.known[u.ID] != "99999999-8888-7777-6666-555555555555" {
		t.Fatalf("anchor after the new sign-in: %v", anchor.known)
	}
	// SID when there's no GUID.
	if got := AccountAnchor(&DomainAccount{SID: "s-1-5-21-1-2-3-1105"}); got != "S-1-5-21-1-2-3-1105" {
		t.Fatalf("SID anchor %q", got)
	}
}
