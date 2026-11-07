package cluster

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestSelectorFailoverAndBack(t *testing.T) {
	tm := PathTimings{Interval: time.Second, DownAfter: 3, UpAfter: 10}
	s := newSelector([]Path{PathLAN, PathStorage, PathNetBird})
	now := time.Unix(0, 0)
	all := func(lan, sto, nb bool) {
		s.observe(PathLAN, lan, time.Millisecond, tm, now)
		s.observe(PathStorage, sto, time.Millisecond, tm, now)
		s.observe(PathNetBird, nb, 10*time.Millisecond, tm, now)
	}
	all(true, true, true)
	if s.cur != PathLAN {
		t.Fatalf("start: %s", s.cur)
	}
	// Two misses: still LAN; the third: storage.
	all(false, true, true)
	all(false, true, true)
	if s.cur != PathLAN {
		t.Fatalf("after 2 misses: %s", s.cur)
	}
	all(false, true, true)
	if s.cur != PathStorage {
		t.Fatalf("after 3 misses: %s", s.cur)
	}
	// Storage fails too: NetBird.
	for i := 0; i < 3; i++ {
		all(false, false, true)
	}
	if s.cur != PathNetBird {
		t.Fatalf("both down: %s", s.cur)
	}
	// LAN back: 9 good probes aren't enough, the 10th is.
	for i := 0; i < 9; i++ {
		all(true, false, true)
	}
	if s.cur != PathNetBird {
		t.Fatalf("after 9 good: %s", s.cur)
	}
	all(true, false, true)
	if s.cur != PathLAN {
		t.Fatalf("after 10 good: %s", s.cur)
	}
	// A flapping LAN (good, bad) never comes back early.
	for i := 0; i < 3; i++ {
		all(false, true, true)
	}
	for i := 0; i < 20; i++ {
		all(i%2 == 0, true, true)
	}
	if s.cur != PathStorage {
		t.Fatalf("flapping LAN taken: %s", s.cur)
	}
}

func TestAvailablePathsWitnessNetBirdOnly(t *testing.T) {
	m := Addresses{LAN: netip.MustParseAddr("192.168.1.2"), Storage: netip.MustParseAddr("10.77.0.2"), NetBird: netip.MustParseAddr("100.64.0.2")}
	w := Addresses{LAN: netip.MustParseAddr("192.168.1.9"), NetBird: netip.MustParseAddr("100.64.0.9")}
	if got := Available(m, w, RoleCompute, RoleWitness); len(got) != 1 || got[0] != PathNetBird {
		t.Fatalf("witness paths %v", got)
	}
	if got := Available(m, m, RoleCompute, RoleStorage); len(got) != 3 {
		t.Fatalf("member paths %v", got)
	}
}

func TestAssertions(t *testing.T) {
	id, _ := NewIdentity("c1")
	other, _ := NewIdentity("c2")
	now := time.Unix(1_800_000_000, 0)
	req := RequestHash("POST", "/api/v1/vms", "x=1", []byte(`{"a":1}`))
	a := Assertion{Issuer: "c1", Audience: "c2", Subject: Principal{Kind: "local", Name: "alice", Admin: true},
		Session: "abc", IssuedAt: now.Unix(), ExpiresAt: now.Unix() + 60, Nonce: NewNonce(), Request: req}
	jws, err := SignAssertion(id, a)
	if err != nil {
		t.Fatal(err)
	}
	nc := &NonceCache{}
	chk := AssertionCheck{Issuer: "c1", IssuerKey: id.PublicKey, Audience: "c2", Request: req, Now: now, Nonces: nc}
	if _, err := VerifyAssertion(jws, chk); err != nil {
		t.Fatalf("valid: %v", err)
	}
	// Replay.
	if _, err := VerifyAssertion(jws, chk); !errors.Is(err, ErrAssertionReplay) {
		t.Fatalf("replay: %v", err)
	}
	fresh := func() AssertionCheck { c := chk; c.Nonces = &NonceCache{}; return c }
	bad := []struct {
		name string
		mod  func(c *AssertionCheck)
	}{
		{"wrong key", func(c *AssertionCheck) { c.IssuerKey = other.PublicKey }},
		{"wrong audience", func(c *AssertionCheck) { c.Audience = "nas" }},
		{"other request", func(c *AssertionCheck) { c.Request = RequestHash("DELETE", "/api/v1/vms", "x=1", nil) }},
		{"expired", func(c *AssertionCheck) { c.Now = now.Add(70 * time.Second) }},
		{"from the future", func(c *AssertionCheck) { c.Now = now.Add(-10 * time.Second) }},
		{"other sender", func(c *AssertionCheck) { c.Issuer = "c3" }},
	}
	for _, b := range bad {
		c := fresh()
		b.mod(&c)
		if _, err := VerifyAssertion(jws, c); err == nil {
			t.Errorf("%s accepted", b.name)
		}
	}
	// Lifetime over 60 s can't be signed; alg none isn't read.
	long := a
	long.ExpiresAt = long.IssuedAt + 120
	if _, err := SignAssertion(id, long); err == nil {
		t.Error("120 s assertion signed")
	}
	if _, err := VerifyAssertion("eyJhbGciOiJub25lIn0.e30.", fresh()); err == nil {
		t.Error("alg none accepted")
	}
	// A domain subject needs its SID.
	d := a
	d.Subject = Principal{Kind: "domain", Name: `HOME\bob`}
	d.Nonce = NewNonce()
	jd, _ := SignAssertion(id, d)
	if _, err := VerifyAssertion(jd, fresh()); err == nil {
		t.Error("domain subject without SID accepted")
	}
}

func TestIdentityRoundTripAndSignature(t *testing.T) {
	id, _ := NewIdentity("nas")
	b, _ := MarshalIdentity(id)
	id2, err := UnmarshalIdentity(b)
	if err != nil || id2.Pin != id.Pin {
		t.Fatalf("round trip: %v", err)
	}
	if PinOfKey(id.PublicKey) != id.Pin {
		t.Fatal("pin")
	}
	if !versionWindow("1.4.0", "1.5.2") || versionWindow("1.3.0", "1.5.0") || versionWindow("2.0.0", "1.9.0") {
		t.Fatal("version window")
	}
	c, err := ParseCode(FormatCode([]byte("0123456789abcdef")))
	if err != nil || string(c) != "0123456789abcdef" {
		t.Fatal("code format")
	}
}
