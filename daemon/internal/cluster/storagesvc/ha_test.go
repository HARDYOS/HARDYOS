package storagesvc

import (
	"os"
	"testing"
	"time"
)

// A copy token is good once, for the server it was made for, for a
// minute (decision 480).
func TestCopySessions(t *testing.T) {
	var c copySessions
	mk := func(node string, ttl time.Duration) *copySession {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { r.Close(); w.Close() })
		cs := &copySession{token: newCopyToken(), node: "c1", file: w, expires: time.Now().Add(ttl)}
		if node != "" {
			cs.node = "c2"
		}
		c.add(cs)
		return cs
	}
	a := mk("", time.Minute)
	if c.take(a.token, "c2") != nil {
		t.Fatal("another server used c1's token")
	}
	if c.take(a.token, "c1") != nil {
		t.Fatal("a token refused once stays usable")
	}
	b := mk("", time.Minute)
	if got := c.take(b.token, "c1"); got != b {
		t.Fatal("c1's own token was refused")
	}
	if c.take(b.token, "c1") != nil {
		t.Fatal("a token was used twice")
	}
	old := mk("", -time.Second)
	if c.take(old.token, "c1") != nil {
		t.Fatal("an expired token was accepted")
	}
	if c.take("", "c1") != nil || c.take("nope", "c1") != nil {
		t.Fatal("an unknown token was accepted")
	}
	if len(newCopyToken()) != 48 {
		t.Fatal("tokens are 24 random bytes")
	}
}
