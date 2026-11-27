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
		c.add(cs, nil)
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

// A session nobody took is dropped at its expiry (M4): its file closed,
// root's stream cancelled, so the dataset isn't left busy; and only the
// server that opened a stream may give it up.
func TestCopySessionExpiry(t *testing.T) {
	var c copySessions
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	dropped := make(chan string, 1)
	c.add(&copySession{token: newCopyToken(), node: "c1", file: w, stream: "st1", expires: time.Now().Add(20 * time.Millisecond)},
		func(s string) { dropped <- s })
	select {
	case s := <-dropped:
		if s != "st1" {
			t.Fatalf("dropped %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an unused session wasn't dropped")
	}
	if _, err := w.Write([]byte("x")); err == nil {
		t.Fatal("the dropped session's file is still open")
	}

	_, w2, _ := os.Pipe()
	c.add(&copySession{token: newCopyToken(), node: "c1", file: w2, stream: "st2", expires: time.Now().Add(time.Minute)}, nil)
	if c.byStream("st2", "c2") {
		t.Fatal("another server gave up c1's stream")
	}
	if !c.byStream("st2", "c1") || c.byStream("st2", "c1") {
		t.Fatal("c1 couldn't give up its own waiting stream (once)")
	}
	var o openedStreams
	o.add("st3", "c1")
	if !o.owns("st3", "c1") || o.owns("st3", "c2") || o.owns("nope", "c1") {
		t.Fatal("opened streams' owners")
	}
}
