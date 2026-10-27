package clientip

import (
	"net/http/httptest"
	"testing"
)

func TestIP(t *testing.T) {
	trusted, err := ParseTrusted(" 127.0.0.1, 10.0.0.0/8 ,::1")
	if err != nil || len(trusted) != 3 {
		t.Fatalf("parse = %v %v", trusted, err)
	}
	if _, err := ParseTrusted("10.0.0.0/33"); err == nil {
		t.Fatal("bad CIDR accepted")
	}
	if l, err := ParseTrusted(""); err != nil || len(l) != 0 {
		t.Fatal("empty list")
	}
	withProxy := &Resolver{Trusted: trusted}
	cases := []struct {
		r      *Resolver
		remote string
		xff    []string
		want   string
	}{
		// No trusted proxies: the header is never read.
		{nil, "203.0.113.5:4000", []string{"1.2.3.4"}, "203.0.113.5"},
		{&Resolver{}, "127.0.0.1:4000", []string{"1.2.3.4"}, "127.0.0.1"},
		// An untrusted peer can't claim to be someone else.
		{withProxy, "203.0.113.5:4000", []string{"1.2.3.4"}, "203.0.113.5"},
		// A trusted proxy: the right-most address it didn't add itself.
		{withProxy, "127.0.0.1:4000", []string{"1.2.3.4"}, "1.2.3.4"},
		{withProxy, "127.0.0.1:4000", []string{"6.6.6.6, 1.2.3.4"}, "1.2.3.4"},
		{withProxy, "127.0.0.1:4000", []string{"6.6.6.6", "1.2.3.4, 10.1.2.3"}, "1.2.3.4"},
		{withProxy, "[::1]:4000", []string{"2001:db8::7"}, "2001:db8::7"},
		{withProxy, "127.0.0.1:4000", nil, "127.0.0.1"},
		{withProxy, "127.0.0.1:4000", []string{"not-an-ip"}, "127.0.0.1"},
		{withProxy, "127.0.0.1:4000", []string{"10.0.0.2"}, "127.0.0.1"},
	}
	for i, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		for _, h := range c.xff {
			r.Header.Add("X-Forwarded-For", h)
		}
		if got := c.r.IP(r); got != c.want {
			t.Errorf("case %d: IP = %q, want %q", i, got, c.want)
		}
	}
}
