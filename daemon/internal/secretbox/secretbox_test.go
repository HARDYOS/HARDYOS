package secretbox

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestSealOpen(t *testing.T) {
	src := NewStaticSource()
	k, err := src.Key(context.Background(), "oidc-signing")
	if err != nil {
		t.Fatal(err)
	}
	other, _ := src.Key(context.Background(), "netbird-token")
	if bytes.Equal(k, other) {
		t.Fatal("purposes share a key")
	}
	sealed, err := Seal(k, []byte("private key"), []byte("row-1"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("private key")) {
		t.Fatal("plain text in the sealed value")
	}
	got, err := Open(k, sealed, []byte("row-1"))
	if err != nil || string(got) != "private key" {
		t.Fatalf("open: %q %v", got, err)
	}
	for name, try := range map[string]func() ([]byte, error){
		"other row":     func() ([]byte, error) { return Open(k, sealed, []byte("row-2")) },
		"other purpose": func() ([]byte, error) { return Open(other, sealed, []byte("row-1")) },
		"other server": func() ([]byte, error) {
			k2, _ := NewStaticSource().Key(context.Background(), "oidc-signing")
			return Open(k2, sealed, []byte("row-1"))
		},
		"damaged": func() ([]byte, error) { d := bytes.Clone(sealed); d[len(d)-1] ^= 1; return Open(k, d, []byte("row-1")) },
		"short":   func() ([]byte, error) { return Open(k, sealed[:5], nil) },
	} {
		if _, err := try(); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
