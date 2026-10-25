package tlscert

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateReusesCertificate(t *testing.T) {
	dir := t.TempDir()
	c1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c1.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range leaf.DNSNames {
		if n == "localhost" {
			found = true
		}
	}
	if !found {
		t.Fatalf("localhost missing from SANs: %v", leaf.DNSNames)
	}
	info, err := os.Stat(filepath.Join(dir, "server.key"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file perms: %v %v", info.Mode(), err)
	}

	c2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(c1.Certificate[0]) != string(c2.Certificate[0]) {
		t.Fatal("certificate regenerated instead of reused")
	}
}
