package cluster

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"testing"
)

// Large relayed bodies go to the spooler's own folder, within its quota
// across requests (decision 371).
func TestSpoolerQuota(t *testing.T) {
	dir := t.TempDir()
	sp := &Spooler{Dir: dir, Quota: relayMemBody * 3 / 2}
	body := bytes.Repeat([]byte("a"), relayMemBody+1024)
	a, err := sp.Spool(bytes.NewReader(body), MaxRelayBody)
	if err != nil {
		t.Fatal(err)
	}
	if a.file == nil || sp.Used() != int64(len(body)) {
		t.Fatalf("not spooled to a file: used %d", sp.Used())
	}
	if want := sha256.Sum256(body); !bytes.Equal(a.Sum, want[:]) {
		t.Fatal("wrong hash")
	}
	got, _ := io.ReadAll(a.Reader())
	if !bytes.Equal(got, body) {
		t.Fatal("wrong body")
	}
	// The spooled file lives in the spooler's folder (unlinked at once).
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("left files: %v", ents)
	}
	// A second one doesn't fit while the first is held.
	if _, err := sp.Spool(bytes.NewReader(body), MaxRelayBody); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("over quota: %v", err)
	}
	if sp.Used() != int64(len(body)) {
		t.Fatalf("refused spool kept its room: %d", sp.Used())
	}
	a.Close()
	a.Close()
	if sp.Used() != 0 {
		t.Fatalf("not released: %d", sp.Used())
	}
	b, err := sp.Spool(bytes.NewReader(body), MaxRelayBody)
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
	// Small bodies stay in memory and use none of the quota.
	c, err := sp.Spool(bytes.NewReader([]byte("small")), MaxRelayBody)
	if err != nil || c.file != nil || sp.Used() != 0 {
		t.Fatalf("small body: %v", err)
	}
}

func TestValidHost(t *testing.T) {
	for h, want := range map[string]bool{
		"nas.lan": true, "nas.lan:8443": true, "192.168.1.5": true, "[fe80::1]:443": true, "c1": true,
		"": false, "evil\r\nx": false, "a b": false, "nas:99999": false, "-x": false, "nas/x": false, "a@b": false,
	} {
		if got := ValidHost(h); got != want {
			t.Errorf("%q = %v", h, got)
		}
	}
}
