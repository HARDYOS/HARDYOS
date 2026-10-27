package domain

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

const showreplTwoDCs = `{
 "repsFrom": [
  {"NC dn": "DC=hardy,DC=home", "DSA objectGUID": "8c3a...", "DSA": "Default-First-Site-Name\\DC2", "last attempt time": "Mon Oct 27 10:00:01 2026 CDT",
   "last attempt message": "WERR_OK", "consecutive failures": 0, "last success": "Mon Oct 27 10:00:01 2026 CDT", "NTDS DN": "CN=NTDS Settings,...", "is deleted": false},
  {"NC dn": "CN=Configuration,DC=hardy,DC=home", "DSA objectGUID": "8c3a...", "DSA": "Default-First-Site-Name\\DC2", "last attempt time": "Mon Oct 27 10:00:01 2026 CDT",
   "last attempt message": "WERR_BADFILE", "consecutive failures": 7, "last success": "Sun Oct 26 22:00:00 2026 CDT", "is deleted": false},
  {"NC dn": "DC=old", "DSA objectGUID": "x", "consecutive failures": 99, "is deleted": true}
 ],
 "repsTo": [], "NTDSConnections": [], "dsa": {"DSA Options": "0x00000001"}
}`

func TestParseShowrepl(t *testing.T) {
	r, err := ParseShowrepl([]byte(showreplTwoDCs))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Checked || len(r.Links) != 2 || len(r.Failing) != 1 {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.Failing[0], `Default-First-Site-Name\DC2 (CN=Configuration,DC=hardy,DC=home): 7 failed attempts`) || !strings.Contains(r.Failing[0], "WERR_BADFILE") {
		t.Errorf("failing %q", r.Failing[0])
	}
	alone, _ := ParseShowrepl([]byte(`{"repsFrom": [], "repsTo": []}`))
	if alone.Checked {
		t.Error("a single DC counted as replicating")
	}
	if _, err := ParseShowrepl([]byte("ERROR")); err == nil {
		t.Error("garbage parsed")
	}
}

// slowRunner blocks samba-tool until its context ends.
type slowRunner struct{ *sysexec.Fake }

func (s slowRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) (sysexec.Result, error) {
	if name == "ip" && len(args) > 3 && args[3] == "samba-tool" {
		<-ctx.Done()
		return sysexec.Result{}, ctx.Err()
	}
	return s.Fake.Run(ctx, stdin, name, args...)
}

func TestReplicationDoesntHoldTheLock(t *testing.T) {
	f := &sysexec.Fake{}
	m := testManager(t, f)
	f.OnPrefix("systemctl is-active", sysexec.Result{})
	_ = os.MkdirAll(m.dataPath(), 0o700)
	if err := m.save(&Config{Domain: "home.example.net", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	m.Runner = slowRunner{f}
	old := ReplicationTimeout
	ReplicationTimeout = 300 * time.Millisecond
	defer func() { ReplicationTimeout = old }()
	done := make(chan error, 1)
	go func() { _, err := m.Replication(context.Background()); done <- err }()
	time.Sleep(50 * time.Millisecond)
	locked := make(chan struct{})
	go func() { m.mu.Lock(); m.mu.Unlock(); close(locked) }()
	select {
	case <-locked:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("samba-tool held the domain lock")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Error("a stuck samba-tool didn't time out")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no timeout")
	}
}
