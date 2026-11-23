package priv

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClusterHostStatus(t *testing.T) {
	root := t.TempDir()
	write := func(p, s string) {
		t.Helper()
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("proc/sys/kernel/random/boot_id", "abc-123\n")
	write("sys/class/watchdog/watchdog1/identity", "Software Watchdog\n")
	write("sys/class/watchdog/watchdog1/timeout", "60\n")
	write("sys/class/watchdog/watchdog0/identity", "iTCO_wdt\n")
	write("sys/class/watchdog/watchdog0/timeout", "30\n")
	_ = os.MkdirAll(filepath.Join(root, "var/lib/hardyos/cluster"), 0o700)
	st := ClusterHost(root)
	if st.BootID != "abc-123" || len(st.Watchdogs) != 2 || st.Watchdogs[0].Identity != "iTCO_wdt" || st.Watchdogs[0].Software ||
		!st.Watchdogs[1].Software || st.Watchdogs[1].Timeout != 60 || !st.StateDir.Exists || st.StateDir.UID != os.Getuid() {
		t.Fatalf("status %+v", st)
	}
	if st := ClusterHost(t.TempDir()); st.Watchdogs == nil || st.StateDir.Exists {
		t.Fatalf("empty host %+v", st)
	}
}
