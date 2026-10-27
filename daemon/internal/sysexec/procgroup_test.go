//go:build unix

package sysexec

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A timed-out command is killed with everything it started (an apt run's
// dpkg, a DKMS build's compiler), and Run returns even though a child
// still held the output pipe.
func TestTimeoutKillsTheProcessGroup(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Exec{}.Run(ctx, nil, "/bin/sh", "-c", "sleep 60 & echo $! > "+pidFile+"; wait")
	if err == nil {
		t.Fatal("no error for a timed-out command")
	}
	if d := time.Since(start); d > WaitDelay {
		t.Fatalf("Run took %v", d)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if pid <= 0 {
		t.Fatalf("pid %q", b)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		// Gone, or a zombie waiting for its reaper.
		stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if err != nil || strings.Contains(string(stat), ") Z ") {
			break
		}
		if syscall.Kill(pid, 0) != nil {
			break
		}
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("the command's child %d survived the timeout", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
