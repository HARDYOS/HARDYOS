package sftp

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// fakeProc writes a /proc with processes: pid -> exe, uids, start ticks.
func fakeProc(t *testing.T, boot int64, procs map[int]struct {
	exe   string
	uids  string
	ticks int64
}) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "stat"), []byte(fmt.Sprintf("cpu 1 2 3\nbtime %d\nprocesses 9\n", boot)), 0o644); err != nil {
		t.Fatal(err)
	}
	for pid, p := range procs {
		d := filepath.Join(root, fmt.Sprint(pid))
		_ = os.MkdirAll(d, 0o755)
		_ = os.Symlink(p.exe, filepath.Join(d, "exe"))
		_ = os.WriteFile(filepath.Join(d, "status"), []byte("Name:\tx\nUid:\t"+p.uids+"\nGid:\t1\t1\t1\t1\n"), 0o644)
		// comm with a space and a paren, as a process can name itself.
		_ = os.WriteFile(filepath.Join(d, "stat"), []byte(fmt.Sprintf("%d (sshd: x) y) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 %d 0 0", pid, p.ticks)), 0o644)
	}
	_ = os.MkdirAll(filepath.Join(root, "self"), 0o755)
	return root
}

// Only the account's own sshd session processes that started before the
// time end (decision 519).
func TestEndSessions(t *testing.T) {
	boot := time.Now().Add(-time.Hour).Unix()
	const alice = 101103
	a := fmt.Sprint(alice)
	all := a + "\t" + a + "\t" + a + "\t" + a
	root := fakeProc(t, boot, map[int]struct {
		exe   string
		uids  string
		ticks int64
	}{
		100: {"/usr/lib/openssh/sshd-session", all, 100 * 60},                         // a minute after boot
		101: {"/usr/sbin/sshd", all, 100 * 3000},                                      // 50 minutes after boot
		102: {"/usr/sbin/smbd", all, 100},                                             // not sshd
		103: {"/usr/sbin/sshd", "0\t" + a + "\t0\t0", 100},                            // root's privileged monitor
		104: {"/usr/lib/openssh/sshd-session", "101104\t101104\t101104\t101104", 100}, // bob
		105: {"/usr/sbin/sshd (deleted)", all, 100},                                   // after an upgrade
	})
	var killed []int
	m := &Manager{ProcRoot: root, Kill: func(pid int) error { killed = append(killed, pid); return nil }}
	n, err := m.EndSessions(alice, time.Unix(boot, 0).Add(10*time.Minute))
	slices.Sort(killed)
	if err != nil || n != 2 || !slices.Equal(killed, []int{100, 105}) {
		t.Fatalf("before 10 minutes: %d %v %v", n, killed, err)
	}
	killed = nil
	if n, _ := m.EndSessions(alice, time.Time{}); n != 3 {
		t.Fatalf("all: %d %v", n, killed)
	}
	for _, uid := range []int{0, 1000, DomainUIDHigh + 1} {
		if _, err := m.EndSessions(uid, time.Time{}); err == nil {
			t.Errorf("uid %d accepted", uid)
		}
	}
}
