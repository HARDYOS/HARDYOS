package sftp

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Ending a domain account's open SFTP sessions (decision 519): when its app
// password is revoked, its two-factor sign-in is reset or set up, or its
// password changes, the sessions it opened before go too. An SFTP session
// is sshd's per-connection process (sshd, or sshd-session since OpenSSH
// 9.8) running internal-sftp as the account: every user ID it has is the
// account's. Nothing else is touched.

// clockTicks is USER_HZ, the unit of /proc/<pid>/stat's start time (100 on
// every architecture Linux supports today).
const clockTicks = 100

func (m *Manager) procRoot() string { return or(m.ProcRoot, "/proc") }

// bootTime reads btime from /proc/stat.
func (m *Manager) bootTime() (time.Time, error) {
	b, err := os.ReadFile(filepath.Join(m.procRoot(), "stat"))
	if err != nil {
		return time.Time{}, err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "btime" {
			n, err := strconv.ParseInt(f[1], 10, 64)
			if err != nil {
				break
			}
			return time.Unix(n, 0), nil
		}
	}
	return time.Time{}, fmt.Errorf("no btime in %s/stat", m.procRoot())
}

// sessionOf reports whether pid is an SFTP session of uid, and when it
// started.
func (m *Manager) sessionOf(pid string, uid int, boot time.Time) (bool, time.Time) {
	dir := filepath.Join(m.procRoot(), pid)
	exe, err := os.Readlink(filepath.Join(dir, "exe"))
	if err != nil {
		return false, time.Time{}
	}
	if b := filepath.Base(strings.TrimSuffix(exe, " (deleted)")); b != "sshd" && b != "sshd-session" {
		return false, time.Time{}
	}
	st, err := os.ReadFile(filepath.Join(dir, "status"))
	if err != nil {
		return false, time.Time{}
	}
	mine := false
	for _, l := range strings.Split(string(st), "\n") {
		if !strings.HasPrefix(l, "Uid:") {
			continue
		}
		f := strings.Fields(strings.TrimPrefix(l, "Uid:"))
		mine = len(f) == 4
		for _, x := range f {
			mine = mine && x == strconv.Itoa(uid)
		}
	}
	if !mine {
		return false, time.Time{}
	}
	b, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return true, time.Time{}
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return true, time.Time{}
	}
	// Fields after the command: state is field 3, start time field 22.
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return true, time.Time{}
	}
	ticks, err := strconv.ParseInt(f[19], 10, 64)
	if err != nil {
		return true, time.Time{}
	}
	return true, boot.Add(time.Duration(ticks) * time.Second / clockTicks)
}

// EndSessions ends uid's SFTP sessions that started before before (all of
// them when before is zero) and says how many. uid must be a domain
// account's.
func (m *Manager) EndSessions(uid int, before time.Time) (int, error) {
	if uid < DomainUIDLow || uid > DomainUIDHigh {
		return 0, fmt.Errorf("user ID %d isn't a domain account's", uid)
	}
	boot, err := m.bootTime()
	if err != nil {
		return 0, err
	}
	ents, err := os.ReadDir(m.procRoot())
	if err != nil {
		return 0, err
	}
	kill := m.Kill
	if kill == nil {
		kill = func(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) }
	}
	n := 0
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 1 {
			continue
		}
		ok, started := m.sessionOf(e.Name(), uid, boot)
		if !ok {
			continue
		}
		// A start time that can't be read counts as before.
		if !before.IsZero() && !started.IsZero() && !started.Before(before) {
			continue
		}
		if err := kill(pid); err == nil {
			n++
		}
	}
	if n > 0 {
		m.log().Info("sftp: ended a domain account's sessions", "uid", uid, "sessions", n)
	}
	return n, nil
}
