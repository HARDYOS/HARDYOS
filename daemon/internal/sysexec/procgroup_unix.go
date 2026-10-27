//go:build unix

package sysexec

import (
	"os/exec"
	"syscall"
	"time"
)

// WaitDelay bounds how long a finished or cancelled command's output pipes
// are waited for: a child it left behind (apt's dpkg, a DKMS build) can
// otherwise hold them open, and Wait would never return.
const WaitDelay = 10 * time.Second

// own puts the command in a process group of its own, and makes a
// cancelled or timed-out context kill the whole group (the command and
// everything it started), not just the command itself.
func own(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// The group's ID is the command's PID (Setpgid with Pgid 0).
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = WaitDelay
}

func ownGroup(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

// KillGroup kills a started command's process group (OwnGroup).
func KillGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		_ = cmd.Process.Kill()
	}
}
