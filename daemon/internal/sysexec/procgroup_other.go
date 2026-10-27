//go:build !unix

package sysexec

import (
	"os/exec"
	"time"
)

// WaitDelay bounds how long a finished or cancelled command's output pipes
// are waited for.
const WaitDelay = 10 * time.Second

func own(cmd *exec.Cmd) { cmd.WaitDelay = WaitDelay }
