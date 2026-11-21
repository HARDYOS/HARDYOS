// Package sdlisten takes the sockets systemd passes a service (socket
// activation: LISTEN_PID, LISTEN_FDS, LISTEN_FDNAMES). hardyd gets its mail
// sign-in socket this way, so systemd sets its owner, group and mode
// (hardyd-mail-auth.socket), which hardyd couldn't itself.
package sdlisten

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// firstFD is where systemd's sockets start.
const firstFD = 3

// Listeners returns the sockets systemd passed, by FileDescriptorName, and
// clears the variables so child processes don't see them. None passed: an
// empty map.
func Listeners() (map[string]net.Listener, error) {
	defer func() {
		_ = os.Unsetenv("LISTEN_PID")
		_ = os.Unsetenv("LISTEN_FDS")
		_ = os.Unsetenv("LISTEN_FDNAMES")
	}()
	return listeners(os.Getenv, os.Getpid(), firstFD)
}

func listeners(getenv func(string) string, pid, first int) (map[string]net.Listener, error) {
	out := map[string]net.Listener{}
	if p, err := strconv.Atoi(getenv("LISTEN_PID")); err != nil || p != pid {
		return out, nil
	}
	n, err := strconv.Atoi(getenv("LISTEN_FDS"))
	if err != nil || n <= 0 {
		return out, nil
	}
	if n > 64 {
		return out, fmt.Errorf("LISTEN_FDS=%d is too many", n)
	}
	names := strings.Split(getenv("LISTEN_FDNAMES"), ":")
	for i := 0; i < n; i++ {
		fd := first + i
		syscall.CloseOnExec(fd)
		name := "unknown"
		if i < len(names) && names[i] != "" {
			name = names[i]
		}
		f := os.NewFile(uintptr(fd), name)
		ln, err := net.FileListener(f)
		_ = f.Close() // FileListener made its own copy
		if err != nil {
			return out, fmt.Errorf("socket %s from systemd: %w", name, err)
		}
		out[name] = ln
	}
	return out, nil
}
