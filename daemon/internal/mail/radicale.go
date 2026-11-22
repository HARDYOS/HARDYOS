package mail

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// RadicaleDialer connects hardyd to Radicale (decision 319). Before
// anything is sent (each request carries a mailbox's Radicale password) it
// checks that the socket is Radicale's: a socket owned by the radicale
// user, in a folder only root or radicale can write to. Nothing else on
// the server can put a socket there.
type RadicaleDialer struct {
	// Socket is the path (default RadicaleSocket); Owner the user that must
	// own it (default "radicale").
	Socket string
	Owner  string
}

// DialContext implements http.Transport's DialContext.
func (d RadicaleDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	path := d.Socket
	if path == "" {
		path = RadicaleSocket
	}
	if err := d.check(path); err != nil {
		return nil, err
	}
	return (&net.Dialer{}).DialContext(ctx, "unix", path)
}

func (d RadicaleDialer) check(path string) error {
	owner := d.Owner
	if owner == "" {
		owner = "radicale"
	}
	u, err := user.Lookup(owner)
	if err != nil {
		return fmt.Errorf("calendars: no %s user: %w", owner, err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	dir, err := os.Lstat(dirOf(path))
	if err != nil {
		return fmt.Errorf("calendars: %w", err)
	}
	dst, ok := dir.Sys().(*syscall.Stat_t)
	if !ok || !dir.IsDir() || dir.Mode().Perm()&0o022 != 0 || (int(dst.Uid) != uid && dst.Uid != 0) {
		return fmt.Errorf("calendars: %s isn't Radicale's folder", dirOf(path))
	}
	st, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("calendars: %w", err)
	}
	sst, ok := st.Sys().(*syscall.Stat_t)
	if !ok || st.Mode().Type() != fs.ModeSocket || int(sst.Uid) != uid {
		return fmt.Errorf("calendars: %s isn't Radicale's socket", path)
	}
	return nil
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			if i == 0 {
				return "/"
			}
			return p[:i]
		}
	}
	return "."
}
