//go:build linux

package vms

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// MigrateConnectArg is hardyd-priv's subcommand that connects to libvirt
// as MigrateUser and hands the connection back over fd 3. libvirt learns
// who is connecting from the socket's peer credentials, taken when the
// connection is made: the helper has MigrateUser's identity then, so the
// polkit rules see that user, never root.
const MigrateConnectArg = "migrate-connect"

// connectAs runs the helper with MigrateUser's identity.
func connectAs(ctx context.Context, sock string) (*os.File, error) {
	u, err := user.Lookup(MigrateUser)
	if err != nil {
		return nil, fmt.Errorf("the %s user is missing (set live migration up first): %w", MigrateUser, err)
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	groups := []uint32{}
	if g, err := user.LookupGroup("libvirt"); err == nil {
		n, _ := strconv.ParseUint(g.Gid, 10, 32)
		groups = append(groups, uint32(n))
	}
	if uid == 0 {
		return nil, errors.New("the migration user must not be root")
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parent := os.NewFile(uintptr(fds[0]), "migrate-parent")
	child := os.NewFile(uintptr(fds[1]), "migrate-child")
	defer parent.Close()
	self, err := os.Executable()
	if err != nil {
		child.Close()
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, self, MigrateConnectArg, sock)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.ExtraFiles = []*os.File{child}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups},
		Pdeathsig:  syscall.SIGKILL,
	}
	if err := cmd.Start(); err != nil {
		child.Close()
		return nil, err
	}
	child.Close()
	conn, err := net.FileConn(parent)
	if err != nil {
		_ = cmd.Wait()
		return nil, err
	}
	defer conn.Close()
	uc := conn.(*net.UnixConn)
	_ = uc.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 64)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, rerr := uc.ReadMsgUnix(buf, oob)
	werr := cmd.Wait()
	if rerr != nil {
		return nil, fmt.Errorf("the migration helper: %w", rerr)
	}
	if oobn == 0 {
		msg := string(buf[:n])
		if werr != nil && msg == "" {
			msg = werr.Error()
		}
		return nil, fmt.Errorf("the migration helper couldn't connect to libvirt: %s", msg)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		return nil, errors.New("the migration helper sent no connection")
	}
	rights, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(rights) != 1 {
		for _, fd := range rights {
			_ = unix.Close(fd)
		}
		return nil, errors.New("the migration helper sent no connection")
	}
	return os.NewFile(uintptr(rights[0]), "libvirt-migrate"), nil
}

// MigrateConnectMain is the helper (already running as MigrateUser):
// connect to libvirt's socket and send the connection over fd 3.
func MigrateConnectMain(args []string) int {
	out := os.NewFile(3, "parent")
	if out == nil || len(args) != 1 || args[0] != LibvirtSocket {
		return 2
	}
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		_, _ = out.Write([]byte("refusing to connect as root"))
		return 2
	}
	c, err := net.DialTimeout("unix", args[0], 10*time.Second)
	if err != nil {
		_, _ = out.Write([]byte(err.Error()))
		return 1
	}
	f, err := c.(*net.UnixConn).File()
	c.Close()
	if err != nil {
		_, _ = out.Write([]byte(err.Error()))
		return 1
	}
	pc, err := net.FileConn(out)
	if err != nil {
		return 1
	}
	if _, _, err := pc.(*net.UnixConn).WriteMsgUnix([]byte("ok"), unix.UnixRights(int(f.Fd())), nil); err != nil {
		return 1
	}
	return 0
}
