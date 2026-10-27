//go:build linux

package fileworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"syscall"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"golang.org/x/sys/unix"
)

// MaxResultBytes bounds a worker's answer.
const MaxResultBytes = 64 << 20

// spawn runs one worker as ident with the given roots.
func (s *Server) spawn(ctx context.Context, ident *Identity, roots []*root, req Request) (json.RawMessage, *os.File, error) {
	if ident.UID == 0 || ident.GID == 0 {
		return nil, nil, errorf(CodeNoAccess, "refusing to act as root")
	}
	if s.Exe == "" {
		return nil, nil, errorf(CodeFailed, "file worker isn't set up")
	}
	timeout := 2 * time.Minute
	if req.Op == OpDelete {
		timeout = 9 * time.Minute // deleting a big folder for good
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var files []*os.File
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	mine := os.NewFile(uintptr(sp[0]), "fileworker-parent")
	defer mine.Close()
	theirs := os.NewFile(uintptr(sp[1]), "fileworker-child")
	files = append(files, theirs)
	for _, r := range roots {
		// Only the verified mount of the folder's own dataset (or home
		// folder), reached without following any link.
		fd, err := shares.OpenRoot(r.path, r.dev, unix.O_PATH)
		if err != nil {
			s.log().Warn("file worker: folder refused", "folder", r.id, "path", r.path, "err", err)
			return nil, nil, errorf(CodeNotFound, "the folder isn't available right now")
		}
		files = append(files, os.NewFile(uintptr(fd), r.path))
	}
	if req.Op == OpDelete && req.Recycle {
		if err := s.ensureRecycle(roots[0], int(files[1].Fd())); err != nil {
			return nil, nil, err
		}
	}

	req.UID, req.GID, req.Roots = ident.UID, ident.GID, len(roots)
	in, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}
	cred := &syscall.Credential{Uid: uint32(ident.UID), Gid: uint32(ident.GID)}
	for _, g := range ident.Groups {
		cred.Groups = append(cred.Groups, uint32(g))
	}
	if os.Geteuid() != 0 {
		// Development and tests without root: only our own identity works.
		if ident.UID != os.Getuid() || ident.GID != os.Getgid() {
			return nil, nil, errorf(CodeFailed, "hardyd-priv isn't running as root, so it can't act as %d", ident.UID)
		}
		cred.NoSetGroups, cred.Groups = true, nil
	}
	cmd := exec.CommandContext(ctx, s.Exe, s.Args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	cmd.Dir = "/"
	cmd.Stdin = bytes.NewReader(in)
	out := &capped{max: MaxResultBytes}
	stderr := &capped{max: 16 << 10}
	cmd.Stdout, cmd.Stderr = out, stderr
	cmd.ExtraFiles = files
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("starting the file worker: %w", err)
	}
	// Our copies of the child's descriptors aren't needed any more.
	for _, f := range files {
		f.Close()
	}
	files = nil
	werr := cmd.Wait()

	var res struct {
		OK    bool            `json:"ok"`
		Error *Error          `json:"error"`
		Data  json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		if ctx.Err() != nil {
			return nil, nil, errorf(CodeFailed, "the file operation took too long")
		}
		s.log().Warn("file worker failed", "op", req.Op, "err", werr, "stderr", stderr.String())
		return nil, nil, errorf(CodeFailed, "the file worker failed: %v", werr)
	}
	if !res.OK {
		if res.Error == nil {
			res.Error = errorf(CodeFailed, "the file operation failed")
		}
		return nil, nil, res.Error
	}
	file, err := receiveFile(mine)
	if err != nil {
		return nil, nil, err
	}
	switch req.Op {
	case OpOpen, OpCreate, OpOpenWrite:
		if file == nil {
			return nil, nil, errorf(CodeFailed, "the file worker didn't hand over the file")
		}
		if err := checkHanded(file, req.Op, roots[0].dev, req.Snapshot != ""); err != nil {
			file.Close()
			s.log().Warn("file worker handed over the wrong kind of file", "op", req.Op, "err", err)
			return nil, nil, errorf(CodeFailed, "the file worker handed over the wrong file")
		}
	default:
		if file != nil {
			file.Close()
			file = nil
		}
	}
	return res.Data, file, nil
}

// receiveFile takes the descriptor a worker sent, if any (it's queued on the
// socket even though the worker has exited).
func receiveFile(sock *os.File) (*os.File, error) {
	buf := make([]byte, 8)
	oob := make([]byte, unix.CmsgSpace(4*4))
	n, oobn, _, _, err := unix.Recvmsg(int(sock.Fd()), buf, oob, unix.MSG_DONTWAIT|unix.MSG_CMSG_CLOEXEC)
	if errors.Is(err, unix.EAGAIN) || (err == nil && n == 0 && oobn == 0) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("receiving the file: %w", err)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, fmt.Errorf("receiving the file: %w", err)
	}
	var file *os.File
	for _, m := range msgs {
		fds, err := unix.ParseUnixRights(&m)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if file == nil {
				file = os.NewFile(uintptr(fd), "file")
			} else {
				unix.Close(fd)
			}
		}
	}
	return file, nil
}

// ensureRecycle makes sure the share's .recycle is root's, 1777 and
// without ACL entries (shares.EnsureRecycle), as root through the share's
// descriptor; each person's bin inside it is made and checked by their
// worker. An existing link or file there is refused, never followed.
func (s *Server) ensureRecycle(r *root, rootfd int) error {
	fixed, err := shares.EnsureRecycle(rootfd)
	switch {
	case slices.Contains(fixed, "owner"):
		s.log().Warn("recycle bin belonged to someone else; given back to root", "folder", r.id, "fixed", fixed)
	case len(fixed) > 0:
		s.log().Info("recycle bin set up", "folder", r.id, "fixed", fixed)
	}
	if err != nil {
		var be *shares.BinError
		if errors.As(err, &be) {
			s.log().Warn("recycle bin refused", "folder", r.id, "err", err)
			return errorf(CodeNotAllowed, "%s; delete permanently instead", be.Msg)
		}
		return errorf(CodeFailed, "the recycle bin: %v", err)
	}
	return nil
}

// checkHanded checks the descriptor a worker handed back before hardyd
// gets it: a regular file opened for exactly what the operation is for
// (read only for open, write only for create and openwrite; never O_PATH),
// on the folder's own file system unless it's an older version.
func checkHanded(f *os.File, op string, dev uint64, snapshot bool) error {
	fd := int(f.Fd())
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("not a regular file (mode %o)", st.Mode)
	}
	fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	want := unix.O_RDONLY
	if op == OpCreate || op == OpOpenWrite {
		want = unix.O_WRONLY
	}
	if fl&unix.O_PATH != 0 || fl&unix.O_ACCMODE != want {
		return fmt.Errorf("opened with flags %#o for %s", fl, op)
	}
	if !snapshot && st.Dev != dev {
		return fmt.Errorf("on another file system")
	}
	return nil
}

// canOpenRoot reports whether r is still its verified mount.
func canOpenRoot(r *root) bool {
	fd, err := shares.OpenRoot(r.path, r.dev, unix.O_PATH)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}

// capped keeps at most max bytes (and fails the write past that).
type capped struct {
	bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if c.Len()+len(p) > c.max {
		return 0, errors.New("too much output")
	}
	return c.Buffer.Write(p)
}
