//go:build linux

package fileworker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"golang.org/x/sys/unix"
)

// File descriptors a worker inherits.
const (
	sockFD      = 3 // where an opened file is sent back
	firstRootFD = 4 // the roots, in order
)

// resolveFlags: never leave the root, never follow a link of any kind.
const resolveFlags = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS

// ChildMain is the worker's entry point (hardyd-priv fileworker). It never
// returns.
func ChildMain() {
	os.Exit(childMain(os.Stdin, os.Stdout))
}

func childMain(in io.Reader, out io.Writer) int {
	res := func() Response {
		if err := harden(); err != nil {
			return Response{Error: errorf(CodeFailed, "file worker: %v", err)}
		}
		var req Request
		if err := json.NewDecoder(io.LimitReader(in, 1<<20)).Decode(&req); err != nil {
			return Response{Error: errorf(CodeBadArgs, "file worker: bad request: %v", err)}
		}
		if os.Getuid() != req.UID || os.Geteuid() != req.UID || os.Getgid() != req.GID || os.Getegid() != req.GID {
			return Response{Error: errorf(CodeFailed, "file worker: running as %d:%d, expected %d:%d", os.Geteuid(), os.Getegid(), req.UID, req.GID)}
		}
		if req.Roots < 1 || req.Roots > 512 {
			return Response{Error: errorf(CodeBadArgs, "file worker: bad root count")}
		}
		w := &worker{req: req, sock: sockFD}
		for i := 0; i < req.Roots; i++ {
			fd := firstRootFD + i
			var st unix.Stat_t
			if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
				return Response{Error: errorf(CodeFailed, "file worker: root %d isn't a folder", i)}
			}
			w.roots = append(w.roots, fd)
		}
		data, err := w.run()
		if err != nil {
			return Response{Error: asError(err)}
		}
		return Response{OK: true, Data: data}
	}()
	_ = json.NewEncoder(out).Encode(res)
	if res.OK {
		return 0
	}
	return 1
}

// harden refuses to run as root or with any capability, and makes sure the
// worker can't gain privileges or be inspected by other processes of the
// same user.
func harden() error {
	if os.Getuid() == 0 || os.Geteuid() == 0 || os.Getgid() == 0 || os.Getegid() == 0 {
		return errors.New("refusing to run as root")
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("reading capabilities: %w", err)
	}
	for _, d := range data {
		if d.Effective != 0 || d.Permitted != 0 {
			return errors.New("refusing to run with capabilities")
		}
	}
	// no_new_privs is per thread; set it on every thread the runtime has.
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); e != 0 {
		if e != syscall.ENOTSUP {
			return fmt.Errorf("no_new_privs: %w", e)
		}
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return fmt.Errorf("no_new_privs: %w", err)
		}
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("dumpable: %w", err)
	}
	unix.Umask(0o022)
	return nil
}

// worker runs one operation beneath its roots.
type worker struct {
	req   Request
	roots []int
	sock  int // -1 in tests that don't pass files
	// sent is the file handed back (tests without a socket read it here).
	sent *os.File
}

func (w *worker) run() (any, error) {
	r := w.req
	if r.Snapshot != "" && !SnapshotRE.MatchString(r.Snapshot) {
		return nil, errorf(CodeBadArgs, "there's no such older version")
	}
	if r.Op == OpShares {
		return w.shares(), nil
	}
	parts, err := OpPath(r.Op, r.Path, r.Op == OpDelete && !r.Recycle)
	if err != nil {
		return nil, err
	}
	if r.Snapshot != "" {
		switch r.Op {
		case OpList, OpStat, OpOpen:
		default:
			return nil, errorf(CodeNotAllowed, "older versions can't be changed")
		}
	}
	switch r.Op {
	case OpList:
		return w.list(parts)
	case OpStat:
		return w.stat(parts)
	case OpOpen:
		return w.open(parts)
	case OpCreate:
		return w.create(parts)
	case OpOpenWrite:
		return w.openWrite(parts)
	case OpMkdir:
		return w.mkdir(parts)
	case OpRename:
		to, err := RenameTarget(r.To)
		if err != nil {
			return nil, err
		}
		return w.rename(parts, to)
	case OpDelete:
		return w.delete(parts)
	case OpSetTime:
		return w.setTime(parts)
	case OpVersions:
		return w.versions(parts)
	}
	return nil, errorf(CodeBadArgs, "unknown file operation %q", r.Op)
}

// ---- resolving ---------------------------------------------------------------

// inner turns components into the path openat2 resolves: inside the
// snapshot when one is asked for (the only way into .zfs).
func (w *worker) inner(parts []string) string {
	p := Join(parts)
	if w.req.Snapshot != "" {
		p = strings.TrimSuffix(".zfs/snapshot/"+w.req.Snapshot+"/"+p, "/")
	}
	if p == "" {
		return "."
	}
	return p
}

// openIn opens p (already checked) beneath root without following links.
func openIn(root int, p string, flags int, mode uint32) (int, error) {
	flags |= unix.O_CLOEXEC
	if flags&unix.O_PATH == 0 {
		flags |= unix.O_NOCTTY // openat2 allows nothing else with O_PATH
	}
	how := &unix.OpenHow{Flags: uint64(flags), Mode: uint64(mode), Resolve: resolveFlags}
	for {
		fd, err := unix.Openat2(root, p, how)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		return fd, err
	}
}

// openParent opens the folder holding the last component, for the *at calls.
func (w *worker) openParent(root int, parts []string) (int, string, error) {
	if len(parts) == 0 {
		return -1, "", errorf(CodeNotAllowed, "that can't be done to the top of a shared folder")
	}
	fd, err := openIn(root, w.inner(parts[:len(parts)-1]), unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return -1, "", err
	}
	return fd, parts[len(parts)-1], nil
}

func canWrite(dirfd int, name string) bool {
	flags := unix.AT_EACCESS | unix.AT_SYMLINK_NOFOLLOW
	if name == "" {
		flags = unix.AT_EACCESS | unix.AT_EMPTY_PATH
	}
	return unix.Faccessat(dirfd, name, unix.W_OK, flags) == nil
}

func entryFrom(name, path string, st *unix.Stat_t) Entry {
	dir := st.Mode&unix.S_IFMT == unix.S_IFDIR
	e := Entry{Name: name, Path: path, Dir: dir, Modified: time.Unix(st.Mtim.Unix()).UTC()}
	if !dir {
		e.Size = st.Size
	}
	return e
}

func usable(st *unix.Stat_t) bool {
	t := st.Mode & unix.S_IFMT
	return t == unix.S_IFREG || t == unix.S_IFDIR
}

// ---- operations ----------------------------------------------------------------

func (w *worker) shares() []RootAccess {
	out := make([]RootAccess, len(w.roots))
	for i, fd := range w.roots {
		out[i].Read = unix.Faccessat(fd, "", unix.R_OK|unix.X_OK, unix.AT_EACCESS|unix.AT_EMPTY_PATH) == nil
		out[i].Write = out[i].Read && !w.req.ReadOnly && unix.Faccessat(fd, "", unix.W_OK|unix.X_OK, unix.AT_EACCESS|unix.AT_EMPTY_PATH) == nil
	}
	return out
}

func (w *worker) writable(dirfd int, name string) bool {
	return !w.req.ReadOnly && w.req.Snapshot == "" && canWrite(dirfd, name)
}

func (w *worker) list(parts []string) (*Listing, error) {
	fd, err := openIn(w.roots[0], w.inner(parts), unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "dir")
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	dirW := w.writable(fd, "")
	name := ""
	if len(parts) > 0 {
		name = parts[len(parts)-1]
	}
	l := &Listing{Folder: entryFrom(name, Join(parts), &st), Entries: []Entry{}}
	l.Folder.Writable = dirW
	prefix := Join(parts)
	if prefix != "" {
		prefix += "/"
	}
	for {
		names, rerr := f.Readdirnames(1024)
		for _, n := range names {
			if strings.HasPrefix(n, UploadPrefix) && dirW {
				cleanStaleUpload(fd, n)
			}
			if Hidden(n) || !utf8.ValidString(n) || len(l.Entries) >= MaxEntries {
				l.Truncated = l.Truncated || len(l.Entries) >= MaxEntries
				continue
			}
			var est unix.Stat_t
			if unix.Fstatat(fd, n, &est, unix.AT_SYMLINK_NOFOLLOW) != nil || !usable(&est) {
				continue // links, devices, pipes and sockets aren't shown
			}
			e := entryFrom(n, prefix+n, &est)
			e.Writable = dirW && w.writable(fd, n)
			l.Entries = append(l.Entries, e)
		}
		if rerr == io.EOF || (rerr == nil && len(names) == 0) {
			break
		}
		if rerr != nil {
			return nil, rerr
		}
	}
	sort.Slice(l.Entries, func(i, j int) bool {
		a, b := l.Entries[i], l.Entries[j]
		if a.Dir != b.Dir {
			return a.Dir
		}
		if la, lb := strings.ToLower(a.Name), strings.ToLower(b.Name); la != lb {
			return la < lb
		}
		return a.Name < b.Name
	})
	return l, nil
}

// cleanStaleUpload removes an upload that was abandoned two days ago.
func cleanStaleUpload(dirfd int, name string) {
	var st unix.Stat_t
	if unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return
	}
	if time.Since(time.Unix(st.Mtim.Unix())) > 48*time.Hour {
		_ = unix.Unlinkat(dirfd, name, 0)
	}
}

func (w *worker) stat(parts []string) (*Entry, error) {
	fd, err := openIn(w.roots[0], w.inner(parts), unix.O_PATH, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if !usable(&st) {
		return nil, errorf(CodeNotAllowed, "that isn't a file or folder")
	}
	name := ""
	if len(parts) > 0 {
		name = parts[len(parts)-1]
	}
	e := entryFrom(name, Join(parts), &st)
	if len(parts) == 0 {
		e.Writable = w.writable(fd, "")
		return &e, nil
	}
	pfd, _, err := w.openParent(w.roots[0], parts)
	if err != nil {
		return nil, err
	}
	defer unix.Close(pfd)
	e.Writable = w.writable(pfd, "") && w.writable(fd, "")
	return &e, nil
}

// send hands fd to the parent and closes it here.
func (w *worker) send(fd int) error {
	if w.sock < 0 {
		w.sent = os.NewFile(uintptr(fd), "file")
		return nil
	}
	defer unix.Close(fd)
	return unix.Sendmsg(w.sock, []byte{1}, unix.UnixRights(fd), nil, 0)
}

// openFile opens a regular file and hands it over.
func (w *worker) openFile(root int, p string, flags int, mode uint32, parts []string) (*Entry, error) {
	// O_NONBLOCK: opening a pipe someone left there mustn't hang.
	fd, err := openIn(root, p, flags|unix.O_NONBLOCK, mode)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			return nil, errorf(CodeNotAllowed, "that's a folder, not a file")
		}
		return nil, errorf(CodeNotAllowed, "that isn't a file")
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		unix.Close(fd)
		return nil, err
	}
	e := entryFrom(parts[len(parts)-1], Join(parts), &st)
	e.Writable = flags&(unix.O_WRONLY|unix.O_RDWR) != 0
	if err := w.send(fd); err != nil {
		return nil, fmt.Errorf("handing over the file: %w", err)
	}
	return &e, nil
}

func (w *worker) open(parts []string) (*Entry, error) {
	if len(parts) == 0 {
		return nil, errorf(CodeNotAllowed, "that's a folder, not a file")
	}
	return w.openFile(w.roots[0], w.inner(parts), unix.O_RDONLY, 0, parts)
}

func (w *worker) create(parts []string) (*Entry, error) {
	if w.req.ReadOnly {
		return nil, errorf(CodeNoAccess, "you can only read this shared folder")
	}
	pfd, name, err := w.openParent(w.roots[0], parts)
	if err != nil {
		return nil, err
	}
	defer unix.Close(pfd)
	flags := unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL
	if w.req.Overwrite {
		var st unix.Stat_t
		if err := unix.Fstatat(pfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil && st.Mode&unix.S_IFMT != unix.S_IFREG {
			return nil, errorf(CodeExists, "%s is already there and isn't a file", name)
		}
		flags = unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC
	}
	return w.openFile(pfd, name, flags, 0o666, parts)
}

func (w *worker) openWrite(parts []string) (*Entry, error) {
	if w.req.ReadOnly {
		return nil, errorf(CodeNoAccess, "you can only read this shared folder")
	}
	if len(parts) == 0 {
		return nil, errorf(CodeNotAllowed, "that's a folder, not a file")
	}
	return w.openFile(w.roots[0], w.inner(parts), unix.O_WRONLY, 0, parts)
}

func (w *worker) mkdir(parts []string) (*Entry, error) {
	if w.req.ReadOnly {
		return nil, errorf(CodeNoAccess, "you can only read this shared folder")
	}
	pfd, name, err := w.openParent(w.roots[0], parts)
	if err != nil {
		return nil, err
	}
	defer unix.Close(pfd)
	if err := unix.Mkdirat(pfd, name, 0o777); err != nil {
		return nil, err
	}
	return w.stat(parts)
}

func (w *worker) rename(from, to []string) (any, error) {
	if w.req.ReadOnly {
		return nil, errorf(CodeNoAccess, "you can only read this shared folder")
	}
	if w.req.ToRoot < 0 || w.req.ToRoot >= len(w.roots) {
		return nil, errorf(CodeBadArgs, "bad destination")
	}
	if len(to) == 0 {
		return nil, errorf(CodeNotAllowed, "that can't be done to the top of a shared folder")
	}
	pfd, name, err := w.openParent(w.roots[0], from)
	if err != nil {
		return nil, err
	}
	defer unix.Close(pfd)
	tfd, tname, err := w.openParent(w.roots[w.req.ToRoot], to)
	if err != nil {
		return nil, err
	}
	defer unix.Close(tfd)
	var st unix.Stat_t
	if err := unix.Fstatat(pfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	if !usable(&st) {
		return nil, errorf(CodeNotAllowed, "that isn't a file or folder")
	}
	flags := uint(unix.RENAME_NOREPLACE)
	if w.req.Overwrite {
		// Only a file replaces a file (finishing an upload).
		var tst unix.Stat_t
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			return nil, errorf(CodeExists, "something with that name is already there")
		}
		if err := unix.Fstatat(tfd, tname, &tst, unix.AT_SYMLINK_NOFOLLOW); err == nil && tst.Mode&unix.S_IFMT != unix.S_IFREG {
			return nil, errorf(CodeExists, "%s is already there and isn't a file", tname)
		}
		flags = 0
	}
	if err := unix.Renameat2(pfd, name, tfd, tname, flags); err != nil {
		if err == unix.EXDEV {
			return nil, errorf(CodeCrossDevice, "moving between these folders needs a copy")
		}
		if err == unix.EINVAL {
			return nil, errorf(CodeNotAllowed, "a folder can't be moved into itself")
		}
		return nil, err
	}
	return map[string]string{"path": Join(to)}, nil
}

func (w *worker) setTime(parts []string) (any, error) {
	if w.req.ReadOnly {
		return nil, errorf(CodeNoAccess, "you can only read this shared folder")
	}
	pfd, name, err := w.openParent(w.roots[0], parts)
	if err != nil {
		return nil, err
	}
	defer unix.Close(pfd)
	ts := []unix.Timespec{{Nsec: unix.UTIME_OMIT}, unix.NsecToTimespec(w.req.Modified.UnixNano())}
	if err := unix.UtimesNanoAt(pfd, name, ts, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	return w.stat(parts)
}

// ---- deleting ----------------------------------------------------------------

func (w *worker) delete(parts []string) (any, error) {
	if w.req.ReadOnly {
		return nil, errorf(CodeNoAccess, "you can only read this shared folder")
	}
	pfd, name, err := w.openParent(w.roots[0], parts)
	if err != nil {
		return nil, err
	}
	defer unix.Close(pfd)
	var st unix.Stat_t
	if err := unix.Fstatat(pfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	if !w.req.Recycle {
		if err := removeAll(pfd, name, 0); err != nil {
			return nil, err
		}
		return map[string]any{"recycled": false}, nil
	}
	dest, err := w.toRecycle(pfd, name, parts, &st)
	if err != nil {
		return nil, err
	}
	return map[string]any{"recycled": true, "binPath": dest}, nil
}

// validBin: the administrators' bin, or a domain account's
// <netbios>.<user> (shares.BinName).
func validBin(bin string) bool {
	if bin == shares.FilesBin {
		return true
	}
	nb, user, ok := strings.Cut(bin, ".")
	return ok && shares.BinName(nb, user) == bin
}

// openBin opens the person's own bin in .recycle (making it, 0700, if it
// isn't there) and makes sure it is theirs alone: owned by them, with no
// group, other or ACL access. A bin someone else made (.recycle is open to
// everyone) is refused, so nobody can collect another person's deleted
// files; one that is the person's but too open is closed up.
func (w *worker) openBin(bin string) (int, error) {
	if !validBin(bin) {
		return -1, errorf(CodeFailed, "no recycle bin name")
	}
	rfd, err := openIn(w.roots[0], shares.RecycleDir, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return -1, fmt.Errorf("the recycle bin: %w", err)
	}
	defer unix.Close(rfd)
	if err := unix.Mkdirat(rfd, bin, 0o700); err != nil && err != unix.EEXIST {
		return -1, fmt.Errorf("the recycle bin: %w", err)
	}
	fd, err := openIn(rfd, bin, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		if err == unix.EACCES || err == unix.ELOOP || err == unix.ENOTDIR || err == unix.EXDEV {
			return -1, errorf(CodeNotAllowed, "your recycle bin in this shared folder (.recycle/%s) isn't yours, so nothing can be put in it; ask an administrator to look at it, or delete permanently", bin)
		}
		return -1, fmt.Errorf("the recycle bin: %w", err)
	}
	owner, err := shares.CheckBin(fd, uint32(w.req.UID))
	if err != nil && owner {
		if terr := shares.TightenBin(fd); terr == nil {
			_, err = shares.CheckBin(fd, uint32(w.req.UID))
		}
	}
	if err != nil {
		unix.Close(fd)
		var be *shares.BinError
		if errors.As(err, &be) {
			return -1, errorf(CodeNotAllowed, "your recycle bin in this shared folder (.recycle/%s) can't be used safely (%s); ask an administrator to look at it, or delete permanently", bin, be.Msg)
		}
		return -1, fmt.Errorf("the recycle bin: %w", err)
	}
	return fd, nil
}

// toRecycle moves parent/name into .recycle/<bin>/<its folders>/, keeping
// the folder tree and never replacing an earlier deleted copy.
func (w *worker) toRecycle(pfd int, name string, parts []string, st *unix.Stat_t) (string, error) {
	bin := w.req.Bin
	dir, err := w.openBin(bin)
	if err != nil {
		return "", err
	}
	for _, c := range parts[:len(parts)-1] {
		if err := unix.Mkdirat(dir, c, 0o700); err != nil && err != unix.EEXIST {
			unix.Close(dir)
			return "", fmt.Errorf("the recycle bin: %w", err)
		}
		next, err := openIn(dir, c, unix.O_PATH|unix.O_DIRECTORY, 0)
		unix.Close(dir)
		if err != nil {
			return "", fmt.Errorf("the recycle bin: %w", err)
		}
		dir = next
	}
	defer unix.Close(dir)
	target := name
	stem, ext := splitExt(name, st.Mode&unix.S_IFMT == unix.S_IFDIR)
	for i := 0; ; i++ {
		if i > 0 {
			target = fmt.Sprintf("%s (deleted %s)%s", stem, time.Now().UTC().Format("2006-01-02 150405"), ext)
			if i > 1 {
				target = fmt.Sprintf("%s (deleted %s %d)%s", stem, time.Now().UTC().Format("2006-01-02 150405"), i, ext)
			}
		}
		err := unix.Renameat2(pfd, name, dir, target, unix.RENAME_NOREPLACE)
		if err == nil {
			break
		}
		if err == unix.EXDEV {
			return "", errorf(CodeNotAllowed, "%s can't go to the recycle bin (it's on another file system)", name)
		}
		if err != unix.EEXIST || i > 50 {
			return "", err
		}
	}
	return Join(append(append([]string{bin}, parts[:len(parts)-1]...), target)), nil
}

// splitExt splits "photo.jpg" into "photo" and ".jpg" (folders have none).
func splitExt(name string, dir bool) (string, string) {
	if dir {
		return name, ""
	}
	i := strings.LastIndexByte(name, '.')
	if i <= 0 {
		return name, ""
	}
	return name[:i], name[i:]
}

// removeAll deletes parent/name and everything below it, through file
// descriptors and without following links.
func removeAll(pfd int, name string, depth int) error {
	err := unix.Unlinkat(pfd, name, 0)
	if err == nil || err == unix.ENOENT {
		return nil
	}
	if err != unix.EISDIR && err != unix.EPERM {
		return err
	}
	var st unix.Stat_t
	if serr := unix.Fstatat(pfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); serr != nil {
		return serr
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return err
	}
	if depth >= maxDepth {
		return errorf(CodeNotAllowed, "the folder is too deep to delete")
	}
	fd, oerr := openIn(pfd, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if oerr != nil {
		return oerr
	}
	f := os.NewFile(uintptr(fd), name)
	names, rerr := f.Readdirnames(-1)
	if rerr != nil {
		f.Close()
		return rerr
	}
	for _, n := range names {
		if err := removeAll(fd, n, depth+1); err != nil {
			f.Close()
			return err
		}
	}
	f.Close()
	return unix.Unlinkat(pfd, name, unix.AT_REMOVEDIR)
}

// ---- older versions --------------------------------------------------------------

func (w *worker) versions(parts []string) ([]Version, error) {
	out := []Version{}
	// The current copy, to leave out versions that are the same.
	var cur unix.Stat_t
	haveCur := false
	if fd, err := openIn(w.roots[0], w.inner(parts), unix.O_PATH, 0); err == nil {
		haveCur = unix.Fstat(fd, &cur) == nil
		unix.Close(fd)
	} else if err != unix.ENOENT {
		return nil, err
	}
	sfd, err := openIn(w.roots[0], ".zfs/snapshot", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return out, nil // no snapshots here
	}
	f := os.NewFile(uintptr(sfd), "snapshots")
	names, _ := f.Readdirnames(-1)
	f.Close()
	type snap struct {
		name  string
		taken time.Time
	}
	var snaps []snap
	for _, n := range names {
		if t, ok := SnapshotTime(n); ok {
			snaps = append(snaps, snap{n, t})
		}
	}
	sort.Slice(snaps, func(i, j int) bool {
		if !snaps[i].taken.Equal(snaps[j].taken) {
			return snaps[i].taken.After(snaps[j].taken)
		}
		return snaps[i].name < snaps[j].name
	})
	var last *Version
	for _, s := range snaps {
		p := ".zfs/snapshot/" + s.name
		if len(parts) > 0 {
			p += "/" + Join(parts)
		}
		fd, err := openIn(w.roots[0], p, unix.O_PATH, 0)
		if err != nil {
			continue
		}
		var st unix.Stat_t
		err = unix.Fstat(fd, &st)
		unix.Close(fd)
		if err != nil || !usable(&st) {
			continue
		}
		v := Version{Snapshot: s.name, Taken: s.taken, Dir: st.Mode&unix.S_IFMT == unix.S_IFDIR, Modified: time.Unix(st.Mtim.Unix()).UTC()}
		if !v.Dir {
			v.Size = st.Size
			// Files: only versions that differ from the current file and
			// from the next newer version.
			if haveCur && cur.Mode&unix.S_IFMT == unix.S_IFREG && cur.Size == st.Size && cur.Mtim == st.Mtim {
				continue
			}
			if last != nil && !last.Dir && last.Size == v.Size && last.Modified.Equal(v.Modified) {
				continue
			}
		}
		out = append(out, v)
		last = &out[len(out)-1]
	}
	return out, nil
}

// ---- errors ------------------------------------------------------------------

// asError turns a system error into a coded one with a message for people.
func asError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	var errno unix.Errno
	if !errors.As(err, &errno) {
		return errorf(CodeFailed, "%v", err)
	}
	switch errno {
	case unix.ENOENT, unix.ENOTDIR:
		return errorf(CodeNotFound, "there's no such file or folder")
	case unix.EACCES, unix.EPERM:
		return errorf(CodeNoAccess, "you don't have access to that")
	case unix.EEXIST, unix.ENOTEMPTY:
		return errorf(CodeExists, "something with that name is already there")
	case unix.ELOOP, unix.EXDEV:
		return errorf(CodeNotAllowed, "links aren't followed in shared folders")
	case unix.EROFS:
		return errorf(CodeNotAllowed, "that can't be changed (older versions are read only)")
	case unix.EISDIR:
		return errorf(CodeNotAllowed, "that's a folder, not a file")
	case unix.ENOSPC, unix.EDQUOT:
		return errorf(CodeFull, "there's no space left in this shared folder")
	case unix.ENAMETOOLONG:
		return errorf(CodeBadArgs, "the name is too long")
	case unix.EBUSY:
		return errorf(CodeNotAllowed, "that's in use and can't be changed")
	case unix.ENXIO:
		return errorf(CodeNotAllowed, "that isn't a file")
	}
	return errorf(CodeFailed, "%v", err)
}
