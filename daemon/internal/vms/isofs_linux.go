package vms

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/sys/unix"

	"github.com/hardyos/hardyos/daemon/internal/shares"
)

// The ISO library is a shared folder, so people can put anything there
// (over SMB, as links, as folders with odd names). Root only ever works in
// it through a descriptor of the folder's verified mount (shares.OpenRoot)
// and names resolved beneath it without following links.

func openFolder(f *Folder) (int, error) {
	return shares.OpenRoot(f.Path, f.Dev, unix.O_RDONLY)
}

func beneath(dirfd int, name string, flags int, mode uint32) (int, error) {
	if err := ValidFile(name); err != nil {
		return -1, err
	}
	how := &unix.OpenHow{
		Flags:   uint64(flags | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Mode:    uint64(mode),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	}
	for {
		fd, err := unix.Openat2(dirfd, name, how)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		return fd, err
	}
}

// listFolder lists the library's discs and disk images.
func listFolder(f *Folder) ([]LibraryFile, error) {
	fd, err := openFolder(f)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), f.Path)
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	out := []LibraryFile{}
	for _, e := range entries {
		name := e.Name()
		if ValidFile(name) != nil || !(IsISO(name) || IsDiskImage(name)) {
			continue
		}
		var st unix.Stat_t
		if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			continue
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Dev != f.Dev {
			continue
		}
		kind := "iso"
		if !IsISO(name) {
			kind = "disk"
		}
		out = append(out, LibraryFile{Name: name, Kind: kind, Size: st.Size, Modified: time.Unix(st.Mtim.Sec, 0).UTC()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// openFile opens a regular file in the library for reading.
func openFile(f *Folder, name string) (*os.File, error) {
	root, err := openFolder(f)
	if err != nil {
		return nil, err
	}
	defer unix.Close(root)
	fd, err := beneath(root, name, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, fmt.Errorf("%s isn't in the ISOs shared folder: %w", name, os.ErrNotExist)
		}
		return nil, fmt.Errorf("%s in the ISOs shared folder can't be used (links and folders aren't): %w", name, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Dev != f.Dev {
		unix.Close(fd)
		return nil, fmt.Errorf("%s in the ISOs shared folder isn't a regular file", name)
	}
	// Reads should block normally from here on.
	if err := unix.SetNonblock(fd, false); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

// verifyPath checks that the path libvirt hands QEMU for a disc in the
// library is, right now, the file checked through the folder's descriptor:
// a regular file, not a link, the same device and inode, in the folder's
// own mount (decision 140).
func verifyPath(f *Folder, name string) error {
	file, err := openFile(f, name)
	if err != nil {
		return err
	}
	defer file.Close()
	var want, dir, got unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &want); err != nil {
		return err
	}
	if err := unix.Lstat(f.Path, &dir); err != nil || dir.Mode&unix.S_IFMT != unix.S_IFDIR || dir.Dev != f.Dev {
		return errors.New("the ISOs shared folder moved; try again")
	}
	if err := unix.Lstat(filepath.Join(f.Path, name), &got); err != nil {
		return fmt.Errorf("%s changed in the ISOs shared folder; try again: %w", name, err)
	}
	if got.Mode&unix.S_IFMT != unix.S_IFREG || got.Dev != want.Dev || got.Ino != want.Ino {
		return fmt.Errorf("%s changed in the ISOs shared folder (it was replaced or became a link); try again", name)
	}
	return nil
}

// grantQEMU lets QEMU's user read a disc in the library (and pass through
// the folder to it).
func grantQEMU(f *Folder, name string, uid uint32) error {
	root, err := openFolder(f)
	if err != nil {
		return err
	}
	defer unix.Close(root)
	if err := shares.GrantReadFD(root, uid); err != nil {
		return fmt.Errorf("letting VMs into the ISOs shared folder: %w", err)
	}
	file, err := openFile(f, name)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := shares.GrantReadFD(int(file.Fd()), uid); err != nil {
		return fmt.Errorf("letting VMs read %s: %w", name, err)
	}
	return nil
}

// createTemp makes a new hidden file in the library for a download.
func createTemp(f *Folder, name string) (*os.File, error) {
	root, err := openFolder(f)
	if err != nil {
		return nil, err
	}
	defer unix.Close(root)
	fd, err := beneath(root, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o644)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

// renameInto moves a finished download to its name; an existing file of
// that name is never replaced.
func renameInto(f *Folder, from, to string) error {
	if err := ValidFile(to); err != nil {
		return err
	}
	root, err := openFolder(f)
	if err != nil {
		return err
	}
	defer unix.Close(root)
	if err := unix.Renameat2(root, from, root, to, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("there's already a file called %s in the ISOs shared folder", to)
		}
		return err
	}
	return nil
}

// removeFile deletes a regular file from the library.
func removeFile(f *Folder, name string) error {
	if err := ValidFile(name); err != nil {
		return err
	}
	root, err := openFolder(f)
	if err != nil {
		return err
	}
	defer unix.Close(root)
	var st unix.Stat_t
	if err := unix.Fstatat(root, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("%s isn't in the ISOs shared folder", name)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%s isn't a file", name)
	}
	return unix.Unlinkat(root, name, 0)
}

// TPM state limits: swtpm keeps a few small files.
const (
	maxTreeDepth   = 4
	maxTreeEntries = 256
	maxTreeFile    = 64 << 20
)

// copyTree copies a small tree of plain files and folders from src to a
// new folder dst, keeping modes and owners (TPM state belongs to swtpm's
// user, who can change it under us). Everything goes through descriptors:
// names are opened beneath their folder without following links, links
// and special files are skipped, owners and modes are set on the
// descriptors of the copies.
func copyTree(src, dst string) error {
	sfd, err := unix.Open(src, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(sfd)
	if err := unix.Mkdir(dst, 0o700); err != nil {
		return err
	}
	dfd, err := unix.Open(dst, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	budget := maxTreeEntries
	if err := copyDirFD(sfd, dfd, 0, &budget); err != nil {
		return err
	}
	return sameOwnerMode(sfd, dfd)
}

func sameOwnerMode(from, to int) error {
	var st unix.Stat_t
	if err := unix.Fstat(from, &st); err != nil {
		return err
	}
	if err := unix.Fchown(to, int(st.Uid), int(st.Gid)); err != nil {
		return err
	}
	return unix.Fchmod(to, st.Mode&0o777)
}

func openBeneath(dirfd int, name string, flags int, mode uint32) (int, error) {
	how := &unix.OpenHow{
		Flags:   uint64(flags | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Mode:    uint64(mode),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	}
	for {
		fd, err := unix.Openat2(dirfd, name, how)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		return fd, err
	}
}

func copyDirFD(sfd, dfd, depth int, budget *int) error {
	dup, err := unix.Dup(sfd)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(dup), "tpm")
	names, err := dir.Readdirnames(-1)
	dir.Close()
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		if *budget--; *budget < 0 {
			return errors.New("the TPM state has too many files")
		}
		fd, err := openBeneath(sfd, name, unix.O_RDONLY|unix.O_NONBLOCK, 0)
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) || errors.Is(err, unix.ENXIO) {
			continue // a link, a mount, a socket
		}
		if err != nil {
			return err
		}
		err = copyEntryFD(fd, dfd, name, depth, budget)
		unix.Close(fd)
		if err != nil {
			return err
		}
	}
	return nil
}

func copyEntryFD(fd, dfd int, name string, depth int, budget *int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		if depth+1 > maxTreeDepth {
			return errors.New("the TPM state has too many levels of folders")
		}
		if err := unix.Mkdirat(dfd, name, 0o700); err != nil {
			return err
		}
		cfd, err := openBeneath(dfd, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if err != nil {
			return err
		}
		defer unix.Close(cfd)
		if err := copyDirFD(fd, cfd, depth+1, budget); err != nil {
			return err
		}
		return sameOwnerMode(fd, cfd)
	case unix.S_IFREG:
		if st.Size > maxTreeFile {
			return fmt.Errorf("%s in the TPM state is too big", name)
		}
		if err := unix.SetNonblock(fd, false); err != nil {
			return err
		}
		wfd, err := openBeneath(dfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		in := os.NewFile(uintptr(fd), name)
		out := os.NewFile(uintptr(wfd), name)
		defer out.Close()
		n, err := io.Copy(out, io.LimitReader(in, maxTreeFile+1))
		if err != nil {
			return err
		}
		if n > maxTreeFile {
			return fmt.Errorf("%s in the TPM state is too big", name)
		}
		if err := out.Sync(); err != nil {
			return err
		}
		return sameOwnerMode(fd, wfd)
	}
	return nil // fifos, devices
}
