package vms

import (
	"errors"
	"fmt"
	"os"
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

// chownLike gives target the owner of info's file (TPM state belongs to
// swtpm's user).
func chownLike(target string, info os.FileInfo) {
	if st, ok := info.Sys().(*unix.Stat_t); ok {
		_ = os.Lchown(target, int(st.Uid), int(st.Gid))
	}
}
