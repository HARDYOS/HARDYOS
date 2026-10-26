package apps

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// dirOwner is who a folder mkdirStrict makes belongs to. UID/GID below 0
// leave that part as is. OnlyIfNew: set the owner only when mkdirStrict
// created the folder (a container may have changed it since, on purpose).
type dirOwner struct {
	UID, GID  int
	OnlyIfNew bool
}

// keepOwner leaves the folder's owner alone.
var keepOwner = dirOwner{UID: -1, GID: -1}

// mkdirStrict creates base/rel one level at a time and sets the last
// folder's mode and owner. A running container can write in the app's data
// folder, so it could swap any folder on the way for a symbolic link at
// any moment (rename over it, or renameat2 RENAME_EXCHANGE): nothing here
// uses a path after the base. Every level is created with mkdirat and
// opened with openat(O_NOFOLLOW|O_DIRECTORY) relative to the folder above
// it, and the mode and owner are set through the last folder's own file
// descriptor, so a link anywhere is refused instead of followed. base
// itself is root's (a ZFS mountpoint, or the data folder in it, which no
// container can replace).
func mkdirStrict(base, rel string, mode os.FileMode, own dirOwner) error {
	segs := strings.Split(rel, "/")
	for _, seg := range segs {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("folder %q: use a plain path inside the app's folder", rel)
		}
	}
	const flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Open(base, flags, 0)
	if err != nil {
		return fmt.Errorf("opening %s: %w", base, err)
	}
	cur := base
	created := false
	for _, seg := range segs {
		cur = filepath.Join(cur, seg)
		created = false
		switch err := unix.Mkdirat(fd, seg, 0o755); {
		case err == nil:
			created = true
		case errors.Is(err, unix.EEXIST):
		default:
			unix.Close(fd)
			return fmt.Errorf("creating %s: %w", cur, err)
		}
		next, err := unix.Openat(fd, seg, flags, 0)
		unix.Close(fd)
		if err != nil {
			if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
				return fmt.Errorf("%s exists and isn't a folder", cur)
			}
			return fmt.Errorf("opening %s: %w", cur, err)
		}
		fd = next
	}
	defer unix.Close(fd)
	if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return fmt.Errorf("setting the mode of %s: %w", cur, err)
	}
	if (own.UID >= 0 || own.GID >= 0) && (created || !own.OnlyIfNew) {
		// Only root can give folders away; tests run as anyone.
		if err := unix.Fchown(fd, own.UID, own.GID); err != nil && !errors.Is(err, unix.EPERM) {
			return fmt.Errorf("setting the owner of %s: %w", cur, err)
		}
	}
	return nil
}
