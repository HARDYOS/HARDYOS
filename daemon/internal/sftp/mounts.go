package sftp

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// MountPoint is a mount below the views' root, from /proc/self/mountinfo.
type MountPoint struct {
	Target string
	// Source is the mounted file system (a ZFS dataset's name).
	Source string
	// Root is the folder of that file system the mount shows (mountinfo's
	// fourth field): "/" for a bind of a dataset's own mount.
	Root string
	// Dev is the mount's device (st_dev of everything in it).
	Dev      uint64
	ReadOnly bool
	// NoSuid, NoDev, NoExec: the per-mount restrictions.
	NoSuid, NoDev, NoExec bool
	// Shared, Slave: the mount takes part in mount propagation (a peer
	// group, or receiving from one). A view's binds must be neither.
	Shared, Slave bool
}

// Restricted reports whether the mount carries the restrictions every view
// bind has (nosuid, nodev, noexec, no propagation).
func (m MountPoint) Restricted() bool {
	return m.NoSuid && m.NoDev && m.NoExec && !m.Shared && !m.Slave
}

// Mounter makes and removes the views' bind mounts (the real one uses the
// mount system calls; tests use a fake).
type Mounter interface {
	// List returns the mounts strictly below dir.
	List(dir string) ([]MountPoint, error)
	// IsMount reports whether dir is itself a mount point.
	IsMount(dir string) (bool, error)
	// MakePrivate makes dir a mount point of its own that shares no mount
	// events with any other mount, and then makes every mount below it
	// private too (MS_REC): binds made before this version were peers of
	// the shared folders' own mounts, and unmounting anything inside them
	// would otherwise unmount it on the host as well.
	MakePrivate(dir string) error
	// Bind mounts the folder src on dst: private (in no peer group),
	// non-recursive (file systems mounted inside src aren't carried into
	// the view), nosuid, nodev, noexec, read-only when ro; both opened
	// without following links. src must be the verified mount on dev
	// (shares.OpenRoot).
	Bind(src string, dev uint64, dst string, ro bool) error
	Unmount(dst string) error
}

// unescapeMount undoes mountinfo's octal escapes (\040 for a space).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// mkdev builds a device number the way Linux (and glibc's makedev) encode
// it, so it compares with st_dev.
func mkdev(major, minor uint64) uint64 {
	return (minor & 0xff) | ((major & 0xfff) << 8) | ((minor &^ 0xff) << 12) | ((major &^ 0xfff) << 32)
}

func parseDev(s string) uint64 {
	ma, mi, ok := strings.Cut(s, ":")
	if !ok {
		return 0
	}
	a, err1 := strconv.ParseUint(ma, 10, 32)
	b, err2 := strconv.ParseUint(mi, 10, 32)
	if err1 != nil || err2 != nil {
		return 0
	}
	return mkdev(a, b)
}

// parseMountinfo returns the mounts strictly below dir (no trailing slash).
func parseMountinfo(r io.Reader, dir string) ([]MountPoint, error) {
	var out []MountPoint
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		sep := -1
		for i, x := range f {
			if x == "-" {
				sep = i
				break
			}
		}
		if len(f) < 6 || sep < 6 || sep+2 >= len(f) {
			continue
		}
		target := unescapeMount(f[4])
		if !strings.HasPrefix(target, dir+"/") {
			continue
		}
		mp := MountPoint{Target: target, Source: unescapeMount(f[sep+2]), Root: unescapeMount(f[3]), Dev: parseDev(f[2])}
		for _, o := range strings.Split(f[5], ",") {
			switch o {
			case "ro":
				mp.ReadOnly = true
			case "nosuid":
				mp.NoSuid = true
			case "nodev":
				mp.NoDev = true
			case "noexec":
				mp.NoExec = true
			}
		}
		for _, o := range f[6:sep] {
			switch {
			case strings.HasPrefix(o, "shared:"):
				mp.Shared = true
			case strings.HasPrefix(o, "master:"):
				mp.Slave = true
			}
		}
		out = append(out, mp)
	}
	return out, sc.Err()
}

func isMountIn(r io.Reader, dir string) (bool, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) > 4 && unescapeMount(f[4]) == dir {
			return true, nil
		}
	}
	return false, sc.Err()
}
