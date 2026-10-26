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
	Source   string
	ReadOnly bool
}

// Mounter makes and removes the views' bind mounts (the real one uses the
// mount system calls; tests use a fake).
type Mounter interface {
	// List returns the mounts strictly below dir.
	List(dir string) ([]MountPoint, error)
	// IsMount reports whether dir is itself a mount point.
	IsMount(dir string) (bool, error)
	// MakePrivate makes dir a mount point of its own that shares no mount
	// events with any other mount namespace.
	MakePrivate(dir string) error
	// Bind mounts the folder src on dst (nosuid, nodev, noexec; read-only
	// when ro), opening both without following links.
	Bind(src, dst string, ro bool) error
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
		ro := false
		for _, o := range strings.Split(f[5], ",") {
			if o == "ro" {
				ro = true
			}
		}
		out = append(out, MountPoint{Target: target, Source: unescapeMount(f[sep+2]), ReadOnly: ro})
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
