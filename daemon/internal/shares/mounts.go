package shares

// Where datasets are really mounted. A shared folder's settings (and its
// mountpoint) come from the pool, and a pool can come from anywhere: an
// imported disk can describe a "shared folder" at any path it likes. So
// before hardyd-priv does anything as root to a shared folder (ACLs, the
// recycle bin, SMB, the file workers), the folder's path must be the root
// of that very dataset's ZFS mount, as the kernel reports it in
// /proc/self/mountinfo. Manager.List checks this and records the mount's
// device number in Share.RootDev; OpenRoot then opens the folder without
// following links and refuses it unless it is on that device.

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ErrUnverified means a shared folder's mount hasn't been verified (or
// failed verification), so nothing may be done to it as root.
var ErrUnverified = errors.New("the shared folder's mount isn't verified")

// MountEntry is one mount from /proc/self/mountinfo.
type MountEntry struct {
	Mountpoint string
	// Root is the path inside the file system that is mounted ("/" unless
	// it's a bind mount of a subfolder).
	Root   string
	FSType string
	Source string
	Dev    uint64
}

// MountTable is the mount table, in the kernel's order.
type MountTable []MountEntry

// MountVerifier says whether path is the root of dataset's ZFS mount and,
// if it is, that mount's device number.
type MountVerifier interface {
	VerifyMount(path, dataset string) (dev uint64, err error)
}

// MountFunc is a MountVerifier from a function (tests).
type MountFunc func(path, dataset string) (uint64, error)

// VerifyMount implements MountVerifier.
func (f MountFunc) VerifyMount(path, dataset string) (uint64, error) { return f(path, dataset) }

// MountInfoPath is the kernel's mount table for this process.
const MountInfoPath = "/proc/self/mountinfo"

// ReadMountTable reads /proc/self/mountinfo.
func ReadMountTable() (MountTable, error) {
	b, err := os.ReadFile(MountInfoPath)
	if err != nil {
		return nil, err
	}
	return ParseMountInfo(b)
}

// mkdev builds a device number the way the kernel reports st_dev (glibc's
// makedev).
func mkdev(major, minor uint64) uint64 {
	return (major&0xfffff000)<<32 | (major&0xfff)<<8 | (minor&0xffffff00)<<12 | (minor & 0xff)
}

// unescapeMount undoes mountinfo's octal escapes (\040 for a space, \011,
// \012, \134).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
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

// ParseMountInfo parses the kernel's mountinfo format:
//
//	36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw
func ParseMountInfo(b []byte) (MountTable, error) {
	var t MountTable
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, " ")
		sep := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if len(f) < 7 || sep < 0 || sep+2 >= len(f) {
			return nil, fmt.Errorf("mountinfo: unexpected line %q", line)
		}
		maj, min, ok := strings.Cut(f[2], ":")
		if !ok {
			return nil, fmt.Errorf("mountinfo: unexpected device %q", f[2])
		}
		ma, err1 := strconv.ParseUint(maj, 10, 32)
		mi, err2 := strconv.ParseUint(min, 10, 32)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("mountinfo: unexpected device %q", f[2])
		}
		t = append(t, MountEntry{
			Root:       unescapeMount(f[3]),
			Mountpoint: unescapeMount(f[4]),
			FSType:     f[sep+1],
			Source:     unescapeMount(f[sep+2]),
			Dev:        mkdev(ma, mi),
		})
	}
	return t, nil
}

// VerifyMount implements MountVerifier: the mount visible at path (the
// last one mounted there) must be a ZFS mount of dataset's own root.
func (t MountTable) VerifyMount(path, dataset string) (uint64, error) {
	var top *MountEntry
	for i := range t {
		if t[i].Mountpoint == path {
			top = &t[i]
		}
	}
	switch {
	case top == nil:
		return 0, fmt.Errorf("nothing is mounted at %s", path)
	case top.FSType != "zfs" || top.Source != dataset:
		return 0, fmt.Errorf("%s is %s (%s), not the dataset %s", path, top.Source, top.FSType, dataset)
	case top.Root != "/":
		return 0, fmt.Errorf("%s is a bind mount of %s inside %s, not the dataset's own mount", path, top.Root, dataset)
	case top.Dev == 0:
		return 0, fmt.Errorf("%s has no device number", path)
	}
	return top.Dev, nil
}
