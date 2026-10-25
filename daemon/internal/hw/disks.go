// Package hw detects the hardware HardyOS runs on: disks, CPU, memory, GPUs,
// network interfaces and IOMMU support, and turns that into a capability
// profile the rest of the system adapts to.
package hw

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// DiskKind classifies a disk by technology.
type DiskKind string

const (
	KindHDD  DiskKind = "hdd"
	KindSSD  DiskKind = "ssd"
	KindNVMe DiskKind = "nvme"
)

// UsageState says what a disk is currently used for.
type UsageState string

const (
	UsageFree    UsageState = "free"     // blank, safe to use
	UsageHasData UsageState = "has-data" // partitions or filesystems present; usable only after a confirmed wipe
	UsagePool    UsageState = "pool"     // member of a ZFS pool
	UsageBoot    UsageState = "boot"     // holds the running OS
	UsageMounted UsageState = "mounted"  // a filesystem on it is mounted (e.g. the install USB stick)
)

// Usable reports whether the disk may be offered for a new pool or vdev.
func (u UsageState) Usable() bool { return u == UsageFree || u == UsageHasData }

// Disk is one physical (or virtual) block device.
type Disk struct {
	Name          string      `json:"name"`          // sda, nvme0n1
	Path          string      `json:"path"`          // /dev/sda
	ByID          string      `json:"byId"`          // stable path used for pools
	Model         string      `json:"model"`         // drive model
	Serial        string      `json:"serial"`        // serial number
	WWN           string      `json:"wwn"`           // world-wide name, if any
	Transport     string      `json:"transport"`     // sata, sas, nvme, usb, virtio...
	Kind          DiskKind    `json:"kind"`          // hdd, ssd or nvme
	SizeBytes     uint64      `json:"sizeBytes"`     // capacity
	PhysSector    uint64      `json:"physSector"`    // physical sector size in bytes
	Removable     bool        `json:"removable"`     // hot-pluggable (USB and similar)
	Usage         UsageState  `json:"usage"`         // see UsageState
	Pool          string      `json:"pool"`          // pool name when Usage is pool or boot
	UsageDetail   string      `json:"usageDetail"`   // human explanation
	Partitions    []Partition `json:"partitions"`    // existing partitions
	PowerLossProt *bool       `json:"powerLossProt"` // from SMART when known; nil = unknown
}

// Partition is a partition on a disk.
type Partition struct {
	Name        string   `json:"name"`
	SizeBytes   uint64   `json:"sizeBytes"`
	FSType      string   `json:"fsType"`
	Label       string   `json:"label"`
	Mountpoints []string `json:"mountpoints"`
}

// Boot pool names created by the HardyOS installer.
var bootPools = map[string]bool{"rpool": true, "bpool": true, "hardyos-boot": true}

// systemMounts mark a disk as holding the running OS.
var systemMounts = map[string]bool{"/": true, "/boot": true, "/boot/efi": true, "[SWAP]": true}

// lsblkColumns are requested from lsblk; keep in sync with lsblkDev.
const lsblkColumns = "NAME,PATH,SIZE,TYPE,ROTA,MODEL,SERIAL,WWN,TRAN,FSTYPE,LABEL,MOUNTPOINTS,HOTPLUG,PHY-SEC"

type lsblkOutput struct {
	BlockDevices []lsblkDev `json:"blockdevices"`
}

type lsblkDev struct {
	Name        string     `json:"name"`
	Path        string     `json:"path"`
	Size        flexUint   `json:"size"`
	Type        string     `json:"type"`
	Rota        flexBool   `json:"rota"`
	Model       *string    `json:"model"`
	Serial      *string    `json:"serial"`
	WWN         *string    `json:"wwn"`
	Tran        *string    `json:"tran"`
	FSType      *string    `json:"fstype"`
	Label       *string    `json:"label"`
	Mountpoints []*string  `json:"mountpoints"`
	Hotplug     flexBool   `json:"hotplug"`
	PhySec      flexUint   `json:"phy-sec"`
	Children    []lsblkDev `json:"children"`
	Mountpoint  *string    `json:"mountpoint"` // older util-linux
}

// ListDisks runs lsblk and resolves stable /dev/disk/by-id paths from root
// (a filesystem rooted at "/", e.g. os.DirFS("/")).
func ListDisks(ctx context.Context, r sysexec.Runner, root fs.FS) ([]Disk, error) {
	out, err := sysexec.Output(ctx, r, "lsblk", "-J", "-b", "-o", lsblkColumns)
	if err != nil {
		return nil, err
	}
	return parseDisks(out, byIDMap(root))
}

func parseDisks(lsblkJSON []byte, byID map[string][]string) ([]Disk, error) {
	var o lsblkOutput
	if err := json.Unmarshal(lsblkJSON, &o); err != nil {
		return nil, fmt.Errorf("parse lsblk: %w", err)
	}
	var disks []Disk
	for _, d := range o.BlockDevices {
		if d.Type != "disk" || skipDisk(d.Name) {
			continue
		}
		disk := Disk{
			Name:       d.Name,
			Path:       orDefault(d.Path, "/dev/"+d.Name),
			Model:      strings.TrimSpace(str(d.Model)),
			Serial:     strings.TrimSpace(str(d.Serial)),
			WWN:        str(d.WWN),
			Transport:  str(d.Tran),
			SizeBytes:  uint64(d.Size),
			PhysSector: uint64(d.PhySec),
			Removable:  bool(d.Hotplug),
			Partitions: []Partition{},
		}
		disk.Kind = classify(d)
		disk.ByID = pickByID(byID[d.Name], disk.Path)
		for _, c := range d.Children {
			disk.Partitions = append(disk.Partitions, Partition{
				Name: c.Name, SizeBytes: uint64(c.Size), FSType: str(c.FSType),
				Label: str(c.Label), Mountpoints: mounts(c),
			})
		}
		disk.Usage, disk.Pool, disk.UsageDetail = usage(d)
		disks = append(disks, disk)
	}
	sort.Slice(disks, func(i, j int) bool { return naturalLess(disks[i].Name, disks[j].Name) })
	return disks, nil
}

func skipDisk(name string) bool {
	for _, p := range []string{"loop", "ram", "zram", "zd", "sr", "fd", "md", "dm-", "nbd"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func classify(d lsblkDev) DiskKind {
	if strings.HasPrefix(d.Name, "nvme") || str(d.Tran) == "nvme" {
		return KindNVMe
	}
	if bool(d.Rota) {
		return KindHDD
	}
	return KindSSD
}

func usage(d lsblkDev) (UsageState, string, string) {
	all := append([]lsblkDev{d}, d.Children...)
	for _, p := range all {
		for _, m := range mounts(p) {
			if systemMounts[m] {
				return UsageBoot, "", fmt.Sprintf("holds the running system (%s on %s)", m, p.Name)
			}
		}
	}
	for _, p := range all {
		if str(p.FSType) == "zfs_member" {
			pool := str(p.Label)
			if bootPools[pool] {
				return UsageBoot, pool, "boot pool " + pool
			}
			return UsagePool, pool, "member of pool " + pool
		}
	}
	for _, p := range all {
		if m := mounts(p); len(m) > 0 {
			return UsageMounted, "", fmt.Sprintf("%s is mounted at %s", p.Name, m[0])
		}
	}
	if len(d.Children) > 0 || str(d.FSType) != "" {
		var what []string
		for _, p := range all {
			if fs := str(p.FSType); fs != "" {
				what = append(what, fs)
			}
		}
		detail := fmt.Sprintf("%d partition(s)", len(d.Children))
		if len(what) > 0 {
			detail += ": " + strings.Join(what, ", ")
		}
		return UsageHasData, "", detail
	}
	return UsageFree, "", "blank"
}

func mounts(d lsblkDev) []string {
	var out []string
	for _, m := range d.Mountpoints {
		if m != nil && *m != "" {
			out = append(out, *m)
		}
	}
	if len(out) == 0 && d.Mountpoint != nil && *d.Mountpoint != "" {
		out = append(out, *d.Mountpoint)
	}
	return out
}

// byIDMap maps kernel names (sda) to their /dev/disk/by-id link names.
func byIDMap(root fs.FS) map[string][]string {
	out := map[string][]string{}
	if root == nil {
		return out
	}
	entries, err := fs.ReadDir(root, "dev/disk/by-id")
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		if strings.Contains(name, "-part") {
			continue
		}
		target, err := fs.ReadLink(root, path.Join("dev/disk/by-id", name))
		if err != nil {
			continue
		}
		kernel := path.Base(target)
		out[kernel] = append(out[kernel], name)
	}
	return out
}

// pickByID prefers the most stable identifier: WWN, then NVMe model+serial,
// then ATA/SCSI, then anything else; falls back to the kernel path.
func pickByID(names []string, fallback string) string {
	rank := func(n string) int {
		switch {
		case strings.HasPrefix(n, "wwn-"):
			return 0
		case strings.HasPrefix(n, "nvme-") && !strings.HasPrefix(n, "nvme-eui.") && !strings.HasPrefix(n, "nvme-nvme."):
			return 1
		case strings.HasPrefix(n, "ata-"), strings.HasPrefix(n, "scsi-3"):
			return 2
		case strings.HasPrefix(n, "nvme-eui."):
			return 3
		default:
			return 4
		}
	}
	if len(names) == 0 {
		return fallback
	}
	best := names[0]
	for _, n := range names[1:] {
		if rank(n) < rank(best) || (rank(n) == rank(best) && n < best) {
			best = n
		}
	}
	return "/dev/disk/by-id/" + best
}

// naturalLess orders disk names the way people expect: sda < sdb < sdz < sdaa,
// and nvme2n1 < nvme10n1.
func naturalLess(a, b string) bool {
	if strings.HasPrefix(a, "sd") && strings.HasPrefix(b, "sd") && len(a) != len(b) {
		return len(a) < len(b)
	}
	for a != "" && b != "" {
		ad, bd := isDigit(a[0]), isDigit(b[0])
		if ad && bd {
			na, ra := leadingNumber(a)
			nb, rb := leadingNumber(b)
			if na != nb {
				return na < nb
			}
			a, b = ra, rb
			continue
		}
		if a[0] != b[0] {
			return a[0] < b[0]
		}
		a, b = a[1:], b[1:]
	}
	return len(a) < len(b)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func leadingNumber(s string) (uint64, string) {
	var n uint64
	i := 0
	for i < len(s) && isDigit(s[i]) {
		n = n*10 + uint64(s[i]-'0')
		i++
	}
	return n, s[i:]
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// flexBool accepts true/false, "1"/"0" and 1/0 (lsblk changed formats over versions).
type flexBool bool

func (b *flexBool) UnmarshalJSON(data []byte) error {
	switch strings.Trim(string(data), `"`) {
	case "true", "1":
		*b = true
	default:
		*b = false
	}
	return nil
}

// flexUint accepts numbers and numeric strings.
type flexUint uint64

func (u *flexUint) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "null" || s == "" {
		*u = 0
		return nil
	}
	var n uint64
	if _, err := fmt.Sscan(s, &n); err != nil {
		return fmt.Errorf("not a number: %s", data)
	}
	*u = flexUint(n)
	return nil
}
