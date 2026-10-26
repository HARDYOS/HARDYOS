// Package install puts HardyOS onto boot disks from the live ISO. It runs
// inside hardyd-priv (root) and only exists on the live installer: the
// operations are not registered on an installed system.
//
// Layout of every boot disk (GPT):
//
//	1  BIOS boot   1 MiB    GRUB core image for legacy BIOS boot
//	2  EFI system  1 GiB    FAT32: GRUB, kernels and initramfs per boot environment
//	3  ZFS         rest     member of rpool (mirrored across disks)
//
// rpool datasets:
//
//	rpool/ROOT/hardyos-<version>  one boot environment per installed version (/)
//	rpool/hardyos                 /var/lib/hardyos, shared by all boot environments
package install

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// Pool is the boot pool's name.
const Pool = "rpool"

// MaxBootDisks bounds the boot mirror width.
const MaxBootDisks = 4

// MinDiskBytes is the smallest usable boot disk.
const MinDiskBytes = 16 << 30

// Plan is what the person chose in the installer.
type Plan struct {
	// Disks are whole disks; two or more become a mirror.
	Disks    []string `json:"disks"`
	Hostname string   `json:"hostname"`
	Timezone string   `json:"timezone"`
	Network  Network  `json:"network"`
}

// Network is the installed system's network setup.
type Network struct {
	Mode string `json:"mode"` // dhcp or static
	// Static only:
	Interface string   `json:"interface,omitempty"`
	Address   string   `json:"address,omitempty"` // CIDR, 192.168.1.20/24
	Gateway   string   `json:"gateway,omitempty"`
	DNS       []string `json:"dns,omitempty"`
}

// Seed is the first administrator, created by hardyd on first boot. The
// password arrives already hashed; the plain password never reaches root.
type Seed struct {
	Username     string `json:"username"`
	DisplayName  string `json:"displayName"`
	PasswordHash string `json:"passwordHash"`
}

// SeedFile is where the seed is written on the installed system.
const SeedFile = "/var/lib/hardyos/install-seed.json"

var (
	hostnameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	tzRE       = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$`)
	ifaceRE    = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
	// Kernel paths are accepted only for disks without a by-id link (some
	// virtual disks); the stable by-id path is preferred everywhere else.
	// Loop devices are for the integration test; the disk scan never lists them.
	kernelDiskRE = regexp.MustCompile(`^/dev/(sd[a-z]{1,3}|vd[a-z]{1,3}|xvd[a-z]{1,3}|nvme[0-9]{1,3}n[0-9]{1,3}|mmcblk[0-9]{1,3}|loop[0-9]{1,3})$`)
	hashRE       = regexp.MustCompile(`^\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$`)
)

// ValidDisk accepts a whole-disk by-id path, or a plain kernel path for disks
// that have no by-id link.
func ValidDisk(p string) error {
	if zfs.ValidDiskPath(p) == nil || kernelDiskRE.MatchString(p) {
		return nil
	}
	return fmt.Errorf("disk %q: expected a whole disk", p)
}

// Partition returns the path of partition n on a disk path.
func Partition(disk string, n int) string {
	if strings.HasPrefix(disk, "/dev/disk/by-id/") {
		return fmt.Sprintf("%s-part%d", disk, n)
	}
	if last := disk[len(disk)-1]; last >= '0' && last <= '9' {
		return fmt.Sprintf("%sp%d", disk, n) // nvme0n1p3, mmcblk0p3
	}
	return fmt.Sprintf("%s%d", disk, n)
}

// Validate checks everything that doesn't need the hardware.
func (p *Plan) Validate() error {
	if len(p.Disks) == 0 {
		return errors.New("choose at least one boot disk")
	}
	if len(p.Disks) > MaxBootDisks {
		return fmt.Errorf("at most %d boot disks", MaxBootDisks)
	}
	seen := map[string]bool{}
	for _, d := range p.Disks {
		if err := ValidDisk(d); err != nil {
			return err
		}
		if seen[d] {
			return fmt.Errorf("disk %s is listed twice", d)
		}
		seen[d] = true
	}
	if !hostnameRE.MatchString(p.Hostname) {
		return errors.New("hostname: 1-63 lowercase letters, digits and '-', not starting or ending with '-'")
	}
	if !tzRE.MatchString(p.Timezone) || strings.Contains(p.Timezone, "..") {
		return fmt.Errorf("timezone %q is not valid", p.Timezone)
	}
	return p.Network.Validate()
}

// Validate checks the network settings.
func (n *Network) Validate() error {
	switch n.Mode {
	case "dhcp":
		return nil
	case "static":
	default:
		return errors.New("network mode must be dhcp or static")
	}
	if !ifaceRE.MatchString(n.Interface) {
		return errors.New("choose the network interface for the static address")
	}
	prefix, err := netip.ParsePrefix(n.Address)
	if err != nil || !prefix.Addr().Is4() && !prefix.Addr().Is6() {
		return fmt.Errorf("address %q: use CIDR form, like 192.168.1.20/24", n.Address)
	}
	if prefix.Bits() == prefix.Addr().BitLen() || prefix.Addr() == prefix.Masked().Addr() {
		return fmt.Errorf("address %q is a network address, not a host address", n.Address)
	}
	if n.Gateway != "" {
		gw, err := netip.ParseAddr(n.Gateway)
		if err != nil {
			return fmt.Errorf("gateway %q is not an IP address", n.Gateway)
		}
		if !prefix.Masked().Contains(gw) {
			return fmt.Errorf("gateway %s is outside %s", n.Gateway, prefix.Masked())
		}
	}
	if len(n.DNS) > 3 {
		return errors.New("at most 3 DNS servers")
	}
	for _, d := range n.DNS {
		if _, err := netip.ParseAddr(d); err != nil {
			return fmt.Errorf("DNS server %q is not an IP address", d)
		}
	}
	return nil
}

// Validate checks the administrator seed.
func (s *Seed) Validate() error {
	if !regexp.MustCompile(`^[a-z][a-z0-9._-]{1,31}$`).MatchString(s.Username) {
		return errors.New("invalid administrator username")
	}
	if !hashRE.MatchString(s.PasswordHash) {
		return errors.New("invalid password hash")
	}
	if len(s.DisplayName) > 100 || strings.ContainsAny(s.DisplayName, "\n\r\x00") {
		return errors.New("invalid display name")
	}
	return nil
}
