// Package zfs builds and parses zpool/zfs commands. It validates every name,
// device path and property value itself, so nothing reaches the command line
// that could be read as an option or select the wrong target.
package zfs

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	poolNameRE   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)
	componentRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	snapLabelRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	byIDRE       = regexp.MustCompile(`^/dev/disk/by-id/[A-Za-z0-9][A-Za-z0-9._:+@-]{0,200}$`)
	partSuffixRE = regexp.MustCompile(`-part[0-9]+$`)
	vdevNameRE   = regexp.MustCompile(`^(mirror|raidz[123]?|draid[123]?)-[0-9]+$`)
	guidRE       = regexp.MustCompile(`^[0-9]{1,20}$`)
)

// reservedPoolNames are refused by zpool or confusing in its output.
var reservedPoolNames = map[string]bool{
	"mirror": true, "raidz": true, "raidz1": true, "raidz2": true, "raidz3": true,
	"draid": true, "spare": true, "log": true, "logs": true, "cache": true,
	"special": true, "dedup": true, "rpool": true, "bpool": true, "hardyos-boot": true,
}

// ValidPoolName reports whether name may be used for a new data pool.
func ValidPoolName(name string) error {
	if !poolNameRE.MatchString(name) || reservedPoolNames[strings.ToLower(name)] {
		return fmt.Errorf("pool name %q: use 1-64 letters, digits, '_', '.', '-', starting with a letter (not a reserved word)", name)
	}
	if regexp.MustCompile(`^c[0-9]`).MatchString(name) {
		return fmt.Errorf("pool name %q: names like c0, c1 are reserved by ZFS", name)
	}
	return nil
}

// ValidDatasetName checks pool/child/grandchild names (no snapshot part).
func ValidDatasetName(name string) error {
	parts := strings.Split(name, "/")
	if !poolNameRE.MatchString(parts[0]) {
		return fmt.Errorf("dataset %q: invalid pool part", name)
	}
	if len(parts) > 32 || len(name) > 250 {
		return fmt.Errorf("dataset %q: name too long", name)
	}
	for _, p := range parts[1:] {
		if !componentRE.MatchString(p) {
			return fmt.Errorf("dataset %q: invalid component %q", name, p)
		}
	}
	return nil
}

// ValidSnapshotName checks dataset@label.
func ValidSnapshotName(name string) error {
	ds, label, ok := strings.Cut(name, "@")
	if !ok {
		return fmt.Errorf("snapshot %q: missing @", name)
	}
	if err := ValidDatasetName(ds); err != nil {
		return err
	}
	if !snapLabelRE.MatchString(label) {
		return fmt.Errorf("snapshot %q: invalid label", name)
	}
	return nil
}

// ValidDiskPath requires a whole disk under /dev/disk/by-id (stable across reboots).
func ValidDiskPath(p string) error {
	if !byIDRE.MatchString(p) || partSuffixRE.MatchString(p) || strings.Contains(p, "..") {
		return fmt.Errorf("disk %q: must be a whole disk under /dev/disk/by-id", p)
	}
	return nil
}

// ValidVdevRef checks a device reference inside an existing pool: a by-id
// path (whole disk or partition), a top-level vdev name like raidz2-0, or a GUID.
func ValidVdevRef(ref string) error {
	switch {
	case guidRE.MatchString(ref), vdevNameRE.MatchString(ref):
		return nil
	case byIDRE.MatchString(ref) && !strings.Contains(ref, ".."):
		return nil
	}
	return fmt.Errorf("device %q: expected a /dev/disk/by-id path, vdev name or GUID", ref)
}

// DiskOf strips a partition suffix: .../wwn-0x5000-part1 -> .../wwn-0x5000.
func DiskOf(p string) string { return partSuffixRE.ReplaceAllString(p, "") }

// Property validation ------------------------------------------------------

var (
	sizeRE      = regexp.MustCompile(`^[0-9]{1,15}(\.[0-9]{1,3})?[KMGTP]?$`)
	userPropRE  = regexp.MustCompile(`^hardyos:[a-z0-9_.-]{1,64}$`)
	mountRE     = regexp.MustCompile(`^/mnt/[A-Za-z0-9][A-Za-z0-9_./:-]{0,250}$`)
	compression = map[string]bool{"off": true, "on": true, "lz4": true, "zstd": true, "gzip": true, "zle": true}
)

func powerOfTwoSize(v string, minK, maxK int) bool {
	if !strings.HasSuffix(v, "K") && !strings.HasSuffix(v, "M") {
		return false
	}
	n, err := strconv.Atoi(v[:len(v)-1])
	if err != nil || n <= 0 {
		return false
	}
	k := n
	if strings.HasSuffix(v, "M") {
		k = n * 1024
	}
	return k >= minK && k <= maxK && k&(k-1) == 0
}

// ValidateProperty checks a dataset property name and value against an allowlist.
func ValidateProperty(name, value string) error {
	bad := func() error { return fmt.Errorf("invalid value %q for %s", value, name) }
	switch name {
	case "compression":
		if compression[value] || regexp.MustCompile(`^(zstd-([1-9]|1[0-9])|gzip-[1-9])$`).MatchString(value) {
			return nil
		}
		return bad()
	case "atime", "readonly", "relatime":
		if value == "on" || value == "off" {
			return nil
		}
		return bad()
	case "sync":
		if value == "standard" || value == "always" || value == "disabled" {
			return nil
		}
		return bad()
	case "recordsize":
		if powerOfTwoSize(value, 4, 16*1024) {
			return nil
		}
		return bad()
	case "special_small_blocks":
		if value == "0" || powerOfTwoSize(value, 4, 1024) {
			return nil
		}
		return bad()
	case "quota", "refquota", "reservation", "refreservation":
		if value == "none" || sizeRE.MatchString(value) {
			return nil
		}
		return bad()
	case "volsize":
		if sizeRE.MatchString(value) && value != "0" {
			return nil
		}
		return bad()
	case "copies":
		if value == "1" || value == "2" || value == "3" {
			return nil
		}
		return bad()
	case "xattr":
		if value == "sa" || value == "on" {
			return nil
		}
		return bad()
	case "mountpoint":
		if value == "none" || (mountRE.MatchString(value) && !strings.Contains(value, "..")) {
			return nil
		}
		return bad()
	}
	if userPropRE.MatchString(name) {
		if len(value) > 256 || strings.ContainsAny(value, "\x00\n\r\t") {
			return bad()
		}
		return nil
	}
	return fmt.Errorf("property %q can't be set through HardyOS", name)
}
