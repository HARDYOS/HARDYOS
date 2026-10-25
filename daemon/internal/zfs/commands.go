package zfs

import (
	"fmt"
	"sort"
)

// VdevType is a redundancy layout for a group of disks.
type VdevType string

const (
	Stripe VdevType = "stripe" // single disk, no redundancy
	Mirror VdevType = "mirror"
	RAIDZ1 VdevType = "raidz1"
	RAIDZ2 VdevType = "raidz2"
	RAIDZ3 VdevType = "raidz3"
)

// MinDisks is the smallest sensible disk count per layout.
func (t VdevType) MinDisks() int {
	switch t {
	case Stripe:
		return 1
	case Mirror:
		return 2
	case RAIDZ1:
		return 3
	case RAIDZ2:
		return 4
	case RAIDZ3:
		return 5
	}
	return 0
}

// Parity is how many disks the vdev can lose.
func (t VdevType) Parity(disks int) int {
	switch t {
	case Mirror:
		return disks - 1
	case RAIDZ1:
		return 1
	case RAIDZ2:
		return 2
	case RAIDZ3:
		return 3
	}
	return 0
}

// VdevSpec is one group of disks with a layout.
type VdevSpec struct {
	Type  VdevType `json:"type"`
	Disks []string `json:"disks"` // /dev/disk/by-id paths
}

func (v VdevSpec) validate(role string) error {
	if v.Type.MinDisks() == 0 {
		return fmt.Errorf("%s: unknown layout %q", role, v.Type)
	}
	if len(v.Disks) < v.Type.MinDisks() {
		return fmt.Errorf("%s: %s needs at least %d disks, got %d", role, v.Type, v.Type.MinDisks(), len(v.Disks))
	}
	if v.Type == Stripe && len(v.Disks) != 1 {
		return fmt.Errorf("%s: a stripe vdev is one disk; use several stripe vdevs for more", role)
	}
	if len(v.Disks) > 24 {
		return fmt.Errorf("%s: more than 24 disks in one vdev; split into several vdevs", role)
	}
	for _, d := range v.Disks {
		if err := ValidDiskPath(d); err != nil {
			return fmt.Errorf("%s: %w", role, err)
		}
	}
	return nil
}

func (v VdevSpec) args() []string {
	if v.Type == Stripe {
		return append([]string{}, v.Disks...)
	}
	return append([]string{string(v.Type)}, v.Disks...)
}

// PoolSpec describes a new pool or a set of vdevs to add.
type PoolSpec struct {
	Name    string     `json:"name"`
	Data    []VdevSpec `json:"data"`
	Special *VdevSpec  `json:"special,omitempty"` // metadata + small blocks; must be mirrored
	Log     *VdevSpec  `json:"log,omitempty"`     // SLOG
	Cache   []string   `json:"cache,omitempty"`   // L2ARC disks
	Spares  []string   `json:"spares,omitempty"`  // hot spares
	// Options (create only)
	Encrypt          bool   `json:"encrypt"`
	SpecialSmallBlks string `json:"specialSmallBlocks,omitempty"` // default 32K when Special is set
}

// Disks returns every disk the spec uses.
func (p PoolSpec) Disks() []string {
	var out []string
	for _, v := range p.Data {
		out = append(out, v.Disks...)
	}
	if p.Special != nil {
		out = append(out, p.Special.Disks...)
	}
	if p.Log != nil {
		out = append(out, p.Log.Disks...)
	}
	out = append(out, p.Cache...)
	out = append(out, p.Spares...)
	return out
}

// Validate checks the spec. forCreate requires at least one data vdev and a valid name.
func (p PoolSpec) Validate(forCreate bool) error {
	if forCreate {
		if err := ValidPoolName(p.Name); err != nil {
			return err
		}
		if len(p.Data) == 0 {
			return fmt.Errorf("a pool needs at least one data vdev")
		}
	}
	types := map[VdevType]bool{}
	for i, v := range p.Data {
		if err := v.validate(fmt.Sprintf("data vdev %d", i+1)); err != nil {
			return err
		}
		types[v.Type] = true
	}
	if len(types) > 1 {
		return fmt.Errorf("all data vdevs should use the same layout; mixing layouts makes the pool only as safe as its weakest vdev")
	}
	if p.Special != nil {
		if err := p.Special.validate("special vdev"); err != nil {
			return err
		}
		if p.Special.Type != Mirror {
			return fmt.Errorf("the special vdev must be a mirror: losing it loses the whole pool")
		}
	}
	if p.Log != nil {
		if err := p.Log.validate("log vdev"); err != nil {
			return err
		}
		if p.Log.Type != Mirror && p.Log.Type != Stripe {
			return fmt.Errorf("a log vdev must be a mirror or a single disk")
		}
	}
	for _, d := range append(append([]string{}, p.Cache...), p.Spares...) {
		if err := ValidDiskPath(d); err != nil {
			return err
		}
	}
	if p.SpecialSmallBlks != "" {
		if err := ValidateProperty("special_small_blocks", p.SpecialSmallBlks); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, d := range p.Disks() {
		if seen[d] {
			return fmt.Errorf("disk %s is used more than once", d)
		}
		seen[d] = true
	}
	if len(seen) == 0 {
		return fmt.Errorf("no disks given")
	}
	return nil
}

// Warnings returns advice about a valid spec that the user should see before
// confirming (it doesn't block creation).
func (p PoolSpec) Warnings() []string {
	w := []string{}
	if len(p.Data) == 1 && p.Data[0].Type == Stripe {
		w = append(w, "A single disk has no redundancy: if it fails, everything on the pool is lost.")
	}
	if p.Special != nil && len(p.Data) > 0 {
		need := p.Data[0].Type.Parity(len(p.Data[0].Disks))
		if have := p.Special.Type.Parity(len(p.Special.Disks)); have < need {
			w = append(w, fmt.Sprintf("The special vdev survives %d disk failure(s) but the data disks survive %d. "+
				"Losing the special vdev loses the whole pool; a %d-way mirror would match.", have, need, need+1))
		}
	}
	if p.Log != nil && p.Log.Type == Stripe {
		w = append(w, "A single log disk is fine for performance, but if it fails during a power cut, the last few seconds of synchronous writes are lost.")
	}
	return w
}

// vdevArgs renders the device part of create/add commands.
func (p PoolSpec) vdevArgs() []string {
	var args []string
	for _, v := range p.Data {
		args = append(args, v.args()...)
	}
	if p.Special != nil {
		args = append(append(args, "special"), p.Special.args()...)
	}
	if p.Log != nil {
		args = append(append(args, "log"), p.Log.args()...)
	}
	if len(p.Cache) > 0 {
		args = append(append(args, "cache"), p.Cache...)
	}
	if len(p.Spares) > 0 {
		args = append(append(args, "spare"), p.Spares...)
	}
	return args
}

// MountRoot is where data pools are mounted.
const MountRoot = "/mnt"

// KeyDir holds encryption key files for pools that unlock at boot.
const KeyDir = "/var/lib/hardyos/keys"

// KeyFile returns the key file path for a pool.
func KeyFile(pool string) string { return KeyDir + "/" + pool + ".key" }

// CreateArgs returns the zpool create arguments. Call Validate(true) first.
func (p PoolSpec) CreateArgs() []string {
	props := map[string]string{
		"compression": "lz4", "atime": "off", "xattr": "sa", "acltype": "posixacl",
		"dnodesize": "auto", "normalization": "formD",
	}
	if p.Special != nil {
		v := p.SpecialSmallBlks
		if v == "" {
			v = "32K"
		}
		props["special_small_blocks"] = v
	}
	if p.Encrypt {
		props["encryption"] = "aes-256-gcm"
		props["keyformat"] = "raw"
		props["keylocation"] = "file://" + KeyFile(p.Name)
	}
	args := []string{"create", "-f", "-o", "ashift=12", "-o", "autotrim=on", "-m", MountRoot + "/" + p.Name}
	keys := make([]string, 0, len(props))
	for k := range props {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "-O", k+"="+props[k])
	}
	args = append(args, p.Name)
	return append(args, p.vdevArgs()...)
}

// AddArgs returns zpool add arguments for adding vdevs to pool.
// No -f: zpool's own replication-mismatch check stays on.
func (p PoolSpec) AddArgs(pool string) []string {
	return append([]string{"add", pool}, p.vdevArgs()...)
}
