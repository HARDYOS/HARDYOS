// Package storage is hardyd's storage service: pool layout recommendations,
// pool and dataset management through the root helper, schedules for
// snapshots, scrubs and SMART checks.
package storage

import (
	"fmt"
	"sort"

	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// Recommendation is a suggested pool layout for the detected disks.
type Recommendation struct {
	Spec        zfs.PoolSpec `json:"spec"`
	UsableBytes uint64       `json:"usableBytes"` // rough estimate before ZFS overhead
	Survives    int          `json:"survives"`    // data disks that can fail per vdev
	Explanation []string     `json:"explanation"`
	Warnings    []string     `json:"warnings"`
	Unused      []string     `json:"unused"` // usable disks the recommendation leaves out
}

// Recommend proposes a pool named name from the usable disks.
func Recommend(name string, disks []hw.Disk, ramBytes uint64) (*Recommendation, error) {
	var hdd, flash []hw.Disk
	for _, d := range disks {
		if !d.Usage.Usable() || d.Removable || d.SizeBytes == 0 {
			continue
		}
		if d.Kind == hw.KindHDD {
			hdd = append(hdd, d)
		} else {
			flash = append(flash, d)
		}
	}
	rec := &Recommendation{Spec: zfs.PoolSpec{Name: name}, Explanation: []string{}, Warnings: []string{}, Unused: []string{}}

	// Data disks: HDDs if there are any, otherwise an all-flash pool.
	pool := hdd
	allFlash := false
	if len(pool) == 0 {
		pool, flash, allFlash = flash, nil, true
	}
	if len(pool) == 0 {
		return nil, fmt.Errorf("no unused disks found")
	}
	group, rest := largestSameSizeGroup(pool)
	for _, d := range rest {
		rec.Unused = append(rec.Unused, d.ByID)
	}
	if len(rest) > 0 {
		rec.Warnings = append(rec.Warnings, fmt.Sprintf("%d disk(s) of a different size were left out; a vdev is limited by its smallest disk.", len(rest)))
	}

	vdevs, survives, spares := layoutFor(group)
	rec.Spec.Data = vdevs
	rec.Survives = survives
	for _, s := range spares {
		rec.Spec.Spares = append(rec.Spec.Spares, s.ByID)
	}
	size := minSize(group)
	for _, v := range vdevs {
		rec.UsableBytes += dataDisks(v) * size
	}
	rec.Explanation = append(rec.Explanation, describe(vdevs, size, allFlash))
	if len(spares) > 0 {
		rec.Explanation = append(rec.Explanation, fmt.Sprintf("%d leftover disk(s) become hot spares that replace a failed disk automatically.", len(spares)))
	}

	// Cache roles from spare flash: special first (biggest win), then log (only with
	// power-loss protection), then L2ARC (only with enough RAM).
	sort.SliceStable(flash, func(i, j int) bool {
		if (flash[i].Kind == hw.KindNVMe) != (flash[j].Kind == hw.KindNVMe) {
			return flash[i].Kind == hw.KindNVMe
		}
		return flash[i].SizeBytes < flash[j].SizeBytes
	})
	if len(flash) >= 2 {
		a, b := flash[0], flash[1]
		rec.Spec.Special = &zfs.VdevSpec{Type: zfs.Mirror, Disks: []string{a.ByID, b.ByID}}
		flash = flash[2:]
		rec.Explanation = append(rec.Explanation, "Two SSDs form a mirrored special vdev for metadata and small files, which makes browsing folders and photo thumbnails much faster.")
	}
	var plp []hw.Disk
	var other []hw.Disk
	for _, d := range flash {
		if d.PowerLossProt != nil && *d.PowerLossProt {
			plp = append(plp, d)
		} else {
			other = append(other, d)
		}
	}
	if len(plp) >= 2 {
		rec.Spec.Log = &zfs.VdevSpec{Type: zfs.Mirror, Disks: []string{plp[0].ByID, plp[1].ByID}}
		other = append(other, plp[2:]...)
		rec.Explanation = append(rec.Explanation, "Two SSDs with power-loss protection form a mirrored log (SLOG) to speed up synchronous writes from NFS and VMs.")
	} else {
		other = append(other, plp...)
	}
	if len(other) >= 1 && ramBytes >= 32*hw.GiB {
		sort.Slice(other, func(i, j int) bool { return other[i].SizeBytes > other[j].SizeBytes })
		rec.Spec.Cache = []string{other[0].ByID}
		other = other[1:]
		rec.Explanation = append(rec.Explanation, "One SSD becomes an L2ARC read cache. It's safe to lose: the pool keeps working without it.")
	}
	for _, d := range other {
		rec.Unused = append(rec.Unused, d.ByID)
	}

	rec.Warnings = append(rec.Warnings, rec.Spec.Warnings()...)
	if err := rec.Spec.Validate(true); err != nil {
		return nil, fmt.Errorf("internal: recommended layout is invalid: %w", err)
	}
	return rec, nil
}

// layoutFor picks vdevs for n same-size disks following the HardyOS table:
// 1 stripe, 2-3 mirror, 4-5 RAIDZ1, 6-11 RAIDZ2, 12+ several RAIDZ2 vdevs.
func layoutFor(disks []hw.Disk) (vdevs []zfs.VdevSpec, survives int, spares []hw.Disk) {
	paths := make([]string, len(disks))
	for i, d := range disks {
		paths[i] = d.ByID
	}
	n := len(paths)
	switch {
	case n == 1:
		return []zfs.VdevSpec{{Type: zfs.Stripe, Disks: paths}}, 0, nil
	case n <= 3:
		return []zfs.VdevSpec{{Type: zfs.Mirror, Disks: paths}}, n - 1, nil
	case n <= 5:
		return []zfs.VdevSpec{{Type: zfs.RAIDZ1, Disks: paths}}, 1, nil
	case n <= 11:
		return []zfs.VdevSpec{{Type: zfs.RAIDZ2, Disks: paths}}, 2, nil
	}
	// 12+: equal-width RAIDZ2 vdevs of 6-10 disks; leftovers become spares.
	bestW, bestLeft := 6, n%6
	for w := 10; w >= 6; w-- {
		if left := n % w; left < bestLeft || (left == bestLeft && w > bestW) {
			bestW, bestLeft = w, left
		}
	}
	used := n - bestLeft
	for i := 0; i < used; i += bestW {
		vdevs = append(vdevs, zfs.VdevSpec{Type: zfs.RAIDZ2, Disks: paths[i : i+bestW]})
	}
	return vdevs, 2, disks[used:]
}

func describe(vdevs []zfs.VdevSpec, size uint64, allFlash bool) string {
	kind := "hard drives"
	if allFlash {
		kind = "SSDs"
	}
	v := vdevs[0]
	n := len(v.Disks)
	switch v.Type {
	case zfs.Stripe:
		return fmt.Sprintf("One %s with no redundancy.", human(size))
	case zfs.Mirror:
		return fmt.Sprintf("%d %s %s mirrored: every disk holds a full copy, so %d can fail.", n, human(size), kind, n-1)
	}
	if len(vdevs) == 1 {
		return fmt.Sprintf("%d %s %s in %s: any %d can fail without losing data.", n, human(size), kind, upper(v.Type), v.Type.Parity(n))
	}
	return fmt.Sprintf("%d groups of %d %s %s in %s: up to %d disks per group can fail.", len(vdevs), n, human(size), kind, upper(v.Type), v.Type.Parity(n))
}

func upper(t zfs.VdevType) string {
	switch t {
	case zfs.RAIDZ1:
		return "RAIDZ1"
	case zfs.RAIDZ2:
		return "RAIDZ2"
	case zfs.RAIDZ3:
		return "RAIDZ3"
	}
	return string(t)
}

// largestSameSizeGroup returns the biggest set of disks within 1% of each other in size.
func largestSameSizeGroup(disks []hw.Disk) (group, rest []hw.Disk) {
	sorted := append([]hw.Disk{}, disks...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].SizeBytes < sorted[j].SizeBytes })
	bestStart, bestLen := 0, 0
	for i := range sorted {
		j := i
		for j < len(sorted) && float64(sorted[j].SizeBytes) <= float64(sorted[i].SizeBytes)*1.01 {
			j++
		}
		// Prefer more disks, then bigger disks.
		if j-i > bestLen || (j-i == bestLen && sorted[i].SizeBytes > sorted[bestStart].SizeBytes) {
			bestStart, bestLen = i, j-i
		}
	}
	group = append(group, sorted[bestStart:bestStart+bestLen]...)
	rest = append(append(rest, sorted[:bestStart]...), sorted[bestStart+bestLen:]...)
	sort.Slice(group, func(i, j int) bool { return group[i].Name < group[j].Name })
	return group, rest
}

// dataDisks is how many disks' worth of space a vdev stores (a mirror stores one).
func dataDisks(v zfs.VdevSpec) uint64 {
	if v.Type == zfs.Mirror || v.Type == zfs.Stripe {
		return 1
	}
	return uint64(len(v.Disks) - v.Type.Parity(len(v.Disks)))
}

func minSize(disks []hw.Disk) uint64 {
	m := disks[0].SizeBytes
	for _, d := range disks[1:] {
		if d.SizeBytes < m {
			m = d.SizeBytes
		}
	}
	return m
}

func human(b uint64) string {
	const tb, gb = 1e12, 1e9
	if b >= tb {
		v := float64(b) / tb
		if v == float64(int(v)) {
			return fmt.Sprintf("%d TB", int(v))
		}
		return fmt.Sprintf("%.1f TB", v)
	}
	return fmt.Sprintf("%d GB", int(float64(b)/gb+0.5))
}
