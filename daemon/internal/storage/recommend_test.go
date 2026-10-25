package storage

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

const tb = 12_000_138_625_024

func mk(kind hw.DiskKind, n int, size uint64, prefix string) []hw.Disk {
	out := make([]hw.Disk, n)
	for i := range out {
		name := fmt.Sprintf("%s%02d", prefix, i)
		out[i] = hw.Disk{Name: name, ByID: "/dev/disk/by-id/" + name, Kind: kind, SizeBytes: size, Usage: hw.UsageFree}
	}
	return out
}

func TestRecommendLayoutsByDiskCount(t *testing.T) {
	cases := []struct {
		n        int
		layout   zfs.VdevType
		vdevs    int
		survives int
		spares   int
	}{
		{1, zfs.Stripe, 1, 0, 0},
		{2, zfs.Mirror, 1, 1, 0},
		{3, zfs.Mirror, 1, 2, 0},
		{4, zfs.RAIDZ1, 1, 1, 0},
		{6, zfs.RAIDZ2, 1, 2, 0},
		{11, zfs.RAIDZ2, 1, 2, 0},
		{12, zfs.RAIDZ2, 2, 2, 0},
		{20, zfs.RAIDZ2, 2, 2, 0},
		{13, zfs.RAIDZ2, 2, 2, 1},
	}
	for _, c := range cases {
		rec, err := Recommend("tank", mk(hw.KindHDD, c.n, tb, "hdd"), 16*hw.GiB)
		if err != nil {
			t.Fatalf("%d disks: %v", c.n, err)
		}
		got := rec.Spec.Data
		if len(got) != c.vdevs || got[0].Type != c.layout || rec.Survives != c.survives || len(rec.Spec.Spares) != c.spares {
			t.Errorf("%d disks: %d×%s survives %d spares %d; want %d×%s survives %d spares %d",
				c.n, len(got), got[0].Type, rec.Survives, len(rec.Spec.Spares), c.vdevs, c.layout, c.survives, c.spares)
		}
	}
}

func TestRecommendSixDrivesWithCacheRoles(t *testing.T) {
	disks := mk(hw.KindHDD, 6, tb, "hdd")
	special := mk(hw.KindNVMe, 2, 1_000_000_000_000, "nvme")
	big := mk(hw.KindNVMe, 1, 2_000_000_000_000, "l2arc")
	yes := true
	plp := mk(hw.KindSSD, 2, 400_000_000_000, "plp")
	for i := range plp {
		plp[i].PowerLossProt = &yes
	}
	boot := mk(hw.KindNVMe, 1, 256_000_000_000, "boot")
	boot[0].Usage = hw.UsageBoot
	all := append(append(append(append(disks, special...), big...), plp...), boot...)

	rec, err := Recommend("tank", all, 128*hw.GiB)
	if err != nil {
		t.Fatal(err)
	}
	s := rec.Spec
	if s.Data[0].Type != zfs.RAIDZ2 || len(s.Data[0].Disks) != 6 {
		t.Fatalf("data = %+v", s.Data)
	}
	if s.Special == nil || !strings.Contains(strings.Join(s.Special.Disks, ","), "nvme") {
		t.Errorf("special = %+v", s.Special)
	}
	if s.Log == nil || !strings.Contains(s.Log.Disks[0], "plp") {
		t.Errorf("log = %+v", s.Log)
	}
	if len(s.Cache) != 1 || !strings.Contains(s.Cache[0], "l2arc") {
		t.Errorf("cache = %v", s.Cache)
	}
	for _, d := range s.Disks() {
		if strings.Contains(d, "boot") {
			t.Fatal("boot disk used")
		}
	}
	if rec.UsableBytes != 4*tb {
		t.Errorf("usable = %d, want 4 disks' worth", rec.UsableBytes)
	}
	if len(rec.Warnings) == 0 {
		t.Error("expected the special-vdev parity warning")
	}
}

func TestRecommendSkipsSLOGWithoutPLPAndL2ARCWithLowRAM(t *testing.T) {
	all := append(mk(hw.KindHDD, 4, tb, "hdd"), mk(hw.KindSSD, 4, 500_000_000_000, "ssd")...)
	rec, err := Recommend("tank", all, 16*hw.GiB)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Spec.Special == nil || rec.Spec.Log != nil || len(rec.Spec.Cache) != 0 {
		t.Errorf("spec = %+v", rec.Spec)
	}
	if len(rec.Unused) != 2 {
		t.Errorf("unused = %v", rec.Unused)
	}
}

func TestRecommendAllFlashAndMixedSizes(t *testing.T) {
	rec, err := Recommend("fast", mk(hw.KindNVMe, 2, 2_000_000_000_000, "nv"), 16*hw.GiB)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Spec.Data[0].Type != zfs.Mirror || rec.Spec.Special != nil {
		t.Errorf("all-flash spec = %+v", rec.Spec)
	}

	mixed := append(mk(hw.KindHDD, 4, tb, "big"), mk(hw.KindHDD, 1, 4_000_000_000_000, "small")...)
	rec, err = Recommend("tank", mixed, 16*hw.GiB)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Spec.Data[0].Disks) != 4 || len(rec.Unused) != 1 || !strings.Contains(rec.Unused[0], "small") {
		t.Errorf("mixed sizes: data %v unused %v", rec.Spec.Data, rec.Unused)
	}
}

func TestRecommendNoDisks(t *testing.T) {
	inUse := mk(hw.KindHDD, 2, tb, "x")
	for i := range inUse {
		inUse[i].Usage = hw.UsagePool
	}
	if _, err := Recommend("tank", inUse, 0); err == nil {
		t.Fatal("expected an error with no usable disks")
	}
}
