package zfs

import (
	"strings"
	"testing"
)

const statusFixture = `  pool: tank
 state: ONLINE
status: One or more devices is currently being resilvered.  The pool will
	continue to function, possibly in a degraded state.
action: Wait for the resilver to complete.
  scan: resilver in progress since Sat Oct 24 20:00:00 2026
	1319413953331 / 23529000000000 scanned at 524288000/s, 659706976665 / 23529000000000 issued at 262144000/s
	109951162777 resilvered, 2.80% done, 1 days 00:12:00 to go
config:

	NAME                                                   STATE     READ WRITE CKSUM
	tank                                                   ONLINE       0     0     0
	  raidz2-0                                             ONLINE       0     0     0
	    /dev/disk/by-id/wwn-0x5000cca2aaaaaaa1-part1        ONLINE       0     0     0
	    /dev/disk/by-id/wwn-0x5000cca2aaaaaaa2-part1        ONLINE       0     0     0
	    /dev/disk/by-id/wwn-0x5000cca2aaaaaaa3-part1        ONLINE       0     0     2
	    replacing-3                                        ONLINE       0     0     0
	      /dev/disk/by-id/wwn-0x5000cca2aaaaaaa4-part1      OFFLINE      0     0     0
	      /dev/disk/by-id/wwn-0x5000cca2aaaaaaa7-part1      ONLINE       0     0     0  (resilvering)
	    /dev/disk/by-id/wwn-0x5000cca2aaaaaaa5-part1        ONLINE       0     0     0
	    /dev/disk/by-id/wwn-0x5000cca2aaaaaaa6-part1        ONLINE       0     0     0
	special
	  mirror-1                                             ONLINE       0     0     0
	    /dev/disk/by-id/nvme-WD_Red_SN700_1000GB_22AAA-part1  ONLINE       0     0     0
	    /dev/disk/by-id/nvme-WD_Red_SN700_1000GB_22BBB-part1  ONLINE       0     0     0
	logs
	  mirror-2                                             ONLINE       0     0     0
	    /dev/disk/by-id/ata-INTEL_SSDSC2KB480G8_PHYF1-part1  ONLINE       0     0     0
	    /dev/disk/by-id/ata-INTEL_SSDSC2KB480G8_PHYF2-part1  ONLINE       0     0     0
	cache
	  /dev/disk/by-id/nvme-Samsung_SSD_990_2TB_S7KC-part1    ONLINE       0     0     0
	spares
	  /dev/disk/by-id/wwn-0x5000cca2aaaaaaa8-part1          AVAIL

errors: No known data errors
`

func TestParseStatusTree(t *testing.T) {
	st, err := ParseStatus([]byte(statusFixture))
	if err != nil {
		t.Fatal(err)
	}
	if st.Name != "tank" || st.State != "ONLINE" {
		t.Fatalf("header = %q %q", st.Name, st.State)
	}
	if !strings.HasPrefix(st.Status, "One or more devices") || !strings.Contains(st.Status, "degraded state.") {
		t.Errorf("status text = %q", st.Status)
	}
	if st.Scan.Kind != "resilver" || st.Scan.State != "running" || st.Scan.Percent == nil || *st.Scan.Percent != 2.8 {
		t.Errorf("scan = %+v", st.Scan)
	}
	if st.Scan.Remaining != "1 days 00:12:00" {
		t.Errorf("remaining = %q", st.Scan.Remaining)
	}
	if st.Errors != "No known data errors" {
		t.Errorf("errors = %q", st.Errors)
	}

	if len(st.Groups) != 5 {
		names := []string{}
		for _, g := range st.Groups {
			names = append(names, g.Name+"("+string(g.Class)+")")
		}
		t.Fatalf("groups = %v, want raidz2-0, mirror-1, mirror-2, cache disk, spare", names)
	}
	data, special, logv, cache, spare := st.Groups[0], st.Groups[1], st.Groups[2], st.Groups[3], st.Groups[4]
	if data.Type != "raidz2" || data.Class != ClassData || len(data.Children) != 6 {
		t.Errorf("data = %s %s %d children", data.Type, data.Class, len(data.Children))
	}
	if special.Type != "mirror" || special.Class != ClassSpecial || len(special.Children) != 2 {
		t.Errorf("special = %+v", special)
	}
	if logv.Class != ClassLog || cache.Class != ClassCache || cache.Type != "disk" || spare.Class != ClassSpare || spare.State != "AVAIL" {
		t.Errorf("log/cache/spare = %s / %s %s / %s %s", logv.Class, cache.Class, cache.Type, spare.Class, spare.State)
	}
	if c := data.Children[2]; c.Checksum != 2 || c.Disk != "/dev/disk/by-id/wwn-0x5000cca2aaaaaaa3" {
		t.Errorf("disk 3 = %+v", c)
	}
	repl := data.Children[3]
	if repl.Type != "replacing" || len(repl.Children) != 2 || repl.Children[1].Note != "(resilvering)" || repl.Children[0].State != "OFFLINE" {
		t.Errorf("replacing = %+v", repl)
	}
	if len(st.Root.Children) != 1 {
		t.Errorf("root should only hold data vdevs, has %d", len(st.Root.Children))
	}
}

func TestParseStatusFinishedScrubAndExpansion(t *testing.T) {
	out := `  pool: media
 state: ONLINE
  scan: scrub repaired 0 in 05:12:33 with 0 errors on Sun Oct 18 05:36:34 2026
expand: expanded raidz1-0 copied 4740000000 in 00:00:11, on Fri Oct 23 10:00:00 2026
config:

	NAME                                     STATE     READ WRITE CKSUM
	media                                    ONLINE       0     0     0
	  /dev/disk/by-id/ata-ST4000_Z1-part1    ONLINE       0     0     0

errors: No known data errors
`
	st, err := ParseStatus([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if st.Scan.Kind != "scrub" || st.Scan.State != "finished" || *st.Scan.Percent != 100 || *st.Scan.Errors != 0 || st.Scan.FinishedAt == nil {
		t.Errorf("scan = %+v", st.Scan)
	}
	if st.Scan.FinishedAt.Day() != 18 {
		t.Errorf("finished at = %v", st.Scan.FinishedAt)
	}
	if st.Expand == nil || st.Expand.State != "finished" {
		t.Errorf("expand = %+v", st.Expand)
	}
	if len(st.Groups) != 1 || st.Groups[0].Type != "disk" {
		t.Errorf("single-disk pool groups = %+v", st.Groups)
	}
}

func TestParsePoolList(t *testing.T) {
	out := "tank\t47961329713152\t23529000000000\t24432329713152\t3\t49\tONLINE\t1234567890123456789\n" +
		"media\t3985729650688\t100000\t3985729550688\t-\t0\tDEGRADED\t42\n"
	pools, err := ParsePoolList([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(pools) != 2 || pools[0].CapacityPct != 49 || *pools[0].Fragmentation != 3 || pools[1].Fragmentation != nil || pools[1].Health != "DEGRADED" {
		t.Fatalf("pools = %+v", pools)
	}
	if _, err := ParsePoolList([]byte("garbage line\n")); err == nil {
		t.Fatal("expected an error for a malformed line")
	}
}

func TestParseDatasetsAndSnapshots(t *testing.T) {
	ds := "tank\tfilesystem\t100\t200\t50\t/mnt/tank\tlz4\t1.31x\toff\t-\t0\t131072\t-\tyes\n" +
		"tank/vms/win11\tvolume\t1000\t200\t1000\t-\tlz4\t1.00x\taes-256-gcm\tavailable\t-\t-\t68719476736\t-\n"
	list, err := ParseDatasets([]byte(ds))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || !list[0].Mounted || list[1].Type != "volume" || list[1].VolSizeBytes != 68719476736 || list[1].KeyStatus != "available" {
		t.Fatalf("datasets = %+v", list)
	}
	snaps, err := ParseSnapshots([]byte("tank/family@auto-daily-20261024-0000\t4096\t1000000\t1792800000\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 1 || snaps[0].Dataset != "tank/family" || snaps[0].Label != "auto-daily-20261024-0000" || snaps[0].CreatedAt.Unix() != 1792800000 {
		t.Fatalf("snaps = %+v", snaps)
	}
}

func TestParseImportable(t *testing.T) {
	out := `   pool: oldtank
     id: 15094384756372881234
  state: ONLINE
status: The pool was last accessed by another system.
 action: The pool can be imported using its name or numeric identifier and
	the '-f' flag.
 config:

	oldtank      ONLINE
	  mirror-0   ONLINE
	    sda      ONLINE
	    sdb      ONLINE
`
	list := ParseImportable([]byte(out))
	if len(list) != 1 || list[0].Name != "oldtank" || list[0].ID != "15094384756372881234" || !strings.Contains(list[0].Status, "another system") {
		t.Fatalf("importable = %+v", list)
	}
	if got := ParseImportable([]byte("no pools available to import\n")); len(got) != 0 {
		t.Fatalf("expected none, got %+v", got)
	}
}

func TestNames(t *testing.T) {
	for _, ok := range []string{"tank", "Media", "pool_2.backup"} {
		if ValidPoolName(ok) != nil {
			t.Errorf("pool %q rejected", ok)
		}
	}
	for _, bad := range []string{"", "-f", "mirror", "rpool", "c0d0", "1tank", "tank/sub", "tank name"} {
		if ValidPoolName(bad) == nil {
			t.Errorf("pool %q accepted", bad)
		}
	}
	if ValidDatasetName("tank/family/photos") != nil || ValidDatasetName("tank/../etc") == nil || ValidDatasetName("tank/-o") == nil {
		t.Error("dataset name checks wrong")
	}
	if ValidSnapshotName("tank/family@before-update") != nil || ValidSnapshotName("tank/family") == nil || ValidSnapshotName("tank@-r") == nil {
		t.Error("snapshot name checks wrong")
	}
	if ValidDiskPath("/dev/disk/by-id/wwn-0x5000cca2aaaaaaa1") != nil {
		t.Error("whole disk rejected")
	}
	for _, bad := range []string{"/dev/sda", "/dev/disk/by-id/wwn-0x5000-part1", "/dev/disk/by-id/../../sda", "-f", "/dev/disk/by-id/-o"} {
		if ValidDiskPath(bad) == nil {
			t.Errorf("disk %q accepted", bad)
		}
	}
	for _, ok := range []string{"raidz2-0", "mirror-12", "1234567890", "/dev/disk/by-id/wwn-0x5000-part1"} {
		if ValidVdevRef(ok) != nil {
			t.Errorf("vdev ref %q rejected", ok)
		}
	}
}

func TestValidateProperty(t *testing.T) {
	good := [][2]string{{"compression", "zstd-3"}, {"recordsize", "1M"}, {"recordsize", "16K"}, {"quota", "500G"},
		{"quota", "none"}, {"special_small_blocks", "64K"}, {"mountpoint", "/mnt/tank/family"}, {"hardyos:app", "photos"}, {"sync", "disabled"}}
	for _, g := range good {
		if err := ValidateProperty(g[0], g[1]); err != nil {
			t.Errorf("%s=%s rejected: %v", g[0], g[1], err)
		}
	}
	bad := [][2]string{{"compression", "zstd-99"}, {"recordsize", "3K"}, {"recordsize", "32M"}, {"quota", "-1"},
		{"mountpoint", "/etc"}, {"mountpoint", "/mnt/../etc"}, {"canmount", "off"}, {"hardyos:app", "x\ny"}, {"sharenfs", "rw"}}
	for _, b := range bad {
		if ValidateProperty(b[0], b[1]) == nil {
			t.Errorf("%s=%s accepted", b[0], b[1])
		}
	}
}

func disks(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "/dev/disk/by-id/" + prefix + string(rune('a'+i))
	}
	return out
}

func TestPoolSpecCreateArgs(t *testing.T) {
	spec := PoolSpec{
		Name:    "tank",
		Data:    []VdevSpec{{Type: RAIDZ2, Disks: disks("wwn-hdd", 6)}},
		Special: &VdevSpec{Type: Mirror, Disks: disks("nvme-sp", 2)},
		Log:     &VdevSpec{Type: Mirror, Disks: disks("ata-slog", 2)},
		Cache:   disks("nvme-l2", 1),
		Encrypt: true,
	}
	if err := spec.Validate(true); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(spec.CreateArgs(), " ")
	for _, want := range []string{
		"create -f -o ashift=12 -o autotrim=on -m /mnt/tank",
		"-O compression=lz4", "-O encryption=aes-256-gcm", "-O keyformat=raw",
		"-O keylocation=file:///var/lib/hardyos/keys/tank.key", "-O special_small_blocks=32K",
		"tank raidz2 /dev/disk/by-id/wwn-hdda",
		"special mirror /dev/disk/by-id/nvme-spa /dev/disk/by-id/nvme-spb",
		"log mirror /dev/disk/by-id/ata-sloga", "cache /dev/disk/by-id/nvme-l2a",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("create args missing %q\n%s", want, got)
		}
	}
	if w := spec.Warnings(); len(w) != 1 || !strings.Contains(w[0], "special vdev survives 1") {
		t.Errorf("warnings = %v", w)
	}
	add := PoolSpec{Data: []VdevSpec{{Type: RAIDZ2, Disks: disks("wwn-new", 6)}}}
	if err := add.Validate(false); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(add.AddArgs("tank"), " "); !strings.HasPrefix(got, "add tank raidz2 ") || strings.Contains(got, "-f") {
		t.Errorf("add args = %s", got)
	}
}

func TestPoolSpecValidation(t *testing.T) {
	d := disks("wwn-x", 8)
	cases := []struct {
		name string
		spec PoolSpec
	}{
		{"no data", PoolSpec{Name: "tank"}},
		{"too few for raidz2", PoolSpec{Name: "tank", Data: []VdevSpec{{Type: RAIDZ2, Disks: d[:3]}}}},
		{"striped special", PoolSpec{Name: "tank", Data: []VdevSpec{{Type: Mirror, Disks: d[:2]}}, Special: &VdevSpec{Type: Stripe, Disks: d[2:3]}}},
		{"duplicate disk", PoolSpec{Name: "tank", Data: []VdevSpec{{Type: Mirror, Disks: []string{d[0], d[0]}}}}},
		{"mixed layouts", PoolSpec{Name: "tank", Data: []VdevSpec{{Type: Mirror, Disks: d[:2]}, {Type: RAIDZ1, Disks: d[2:5]}}}},
		{"bad disk path", PoolSpec{Name: "tank", Data: []VdevSpec{{Type: Mirror, Disks: []string{"/dev/sda", "/dev/sdb"}}}}},
		{"bad name", PoolSpec{Name: "mirror", Data: []VdevSpec{{Type: Mirror, Disks: d[:2]}}}},
		{"multi-disk stripe", PoolSpec{Name: "tank", Data: []VdevSpec{{Type: Stripe, Disks: d[:2]}}}},
	}
	for _, c := range cases {
		if err := c.spec.Validate(true); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}
