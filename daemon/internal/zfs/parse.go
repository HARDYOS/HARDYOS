package zfs

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Pool is one row of `zpool list`.
type Pool struct {
	Name          string `json:"name"`
	SizeBytes     uint64 `json:"sizeBytes"`
	AllocBytes    uint64 `json:"allocBytes"`
	FreeBytes     uint64 `json:"freeBytes"`
	Fragmentation *int   `json:"fragmentation"` // percent; nil when not reported
	CapacityPct   int    `json:"capacityPct"`
	Health        string `json:"health"` // ONLINE, DEGRADED, FAULTED, ...
	GUID          string `json:"guid"`
}

// PoolListArgs are the arguments ParsePoolList expects.
var PoolListArgs = []string{"list", "-Hp", "-o", "name,size,allocated,free,fragmentation,capacity,health,guid"}

// ParsePoolList parses `zpool list -Hp -o name,size,allocated,free,fragmentation,capacity,health,guid`.
func ParsePoolList(out []byte) ([]Pool, error) {
	pools := []Pool{}
	for _, line := range lines(out) {
		f := strings.Split(line, "\t")
		if len(f) != 8 {
			return nil, fmt.Errorf("zpool list: unexpected line %q", line)
		}
		p := Pool{Name: f[0], Health: f[6], GUID: f[7]}
		p.SizeBytes, _ = strconv.ParseUint(f[1], 10, 64)
		p.AllocBytes, _ = strconv.ParseUint(f[2], 10, 64)
		p.FreeBytes, _ = strconv.ParseUint(f[3], 10, 64)
		if n, err := strconv.Atoi(strings.TrimSuffix(f[4], "%")); err == nil {
			p.Fragmentation = &n
		}
		p.CapacityPct, _ = strconv.Atoi(strings.TrimSuffix(f[5], "%"))
		pools = append(pools, p)
	}
	return pools, nil
}

// VdevClass groups top-level vdevs the way `zpool status` does.
type VdevClass string

const (
	ClassData    VdevClass = "data"
	ClassSpecial VdevClass = "special"
	ClassDedup   VdevClass = "dedup"
	ClassLog     VdevClass = "log"
	ClassCache   VdevClass = "cache"
	ClassSpare   VdevClass = "spare"
)

// Vdev is a node in a pool's device tree.
type Vdev struct {
	Name     string    `json:"name"`
	Type     string    `json:"type"` // root, mirror, raidz1, raidz2, raidz3, draid, replacing, spare, disk, file
	Class    VdevClass `json:"class"`
	State    string    `json:"state"`
	Read     uint64    `json:"read"`
	Write    uint64    `json:"write"`
	Checksum uint64    `json:"checksum"`
	Disk     string    `json:"disk"` // whole-disk by-id path for leaf devices
	Note     string    `json:"note"` // e.g. "(resilvering)", "was /dev/..."
	Children []*Vdev   `json:"children"`
}

// Scan describes the last or current scrub/resilver/expansion.
type Scan struct {
	Kind       string     `json:"kind"`  // scrub, resilver, expand, none
	State      string     `json:"state"` // running, paused, finished, cancelled, none
	Percent    *float64   `json:"percent"`
	Errors     *uint64    `json:"errors"`
	FinishedAt *time.Time `json:"finishedAt"`
	Remaining  string     `json:"remaining"` // "01:23:45 to go"
	Text       string     `json:"text"`      // the raw scan lines
}

// Status is the parsed result of `zpool status -P -p <pool>`.
type Status struct {
	Name   string  `json:"name"`
	State  string  `json:"state"`
	Status string  `json:"status"`
	Action string  `json:"action"`
	Scan   Scan    `json:"scan"`
	Expand *Scan   `json:"expand"`
	Errors string  `json:"errors"`
	Root   *Vdev   `json:"root"`
	Groups []*Vdev `json:"groups"` // top-level vdevs in every class (data, special, log, cache, spare)
}

// StatusArgs returns the arguments ParseStatus expects for one pool.
func StatusArgs(pool string) []string { return []string{"status", "-P", "-p", pool} }

var (
	percentRE  = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)% done`)
	errCountRE = regexp.MustCompile(`with ([0-9]+) errors`)
	remainRE   = regexp.MustCompile(`([0-9]+ days [0-9:]+|[0-9:]+) to go`)
	onDateRE   = regexp.MustCompile(` on (\w{3} \w{3} +[0-9]{1,2} [0-9:]{8} [0-9]{4})`)
)

// ParseStatus parses `zpool status -P -p` output for one pool.
func ParseStatus(out []byte) (*Status, error) {
	st := &Status{Groups: []*Vdev{}}
	var section string // current "key:" block
	var scanLines, expandLines []string
	var config []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		if k, v, ok := strings.Cut(trimmed, ":"); ok && isHeaderKey(k) && !strings.HasPrefix(raw, "\t") {
			section = k
			v = strings.TrimSpace(v)
			switch k {
			case "pool":
				st.Name = v
			case "state":
				st.State = v
			case "status":
				st.Status = v
			case "action":
				st.Action = v
			case "scan":
				scanLines = append(scanLines, v)
			case "expand":
				expandLines = append(expandLines, v)
			case "errors":
				st.Errors = v
			}
			continue
		}
		switch section {
		case "status":
			st.Status = joinText(st.Status, trimmed)
		case "action":
			st.Action = joinText(st.Action, trimmed)
		case "scan":
			if trimmed != "" {
				scanLines = append(scanLines, trimmed)
			}
		case "expand":
			if trimmed != "" {
				expandLines = append(expandLines, trimmed)
			}
		case "config":
			config = append(config, raw)
		}
	}
	if st.Name == "" {
		return nil, fmt.Errorf("zpool status: no pool in output")
	}
	st.Scan = parseScan(scanLines)
	if len(expandLines) > 0 {
		e := parseScan(expandLines)
		e.Kind = "expand"
		st.Expand = &e
	}
	root, groups, err := parseConfig(config)
	if err != nil {
		return nil, err
	}
	st.Root, st.Groups = root, groups
	return st, nil
}

func isHeaderKey(k string) bool {
	switch k {
	case "pool", "id", "state", "status", "action", "see", "scan", "expand", "config", "errors", "remove", "checkpoint":
		return true
	}
	return false
}

func joinText(a, b string) string {
	if b == "" {
		return a
	}
	if a == "" {
		return b
	}
	return a + " " + b
}

func parseScan(lines []string) Scan {
	s := Scan{Kind: "none", State: "none", Text: strings.Join(lines, "\n")}
	if len(lines) == 0 || strings.HasPrefix(lines[0], "none requested") {
		return s
	}
	first := lines[0]
	switch {
	case strings.HasPrefix(first, "scrub"):
		s.Kind = "scrub"
	case strings.HasPrefix(first, "resilver"):
		s.Kind = "resilver"
	case strings.HasPrefix(first, "expansion"), strings.HasPrefix(first, "expanded"):
		s.Kind = "expand"
	}
	switch {
	case strings.Contains(first, "in progress"):
		s.State = "running"
	case strings.Contains(first, "paused"):
		s.State = "paused"
	case strings.Contains(first, "canceled") || strings.Contains(first, "cancelled"):
		s.State = "cancelled"
	case strings.Contains(first, "repaired") || strings.Contains(first, "resilvered") ||
		strings.Contains(first, "completed") || strings.HasPrefix(first, "expanded"):
		s.State = "finished"
	}
	all := strings.Join(lines, " ")
	if m := percentRE.FindStringSubmatch(all); m != nil {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil {
			s.Percent = &v
		}
	}
	if s.State == "finished" {
		v := 100.0
		s.Percent = &v
	}
	if m := errCountRE.FindStringSubmatch(all); m != nil {
		if v, err := strconv.ParseUint(m[1], 10, 64); err == nil {
			s.Errors = &v
		}
	}
	if m := remainRE.FindStringSubmatch(all); m != nil {
		s.Remaining = m[1]
	}
	if m := onDateRE.FindStringSubmatch(first); m != nil && s.State == "finished" {
		if t, err := time.ParseInLocation("Mon Jan _2 15:04:05 2006", m[1], time.Local); err == nil {
			s.FinishedAt = &t
		}
	}
	return s
}

func parseConfig(lines []string) (*Vdev, []*Vdev, error) {
	type frame struct {
		depth int
		v     *Vdev
	}
	var root *Vdev
	groups := []*Vdev{}
	var stack []frame
	class := ClassData
	for _, raw := range lines {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		body := strings.TrimPrefix(raw, "\t")
		indent := len(body) - len(strings.TrimLeft(body, " "))
		f := strings.Fields(body)
		if f[0] == "NAME" {
			continue
		}
		depth := indent / 2
		// Section headers ("special", "logs", "cache", "spares", "dedup") sit at depth 0 alone.
		if depth == 0 && root != nil && len(f) == 1 {
			switch f[0] {
			case "special":
				class = ClassSpecial
			case "logs":
				class = ClassLog
			case "cache":
				class = ClassCache
			case "spares":
				class = ClassSpare
			case "dedup":
				class = ClassDedup
			}
			stack = stack[:0]
			continue
		}
		v := &Vdev{Name: f[0], Class: class, Children: []*Vdev{}}
		if len(f) > 1 {
			v.State = f[1]
		}
		if len(f) >= 5 {
			v.Read, _ = strconv.ParseUint(f[2], 10, 64)
			v.Write, _ = strconv.ParseUint(f[3], 10, 64)
			v.Checksum, _ = strconv.ParseUint(f[4], 10, 64)
			if len(f) > 5 {
				v.Note = strings.Join(f[5:], " ")
			}
		}
		v.Type = vdevType(v.Name)
		if v.Type == "disk" {
			v.Disk = DiskOf(v.Name)
		}

		if root == nil {
			v.Type, v.Class = "root", ClassData
			root = v
			stack = []frame{{depth, v}}
			continue
		}
		for len(stack) > 0 && stack[len(stack)-1].depth >= depth {
			stack = stack[:len(stack)-1]
		}
		if len(stack) == 0 {
			// Top level of a non-data section (cache devices, spares, special/log vdevs).
			groups = append(groups, v)
		} else {
			parent := stack[len(stack)-1].v
			if parent == root {
				groups = append(groups, v)
			}
			parent.Children = append(parent.Children, v)
		}
		stack = append(stack, frame{depth, v})
	}
	if root == nil {
		return nil, nil, fmt.Errorf("zpool status: no config section")
	}
	return root, groups, nil
}

func vdevType(name string) string {
	switch {
	case strings.HasPrefix(name, "mirror-"):
		return "mirror"
	case strings.HasPrefix(name, "raidz1-"), strings.HasPrefix(name, "raidz-"):
		return "raidz1"
	case strings.HasPrefix(name, "raidz2-"):
		return "raidz2"
	case strings.HasPrefix(name, "raidz3-"):
		return "raidz3"
	case strings.HasPrefix(name, "draid"):
		return "draid"
	case strings.HasPrefix(name, "replacing-"):
		return "replacing"
	case strings.HasPrefix(name, "spare-"):
		return "spare"
	case strings.HasPrefix(name, "/dev/"):
		return "disk"
	case strings.HasPrefix(name, "/"):
		return "file"
	}
	return "disk"
}

// Dataset is a ZFS filesystem or volume.
type Dataset struct {
	Name          string `json:"name"`
	Type          string `json:"type"` // filesystem, volume
	UsedBytes     uint64 `json:"usedBytes"`
	AvailBytes    uint64 `json:"availBytes"`
	ReferBytes    uint64 `json:"referBytes"`
	Mountpoint    string `json:"mountpoint"`
	Compression   string `json:"compression"`
	CompressRatio string `json:"compressRatio"`
	Encryption    string `json:"encryption"`
	KeyStatus     string `json:"keyStatus"`
	QuotaBytes    uint64 `json:"quotaBytes"` // 0 = none
	RecordSize    string `json:"recordSize"`
	VolSizeBytes  uint64 `json:"volSizeBytes"`
	Mounted       bool   `json:"mounted"`
}

// DatasetListArgs are the arguments ParseDatasets expects (append a root dataset to limit scope).
var DatasetListArgs = []string{"list", "-Hp", "-t", "filesystem,volume", "-o",
	"name,type,used,avail,refer,mountpoint,compression,compressratio,encryption,keystatus,quota,recordsize,volsize,mounted"}

// ParseDatasets parses `zfs list -Hp ...` with DatasetListArgs columns.
func ParseDatasets(out []byte) ([]Dataset, error) {
	list := []Dataset{}
	for _, line := range lines(out) {
		f := strings.Split(line, "\t")
		if len(f) != 14 {
			return nil, fmt.Errorf("zfs list: unexpected line %q", line)
		}
		d := Dataset{Name: f[0], Type: f[1], Mountpoint: f[5], Compression: f[6], CompressRatio: f[7],
			Encryption: f[8], KeyStatus: f[9], RecordSize: f[11], Mounted: f[13] == "yes"}
		d.UsedBytes = num(f[2])
		d.AvailBytes = num(f[3])
		d.ReferBytes = num(f[4])
		d.QuotaBytes = num(f[10])
		d.VolSizeBytes = num(f[12])
		if d.RecordSize == "-" {
			d.RecordSize = ""
		}
		list = append(list, d)
	}
	return list, nil
}

// Snapshot is a ZFS snapshot.
type Snapshot struct {
	Name       string    `json:"name"` // pool/ds@label
	Dataset    string    `json:"dataset"`
	Label      string    `json:"label"`
	UsedBytes  uint64    `json:"usedBytes"`
	ReferBytes uint64    `json:"referBytes"`
	CreatedAt  time.Time `json:"createdAt"`
}

// SnapshotListArgs are the arguments ParseSnapshots expects.
var SnapshotListArgs = []string{"list", "-Hp", "-t", "snapshot", "-o", "name,used,refer,creation", "-s", "creation"}

// ParseSnapshots parses `zfs list -Hp -t snapshot -o name,used,refer,creation`.
func ParseSnapshots(out []byte) ([]Snapshot, error) {
	list := []Snapshot{}
	for _, line := range lines(out) {
		f := strings.Split(line, "\t")
		if len(f) != 4 {
			return nil, fmt.Errorf("zfs list snapshots: unexpected line %q", line)
		}
		ds, label, _ := strings.Cut(f[0], "@")
		s := Snapshot{Name: f[0], Dataset: ds, Label: label, UsedBytes: num(f[1]), ReferBytes: num(f[2])}
		if sec, err := strconv.ParseInt(f[3], 10, 64); err == nil {
			s.CreatedAt = time.Unix(sec, 0).UTC()
		}
		list = append(list, s)
	}
	return list, nil
}

// ImportablePool is a pool found on disks but not imported.
type ImportablePool struct {
	Name   string `json:"name"`
	ID     string `json:"id"`
	State  string `json:"state"`
	Status string `json:"status"`
}

// ParseImportable parses the output of `zpool import` (no arguments).
func ParseImportable(out []byte) []ImportablePool {
	var list []ImportablePool
	var cur *ImportablePool
	var section string
	for _, raw := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(raw)
		k, v, ok := strings.Cut(t, ":")
		if ok && isHeaderKey(k) {
			section = k
			v = strings.TrimSpace(v)
			switch k {
			case "pool":
				list = append(list, ImportablePool{Name: v})
				cur = &list[len(list)-1]
			case "id":
				if cur != nil {
					cur.ID = v
				}
			case "state":
				if cur != nil {
					cur.State = v
				}
			case "status":
				if cur != nil {
					cur.Status = v
				}
			}
			continue
		}
		if section == "status" && cur != nil && t != "" {
			cur.Status = joinText(cur.Status, t)
		}
	}
	if list == nil {
		list = []ImportablePool{}
	}
	return list
}

func lines(out []byte) []string {
	var res []string
	for _, l := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if strings.TrimSpace(l) != "" {
			res = append(res, l)
		}
	}
	return res
}

func num(s string) uint64 {
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}
