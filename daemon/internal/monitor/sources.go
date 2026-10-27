package monitor

import (
	"context"
	"io/fs"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/metrics"
)

// Point is one value a Source collected.
type Point struct {
	Series string  // "cpu.percent", "disk.read:sda"
	Label  string  // shown in the UI ("sda", "Immich"); "" for the obvious
	Unit   string  // percent, bytes, bytes/s, celsius, seconds, watts, count
	Value  float64 //
}

// Source is anything that adds resource history. A future solar or energy
// source (inverter power, battery state of charge) implements it and is
// added with Service.AddSource; nothing else needs to change.
type Source interface {
	// Name identifies the source in logs.
	Name() string
	// Interval is how often to collect: a multiple of 10 s.
	Interval() time.Duration
	// Collect returns the current values. Errors are logged; a source that
	// can't read anything (no hwmon sensors in a VM) returns no points.
	Collect(ctx context.Context, now time.Time) ([]Point, error)
}

// Units.
const (
	UnitPercent = "percent"
	UnitBytes   = "bytes"
	UnitBps     = "bytes/s"
	UnitCelsius = "celsius"
	UnitSeconds = "seconds"
	UnitWatts   = "watts"
	UnitCount   = "count"
	UnitVolts   = "volts"
)

// SystemSource records CPU, memory, the ZFS cache, network and load from
// the live collector (internal/metrics), which already samples /proc.
type SystemSource struct{ Collector *metrics.Collector }

func (SystemSource) Name() string            { return "system" }
func (SystemSource) Interval() time.Duration { return 10 * time.Second }

func (s SystemSource) Collect(context.Context, time.Time) ([]Point, error) {
	snap := s.Collector.Snapshot()
	if snap.Current.Time.IsZero() {
		return nil, nil
	}
	c := snap.Current
	return []Point{
		{Series: "cpu.percent", Unit: UnitPercent, Value: c.CPUPercent},
		{Series: "mem.used", Unit: UnitBytes, Value: float64(c.MemUsed)},
		{Series: "mem.total", Unit: UnitBytes, Value: float64(c.MemTotal)},
		{Series: "mem.arc", Unit: UnitBytes, Value: float64(c.ARCBytes)},
		{Series: "net.rx", Unit: UnitBps, Value: c.NetRxBps},
		{Series: "net.tx", Unit: UnitBps, Value: c.NetTxBps},
		{Series: "load.1", Unit: UnitCount, Value: c.Load1},
	}, nil
}

// rateSource turns counters into per-second rates between collections.
type rateSource struct {
	mu   sync.Mutex
	prev map[string]float64
	at   time.Time
}

func (r *rateSource) rates(now time.Time, cur map[string]float64) map[string]float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]float64{}
	if r.prev != nil {
		if secs := now.Sub(r.at).Seconds(); secs > 0 {
			for k, v := range cur {
				if p, ok := r.prev[k]; ok && v >= p {
					out[k] = (v - p) / secs
				}
			}
		}
	}
	r.prev, r.at = cur, now
	return out
}

// diskNameRE: whole disks only (no partitions, no loop, ram, zram or zd).
var diskNameRE = regexp.MustCompile(`^(sd[a-z]{1,3}|nvme[0-9]+n[0-9]+|vd[a-z]{1,3}|xvd[a-z]{1,3}|hd[a-z])$`)

// DiskIOSource records read and write throughput and busy time per disk
// from /proc/diskstats.
type DiskIOSource struct {
	Root fs.FS
	rs   rateSource
}

func (*DiskIOSource) Name() string            { return "disk-io" }
func (*DiskIOSource) Interval() time.Duration { return 10 * time.Second }

func (d *DiskIOSource) Collect(_ context.Context, now time.Time) ([]Point, error) {
	data, err := fs.ReadFile(d.Root, "proc/diskstats")
	if err != nil {
		return nil, err
	}
	cur := map[string]float64{}
	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 14 || !diskNameRE.MatchString(f[2]) {
			continue
		}
		rd, _ := strconv.ParseFloat(f[5], 64)  // sectors read
		wr, _ := strconv.ParseFloat(f[9], 64)  // sectors written
		io, _ := strconv.ParseFloat(f[12], 64) // ms spent doing I/O
		cur["r:"+f[2]], cur["w:"+f[2]], cur["b:"+f[2]] = rd*512, wr*512, io
		names = append(names, f[2])
	}
	rates := d.rs.rates(now, cur)
	var out []Point
	for _, n := range names {
		r, ok1 := rates["r:"+n]
		w, ok2 := rates["w:"+n]
		b, ok3 := rates["b:"+n]
		if !ok1 || !ok2 || !ok3 {
			continue
		}
		busy := b / 10 // ms per second -> percent
		if busy > 100 {
			busy = 100
		}
		out = append(out,
			Point{Series: "disk.read:" + n, Label: n, Unit: UnitBps, Value: r},
			Point{Series: "disk.write:" + n, Label: n, Unit: UnitBps, Value: w},
			Point{Series: "disk.busy:" + n, Label: n, Unit: UnitPercent, Value: busy})
	}
	return out, nil
}

// Sensor is one hwmon temperature input.
type Sensor struct {
	Key   string   // "coretemp-temp1"
	Label string   // "CPU Package id 0"
	TempC float64  //
	MaxC  *float64 // the chip's own limits, when it has them
	CritC *float64 //
	Chip  string   // coretemp, k10temp, nvme, drivetemp, acpitz…
}

var hwmonKeyRE = regexp.MustCompile(`[^a-z0-9_-]+`)

func readMilli(root fs.FS, p string) (float64, bool) {
	b, err := fs.ReadFile(root, p)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
	if err != nil {
		return 0, false
	}
	return v / 1000, true
}

// ReadSensors lists every temperature sensor under /sys/class/hwmon. What
// exists depends on the hardware and is found at run time (coretemp on
// Intel, k10temp on AMD, nvme, drivetemp, acpitz, or none in a VM).
func ReadSensors(root fs.FS) []Sensor {
	entries, err := fs.ReadDir(root, "sys/class/hwmon")
	if err != nil {
		return nil
	}
	var out []Sensor
	for _, e := range entries {
		dir := path.Join("sys/class/hwmon", e.Name())
		nameB, err := fs.ReadFile(root, path.Join(dir, "name"))
		if err != nil {
			continue
		}
		chip := strings.TrimSpace(string(nameB))
		files, _ := fs.ReadDir(root, dir)
		for _, f := range files {
			n := f.Name()
			if !strings.HasPrefix(n, "temp") || !strings.HasSuffix(n, "_input") {
				continue
			}
			base := strings.TrimSuffix(n, "_input")
			t, ok := readMilli(root, path.Join(dir, n))
			if !ok || t < -40 || t > 150 {
				continue
			}
			label := chip + " " + base
			if b, err := fs.ReadFile(root, path.Join(dir, base+"_label")); err == nil && strings.TrimSpace(string(b)) != "" {
				label = chip + " " + strings.TrimSpace(string(b))
			}
			s := Sensor{Key: hwmonKeyRE.ReplaceAllString(strings.ToLower(chip+"-"+e.Name()+"-"+base), "-"), Label: label, TempC: t, Chip: chip}
			if v, ok := readMilli(root, path.Join(dir, base+"_max")); ok && v > 0 && v < 150 {
				s.MaxC = &v
			}
			if v, ok := readMilli(root, path.Join(dir, base+"_crit")); ok && v > 0 && v < 150 {
				s.CritC = &v
			}
			out = append(out, s)
		}
	}
	return out
}

// HwmonSource records every hwmon temperature.
type HwmonSource struct{ Root fs.FS }

func (HwmonSource) Name() string            { return "hwmon" }
func (HwmonSource) Interval() time.Duration { return 30 * time.Second }

func (h HwmonSource) Collect(context.Context, time.Time) ([]Point, error) {
	var out []Point
	for _, s := range ReadSensors(h.Root) {
		out = append(out, Point{Series: "temp:" + s.Key, Label: s.Label, Unit: UnitCelsius, Value: s.TempC})
	}
	return out, nil
}

// AppSlicesDir is where systemd puts the apps' slices (internal/apps names
// them hardyos-app-<id>.slice, nested by systemd under hardyos.slice and
// hardyos-app.slice).
const AppSlicesDir = "sys/fs/cgroup/hardyos.slice/hardyos-app.slice"

// unescapeSlice undoes systemd's \x2d escaping of dashes in unit names.
func unescapeSlice(s string) string {
	return strings.ReplaceAll(s, `\x2d`, "-")
}

// AppsSource records CPU, memory and disk I/O per app from its cgroup
// (cgroup v2: cpu.stat, memory.current, io.stat; world-readable).
type AppsSource struct {
	Root  fs.FS
	CPUs  func() int
	Names func() map[string]string // app id -> name, for labels
	rs    rateSource
}

func (*AppsSource) Name() string            { return "apps" }
func (*AppsSource) Interval() time.Duration { return 10 * time.Second }

func (a *AppsSource) Collect(_ context.Context, now time.Time) ([]Point, error) {
	entries, err := fs.ReadDir(a.Root, AppSlicesDir)
	if err != nil {
		return nil, nil // no apps yet
	}
	cpus := 1
	if a.CPUs != nil && a.CPUs() > 0 {
		cpus = a.CPUs()
	}
	var names map[string]string
	if a.Names != nil {
		names = a.Names()
	}
	cur := map[string]float64{}
	mem := map[string]float64{}
	var ids []string
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() || !strings.HasPrefix(n, "hardyos-app-") || !strings.HasSuffix(n, ".slice") {
			continue
		}
		id := unescapeSlice(strings.TrimSuffix(strings.TrimPrefix(n, "hardyos-app-"), ".slice"))
		dir := path.Join(AppSlicesDir, n)
		if b, err := fs.ReadFile(a.Root, path.Join(dir, "cpu.stat")); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if f := strings.Fields(line); len(f) == 2 && f[0] == "usage_usec" {
					v, _ := strconv.ParseFloat(f[1], 64)
					cur["cpu:"+id] = v
				}
			}
		}
		if b, err := fs.ReadFile(a.Root, path.Join(dir, "memory.current")); err == nil {
			v, _ := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
			mem[id] = v
		}
		if b, err := fs.ReadFile(a.Root, path.Join(dir, "io.stat")); err == nil {
			var rb, wb float64
			for _, line := range strings.Split(string(b), "\n") {
				for _, kv := range strings.Fields(line) {
					k, v, ok := strings.Cut(kv, "=")
					if !ok {
						continue
					}
					x, _ := strconv.ParseFloat(v, 64)
					switch k {
					case "rbytes":
						rb += x
					case "wbytes":
						wb += x
					}
				}
			}
			cur["r:"+id], cur["w:"+id] = rb, wb
		}
		ids = append(ids, id)
	}
	rates := a.rs.rates(now, cur)
	var out []Point
	for _, id := range ids {
		label := id
		if names[id] != "" {
			label = names[id]
		}
		if m, ok := mem[id]; ok {
			out = append(out, Point{Series: "app.mem:" + id, Label: label, Unit: UnitBytes, Value: m})
		}
		if v, ok := rates["cpu:"+id]; ok {
			pct := v / 1e6 / float64(cpus) * 100 // usec per second over every CPU
			out = append(out, Point{Series: "app.cpu:" + id, Label: label, Unit: UnitPercent, Value: min(pct, 100)})
		}
		if v, ok := rates["r:"+id]; ok {
			out = append(out, Point{Series: "app.read:" + id, Label: label, Unit: UnitBps, Value: v})
		}
		if v, ok := rates["w:"+id]; ok {
			out = append(out, Point{Series: "app.write:" + id, Label: label, Unit: UnitBps, Value: v})
		}
	}
	return out, nil
}

// FuncSource adapts a function to a Source (pools, VMs and the UPS feed
// history from the checks that read them anyway).
type FuncSource struct {
	ID    string
	Every time.Duration
	Fn    func(ctx context.Context, now time.Time) ([]Point, error)
}

func (f FuncSource) Name() string            { return f.ID }
func (f FuncSource) Interval() time.Duration { return f.Every }
func (f FuncSource) Collect(ctx context.Context, now time.Time) ([]Point, error) {
	return f.Fn(ctx, now)
}
