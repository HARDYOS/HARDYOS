// Package metrics samples CPU, memory, network and load from /proc every few
// seconds and keeps a short history for the Resource Monitor and widgets.
package metrics

import (
	"bufio"
	"bytes"
	"context"
	"io/fs"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Sample is one point in time.
type Sample struct {
	Time       time.Time `json:"time"`
	CPUPercent float64   `json:"cpuPercent"`
	MemUsed    uint64    `json:"memUsed"`    // bytes used by programs (excludes reclaimable cache)
	MemTotal   uint64    `json:"memTotal"`   // bytes
	ARCBytes   uint64    `json:"arcBytes"`   // ZFS ARC size (reclaimable cache)
	NetRxBps   float64   `json:"netRxBps"`   // bytes per second received, physical NICs
	NetTxBps   float64   `json:"netTxBps"`   // bytes per second sent
	Load1      float64   `json:"load1"`      // 1-minute load average
	UptimeSecs float64   `json:"uptimeSecs"` // system uptime
}

// Snapshot is the current sample plus recent history (oldest first).
type Snapshot struct {
	Current Sample   `json:"current"`
	History []Sample `json:"history"`
	CPUs    int      `json:"cpus"`
}

// Collector samples /proc under Root.
type Collector struct {
	Root     fs.FS // filesystem rooted at "/"
	Interval time.Duration
	Keep     int // samples of history kept

	mu      sync.RWMutex
	history []Sample
	cpus    int
	prevCPU cpuTimes
	prevNet netCounters
	prevAt  time.Time
}

// Run samples until ctx is done.
func (c *Collector) Run(ctx context.Context) {
	if c.Interval == 0 {
		c.Interval = 2 * time.Second
	}
	if c.Keep == 0 {
		c.Keep = 150 // 5 minutes at 2 s
	}
	c.sample(time.Now())
	t := time.NewTicker(c.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			c.sample(now)
		}
	}
}

// Snapshot returns the latest sample and history.
func (c *Collector) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s := Snapshot{History: append([]Sample{}, c.history...), CPUs: c.cpus}
	if n := len(c.history); n > 0 {
		s.Current = c.history[n-1]
	}
	return s
}

func (c *Collector) sample(now time.Time) {
	cpu, cpus := readCPU(c.Root)
	net := readNet(c.Root)
	s := Sample{Time: now.UTC()}
	s.MemTotal, s.MemUsed = readMem(c.Root)
	s.ARCBytes = readARC(c.Root)
	s.Load1, s.UptimeSecs = readLoad(c.Root), readUptime(c.Root)

	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.prevAt.IsZero() {
		if dt := cpu.total - c.prevCPU.total; dt > 0 {
			busy := float64(dt-(cpu.idle-c.prevCPU.idle)) / float64(dt) * 100
			s.CPUPercent = clamp(busy, 0, 100)
		}
		if secs := now.Sub(c.prevAt).Seconds(); secs > 0 {
			s.NetRxBps = float64(sub(net.rx, c.prevNet.rx)) / secs
			s.NetTxBps = float64(sub(net.tx, c.prevNet.tx)) / secs
		}
	}
	// The ARC is reclaimable; don't count it as used memory.
	if s.ARCBytes < s.MemUsed {
		s.MemUsed -= s.ARCBytes
	}
	c.prevCPU, c.prevNet, c.prevAt, c.cpus = cpu, net, now, cpus
	c.history = append(c.history, s)
	if len(c.history) > c.Keep {
		c.history = c.history[len(c.history)-c.Keep:]
	}
}

type cpuTimes struct{ total, idle uint64 }

func readCPU(root fs.FS) (cpuTimes, int) {
	var t cpuTimes
	cpus := 0
	data, err := fs.ReadFile(root, "proc/stat")
	if err != nil {
		return t, 0
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "cpu ") {
			f := strings.Fields(line)[1:]
			for i, v := range f {
				n, _ := strconv.ParseUint(v, 10, 64)
				if i >= 8 { // guest and guest_nice are already counted in user/nice
					break
				}
				t.total += n
				if i == 3 || i == 4 { // idle + iowait
					t.idle += n
				}
			}
		} else if strings.HasPrefix(line, "cpu") {
			cpus++
		}
	}
	return t, cpus
}

func readMem(root fs.FS) (total, used uint64) {
	data, err := fs.ReadFile(root, "proc/meminfo")
	if err != nil {
		return 0, 0
	}
	vals := map[string]uint64{}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) > 0 {
			n, _ := strconv.ParseUint(f[0], 10, 64)
			vals[k] = n * 1024
		}
	}
	total = vals["MemTotal"]
	if avail, ok := vals["MemAvailable"]; ok && avail <= total {
		used = total - avail
	}
	return total, used
}

func readARC(root fs.FS) uint64 {
	data, err := fs.ReadFile(root, "proc/spl/kstat/zfs/arcstats")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "size" {
			n, _ := strconv.ParseUint(f[2], 10, 64)
			return n
		}
	}
	return 0
}

type netCounters struct{ rx, tx uint64 }

// readNet sums counters for interfaces that look physical (skips lo, docker, veth, bridges, tun).
func readNet(root fs.FS) netCounters {
	var n netCounters
	data, err := fs.ReadFile(root, "proc/net/dev")
	if err != nil {
		return n
	}
	for _, line := range strings.Split(string(data), "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "lo" || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "veth") ||
			strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "virbr") || strings.HasPrefix(name, "tun") ||
			strings.HasPrefix(name, "wt") || strings.HasPrefix(name, "vnet") {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(f[0], 10, 64)
		tx, _ := strconv.ParseUint(f[8], 10, 64)
		n.rx += rx
		n.tx += tx
	}
	return n
}

func readLoad(root fs.FS) float64 {
	data, err := fs.ReadFile(root, "proc/loadavg")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

func readUptime(root fs.FS) float64 {
	data, err := fs.ReadFile(root, "proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

func sub(a, b uint64) uint64 {
	if a < b { // counter reset
		return 0
	}
	return a - b
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
