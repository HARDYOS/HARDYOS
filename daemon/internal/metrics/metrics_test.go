package metrics

import (
	"testing"
	"testing/fstest"
	"time"
)

func procFS(user, idle, rx, tx uint64) fstest.MapFS {
	return fstest.MapFS{
		"proc/stat": {Data: []byte(
			"cpu  " + u(user) + " 0 0 " + u(idle) + " 0 0 0 0 0 0\n" +
				"cpu0 1 0 0 1 0 0 0 0 0 0\ncpu1 1 0 0 1 0 0 0 0 0 0\nintr 0\n")},
		"proc/meminfo": {Data: []byte("MemTotal: 16000000 kB\nMemFree: 1000000 kB\nMemAvailable: 12000000 kB\n")},
		"proc/net/dev": {Data: []byte("Inter-|   Receive\n face |bytes packets\n" +
			"    lo: 999999 0 0 0 0 0 0 0 999999 0 0 0 0 0 0 0\n" +
			"  eno1: " + u(rx) + " 0 0 0 0 0 0 0 " + u(tx) + " 0 0 0 0 0 0 0\n" +
			"docker0: 5555 0 0 0 0 0 0 0 5555 0 0 0 0 0 0 0\n")},
		"proc/loadavg":                {Data: []byte("0.42 0.30 0.20 1/300 1234\n")},
		"proc/uptime":                 {Data: []byte("86400.5 100.0\n")},
		"proc/spl/kstat/zfs/arcstats": {Data: []byte("name type data\nhits 4 100\nsize 4 2048000000\n")},
	}
}

func u(n uint64) string {
	b := []byte{}
	if n == 0 {
		return "0"
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestSampling(t *testing.T) {
	c := &Collector{Root: procFS(100, 900, 1000, 500), Keep: 3}
	t0 := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	c.sample(t0)

	// 2 s later: 100 more busy ticks out of 400 => 25 %; 2000 bytes in, 1000 out.
	c.Root = procFS(200, 1200, 3000, 1500)
	c.sample(t0.Add(2 * time.Second))

	s := c.Snapshot()
	if s.CPUs != 2 || len(s.History) != 2 {
		t.Fatalf("cpus=%d history=%d", s.CPUs, len(s.History))
	}
	cur := s.Current
	if cur.CPUPercent != 25 {
		t.Errorf("cpu = %v, want 25", cur.CPUPercent)
	}
	if cur.NetRxBps != 1000 || cur.NetTxBps != 500 {
		t.Errorf("net = %v/%v, want 1000/500 (lo and docker excluded)", cur.NetRxBps, cur.NetTxBps)
	}
	wantUsed := uint64(4000000*1024) - 2048000000
	if cur.MemTotal != 16000000*1024 || cur.MemUsed != wantUsed || cur.ARCBytes != 2048000000 {
		t.Errorf("mem = %d/%d arc %d, want used %d", cur.MemUsed, cur.MemTotal, cur.ARCBytes, wantUsed)
	}
	if cur.Load1 != 0.42 || cur.UptimeSecs != 86400.5 {
		t.Errorf("load/uptime = %v/%v", cur.Load1, cur.UptimeSecs)
	}

	for i := 0; i < 5; i++ {
		c.sample(t0.Add(time.Duration(4+i) * time.Second))
	}
	if n := len(c.Snapshot().History); n != 3 {
		t.Errorf("history not trimmed: %d", n)
	}
}

func TestMissingProcIsHarmless(t *testing.T) {
	c := &Collector{Root: fstest.MapFS{}}
	c.sample(time.Now())
	if s := c.Snapshot(); s.Current.MemTotal != 0 || s.CPUs != 0 {
		t.Fatalf("got %+v", s)
	}
}
