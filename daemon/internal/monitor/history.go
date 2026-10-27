package monitor

// History is a small time-series store for the Resource Monitor, in its
// own SQLite file (metrics.db next to hardyd.db) so settings backups of
// hardyd.db stay small. Values are kept in four tiers, each the average of
// the one below:
//
//	tier 0: every 10 s, kept 1 day
//	tier 1: every minute, kept 7 days
//	tier 2: every 15 minutes, kept 90 days
//	tier 3: every hour, kept 2 years
//
// A tier is stored as chunks: one row per series and time span with the
// span's values packed as little-endian float32 (NaN for "no value"), so
// a day of one series at 10 s is 24 rows of 1.4 KB rather than 8,640 rows.
// Recording touches only memory; Flush writes the chunks that changed
// (every minute). Rollups compute a coarser tier's buckets from the finer
// tier's stored values once the bucket is complete, so a restart loses at
// most the unflushed minute and nothing has to be kept in memory to roll
// up later.

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type tier struct {
	step, chunk, keep time.Duration
}

// Tiers are the resolutions history keeps.
var Tiers = []tier{
	{step: 10 * time.Second, chunk: time.Hour, keep: 24 * time.Hour},
	{step: time.Minute, chunk: 6 * time.Hour, keep: 7 * 24 * time.Hour},
	{step: 15 * time.Minute, chunk: 4 * 24 * time.Hour, keep: 90 * 24 * time.Hour},
	{step: time.Hour, chunk: 16 * 24 * time.Hour, keep: 730 * 24 * time.Hour},
}

func (t tier) slots() int { return int(t.chunk / t.step) }

// SeriesInfo describes one series.
type SeriesInfo struct {
	Name     string    `json:"name"`  // "cpu.percent", "disk.read:sda", "app.cpu:immich"
	Label    string    `json:"label"` // what people read: "sda", "Immich"
	Unit     string    `json:"unit"`  // percent, bytes, bytes/s, celsius, seconds, watts, count
	LastSeen time.Time `json:"lastSeen"`
}

type chunkKey struct {
	series int64
	tier   int
	start  int64 // unix seconds
}

type chunk struct {
	vals    []float32
	dirty   bool
	touched time.Time
}

// History is the store. It's safe for concurrent use.
type History struct {
	db *sql.DB

	mu     sync.Mutex
	ids    map[string]int64
	meta   map[string]SeriesInfo
	chunks map[chunkKey]*chunk
	seen   map[int64]time.Time // last value per series (for last_seen)
}

// OpenHistory opens (creating) the store at path; ":memory:" for tests.
func OpenHistory(ctx context.Context, path string) (*History, error) {
	dsn := "file::memory:"
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, err
		}
		dsn = "file:" + path
	}
	db, err := sql.Open("sqlite", dsn+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS series (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
			label TEXT NOT NULL DEFAULT '', unit TEXT NOT NULL DEFAULT '', last_seen INTEGER NOT NULL DEFAULT 0);
		CREATE TABLE IF NOT EXISTS chunks (series_id INTEGER NOT NULL, tier INTEGER NOT NULL, start INTEGER NOT NULL,
			data BLOB NOT NULL, PRIMARY KEY (series_id, tier, start)) WITHOUT ROWID;
		CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);`); err != nil {
		db.Close()
		return nil, fmt.Errorf("history schema: %w", err)
	}
	if path != ":memory:" {
		_ = os.Chmod(path, 0o600)
	}
	h := &History{db: db, ids: map[string]int64{}, meta: map[string]SeriesInfo{}, chunks: map[chunkKey]*chunk{}, seen: map[int64]time.Time{}}
	rows, err := db.QueryContext(ctx, `SELECT id, name, label, unit, last_seen FROM series`)
	if err != nil {
		db.Close()
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, last int64
		var si SeriesInfo
		if err := rows.Scan(&id, &si.Name, &si.Label, &si.Unit, &last); err != nil {
			return nil, err
		}
		si.LastSeen = time.Unix(last, 0).UTC()
		h.ids[si.Name], h.meta[si.Name] = id, si
	}
	return h, rows.Err()
}

// Close flushes and closes the store.
func (h *History) Close() error {
	_ = h.Flush(context.Background())
	return h.db.Close()
}

func encode(v []float32) []byte {
	b := make([]byte, 4*len(v))
	for i, f := range v {
		binary.LittleEndian.PutUint32(b[4*i:], math.Float32bits(f))
	}
	return b
}

func decode(b []byte, n int) []float32 {
	v := make([]float32, n)
	for i := range v {
		if 4*i+4 <= len(b) {
			v[i] = math.Float32frombits(binary.LittleEndian.Uint32(b[4*i:]))
		} else {
			v[i] = float32(math.NaN())
		}
	}
	return v
}

func nanChunk(n int) []float32 {
	v := make([]float32, n)
	for i := range v {
		v[i] = float32(math.NaN())
	}
	return v
}

// seriesID returns (making) the id for a series. Caller holds h.mu.
func (h *History) seriesID(ctx context.Context, si SeriesInfo) (int64, error) {
	if id, ok := h.ids[si.Name]; ok {
		if m := h.meta[si.Name]; (si.Label != "" && m.Label != si.Label) || (si.Unit != "" && m.Unit != si.Unit) {
			m.Label, m.Unit = si.Label, si.Unit
			h.meta[si.Name] = m
			_, _ = h.db.ExecContext(ctx, `UPDATE series SET label = ?, unit = ? WHERE id = ?`, si.Label, si.Unit, id)
		}
		return id, nil
	}
	res, err := h.db.ExecContext(ctx, `INSERT INTO series (name, label, unit) VALUES (?, ?, ?) ON CONFLICT(name) DO NOTHING`, si.Name, si.Label, si.Unit)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	if n, _ := res.RowsAffected(); n == 0 {
		if err := h.db.QueryRowContext(ctx, `SELECT id FROM series WHERE name = ?`, si.Name).Scan(&id); err != nil {
			return 0, err
		}
	}
	h.ids[si.Name], h.meta[si.Name] = id, si
	return id, nil
}

// chunkFor returns the chunk holding t at a tier, loading it. Caller holds h.mu.
func (h *History) chunkFor(ctx context.Context, id int64, ti int, t time.Time) (*chunk, chunkKey, error) {
	tr := Tiers[ti]
	start := t.Unix() - t.Unix()%int64(tr.chunk/time.Second)
	k := chunkKey{id, ti, start}
	if c, ok := h.chunks[k]; ok {
		c.touched = time.Now()
		return c, k, nil
	}
	var data []byte
	err := h.db.QueryRowContext(ctx, `SELECT data FROM chunks WHERE series_id = ? AND tier = ? AND start = ?`, id, ti, start).Scan(&data)
	c := &chunk{touched: time.Now()}
	switch {
	case err == sql.ErrNoRows:
		c.vals = nanChunk(tr.slots())
	case err != nil:
		return nil, k, err
	default:
		c.vals = decode(data, tr.slots())
	}
	h.chunks[k] = c
	return c, k, nil
}

func slot(t time.Time, k chunkKey, tr tier) int {
	return int((t.Unix() - k.start) / int64(tr.step/time.Second))
}

// Record stores one value of a series at time t (tier 0).
func (h *History) Record(ctx context.Context, si SeriesInfo, t time.Time, v float64) error {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	id, err := h.seriesID(ctx, si)
	if err != nil {
		return err
	}
	c, k, err := h.chunkFor(ctx, id, 0, t)
	if err != nil {
		return err
	}
	c.vals[slot(t, k, Tiers[0])] = float32(v)
	c.dirty = true
	h.seen[id] = t
	return nil
}

// Flush writes changed chunks and drops ones not used for a while.
func (h *History) Flush(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for k, c := range h.chunks {
		if !c.dirty {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO chunks (series_id, tier, start, data) VALUES (?, ?, ?, ?)
			ON CONFLICT(series_id, tier, start) DO UPDATE SET data = excluded.data`, k.series, k.tier, k.start, encode(c.vals)); err != nil {
			return err
		}
	}
	for id, t := range h.seen {
		if _, err := tx.ExecContext(ctx, `UPDATE series SET last_seen = ? WHERE id = ?`, t.Unix(), id); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	for name, id := range h.ids {
		if t, ok := h.seen[id]; ok {
			m := h.meta[name]
			m.LastSeen = t.UTC()
			h.meta[name] = m
		}
	}
	h.seen = map[int64]time.Time{}
	for k, c := range h.chunks {
		c.dirty = false
		if time.Since(c.touched) > 10*time.Minute {
			delete(h.chunks, k)
		}
	}
	return nil
}

func (h *History) metaGet(ctx context.Context, key string) int64 {
	var v int64
	_ = h.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	return v
}

func (h *History) metaSet(ctx context.Context, key string, v int64) {
	_, _ = h.db.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, v)
}

// values reads a tier's values in [from, to) for one series, stepping by
// the tier's step (NaN where there's nothing). Caller holds h.mu.
func (h *History) values(ctx context.Context, id int64, ti int, from, to time.Time) ([]float32, error) {
	tr := Tiers[ti]
	step := int64(tr.step / time.Second)
	f, t := from.Unix()-from.Unix()%step, to.Unix()
	var out []float32
	for ts := f; ts < t; {
		c, k, err := h.chunkFor(ctx, id, ti, time.Unix(ts, 0))
		if err != nil {
			return nil, err
		}
		end := k.start + int64(tr.chunk/time.Second)
		for ; ts < t && ts < end; ts += step {
			out = append(out, c.vals[(ts-k.start)/step])
		}
	}
	return out, nil
}

// Rollup fills coarser tiers from finer ones for every bucket completed
// by now.
func (h *History) Rollup(ctx context.Context, now time.Time) error {
	for ti := 1; ti < len(Tiers); ti++ {
		if err := h.rollupTier(ctx, ti, now); err != nil {
			return err
		}
	}
	return nil
}

func (h *History) rollupTier(ctx context.Context, ti int, now time.Time) error {
	tr, fine := Tiers[ti], Tiers[ti-1]
	step := int64(tr.step / time.Second)
	key := fmt.Sprintf("rollup.%d", ti)
	last := h.metaGet(ctx, key) // start of the next bucket to compute
	end := now.Unix() - now.Unix()%step
	if earliest := now.Add(-fine.keep).Unix(); last < earliest {
		last = earliest - earliest%step
	}
	if last >= end {
		return nil
	}
	h.mu.Lock()
	ids := make([]int64, 0, len(h.ids))
	for _, id := range h.ids {
		ids = append(ids, id)
	}
	h.mu.Unlock()
	for b := last; b < end; b += step {
		h.mu.Lock()
		for _, id := range ids {
			vals, err := h.values(ctx, id, ti-1, time.Unix(b, 0), time.Unix(b+step, 0))
			if err != nil {
				h.mu.Unlock()
				return err
			}
			var sum float64
			n := 0
			for _, v := range vals {
				if !math.IsNaN(float64(v)) {
					sum += float64(v)
					n++
				}
			}
			if n == 0 {
				continue
			}
			c, k, err := h.chunkFor(ctx, id, ti, time.Unix(b, 0))
			if err != nil {
				h.mu.Unlock()
				return err
			}
			c.vals[slot(time.Unix(b, 0), k, tr)] = float32(sum / float64(n))
			c.dirty = true
		}
		h.mu.Unlock()
	}
	h.metaSet(ctx, key, end)
	return nil
}

// Prune deletes chunks older than their tier keeps, and series not seen
// for longer than the longest tier.
func (h *History) Prune(ctx context.Context, now time.Time) error {
	for ti, tr := range Tiers {
		cut := now.Add(-tr.keep - tr.chunk).Unix()
		if _, err := h.db.ExecContext(ctx, `DELETE FROM chunks WHERE tier = ? AND start < ?`, ti, cut); err != nil {
			return err
		}
	}
	old := now.Add(-Tiers[len(Tiers)-1].keep).Unix()
	h.mu.Lock()
	defer h.mu.Unlock()
	rows, err := h.db.QueryContext(ctx, `SELECT id, name FROM series WHERE last_seen > 0 AND last_seen < ?`, old)
	if err != nil {
		return err
	}
	var gone []int64
	for rows.Next() {
		var id int64
		var name string
		if rows.Scan(&id, &name) == nil {
			gone = append(gone, id)
			delete(h.ids, name)
			delete(h.meta, name)
		}
	}
	rows.Close()
	for _, id := range gone {
		_, _ = h.db.ExecContext(ctx, `DELETE FROM chunks WHERE series_id = ?`, id)
		_, _ = h.db.ExecContext(ctx, `DELETE FROM series WHERE id = ?`, id)
	}
	return nil
}

// Series lists every series, by name.
func (h *History) Series() []SeriesInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]SeriesInfo, 0, len(h.meta))
	for _, m := range h.meta {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SeriesData is one series over a range.
type SeriesData struct {
	Name   string     `json:"name"`
	Label  string     `json:"label"`
	Unit   string     `json:"unit"`
	Values []*float64 `json:"values"` // null where there's no value
}

// HistoryResult is a query's answer: every series has one value per Step
// from From.
type HistoryResult struct {
	From   time.Time    `json:"from"`
	To     time.Time    `json:"to"`
	Step   int          `json:"step"` // seconds
	Tier   int          `json:"tier"`
	Series []SeriesData `json:"series"`
}

// MaxQuerySeries bounds one query.
const MaxQuerySeries = 64

// Query returns series in [from, to) with at most maxPoints values each,
// from the finest tier that still covers from.
func (h *History) Query(ctx context.Context, names []string, from, to, now time.Time, maxPoints int) (*HistoryResult, error) {
	if len(names) > MaxQuerySeries {
		return nil, fmt.Errorf("at most %d series at once", MaxQuerySeries)
	}
	if maxPoints <= 0 || maxPoints > 2000 {
		maxPoints = 500
	}
	if !to.After(from) {
		return nil, fmt.Errorf("the range is empty")
	}
	if err := h.Flush(ctx); err != nil {
		return nil, err
	}
	ti := len(Tiers) - 1
	for i, tr := range Tiers {
		if !from.Before(now.Add(-tr.keep)) && int(to.Sub(from)/tr.step) <= maxPoints*12 {
			ti = i
			break
		}
	}
	tr := Tiers[ti]
	step := int64(tr.step / time.Second)
	f := from.Unix() - from.Unix()%step
	n := int((to.Unix() - f + step - 1) / step)
	group := (n + maxPoints - 1) / maxPoints
	if group < 1 {
		group = 1
	}
	res := &HistoryResult{From: time.Unix(f, 0).UTC(), To: to.UTC(), Step: int(step) * group, Tier: ti, Series: []SeriesData{}}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, name := range names {
		id, ok := h.ids[name]
		m := h.meta[name]
		sd := SeriesData{Name: name, Label: m.Label, Unit: m.Unit, Values: []*float64{}}
		if ok {
			vals, err := h.values(ctx, id, ti, time.Unix(f, 0), to)
			if err != nil {
				return nil, err
			}
			for i := 0; i < len(vals); i += group {
				var sum float64
				cnt := 0
				for _, v := range vals[i:min(i+group, len(vals))] {
					if !math.IsNaN(float64(v)) {
						sum += float64(v)
						cnt++
					}
				}
				if cnt == 0 {
					sd.Values = append(sd.Values, nil)
				} else {
					avg := math.Round(sum/float64(cnt)*1000) / 1000
					sd.Values = append(sd.Values, &avg)
				}
			}
		}
		res.Series = append(res.Series, sd)
	}
	return res, nil
}

// ExpandNames turns "prefix:*" patterns into the matching series names.
func (h *History) ExpandNames(patterns []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range patterns {
		if strings.HasSuffix(p, "*") {
			pre := strings.TrimSuffix(p, "*")
			for _, s := range h.Series() {
				if strings.HasPrefix(s.Name, pre) && !seen[s.Name] {
					out = append(out, s.Name)
					seen[s.Name] = true
				}
			}
			continue
		}
		if !seen[p] {
			out = append(out, p)
			seen[p] = true
		}
	}
	return out
}
