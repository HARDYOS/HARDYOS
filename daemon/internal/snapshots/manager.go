package snapshots

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// Shares is what the scheduler needs from the shared folders
// (*shares.Manager).
type Shares interface {
	List(ctx context.Context) ([]shares.Share, error)
	Get(ctx context.Context, id string) (*shares.Share, error)
}

// Snapshot is one snapshot of a shared folder.
type Snapshot struct {
	Name       string    `json:"name"` // the label after @
	Kind       string    `json:"kind"` // hourly, daily, weekly, monthly, manual, other
	CreatedAt  time.Time `json:"createdAt"`
	UsedBytes  uint64    `json:"usedBytes"`
	ReferBytes uint64    `json:"referBytes"`
}

// Manager takes automatic snapshots on schedule and serves the manual
// list, create and delete operations. It runs as root.
type Manager struct {
	Runner sysexec.Runner
	Shares Shares
	Log    *slog.Logger
	// Now is the clock (UTC); time.Now unless a test sets it.
	Now func() time.Time

	mu sync.Mutex // one tick or operation at a time
	// done remembers, per dataset, the plan (slots and counts) last carried
	// out completely, so an idle minute costs one `zfs list` of the shares.
	done map[string]string
}

func (m *Manager) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *Manager) zfs(ctx context.Context, args ...string) ([]byte, error) {
	return sysexec.Output(ctx, m.Runner, "zfs", args...)
}

func invalid(format string, a ...any) error {
	return &shares.ValidationError{Msg: fmt.Sprintf(format, a...)}
}

// ---- schedule --------------------------------------------------------------

// tickTimeout bounds one pass over every shared folder.
const tickTimeout = 5 * time.Minute

// Run ticks every minute (a couple of seconds after the minute starts)
// until ctx is done. The first tick runs at once, so the newest missed
// snapshot of each kind is taken when the server comes back.
func (m *Manager) Run(ctx context.Context) {
	for {
		tctx, cancel := context.WithTimeout(ctx, tickTimeout)
		m.Tick(tctx)
		cancel()
		now := time.Now()
		next := now.Truncate(time.Minute).Add(time.Minute + 2*time.Second)
		t := time.NewTimer(next.Sub(now))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// Tick takes the snapshots that are due and prunes old ones, for every
// mounted shared folder. It is idempotent: a snapshot is named after its
// slot, so running it twice in a slot takes nothing new. Missed slots are
// never back-filled; only the current slot of each kind is considered, so
// after a long power cut each kind gets one snapshot, named for its newest
// slot. One folder's failure doesn't stop the others.
func (m *Manager) Tick(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	l, err := m.Shares.List(ctx)
	if err != nil {
		m.log().Warn("snapshots: listing the shared folders failed", "err", err)
		return
	}
	if m.done == nil {
		m.done = map[string]string{}
	}
	seen := map[string]bool{}
	for _, sh := range l {
		seen[sh.Dataset] = true
		if !sh.Mounted {
			// Locked or not mounted: nothing can have changed in it, and
			// pruning waits until it's back.
			continue
		}
		key := plan(sh.Services.Snapshots, now)
		if m.done[sh.Dataset] == key {
			continue
		}
		if err := m.runShare(ctx, sh, now); err != nil {
			m.log().Warn("snapshots: automatic snapshots of a shared folder failed", "share", sh.ID, "dataset", sh.Dataset, "err", err)
			delete(m.done, sh.Dataset)
			continue
		}
		m.done[sh.Dataset] = key
	}
	for ds := range m.done {
		if !seen[ds] {
			delete(m.done, ds) // deleted, or its pool went away
		}
	}
}

// plan identifies what a tick does for a folder: the current slot of each
// kind kept and every count (a lower count prunes at once).
func plan(c shares.Snapshots, now time.Time) string {
	var b strings.Builder
	for _, k := range Kinds {
		n := Keep(k, c.Hourly, c.Daily, c.Weekly, c.Monthly)
		b.WriteString(strconv.Itoa(n))
		if n > 0 {
			b.WriteString("@" + Slot(k, now).Format(timeFormat))
		}
		b.WriteByte(';')
	}
	return b.String()
}

// runShare takes the folder's missing snapshots for now and prunes each
// kind to its count.
func (m *Manager) runShare(ctx context.Context, sh shares.Share, now time.Time) error {
	if err := zfs.ValidDatasetName(sh.Dataset); err != nil || sh.Dataset != shares.Dataset(sh.Pool, sh.ID) {
		return fmt.Errorf("%q isn't a shared folder dataset", sh.Dataset)
	}
	snaps, err := m.list(ctx, sh.Dataset)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, s := range snaps {
		have[s.Name] = true
	}
	c := sh.Services.Snapshots
	var take []string
	for _, k := range Kinds {
		if Keep(k, c.Hourly, c.Daily, c.Weekly, c.Monthly) <= 0 {
			continue
		}
		if name := Name(k, Slot(k, now)); !have[name] {
			take = append(take, name)
		}
	}
	var errs []error
	if len(take) > 0 {
		// One command: the kinds due at the same moment (midnight on a
		// Monday the 1st) are taken atomically, in one transaction group.
		args := []string{"snapshot"}
		for _, n := range take {
			args = append(args, sh.Dataset+"@"+n)
		}
		if _, err := m.zfs(ctx, args...); err != nil {
			errs = append(errs, fmt.Errorf("taking %s: %w", strings.Join(take, ", "), err))
		} else {
			for _, n := range take {
				have[n] = true
			}
			m.log().Info("snapshots: taken", "share", sh.ID, "snapshots", take)
		}
	}
	labels := make([]string, 0, len(have))
	for n := range have {
		labels = append(labels, n)
	}
	for _, n := range Prune(labels, c) {
		if _, err := m.zfs(ctx, "destroy", sh.Dataset+"@"+n); err != nil {
			errs = append(errs, fmt.Errorf("deleting the old snapshot %s: %w", n, err))
			continue
		}
		m.log().Info("snapshots: pruned", "share", sh.ID, "snapshot", n)
	}
	return errors.Join(errs...)
}

// Prune returns the automatic snapshots to delete so that each kind keeps
// only its newest count (by slot time), oldest first. Labels that aren't exactly an
// automatic snapshot's are never returned.
func Prune(labels []string, c shares.Snapshots) []string {
	byKind := map[Kind][]struct {
		label string
		slot  time.Time
	}{}
	for _, l := range labels {
		k, t, ok := Parse(l)
		if !ok {
			continue
		}
		byKind[k] = append(byKind[k], struct {
			label string
			slot  time.Time
		}{l, t})
	}
	var out []string
	for _, k := range Kinds {
		l := byKind[k]
		sort.Slice(l, func(i, j int) bool { return l[i].slot.After(l[j].slot) })
		keep := Keep(k, c.Hourly, c.Daily, c.Weekly, c.Monthly)
		if keep < 0 {
			keep = 0
		}
		for i := len(l) - 1; i >= keep; i-- { // oldest first
			out = append(out, l[i].label)
		}
	}
	return out
}

// ---- listing ---------------------------------------------------------------

var snapListCols = "name,used,refer,creation," + PropMade

// list returns the dataset's own snapshots, oldest first.
func (m *Manager) list(ctx context.Context, ds string) ([]Snapshot, error) {
	out, err := m.zfs(ctx, "list", "-Hp", "-t", "snapshot", "-o", snapListCols, "-s", "creation", "-d", "1", ds)
	if err != nil {
		return nil, fmt.Errorf("listing the snapshots of %s: %w", ds, err)
	}
	return parseList(out, ds), nil
}

func parseList(out []byte, ds string) []Snapshot {
	l := []Snapshot{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 5 {
			continue
		}
		d, label, ok := strings.Cut(f[0], "@")
		if !ok || d != ds || label == "" {
			continue
		}
		s := Snapshot{Name: label, Kind: KindOf(label, f[4])}
		s.UsedBytes, _ = strconv.ParseUint(f[1], 10, 64)
		s.ReferBytes, _ = strconv.ParseUint(f[2], 10, 64)
		if secs, err := strconv.ParseInt(f[3], 10, 64); err == nil {
			s.CreatedAt = time.Unix(secs, 0).UTC()
		}
		l = append(l, s)
	}
	return l
}

// share finds a shared folder and checks its dataset name.
func (m *Manager) share(ctx context.Context, id string) (*shares.Share, error) {
	sh, err := m.Shares.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if sh.Dataset != shares.Dataset(sh.Pool, sh.ID) || zfs.ValidDatasetName(sh.Dataset) != nil {
		return nil, fmt.Errorf("%q isn't a shared folder dataset", sh.Dataset)
	}
	return sh, nil
}

// List returns a shared folder's snapshots, newest first.
func (m *Manager) List(ctx context.Context, id string) ([]Snapshot, error) {
	sh, err := m.share(ctx, id)
	if err != nil {
		return nil, err
	}
	l, err := m.list(ctx, sh.Dataset)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(l, func(i, j int) bool { return l[i].CreatedAt.After(l[j].CreatedAt) })
	return l, nil
}

// ---- manual snapshots ------------------------------------------------------

// MaxNameLen bounds a manual snapshot's name.
const MaxNameLen = 64

var manualRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]*$`)

// CleanName checks a manual snapshot's name; "" becomes
// manual-<YYYY-MM-DD-HHMM> (UTC) at now.
func CleanName(name string, now time.Time) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "manual-" + now.UTC().Format(timeFormat), nil
	}
	switch {
	case len(name) > MaxNameLen:
		return "", invalid("the snapshot name is too long: at most %d characters", MaxNameLen)
	case !manualRE.MatchString(name):
		return "", invalid("the snapshot name %q can only have letters a-z, digits and . _ : - (no spaces), starting with a letter or digit", name)
	case reservedLabel(name):
		return "", invalid("names starting with %s are kept for automatic snapshots", AutoPrefix)
	}
	return name, nil
}

// Create takes a manual snapshot of a shared folder. Automatic pruning
// never deletes it.
func (m *Manager) Create(ctx context.Context, id, name string) (*Snapshot, error) {
	label, err := CleanName(name, m.now())
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sh, err := m.share(ctx, id)
	if err != nil {
		return nil, err
	}
	full := sh.Dataset + "@" + label
	if err := zfs.ValidSnapshotName(full); err != nil {
		return nil, invalid("%v", err)
	}
	l, err := m.list(ctx, sh.Dataset)
	if err != nil {
		return nil, err
	}
	for _, s := range l {
		if s.Name == label {
			return nil, invalid("%s already has a snapshot called %s", sh.Name, label)
		}
	}
	if _, err := m.zfs(ctx, "snapshot", "-o", PropMade+"="+MadeManual, full); err != nil {
		return nil, fmt.Errorf("taking a snapshot of %s: %w", sh.Name, err)
	}
	m.log().Info("snapshots: manual snapshot", "share", sh.ID, "snapshot", label)
	l, err = m.list(ctx, sh.Dataset)
	if err == nil {
		for _, s := range l {
			if s.Name == label {
				return &s, nil
			}
		}
	}
	return &Snapshot{Name: label, Kind: "manual", CreatedAt: m.now()}, nil
}

// Delete destroys one snapshot of a shared folder (never its dataset or
// other snapshots). Confirm must be the snapshot's name.
func (m *Manager) Delete(ctx context.Context, id, snapshot, confirm string) error {
	if strings.TrimSpace(confirm) != snapshot || snapshot == "" {
		return invalid("confirm with the snapshot's name: what it holds can't be brought back once it's deleted")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sh, err := m.share(ctx, id)
	if err != nil {
		return err
	}
	full := sh.Dataset + "@" + snapshot
	if err := zfs.ValidSnapshotName(full); err != nil {
		return invalid("%q isn't a snapshot name", snapshot)
	}
	l, err := m.list(ctx, sh.Dataset)
	if err != nil {
		return err
	}
	found := false
	for _, s := range l {
		found = found || s.Name == snapshot
	}
	if !found {
		return invalid("%s has no snapshot called %s", sh.Name, snapshot)
	}
	if _, err := m.zfs(ctx, "destroy", full); err != nil {
		return fmt.Errorf("deleting the snapshot %s: %w", snapshot, err)
	}
	// m.done is left alone: a deleted automatic snapshot isn't taken again
	// in the same slot.
	m.log().Info("snapshots: deleted", "share", sh.ID, "snapshot", snapshot)
	return nil
}
