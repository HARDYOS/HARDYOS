package replica

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// LocalItem is something on this server that can be replicated.
type LocalItem struct {
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	Pool      string `json:"pool"`
	Dataset   string `json:"dataset"`
	UsedBytes uint64 `json:"usedBytes"`
}

// Items finds shared folders, apps and VMs (in hardyd-priv: the shares,
// apps and VM managers).
type Items interface {
	List(ctx context.Context) ([]LocalItem, error)
	// Resolve returns the item's own top dataset; ErrNotFound if there's
	// no such item.
	Resolve(ctx context.Context, kind, id string) (string, error)
}

// Freezer runs snap with a VM's file systems frozen by its guest agent
// when it can (vms.Manager.Frozen); consistent says whether they were.
type Freezer func(ctx context.Context, vmID string, snap func(ctx context.Context) error) (consistent bool, err error)

// ErrNotFound means the item, replica or snapshot doesn't exist.
var ErrNotFound = errors.New("not found")

// Manager is the root side of replication. One per hardyd-priv.
type Manager struct {
	Runner  sysexec.Runner
	Starter Starter // nil: ExecStarter
	Items   Items
	Freeze  Freezer
	// Restore adopts what a restore brings back (nil: restores refused).
	Restore Restorer
	Log     *slog.Logger
	// Now is the clock; time.Now unless a test sets it.
	Now func() time.Time
	// BrowseDir is where replica snapshots are mounted to be browsed
	// (default /run/hardyos/replica-browse).
	BrowseDir string

	mu      sync.Mutex // snapshots and pruning, one at a time
	streams streams
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

func (m *Manager) starter() Starter {
	if m.Starter != nil {
		return m.Starter
	}
	return ExecStarter{}
}

func (m *Manager) zfs(ctx context.Context, args ...string) ([]byte, error) {
	return sysexec.Output(ctx, m.Runner, "zfs", args...)
}

func (m *Manager) exists(ctx context.Context, ds string) (typ string, ok bool) {
	out, err := m.zfs(ctx, "list", "-H", "-o", "type", ds)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

func lines(b []byte) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimRight(l, "\r"); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// ---- source side -----------------------------------------------------------

// Child is one dataset of an item's tree, relative to the item.
type Child struct {
	Child string `json:"child"` // "" is the item itself
	Type  string `json:"type"`  // filesystem or volume
}

// SnapshotArgs takes a replication snapshot of an item.
type SnapshotArgs struct {
	Task string `json:"task"`
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// SnapshotResult is the snapshot taken and what it covers.
type SnapshotResult struct {
	Snapshot   string  `json:"snapshot"`
	Pool       string  `json:"pool"`
	Children   []Child `json:"children"`
	Consistent bool    `json:"consistent"`
}

func (m *Manager) resolve(ctx context.Context, kind, id string) (string, error) {
	if err := (Item{Kind: kind, ID: id}).Validate(); err != nil {
		return "", err
	}
	if m.Items == nil {
		return "", ErrNotFound
	}
	ds, err := m.Items.Resolve(ctx, kind, id)
	if err != nil {
		return "", err
	}
	if err := zfs.ValidDatasetName(ds); err != nil {
		return "", err
	}
	return ds, nil
}

// children lists an item's datasets (the item first), relative to it.
func (m *Manager) children(ctx context.Context, ds string) ([]Child, error) {
	out, err := m.zfs(ctx, "list", "-H", "-o", "name,type", "-r", "-t", "filesystem,volume", ds)
	if err != nil {
		return nil, err
	}
	var res []Child
	for _, l := range lines(out) {
		f := strings.Split(l, "\t")
		if len(f) != 2 {
			return nil, fmt.Errorf("unexpected zfs list output %q", l)
		}
		rel := ""
		if f[0] != ds {
			r, ok := strings.CutPrefix(f[0], ds+"/")
			if !ok {
				return nil, fmt.Errorf("zfs listed %s under %s", f[0], ds)
			}
			rel = r
		}
		if err := ValidChild(rel); err != nil {
			return nil, fmt.Errorf("%s can't be replicated: %w", f[0], err)
		}
		if f[1] != "filesystem" && f[1] != "volume" {
			continue
		}
		res = append(res, Child{Child: rel, Type: f[1]})
	}
	if len(res) == 0 || res[0].Child != "" {
		return nil, fmt.Errorf("%s: %w", ds, ErrNotFound)
	}
	sort.SliceStable(res[1:], func(i, j int) bool { return res[1+i].Child < res[1+j].Child })
	return res, nil
}

// Snapshot takes a replication snapshot of an item and all its datasets
// at once (zfs snapshot -r: one transaction group). A running VM's file
// systems are frozen for that moment when its guest agent can.
func (m *Manager) Snapshot(ctx context.Context, a SnapshotArgs) (*SnapshotResult, error) {
	if err := ValidTask(a.Task); err != nil {
		return nil, err
	}
	ds, err := m.resolve(ctx, a.Kind, a.ID)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	kids, err := m.children(ctx, ds)
	if err != nil {
		return nil, err
	}
	label := SnapName(a.Task, m.now())
	if _, ok := m.exists(ctx, ds+"@"+label); ok {
		return nil, fmt.Errorf("the snapshot %s already exists; try again in a second", label)
	}
	take := func(ctx context.Context) error {
		_, err := m.zfs(ctx, "snapshot", "-r", ds+"@"+label)
		return err
	}
	consistent := true
	if a.Kind == KindVM && m.Freeze != nil {
		consistent, err = m.Freeze(ctx, a.ID, take)
	} else {
		err = take(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("taking the snapshot: %w", err)
	}
	pool, _, _ := strings.Cut(ds, "/")
	m.log().Info("replication: snapshot", "dataset", ds, "snapshot", label, "consistent", consistent)
	return &SnapshotResult{Snapshot: label, Pool: pool, Children: kids, Consistent: consistent}, nil
}

// SnapInfo is one snapshot.
type SnapInfo struct {
	Name    string    `json:"name"` // the label after @
	GUID    string    `json:"guid"`
	Created time.Time `json:"created"`
}

// listSnaps lists ds's snapshots (only its own, -d 1) whose labels are
// replication snapshots (of task, when it's not empty), oldest first.
func (m *Manager) listSnaps(ctx context.Context, ds, task string) ([]SnapInfo, error) {
	out, err := m.zfs(ctx, "list", "-H", "-p", "-t", "snapshot", "-o", "name,guid,creation", "-d", "1", ds)
	if err != nil {
		return nil, err
	}
	var res []SnapInfo
	for _, l := range lines(out) {
		f := strings.Split(l, "\t")
		if len(f) != 3 {
			continue
		}
		name, label, ok := strings.Cut(f[0], "@")
		if !ok || name != ds {
			continue
		}
		tk, at, ok := ParseSnap(label)
		if !ok || (task != "" && tk != task) {
			continue
		}
		if _, err := strconv.ParseUint(f[1], 10, 64); err != nil {
			continue
		}
		created := at
		if n, err := strconv.ParseInt(f[2], 10, 64); err == nil {
			created = time.Unix(n, 0).UTC()
		}
		res = append(res, SnapInfo{Name: label, GUID: f[1], Created: created})
	}
	sortSnaps(res)
	return res, nil
}

// sortSnaps orders by the time in the label (then the label).
func sortSnaps(l []SnapInfo) {
	sort.SliceStable(l, func(i, j int) bool {
		_, a, _ := ParseSnap(l[i].Name)
		_, b, _ := ParseSnap(l[j].Name)
		if !a.Equal(b) {
			return a.Before(b)
		}
		return l[i].Name < l[j].Name
	})
}

// LocalSnapshotsArgs names one dataset of an item.
type LocalSnapshotsArgs struct {
	Task  string `json:"task"`
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Child string `json:"child"`
}

// LocalSnapshots lists a task's snapshots of one dataset of an item.
func (m *Manager) LocalSnapshots(ctx context.Context, a LocalSnapshotsArgs) ([]SnapInfo, error) {
	if err := ValidTask(a.Task); err != nil {
		return nil, err
	}
	if err := ValidChild(a.Child); err != nil {
		return nil, err
	}
	ds, err := m.resolve(ctx, a.Kind, a.ID)
	if err != nil {
		return nil, err
	}
	l, err := m.listSnaps(ctx, ds+childSuffix(a.Child), a.Task)
	if l == nil {
		l = []SnapInfo{}
	}
	return l, err
}

// SendArgs starts a zfs send of one dataset of an item: the whole
// snapshot (From empty), the changes since From, or the rest of an
// interrupted stream (Token, from the receiver).
type SendArgs struct {
	Task     string `json:"task"`
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Child    string `json:"child"`
	Snapshot string `json:"snapshot"`
	From     string `json:"from,omitempty"`
	Token    string `json:"token,omitempty"`
}

// SendStart is a started send; the stream itself is the file handed over.
type SendStart struct {
	Stream string `json:"stream"`
	// Estimate is zfs's estimate of the stream's size in bytes (0 if it
	// didn't say).
	Estimate int64 `json:"estimate"`
	// Snapshot is the snapshot the stream carries.
	Snapshot string `json:"snapshot"`
}

// sendFlags: large blocks, embedded data and compressed blocks as they
// are on disk (no -p, -R, -I: properties and other datasets never travel;
// the receiver refuses such streams anyway).
var sendFlags = []string{"-L", "-e", "-c"}

// Send starts zfs send and returns the read end of its output. With a
// Token, Snapshot may be empty: the token names it (and must name one of
// this task's snapshots of exactly this dataset).
func (m *Manager) Send(ctx context.Context, a SendArgs) (*SendStart, *os.File, error) {
	if err := ValidTask(a.Task); err != nil {
		return nil, nil, err
	}
	if err := ValidChild(a.Child); err != nil {
		return nil, nil, err
	}
	if a.Snapshot != "" || a.Token == "" {
		if err := ValidSnap(a.Snapshot, a.Task); err != nil {
			return nil, nil, err
		}
	}
	top, err := m.resolve(ctx, a.Kind, a.ID)
	if err != nil {
		return nil, nil, err
	}
	ds := top + childSuffix(a.Child)
	if a.Token != "" {
		if err := ValidToken(a.Token); err != nil {
			return nil, nil, err
		}
		// The token comes from the receiver: it names what to send, so it
		// must name this dataset and one of this task's snapshots.
		out, err := m.zfs(ctx, "send", "-n", "-v", "-P", "-t", a.Token)
		if err != nil {
			return nil, nil, fmt.Errorf("the interrupted transfer can't be resumed: %w", err)
		}
		to := tokenToName(out)
		name, label, _ := strings.Cut(to, "@")
		if name != ds || ValidSnap(label, a.Task) != nil || (a.Snapshot != "" && label != a.Snapshot) {
			return nil, nil, invalid("the resume token is for %q, not a snapshot of %s", to, ds)
		}
		st, f, err := m.startSend([]string{"send", "-t", a.Token}, sizeOf(out))
		if st != nil {
			st.Snapshot = label
		}
		return st, f, err
	}
	snap := ds + "@" + a.Snapshot
	if _, ok := m.exists(ctx, snap); !ok {
		return nil, nil, fmt.Errorf("snapshot %s: %w", snap, ErrNotFound)
	}
	var args []string
	if a.From != "" {
		if err := ValidSnap(a.From, a.Task); err != nil {
			return nil, nil, err
		}
		if a.From == a.Snapshot {
			return nil, nil, invalid("nothing to send: the replica already has %s", a.Snapshot)
		}
		if _, ok := m.exists(ctx, ds+"@"+a.From); !ok {
			return nil, nil, fmt.Errorf("snapshot %s@%s: %w", ds, a.From, ErrNotFound)
		}
		args = append(append([]string{"send"}, sendFlags...), "-i", ds+"@"+a.From, snap)
	} else {
		args = append(append([]string{"send"}, sendFlags...), snap)
	}
	var est int64
	if out, err := m.zfs(ctx, append([]string{"send", "-n", "-P"}, args[1:]...)...); err == nil {
		est = sizeOf(out)
	}
	st, f, err := m.startSend(args, est)
	if st != nil {
		st.Snapshot = a.Snapshot
	}
	return st, f, err
}

func (m *Manager) startSend(args []string, est int64) (*SendStart, *os.File, error) {
	s, err := m.streams.add("")
	if err != nil {
		return nil, nil, err
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		s.finish(err)
		return nil, nil, err
	}
	errs := &tail{}
	p, err := m.starter().Start("zfs", args, nil, pw, errs)
	pw.Close() // the command has its own copy
	if err != nil {
		pr.Close()
		s.finish(err)
		return nil, nil, err
	}
	s.mu.Lock()
	s.proc = p
	s.mu.Unlock()
	go func() {
		err := p.Wait()
		if err != nil {
			if msg := errs.String(); msg != "" {
				err = fmt.Errorf("zfs send: %s", msg)
			} else {
				err = fmt.Errorf("zfs send: %w", err)
			}
		}
		s.finish(err)
	}()
	what := args[len(args)-1]
	if len(args) == 3 && args[1] == "-t" {
		what = "(resume)"
	}
	m.log().Info("replication: send", "stream", s.id, "what", what)
	return &SendStart{Stream: s.id, Estimate: est}, pr, nil
}

// sizeOf reads "size\t<n>" from zfs send -P's dry run.
func sizeOf(out []byte) int64 {
	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) == 2 && f[0] == "size" {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			return n
		}
	}
	return 0
}

// tokenToName reads "toname = <name>" from zfs send -nv -t.
func tokenToName(out []byte) string {
	for _, l := range lines(out) {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if ok && strings.TrimSpace(k) == "toname" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// StreamArgs names a running send or receive.
type StreamArgs struct {
	Stream string `json:"stream"`
}

// Stream reports a send's or receive's state.
func (m *Manager) Stream(id string) (*StreamState, error) {
	s, err := m.streams.get(id)
	if err != nil {
		return nil, err
	}
	st := s.state()
	return &st, nil
}

// Cancel kills a running send or receive (its whole process group).
func (m *Manager) Cancel(id string) error {
	s, err := m.streams.get(id)
	if err != nil {
		return err
	}
	s.cancel()
	return nil
}

// PruneArgs removes a task's older snapshots of an item. Keep is how
// many to keep (at least 1, except when Forget removes them all because
// the task is gone); Protect names labels that stay whatever happens (the
// last snapshot both sides have).
type PruneArgs struct {
	Task    string   `json:"task"`
	Kind    string   `json:"kind"`
	ID      string   `json:"id"`
	Keep    int      `json:"keep"`
	Protect []string `json:"protect,omitempty"`
	Forget  bool     `json:"forget,omitempty"`
}

// PruneResult lists the labels removed.
type PruneResult struct {
	Deleted []string `json:"deleted"`
}

// Prune deletes a task's replication snapshots of an item beyond Keep.
// Only labels of that task are touched; user, automatic, app and VM
// snapshots never are.
func (m *Manager) Prune(ctx context.Context, a PruneArgs) (*PruneResult, error) {
	if err := ValidTask(a.Task); err != nil {
		return nil, err
	}
	for _, p := range a.Protect {
		if err := ValidSnap(p, a.Task); err != nil {
			return nil, err
		}
	}
	if a.Keep < 1 && !a.Forget {
		a.Keep = 1
	}
	if a.Forget {
		a.Keep, a.Protect = 0, nil
	}
	ds, err := m.resolve(ctx, a.Kind, a.ID)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pruneTree(ctx, ds, a.Task, a.Keep, a.Protect)
}

// pruneTree prunes a task's snapshots across an item's datasets. A label
// is only a candidate when it's older than the newest label every
// dataset has (a dataset that missed the last run keeps what it shares
// with the other side), and the newest Keep of those every dataset has
// stay.
func (m *Manager) pruneTree(ctx context.Context, top, task string, keep int, protect []string) (*PruneResult, error) {
	out, err := m.zfs(ctx, "list", "-H", "-o", "name", "-t", "snapshot", "-r", top)
	if err != nil {
		return nil, err
	}
	kids, err := m.children(ctx, top)
	if err != nil {
		return nil, err
	}
	has := map[string]map[string]bool{} // label -> datasets
	for _, l := range lines(out) {
		ds, label, ok := strings.Cut(l, "@")
		if !ok || !(ds == top || strings.HasPrefix(ds, top+"/")) {
			continue
		}
		if tk, _, ok := ParseSnap(label); !ok || tk != task {
			continue
		}
		if has[label] == nil {
			has[label] = map[string]bool{}
		}
		has[label][ds] = true
	}
	var common, all []SnapInfo
	for label, dss := range has {
		all = append(all, SnapInfo{Name: label})
		if len(dss) == len(kids) {
			common = append(common, SnapInfo{Name: label})
		}
	}
	sortSnaps(common)
	sortSnaps(all)
	stay := map[string]bool{}
	for _, p := range protect {
		stay[p] = true
	}
	if keep > 0 {
		if len(common) == 0 {
			return &PruneResult{Deleted: []string{}}, nil // nothing every dataset shares: keep all
		}
		for i := len(common) - 1; i >= 0 && i >= len(common)-keep; i-- {
			stay[common[i].Name] = true
		}
		_, newest, _ := ParseSnap(common[len(common)-1].Name)
		for _, s := range all {
			if _, t, _ := ParseSnap(s.Name); t.After(newest) {
				stay[s.Name] = true
			}
		}
	}
	res := &PruneResult{Deleted: []string{}}
	for _, s := range all {
		if stay[s.Name] {
			continue
		}
		// One dataset at a time (no -r): exactly the snapshots listed.
		var failed error
		for ds := range has[s.Name] {
			if _, err := m.zfs(ctx, "destroy", ds+"@"+s.Name); err != nil {
				failed = err
			}
		}
		if failed != nil {
			m.log().Warn("replication: pruning a snapshot", "dataset", top, "snapshot", s.Name, "err", failed)
			continue
		}
		res.Deleted = append(res.Deleted, s.Name)
	}
	sort.Strings(res.Deleted)
	if len(res.Deleted) > 0 {
		m.log().Info("replication: pruned", "dataset", top, "snapshots", len(res.Deleted))
	}
	return res, nil
}

// ListItems lists what can be replicated.
func (m *Manager) ListItems(ctx context.Context) ([]LocalItem, error) {
	if m.Items == nil {
		return []LocalItem{}, nil
	}
	l, err := m.Items.List(ctx)
	if l == nil {
		l = []LocalItem{}
	}
	return l, err
}
