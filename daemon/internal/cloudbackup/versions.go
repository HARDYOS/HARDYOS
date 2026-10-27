package cloudbackup

import (
	"context"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/fileworker"
	"github.com/hardyos/hardyos/daemon/internal/shares"
)

// A version is one run of a task: the restic snapshots that share its run
// tag, one per item (a VM has one for its settings and one per disk), and
// the run's manifest.

// VersionItem is one item in a version.
type VersionItem struct {
	Item     string            `json:"item"`
	Snapshot string            `json:"snapshot"` // folder items: the snapshot to browse
	Disks    map[string]string `json:"disks,omitempty"`
	Time     time.Time         `json:"time"`
	Files    int64             `json:"files"`
	Bytes    int64             `json:"bytes"`
}

// Version is one run.
type Version struct {
	Run      string        `json:"run"`
	Task     string        `json:"task"`
	Time     time.Time     `json:"time"`
	Manifest string        `json:"manifest,omitempty"`
	Items    []VersionItem `json:"items"`
}

type snapCache struct {
	mu sync.Mutex
	m  map[string]cachedSnaps
}

type cachedSnaps struct {
	at    time.Time
	snaps []Snapshot
}

var snapshotCache snapCache

func (c *snapCache) get(target string) ([]Snapshot, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[target]
	if !ok || time.Since(e.at) > 30*time.Second {
		return nil, false
	}
	return e.snaps, true
}

func (c *snapCache) put(target string, s []Snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]cachedSnaps{}
	}
	c.m[target] = cachedSnaps{at: time.Now(), snaps: s}
}

func (c *snapCache) drop(target string) {
	c.mu.Lock()
	delete(c.m, target)
	c.mu.Unlock()
}

func (r *Root) snapshots(ctx context.Context, repo *Repo) ([]Snapshot, error) {
	if s, ok := snapshotCache.get(repo.Target.ID); ok {
		return s, nil
	}
	s, err := r.Restic.Snapshots(ctx, repo)
	if err != nil {
		return nil, err
	}
	snapshotCache.put(repo.Target.ID, s)
	return s, nil
}

// GroupVersions turns snapshots into versions, newest first.
func GroupVersions(snaps []Snapshot) []Version {
	byRun := map[string]*Version{}
	items := map[string]map[string]*VersionItem{}
	for i := range snaps {
		s := &snaps[i]
		run, task, item := s.Tag("run"), s.Tag("task"), s.Tag("item")
		if run == "" || item == "" || ValidRunID(run) != nil {
			continue
		}
		v := byRun[run]
		if v == nil {
			v = &Version{Run: run, Task: task, Time: s.Time}
			byRun[run] = v
			items[run] = map[string]*VersionItem{}
		}
		if s.Time.Before(v.Time) {
			v.Time = s.Time
		}
		if item == "manifest" {
			v.Manifest = s.ID
			continue
		}
		vi := items[run][item]
		if vi == nil {
			vi = &VersionItem{Item: item, Time: s.Time}
			items[run][item] = vi
		}
		if s.Summary != nil {
			vi.Files += s.Summary.TotalFiles
			vi.Bytes += s.Summary.TotalBytes
		}
		part := s.Tag("part")
		if d, ok := strings.CutPrefix(part, "disk:"); ok {
			if vi.Disks == nil {
				vi.Disks = map[string]string{}
			}
			vi.Disks[d] = s.ID
			continue
		}
		vi.Snapshot = s.ID
	}
	out := []Version{}
	for run, v := range byRun {
		for _, vi := range items[run] {
			v.Items = append(v.Items, *vi)
		}
		sort.Slice(v.Items, func(i, j int) bool { return v.Items[i].Item < v.Items[j].Item })
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}

// Versions lists a destination's versions, newest first.
func (r *Root) Versions(ctx context.Context, target string) ([]Version, error) {
	repo, err := r.repo(target)
	if err != nil {
		return nil, err
	}
	s, err := r.snapshots(ctx, repo)
	if err != nil {
		return nil, err
	}
	return GroupVersions(s), nil
}

// findSnapshot looks a snapshot up and returns its item.
func (r *Root) findSnapshot(ctx context.Context, repo *Repo, id string) (*Snapshot, Item, error) {
	if !snapIDRE.MatchString(id) {
		return nil, Item{}, problemf("there's no such version")
	}
	l, err := r.snapshots(ctx, repo)
	if err != nil {
		return nil, Item{}, err
	}
	for i := range l {
		if l[i].ID == id || (len(id) >= 8 && l[i].ShortID == id) {
			it, err := ParseItem(l[i].Tag("item"))
			if err != nil || len(l[i].Paths) != 1 {
				return nil, Item{}, problemf("that version isn't one HardyOS made")
			}
			return &l[i], it, nil
		}
	}
	return nil, Item{}, problemf("there's no such version (it may have been removed by the task's retention)")
}

// Entry is a file or folder in a version.
type Entry struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	Dir      bool      `json:"dir"`
	Type     string    `json:"type"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

// BrowseArgs lists a folder of a version. Who is set for a person who
// isn't an administrator: only shared folders their rules let them read.
type BrowseArgs struct {
	Target   string          `json:"target"`
	Snapshot string          `json:"snapshot"`
	Path     string          `json:"path"`
	Who      *fileworker.Who `json:"who,omitempty"`
}

// cleanRel checks a path inside an item ("" is its top). Hidden names
// (.recycle, .zfs, .hardyos*) are refused like in the File Manager.
func cleanRel(p string) ([]string, error) {
	parts, err := fileworker.CleanPath(p)
	if err != nil {
		return nil, &Problem{Msg: err.Error()}
	}
	for _, c := range parts {
		if fileworker.UploadTempRE.MatchString(c) {
			return nil, problemf("that path can't be restored")
		}
	}
	return parts, nil
}

// checkWho checks that a person may see a shared folder's versions: the
// folder's rules give them at least read today.
func (r *Root) checkWho(ctx context.Context, who *fileworker.Who, it Item) error {
	if who == nil {
		return nil
	}
	if it.Kind != ItemShare {
		return problemf("only shared folders' versions can be opened")
	}
	if r.Files == nil {
		return problemf("restoring your own files isn't available")
	}
	level, err := r.Files.RulesLevel(ctx, *who, it.ID)
	if err != nil || level == shares.LevelNone {
		return problemf("you don't have access to that shared folder")
	}
	return nil
}

// Browse lists one folder of a version (not recursive).
func (r *Root) Browse(ctx context.Context, a BrowseArgs) ([]Entry, error) {
	repo, err := r.repo(a.Target)
	if err != nil {
		return nil, err
	}
	snap, it, err := r.findSnapshot(ctx, repo, a.Snapshot)
	if err != nil {
		return nil, err
	}
	if it.Kind != ItemShare && it.Kind != ItemApp {
		return nil, problemf("only shared folders and apps can be browsed")
	}
	if err := r.checkWho(ctx, a.Who, it); err != nil {
		return nil, err
	}
	parts, err := cleanRel(a.Path)
	if err != nil {
		return nil, err
	}
	base := snap.Paths[0]
	dir := path.Join(append([]string{base}, parts...)...)
	nodes, err := r.Restic.Ls(ctx, repo, snap.ID, dir)
	if err != nil {
		return nil, err
	}
	out := []Entry{}
	for _, n := range nodes {
		if fileworker.Hidden(n.Name) || (a.Who != nil && n.Type != "file" && n.Type != "dir") {
			continue
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(n.Path, base), "/")
		out = append(out, Entry{Name: n.Name, Path: rel, Dir: n.Type == "dir", Type: n.Type, Size: n.Size, Modified: n.ModTime})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}
