package apps

// "Make highly available" and "Make local again" for apps
// (docs/plans/make-ha.md, decision 483): what the apps engine checks and
// rewrites when an app's folder moves between this server's pool and
// cluster storage. Copying the dataset is root's hacopy; here: what may
// become a cluster app, letting go of a stopped app before its folder is
// parked (its containers go, its data stays), and the folder's path in
// the resolved compose file wherever it lands.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// HACheckResult is what the conversion needs to know about a local app.
type HACheckResult struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Pool is the apps engine's pool; Dir the app's folder on it.
	Pool    string `json:"pool"`
	Dir     string `json:"dir"`
	Running bool   `json:"running"`
	UID     int    `json:"uid"`
	// Mode is the app's default data mode on cluster storage (nfs or
	// block) and why.
	Mode       string   `json:"mode"`
	ModeReason string   `json:"modeReason"`
	MemoryMB   int      `json:"memoryMB"`
	Images     []string `json:"images"`
	// Hash is the approved settings' hash of the app as it is now; the
	// conversion records the rewritten one after it is attached.
	Hash     string   `json:"hash"`
	Problems []string `json:"problems"`
	// Shares are the shared folders the app was given: they move to the
	// storage server with it (decision 500). Path is where this server
	// has each now (what its compose file names).
	Shares []HAShare `json:"shares"`
	// HeldBy is the conversion holding the app ("" none).
	HeldBy string `json:"heldBy,omitempty"`
}

// HAShare is one shared folder an app uses.
type HAShare struct {
	ID    string `json:"id"`
	Path  string `json:"path,omitempty"`
	Write bool   `json:"write"`
}

// HACheck says whether a local app can move to cluster storage.
func (m *Manager) HACheck(ctx context.Context, id string) (*HACheckResult, error) {
	ia, c, err := m.app(ctx, id)
	if err != nil {
		return nil, err
	}
	res := &HACheckResult{ID: id, Name: ia.manifest.Name, Dir: ia.dir, UID: ia.state.UID, MemoryMB: ia.state.Limits.MemoryMB,
		Images: []string{}, Problems: []string{}, Shares: []HAShare{}}
	for _, l := range shareLevelsSorted(ia.state.Shares) {
		res.Shares = append(res.Shares, HAShare{ID: l.id, Write: l.write})
	}
	if ia.remote {
		res.Problems = append(res.Problems, ia.manifest.Name+" is on cluster storage already")
		return res, nil
	}
	res.Pool = c.Pool
	if err := m.guard(id); err != nil {
		res.Problems = append(res.Problems, err.Error())
	}
	if ia.state.Blocked != "" {
		res.Problems = append(res.Problems, "it may not start: "+ia.state.Blocked)
	}
	// Its shared folders move with it (decision 500): each one's folder
	// here, as its compose file names it; hardyd checks the rest (who else
	// uses them, the storage server's side).
	for i := range res.Shares {
		sh := &res.Shares[i]
		if m.Shares == nil {
			res.Problems = append(res.Problems, "shared folders aren't available on this server")
			break
		}
		p, err := m.Shares.Resolve(ctx, sh.ID, "")
		if err != nil {
			res.Problems = append(res.Problems, fmt.Sprintf("shared folder %s: %v", sh.ID, err))
			continue
		}
		sh.Path = filepath.Clean(p)
		if err := validSharePath(sh.Path, sh.ID); err != nil {
			res.Problems = append(res.Problems, fmt.Sprintf("shared folder %s: %v", sh.ID, err))
		}
	}
	for name, ch := range ia.state.Shares {
		if ch.Share != "" && ch.Path != "" {
			res.Problems = append(res.Problems, fmt.Sprintf("%s has a subfolder of shared folder %s for %s; choose the shared folder itself in its settings first", ia.manifest.Name, ch.Share, name))
		}
	}
	if ia.state.UID < FirstAppUID || ia.state.UID > LastAppUID {
		res.Problems = append(res.Problems, "it has no app user id")
	}
	cs := m.containers(ctx)
	for _, ct := range cs[id] {
		if ct.State == "running" || ct.State == "restarting" {
			res.Running = true
		}
	}
	compose, _ := readStateFile(ia.meta(ComposeFile))
	res.Mode, res.ModeReason = DefaultStorageMode(ia.manifest, compose)
	if r, err := m.resolved(ctx, ia); err == nil {
		for _, s := range r.Services() {
			if s.Image != "" && !slices.Contains(res.Images, s.Image) {
				res.Images = append(res.Images, s.Image)
			}
		}
		if len(res.Images) > MaxPrepull {
			res.Problems = append(res.Problems, fmt.Sprintf("it uses more than %d images", MaxPrepull))
		}
	} else {
		res.Problems = append(res.Problems, "its compose file doesn't pass the checks now: "+err.Error())
	}
	res.HeldBy = m.heldBy(ctx, c.Pool+"/apps/"+id)
	if res.Hash, err = m.clusterHash(ia); err != nil {
		return nil, err
	}
	return res, nil
}

// HARelease stops a local app and removes its containers (its folder and
// data stay), then runs park, which moves its folder away.
func (m *Manager) HARelease(ctx context.Context, id string, park func() error) error {
	ia, _, err := m.app(ctx, id)
	if err != nil {
		return err
	}
	if ia.remote {
		return ErrClusterPlaced
	}
	if err := m.guard(id); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.runCompose(ctx, m.composeArgs(ia, "down", "--remove-orphans")...); err != nil {
		return err
	}
	if err := park(); err != nil {
		return err
	}
	if err := m.removeSlice(ctx, id); err != nil {
		m.log().Warn("apps: removing a moved app's slice", "app", id, "err", err)
	}
	m.log().Warn("apps: let go of an app whose folder moves", "app", id)
	return nil
}

// PropHAHold marks an app's dataset held by a conversion (its id): from
// the conversion's final snapshot until its folder is parked, or the
// conversion gives up and starts it again, nothing may start or write it.
const PropHAHold = "org.hardyos:ha-hold"

// PropHAHoldRunning records, with a hold, whether the app ran before its
// conversion stopped it ("on"): the hold outlives hardyd and its record,
// so whatever ends the hold (Abandon, Undo) starts it again only then
// (decision 504).
const PropHAHoldRunning = "org.hardyos:ha-hold-running"

var convRE = regexp.MustCompile(`^[a-z0-9]{8,32}$`)

// HAHoldArgs is apps.ha.hold.
type HAHoldArgs struct {
	ID   string `json:"id"`
	Conv string `json:"conv"`
	// Release ends the hold (its own conversion's only).
	Release bool `json:"release,omitempty"`
	// WasRunning: the app ran before the conversion stopped it (recorded
	// with the hold; root also counts containers still running then).
	WasRunning bool `json:"wasRunning,omitempty"`
}

// HAHoldResult says what a release found: whether the conversion held the
// app, and whether it ran before the hold (its recorded state).
type HAHoldResult struct {
	Held       bool `json:"held"`
	WasRunning bool `json:"wasRunning"`
}

// ErrHeld: a conversion holds the app (it is being moved).
var ErrHeld = errors.New("it is being moved to or from cluster storage")

// HAHold holds a local app for a conversion: its containers removed (so
// Docker's restart policy can't start them), its dataset read-only and
// marked, so Start, Restart and updates refuse (Up) until the hold ends.
// The hold is on the dataset, so it outlives restarts of hardyd-priv.
func (m *Manager) HAHold(ctx context.Context, a HAHoldArgs) error {
	_, err := m.HAHoldState(ctx, a)
	return err
}

// HAHoldState is HAHold; a release reports what the hold recorded.
func (m *Manager) HAHoldState(ctx context.Context, a HAHoldArgs) (*HAHoldResult, error) {
	res := &HAHoldResult{}
	if !convRE.MatchString(a.Conv) {
		return nil, Problems{"bad conversion id"}
	}
	ia, c, err := m.app(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	if ia.remote {
		return nil, ErrClusterPlaced
	}
	ds := c.Pool + "/apps/" + a.ID
	cur := m.heldBy(ctx, ds)
	if a.Release {
		if cur == "" {
			return res, nil
		}
		if cur != a.Conv {
			return nil, Problems{"another conversion holds it"}
		}
		res.Held = true
		res.WasRunning = m.heldRunning(ctx, ds)
		for _, p := range []string{"readonly", PropHAHold, PropHAHoldRunning} {
			if _, err := m.run(ctx, "zfs", "inherit", p, ds); err != nil {
				return nil, err
			}
		}
		m.log().Info("apps: an app's conversion let go of it", "app", a.ID, "conv", a.Conv, "ranBefore", res.WasRunning)
		return res, nil
	}
	if cur != "" && cur != a.Conv {
		return nil, Problems{"another conversion holds it"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	running := a.WasRunning
	if cur == a.Conv {
		// Held already (a resumed conversion): what was recorded stays.
		running = running || m.heldRunning(ctx, ds)
	}
	for _, ct := range m.containers(ctx)[a.ID] {
		if ct.State == "running" || ct.State == "restarting" {
			running = true
		}
	}
	if _, err := m.runCompose(ctx, m.composeArgs(ia, "down", "--remove-orphans")...); err != nil {
		return nil, err
	}
	if _, err := m.run(ctx, "zfs", "set", "readonly=on", PropHAHold+"="+a.Conv, PropHAHoldRunning+"="+onOff(running), ds); err != nil {
		return nil, err
	}
	m.log().Warn("apps: held for a conversion (read-only, no containers)", "app", a.ID, "conv", a.Conv, "ranBefore", running)
	return res, nil
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// heldRunning is the state a hold recorded (only "on" counts).
func (m *Manager) heldRunning(ctx context.Context, ds string) bool {
	out, err := m.run(ctx, "zfs", "get", "-H", "-p", "-s", "local", "-o", "value", PropHAHoldRunning, ds)
	return err == nil && strings.TrimSpace(string(out)) == "on"
}

// heldBy is the conversion holding an app's dataset ("" none).
func (m *Manager) heldBy(ctx context.Context, ds string) string {
	out, err := m.run(ctx, "zfs", "get", "-H", "-p", "-s", "local", "-o", "value", PropHAHold, ds)
	if err != nil {
		return ""
	}
	// Only a conversion id is a hold (the mark is ours; anything else
	// there, or a tool answering something else, isn't).
	if v := strings.TrimSpace(string(out)); convRE.MatchString(v) {
		return v
	}
	return ""
}

// checkHeld refuses starting a held app.
func (m *Manager) checkHeld(ctx context.Context, ia *installedApp, c *EngineConfig) error {
	if c == nil || ia.remote {
		return nil
	}
	if conv := m.heldBy(ctx, c.Pool+"/apps/"+ia.state.ID); conv != "" {
		return Problems{fmt.Sprintf("%s %s (conversion %s): resume, abandon or undo it first", ia.manifest.Name, ErrHeld, conv)}
	}
	return nil
}

// rewriteDir replaces the app's folder from with to in every string of
// the resolved compose file that is that folder or a path below it.
func rewriteDir(b []byte, from, to string) ([]byte, int, error) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, 0, err
	}
	n := 0
	var walk func(x any) any
	walk = func(x any) any {
		switch t := x.(type) {
		case map[string]any:
			for k, e := range t {
				t[k] = walk(e)
			}
			return t
		case []any:
			for i, e := range t {
				t[i] = walk(e)
			}
			return t
		case string:
			if t == from {
				n++
				return to
			}
			if rest, ok := strings.CutPrefix(t, from+"/"); ok {
				n++
				return to + "/" + rest
			}
			return t
		}
		return x
	}
	v = walk(v)
	out, err := json.Marshal(v)
	return out, n, err
}

func validDir(dir, id string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || filepath.Base(dir) != id || filepath.Base(filepath.Dir(dir)) != "apps" {
		return Problems{fmt.Sprintf("%q isn't an app's folder", dir)}
	}
	return nil
}

type shareLevel struct {
	id    string
	write bool
}

// shareLevelsSorted is shareLevels in id order.
func shareLevelsSorted(ch map[string]ShareChoice) []shareLevel {
	lv := shareLevels(ch)
	ids := make([]string, 0, len(lv))
	for id := range lv {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]shareLevel, 0, len(ids))
	for _, id := range ids {
		out = append(out, shareLevel{id: id, write: lv[id]})
	}
	return out
}

// HAAdoptArgs rewrites a moved app's resolved compose file for the folder
// it is in now.
type HAAdoptArgs struct {
	ID string `json:"id"`
	// From is the folder the app was in before it moved.
	From string `json:"from"`
	// Shares are, for each shared folder that moved with it (decision
	// 500), the folder this server had it in: its compose file names that
	// one, and it is now the storage server's, mounted here.
	Shares map[string]string `json:"shares,omitempty"`
}

// validSharePath checks a shared folder's old folder: an absolute, clean
// path ending in shares/<id> (as shares.Manager mounts them).
func validSharePath(p, id string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || filepath.Base(p) != id || filepath.Base(filepath.Dir(p)) != "shares" ||
		strings.ContainsAny(p, "'\n\r\x00") {
		return Problems{fmt.Sprintf("%q isn't shared folder %s's folder", p, id)}
	}
	return nil
}

// ClusterAdopt rewrites a newly converted cluster app's resolved compose
// file (attached here) for its folder on cluster storage, checks it again
// and returns the hash of its approved settings.
func (m *Manager) ClusterAdopt(ctx context.Context, a HAAdoptArgs) (string, error) {
	if err := validDir(a.From, a.ID); err != nil {
		return "", err
	}
	ia, _, err := m.remote(ctx, a.ID)
	if err != nil {
		return "", err
	}
	if err := m.rewriteResolved(ia, a.From); err != nil {
		return "", err
	}
	if err := m.rewriteShares(ctx, ia, a.Shares); err != nil {
		return "", err
	}
	if err := m.clusterRecheck(ctx, ia); err != nil {
		return "", err
	}
	return m.clusterHash(ia)
}

// HALocal rewrites an app's resolved compose file after it came back from
// cluster storage to this server's pool.
func (m *Manager) HALocal(ctx context.Context, a HAAdoptArgs) error {
	if err := validDir(a.From, a.ID); err != nil {
		return err
	}
	ia, _, err := m.app(ctx, a.ID)
	if err != nil {
		return err
	}
	if ia.remote {
		return ErrClusterPlaced
	}
	if err := m.rewriteResolved(ia, a.From); err != nil {
		return err
	}
	_, err = m.resolved(ctx, ia)
	return err
}

// rewriteShares points a moved app's compose file at its shared folders
// on the storage server (mounted here): every shared folder it was given
// must be named, with the folder this server had it in, and must be
// mounted from the storage server now.
func (m *Manager) rewriteShares(ctx context.Context, ia *installedApp, old map[string]string) error {
	want := shareLevels(ia.state.Shares)
	if len(old) != len(want) {
		return Problems{fmt.Sprintf("%s uses %d shared folders; %d were named", ia.manifest.Name, len(want), len(old))}
	}
	if len(want) == 0 {
		return nil
	}
	res := m.sharesFor(ia)
	if res == nil || !ia.remote {
		return Problems{"shared folders on cluster storage aren't available here"}
	}
	b, err := readStateFile(ia.meta(resolvedFile))
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	total := 0
	for _, id := range ids {
		from, ok := old[id]
		if !ok {
			return Problems{fmt.Sprintf("shared folder %s wasn't named", id)}
		}
		if err := validSharePath(from, id); err != nil {
			return err
		}
		to, err := res.Resolve(ctx, id, "")
		if err != nil {
			return fmt.Errorf("shared folder %s: %w", id, err)
		}
		to = filepath.Clean(to)
		if !filepath.IsAbs(to) || strings.ContainsAny(to, "'\n\r\x00") {
			return Problems{fmt.Sprintf("shared folder %s's path can't be used", id)}
		}
		if from == to {
			continue
		}
		out, n, err := rewriteDir(b, from, to)
		if err != nil {
			return fmt.Errorf("the resolved compose file: %w", err)
		}
		b, total = out, total+n
	}
	if _, err := ParseResolved(b); err != nil {
		return err
	}
	if err := writeFileAtomic(ia.meta(resolvedFile), b, 0o600); err != nil {
		return err
	}
	m.log().Info("apps: moved app's shared folders written in its compose file", "app", ia.state.ID, "shares", len(ids), "paths", total)
	return nil
}

func (m *Manager) rewriteResolved(ia *installedApp, from string) error {
	if from == ia.dir {
		return nil
	}
	b, err := readStateFile(ia.meta(resolvedFile))
	if err != nil {
		return err
	}
	out, n, err := rewriteDir(b, from, ia.dir)
	if err != nil {
		return fmt.Errorf("the resolved compose file: %w", err)
	}
	if _, err := ParseResolved(out); err != nil {
		return err
	}
	if err := writeFileAtomic(ia.meta(resolvedFile), out, 0o600); err != nil {
		return err
	}
	m.log().Info("apps: moved app's folder written in its compose file", "app", ia.state.ID, "from", from, "to", ia.dir, "paths", n)
	return nil
}
