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
}

// HACheck says whether a local app can move to cluster storage.
func (m *Manager) HACheck(ctx context.Context, id string) (*HACheckResult, error) {
	ia, c, err := m.app(ctx, id)
	if err != nil {
		return nil, err
	}
	res := &HACheckResult{ID: id, Name: ia.manifest.Name, Dir: ia.dir, UID: ia.state.UID, MemoryMB: ia.state.Limits.MemoryMB,
		Images: []string{}, Problems: []string{}}
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
	if len(ia.state.Shares) > 0 {
		names := make([]string, 0, len(ia.state.Shares))
		for n := range ia.state.Shares {
			names = append(names, n)
		}
		sort.Strings(names)
		res.Problems = append(res.Problems, "it uses shared folders ("+strings.Join(names, ", ")+"); apps with shared folders stay on their server for now")
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

var convRE = regexp.MustCompile(`^[a-z0-9]{8,32}$`)

// HAHoldArgs is apps.ha.hold.
type HAHoldArgs struct {
	ID   string `json:"id"`
	Conv string `json:"conv"`
	// Release ends the hold (its own conversion's only).
	Release bool `json:"release,omitempty"`
}

// ErrHeld: a conversion holds the app (it is being moved).
var ErrHeld = errors.New("it is being moved to or from cluster storage")

// HAHold holds a local app for a conversion: its containers removed (so
// Docker's restart policy can't start them), its dataset read-only and
// marked, so Start, Restart and updates refuse (Up) until the hold ends.
// The hold is on the dataset, so it outlives restarts of hardyd-priv.
func (m *Manager) HAHold(ctx context.Context, a HAHoldArgs) error {
	if !convRE.MatchString(a.Conv) {
		return Problems{"bad conversion id"}
	}
	ia, c, err := m.app(ctx, a.ID)
	if err != nil {
		return err
	}
	if ia.remote {
		return ErrClusterPlaced
	}
	ds := c.Pool + "/apps/" + a.ID
	cur := m.heldBy(ctx, ds)
	if a.Release {
		if cur == "" {
			return nil
		}
		if cur != a.Conv {
			return Problems{"another conversion holds it"}
		}
		for _, p := range []string{"readonly", PropHAHold} {
			if _, err := m.run(ctx, "zfs", "inherit", p, ds); err != nil {
				return err
			}
		}
		m.log().Info("apps: an app's conversion let go of it", "app", a.ID, "conv", a.Conv)
		return nil
	}
	if cur != "" && cur != a.Conv {
		return Problems{"another conversion holds it"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.runCompose(ctx, m.composeArgs(ia, "down", "--remove-orphans")...); err != nil {
		return err
	}
	if _, err := m.run(ctx, "zfs", "set", "readonly=on", PropHAHold+"="+a.Conv, ds); err != nil {
		return err
	}
	m.log().Warn("apps: held for a conversion (read-only, no containers)", "app", a.ID, "conv", a.Conv)
	return nil
}

// heldBy is the conversion holding an app's dataset ("" none).
func (m *Manager) heldBy(ctx context.Context, ds string) string {
	out, err := m.run(ctx, "zfs", "get", "-H", "-p", "-s", "local", "-o", "value", PropHAHold, ds)
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(out))
	if v == "-" {
		return ""
	}
	return v
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

// HAAdoptArgs rewrites a moved app's resolved compose file for the folder
// it is in now.
type HAAdoptArgs struct {
	ID string `json:"id"`
	// From is the folder the app was in before it moved.
	From string `json:"from"`
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
