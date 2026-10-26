package apps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Changing an installed app: its settings, snapshots of its dataset before
// updates, and going back to one.

const (
	// imagesFile records the image each service ran when a snapshot was
	// taken, so a rollback can put moving tags ("latest") back.
	imagesFile = "images.json"
	// versionProp is set on each snapshot: the app version it holds.
	versionProp = "org.hardyos:app-version"
	// keepUpdateSnapshots is how many hardyos-update-* snapshots are kept.
	keepUpdateSnapshots = 3
)

var (
	snapNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:+-]{0,200}$`)
	imageIDRE  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// installedPackage rebuilds the package the app was installed from.
func installedPackage(ia *installedApp) (*Package, error) {
	mf := ia.manifest
	if err := mf.Validate(); err != nil {
		return nil, err
	}
	compose, err := os.ReadFile(ia.meta(ComposeFile))
	if err != nil {
		return nil, err
	}
	pkg := &Package{Manifest: mf, Compose: compose}
	if mf.Icon != "" {
		pkg.Icon, _ = os.ReadFile(ia.meta("icon" + filepath.Ext(mf.Icon)))
	}
	return pkg, nil
}

// Reconfigure changes an installed app's settings, ports, shares, grants
// and limits; the caller then runs Up.
func (m *Manager) Reconfigure(ctx context.Context, a ReconfigureArgs) (*PrepareResult, error) {
	if !m.Available() {
		return nil, errors.New("this HardyOS build doesn't include Docker")
	}
	ia, _, err := m.app(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	pkg, err := installedPackage(ia)
	if err != nil {
		return nil, err
	}
	// A password left empty keeps the one the app has.
	settings := map[string]string{}
	for k, v := range a.Settings {
		if s := ia.manifest.Setting(k); s != nil && s.Type == "password" && v == "" {
			continue
		}
		settings[k] = v
	}
	pa := PrepareArgs{Ports: a.Ports, Settings: settings, Shares: a.Shares, Limits: a.Limits}
	if a.Grants != nil {
		pa.Grants = append([]string{}, (*a.Grants)...)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.prepare(ctx, pkg, pa, true)
}

// Config returns the app's current configuration. Secret values never
// leave: passwords come back empty with Set, generated secrets not at all.
func (m *Manager) Config(ctx context.Context, id string) (*AppConfig, error) {
	ia, _, err := m.app(ctx, id)
	if err != nil {
		return nil, err
	}
	env := map[string]string{}
	if b, err := os.ReadFile(ia.meta(envFile)); err == nil {
		env = parseEnv(b)
	}
	cfg := &AppConfig{
		ID: ia.state.ID, Source: ia.state.Source, SourceName: ia.state.SourceName, UID: ia.state.UID,
		Manifest: ia.manifest, Ports: map[string]int{}, Settings: []SettingValue{}, Shares: ia.shares(),
		Grants: append([]string{}, ia.state.Grants...), Limits: ia.state.Limits,
	}
	if cfg.Source == "" {
		cfg.Source = SourceCatalog
	}
	for k, v := range ia.state.Ports {
		cfg.Ports[k] = v
	}
	for _, s := range ia.manifest.Settings {
		if s.Hidden() {
			continue
		}
		v, ok := env[s.Env]
		if !ok {
			v = ia.state.Settings[s.Env]
		}
		sv := SettingValue{Env: s.Env, Value: v, Set: v != ""}
		if s.Secret() {
			sv.Value = ""
		}
		cfg.Settings = append(cfg.Settings, sv)
	}
	return cfg, nil
}

// Snapshot takes a snapshot of the app's dataset and returns its name.
// Update snapshots beyond the newest three are deleted.
func (m *Manager) Snapshot(ctx context.Context, a SnapshotArgs) (string, error) {
	if a.Reason != "update" && a.Reason != "manual" {
		return "", Problems{"reason must be update or manual"}
	}
	ia, _, err := m.app(ctx, a.ID)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recordImages(ctx, ia)
	name := fmt.Sprintf("hardyos-%s-%s", a.Reason, m.now().Format("20060102-150405"))
	if _, err := m.run(ctx, "zfs", "snapshot", "-o", versionProp+"="+ia.manifest.Version, ia.dataset+"@"+name); err != nil {
		return "", fmt.Errorf("snapshotting %s: %w", ia.dataset, err)
	}
	snaps, err := m.snapshots(ctx, ia.dataset)
	if err != nil {
		m.log().Warn("apps: listing snapshots failed", "app", a.ID, "err", err)
		return name, nil
	}
	kept := 0
	for _, s := range snaps { // newest first
		if !strings.HasPrefix(s.Name, "hardyos-update-") {
			continue
		}
		if kept++; kept <= keepUpdateSnapshots {
			continue
		}
		if _, err := m.run(ctx, "zfs", "destroy", ia.dataset+"@"+s.Name); err != nil {
			m.log().Warn("apps: deleting an old update snapshot failed", "app", a.ID, "snapshot", s.Name, "err", err)
		}
	}
	m.log().Info("apps: snapshot", "app", a.ID, "snapshot", name)
	return name, nil
}

// recordImages notes the image each service runs now (best effort).
func (m *Manager) recordImages(ctx context.Context, ia *installedApp) {
	r, err := m.resolved(ctx, ia)
	if err != nil {
		return
	}
	images := map[string]string{}
	for _, s := range r.Services() {
		out, err := m.run(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", s.Image)
		if id := strings.TrimSpace(string(out)); err == nil && imageIDRE.MatchString(id) {
			images[s.Image] = id
		}
	}
	if err := writeFileAtomic(ia.meta(imagesFile), mustJSON(images), 0o600); err != nil {
		m.log().Warn("apps: recording images failed", "app", ia.state.ID, "err", err)
	}
}

// Snapshots lists the app's snapshots, newest first.
func (m *Manager) Snapshots(ctx context.Context, id string) ([]Snapshot, error) {
	ia, _, err := m.app(ctx, id)
	if err != nil {
		return nil, err
	}
	return m.snapshots(ctx, ia.dataset)
}

func (m *Manager) snapshots(ctx context.Context, ds string) ([]Snapshot, error) {
	out, err := m.run(ctx, "zfs", "list", "-H", "-p", "-t", "snapshot", "-o", "name,creation,"+versionProp, "-s", "creation", "-d", "1", ds)
	if err != nil {
		return nil, fmt.Errorf("listing snapshots of %s: %w", ds, err)
	}
	res := []Snapshot{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 3 {
			continue
		}
		dsName, snap, ok := strings.Cut(f[0], "@")
		if !ok || dsName != ds {
			continue
		}
		s := Snapshot{Name: snap}
		if secs, err := strconv.ParseInt(f[1], 10, 64); err == nil {
			s.Created = time.Unix(secs, 0).UTC()
		}
		if v := strings.TrimSpace(f[2]); v != "-" {
			s.Version = v
		}
		res = append(res, s)
	}
	sort.SliceStable(res, func(i, j int) bool { return res[i].Created.After(res[j].Created) })
	return res, nil
}

// Rollback puts the app back to a snapshot: it stops the app, rolls its
// dataset back (later snapshots go) and starts it with the package,
// settings, shares and limits the snapshot holds. Confirm is the app's name.
func (m *Manager) Rollback(ctx context.Context, a RollbackArgs) error {
	ia, c, err := m.app(ctx, a.ID)
	if err != nil {
		return err
	}
	if !confirmed(a.Confirm, ia) {
		return Problems{fmt.Sprintf("type the app's name (%s) to confirm", ia.manifest.Name)}
	}
	if !snapNameRE.MatchString(a.Snapshot) {
		return Problems{fmt.Sprintf("%q isn't a snapshot name", a.Snapshot)}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	snaps, err := m.snapshots(ctx, ia.dataset)
	if err != nil {
		return err
	}
	found := false
	for _, s := range snaps {
		found = found || s.Name == a.Snapshot
	}
	if !found {
		return Problems{fmt.Sprintf("%s has no snapshot called %s", ia.manifest.Name, a.Snapshot)}
	}
	if _, err := m.runCompose(ctx, m.composeArgs(ia, "stop")...); err != nil {
		return fmt.Errorf("stopping %s: %w", ia.manifest.Name, err)
	}
	if _, err := m.run(ctx, "zfs", "rollback", "-r", ia.dataset+"@"+a.Snapshot); err != nil {
		return fmt.Errorf("rolling back %s: %w", ia.dataset, err)
	}
	back, err := m.load(ctx, c, a.ID)
	if err != nil {
		return fmt.Errorf("reading %s after the rollback: %w", ia.manifest.Name, err)
	}
	if back.state.Removed {
		back.state.Removed = false
	}
	back.state.UpdatedAt = m.now()
	if err := writeFileAtomic(back.meta(stateFile), mustJSON(back.state), 0o600); err != nil {
		return err
	}
	// The snapshot's shared folder choices, as they were then.
	var live map[string]ShareChoice
	if !ia.state.Removed {
		live = ia.state.Shares
	}
	if err := m.applyShareGrants(ctx, a.ID, back.state.UID, live, back.state.Shares); err != nil {
		return err
	}
	m.restoreImages(ctx, back)
	m.log().Info("apps: rolled back", "app", a.ID, "snapshot", a.Snapshot, "version", back.manifest.Version)
	return m.up(ctx, back, c)
}

// restoreImages points moving tags back at the images the snapshot ran,
// where those are still on the server.
func (m *Manager) restoreImages(ctx context.Context, ia *installedApp) {
	b, err := os.ReadFile(ia.meta(imagesFile))
	if err != nil {
		return
	}
	var images map[string]string
	if json.Unmarshal(b, &images) != nil {
		return
	}
	r, err := readResolvedFile(ia.meta(resolvedFile))
	if err != nil {
		return
	}
	for _, s := range r.Services() {
		id := images[s.Image]
		if !imageIDRE.MatchString(id) {
			continue
		}
		out, err := m.run(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", s.Image)
		if err == nil && strings.TrimSpace(string(out)) == id {
			continue
		}
		if _, err := m.run(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", id); err != nil {
			m.log().Warn("apps: the image a snapshot ran is gone; using the current one", "app", ia.state.ID, "image", s.Image)
			continue
		}
		if _, err := m.run(ctx, "docker", "image", "tag", id, s.Image); err != nil {
			m.log().Warn("apps: putting an image back failed", "app", ia.state.ID, "image", s.Image, "err", err)
		}
	}
}

// readResolvedFile reads a resolved compose file from disk.
func readResolvedFile(path string) (Resolved, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseResolved(b)
}
