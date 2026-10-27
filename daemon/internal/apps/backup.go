package apps

import (
	"context"
	"errors"
	"fmt"

	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// Cloud backups (internal/cloudbackup) back an app up from a snapshot of
// its dataset (data and .hardyos: package, settings, generated secrets) and
// bring it back as a working app: in place, or onto a rebuilt server.

// BackupSource is an installed app's dataset, for a backup.
type BackupSource struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Pool    string `json:"pool"`
	Dataset string `json:"dataset"`
}

// BackupSource names an installed app's dataset.
func (m *Manager) BackupSource(ctx context.Context, id string) (*BackupSource, error) {
	ia, c, err := m.app(ctx, id)
	if err != nil {
		return nil, err
	}
	return &BackupSource{ID: ia.state.ID, Name: ia.manifest.Name, Version: ia.manifest.Version, Pool: c.Pool, Dataset: ia.dataset}, nil
}

// BackupSources lists every installed app (none when apps aren't set up).
func (m *Manager) BackupSources(ctx context.Context) ([]BackupSource, error) {
	c, err := m.engine()
	if err != nil || c == nil {
		return []BackupSource{}, err
	}
	l, err := m.installed(ctx, c)
	if err != nil {
		return nil, err
	}
	out := []BackupSource{}
	for _, ia := range l {
		if !ia.state.Removed {
			out = append(out, BackupSource{ID: ia.state.ID, Name: ia.manifest.Name, Version: ia.manifest.Version, Pool: c.Pool, Dataset: ia.dataset})
		}
	}
	return out, nil
}

// Fill writes an app's data into its mounted dataset (dir is the
// dataset's mountpoint, dataset its name).
type Fill func(ctx context.Context, dir, dataset string) error

// RestoreData puts an installed app's data back to a version from a
// backup. Confirm is the app's name. The app is stopped, a safety snapshot
// (hardyos-manual-<time>) is taken so the step can be undone, fill
// replaces the dataset's contents, and the app comes back like after a
// rollback: the package and settings the version holds, but never
// permissions the admin has taken away since (decision 77).
func (m *Manager) RestoreData(ctx context.Context, id, confirm string, fill Fill) error {
	ia, c, err := m.app(ctx, id)
	if err != nil {
		return err
	}
	if !confirmed(confirm, ia) {
		return Problems{fmt.Sprintf("type the app's name (%s) to confirm", ia.manifest.Name)}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.runCompose(ctx, m.composeArgs(ia, "stop")...); err != nil {
		return fmt.Errorf("stopping %s: %w", ia.manifest.Name, err)
	}
	safety := "hardyos-manual-" + m.now().Format("20060102-150405")
	if _, err := m.run(ctx, "zfs", "snapshot", "-o", versionProp+"="+ia.manifest.Version, ia.dataset+"@"+safety); err != nil {
		return fmt.Errorf("snapshotting %s first: %w", ia.dataset, err)
	}
	if err := fill(ctx, ia.dir, ia.dataset); err != nil {
		return fmt.Errorf("restoring %s's data (the snapshot %s has it as it was): %w", ia.manifest.Name, safety, err)
	}
	return m.bringBack(ctx, ia, c, "the backup")
}

// RestoreNew brings back an app that isn't installed here (a rebuilt
// server): it sets up apps on pool if needed, creates the app's dataset,
// lets fill write its data and starts it from the package and settings the
// backup holds. Shared folders it used come back only where a folder with
// that id exists again.
func (m *Manager) RestoreNew(ctx context.Context, id, pool string, fill Fill) error {
	if err := ValidID(id); err != nil {
		return Problems{err.Error()}
	}
	if !m.Available() {
		return errors.New("this HardyOS build doesn't include Docker")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.engine()
	if err != nil {
		return err
	}
	if c == nil {
		if err := zfs.ValidPoolName(pool); err != nil {
			return Problems{"choose the pool for apps"}
		}
		if c, err = m.setupEngine(ctx, pool); err != nil {
			return err
		}
	} else if err := m.startEngine(ctx, c); err != nil {
		return err
	}
	ds := c.Pool + "/apps/" + id
	if m.datasetExists(ctx, ds) {
		if ia, err := m.load(ctx, c, id); err == nil && !ia.state.Removed {
			return Problems{fmt.Sprintf("%s is already installed; restore it from its own version list instead", ia.manifest.Name)}
		}
		return Problems{fmt.Sprintf("%s already has kept data on this server; remove it first", id)}
	}
	if _, err := m.run(ctx, "zfs", "create", ds); err != nil {
		return fmt.Errorf("creating %s: %w", ds, err)
	}
	dir, _, err := m.mountpoint(ctx, ds)
	if err != nil {
		return err
	}
	if err := fill(ctx, dir, ds); err != nil {
		return fmt.Errorf("restoring %s's data: %w", id, err)
	}
	ia, err := m.load(ctx, c, id)
	if err != nil {
		return fmt.Errorf("the restored app can't be read: %w", err)
	}
	if ia.state.ID != id || ia.manifest.ID != id {
		return Problems{"the backup holds a different app"}
	}
	ia.state.Removed = false
	if err := writeFileAtomic(ia.meta(stateFile), mustJSON(ia.state), 0o600); err != nil {
		return err
	}
	return m.bringBack(ctx, ia, c, "the backup")
}
