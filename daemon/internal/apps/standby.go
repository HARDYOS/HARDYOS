package apps

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// DataFolder returns an installed app's data folder (what its compose file
// binds as ${HARDY_APP_DATA}), whether any of its containers runs, and
// whether root itself verified it as the shipped catalog package (decision
// 75). The NetBird standby uses it to stage a take-over (decision 425):
// only a stopped catalog app gets the VPS's state.
func (m *Manager) DataFolder(ctx context.Context, id string) (dir string, running, catalog bool, err error) {
	ia, _, err := m.app(ctx, id)
	if err != nil {
		return "", false, false, err
	}
	for _, c := range m.containers(ctx)[id] {
		if c.State == "running" || c.State == "restarting" || c.State == "paused" {
			running = true
		}
	}
	// The data folder itself, never a link someone put in its place.
	dir = filepath.Join(ia.dir, dataDirName)
	fi, err := os.Lstat(dir)
	if err != nil {
		return "", false, false, err
	}
	if !fi.IsDir() {
		return "", false, false, fmt.Errorf("%s isn't a folder", dir)
	}
	return dir, running, ia.state.Source == SourceCatalog && ia.state.CatalogSHA256 != "", nil
}

// IsNotInstalled reports whether err means the app (or the apps engine) isn't there.
func IsNotInstalled(err error) bool {
	return errors.Is(err, ErrNotInstalled) || errors.Is(err, ErrNoEngine)
}
