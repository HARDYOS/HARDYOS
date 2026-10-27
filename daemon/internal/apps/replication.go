package apps

import (
	"context"
	"fmt"
)

// Helpers for replication between servers (internal/replica).

// EnginePool is the pool apps live on (<pool>/apps/<id>).
func (m *Manager) EnginePool() (string, error) {
	c, err := m.engine()
	if err != nil {
		return "", err
	}
	if c == nil {
		return "", ErrNoEngine
	}
	return c.Pool, nil
}

// AdoptRestored marks an app's dataset that was just restored from a
// replica as kept data: the app shows up under kept data and runs again
// once it's reinstalled from the App Store, whose package is checked like
// any install (the restored compose files are never run as they are).
func (m *Manager) AdoptRestored(ctx context.Context, id string) error {
	if err := ValidID(id); err != nil {
		return Problems{err.Error()}
	}
	c, err := m.engine()
	if err != nil {
		return err
	}
	if c == nil {
		return ErrNoEngine
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ia, err := m.load(ctx, c, id)
	if err != nil {
		return fmt.Errorf("the restored app can't be read: %w", err)
	}
	if ia.state.ID != id {
		return fmt.Errorf("the restored app's state is for %q, not %s", ia.state.ID, id)
	}
	// Its user ID came with the data: keep it only when it's an app ID no
	// other app here has, else the reinstall picks a free one.
	if ia.state.UID != 0 {
		if !m.uidFree(ctx, c, id, ia.state.UID) {
			m.log().Warn("apps: the restored app's user ID is taken or invalid; a new one is chosen when it's reinstalled", "app", id, "uid", ia.state.UID)
			ia.state.UID = 0
		}
	}
	ia.state.Removed = true
	ia.state.UpdatedAt = m.now()
	m.log().Info("apps: restored from a replica as kept data", "app", id, "dataset", ia.dataset)
	return writeFileAtomic(ia.meta(stateFile), mustJSON(ia.state), 0o600)
}
