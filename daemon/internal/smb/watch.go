package smb

import (
	"context"
	"time"
)

// CleanRecycle removes files that have been in the shared folders' recycle
// bins for more than RecycleDays days.
func (m *Manager) CleanRecycle(ctx context.Context) (int, error) {
	list, err := m.Shares.List(ctx)
	if err != nil {
		return 0, err
	}
	cutoff := m.now().Add(-RecycleDays * 24 * time.Hour)
	total := 0
	for _, sh := range list {
		if !sh.Recycle || !sh.Mounted || sh.Path == "" {
			continue
		}
		n, err := cleanRecycleDir(sh.Path, cutoff)
		if err != nil {
			m.log().Warn("emptying a recycle bin", "share", sh.ID, "err", err)
			continue
		}
		if n > 0 {
			m.log().Info("recycle bin: old files removed", "share", sh.ID, "files", n)
		}
		total += n
	}
	if err := m.updateState(func(s *state) { s.RecycleCleaned = m.now().UTC() }); err != nil {
		m.log().Warn("saving the file server's state", "err", err)
	}
	return total, nil
}

// Watch keeps the file server in step: the config and home folders every
// 10 minutes (and soon after start, once pools are mounted), the recycle
// bins once a day.
func (m *Manager) Watch(ctx context.Context) {
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.stopBackgroundAll()
			return
		case <-t.C:
		}
		if st := m.loadState(); st.Joined {
			if _, err := m.Apply(ctx); err != nil {
				m.log().Warn("file sharing: applying the settings", "err", err)
			}
			if m.now().Sub(st.RecycleCleaned) >= 24*time.Hour {
				if _, err := m.CleanRecycle(ctx); err != nil {
					m.log().Warn("file sharing: emptying old files from recycle bins", "err", err)
				}
			}
		}
		t.Reset(HomesInterval)
	}
}
