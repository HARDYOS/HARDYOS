package vms

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Helpers for replication between servers (internal/replica).

// Frozen runs snap (a replication snapshot of the VM's datasets) with the
// guest's file systems frozen by its agent when the VM runs and has one,
// like TakeSnapshot; consistent says whether they were frozen (or the VM
// was off). The VM's lock is held, so it isn't changed meanwhile.
func (m *Manager) Frozen(ctx context.Context, id string, snap func(ctx context.Context) error) (consistent bool, err error) {
	unlock, err := m.lockValid(id)
	if err != nil {
		return false, err
	}
	defer unlock()
	st, err := m.find(ctx, id)
	if err != nil {
		return false, err
	}
	running := m.state(ctx, id) == "running"
	frozen := false
	if running && st.spec.GuestAgent {
		fctx, cancel := context.WithTimeout(ctx, FreezeTimeout)
		if _, err := m.virsh(fctx, "domfsfreeze", id); err == nil {
			frozen = true
		} else {
			m.log().Info("vms: the guest agent didn't freeze the file systems; the replication snapshot is crash-consistent", "id", id, "err", err)
			// A freeze that timed out may still happen in the guest.
			m.thaw(id)
		}
		cancel()
	}
	serr := snap(ctx)
	if frozen {
		m.thaw(id)
	}
	return frozen || !running, serr
}

// Free reports an error when a VM already uses id (a restore brings a VM
// back only under a free id).
func (m *Manager) Free(ctx context.Context, id string) error {
	if err := ValidID(id); err != nil {
		return Problems{err.Error()}
	}
	if _, err := m.find(ctx, id); err == nil {
		return Problems{fmt.Sprintf("there's already a VM called %s; delete it first to restore it from a replica", id)}
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	return nil
}

// Adopt defines a VM whose datasets were just put back on its pool (a
// restore from a replica): its spec is read and checked like any VM's on a
// pool, it gets its space limit and stays off.
func (m *Manager) Adopt(ctx context.Context, id string) (*VM, error) {
	unlock, err := m.lockValid(id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	ds, err := m.datasets(ctx)
	if err != nil {
		return nil, err
	}
	var st *stored
	for name, mp := range ds {
		pool, _, _ := strings.Cut(name, "/")
		if name != Dataset(pool, id) {
			continue
		}
		if st, err = m.read(name, mp); err != nil {
			return nil, fmt.Errorf("the restored VM can't be used: %w", err)
		}
		if _, err := m.mounted(ctx, name); err != nil {
			return nil, err
		}
		break
	}
	if st == nil {
		return nil, ErrNotFound
	}
	if err := m.define(ctx, st, nil); err != nil {
		return nil, err
	}
	if err := m.setQuota(ctx, st.dataset, &st.spec, 0); err != nil {
		m.log().Warn("vms: setting a restored VM's space limit", "id", id, "err", err)
	}
	m.log().Info("vms: restored from a replica", "id", id, "dataset", st.dataset)
	return m.Get(ctx, id)
}
