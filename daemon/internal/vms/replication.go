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
// pool, it gets its space limit and stays off. What could reach beyond the
// VM or clash with the original is reset first, and listed in notes: it
// doesn't start with the server, has no host devices, keeps the network
// filter on, has no streaming or cloud-init, and gets new MAC addresses and
// a new UUID.
func (m *Manager) Adopt(ctx context.Context, id string) (*VM, []string, error) {
	unlock, err := m.lockValid(id)
	if err != nil {
		return nil, nil, err
	}
	defer unlock()
	ds, err := m.datasets(ctx)
	if err != nil {
		return nil, nil, err
	}
	var st *stored
	for name, mp := range ds {
		pool, _, _ := strings.Cut(name, "/")
		if name != Dataset(pool, id) {
			continue
		}
		if st, err = m.read(name, mp); err != nil {
			return nil, nil, fmt.Errorf("the restored VM can't be used: %w", err)
		}
		if _, err := m.mounted(ctx, name); err != nil {
			return nil, nil, err
		}
		break
	}
	if st == nil {
		return nil, nil, ErrNotFound
	}
	notes := ResetRestored(&st.spec)
	if err := m.saveSpec(st); err != nil {
		return nil, nil, err
	}
	if err := m.define(ctx, st, nil); err != nil {
		return nil, nil, err
	}
	if err := m.setQuota(ctx, st.dataset, &st.spec, 0); err != nil {
		m.log().Warn("vms: setting a restored VM's space limit", "id", id, "err", err)
	}
	m.log().Info("vms: restored from a replica", "id", id, "dataset", st.dataset, "reset", strings.Join(notes, "; "))
	v, err := m.Get(ctx, id)
	return v, notes, err
}

// ResetRestored takes out of a restored VM's spec what could reach beyond
// the VM or clash with the original, and says what changed.
func ResetRestored(s *Spec) []string {
	notes := []string{}
	if s.Autostart.Enabled {
		s.Autostart.Enabled = false
		notes = append(notes, "it no longer starts with the server")
	}
	if len(s.Devices) > 0 {
		notes = append(notes, fmt.Sprintf("%d host devices (GPUs, USB, PCI) were taken off it", len(s.Devices)))
		s.Devices = nil
	}
	spoof := false
	for i := range s.NICs {
		spoof = spoof || s.NICs[i].AllowSpoofing
		s.NICs[i].AllowSpoofing = false
		s.NICs[i].MAC = NewMAC()
	}
	if spoof {
		notes = append(notes, "the network filter is back on for its cards")
	}
	if len(s.NICs) > 0 {
		notes = append(notes, "its network cards have new MAC addresses")
	}
	if s.Streaming != nil {
		s.Streaming = nil
		notes = append(notes, "game streaming was turned off")
	}
	if s.CloudInit != nil {
		s.CloudInit = nil
		media := s.Media[:0]
		for _, md := range s.Media {
			if md.Kind != "cloudinit" {
				media = append(media, md)
			}
		}
		s.Media = media
		notes = append(notes, "its cloud-init settings were removed")
	}
	s.UUID = NewUUID()
	notes = append(notes, "it has a new UUID (some guests ask to be activated again)")
	return notes
}
