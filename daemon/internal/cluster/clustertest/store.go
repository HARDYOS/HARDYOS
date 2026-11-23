package clustertest

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// MemStore is an in-memory cluster.Store.
type MemStore struct {
	mu    sync.Mutex
	info  *cluster.Info
	seq   uint64
	codes []cluster.JoinCode
}

// Info implements cluster.Store.
func (m *MemStore) Info(context.Context) (*cluster.Info, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.info == nil {
		return nil, nil
	}
	c := *m.info
	return &c, nil
}

// SetInfo implements cluster.Store.
func (m *MemStore) SetInfo(_ context.Context, i *cluster.Info) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *i
	m.info = &c
	return nil
}

// ClearInfo implements cluster.Store.
func (m *MemStore) ClearInfo(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.info = nil
	return nil
}

// Seq implements cluster.Store.
func (m *MemStore) Seq(context.Context) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.seq, nil
}

// SetSeq implements cluster.Store.
func (m *MemStore) SetSeq(_ context.Context, s uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq = s
	return nil
}

// JoinCodes implements cluster.Store.
func (m *MemStore) JoinCodes(_ context.Context, now time.Time) ([]cluster.JoinCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []cluster.JoinCode
	for _, c := range m.codes {
		if now.Before(c.Expires) {
			out = append(out, c)
		}
	}
	return out, nil
}

// AddJoinCode implements cluster.Store.
func (m *MemStore) AddJoinCode(_ context.Context, c cluster.JoinCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes = append(m.codes, c)
	return nil
}

// TakeJoinCode implements cluster.Store.
func (m *MemStore) TakeJoinCode(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes = slices.DeleteFunc(m.codes, func(c cluster.JoinCode) bool { return c.ID == id })
	return nil
}

// JoinCodeFailed implements cluster.Store.
func (m *MemStore) JoinCodeFailed(_ context.Context, id string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.codes {
		if m.codes[i].ID == id {
			m.codes[i].Failures++
			return m.codes[i].Failures, nil
		}
	}
	return 0, nil
}
