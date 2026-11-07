package storagesvc

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/network"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Store keeps this server's storage network settings, its sealed CHAP
// secrets and app storage mode choices (migration 0071).
type Store struct {
	DB *store.DB
	// Keys seals the CHAP secrets (purpose cluster.SecretsPurpose); nil
	// uses a per-process key (tests).
	Keys secretbox.Source

	fallback secretbox.Source
}

func (s *Store) keys() secretbox.Source {
	if s.Keys != nil {
		return s.Keys
	}
	if s.fallback == nil {
		s.fallback = secretbox.NewStaticSource()
	}
	return s.fallback
}

// StorageNet returns the saved storage network plan (nil when none).
func (s *Store) StorageNet(ctx context.Context) (*network.StoragePlan, error) {
	var p network.StoragePlan
	err := s.DB.QueryRowContext(ctx, `SELECT kind, iface, vlan, address, mtu FROM cluster_storage_net WHERE id = 1`).
		Scan(&p.Kind, &p.Interface, &p.VLAN, &p.Address, &p.MTU)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// SaveStorageNet records the plan.
func (s *Store) SaveStorageNet(ctx context.Context, p network.StoragePlan) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO cluster_storage_net (id, kind, iface, vlan, address, mtu, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET kind = excluded.kind, iface = excluded.iface, vlan = excluded.vlan,
		address = excluded.address, mtu = excluded.mtu, updated_at = excluded.updated_at`,
		p.Kind, p.Interface, p.VLAN, p.Address, p.MTU, store.Now())
	return err
}

func chapAAD(node cluster.NodeID) []byte { return []byte("cluster_storage_chap:" + string(node)) }

// CHAP returns this node's sealed CHAP secrets (nil when none yet).
func (s *Store) CHAP(ctx context.Context, node cluster.NodeID) (*san.Secrets, error) {
	var sealed []byte
	err := s.DB.QueryRowContext(ctx, `SELECT sealed FROM cluster_storage_chap WHERE node = ?`, string(node)).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	k, err := s.keys().Key(ctx, cluster.SecretsPurpose)
	if err != nil {
		return nil, err
	}
	plain, err := secretbox.Open(k, sealed, chapAAD(node))
	if err != nil {
		return nil, err
	}
	var sec san.Secrets
	if err := json.Unmarshal(plain, &sec); err != nil {
		return nil, fmt.Errorf("reading the CHAP secrets: %w", err)
	}
	return &sec, nil
}

// SaveCHAP seals and stores this node's CHAP secrets.
func (s *Store) SaveCHAP(ctx context.Context, node cluster.NodeID, sec san.Secrets) error {
	if err := sec.Validate(); err != nil {
		return err
	}
	k, err := s.keys().Key(ctx, cluster.SecretsPurpose)
	if err != nil {
		return err
	}
	plain, _ := json.Marshal(sec)
	sealed, err := secretbox.Seal(k, plain, chapAAD(node))
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO cluster_storage_chap (node, sealed, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (node) DO UPDATE SET sealed = excluded.sealed, updated_at = excluded.updated_at`, string(node), sealed, store.Now())
	return err
}

// ForgetCHAP removes the stored secrets (leaving, or rotated).
func (s *Store) ForgetCHAP(ctx context.Context, node cluster.NodeID) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM cluster_storage_chap WHERE node = ?`, string(node))
	return err
}

// AppMode is an administrator's storage mode choice for an app.
type AppMode struct {
	App  string              `json:"app"`
	Mode cluster.StorageMode `json:"mode"`
	FS   string              `json:"fs,omitempty"`
}

// AppModes lists the choices.
func (s *Store) AppModes(ctx context.Context) (map[string]AppMode, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT app, mode, fs FROM cluster_app_storage_mode`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]AppMode{}
	for rows.Next() {
		var m AppMode
		var mode string
		if err := rows.Scan(&m.App, &mode, &m.FS); err != nil {
			return nil, err
		}
		m.Mode = cluster.StorageMode(mode)
		out[m.App] = m
	}
	return out, rows.Err()
}

// SaveAppMode records a choice.
func (s *Store) SaveAppMode(ctx context.Context, m AppMode) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO cluster_app_storage_mode (app, mode, fs, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (app) DO UPDATE SET mode = excluded.mode, fs = excluded.fs, updated_at = excluded.updated_at`,
		m.App, string(m.Mode), m.FS, store.Now())
	return err
}
