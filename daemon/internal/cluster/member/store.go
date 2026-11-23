// Package member is hardyd's side of the cluster core: the database-backed
// membership store and sealed identity, the jobs that create, join, leave
// and dissolve a cluster, address discovery and alerts. The protocol itself
// is internal/cluster.
package member

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

const (
	keyInfo     = "cluster.info"
	keySeq      = "cluster.seq"
	keyIdentity = "cluster.identity"
)

// DBStore keeps the membership in hardyd's database (cluster.Store).
type DBStore struct {
	DB *store.DB
	// Keys seals the identity and join codes (purpose "cluster"); nil uses
	// a process-lifetime key (tests).
	Keys secretbox.Source
	keys secretbox.Source
}

func (s *DBStore) source() secretbox.Source {
	if s.Keys != nil {
		return s.Keys
	}
	if s.keys == nil {
		s.keys = secretbox.NewStaticSource()
	}
	return s.keys
}

func (s *DBStore) seal(ctx context.Context, plain []byte, aad string) ([]byte, error) {
	k, err := s.source().Key(ctx, cluster.SecretsPurpose)
	if err != nil {
		return nil, err
	}
	return secretbox.Seal(k, plain, []byte(aad))
}

func (s *DBStore) open(ctx context.Context, sealed []byte, aad string) ([]byte, error) {
	k, err := s.source().Key(ctx, cluster.SecretsPurpose)
	if err != nil {
		return nil, err
	}
	return secretbox.Open(k, sealed, []byte(aad))
}

func (s *DBStore) deleteSetting(ctx context.Context, key string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, key)
	return err
}

// Info implements cluster.Store.
func (s *DBStore) Info(ctx context.Context) (*cluster.Info, error) {
	v, err := s.DB.GetSetting(ctx, keyInfo)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var i cluster.Info
	if err := json.Unmarshal([]byte(v), &i); err != nil {
		return nil, fmt.Errorf("cluster membership: %w", err)
	}
	return &i, nil
}

// SetInfo implements cluster.Store.
func (s *DBStore) SetInfo(ctx context.Context, i *cluster.Info) error {
	b, err := json.Marshal(i)
	if err != nil {
		return err
	}
	return s.DB.SetSetting(ctx, keyInfo, string(b))
}

// ClearInfo implements cluster.Store (the sequence number goes too: a new
// membership comes with a new key).
func (s *DBStore) ClearInfo(ctx context.Context) error {
	if err := s.deleteSetting(ctx, keyInfo); err != nil {
		return err
	}
	return s.deleteSetting(ctx, keySeq)
}

// Seq implements cluster.Store.
func (s *DBStore) Seq(ctx context.Context) (uint64, error) {
	v, err := s.DB.GetSetting(ctx, keySeq)
	if errors.Is(err, store.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(v, 10, 64)
}

// SetSeq implements cluster.Store.
func (s *DBStore) SetSeq(ctx context.Context, seq uint64) error {
	return s.DB.SetSetting(ctx, keySeq, strconv.FormatUint(seq, 10))
}

// JoinCodes implements cluster.Store.
func (s *DBStore) JoinCodes(ctx context.Context, now time.Time) ([]cluster.JoinCode, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, code_sealed, role, created_by, expires_at, failures FROM cluster_join_codes ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cluster.JoinCode
	var expired []string
	for rows.Next() {
		var c cluster.JoinCode
		var sealed []byte
		var role, exp string
		if err := rows.Scan(&c.ID, &sealed, &role, &c.CreatedBy, &exp, &c.Failures); err != nil {
			return nil, err
		}
		c.Role, c.Expires = cluster.Role(role), store.ParseTime(exp)
		if !now.Before(c.Expires) {
			expired = append(expired, c.ID)
			continue
		}
		plain, err := s.open(ctx, sealed, "cluster.joincode."+c.ID)
		if err != nil {
			// Unreadable (another server's key, a restored database): useless.
			expired = append(expired, c.ID)
			continue
		}
		c.Code = plain
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	for _, id := range expired {
		_ = s.TakeJoinCode(ctx, id)
	}
	return out, nil
}

// AddJoinCode implements cluster.Store.
func (s *DBStore) AddJoinCode(ctx context.Context, c cluster.JoinCode) error {
	sealed, err := s.seal(ctx, c.Code, "cluster.joincode."+c.ID)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO cluster_join_codes (id, code_sealed, role, created_by, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, c.ID, sealed, string(c.Role), c.CreatedBy, store.Now(), store.FormatTime(c.Expires))
	return err
}

// TakeJoinCode implements cluster.Store.
func (s *DBStore) TakeJoinCode(ctx context.Context, id string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM cluster_join_codes WHERE id = ?`, id)
	return err
}

// JoinCodeFailed implements cluster.Store.
func (s *DBStore) JoinCodeFailed(ctx context.Context, id string) (int, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `UPDATE cluster_join_codes SET failures = failures + 1 WHERE id = ? RETURNING failures`, id).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n, err
}

// Identity reads this server's cluster key (nil, nil when there is none).
func (s *DBStore) Identity(ctx context.Context) (*cluster.Identity, error) {
	v, err := s.DB.GetSetting(ctx, keyIdentity)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("cluster identity: %w", err)
	}
	plain, err := s.open(ctx, raw, keyIdentity)
	if err != nil {
		return nil, fmt.Errorf("cluster identity can't be read (restored from another server?): %w", err)
	}
	return cluster.UnmarshalIdentity(plain)
}

// NewIdentity makes and seals a new key, replacing any old one.
func (s *DBStore) NewIdentity(ctx context.Context, name string) (*cluster.Identity, error) {
	id, err := cluster.NewIdentity(name)
	if err != nil {
		return nil, err
	}
	plain, err := cluster.MarshalIdentity(id)
	if err != nil {
		return nil, err
	}
	sealed, err := s.seal(ctx, plain, keyIdentity)
	if err != nil {
		return nil, err
	}
	return id, s.DB.SetSetting(ctx, keyIdentity, hex.EncodeToString(sealed))
}

// DeleteIdentity forgets the key (leaving the cluster).
func (s *DBStore) DeleteIdentity(ctx context.Context) error { return s.deleteSetting(ctx, keyIdentity) }
