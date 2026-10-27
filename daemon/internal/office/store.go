package office

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Session states.
const (
	StateOpen   = "open"
	StateClosed = "closed"
	StateError  = "error"
)

// Mode is how a participant has the document open.
type Mode string

// Modes.
const (
	ModeEdit Mode = "edit"
	ModeView Mode = "view"
)

// Participant kinds.
const (
	KindUser = "user" // a signed-in HardyOS account
	KindLink = "link" // someone with a share link
)

// Session is one version of one file open in the Document Server.
type Session struct {
	Key          string    `json:"key"`
	Share        string    `json:"share"`
	Path         string    `json:"path"`
	FileType     string    `json:"fileType"`
	BaseModified time.Time `json:"baseModified"`
	BaseSize     int64     `json:"baseSize"`
	State        string    `json:"state"`
	Error        string    `json:"error,omitempty"`
	// Active are the participant ids the Document Server last reported.
	Active    []string  `json:"active"`
	Saves     int       `json:"saves"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Participant is one opening of a session: who the Document Server knows
// as user ID, and who that is for HardyOS.
type Participant struct {
	ID      string    `json:"id"`
	Key     string    `json:"key"`
	Kind    string    `json:"kind"`
	UserID  int64     `json:"userId,omitempty"`
	LinkID  int64     `json:"linkId,omitempty"`
	Name    string    `json:"name"`
	Mode    Mode      `json:"mode"`
	Created time.Time `json:"createdAt"`
}

// ErrNoSession: there is no session with that key.
var ErrNoSession = errors.New("no such editing session")

type dbStore struct{ db *store.DB }

const sessionCols = `doc_key, share, path, file_type, base_modified, base_size, state, error, active, saves, created_at, updated_at`

func scanSession(row interface{ Scan(...any) error }) (*Session, error) {
	var s Session
	var bm, active, created, updated string
	if err := row.Scan(&s.Key, &s.Share, &s.Path, &s.FileType, &bm, &s.BaseSize, &s.State, &s.Error, &active, &s.Saves, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoSession
		}
		return nil, err
	}
	s.BaseModified = store.ParseTime(bm)
	s.CreatedAt, s.UpdatedAt = store.ParseTime(created), store.ParseTime(updated)
	_ = json.Unmarshal([]byte(active), &s.Active)
	if s.Active == nil {
		s.Active = []string{}
	}
	return &s, nil
}

func (d dbStore) session(ctx context.Context, key string) (*Session, error) {
	return scanSession(d.db.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM office_sessions WHERE doc_key = ?`, key))
}

func (d dbStore) openSession(ctx context.Context, share, p string) (*Session, error) {
	return scanSession(d.db.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM office_sessions WHERE share = ? AND path = ? AND state = 'open'`, share, p))
}

func (d dbStore) openSessions(ctx context.Context) ([]*Session, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT `+sessionCols+` FROM office_sessions WHERE state = 'open' ORDER BY updated_at DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d dbStore) insertSession(ctx context.Context, s *Session) error {
	now := store.FormatTime(s.CreatedAt)
	_, err := d.db.ExecContext(ctx, `INSERT INTO office_sessions (doc_key, share, path, file_type, base_modified, base_size, state, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)`, s.Key, s.Share, s.Path, s.FileType, store.FormatTime(s.BaseModified), s.BaseSize, now, now)
	return err
}

func (d dbStore) setState(ctx context.Context, key, state, msg string, now time.Time) error {
	_, err := d.db.ExecContext(ctx, `UPDATE office_sessions SET state = ?, error = ?, active = CASE WHEN ? = 'open' THEN active ELSE '[]' END, updated_at = ? WHERE doc_key = ?`,
		state, msg, state, store.FormatTime(now), key)
	return err
}

func (d dbStore) setActive(ctx context.Context, key string, ids []string, now time.Time) error {
	if ids == nil {
		ids = []string{}
	}
	b, _ := json.Marshal(ids)
	_, err := d.db.ExecContext(ctx, `UPDATE office_sessions SET active = ?, updated_at = ? WHERE doc_key = ?`, string(b), store.FormatTime(now), key)
	return err
}

func (d dbStore) saved(ctx context.Context, key string, mod time.Time, size int64, now time.Time) error {
	_, err := d.db.ExecContext(ctx, `UPDATE office_sessions SET base_modified = ?, base_size = ?, saves = saves + 1, updated_at = ? WHERE doc_key = ?`,
		store.FormatTime(mod), size, store.FormatTime(now), key)
	return err
}

func newID(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func (d dbStore) addParticipant(ctx context.Context, p *Participant) error {
	_, err := d.db.ExecContext(ctx, `INSERT INTO office_participants (id, doc_key, kind, user_id, link_id, name, mode, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, p.ID, p.Key, p.Kind, p.UserID, p.LinkID, p.Name, string(p.Mode), store.FormatTime(p.Created))
	return err
}

func (d dbStore) participant(ctx context.Context, key, id string) (*Participant, error) {
	var p Participant
	var mode, created string
	err := d.db.QueryRowContext(ctx, `SELECT id, doc_key, kind, user_id, link_id, name, mode, created_at FROM office_participants WHERE doc_key = ? AND id = ?`, key, id).
		Scan(&p.ID, &p.Key, &p.Kind, &p.UserID, &p.LinkID, &p.Name, &mode, &created)
	if err != nil {
		return nil, err
	}
	p.Mode, p.Created = Mode(mode), store.ParseTime(created)
	return &p, nil
}

func (d dbStore) participants(ctx context.Context, key string) ([]Participant, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT id, doc_key, kind, user_id, link_id, name, mode, created_at FROM office_participants WHERE doc_key = ? ORDER BY created_at`, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Participant
	for rows.Next() {
		var p Participant
		var mode, created string
		if err := rows.Scan(&p.ID, &p.Key, &p.Kind, &p.UserID, &p.LinkID, &p.Name, &mode, &created); err != nil {
			return nil, err
		}
		p.Mode, p.Created = Mode(mode), store.ParseTime(created)
		out = append(out, p)
	}
	return out, rows.Err()
}

// markCallback records a callback as handled; false when it already was.
func (d dbStore) markCallback(ctx context.Context, key, fp string, status int, now time.Time) (bool, error) {
	res, err := d.db.ExecContext(ctx, `INSERT OR IGNORE INTO office_callbacks (doc_key, fingerprint, status, at) VALUES (?, ?, ?, ?)`,
		key, fp, status, store.FormatTime(now))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (d dbStore) unmarkCallback(ctx context.Context, key, fp string) {
	_, _ = d.db.ExecContext(ctx, `DELETE FROM office_callbacks WHERE doc_key = ? AND fingerprint = ?`, key, fp)
}

func (d dbStore) seenCallback(ctx context.Context, key, fp string) bool {
	var n int
	_ = d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM office_callbacks WHERE doc_key = ? AND fingerprint = ?`, key, fp).Scan(&n)
	return n > 0
}

// prune forgets sessions that ended more than 30 days ago.
func (d dbStore) prune(ctx context.Context, now time.Time) {
	cut := store.FormatTime(now.Add(-30 * 24 * time.Hour))
	_, _ = d.db.ExecContext(ctx, `DELETE FROM office_sessions WHERE state != 'open' AND updated_at < ?`, cut)
}
