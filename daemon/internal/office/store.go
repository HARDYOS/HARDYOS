package office

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/files"
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

// LocationOf is the folder a share id stands for when who uses it: the
// share id itself, or "~home:<principal>" for the person's own home, since
// every person's "~home" is a different folder (decision 263).
func LocationOf(share string, who files.Who) string {
	if share == files.HomeShare {
		return files.HomeShare + ":" + strings.ToLower(who.Principal)
	}
	return share
}

// Session is one version of one file open in the Document Server.
type Session struct {
	Key   string `json:"key"`
	Share string `json:"share"`
	// Location is the folder Share is for whoever opened it (LocationOf).
	Location     string    `json:"location"`
	Path         string    `json:"path"`
	FileType     string    `json:"fileType"`
	BaseModified time.Time `json:"baseModified"`
	BaseSize     int64     `json:"baseSize"`
	State        string    `json:"state"`
	Error        string    `json:"error,omitempty"`
	// Active are the participant ids the Document Server last reported;
	// ActiveAt is when (zero: never).
	Active    []string  `json:"active"`
	ActiveAt  time.Time `json:"activeAt"`
	Saves     int       `json:"saves"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// lastActivity is when the Document Server last said who was in the
// session, or when it was made.
func (s *Session) lastActivity() time.Time {
	if s.ActiveAt.After(s.CreatedAt) {
		return s.ActiveAt
	}
	return s.CreatedAt
}

func (s *Session) isActive(id string) bool {
	for _, a := range s.Active {
		if a == id {
			return true
		}
	}
	return false
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
	IP      string    `json:"ip,omitempty"`
	Created time.Time `json:"createdAt"`
	// SeenAt: last listed as in the document; LeftAt: stopped being listed.
	SeenAt time.Time `json:"seenAt"`
	LeftAt time.Time `json:"leftAt"`
}

// ErrNoSession: there is no session with that key.
var ErrNoSession = errors.New("no such editing session")

type dbStore struct{ db *store.DB }

const sessionCols = `doc_key, share, location, path, file_type, base_modified, base_size, state, error, active, active_at, saves, created_at, updated_at`

func parseOptTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	return store.ParseTime(s)
}

func optTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return store.FormatTime(t)
}

func scanSession(row interface{ Scan(...any) error }) (*Session, error) {
	var s Session
	var bm, active, activeAt, created, updated string
	if err := row.Scan(&s.Key, &s.Share, &s.Location, &s.Path, &s.FileType, &bm, &s.BaseSize, &s.State, &s.Error, &active, &activeAt,
		&s.Saves, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoSession
		}
		return nil, err
	}
	s.BaseModified = store.ParseTime(bm)
	s.ActiveAt = parseOptTime(activeAt)
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

func (d dbStore) openSession(ctx context.Context, location, p string) (*Session, error) {
	return scanSession(d.db.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM office_sessions WHERE location = ? AND path = ? AND state = 'open'`, location, p))
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
	_, err := d.db.ExecContext(ctx, `INSERT INTO office_sessions (doc_key, share, location, path, file_type, base_modified, base_size, state, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)`, s.Key, s.Share, s.Location, s.Path, s.FileType, store.FormatTime(s.BaseModified), s.BaseSize, now, now)
	return err
}

func (d dbStore) setState(ctx context.Context, key, state, msg string, now time.Time) error {
	_, err := d.db.ExecContext(ctx, `UPDATE office_sessions SET state = ?, error = ?, active = CASE WHEN ? = 'open' THEN active ELSE '[]' END, updated_at = ? WHERE doc_key = ?`,
		state, msg, state, store.FormatTime(now), key)
	return err
}

// setActive records who the Document Server says is in the session: those
// listed are seen now, those no longer listed left now.
func (d dbStore) setActive(ctx context.Context, sess *Session, ids []string, now time.Time) error {
	if ids == nil {
		ids = []string{}
	}
	b, _ := json.Marshal(ids)
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	t := store.FormatTime(now)
	if _, err := tx.ExecContext(ctx, `UPDATE office_sessions SET active = ?, active_at = ?, updated_at = ? WHERE doc_key = ?`, string(b), t, t, sess.Key); err != nil {
		return err
	}
	in := map[string]bool{}
	for _, id := range ids {
		in[id] = true
		if _, err := tx.ExecContext(ctx, `UPDATE office_participants SET seen_at = ?, left_at = '' WHERE doc_key = ? AND id = ?`, t, sess.Key, id); err != nil {
			return err
		}
	}
	for _, id := range sess.Active {
		if !in[id] {
			if _, err := tx.ExecContext(ctx, `UPDATE office_participants SET left_at = ? WHERE doc_key = ? AND id = ?`, t, sess.Key, id); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
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
	_, err := d.db.ExecContext(ctx, `INSERT INTO office_participants (id, doc_key, kind, user_id, link_id, name, mode, ip, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, p.ID, p.Key, p.Kind, p.UserID, p.LinkID, p.Name, string(p.Mode), p.IP, store.FormatTime(p.Created))
	return err
}

const participantCols = `id, doc_key, kind, user_id, link_id, name, mode, ip, created_at, seen_at, left_at`

func scanParticipant(row interface{ Scan(...any) error }) (*Participant, error) {
	var p Participant
	var mode, created, seen, left string
	if err := row.Scan(&p.ID, &p.Key, &p.Kind, &p.UserID, &p.LinkID, &p.Name, &mode, &p.IP, &created, &seen, &left); err != nil {
		return nil, err
	}
	p.Mode, p.Created = Mode(mode), store.ParseTime(created)
	p.SeenAt, p.LeftAt = parseOptTime(seen), parseOptTime(left)
	return &p, nil
}

func (d dbStore) participant(ctx context.Context, key, id string) (*Participant, error) {
	return scanParticipant(d.db.QueryRowContext(ctx, `SELECT `+participantCols+` FROM office_participants WHERE doc_key = ? AND id = ?`, key, id))
}

func (d dbStore) participants(ctx context.Context, key string) ([]Participant, error) {
	return d.queryParticipants(ctx, `SELECT `+participantCols+` FROM office_participants WHERE doc_key = ? ORDER BY created_at`, key)
}

func (d dbStore) queryParticipants(ctx context.Context, q string, args ...any) ([]Participant, error) {
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Participant
	for rows.Next() {
		p, err := scanParticipant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// linkParticipants are a link's participants in open sessions.
func (d dbStore) linkParticipants(ctx context.Context, linkID int64) ([]Participant, error) {
	return d.queryParticipants(ctx, `SELECT p.id, p.doc_key, p.kind, p.user_id, p.link_id, p.name, p.mode, p.ip, p.created_at, p.seen_at, p.left_at
		FROM office_participants p JOIN office_sessions s ON s.doc_key = p.doc_key WHERE p.kind = 'link' AND p.link_id = ? AND s.state = 'open'`, linkID)
}

// userParticipants are an account's participants in open sessions.
func (d dbStore) userParticipants(ctx context.Context, userID int64) ([]Participant, error) {
	return d.queryParticipants(ctx, `SELECT p.id, p.doc_key, p.kind, p.user_id, p.link_id, p.name, p.mode, p.ip, p.created_at, p.seen_at, p.left_at
		FROM office_participants p JOIN office_sessions s ON s.doc_key = p.doc_key WHERE p.kind = 'user' AND p.user_id = ? AND s.state = 'open'`, userID)
}

// countFrom counts participants of open sessions made from an address since t.
func (d dbStore) countFrom(ctx context.Context, ip string, since time.Time) int {
	var n int
	_ = d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM office_participants p JOIN office_sessions s ON s.doc_key = p.doc_key
		WHERE p.ip = ? AND p.created_at >= ? AND s.state = 'open'`, ip, store.FormatTime(since)).Scan(&n)
	return n
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
