package photos

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Setting names in hardyd's settings table.
const (
	settingSettings = "photos.settings"
	settingStatus   = "photos.status"
	settingAccount  = "photos.immich"      // sealed Account
	settingClient   = "photos.oidc_client" // sealed ClientCreds
	settingMLMode   = "photos.ml_applied"  // the mode last set on the app
)

// Account is how HardyOS signs in to Immich: its own administrator (made
// with Immich's first sign-up, or linked with an administrator's API key)
// and the family account. Kept sealed; never shown.
type Account struct {
	AdminEmail    string `json:"adminEmail,omitempty"`
	AdminPassword string `json:"adminPassword,omitempty"`
	AdminKey      string `json:"adminKey,omitempty"`
	// Linked: the key came from an administrator (Immich was set up before
	// Photos); HardyOS has no password for that account.
	Linked bool `json:"linked,omitempty"`
	// AdminUserID is that account's Immich id.
	AdminUserID string `json:"adminUserId,omitempty"`

	FamilyUserID   string `json:"familyUserId,omitempty"`
	FamilyEmail    string `json:"familyEmail,omitempty"`
	FamilyPassword string `json:"familyPassword,omitempty"`
	FamilyKey      string `json:"familyKey,omitempty"`
}

// ClientCreds is the sign-in client HardyOS keeps for Immich.
type ClientCreds struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

// LibRecord is a library HardyOS made in Immich.
type LibRecord struct {
	Key        string
	ImmichID   string
	OwnerID    string
	ImportPath string
	// Subject is the owner's sign-in subject when it was made.
	Subject string
}

// AccountRec is an Immich account of a person HardyOS looks after.
type AccountRec struct {
	ImmichID string
	Subject  string
	// Made: HardyOS made it ahead of the person's first sign-in.
	Made bool
	// Suspended: HardyOS soft-deleted it (the person may no longer use
	// Photos).
	Suspended bool
}

// Store keeps Photos' state in hardyd's database. Secrets are sealed with
// secretbox under the "photos" purpose, bound to their setting's name.
type Store struct {
	DB *store.DB
	// Secrets gives the key (secretbox.PrivSource in production); nil uses
	// a key that lasts as long as the process (tests).
	Secrets secretbox.Source

	once     sync.Once
	fallback secretbox.Source
}

// ErrSealed: a sealed value can't be opened here (a settings backup from
// another server): HardyOS forgets it and sets Immich up again.
var ErrSealed = errors.New("Photos' saved Immich keys can't be read on this server")

func (s *Store) key(ctx context.Context) ([]byte, error) {
	src := s.Secrets
	if src == nil {
		s.once.Do(func() { s.fallback = secretbox.NewStaticSource() })
		src = s.fallback
	}
	return src.Key(ctx, KeyPurpose)
}

func (s *Store) setSealed(ctx context.Context, name string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	k, err := s.key(ctx)
	if err != nil {
		return err
	}
	sealed, err := secretbox.Seal(k, b, []byte(name))
	if err != nil {
		return err
	}
	return s.DB.SetSetting(ctx, name, "v1:"+base64.RawStdEncoding.EncodeToString(sealed))
}

func (s *Store) sealed(ctx context.Context, name string, v any) error {
	raw, err := s.DB.GetSetting(ctx, name)
	if errors.Is(err, store.ErrNotFound) || raw == "" {
		return nil
	}
	if err != nil {
		return err
	}
	b, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(raw, "v1:"))
	if err != nil || !strings.HasPrefix(raw, "v1:") {
		return ErrSealed
	}
	k, err := s.key(ctx)
	if err != nil {
		return err
	}
	plain, err := secretbox.Open(k, b, []byte(name))
	if err != nil {
		return ErrSealed
	}
	return json.Unmarshal(plain, v)
}

// Settings are the saved settings (Defaults when none are).
func (s *Store) Settings(ctx context.Context) (Settings, error) {
	out := Defaults()
	raw, err := s.DB.GetSetting(ctx, settingSettings)
	if errors.Is(err, store.ErrNotFound) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return Defaults(), err
	}
	return out.Normalize()
}

// SaveSettings checks and saves settings.
func (s *Store) SaveSettings(ctx context.Context, set Settings) (Settings, error) {
	set, err := set.Normalize()
	if err != nil {
		return set, err
	}
	b, _ := json.Marshal(set)
	return set, s.DB.SetSetting(ctx, settingSettings, string(b))
}

// Account is HardyOS's Immich account (empty when there's none, or when
// the sealed one can't be opened here).
func (s *Store) Account(ctx context.Context) (Account, error) {
	var a Account
	err := s.sealed(ctx, settingAccount, &a)
	if errors.Is(err, ErrSealed) {
		return Account{}, nil
	}
	return a, err
}

// SaveAccount saves the account sealed.
func (s *Store) SaveAccount(ctx context.Context, a Account) error {
	return s.setSealed(ctx, settingAccount, a)
}

// Client is the saved sign-in client secret.
func (s *Store) Client(ctx context.Context) (ClientCreds, error) {
	var c ClientCreds
	err := s.sealed(ctx, settingClient, &c)
	if errors.Is(err, ErrSealed) {
		return ClientCreds{}, nil
	}
	return c, err
}

// SaveClient saves the client secret sealed ("" forgets it).
func (s *Store) SaveClient(ctx context.Context, c ClientCreds) error {
	if c.ID == "" {
		return s.DB.SetSetting(ctx, settingClient, "")
	}
	return s.setSealed(ctx, settingClient, c)
}

// MLApplied is the machine learning mode last set on the app.
func (s *Store) MLApplied(ctx context.Context) string {
	v, _ := s.DB.GetSetting(ctx, settingMLMode)
	return v
}

// SetMLApplied records the mode set on the app.
func (s *Store) SetMLApplied(ctx context.Context, mode string) error {
	return s.DB.SetSetting(ctx, settingMLMode, mode)
}

// Status is the last sync's status (nil when there's been none).
func (s *Store) Status(ctx context.Context) (*Status, error) {
	raw, err := s.DB.GetSetting(ctx, settingStatus)
	if errors.Is(err, store.ErrNotFound) || raw == "" {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st Status
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// SaveStatus saves a sync's status.
func (s *Store) SaveStatus(ctx context.Context, st *Status) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.DB.SetSetting(ctx, settingStatus, string(b))
}

// Libraries are the libraries HardyOS made, by key.
func (s *Store) Libraries(ctx context.Context) (map[string]LibRecord, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT key, immich_id, owner_id, import_path, subject FROM photos_libraries`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]LibRecord{}
	for rows.Next() {
		var r LibRecord
		if err := rows.Scan(&r.Key, &r.ImmichID, &r.OwnerID, &r.ImportPath, &r.Subject); err != nil {
			return nil, err
		}
		out[r.Key] = r
	}
	return out, rows.Err()
}

// SaveLibrary records a library HardyOS made.
func (s *Store) SaveLibrary(ctx context.Context, r LibRecord) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO photos_libraries (key, immich_id, owner_id, import_path, subject, created_at) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET immich_id = excluded.immich_id, owner_id = excluded.owner_id, import_path = excluded.import_path, subject = excluded.subject`,
		r.Key, r.ImmichID, r.OwnerID, r.ImportPath, r.Subject, store.Now())
	return err
}

// Accounts are the Immich accounts HardyOS looks after, by Immich id.
func (s *Store) Accounts(ctx context.Context) (map[string]AccountRec, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT immich_id, subject, made, suspended FROM photos_accounts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]AccountRec{}
	for rows.Next() {
		var r AccountRec
		if err := rows.Scan(&r.ImmichID, &r.Subject, &r.Made, &r.Suspended); err != nil {
			return nil, err
		}
		out[r.ImmichID] = r
	}
	return out, rows.Err()
}

// SaveAccountRec records an account HardyOS looks after.
func (s *Store) SaveAccountRec(ctx context.Context, r AccountRec) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO photos_accounts (immich_id, subject, made, suspended, created_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(immich_id) DO UPDATE SET subject = excluded.subject, made = excluded.made, suspended = excluded.suspended`,
		r.ImmichID, r.Subject, r.Made, r.Suspended, store.Now())
	return err
}

// ForgetAccountRec drops an account's record.
func (s *Store) ForgetAccountRec(ctx context.Context, id string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM photos_accounts WHERE immich_id = ?`, id)
	return err
}

// ForgetLibrary drops a library's record.
func (s *Store) ForgetLibrary(ctx context.Context, key string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM photos_libraries WHERE key = ?`, key)
	return err
}

// Partners are the Immich accounts HardyOS made partners of the family
// account.
func (s *Store) Partners(ctx context.Context) (map[string]bool, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT immich_user_id FROM photos_partners`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// SavePartner records a partner HardyOS added.
func (s *Store) SavePartner(ctx context.Context, id string) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO photos_partners (immich_user_id, created_at) VALUES (?, ?) ON CONFLICT DO NOTHING`, id, store.Now())
	return err
}

// ForgetPartner drops a partner's record.
func (s *Store) ForgetPartner(ctx context.Context, id string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM photos_partners WHERE immich_user_id = ?`, id)
	return err
}

// ForgetImmich drops everything HardyOS knew about the Immich it set up
// (the app was removed with its data, or Immich was set up again).
func (s *Store) ForgetImmich(ctx context.Context) error {
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM photos_libraries`); err != nil {
		return err
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM photos_partners`); err != nil {
		return err
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM photos_accounts`); err != nil {
		return err
	}
	if err := s.DB.SetSetting(ctx, settingMLMode, ""); err != nil {
		return err
	}
	return s.DB.SetSetting(ctx, settingAccount, "")
}

// RandomPassword is 32 random bytes, base64url.
func RandomPassword() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
