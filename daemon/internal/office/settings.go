package office

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"

	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// AppID is the catalog app that runs the Document Server.
const AppID = "onlyoffice"

// Settings are Control Panel › Office's settings (in hardyd's settings
// table, so settings backups carry them).
type Settings struct {
	// Enabled: the office suite is on (the Document Server app runs and
	// documents open in the editor).
	Enabled bool `json:"enabled"`
	// MaxFileMB is the largest document opened or saved (1-1000, default 100).
	MaxFileMB int `json:"maxFileMB"`
	// FontsShare is a shared folder with extra fonts, bound read only into
	// the Document Server ("" for none).
	FontsShare string `json:"fontsShare"`
}

const (
	settingsKey = "office.settings"
	secretKey   = "office.secret"
	// SecretPurpose is the secretbox purpose the JWT secret is sealed for.
	SecretPurpose = "office"
)

// Normalize fills in defaults.
func (s *Settings) Normalize() {
	if s.MaxFileMB == 0 {
		s.MaxFileMB = DefaultMaxFileBytes >> 20
	}
}

// Valid lists what's wrong with s.
func (s Settings) Valid() []string {
	var p []string
	if s.MaxFileMB < 1 || s.MaxFileMB > 1000 {
		p = append(p, "The largest document is from 1 to 1000 MB.")
	}
	return p
}

// SettingsStore keeps the settings and the sealed JWT secret.
type SettingsStore struct {
	DB   *store.DB
	Keys secretbox.Source

	mu     sync.Mutex
	secret []byte
}

// Load returns the settings (defaults when none are saved).
func (st *SettingsStore) Load(ctx context.Context) (Settings, error) {
	var s Settings
	v, err := st.DB.GetSetting(ctx, settingsKey)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return s, err
	}
	if v != "" {
		if err := json.Unmarshal([]byte(v), &s); err != nil {
			return s, err
		}
	}
	s.Normalize()
	return s, nil
}

// Save stores the settings.
func (st *SettingsStore) Save(ctx context.Context, s Settings) error {
	s.Normalize()
	b, _ := json.Marshal(s)
	return st.DB.SetSetting(ctx, settingsKey, string(b))
}

var secretAAD = []byte("settings:" + secretKey)

// ErrNoSecret: the office suite was never turned on (no secret yet), or
// the secret can't be opened with this server's key (a restore without keys).
var ErrNoSecret = errors.New("the office suite has no secret yet; turn it on in Control Panel › Office")

// Secret returns the JWT secret shared with the Document Server.
func (st *SettingsStore) Secret(ctx context.Context) ([]byte, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.secret != nil {
		return st.secret, nil
	}
	v, err := st.DB.GetSetting(ctx, secretKey)
	if errors.Is(err, store.ErrNotFound) || v == "" {
		return nil, ErrNoSecret
	}
	if err != nil {
		return nil, err
	}
	sealed, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, ErrNoSecret
	}
	key, err := st.Keys.Key(ctx, SecretPurpose)
	if err != nil {
		return nil, err
	}
	plain, err := secretbox.Open(key, sealed, secretAAD)
	if err != nil {
		return nil, ErrNoSecret
	}
	st.secret = plain
	return plain, nil
}

// EnsureSecret returns the secret, making and sealing a new one (32 random
// bytes as 64 hex characters, which the Document Server takes as an
// environment variable) when there is none or it can't be opened. created
// says a new one was made: the Document Server must be given it.
func (st *SettingsStore) EnsureSecret(ctx context.Context) (secret []byte, created bool, err error) {
	if s, err := st.Secret(ctx); err == nil {
		return s, false, nil
	} else if !errors.Is(err, ErrNoSecret) {
		return nil, false, err
	}
	s, err := st.Rotate(ctx)
	return s, err == nil, err
}

// Rotate replaces the secret with a new one.
func (st *SettingsStore) Rotate(ctx context.Context) ([]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	secret := []byte(hex.EncodeToString(raw))
	key, err := st.Keys.Key(ctx, SecretPurpose)
	if err != nil {
		return nil, err
	}
	sealed, err := secretbox.Seal(key, secret, secretAAD)
	if err != nil {
		return nil, err
	}
	if err := st.DB.SetSetting(ctx, secretKey, base64.StdEncoding.EncodeToString(sealed)); err != nil {
		return nil, err
	}
	st.mu.Lock()
	st.secret = secret
	st.mu.Unlock()
	return secret, nil
}
