package publish

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// DefaultKeyFile holds hardyd's key for secrets kept in its database. It
// sits next to the database (on the shared state dataset, owned by hardyd,
// mode 0600) but outside it: settings backups (which carry the database)
// then carry the NetBird token and app passwords only sealed, and a
// restore onto another server needs them entered again.
const DefaultKeyFile = "/var/lib/hardyos/secrets/hardyd.key"

// Sealer encrypts small secrets for the database with AES-256-GCM. Each
// value is bound to its name (additional data), so a sealed value can't be
// moved to another setting.
type Sealer struct {
	// KeyFile is created (32 random bytes) on first use.
	KeyFile string

	once sync.Once
	aead cipher.AEAD
	err  error
}

// ErrSealed: a sealed value can't be opened with this server's key (a
// settings restore from another server, or a lost key file).
var ErrSealed = errors.New("a saved secret can't be read on this server (restored from another server?): enter it again")

const sealPrefix = "v1:"

func (s *Sealer) init() error {
	s.once.Do(func() {
		path := s.KeyFile
		if path == "" {
			path = DefaultKeyFile
		}
		key, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			key = make([]byte, 32)
			if _, err = rand.Read(key); err == nil {
				err = writeKey(path, key)
			}
		}
		if err != nil {
			s.err = fmt.Errorf("secret key: %w", err)
			return
		}
		if len(key) != 32 {
			s.err = fmt.Errorf("secret key %s: want 32 bytes, have %d", path, len(key))
			return
		}
		block, err := aes.NewCipher(key)
		if err == nil {
			s.aead, err = cipher.NewGCM(block)
		}
		s.err = err
	})
	return s.err
}

func writeKey(path string, key []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return nil // another process won the race; init reads it next time
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Seal encrypts value for the setting name ("" stays "").
func (s *Sealer) Seal(name, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if err := s.init(); err != nil {
		return "", err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := s.aead.Seal(nonce, nonce, []byte(value), []byte(name))
	return sealPrefix + base64.RawStdEncoding.EncodeToString(out), nil
}

// Open decrypts a value sealed for name ("" stays "").
func (s *Sealer) Open(name, sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	if err := s.init(); err != nil {
		return "", err
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(sealed, sealPrefix))
	if !strings.HasPrefix(sealed, sealPrefix) || err != nil || len(raw) < s.aead.NonceSize() {
		return "", ErrSealed
	}
	n := s.aead.NonceSize()
	plain, err := s.aead.Open(nil, raw[:n], raw[n:], []byte(name))
	if err != nil {
		return "", ErrSealed
	}
	return string(plain), nil
}
