package publish

import (
	"context"
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
	"time"
)

// DefaultKeyFile holds hardyd's key for secrets kept in its database. It
// sits next to the database (on the shared state dataset, owned by hardyd,
// mode 0600) but outside it: settings backups (which carry the database)
// then carry the NetBird token and app passwords only sealed, and a
// restore onto another server needs them entered again.
const DefaultKeyFile = "/var/lib/hardyos/secrets/hardyd.key"

// KeySource hands out a 32-byte key for a purpose. It has the shape of
// secretbox.Source (part B): hardyd-priv's secrets.key op derives one per
// purpose from a root-only master key, so the database and the files
// hardyd can read hold nothing that opens the sealed values.
type KeySource interface {
	Key(ctx context.Context, purpose string) ([]byte, error)
}

// KeyPurpose is publishing's purpose name with a KeySource.
const KeyPurpose = "remote-access"

// Sealer encrypts small secrets for the database with AES-256-GCM. Each
// value is bound to its name (additional data), so a sealed value can't be
// moved to another setting.
type Sealer struct {
	// Source, when set, gives the key (purpose KeyPurpose); production
	// passes secretbox.PrivSource. Without one, KeyFile is used, created
	// (32 random bytes) on first use (tests, development).
	Source  KeySource
	KeyFile string

	mu   sync.Mutex
	aead cipher.AEAD
}

// ErrSealed: a sealed value can't be opened with this server's key (a
// settings restore from another server, or a lost key file).
var ErrSealed = errors.New("a saved secret can't be read on this server (restored from another server?): enter it again")

const sealPrefix = "v1:"

func (s *Sealer) init() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aead != nil {
		return nil
	}
	if s.Source != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		key, err := s.Source.Key(ctx, KeyPurpose)
		if err != nil {
			return fmt.Errorf("secret key: %w", err) // not kept: hardyd-priv may be restarting
		}
		return s.setKey(key)
	}
	var ferr error
	func() {
		path := s.KeyFile
		if path == "" {
			path = DefaultKeyFile
		}
		key, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			key = make([]byte, 32)
			if _, err = rand.Read(key); err == nil {
				if err = writeKey(path, key); err == nil {
					key, err = os.ReadFile(path) // another hardyd may have won the race
				}
			}
		}
		if err != nil {
			ferr = fmt.Errorf("secret key: %w", err)
			return
		}
		ferr = s.setKey(key)
	}()
	return ferr
}

func (s *Sealer) setKey(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("secret key: want 32 bytes, have %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	s.aead, err = cipher.NewGCM(block)
	return err
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
