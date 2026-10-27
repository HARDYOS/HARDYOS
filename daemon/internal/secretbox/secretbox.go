// Package secretbox encrypts hardyd's own secrets at rest (the sign-in
// provider's signing keys; a NetBird access token) with a key that isn't in
// hardyd's database: hardyd-priv derives one per purpose from a root-only
// master key (priv.OpSecretsKey), so a copy of the database, or a nightly
// backup on a pool, holds nothing that decrypts them.
package secretbox

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// Source hands out the key for a purpose.
type Source interface {
	Key(ctx context.Context, purpose string) ([]byte, error)
}

// PrivSource asks hardyd-priv (secrets.key) and keeps each key in memory.
type PrivSource struct {
	Priv *priv.Client

	mu   sync.Mutex
	keys map[string][]byte
}

// Key implements Source.
func (p *PrivSource) Key(ctx context.Context, purpose string) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if k, ok := p.keys[purpose]; ok {
		return k, nil
	}
	var res priv.SecretsKeyResult
	if err := p.Priv.Call(ctx, priv.OpSecretsKey, priv.SecretsKeyArgs{Purpose: purpose}, &res); err != nil {
		return nil, err
	}
	if len(res.Key) != 32 {
		return nil, fmt.Errorf("secrets.key gave a %d-byte key", len(res.Key))
	}
	if p.keys == nil {
		p.keys = map[string][]byte{}
	}
	p.keys[purpose] = res.Key
	return res.Key, nil
}

// StaticSource derives every purpose's key from one master key, the way
// hardyd-priv does. For tests and development machines without hardyd-priv.
type StaticSource []byte

// Key implements Source.
func (s StaticSource) Key(_ context.Context, purpose string) ([]byte, error) {
	if len(s) == 0 {
		return nil, errors.New("no master key")
	}
	return priv.DeriveSecretsKey(s, purpose), nil
}

// NewStaticSource returns a StaticSource with a random master key: secrets
// sealed with it last as long as the process.
func NewStaticSource() StaticSource {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return StaticSource(k)
}

const version1 = 1

// ErrOpen means a sealed value couldn't be opened: another key (a restore
// without keys, a new master key) or damaged data.
var ErrOpen = errors.New("the secret can't be decrypted with this server's key")

// Seal encrypts plain with AES-256-GCM. aad binds the value to where it is
// stored (a table and row id), so a sealed value can't be moved to another
// row and still open.
func Seal(key, plain, aad []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+g.NonceSize(), 1+g.NonceSize()+len(plain)+g.Overhead())
	out[0] = version1
	if _, err := rand.Read(out[1:]); err != nil {
		return nil, err
	}
	return g.Seal(out, out[1:1+g.NonceSize()], plain, aad), nil
}

// Open decrypts what Seal made.
func Open(key, sealed, aad []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < 1+g.NonceSize()+g.Overhead() || sealed[0] != version1 {
		return nil, ErrOpen
	}
	n := 1 + g.NonceSize()
	plain, err := g.Open(nil, sealed[1:n], sealed[n:], aad)
	if err != nil {
		return nil, ErrOpen
	}
	return plain, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("secretbox: key must be 32 bytes")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}
