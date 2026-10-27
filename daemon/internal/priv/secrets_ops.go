package priv

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"

	"github.com/hardyos/hardyos/daemon/internal/rootfile"
)

// OpSecretsKey hands hardyd a key for encrypting one kind of its own data
// at rest (the sign-in provider's signing keys, a NetBird access token).
// Each purpose gets its own key, derived from one master key that only
// root can read. The master key lives with the storage keys
// (/var/lib/hardyos/keys), so it goes only into password-protected
// backups with keys: hardyd's database on its own (a nightly backup on a
// pool, a copied file) holds nothing that decrypts these secrets.
const OpSecretsKey = "secrets.key"

// SecretsKeyArgs names the purpose: lower-case letters, digits and '-'.
type SecretsKeyArgs struct {
	Purpose string `json:"purpose"`
}

// SecretsKeyResult is the 32-byte key for that purpose.
type SecretsKeyResult struct {
	Key []byte `json:"key"`
}

// MasterKeyFile is the master key's name in the keys folder. It starts with
// '_' so it can never be a pool's key file (pool names start with a
// letter), which a pool destroy would delete.
const MasterKeyFile = "_hardyd-secrets.key"

var purposeRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// RegisterSecrets adds secrets.key. keyDir is the keys folder
// (zfs.KeyDir on a real system).
func RegisterSecrets(s *Server, keyDir string) {
	s.Handle(OpSecretsKey, func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a SecretsKeyArgs
		if err := json.Unmarshal(raw, &a); err != nil || !purposeRE.MatchString(a.Purpose) {
			return nil, Errorf(CodeBadArgs, "purpose must be 1-32 lower-case letters, digits or '-'")
		}
		master, err := loadMasterKey(keyDir)
		if err != nil {
			return nil, Errorf(CodeFailed, "secrets key: %v", err)
		}
		return SecretsKeyResult{Key: DeriveSecretsKey(master, a.Purpose)}, nil
	})
}

// DeriveSecretsKey is HMAC-SHA256(master, "hardyos secrets v1\x00" + purpose).
func DeriveSecretsKey(master []byte, purpose string) []byte {
	m := hmac.New(sha256.New, master)
	_, _ = io.WriteString(m, "hardyos secrets v1\x00"+purpose)
	return m.Sum(nil)
}

// loadMasterKey reads the master key, creating it on first use. The keys
// folder sits in hardyd's directory, so it goes through rootfile like the
// pool keys (decision 131): the folder must be root's own (a planted one is
// moved aside), and the key is root's regular file of exactly 32 bytes with
// one name, read and created without following links.
func loadMasterKey(dir string) ([]byte, error) {
	if err := rootfile.EnsureRootDir(dir, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, MasterKeyFile)
	for range 2 {
		b, err := rootfile.ReadFileInRootDir(p)
		if err == nil {
			if len(b) != 32 {
				return nil, fmt.Errorf("%s isn't a 32-byte key file", p)
			}
			return b, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		err = rootfile.CreateExclusive(p, key, 0o600, 0o700)
		if errors.Is(err, fs.ErrExist) {
			continue // someone else made it: read theirs
		}
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	return nil, errors.New("the master key keeps changing")
}
