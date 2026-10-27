package cloudbackup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"sync"

	"github.com/hardyos/hardyos/daemon/internal/rootfile"
)

// Root's own record of the destinations, in its state directory on the
// shared state dataset (rootfile.RootStateDir/cloudbackup/targets.json,
// root 0600, read and written without following links). Each target's
// credentials are sealed with AES-256-GCM under a key derived from
// hardyd-priv's master secrets key (purpose "cloud-backup"), bound to the
// target's id, so a copy of the file alone opens nothing.

// StoreFile is the targets file's name in Root.Dir.
const StoreFile = "targets.json"

type storedTarget struct {
	Target Target `json:"target"`
	Sealed string `json:"sealed"` // base64 of the sealed Credentials
}

type storeFile struct {
	Version int            `json:"version"`
	Targets []storedTarget `json:"targets"`
}

// targetStore keeps the targets file.
type targetStore struct {
	dir string
	key func() ([]byte, error)
	mu  sync.Mutex
}

func (s *targetStore) path() string { return filepath.Join(s.dir, StoreFile) }

func (s *targetStore) load() (*storeFile, error) {
	b, err := rootfile.ReadFileInRootDir(s.path())
	if rootfile.IsNotExist(err) {
		return &storeFile{Version: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	var f storeFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", StoreFile, err)
	}
	// Validate what's read like input.
	ok := f.Targets[:0]
	for _, t := range f.Targets {
		tt := t.Target
		if tt.Normalize(tt.Kind == KindLocal) == nil {
			t.Target = tt
			ok = append(ok, t)
		}
	}
	f.Targets = ok
	return &f, nil
}

func (s *targetStore) save(f *storeFile) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return rootfile.WriteInRootDir(s.path(), b, 0o600, 0o700)
}

func (s *targetStore) list() ([]Target, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	out := []Target{}
	for _, t := range f.Targets {
		out = append(out, t.Target)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// get returns a target with its credentials.
func (s *targetStore) get(id string) (*Repo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	for _, t := range f.Targets {
		if t.Target.ID != id {
			continue
		}
		key, err := s.key()
		if err != nil {
			return nil, err
		}
		raw, err := base64.StdEncoding.DecodeString(t.Sealed)
		if err != nil {
			return nil, errSealed
		}
		plain, err := open(key, raw, []byte("cloud-backup:"+id))
		if err != nil {
			return nil, err
		}
		var c Credentials
		if err := json.Unmarshal(plain, &c); err != nil {
			return nil, errSealed
		}
		return &Repo{Target: t.Target, Creds: c}, nil
	}
	return nil, ErrNotFound
}

func (s *targetStore) put(r *Repo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return err
	}
	key, err := s.key()
	if err != nil {
		return err
	}
	plain, _ := json.Marshal(r.Creds)
	sealed, err := seal(key, plain, []byte("cloud-backup:"+r.Target.ID))
	if err != nil {
		return err
	}
	st := storedTarget{Target: r.Target, Sealed: base64.StdEncoding.EncodeToString(sealed)}
	for i := range f.Targets {
		if f.Targets[i].Target.ID == r.Target.ID {
			f.Targets[i] = st
			return s.save(f)
		}
	}
	f.Targets = append(f.Targets, st)
	return s.save(f)
}

func (s *targetStore) remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return err
	}
	out := f.Targets[:0]
	found := false
	for _, t := range f.Targets {
		if t.Target.ID == id {
			found = true
			continue
		}
		out = append(out, t)
	}
	if !found {
		return ErrNotFound
	}
	f.Targets = out
	return s.save(f)
}

var errSealed = errors.New("the destination's saved credentials can't be opened with this server's key; enter them again")

func seal(key, plain, aad []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+g.NonceSize(), 1+g.NonceSize()+len(plain)+g.Overhead())
	out[0] = 1
	if _, err := rand.Read(out[1:]); err != nil {
		return nil, err
	}
	return g.Seal(out, out[1:1+g.NonceSize()], plain, aad), nil
}

func open(key, sealed, aad []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	n := 1 + g.NonceSize()
	if len(sealed) < n+g.Overhead() || sealed[0] != 1 {
		return nil, errSealed
	}
	plain, err := g.Open(nil, sealed[1:n], sealed[n:], aad)
	if err != nil {
		return nil, errSealed
	}
	return plain, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("the sealing key must be 32 bytes")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// NewRepoPassword makes a repository key: 32 random bytes, base64url
// (43 characters).
func NewRepoPassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
