// Package rootauth checks an administrator's password inside hardyd-priv,
// without trusting hardyd (decision 230). hardyd checks passwords against
// its own database, which a compromised hardyd can change; the few root
// operations that hand out something no backup or restore needs (the cloud
// backup recovery kit: the repository key) ask root to check the password
// itself:
//
//   - a domain account (NETBIOS\name) with a Kerberos AS exchange against
//     the DC this server runs (never a partner DC, decision 78), then its
//     groups by SID: Domain Admins or the recorded HardyOS Admins group;
//   - a local account against root's own verifier: an argon2id hash root
//     keeps for each local administrator it was told about by root itself
//     (the installer's seed, hardyctl reset-password and create-admin) or by
//     the administrator changing their own password with the old one, which
//     root checks first.
//
// A local administrator root has never been told about can't pass; root
// keeps a short failure count of its own.
package rootauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/hardyos/hardyos/daemon/internal/domain"
	"github.com/hardyos/hardyos/daemon/internal/rootfile"
)

// VerifierFile holds local administrators' verifiers in root's state
// directory.
const VerifierFile = "admin-verifiers.json"

// Errors.
var (
	ErrWrong       = errors.New("the password isn't right")
	ErrNotEnrolled = errors.New("the system can't check this account's password itself: sign in with the administrator account made at installation or a domain administrator, or set this account's password with hardyctl reset-password")
	ErrNotAdmin    = errors.New("that account isn't an administrator")
	ErrDomain      = errors.New("the domain controller on this server isn't answering")
	ErrTooMany     = errors.New("too many wrong passwords; try again later")
)

// Domain is what root needs of this server's DC (domain.Manager).
type Domain interface {
	Load() (*domain.Config, error)
	UserGroups(ctx context.Context, username string) (*domain.UserGroups, error)
}

// Checker checks administrators' passwords as root.
type Checker struct {
	// Dir is root's state directory (default rootfile.RootStateDir).
	Dir string
	// Domain is this server's DC; nil when there's none.
	Domain Domain
	// Login does the Kerberos AS exchange (default: gokrb5 against the
	// local DC); tests replace it.
	Login func(ctx context.Context, c *domain.Config, user, password string) error
	Now   func() time.Time

	mu    sync.Mutex
	fails map[string][]time.Time
}

const (
	maxFails   = 5
	failWindow = 15 * time.Minute
)

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Checker) path() string {
	d := c.Dir
	if d == "" {
		d = rootfile.RootStateDir
	}
	return filepath.Join(d, VerifierFile)
}

func key(username string) string { return strings.ToLower(strings.TrimSpace(username)) }

// Check verifies that username is an administrator whose password is
// password.
func (c *Checker) Check(ctx context.Context, username, password string) error {
	k := key(username)
	if k == "" || password == "" || len(password) > 1024 {
		return ErrWrong
	}
	c.mu.Lock()
	if c.fails == nil {
		c.fails = map[string][]time.Time{}
	}
	var recent []time.Time
	for _, t := range c.fails[k] {
		if c.now().Sub(t) < failWindow {
			recent = append(recent, t)
		}
	}
	c.fails[k] = recent
	c.mu.Unlock()
	if len(recent) >= maxFails {
		return ErrTooMany
	}
	err := c.check(ctx, username, password)
	if errors.Is(err, ErrWrong) {
		c.mu.Lock()
		c.fails[k] = append(c.fails[k], c.now())
		c.mu.Unlock()
	}
	return err
}

func (c *Checker) check(ctx context.Context, username, password string) error {
	if nb, name, ok := strings.Cut(username, `\`); ok {
		return c.checkDomain(ctx, nb, name, password)
	}
	v, err := c.load()
	if err != nil {
		return err
	}
	h, ok := v[key(username)]
	if !ok {
		return ErrNotEnrolled
	}
	if !verify(password, h) {
		return ErrWrong
	}
	return nil
}

func (c *Checker) checkDomain(ctx context.Context, netbios, name, password string) error {
	if c.Domain == nil {
		return ErrNotEnrolled
	}
	cfg, err := c.Domain.Load()
	if err != nil || cfg == nil || !cfg.Enabled || cfg.Realm == "" || cfg.IP() == "" {
		return ErrDomain
	}
	if !strings.EqualFold(netbios, cfg.NetBIOS) || name == "" {
		return ErrWrong
	}
	login := c.Login
	if login == nil {
		login = kerberosLogin
	}
	if err := login(ctx, cfg, name, password); err != nil {
		return err
	}
	ug, err := c.Domain.UserGroups(ctx, name)
	if err != nil {
		return ErrDomain
	}
	if !ug.Enabled || ug.LockedOut || ug.Expired {
		return ErrWrong
	}
	da := ""
	if ug.DomainSID != "" {
		da = ug.DomainSID + "-512"
	}
	for _, s := range ug.GroupSIDs {
		if (da != "" && strings.EqualFold(s, da)) || (cfg.AdminsGroupSID != "" && strings.EqualFold(s, cfg.AdminsGroupSID)) {
			return nil
		}
	}
	return ErrNotAdmin
}

func (c *Checker) load() (map[string]string, error) {
	b, err := rootfile.ReadFile(c.path())
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	v := map[string]string{}
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("root's administrator verifiers: %w", err)
	}
	return v, nil
}

func (c *Checker) save(v map[string]string) error {
	b, _ := json.MarshalIndent(v, "", "  ")
	return rootfile.WriteInRootDir(c.path(), b, 0o600, 0o700)
}

// Set records a local administrator's password (root's own callers only:
// hardyctl, the installer's seed).
func (c *Checker) Set(username, password string) error {
	h, err := hash(password)
	if err != nil {
		return err
	}
	return c.SetHash(username, h)
}

// SetHash records an argon2id hash made by root (the installer's seed).
func (c *Checker) SetHash(username, encoded string) error {
	k := key(username)
	if k == "" || strings.Contains(k, `\`) || !strings.HasPrefix(encoded, "$argon2id$") {
		return errors.New("bad administrator verifier")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.load()
	if err != nil {
		return err
	}
	v[k] = encoded
	return c.save(v)
}

// Change replaces a local administrator's verifier when old is the one
// root has (an administrator changing their own password).
func (c *Checker) Change(ctx context.Context, username, old, newPassword string) error {
	if strings.Contains(username, `\`) {
		return nil // domain passwords live in the domain
	}
	if err := c.Check(ctx, username, old); err != nil {
		return err
	}
	if len(newPassword) == 0 || len(newPassword) > 1024 {
		return errors.New("bad new password")
	}
	return c.Set(username, newPassword)
}

// Seed runs once, at hardyd-priv's first start on a new system (before
// hardyd has ever run): it takes the installer's first administrator from
// the seed the installer left for hardyd, then records that root has been
// seeded (an empty verifier file when there was no seed), so a seed file
// written later (by hardyd, which owns it) is never read.
func (c *Checker) Seed(seedPath string) error {
	if _, err := os.Lstat(c.path()); err == nil || !errors.Is(err, os.ErrNotExist) {
		return err
	}
	v := map[string]string{}
	if b, err := readSeed(seedPath); err == nil {
		var s struct {
			Username     string `json:"username"`
			PasswordHash string `json:"passwordHash"`
		}
		if json.Unmarshal(b, &s) == nil && key(s.Username) != "" && !strings.Contains(s.Username, `\`) && strings.HasPrefix(s.PasswordHash, "$argon2id$") {
			v[key(s.Username)] = s.PasswordHash
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.save(v)
}

// readSeed reads the installer's seed without following a link, at most
// 64 KiB.
func readSeed(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, errors.New("the seed isn't a regular file")
	}
	return io.ReadAll(io.LimitReader(f, 64<<10))
}

// argon2id, like internal/auth (same format, so the installer's hash works).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
)

func hash(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	k := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(k)), nil
}

func verify(pw, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m > 1<<20 || t > 16 || p == 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 || len(want) > 64 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
