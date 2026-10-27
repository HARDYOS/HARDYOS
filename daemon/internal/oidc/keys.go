package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Key rotation. A new key is published in the JWKS a day before it starts
// signing (so relying parties that cache the JWKS already have it), signs
// for 30 days, and stays published for 2 days after it stops signing:
// longer than any token it signed lives.
const (
	keyPublishAhead = 24 * time.Hour
	keySignFor      = 30 * 24 * time.Hour
	keyKeepAfter    = 48 * time.Hour
	// rsaBits: RS256 is what every relying party supports (it's the one
	// algorithm OpenID Connect requires).
	rsaBits = 2048
)

// SecretsPurpose is the secretbox purpose signing keys are sealed under.
const SecretsPurpose = "oidc-signing"

// KeyInfo describes a signing key for Control Panel.
type KeyInfo struct {
	ID          string     `json:"id"`
	Algorithm   string     `json:"algorithm"`
	State       string     `json:"state"`
	CreatedAt   time.Time  `json:"createdAt"`
	ActivatedAt *time.Time `json:"activatedAt,omitempty"`
	RetiredAt   *time.Time `json:"retiredAt,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
}

// keyring keeps the signing keys: sealed in the database, opened in memory.
type keyring struct {
	db      *store.DB
	secrets secretbox.Source
	now     func() time.Time

	mu     sync.Mutex
	active *signingKey
	public []op.Key
	loaded time.Time
}

type signingKey struct {
	id  string
	key *rsa.PrivateKey
}

func (k *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k *signingKey) Key() any                                    { return k.key }
func (k *signingKey) ID() string                                  { return k.id }

type publicKey struct {
	id  string
	key *rsa.PublicKey
}

func (k *publicKey) ID() string                         { return k.id }
func (k *publicKey) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k *publicKey) Use() string                        { return "sig" }
func (k *publicKey) Key() any                           { return k.key }

func (r *keyring) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// signing returns the key that signs now.
func (r *keyring) signing(ctx context.Context) (*signingKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.loadLocked(ctx); err != nil {
		return nil, err
	}
	if r.active == nil {
		return nil, errors.New("no signing key")
	}
	return r.active, nil
}

// published returns the keys in the JWKS.
func (r *keyring) published(ctx context.Context) ([]op.Key, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.loadLocked(ctx); err != nil {
		return nil, err
	}
	return r.public, nil
}

// invalidate makes the next use read the keys again.
func (r *keyring) invalidate() {
	r.mu.Lock()
	r.loaded = time.Time{}
	r.mu.Unlock()
}

// loadLocked reads the keys (again every minute, so a rotation in another
// request shows up) and makes sure one signs.
func (r *keyring) loadLocked(ctx context.Context) error {
	if !r.loaded.IsZero() && r.clock().Sub(r.loaded) < time.Minute && r.active != nil {
		return nil
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id, private_seal, public_jwk, state, expires_at FROM oidc_keys ORDER BY created_at`)
	if err != nil {
		return err
	}
	type row struct {
		id, jwk, state string
		seal           []byte
		expires        sql.NullString
	}
	var all []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.id, &x.seal, &x.jwk, &x.state, &x.expires); err != nil {
			rows.Close()
			return err
		}
		all = append(all, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	now := r.clock()
	var active *signingKey
	var pub []op.Key
	for _, x := range all {
		if x.expires.Valid && now.After(store.ParseTime(x.expires.String)) {
			continue
		}
		pk, err := parsePublicJWK(x.jwk)
		if err != nil {
			continue
		}
		pub = append(pub, &publicKey{id: x.id, key: pk})
		if x.state == "active" {
			k, err := r.open(ctx, x.id, x.seal)
			if err != nil {
				return fmt.Errorf("signing key %s: %w", x.id, err)
			}
			active = &signingKey{id: x.id, key: k}
		}
	}
	if active == nil {
		return errors.New("no active signing key (run the key check)")
	}
	r.active, r.public, r.loaded = active, pub, now
	return nil
}

func (r *keyring) open(ctx context.Context, id string, seal []byte) (*rsa.PrivateKey, error) {
	kek, err := r.secrets.Key(ctx, SecretsPurpose)
	if err != nil {
		return nil, err
	}
	der, err := secretbox.Open(kek, seal, []byte("oidc_keys:"+id))
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	return rk, nil
}

// KeyEvent is what a key check did, for the audit log.
type KeyEvent struct {
	Action string // oidc.keys.rotate, oidc.keys.replace
	Detail string
}

// check makes the keys follow the schedule: there is an active key and a
// next one, the next one takes over once the active one has signed for 30
// days (and the next one has been published for a day), retired keys
// expire. Keys that can't be opened with this server's key (a settings
// restore without keys) are retired at once and replaced. force rotates
// now (Control Panel's "Rotate now"): the next key signs at once.
func (r *keyring) check(ctx context.Context, force bool) ([]KeyEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock()
	var events []KeyEvent

	type row struct {
		id, state string
		seal      []byte
		created   time.Time
		activated time.Time
	}
	read := func() ([]row, error) {
		rows, err := r.db.QueryContext(ctx, `SELECT id, state, private_seal, created_at, COALESCE(activated_at, '') FROM oidc_keys WHERE state != 'retired'`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []row
		for rows.Next() {
			var x row
			var c, a string
			if err := rows.Scan(&x.id, &x.state, &x.seal, &c, &a); err != nil {
				return nil, err
			}
			x.created = store.ParseTime(c)
			if a != "" {
				x.activated = store.ParseTime(a)
			}
			out = append(out, x)
		}
		return out, rows.Err()
	}
	keys, err := read()
	if err != nil {
		return nil, err
	}
	// Keys this server can't open can't sign: retire them now.
	replaced := 0
	for _, k := range keys {
		if _, err := r.open(ctx, k.id, k.seal); err != nil {
			if !errors.Is(err, secretbox.ErrOpen) {
				return nil, err // hardyd-priv not answering: try again later
			}
			if err := r.retire(ctx, k.id, now); err != nil {
				return nil, err
			}
			replaced++
		}
	}
	if replaced > 0 {
		events = append(events, KeyEvent{Action: "oidc.keys.replace",
			Detail: fmt.Sprintf("%d signing key(s) couldn't be decrypted on this server (restored without keys?) and were replaced; apps fetch the new ones from the JWKS", replaced)})
		if keys, err = read(); err != nil {
			return nil, err
		}
	}
	var active, next *row
	for i := range keys {
		switch keys[i].state {
		case "active":
			if active == nil || keys[i].activated.After(active.activated) {
				active = &keys[i]
			}
		case "next":
			if next == nil || keys[i].created.After(next.created) {
				next = &keys[i]
			}
		}
	}
	if active == nil {
		// First start (or every key replaced): sign at once.
		id, err := r.create(ctx, "active", now)
		if err != nil {
			return nil, err
		}
		active = &row{id: id, state: "active", activated: now}
	}
	due := force || now.Sub(active.activated) >= keySignFor
	if next != nil && due && (force || now.Sub(next.created) >= keyPublishAhead) {
		if _, err := r.db.ExecContext(ctx, `UPDATE oidc_keys SET state = 'active', activated_at = ? WHERE id = ?`, store.FormatTime(now), next.id); err != nil {
			return nil, err
		}
		if err := r.retire(ctx, active.id, now); err != nil {
			return nil, err
		}
		events = append(events, KeyEvent{Action: "oidc.keys.rotate", Detail: fmt.Sprintf("key %s signs now; %s stays published for 2 days", next.id, active.id)})
		next = nil
	} else if next == nil && due && force {
		id, err := r.create(ctx, "active", now)
		if err != nil {
			return nil, err
		}
		if err := r.retire(ctx, active.id, now); err != nil {
			return nil, err
		}
		events = append(events, KeyEvent{Action: "oidc.keys.rotate", Detail: fmt.Sprintf("key %s signs now; %s stays published for 2 days", id, active.id)})
	}
	if next == nil {
		if _, err := r.create(ctx, "next", now); err != nil {
			return nil, err
		}
	}
	// Retired keys past their time leave the table.
	if _, err := r.db.ExecContext(ctx, `DELETE FROM oidc_keys WHERE state = 'retired' AND expires_at < ?`, store.FormatTime(now)); err != nil {
		return nil, err
	}
	r.loaded = time.Time{}
	return events, nil
}

func (r *keyring) retire(ctx context.Context, id string, now time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE oidc_keys SET state = 'retired', retired_at = ?, expires_at = ? WHERE id = ?`,
		store.FormatTime(now), store.FormatTime(now.Add(keyKeepAfter)), id)
	return err
}

func (r *keyring) create(ctx context.Context, state string, now time.Time) (string, error) {
	k, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return "", err
	}
	idb := make([]byte, 12)
	_, _ = rand.Read(idb)
	id := base64.RawURLEncoding.EncodeToString(idb)
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return "", err
	}
	kek, err := r.secrets.Key(ctx, SecretsPurpose)
	if err != nil {
		return "", err
	}
	seal, err := secretbox.Seal(kek, der, []byte("oidc_keys:"+id))
	if err != nil {
		return "", err
	}
	jwk, err := json.Marshal(jose.JSONWebKey{Key: &k.PublicKey, KeyID: id, Algorithm: string(jose.RS256), Use: "sig"})
	if err != nil {
		return "", err
	}
	var activated any
	if state == "active" {
		activated = store.FormatTime(now)
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO oidc_keys (id, alg, private_seal, public_jwk, state, created_at, activated_at) VALUES (?, 'RS256', ?, ?, ?, ?, ?)`,
		id, seal, string(jwk), state, store.FormatTime(now), activated)
	return id, err
}

func parsePublicJWK(s string) (*rsa.PublicKey, error) {
	var j jose.JSONWebKey
	if err := json.Unmarshal([]byte(s), &j); err != nil {
		return nil, err
	}
	pk, ok := j.Key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return pk, nil
}

// list describes the keys for Control Panel.
func (r *keyring) list(ctx context.Context) ([]KeyInfo, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, alg, state, created_at, activated_at, retired_at, expires_at FROM oidc_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []KeyInfo{}
	opt := func(s sql.NullString) *time.Time {
		if !s.Valid || s.String == "" {
			return nil
		}
		t := store.ParseTime(s.String)
		return &t
	}
	for rows.Next() {
		var k KeyInfo
		var created string
		var a, re, ex sql.NullString
		if err := rows.Scan(&k.ID, &k.Algorithm, &k.State, &created, &a, &re, &ex); err != nil {
			return nil, err
		}
		k.CreatedAt = store.ParseTime(created)
		k.ActivatedAt, k.RetiredAt, k.ExpiresAt = opt(a), opt(re), opt(ex)
		out = append(out, k)
	}
	return out, rows.Err()
}
