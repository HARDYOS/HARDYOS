package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// A Challenge is a sign-in whose password was right and that still needs a
// second factor (or enrollment). It lives in memory only, for ChallengeTTL,
// and allows MaxChallengeTries codes; only the token's hash is kept.
type Challenge struct {
	UserID  int64
	Need    Need
	Outside bool
	// SetupOK: a setup code was accepted for this challenge (outside
	// enrollment may go on).
	SetupOK bool
	// Started: enrollment was begun for this challenge.
	Started bool
	expires time.Time
	tries   int
}

// Challenge limits.
const (
	ChallengeTTL      = 10 * time.Minute
	MaxChallengeTries = 5
	maxChallenges     = 5000
)

// ErrNoChallenge: the token is unknown, used up or expired.
var ErrNoChallenge = errors.New("this sign-in has expired; enter your password again")

// ErrTooManyChallenges: too many sign-ins waiting for a code.
var ErrTooManyChallenges = errors.New("too many sign-ins are waiting for a code; try again in a few minutes")

// Challenges holds pending second-factor sign-ins.
type Challenges struct {
	mu  sync.Mutex
	m   map[string]*Challenge
	Now func() time.Time
}

func (c *Challenges) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func challengeKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// Issue starts a challenge and returns its token. A user has at most one
// open challenge per kind of sign-in: a new one replaces older ones.
func (c *Challenges) Issue(uid int64, need Need, outside bool) (string, time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*Challenge{}
	}
	now := c.now()
	n := 0
	for k, ch := range c.m {
		if now.After(ch.expires) {
			delete(c.m, k)
			continue
		}
		if ch.UserID == uid && ch.Outside == outside {
			n++
			if n >= 3 {
				delete(c.m, k)
			}
		}
	}
	if len(c.m) >= maxChallenges {
		return "", time.Time{}, ErrTooManyChallenges
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)
	exp := now.Add(ChallengeTTL)
	c.m[challengeKey(tok)] = &Challenge{UserID: uid, Need: need, Outside: outside, expires: exp}
	return tok, exp, nil
}

// Get returns a copy of the challenge for token, counting a try; it is
// gone after MaxChallengeTries.
func (c *Challenges) Get(token string) (*Challenge, error) {
	if len(token) < 20 || len(token) > 64 {
		return nil, ErrNoChallenge
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	k := challengeKey(token)
	ch := c.m[k]
	if ch == nil {
		return nil, ErrNoChallenge
	}
	if c.now().After(ch.expires) || ch.tries >= MaxChallengeTries {
		delete(c.m, k)
		return nil, ErrNoChallenge
	}
	ch.tries++
	cp := *ch
	return &cp, nil
}

// Update records progress (setup code accepted, enrollment started) on a
// challenge that is still open.
func (c *Challenges) Update(token string, f func(*Challenge)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ch := c.m[challengeKey(token)]; ch != nil {
		f(ch)
	}
}

// Done removes a challenge that succeeded.
func (c *Challenges) Done(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, challengeKey(token))
}

// DropUser removes every open challenge of a user (2FA reset, disabled).
func (c *Challenges) DropUser(uid int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, ch := range c.m {
		if ch.UserID == uid {
			delete(c.m, k)
		}
	}
}

func subtleEq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
