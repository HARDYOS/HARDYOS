package api

import (
	"context"
	"encoding/base32"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
)

// totpKit gives tests authenticator codes: it enrolls accounts directly
// and drives the server's two-factor clock forward 31 s for every code,
// so each code is fresh (codes can't be replayed).
type totpKit struct {
	mu      sync.Mutex
	now     time.Time
	s       *Server
	secrets map[string][]byte
}

func newTOTPKit(s *Server) *totpKit {
	k := &totpKit{now: time.Now(), s: s, secrets: map[string][]byte{}}
	s.mfa.Now = k.clock
	return k
}

func (k *totpKit) clock() time.Time {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.now
}

// advance moves the clock on.
func (k *totpKit) advance(d time.Duration) {
	k.mu.Lock()
	k.now = k.now.Add(d)
	k.mu.Unlock()
}

// enroll sets up an authenticator for username (once) and returns its
// recovery codes (nil when it was already enrolled).
func (k *totpKit) enroll(t *testing.T, username string) []string {
	t.Helper()
	k.mu.Lock()
	_, done := k.secrets[strings.ToLower(username)]
	k.mu.Unlock()
	if done {
		return nil
	}
	ctx := context.Background()
	u, err := k.s.users.GetByName(ctx, username)
	if err != nil {
		t.Fatalf("enroll %s: %v", username, err)
	}
	e, err := k.s.mfa.BeginEnroll(ctx, u, "HardyOS")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(e.Secret, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	codes, err := k.s.mfa.ConfirmEnroll(ctx, u, auth.TOTPCode(secret, auth.TOTPStep(k.clock())))
	if err != nil {
		t.Fatal(err)
	}
	k.mu.Lock()
	k.secrets[strings.ToLower(username)] = secret
	k.mu.Unlock()
	return codes
}

// setSecret records a secret enrolled another way (through the API).
func (k *totpKit) setSecret(username string, secret []byte) {
	k.mu.Lock()
	k.secrets[strings.ToLower(username)] = secret
	k.mu.Unlock()
}

// code is a fresh authenticator code for username.
func (k *totpKit) code(t *testing.T, username string) string {
	t.Helper()
	k.mu.Lock()
	defer k.mu.Unlock()
	secret, ok := k.secrets[strings.ToLower(username)]
	if !ok {
		t.Fatalf("%s isn't enrolled", username)
	}
	k.now = k.now.Add(31 * time.Second)
	return auth.TOTPCode(secret, auth.TOTPStep(k.now))
}
