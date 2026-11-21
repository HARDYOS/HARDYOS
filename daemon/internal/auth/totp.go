package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238's default, what every authenticator app supports
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters (RFC 6238 with its defaults, which every authenticator
// app understands): HMAC-SHA-1, 6 digits, 30-second steps, and one step of
// clock skew either way.
const (
	TOTPDigits     = 6
	TOTPPeriod     = 30
	TOTPSkew       = 1
	totpSecretSize = 20
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a fresh random secret.
func NewTOTPSecret() ([]byte, error) {
	s := make([]byte, totpSecretSize)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	return s, nil
}

// TOTPSecretText is a secret as people type it into an app: base32 in
// groups of four.
func TOTPSecretText(secret []byte) string {
	s := b32.EncodeToString(secret)
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// TOTPStep is the time step t falls in.
func TOTPStep(t time.Time) int64 { return t.Unix() / TOTPPeriod }

// hotp is RFC 4226's HOTP value for counter, with digits digits.
func hotp(secret []byte, counter int64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

// TOTPCode is the code for a time step.
func TOTPCode(secret []byte, step int64) string { return hotp(secret, step, TOTPDigits) }

// TOTPMatch checks code against the steps around now, newest-allowed
// first, and returns the step it matched. Steps at or before after (the
// last step already accepted) never match, so a code can't be replayed.
func TOTPMatch(secret []byte, code string, now time.Time, after int64) (int64, bool) {
	if len(code) != TOTPDigits {
		return 0, false
	}
	cur := TOTPStep(now)
	matched, found := int64(0), 0
	for d := -TOTPSkew; d <= TOTPSkew; d++ {
		step := cur + int64(d)
		ok := subtle.ConstantTimeCompare([]byte(TOTPCode(secret, step)), []byte(code))
		if ok == 1 && step > after && found == 0 {
			matched, found = step, 1
		}
	}
	return matched, found == 1
}

// TOTPURI is the otpauth:// address an authenticator app reads from the QR
// code (Google Authenticator's key URI format).
func TOTPURI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", b32.EncodeToString(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(TOTPDigits))
	q.Set("period", fmt.Sprint(TOTPPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// normalizeCode strips what people type around a code (spaces, dashes)
// and lower-cases it.
func normalizeCode(code string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(code) {
		switch {
		case r == ' ' || r == '-' || r == '\t':
		case r > 0x7e || r < 0x21:
			return ""
		default:
			b.WriteRune(r)
		}
		if b.Len() > 64 {
			return ""
		}
	}
	return b.String()
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}
