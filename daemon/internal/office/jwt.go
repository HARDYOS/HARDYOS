package office

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// The Document Server and HardyOS share one secret (decision 251) and sign
// everything that crosses between them with HS256 JWTs: the editor config
// hardyd hands the browser, and every callback the Document Server sends.
// This is a deliberately small implementation: HS256 only, the header must
// say exactly that, and anything else (alg "none", RS256 with the secret as
// a "public key", a "crit" header, a "kid") is refused.

// JWT errors.
var (
	ErrTokenMalformed = errors.New("malformed token")
	ErrTokenAlg       = errors.New("token isn't HS256")
	ErrTokenSignature = errors.New("token signature doesn't match")
	ErrTokenExpired   = errors.New("token has expired")
	ErrTokenNotYet    = errors.New("token isn't valid yet")
	ErrTokenNoExpiry  = errors.New("token has no expiry")
)

// MaxTokenBytes bounds a token before anything is decoded.
const MaxTokenBytes = 64 << 10

var b64 = base64.RawURLEncoding

// SignJWT signs claims (a struct or map that marshals to a JSON object)
// with HS256.
func SignJWT(secret []byte, claims any) (string, error) {
	if len(secret) < 16 {
		return "", errors.New("the signing secret is too short")
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	if len(body) == 0 || body[0] != '{' {
		return "", errors.New("claims must be a JSON object")
	}
	head := b64.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	signing := head + "." + b64.EncodeToString(body)
	return signing + "." + b64.EncodeToString(mac(secret, signing)), nil
}

func mac(secret []byte, s string) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(s))
	return m.Sum(nil)
}

// VerifyOptions tune VerifyJWT.
type VerifyOptions struct {
	// Now is the time to check against (default time.Now).
	Now time.Time
	// Leeway is the clock skew allowed on exp/nbf/iat (default 60 s, the
	// Document Server's own clockTolerance).
	Leeway time.Duration
	// RequireExp refuses tokens without an exp claim.
	RequireExp bool
	// MaxAge, if set, refuses tokens whose iat is older than this.
	MaxAge time.Duration
}

// VerifyJWT checks an HS256 token and returns its claims as raw JSON.
func VerifyJWT(secret []byte, token string, opt VerifyOptions) (json.RawMessage, error) {
	if len(secret) == 0 {
		return nil, ErrTokenSignature
	}
	if len(token) == 0 || len(token) > MaxTokenBytes {
		return nil, ErrTokenMalformed
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, ErrTokenMalformed
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	var head map[string]any
	dec := json.NewDecoder(bytes.NewReader(hb))
	if err := dec.Decode(&head); err != nil {
		return nil, ErrTokenMalformed
	}
	if alg, _ := head["alg"].(string); alg != "HS256" {
		return nil, ErrTokenAlg
	}
	for k := range head {
		// typ is optional; nothing else changes how the token is read.
		if k != "alg" && k != "typ" {
			return nil, ErrTokenAlg
		}
	}
	if t, ok := head["typ"]; ok {
		if s, _ := t.(string); !strings.EqualFold(s, "JWT") {
			return nil, ErrTokenAlg
		}
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	if !hmac.Equal(sig, mac(secret, parts[0]+"."+parts[1])) {
		return nil, ErrTokenSignature
	}
	body, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	var std struct {
		Exp *float64 `json:"exp"`
		Nbf *float64 `json:"nbf"`
		Iat *float64 `json:"iat"`
	}
	if err := json.Unmarshal(body, &std); err != nil || len(body) == 0 || body[0] != '{' {
		return nil, ErrTokenMalformed
	}
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}
	leeway := opt.Leeway
	if leeway == 0 {
		leeway = time.Minute
	}
	at := func(f float64) time.Time { return time.Unix(int64(f), 0) }
	if std.Exp == nil {
		if opt.RequireExp {
			return nil, ErrTokenNoExpiry
		}
	} else if now.After(at(*std.Exp).Add(leeway)) {
		return nil, ErrTokenExpired
	}
	if std.Nbf != nil && now.Add(leeway).Before(at(*std.Nbf)) {
		return nil, ErrTokenNotYet
	}
	if std.Iat != nil {
		if now.Add(leeway).Before(at(*std.Iat)) {
			return nil, ErrTokenNotYet
		}
		if opt.MaxAge > 0 && now.Sub(at(*std.Iat)) > opt.MaxAge+leeway {
			return nil, ErrTokenExpired
		}
	}
	return body, nil
}
