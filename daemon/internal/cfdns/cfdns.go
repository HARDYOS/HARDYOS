// Package cfdns is the small Cloudflare DNS client hardyd-priv uses for the
// hostnames feature (decisions 450-454). Only root holds the token; hardyd
// asks for named operations (an ACME challenge record, one A/AAAA/CNAME
// record under the base domain), never for the token.
//
// The client talks to one fixed address (api.cloudflare.com over verified
// TLS), never follows redirects, reads at most 1 MiB per answer and gives up
// after 30 seconds, so nothing hardyd controls can point root's requests
// elsewhere or make it hang.
package cfdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// API is Cloudflare's API base address.
const API = "https://api.cloudflare.com/client/v4"

// Comment marks the records HardyOS made: it only ever changes or deletes
// records carrying it.
const Comment = "hardyos"

// ACMEComment marks ACME challenge records.
const ACMEComment = "hardyos acme"

// Client is a Cloudflare API v4 client for one token.
type Client struct {
	Token string
	// base and hc are set by New (production: API and a client without
	// redirects) or NewForTest.
	base string
	hc   *http.Client
}

// New returns a client for Cloudflare's real API.
func New(token string) *Client {
	return &Client{Token: token, base: API, hc: httpClient(nil)}
}

// NewForTest returns a client for a fake API at base (tests only: hardyd-priv
// never takes an address from hardyd).
func NewForTest(token, base string, hc *http.Client) *Client {
	return &Client{Token: token, base: strings.TrimSuffix(base, "/"), hc: httpClient(hc)}
}

func httpClient(hc *http.Client) *http.Client {
	if hc == nil {
		hc = &http.Client{Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			MaxIdleConns:        2,
			IdleConnTimeout:     30 * time.Second,
		}}
	}
	c := *hc
	c.Timeout = 30 * time.Second
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

// Record is a DNS record in Cloudflare.
type Record struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied *bool  `json:"proxied,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// Error is an error Cloudflare reported (or an answer that wasn't one).
type Error struct {
	Status int
	Msg    string
}

func (e *Error) Error() string { return "Cloudflare: " + e.Msg }

type response struct {
	Success bool            `json:"success"`
	Errors  []message       `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type message struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// clip keeps text from Cloudflare short and printable.
func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "…"
}

func (c *Client) call(ctx context.Context, method, path string, q url.Values, body, out any) error {
	if c.Token == "" {
		return &Error{Msg: "no token"}
	}
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("User-Agent", "HardyOS")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		// The URL holds nothing secret, but keep the message plain.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return &Error{Msg: clip(err.Error(), 200)}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return &Error{Status: resp.StatusCode, Msg: "reading the answer failed"}
	}
	var r response
	if err := json.Unmarshal(raw, &r); err != nil {
		return &Error{Status: resp.StatusCode, Msg: fmt.Sprintf("unexpected answer (HTTP %d)", resp.StatusCode)}
	}
	if !r.Success {
		var msgs []string
		for i, e := range r.Errors {
			if i == 3 {
				break
			}
			msgs = append(msgs, clip(e.Message, 200))
		}
		if len(msgs) == 0 {
			msgs = []string{fmt.Sprintf("HTTP %d", resp.StatusCode)}
		}
		return &Error{Status: resp.StatusCode, Msg: strings.Join(msgs, "; ")}
	}
	if out != nil {
		if err := json.Unmarshal(r.Result, out); err != nil {
			return &Error{Status: resp.StatusCode, Msg: "unexpected result"}
		}
	}
	return nil
}

// Verify checks that the token is active.
func (c *Client) Verify(ctx context.Context) error {
	var r struct {
		Status string `json:"status"`
	}
	if err := c.call(ctx, http.MethodGet, "/user/tokens/verify", nil, nil, &r); err != nil {
		return err
	}
	if r.Status != "active" {
		return &Error{Msg: "the token isn't active (" + clip(r.Status, 40) + ")"}
	}
	return nil
}

// Zone finds the zone holding name, walking up its labels; it returns the
// zone's id and name.
func (c *Client) Zone(ctx context.Context, name string) (id, zone string, err error) {
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(name, ".")), ".")
	for i := 0; i+2 <= len(labels); i++ {
		cand := strings.Join(labels[i:], ".")
		var zs []struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Status string `json:"status"`
		}
		if err := c.call(ctx, http.MethodGet, "/zones", url.Values{"name": {cand}}, nil, &zs); err != nil {
			return "", "", err
		}
		for _, z := range zs {
			if strings.EqualFold(z.Name, cand) && zoneIDRE.MatchString(z.ID) {
				return z.ID, strings.ToLower(z.Name), nil
			}
		}
	}
	return "", "", &Error{Msg: "no zone for " + name + " is visible to this token (it needs Zone › DNS › Edit on that zone)"}
}

var zoneIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// RecordIDOK reports whether id looks like a Cloudflare record id.
func RecordIDOK(id string) bool { return zoneIDRE.MatchString(id) }

// Records lists a zone's records with a name (any type when typ is "").
func (c *Client) Records(ctx context.Context, zoneID, typ, name string) ([]Record, error) {
	q := url.Values{"name": {name}, "per_page": {"100"}}
	if typ != "" {
		q.Set("type", typ)
	}
	var out []Record
	err := c.call(ctx, http.MethodGet, "/zones/"+url.PathEscape(zoneID)+"/dns_records", q, nil, &out)
	return out, err
}

// Create adds a record.
func (c *Client) Create(ctx context.Context, zoneID string, r Record) (*Record, error) {
	var out Record
	if err := c.call(ctx, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records", nil, r, &out); err != nil {
		return nil, err
	}
	if !RecordIDOK(out.ID) {
		return nil, &Error{Msg: "Cloudflare didn't say which record it made"}
	}
	return &out, nil
}

// Update replaces a record.
func (c *Client) Update(ctx context.Context, zoneID, id string, r Record) error {
	return c.call(ctx, http.MethodPut, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(id), nil, r, nil)
}

// Delete removes a record.
func (c *Client) Delete(ctx context.Context, zoneID, id string) error {
	return c.call(ctx, http.MethodDelete, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(id), nil, nil, nil)
}

// ---- names -----------------------------------------------------------------------

var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidDomain reports whether d is a lower-case DNS name of at least two
// labels (no trailing dot, no wildcard, no underscore), at most 253 bytes.
func ValidDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !labelRE.MatchString(l) {
			return false
		}
	}
	// The last label is a TLD: not all digits (then it'd be an address).
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

// Normalize lower-cases a name and drops one trailing dot.
func Normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// Under reports whether name is strictly under base: one or more labels in
// front of it, each a plain label; with wildcard, "*.<base>" also counts.
func Under(name, base string, wildcard bool) bool {
	if !ValidDomain(base) || len(name) > 253 {
		return false
	}
	rest, ok := strings.CutSuffix(name, "."+base)
	if !ok || rest == "" {
		return false
	}
	if wildcard && rest == "*" {
		return true
	}
	for _, l := range strings.Split(rest, ".") {
		if !labelRE.MatchString(l) {
			return false
		}
	}
	return true
}

// ChallengeName is the TXT name for an ACME DNS-01 challenge of name
// ("*.x" and "x" share one).
func ChallengeName(name string) string {
	return "_acme-challenge." + strings.TrimPrefix(name, "*.")
}

// ChallengeTarget is the name an ACME challenge record answers for, if
// name is "_acme-challenge.<target>" with target the base or under it.
func ChallengeTarget(name, base string) (string, bool) {
	t, ok := strings.CutPrefix(name, "_acme-challenge.")
	if !ok {
		return "", false
	}
	return t, t == base || Under(t, base, false)
}

// challengeValueRE is a DNS-01 value: base64url SHA-256 (43 characters).
var challengeValueRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// ChallengeValueOK reports whether v is a DNS-01 record value.
func ChallengeValueOK(v string) bool { return challengeValueRE.MatchString(v) }

// CheckContent validates a record's content for its type: an IPv4 address
// for A, IPv6 for AAAA (neither unspecified, multicast nor loopback), a host
// name for CNAME (not name itself).
func CheckContent(typ, name, content string) (string, error) {
	switch typ {
	case "A", "AAAA":
		a, err := netip.ParseAddr(content)
		if err != nil || a.Zone() != "" {
			return "", fmt.Errorf("%q isn't an IP address", content)
		}
		if (typ == "A") != (a.Is4() || a.Is4In6()) {
			return "", fmt.Errorf("%s records need an IPv%s address", typ, map[bool]string{true: "4", false: "6"}[typ == "A"])
		}
		a = a.Unmap()
		if a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() || a.IsInterfaceLocalMulticast() {
			return "", fmt.Errorf("%s can't be a server's address", a)
		}
		return a.String(), nil
	case "CNAME":
		c := Normalize(content)
		if !ValidDomain(c) {
			return "", fmt.Errorf("%q isn't a host name", content)
		}
		if c == name {
			return "", errors.New("a name can't point at itself")
		}
		return c, nil
	}
	return "", fmt.Errorf("record type %q isn't one HardyOS sets (A, AAAA or CNAME)", typ)
}
