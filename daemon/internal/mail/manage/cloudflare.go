package manage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/hardyos/hardyos/daemon/internal/mail"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/notify"
)

// Cloudflare DNS (decision 243, optional): with an API token limited to
// "Zone › DNS › Edit" on the mail domains' zones, HardyOS publishes the
// records it shows and answers ACME DNS-01 challenges for the mail
// server's certificate. The token is sealed in hardyd's database and never
// returned. HardyOS only adds records and changes the ones it owns (its
// DKIM selector, the single SPF and DMARC records, its MX); it never
// deletes a record it didn't create, and marks what it creates with the
// comment "hardyos".

// CFComment marks records HardyOS made.
const CFComment = "hardyos"

// Cloudflare is a minimal API v4 client.
type Cloudflare struct {
	Token string
	// HTTP and Base are for tests (default: a guarded client and
	// https://api.cloudflare.com/client/v4).
	HTTP *http.Client
	Base string
}

// CFRecord is a DNS record in Cloudflare.
type CFRecord struct {
	ID       string         `json:"id,omitempty"`
	Type     string         `json:"type"`
	Name     string         `json:"name"`
	Content  string         `json:"content,omitempty"`
	Priority *int           `json:"priority,omitempty"`
	TTL      int            `json:"ttl"`
	Proxied  *bool          `json:"proxied,omitempty"`
	Comment  string         `json:"comment,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
}

type cfResponse struct {
	Success bool            `json:"success"`
	Errors  []cfMsg         `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfMsg struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// CFError is an error Cloudflare reported.
type CFError struct {
	Status int
	Msg    string
}

func (e *CFError) Error() string { return "Cloudflare: " + e.Msg }

func (c *Cloudflare) call(ctx context.Context, method, path string, q url.Values, body any, out any) error {
	base := c.Base
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	u := base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = notify.GuardedClient(false)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("Cloudflare: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var r cfResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return &CFError{Status: resp.StatusCode, Msg: fmt.Sprintf("unexpected answer (%d)", resp.StatusCode)}
	}
	if !r.Success {
		var msgs []string
		for _, e := range r.Errors {
			msgs = append(msgs, mail.ClipText(e.Message, 200))
		}
		if len(msgs) == 0 {
			msgs = []string{fmt.Sprintf("HTTP %d", resp.StatusCode)}
		}
		return &CFError{Status: resp.StatusCode, Msg: strings.Join(msgs, "; ")}
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

// Verify checks the token is active.
func (c *Cloudflare) Verify(ctx context.Context) error {
	var r struct {
		Status string `json:"status"`
	}
	if err := c.call(ctx, http.MethodGet, "/user/tokens/verify", nil, nil, &r); err != nil {
		return err
	}
	if r.Status != "active" {
		return &CFError{Msg: "the token isn't active (" + mail.ClipText(r.Status, 40) + ")"}
	}
	return nil
}

// Zone finds the zone holding name (walking up its labels).
func (c *Cloudflare) Zone(ctx context.Context, name string) (id, zone string, err error) {
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(name, ".")), ".")
	for i := 0; i+2 <= len(labels); i++ {
		cand := strings.Join(labels[i:], ".")
		var zs []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := c.call(ctx, http.MethodGet, "/zones", url.Values{"name": {cand}}, nil, &zs); err != nil {
			return "", "", err
		}
		if len(zs) > 0 {
			return zs[0].ID, zs[0].Name, nil
		}
	}
	return "", "", &CFError{Msg: "no zone for " + name + " is visible to this token"}
}

// Records lists a zone's records of a type and name.
func (c *Cloudflare) Records(ctx context.Context, zoneID, typ, name string) ([]CFRecord, error) {
	var out []CFRecord
	err := c.call(ctx, http.MethodGet, "/zones/"+url.PathEscape(zoneID)+"/dns_records",
		url.Values{"type": {typ}, "name": {name}, "per_page": {"100"}}, nil, &out)
	return out, err
}

// Create adds a record.
func (c *Cloudflare) Create(ctx context.Context, zoneID string, r CFRecord) (*CFRecord, error) {
	var out CFRecord
	err := c.call(ctx, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records", nil, r, &out)
	return &out, err
}

// Update replaces a record.
func (c *Cloudflare) Update(ctx context.Context, zoneID, id string, r CFRecord) error {
	return c.call(ctx, http.MethodPut, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(id), nil, r, nil)
}

// Delete removes a record (only ever one HardyOS made: ACME challenges).
func (c *Cloudflare) Delete(ctx context.Context, zoneID, id string) error {
	return c.call(ctx, http.MethodDelete, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(id), nil, nil, nil)
}

// toCF turns a Record into Cloudflare's form.
func toCF(r mail.Record) CFRecord {
	no := false
	out := CFRecord{Type: r.Type, Name: r.Name, TTL: 1, Comment: CFComment}
	switch r.Type {
	case "MX":
		p := r.Priority
		out.Content, out.Priority = r.Value, &p
	case "SRV":
		f := strings.Fields(r.Value)
		w, _ := strconv.Atoi(f[0])
		port, _ := strconv.Atoi(f[1])
		target := f[2]
		pr := 0
		if target != "." {
			pr = 10
		}
		out.Data = map[string]any{"priority": pr, "weight": w, "port": port, "target": target}
	case "A", "AAAA", "CNAME":
		out.Content, out.Proxied = r.Value, &no
	default:
		out.Content = r.Value
	}
	return out
}

// SyncResult says what publishing did per record.
type SyncResult struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Action string `json:"action"` // created, updated, unchanged, skipped, error
	Detail string `json:"detail,omitempty"`
}

// Publish makes Cloudflare hold the records (see the package comment for
// what is changed and what is left alone).
func (c *Cloudflare) Publish(ctx context.Context, recs []mail.Record) []SyncResult {
	var out []SyncResult
	zones := map[string]string{}
	for _, r := range recs {
		res := SyncResult{Name: r.Name, Type: r.Type}
		zid, ok := zones[r.Name]
		if !ok {
			var err error
			zid, _, err = c.Zone(ctx, r.Name)
			if err != nil {
				res.Action, res.Detail = "error", err.Error()
				out = append(out, res)
				continue
			}
			zones[r.Name] = zid
		}
		existing, err := c.Records(ctx, zid, r.Type, r.Name)
		if err != nil {
			res.Action, res.Detail = "error", err.Error()
			out = append(out, res)
			continue
		}
		want := toCF(r)
		var match, owned *CFRecord
		for i := range existing {
			e := &existing[i]
			if sameRecord(r, *e) {
				match = e
			}
			if owns(r, *e) {
				owned = e
			}
		}
		switch {
		case match != nil:
			res.Action = "unchanged"
		case owned != nil:
			if r.Match == "spf" {
				// Keep the senders already listed; add HardyOS's.
				want.Content = MergeSPF(strings.Trim(owned.Content, `"`), r.Value)
			}
			if err := c.Update(ctx, zid, owned.ID, want); err != nil {
				res.Action, res.Detail = "error", err.Error()
			} else {
				res.Action = "updated"
			}
		case r.Type == "CNAME" && len(existing) > 0, r.Type == "A" && len(existing) > 0 && existing[0].Comment != CFComment:
			res.Action, res.Detail = "skipped", "another record already uses this name; change it yourself"
		default:
			if _, err := c.Create(ctx, zid, want); err != nil {
				res.Action, res.Detail = "error", err.Error()
			} else {
				res.Action = "created"
			}
		}
		out = append(out, res)
	}
	return out
}

// sameRecord reports whether Cloudflare already has r.
func sameRecord(r mail.Record, e CFRecord) bool {
	switch r.Type {
	case "MX":
		return strings.EqualFold(strings.TrimSuffix(e.Content, "."), r.Value)
	case "SRV":
		f := strings.Fields(r.Value)
		if e.Data == nil {
			return false
		}
		return fmt.Sprint(e.Data["port"]) == f[1] && strings.EqualFold(strings.TrimSuffix(fmt.Sprint(e.Data["target"]), "."), strings.TrimSuffix(f[2], "."))
	case "TXT":
		got := strings.Trim(e.Content, `"`)
		got = strings.ReplaceAll(got, `" "`, "")
		st, _ := mail.MatchTXT(r, []string{got})
		return st == "ok" && (r.Match == "" || got == r.Value || r.Match == "spf")
	default:
		return strings.EqualFold(strings.TrimSuffix(e.Content, "."), r.Value)
	}
}

// owns reports whether HardyOS may change e into r: records it made, the
// one SPF and DMARC record, and its own DKIM selector.
func owns(r mail.Record, e CFRecord) bool {
	if e.Comment == CFComment {
		return true
	}
	if r.Type != "TXT" {
		return false
	}
	c := strings.ToLower(strings.Trim(e.Content, `"`))
	switch r.Purpose {
	case "spf", "ses-mailfrom":
		return strings.HasPrefix(c, "v=spf1")
	case "dmarc":
		return strings.HasPrefix(c, "v=dmarc1")
	case "dkim":
		return strings.HasPrefix(c, "v=dkim1")
	}
	return false
}

// MergeSPF adds want's mechanisms to an existing SPF record, before its
// "all" term, keeping everything else (other senders) as it was.
func MergeSPF(have, want string) string {
	terms := strings.Fields(have)
	all := "-all"
	var keep []string
	for _, t := range terms {
		lt := strings.ToLower(t)
		if strings.HasSuffix(lt, "all") && len(lt) <= 4 {
			all = t
			continue
		}
		keep = append(keep, t)
	}
	if len(keep) == 0 || !strings.EqualFold(keep[0], "v=spf1") {
		keep = append([]string{"v=spf1"}, keep...)
	}
	for _, w := range strings.Fields(want) {
		lw := strings.ToLower(w)
		if lw == "v=spf1" || strings.HasSuffix(lw, "all") && len(lw) <= 4 {
			continue
		}
		found := false
		for _, k := range keep {
			if strings.EqualFold(k, w) {
				found = true
			}
		}
		if !found {
			keep = append(keep, w)
		}
	}
	return strings.Join(append(keep, all), " ")
}
