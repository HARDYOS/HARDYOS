package priv

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cfdns"
	"github.com/hardyos/hardyos/daemon/internal/domain"
	"github.com/hardyos/hardyos/daemon/internal/rootfile"
)

// DNS through Cloudflare (decisions 451-454). The administrator's token is
// root's alone: hardyd hands it over once (dns.token.set) and never gets it
// back. It is sealed with a key only root can derive (RootKeyFor, never
// secrets.key) in the keys folder, together with the base domain it was
// pasted for. hardyd can then ask for exactly these things:
//
//   - an ACME DNS-01 challenge record, _acme-challenge.<name> for the base
//     or a name under it, and its removal (only records root made);
//   - one A, AAAA or CNAME record for a name strictly under the base (or
//     *.<base>), only creating records or changing ones HardyOS made.
//
// Root talks only to api.cloudflare.com (cfdns): nothing hardyd sends can
// choose where root's requests go.
const (
	OpDNSStatus      = "dns.status"
	OpDNSTokenSet    = "dns.token.set"
	OpDNSTokenVerify = "dns.token.verify"
	OpDNSTokenClear  = "dns.token.clear"
	OpDNSACMEPresent = "dns.acme.present"
	OpDNSACMECleanup = "dns.acme.cleanup"
	OpDNSRecordSet   = "dns.record.set"
)

// DNSStateFile is root's DNS state in the keys folder ('_' first, like the
// master key, so no pool's key file can have the name).
const DNSStateFile = "_hardyos-dns.json"

// dnsKeyPurpose names the root-only key the token is sealed with.
const dnsKeyPurpose = "dns-cloudflare"

// MaxACMEChallenges bounds the challenge records root keeps at once.
const MaxACMEChallenges = 8

// staleChallenge is when a challenge record is removed without being asked.
const staleChallenge = time.Hour

// DNSStatus is what hardyd may know: never the token.
type DNSStatus struct {
	Set        bool      `json:"set"`
	Provider   string    `json:"provider,omitempty"`
	Base       string    `json:"base,omitempty"`
	Zone       string    `json:"zone,omitempty"`
	SetAt      time.Time `json:"setAt,omitzero"`
	VerifiedAt time.Time `json:"verifiedAt,omitzero"`
	// Problem is the last verification's failure ("" when it worked).
	Problem    string           `json:"problem,omitempty"`
	Challenges int              `json:"challenges"`
	Records    []DNSRecordState `json:"records"`
}

// DNSRecordState is a record dns.record.set made.
type DNSRecordState struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Type    string    `json:"type"`
	Content string    `json:"content"`
	SetAt   time.Time `json:"setAt"`
}

// DNSTokenSetArgs hands root the token and the base domain it is for.
type DNSTokenSetArgs struct {
	Token string `json:"token"`
	Base  string `json:"base"`
}

// DNSTokenClearArgs forgets the token; Confirm must be the base domain.
type DNSTokenClearArgs struct {
	Confirm string `json:"confirm"`
}

// DNSACMEPresentArgs publishes one challenge.
type DNSACMEPresentArgs struct {
	Name  string `json:"name"`  // _acme-challenge.<base or a name under it>
	Value string `json:"value"` // the DNS-01 value (43 base64url characters)
}

// DNSACMEPresentResult names the record made.
type DNSACMEPresentResult struct {
	ID string `json:"id"`
}

// DNSACMECleanupArgs removes a challenge root made ("" = all of them).
type DNSACMECleanupArgs struct {
	ID string `json:"id"`
}

// DNSRecordSetArgs sets one record under the base.
type DNSRecordSetArgs struct {
	Name    string `json:"name"`
	Type    string `json:"type"` // A, AAAA or CNAME
	Content string `json:"content"`
	// TTL in seconds: 1 (Cloudflare's automatic) or 60-86400; 0 = 1.
	TTL int `json:"ttl"`
}

// DNSRecordSetResult says what was done.
type DNSRecordSetResult struct {
	ID     string `json:"id"`
	Action string `json:"action"` // created, updated, unchanged
}

// DNSEnv configures the DNS operations.
type DNSEnv struct {
	// KeyDir is the keys folder (zfs.KeyDir).
	KeyDir string
	// Client makes the Cloudflare client for a token (tests: a fake;
	// default cfdns.New, Cloudflare's real API).
	Client func(token string) *cfdns.Client
	// Now is the clock (tests).
	Now func() time.Time
}

type dnsState struct {
	V          int              `json:"v"`
	Base       string           `json:"base,omitempty"`
	Zone       string           `json:"zone,omitempty"`
	ZoneID     string           `json:"zoneId,omitempty"`
	Sealed     []byte           `json:"sealed,omitempty"`
	SetAt      time.Time        `json:"setAt,omitzero"`
	VerifiedAt time.Time        `json:"verifiedAt,omitzero"`
	Problem    string           `json:"problem,omitempty"`
	Challenges []dnsChallenge   `json:"challenges,omitempty"`
	Records    []DNSRecordState `json:"records,omitempty"`
}

type dnsChallenge struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
}

type dnsOps struct {
	env DNSEnv
	mu  sync.Mutex
}

// tokenRE is what a Cloudflare API token looks like (they are 40
// characters of base64url today; allow some room).
var tokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{20,200}$`)

// RegisterDNS adds the dns.* operations.
func RegisterDNS(s *Server, env DNSEnv) {
	if env.Client == nil {
		env.Client = cfdns.New
	}
	if env.Now == nil {
		env.Now = time.Now
	}
	d := &dnsOps{env: env}
	s.Handle(OpDNSStatus, func(ctx context.Context, _ json.RawMessage) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		st, err := d.load()
		if err != nil {
			return nil, Errorf(CodeFailed, "dns state: %v", err)
		}
		return st.status(), nil
	})
	s.Handle(OpDNSTokenSet, func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a DNSTokenSetArgs
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, Errorf(CodeBadArgs, "bad arguments")
		}
		return d.setToken(ctx, a)
	})
	s.Handle(OpDNSTokenVerify, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return d.verify(ctx)
	})
	s.Handle(OpDNSTokenClear, func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a DNSTokenClearArgs
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, Errorf(CodeBadArgs, "bad arguments")
		}
		return d.clear(ctx, a)
	})
	s.Handle(OpDNSACMEPresent, func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a DNSACMEPresentArgs
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, Errorf(CodeBadArgs, "bad arguments")
		}
		return d.present(ctx, a)
	})
	s.Handle(OpDNSACMECleanup, func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a DNSACMECleanupArgs
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, Errorf(CodeBadArgs, "bad arguments")
		}
		return d.cleanup(ctx, a.ID)
	})
	s.Handle(OpDNSRecordSet, func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a DNSRecordSetArgs
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, Errorf(CodeBadArgs, "bad arguments")
		}
		return d.setRecord(ctx, a)
	})
}

// RegisterHostRecords adds domain.dns.hostnames: the hostnames' A records
// in this server's own DC. The base must be the one root keeps with the
// Cloudflare token (never one hardyd names on its own: a zone for any
// other domain on the DC would take that domain over for the LAN), and the
// address one of this server's.
func RegisterHostRecords(s *Server, m *domain.Manager, keyDir string) {
	d := &dnsOps{env: DNSEnv{KeyDir: keyDir}}
	s.Handle(OpDomainHostRecords, typed(func(ctx context.Context, a domain.HostRecordsArgs) (any, error) {
		d.mu.Lock()
		st, err := d.load()
		d.mu.Unlock()
		if err != nil {
			return nil, Errorf(CodeFailed, "dns state: %v", err)
		}
		if len(st.Sealed) == 0 || st.Base == "" || cfdns.Normalize(a.Base) != st.Base {
			return nil, Errorf(CodeBadArgs, "the names must be under the base domain the Cloudflare token is for")
		}
		a.Base = st.Base
		if !ownAddress(a.Address) {
			return nil, Errorf(CodeBadArgs, "%q isn't an address of this server", a.Address)
		}
		r, err := m.SetHostRecords(ctx, a)
		return r, domainErr(err)
	}))
}

func (st *dnsState) status() DNSStatus {
	out := DNSStatus{Set: len(st.Sealed) > 0, Base: st.Base, Zone: st.Zone, SetAt: st.SetAt, VerifiedAt: st.VerifiedAt,
		Problem: st.Problem, Challenges: len(st.Challenges), Records: []DNSRecordState{}}
	if out.Set {
		out.Provider = "cloudflare"
		out.Records = append(out.Records, st.Records...)
	}
	return out
}

func (d *dnsOps) path() string { return filepath.Join(d.env.KeyDir, DNSStateFile) }

// load reads root's state (empty when there is none). The keys folder sits
// in hardyd's directory: it is read like the master key, root's own folder
// and file, no links (decision 131).
func (d *dnsOps) load() (*dnsState, error) {
	if err := rootfile.EnsureRootDir(d.env.KeyDir, 0o700); err != nil {
		return nil, err
	}
	b, err := rootfile.ReadFileInRootDir(d.path())
	if errors.Is(err, fs.ErrNotExist) {
		return &dnsState{V: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	var st dnsState
	if err := json.Unmarshal(b, &st); err != nil || st.V != 1 {
		return nil, fmt.Errorf("%s isn't HardyOS's DNS state", d.path())
	}
	return &st, nil
}

func (d *dnsOps) save(st *dnsState) error {
	st.V = 1
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return rootfile.WriteInRootDir(d.path(), b, 0o600, 0o700)
}

func (d *dnsOps) key() (cipher.AEAD, error) {
	k, err := RootKeyFor(d.env.KeyDir, dnsKeyPurpose)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// aad binds a sealed token to the base it was pasted for: a state file
// edited to another base doesn't open.
func dnsAAD(base string) []byte { return []byte("hardyos dns token v1\x00" + base) }

func (d *dnsOps) seal(token, base string) ([]byte, error) {
	g, err := d.key()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, []byte(token), dnsAAD(base)), nil
}

func (d *dnsOps) open(st *dnsState) (string, error) {
	if len(st.Sealed) == 0 {
		return "", errors.New("no Cloudflare token is set")
	}
	g, err := d.key()
	if err != nil {
		return "", err
	}
	if len(st.Sealed) < g.NonceSize() {
		return "", errors.New("the stored token is damaged")
	}
	plain, err := g.Open(nil, st.Sealed[:g.NonceSize()], st.Sealed[g.NonceSize():], dnsAAD(st.Base))
	if err != nil {
		return "", errors.New("the stored token can't be decrypted with this server's key: paste it again")
	}
	return string(plain), nil
}

// client opens the token for one operation.
func (d *dnsOps) client(st *dnsState) (*cfdns.Client, error) {
	tok, err := d.open(st)
	if err != nil {
		return nil, Errorf(CodeUnavailable, "%v", err)
	}
	return d.env.Client(tok), nil
}

func cfFailed(err error) error {
	var ce *cfdns.Error
	if errors.As(err, &ce) {
		return Errorf(CodeFailed, "%s", ce.Error())
	}
	return Errorf(CodeFailed, "Cloudflare: %v", err)
}

func (d *dnsOps) setToken(ctx context.Context, a DNSTokenSetArgs) (any, error) {
	tok := strings.TrimSpace(a.Token)
	base := cfdns.Normalize(a.Base)
	if !tokenRE.MatchString(tok) {
		return nil, Errorf(CodeBadArgs, "that doesn't look like a Cloudflare API token")
	}
	if !cfdns.ValidDomain(base) {
		return nil, Errorf(CodeBadArgs, "%q isn't a domain like home.example.net", a.Base)
	}
	cl := d.env.Client(tok)
	if err := cl.Verify(ctx); err != nil {
		return nil, cfFailed(err)
	}
	zid, zone, err := cl.Zone(ctx, base)
	if err != nil {
		return nil, cfFailed(err)
	}
	if zone != base && !strings.HasSuffix(base, "."+zone) {
		return nil, Errorf(CodeFailed, "Cloudflare's zone %s doesn't hold %s", zone, base)
	}
	sealed, err := d.seal(tok, base)
	if err != nil {
		return nil, Errorf(CodeFailed, "sealing the token: %v", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := d.load()
	if err != nil {
		return nil, Errorf(CodeFailed, "dns state: %v", err)
	}
	now := d.env.Now().UTC()
	if st.Base != base || st.ZoneID != zid {
		// Another base or zone: what root made for the old one is no
		// longer its to change through this token.
		st.Records, st.Challenges = nil, nil
	}
	st.Base, st.Zone, st.ZoneID, st.Sealed, st.SetAt, st.VerifiedAt, st.Problem = base, zone, zid, sealed, now, now, ""
	if err := d.save(st); err != nil {
		return nil, Errorf(CodeFailed, "saving the token: %v", err)
	}
	return st.status(), nil
}

func (d *dnsOps) verify(ctx context.Context) (any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := d.load()
	if err != nil {
		return nil, Errorf(CodeFailed, "dns state: %v", err)
	}
	cl, err := d.client(st)
	if err != nil {
		return nil, err
	}
	st.Problem = ""
	if err := cl.Verify(ctx); err != nil {
		st.Problem = err.Error()
	} else if zid, _, err := cl.Zone(ctx, st.Base); err != nil {
		st.Problem = err.Error()
	} else if zid != st.ZoneID {
		st.Problem = "the zone for " + st.Base + " changed in Cloudflare: paste the token again"
	} else {
		st.VerifiedAt = d.env.Now().UTC()
	}
	if err := d.save(st); err != nil {
		return nil, Errorf(CodeFailed, "dns state: %v", err)
	}
	return st.status(), nil
}

func (d *dnsOps) clear(ctx context.Context, a DNSTokenClearArgs) (any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := d.load()
	if err != nil {
		return nil, Errorf(CodeFailed, "dns state: %v", err)
	}
	if len(st.Sealed) == 0 {
		return st.status(), nil
	}
	if cfdns.Normalize(a.Confirm) != st.Base {
		return nil, Errorf(CodeBadArgs, "type the base domain (%s) to forget the token", st.Base)
	}
	// Challenge records are only ever temporary: remove them while the
	// token still works. Records for names stay (they point at this
	// server; the administrator removes them in Cloudflare if wanted).
	if cl, err := d.client(st); err == nil {
		for _, c := range st.Challenges {
			_ = cl.Delete(ctx, st.ZoneID, c.ID)
		}
	}
	empty := &dnsState{V: 1}
	if err := d.save(empty); err != nil {
		return nil, Errorf(CodeFailed, "dns state: %v", err)
	}
	return empty.status(), nil
}

// sweepChallenges removes challenge records older than an hour (a job that
// died before cleaning up).
func (d *dnsOps) sweepChallenges(ctx context.Context, st *dnsState, cl *cfdns.Client) {
	now := d.env.Now()
	keep := st.Challenges[:0]
	for _, c := range st.Challenges {
		if now.Sub(c.Created) > staleChallenge {
			if err := cl.Delete(ctx, st.ZoneID, c.ID); err == nil || isNotFound(err) {
				continue
			}
		}
		keep = append(keep, c)
	}
	st.Challenges = keep
}

func isNotFound(err error) bool {
	var ce *cfdns.Error
	return errors.As(err, &ce) && ce.Status == 404
}

func (d *dnsOps) present(ctx context.Context, a DNSACMEPresentArgs) (any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := d.load()
	if err != nil {
		return nil, Errorf(CodeFailed, "dns state: %v", err)
	}
	name := cfdns.Normalize(a.Name)
	if _, ok := cfdns.ChallengeTarget(name, st.Base); !ok || st.Base == "" {
		return nil, Errorf(CodeBadArgs, "%q isn't an ACME challenge name for %s", a.Name, st.Base)
	}
	if !cfdns.ChallengeValueOK(a.Value) {
		return nil, Errorf(CodeBadArgs, "that isn't a DNS-01 challenge value")
	}
	cl, err := d.client(st)
	if err != nil {
		return nil, err
	}
	d.sweepChallenges(ctx, st, cl)
	if len(st.Challenges) >= MaxACMEChallenges {
		_ = d.save(st)
		return nil, Errorf(CodeFailed, "too many challenge records are waiting to be removed")
	}
	rec, err := cl.Create(ctx, st.ZoneID, cfdns.Record{Type: "TXT", Name: name, Content: a.Value, TTL: 60, Comment: cfdns.ACMEComment})
	if err != nil {
		_ = d.save(st)
		return nil, cfFailed(err)
	}
	st.Challenges = append(st.Challenges, dnsChallenge{ID: rec.ID, Name: name, Created: d.env.Now().UTC()})
	if err := d.save(st); err != nil {
		// Root can't remember it: take it away again.
		_ = cl.Delete(ctx, st.ZoneID, rec.ID)
		return nil, Errorf(CodeFailed, "dns state: %v", err)
	}
	slog.Info("dns challenge published", "name", name)
	return DNSACMEPresentResult{ID: rec.ID}, nil
}

func (d *dnsOps) cleanup(ctx context.Context, id string) (any, error) {
	if id != "" && !cfdns.RecordIDOK(id) {
		return nil, Errorf(CodeBadArgs, "bad record id")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := d.load()
	if err != nil {
		return nil, Errorf(CodeFailed, "dns state: %v", err)
	}
	if id != "" {
		found := false
		for _, c := range st.Challenges {
			found = found || c.ID == id
		}
		if !found {
			// Only records root made for a challenge are ever deleted.
			return nil, Errorf(CodeBadArgs, "no challenge record %s was made by HardyOS", id)
		}
	}
	cl, err := d.client(st)
	if err != nil {
		return nil, err
	}
	keep := st.Challenges[:0]
	var failed error
	for _, c := range st.Challenges {
		if id == "" || c.ID == id {
			if err := cl.Delete(ctx, st.ZoneID, c.ID); err != nil && !isNotFound(err) {
				failed = err
				keep = append(keep, c)
			}
			continue
		}
		keep = append(keep, c)
	}
	st.Challenges = keep
	if err := d.save(st); err != nil {
		return nil, Errorf(CodeFailed, "dns state: %v", err)
	}
	if failed != nil {
		return nil, cfFailed(failed)
	}
	return st.status(), nil
}

func (d *dnsOps) setRecord(ctx context.Context, a DNSRecordSetArgs) (any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := d.load()
	if err != nil {
		return nil, Errorf(CodeFailed, "dns state: %v", err)
	}
	name, typ := cfdns.Normalize(a.Name), strings.ToUpper(strings.TrimSpace(a.Type))
	if st.Base == "" || !cfdns.Under(name, st.Base, true) {
		return nil, Errorf(CodeBadArgs, "%q isn't a name under %s", a.Name, st.Base)
	}
	content, err := cfdns.CheckContent(typ, name, strings.TrimSpace(a.Content))
	if err != nil {
		return nil, Errorf(CodeBadArgs, "%v", err)
	}
	ttl := a.TTL
	if ttl == 0 {
		ttl = 1
	}
	if ttl != 1 && (ttl < 60 || ttl > 86400) {
		return nil, Errorf(CodeBadArgs, "ttl must be 1 (automatic) or 60-86400 seconds")
	}
	cl, err := d.client(st)
	if err != nil {
		return nil, err
	}
	existing, err := cl.Records(ctx, st.ZoneID, "", name)
	if err != nil {
		return nil, cfFailed(err)
	}
	ours := map[string]bool{}
	for _, r := range st.Records {
		ours[r.ID] = true
	}
	var same *cfdns.Record
	var oursOther []cfdns.Record
	for i := range existing {
		e := existing[i]
		if !strings.EqualFold(cfdns.Normalize(e.Name), name) {
			continue
		}
		mine := e.Comment == cfdns.Comment && ours[e.ID]
		if !mine {
			// Someone else's record (or one only claiming to be HardyOS's)
			// holds the name: never changed or deleted by HardyOS.
			return nil, Errorf(CodeFailed, "another record (%s) already uses %s in Cloudflare; HardyOS leaves it alone", clipType(e.Type), name)
		}
		if e.Type == typ && same == nil {
			same = &existing[i]
		} else {
			oursOther = append(oursOther, e)
		}
	}
	no := false
	want := cfdns.Record{Type: typ, Name: name, Content: content, TTL: ttl, Proxied: &no, Comment: cfdns.Comment}
	if typ == "CNAME" || (same == nil && len(oursOther) > 0) {
		// A CNAME stands alone, and a name changes type as a whole: drop
		// HardyOS's records of other types first.
		for _, o := range oursOther {
			if err := cl.Delete(ctx, st.ZoneID, o.ID); err != nil && !isNotFound(err) {
				return nil, cfFailed(err)
			}
			st.Records = dropRecord(st.Records, o.ID)
		}
		oursOther = nil
	}
	res := DNSRecordSetResult{}
	switch {
	case same != nil && strings.EqualFold(cfdns.Normalize(same.Content), content) && same.TTL == ttl:
		res.ID, res.Action = same.ID, "unchanged"
	case same != nil:
		if err := cl.Update(ctx, st.ZoneID, same.ID, want); err != nil {
			return nil, cfFailed(err)
		}
		res.ID, res.Action = same.ID, "updated"
	default:
		rec, err := cl.Create(ctx, st.ZoneID, want)
		if err != nil {
			return nil, cfFailed(err)
		}
		res.ID, res.Action = rec.ID, "created"
	}
	slog.Info("dns record set", "name", name, "type", typ, "content", content, "action", res.Action)
	st.Records = dropRecord(st.Records, res.ID)
	st.Records = append(st.Records, DNSRecordState{ID: res.ID, Name: name, Type: typ, Content: content, SetAt: d.env.Now().UTC()})
	if err := d.save(st); err != nil {
		return nil, Errorf(CodeFailed, "dns state: %v", err)
	}
	return res, nil
}

func clipType(t string) string {
	if len(t) > 10 {
		return t[:10]
	}
	return t
}

func dropRecord(rs []DNSRecordState, id string) []DNSRecordState {
	out := rs[:0]
	for _, r := range rs {
		if r.ID != id {
			out = append(out, r)
		}
	}
	return out
}
