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
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
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
//   - the wildcard's ACME DNS-01 challenge record, exactly
//     _acme-challenge.<base>, and its removal (only records root made);
//   - one A, AAAA or CNAME record for a name strictly under the base (or
//     *.<base>), only creating records or changing ones HardyOS made
//     (dns.record.set, decision 454; registered for the NetBird standby,
//     decision 424);
//   - the NetBird standby's one name (dns.standby.*, decision 424): a name
//     in the token's zone, possibly outside the base, whose existing A/AAAA
//     records the administrator saw and adopted by typing the name;
//     dns.record.set may then point it at this server (public addresses
//     only) and dns.standby.restore puts the adopted records back.
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

	OpDNSStandbyPreview = "dns.standby.preview"
	OpDNSStandbyAdopt   = "dns.standby.adopt"
	OpDNSStandbyRestore = "dns.standby.restore"
	OpDNSStandbyForget  = "dns.standby.forget"
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
	// Standby is the NetBird standby's adopted name (nil when none).
	Standby *DNSStandbyState `json:"standby,omitempty"`
}

// DNSStandbyState is the NetBird standby's name and the records adopted
// for it, with what they held when adopted.
type DNSStandbyState struct {
	Name      string       `json:"name"`
	AdoptedAt time.Time    `json:"adoptedAt"`
	Adopted   []DNSAdopted `json:"adopted"`
}

// DNSAdopted is one adopted record as it was.
type DNSAdopted struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment,omitempty"`
}

// DNSStandbyNameArgs names the standby's name.
type DNSStandbyNameArgs struct {
	Name string `json:"name"`
}

// DNSStandbyPreview is what holds a name now.
type DNSStandbyPreview struct {
	Name    string       `json:"name"`
	Zone    string       `json:"zone"`
	Records []DNSAdopted `json:"records"`
	// Adoptable: every record there is A or AAAA and there is an A.
	Adoptable bool   `json:"adoptable"`
	Problem   string `json:"problem,omitempty"`
}

// DNSStandbyAdoptArgs adopts exactly the records seen in the preview.
type DNSStandbyAdoptArgs struct {
	Name    string   `json:"name"`
	Confirm string   `json:"confirm"`
	IDs     []string `json:"ids"`
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
	// StandbyTakenOver reports whether the NetBird standby has taken over,
	// and for which name (nbstandby.TakenOver); the standby name can be
	// pointed at this server only then. nil: never.
	StandbyTakenOver func() (string, bool)
}

type dnsState struct {
	V      int    `json:"v"`
	Base   string `json:"base,omitempty"`
	Zone   string `json:"zone,omitempty"`
	ZoneID string `json:"zoneId,omitempty"`
	// AccountID is set for an account-owned token (verified at
	// /accounts/{id}/tokens/verify).
	AccountID  string           `json:"accountId,omitempty"`
	Sealed     []byte           `json:"sealed,omitempty"`
	SetAt      time.Time        `json:"setAt,omitzero"`
	VerifiedAt time.Time        `json:"verifiedAt,omitzero"`
	Problem    string           `json:"problem,omitempty"`
	Challenges []dnsChallenge   `json:"challenges,omitempty"`
	Records    []DNSRecordState `json:"records,omitempty"`
	Standby    *DNSStandbyState `json:"standby,omitempty"`
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

// RegisterDNS adds the dns.* operations, dns.record.set and the NetBird
// standby's name operations included (decision 424).
func RegisterDNS(s *Server, env DNSEnv) {
	d := registerDNS(s, env)
	registerRecordSet(s, d)
	registerStandbyDNS(s, d)
}

func registerDNS(s *Server, env DNSEnv) *dnsOps {
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
	return d
}

// registerRecordSet adds dns.record.set (decision 454; registered with the
// NetBird standby, decision 424).
func registerRecordSet(s *Server, d *dnsOps) {
	s.Handle(OpDNSRecordSet, func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a DNSRecordSetArgs
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, Errorf(CodeBadArgs, "bad arguments")
		}
		return d.setRecord(ctx, a)
	})
}

// HostLabels are the names HardyOS itself serves under the base, whatever
// is installed (decision 456).
var HostLabels = []string{"sso", "files", "office", "photos", "mail"}

// RegisterHostRecords adds domain.dns.hostnames: the hostnames' A records
// in this server's own DC. Root decides what may be published, never
// hardyd: the base is the one root keeps with the Cloudflare token (a zone
// for any other domain on the DC would take that domain over for the LAN),
// the labels are HardyOS's own, the desktop's (one valid label) and the ids
// of apps with a web page in root's own apps state (apps), the address is
// one of this server's, and a base that is its Cloudflare zone's apex gets
// no zone of its own on the DC. Removing (no labels) needs none of that: it
// works from the DC's own list, also after the token was forgotten.
func RegisterHostRecords(s *Server, m *domain.Manager, keyDir string, apps func(context.Context) ([]string, error)) {
	d := &dnsOps{env: DNSEnv{KeyDir: keyDir}}
	s.Handle(OpDomainHostRecords, typed(func(ctx context.Context, a domain.HostRecordsArgs) (any, error) {
		if len(a.Labels) == 0 {
			r, err := m.RemoveHostRecords(ctx)
			return r, domainErr(err)
		}
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
		allowed := append([]string{}, HostLabels...)
		if desk := strings.ToLower(strings.TrimSpace(a.Desktop)); cfdns.Under(desk+"."+st.Base, st.Base, false) && !strings.Contains(desk, ".") {
			allowed = append(allowed, desk)
		}
		if apps == nil {
			return nil, Errorf(CodeUnavailable, "the apps state isn't available")
		}
		ids, err := apps(ctx)
		if err != nil {
			return nil, Errorf(CodeFailed, "apps state: %v", err)
		}
		allowed = append(allowed, ids...)
		a.Allowed, a.PublicApex = allowed, st.Base == st.Zone
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
		if st.Standby != nil {
			sb := *st.Standby
			sb.Adopted = append([]DNSAdopted{}, st.Standby.Adopted...)
			out.Standby = &sb
		}
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
	zid, zone, acct, err := cl.Zone(ctx, base)
	if err != nil {
		return nil, cfFailed(err)
	}
	// A user's token verifies at /user/tokens/verify; an account-owned
	// token only at its account's (the zone says which account).
	account := ""
	if err := cl.Verify(ctx, ""); err != nil {
		if acct == "" || cl.Verify(ctx, acct) != nil {
			return nil, cfFailed(err)
		}
		account = acct
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
		st.Records, st.Challenges, st.Standby = nil, nil, nil
	}
	st.Base, st.Zone, st.ZoneID, st.AccountID, st.Sealed, st.SetAt, st.VerifiedAt, st.Problem = base, zone, zid, account, sealed, now, now, ""
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
	if err := cl.Verify(ctx, st.AccountID); err != nil {
		st.Problem = err.Error()
	} else if zid, _, _, err := cl.Zone(ctx, st.Base); err != nil {
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
	if st.Base == "" || name != "_acme-challenge."+st.Base {
		// Only the wildcard's own challenge (decision 453).
		return nil, Errorf(CodeBadArgs, "%q isn't the ACME challenge name for *.%s", a.Name, st.Base)
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
	standby := st.Standby != nil && name == st.Standby.Name
	if st.Base == "" || (!standby && !cfdns.Under(name, st.Base, true)) {
		return nil, Errorf(CodeBadArgs, "%q isn't a name under %s", a.Name, st.Base)
	}
	content, err := cfdns.CheckContent(typ, name, strings.TrimSpace(a.Content))
	if err != nil {
		return nil, Errorf(CodeBadArgs, "%v", err)
	}
	adopted := map[string]bool{}
	if standby {
		// The standby's name is the NetBird server's: only this server's
		// public address, never a CNAME or an address on a private network.
		if typ == "CNAME" {
			return nil, Errorf(CodeBadArgs, "the NetBird standby's name takes A and AAAA records only")
		}
		if !publicAddress(content) {
			return nil, Errorf(CodeBadArgs, "%s isn't a public address", content)
		}
		// Only during a take-over root itself staged, for that name: a
		// request at any other time (hardyd compromised) is refused.
		if d.env.StandbyTakenOver == nil {
			return nil, Errorf(CodeForbidden, "the NetBird standby hasn't taken over")
		}
		if host, ok := d.env.StandbyTakenOver(); !ok || host != name {
			return nil, Errorf(CodeForbidden, "the NetBird standby hasn't taken over %s", name)
		}
		for _, r := range st.Standby.Adopted {
			adopted[r.ID] = true
		}
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
		mine := (e.Comment == cfdns.Comment && ours[e.ID]) || adopted[e.ID]
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

// publicAddress reports whether an A/AAAA content is an internet address
// (not private, CGNAT, link-local or another special range).
func publicAddress(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT (and NetBird's own network)
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
}

// standbyName checks a name for the NetBird standby: in the token's zone
// (strictly under its apex: never the zone itself), ordinary labels only,
// never the base or its wildcard.
func (st *dnsState) standbyName(raw string) (string, error) {
	name := cfdns.Normalize(raw)
	if st.Zone == "" || len(st.Sealed) == 0 {
		return "", Errorf(CodeUnavailable, "save a Cloudflare token first (Control Panel › Hostnames)")
	}
	if !cfdns.ValidDomain(name) || !cfdns.Under(name, st.Zone, false) {
		return "", Errorf(CodeBadArgs, "%q isn't a name inside the Cloudflare zone %s (the zone's own name can't be used)", clipName(raw), st.Zone)
	}
	if name == st.Base {
		return "", Errorf(CodeBadArgs, "the NetBird standby can't use the base domain itself")
	}
	return name, nil
}

func clipName(s string) string {
	if len(s) > 80 {
		return s[:80]
	}
	return s
}

func registerStandbyDNS(s *Server, d *dnsOps) {
	s.Handle(OpDNSStandbyPreview, typed(func(ctx context.Context, a DNSStandbyNameArgs) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		st, err := d.load()
		if err != nil {
			return nil, Errorf(CodeFailed, "dns state: %v", err)
		}
		name, err := st.standbyName(a.Name)
		if err != nil {
			return nil, err
		}
		cl, err := d.client(st)
		if err != nil {
			return nil, err
		}
		recs, err := d.standbyRecords(ctx, cl, st, name)
		if err != nil {
			return nil, err
		}
		out := DNSStandbyPreview{Name: name, Zone: st.Zone, Records: recs}
		out.Adoptable, out.Problem = adoptable(recs)
		return out, nil
	}))
	s.Handle(OpDNSStandbyAdopt, typed(func(ctx context.Context, a DNSStandbyAdoptArgs) (any, error) {
		return d.adoptStandby(ctx, a)
	}))
	s.Handle(OpDNSStandbyRestore, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return d.restoreStandby(ctx)
	})
	s.Handle(OpDNSStandbyForget, typed(func(ctx context.Context, a DNSTokenClearArgs) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		st, err := d.load()
		if err != nil {
			return nil, Errorf(CodeFailed, "dns state: %v", err)
		}
		if st.Standby == nil {
			return st.status(), nil
		}
		if cfdns.Normalize(a.Confirm) != st.Standby.Name {
			return nil, Errorf(CodeBadArgs, "type the name (%s) to forget it", st.Standby.Name)
		}
		var keep []DNSRecordState
		for _, r := range st.Records {
			if r.Name != st.Standby.Name {
				keep = append(keep, r)
			}
		}
		st.Records, st.Standby = keep, nil
		if err := d.save(st); err != nil {
			return nil, Errorf(CodeFailed, "dns state: %v", err)
		}
		return st.status(), nil
	}))
}

func (d *dnsOps) standbyRecords(ctx context.Context, cl *cfdns.Client, st *dnsState, name string) ([]DNSAdopted, error) {
	existing, err := cl.Records(ctx, st.ZoneID, "", name)
	if err != nil {
		return nil, cfFailed(err)
	}
	out := []DNSAdopted{}
	for _, e := range existing {
		if !strings.EqualFold(cfdns.Normalize(e.Name), name) || !cfdns.RecordIDOK(e.ID) {
			continue
		}
		out = append(out, DNSAdopted{ID: e.ID, Type: clipType(e.Type), Content: clipName(e.Content), TTL: e.TTL,
			Proxied: e.Proxied != nil && *e.Proxied, Comment: clipName(e.Comment)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func adoptable(recs []DNSAdopted) (bool, string) {
	hasA := false
	for _, r := range recs {
		switch r.Type {
		case "A":
			hasA = true
		case "AAAA":
		default:
			return false, "a " + r.Type + " record holds the name: the standby only takes over names with A and AAAA records"
		}
	}
	if !hasA {
		return false, "the name has no A record pointing at the VPS"
	}
	return true, ""
}

func (d *dnsOps) adoptStandby(ctx context.Context, a DNSStandbyAdoptArgs) (any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := d.load()
	if err != nil {
		return nil, Errorf(CodeFailed, "dns state: %v", err)
	}
	name, err := st.standbyName(a.Name)
	if err != nil {
		return nil, err
	}
	if cfdns.Normalize(a.Confirm) != name {
		return nil, Errorf(CodeBadArgs, "type the name (%s) to let HardyOS change its records", name)
	}
	if st.Standby != nil {
		// Adopting again could record HardyOS's own address as the
		// "original": forget the old adoption first (after a hand-back).
		return nil, Errorf(CodeBadArgs, "%s is already HardyOS's standby name: forget it first", st.Standby.Name)
	}
	for _, r := range st.Records {
		if r.Name == name {
			return nil, Errorf(CodeBadArgs, "HardyOS already made a record for %s", name)
		}
	}
	cl, err := d.client(st)
	if err != nil {
		return nil, err
	}
	recs, err := d.standbyRecords(ctx, cl, st, name)
	if err != nil {
		return nil, err
	}
	if ok, why := adoptable(recs); !ok {
		return nil, Errorf(CodeBadArgs, "%s", why)
	}
	// Exactly the records the administrator saw: if they changed since,
	// the preview is out of date.
	want := append([]string{}, a.IDs...)
	sort.Strings(want)
	if len(want) != len(recs) {
		return nil, Errorf(CodeBadArgs, "the records for %s changed since you looked: look again", name)
	}
	for i := range recs {
		if recs[i].ID != want[i] {
			return nil, Errorf(CodeBadArgs, "the records for %s changed since you looked: look again", name)
		}
	}
	st.Standby = &DNSStandbyState{Name: name, AdoptedAt: d.env.Now().UTC(), Adopted: recs}
	if err := d.save(st); err != nil {
		return nil, Errorf(CodeFailed, "dns state: %v", err)
	}
	slog.Info("dns standby name adopted", "name", name, "records", len(recs))
	return st.status(), nil
}

// restoreStandby puts the adopted records back as they were and deletes
// records HardyOS added at the name.
func (d *dnsOps) restoreStandby(ctx context.Context) (any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := d.load()
	if err != nil {
		return nil, Errorf(CodeFailed, "dns state: %v", err)
	}
	if st.Standby == nil {
		return nil, Errorf(CodeBadArgs, "there is no standby name")
	}
	cl, err := d.client(st)
	if err != nil {
		return nil, err
	}
	sb := st.Standby
	adopted := map[string]bool{}
	for i, r := range sb.Adopted {
		adopted[r.ID] = true
		proxied := r.Proxied
		rec := cfdns.Record{Type: r.Type, Name: sb.Name, Content: r.Content, TTL: r.TTL, Proxied: &proxied, Comment: r.Comment}
		if err := cl.Update(ctx, st.ZoneID, r.ID, rec); err != nil {
			if !isNotFound(err) {
				return nil, cfFailed(err)
			}
			// Gone (HardyOS changed the name's type, or someone deleted
			// it): make it again.
			made, err := cl.Create(ctx, st.ZoneID, rec)
			if err != nil {
				return nil, cfFailed(err)
			}
			delete(adopted, r.ID)
			sb.Adopted[i].ID = made.ID
			adopted[made.ID] = true
		}
	}
	var keep []DNSRecordState
	for _, r := range st.Records {
		if r.Name != sb.Name {
			keep = append(keep, r)
			continue
		}
		if adopted[r.ID] {
			continue
		}
		if err := cl.Delete(ctx, st.ZoneID, r.ID); err != nil && !isNotFound(err) {
			return nil, cfFailed(err)
		}
	}
	st.Records = keep
	if err := d.save(st); err != nil {
		return nil, Errorf(CodeFailed, "dns state: %v", err)
	}
	slog.Info("dns standby name restored", "name", sb.Name)
	return st.status(), nil
}
