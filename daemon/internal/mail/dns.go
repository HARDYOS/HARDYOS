package mail

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"
)

// Record is one DNS record a mail domain needs.
type Record struct {
	// Type is MX, TXT, CNAME, A, AAAA or SRV.
	Type string `json:"type"`
	// Name is the full name (no trailing dot).
	Name string `json:"name"`
	// Value is what the record holds: the host for MX/CNAME, the address
	// for A/AAAA, the text for TXT (unquoted, unsplit) and
	// "<weight> <port> <target>" for SRV.
	Value    string `json:"value"`
	Priority int    `json:"priority"`
	// Purpose groups records in the UI: mx, host, spf, dkim, dmarc, ses,
	// ses-mailfrom, autoconfig, srv, mta-sts.
	Purpose string `json:"purpose"`
	// Required records must be right for mail to work; the others help
	// mail apps or reports.
	Required bool   `json:"required"`
	Note     string `json:"note,omitempty"`
	// Match is how the check compares: "exact" (default), "spf", "dkim",
	// "dmarc", "prefix" (a TXT starting with Value), "sts".
	Match string `json:"-"`
}

// DomainDNS is what a domain's records are made from.
type DomainDNS struct {
	Domain   string
	Hostname string // the mail server's name (MX target)
	// DKIMSelector and DKIMPublicKey (base64 DER) are HardyOS's key.
	DKIMSelector  string
	DKIMPublicKey string
	// DMARCPolicy is none, quarantine or reject; DMARCReports gets the
	// aggregate reports ("" for none).
	DMARCPolicy  string
	DMARCReports string
	// SES: tokens for Easy DKIM (three CNAMEs), the region, and whether a
	// custom MAIL FROM (bounce.<domain>) is used.
	SES          bool
	SESRegion    string
	SESDKIM      []string
	SESMailFrom  bool
	MTASTS       string // off, testing, enforce
	MTASTSID     string // changes whenever the policy does
	ReportsEmail string // TLS-RPT reports (MTA-STS)
}

// ServerRecords are the mail server name's own address records (the VPS's
// public addresses). They're listed once, not per domain.
func ServerRecords(hostname, ipv4, ipv6 string) []Record {
	var out []Record
	if ipv4 != "" {
		out = append(out, Record{Type: "A", Name: hostname, Value: ipv4, Purpose: "host", Required: true,
			Note: "The mail server's name points to the VPS, which receives mail and forwards it home. An MX may not point to a CNAME, so this is an A record (it overrides a wildcard)."})
	}
	if ipv6 != "" {
		out = append(out, Record{Type: "AAAA", Name: hostname, Value: ipv6, Purpose: "host", Required: false})
	}
	return out
}

// DKIMValue is the TXT record of a DKIM public key.
func DKIMValue(pub string) string { return "v=DKIM1; k=rsa; p=" + pub }

// DMARCValue is the DMARC record for a policy and report address.
func DMARCValue(policy, reports string) string {
	if policy == "" {
		policy = "quarantine"
	}
	v := "v=DMARC1; p=" + policy
	if reports != "" {
		v += "; rua=mailto:" + reports
	}
	return v + "; adkim=r; aspf=r"
}

// SPFValue is the domain's SPF record: the MX (the VPS, which sends
// bounces for mail it queued) and Amazon SES (everything people send).
func SPFValue(ses bool) string {
	if ses {
		return "v=spf1 mx include:amazonses.com -all"
	}
	return "v=spf1 mx -all"
}

// Records lists every record a domain needs, required ones first.
func Records(d DomainDNS) []Record {
	h := d.Hostname
	out := []Record{
		{Type: "MX", Name: d.Domain, Value: h, Priority: 10, Purpose: "mx", Required: true,
			Note: "Mail for this domain goes to the VPS."},
		{Type: "TXT", Name: d.Domain, Value: SPFValue(d.SES), Purpose: "spf", Required: true, Match: "spf",
			Note: "Who may send for this domain. Keep a single v=spf1 record; merge other senders into it."},
	}
	if d.DKIMPublicKey != "" {
		out = append(out, Record{Type: "TXT", Name: d.DKIMSelector + "._domainkey." + d.Domain, Value: DKIMValue(d.DKIMPublicKey),
			Purpose: "dkim", Required: true, Match: "dkim", Note: "HardyOS signs everything people send with this key."})
	}
	out = append(out, Record{Type: "TXT", Name: "_dmarc." + d.Domain, Value: DMARCValue(d.DMARCPolicy, d.DMARCReports),
		Purpose: "dmarc", Required: true, Match: "dmarc", Note: "What receivers do with mail that fails SPF and DKIM."})
	if d.SES {
		for _, t := range d.SESDKIM {
			out = append(out, Record{Type: "CNAME", Name: t + "._domainkey." + d.Domain, Value: t + ".dkim.amazonses.com",
				Purpose: "ses", Required: true, Note: "Verifies the domain with Amazon SES (Easy DKIM)."})
		}
		if d.SESMailFrom && d.SESRegion != "" {
			out = append(out,
				Record{Type: "MX", Name: "bounce." + d.Domain, Value: "feedback-smtp." + d.SESRegion + ".amazonses.com", Priority: 10,
					Purpose: "ses-mailfrom", Required: true, Note: "SES's custom MAIL FROM domain (bounces), so SPF aligns for DMARC."},
				Record{Type: "TXT", Name: "bounce." + d.Domain, Value: "v=spf1 include:amazonses.com -all", Purpose: "ses-mailfrom", Required: true, Match: "spf"})
		}
	}
	out = append(out,
		Record{Type: "SRV", Name: "_submissions._tcp." + d.Domain, Value: "1 465 " + h, Purpose: "srv", Note: "Lets mail apps find the server (RFC 6186, 8314)."},
		Record{Type: "SRV", Name: "_submission._tcp." + d.Domain, Value: "1 587 " + h, Purpose: "srv"},
		Record{Type: "SRV", Name: "_imaps._tcp." + d.Domain, Value: "1 993 " + h, Purpose: "srv"},
		Record{Type: "SRV", Name: "_imap._tcp." + d.Domain, Value: "0 0 .", Purpose: "srv", Note: "No plain IMAP."},
		Record{Type: "SRV", Name: "_pop3._tcp." + d.Domain, Value: "0 0 .", Purpose: "srv", Note: "No POP3."},
		Record{Type: "SRV", Name: "_pop3s._tcp." + d.Domain, Value: "0 0 .", Purpose: "srv"},
		Record{Type: "SRV", Name: "_autodiscover._tcp." + d.Domain, Value: "1 443 " + h, Purpose: "autoconfig",
			Note: "Outlook finds its settings at https://" + h + "/autodiscover/autodiscover.xml."},
		Record{Type: "SRV", Name: "_caldavs._tcp." + d.Domain, Value: "1 443 " + h, Purpose: "srv", Note: "Calendars."},
		Record{Type: "SRV", Name: "_carddavs._tcp." + d.Domain, Value: "1 443 " + h, Purpose: "srv", Note: "Contacts."},
		Record{Type: "TXT", Name: "_caldavs._tcp." + d.Domain, Value: "path=" + DAVPath, Purpose: "srv", Match: "prefix"},
		Record{Type: "TXT", Name: "_carddavs._tcp." + d.Domain, Value: "path=" + DAVPath, Purpose: "srv", Match: "prefix"},
		Record{Type: "CNAME", Name: "autoconfig." + d.Domain, Value: h, Purpose: "autoconfig",
			Note: "Thunderbird. Works only if " + h + "'s HTTPS certificate also covers this name; otherwise Thunderbird uses the SRV records or the settings on the Mail setup page."},
	)
	switch d.MTASTS {
	case "testing", "enforce":
		out = append(out,
			Record{Type: "TXT", Name: "_mta-sts." + d.Domain, Value: "v=STSv1; id=" + d.MTASTSID, Purpose: "mta-sts", Match: "sts",
				Note: "MTA-STS: senders insist on TLS to the VPS. Needs the policy served at https://mta-sts." + d.Domain + "/.well-known/mta-sts.txt with a certificate for that name, and a trusted certificate on the VPS's port 25."},
			Record{Type: "TXT", Name: "_smtp._tls." + d.Domain, Value: "v=TLSRPTv1; rua=mailto:" + d.ReportsEmail, Purpose: "mta-sts", Match: "prefix"},
		)
	}
	return out
}

// MTASTSPolicy is the policy file served at mta-sts.<domain>.
func MTASTSPolicy(mode, hostname string) string {
	return "version: STSv1\nmode: " + mode + "\nmx: " + hostname + "\nmax_age: 604800\n"
}

// DAVPath is where hardyd serves calendars and contacts.
const DAVPath = "/dav-mail/"

// Resolver is the subset of net.Resolver the checks use.
type Resolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
}

// PublicResolver asks public DNS servers (Cloudflare, then Google), not
// the server's own resolver: the domain controller answers for the home
// domain and would hide what the internet sees.
func PublicResolver() *net.Resolver {
	servers := []string{"1.1.1.1:53", "8.8.8.8:53"}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 4 * time.Second}
		var last error
		for _, s := range servers {
			c, err := d.DialContext(ctx, network, s)
			if err == nil {
				return c, nil
			}
			last = err
		}
		return nil, last
	}}
}

// Check is a record's state in public DNS.
type Check struct {
	Record
	// Status: ok, missing, wrong, error (DNS didn't answer).
	Status string   `json:"status"`
	Found  []string `json:"found"`
	Detail string   `json:"detail,omitempty"`
}

func trimDot(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }

func notFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// CheckRecords looks each record up.
func CheckRecords(ctx context.Context, r Resolver, recs []Record) []Check {
	out := make([]Check, 0, len(recs))
	for _, rec := range recs {
		out = append(out, checkOne(ctx, r, rec))
	}
	return out
}

func checkOne(ctx context.Context, r Resolver, rec Record) Check {
	c := Check{Record: rec, Found: []string{}}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	fail := func(err error) Check {
		if notFound(err) {
			c.Status = "missing"
			return c
		}
		c.Status, c.Detail = "error", err.Error()
		return c
	}
	switch rec.Type {
	case "MX":
		mxs, err := r.LookupMX(ctx, rec.Name)
		if err != nil {
			return fail(err)
		}
		for _, mx := range mxs {
			c.Found = append(c.Found, fmt.Sprintf("%d %s", mx.Pref, trimDot(mx.Host)))
			if trimDot(mx.Host) == rec.Value {
				c.Status = "ok"
			}
		}
		if c.Status == "" {
			c.Status = statusFor(c.Found)
			if len(mxs) > 0 {
				c.Detail = "other mail servers are listed; mail may go there instead"
			}
		} else if len(mxs) > 1 {
			c.Detail = "more MX records are listed: mail that goes to them won't reach HardyOS"
		}
	case "A", "AAAA":
		ips, err := r.LookupNetIP(ctx, map[string]string{"A": "ip4", "AAAA": "ip6"}[rec.Type], rec.Name)
		if err != nil {
			return fail(err)
		}
		want, _ := netip.ParseAddr(rec.Value)
		for _, ip := range ips {
			c.Found = append(c.Found, ip.Unmap().String())
			if ip.Unmap() == want.Unmap() {
				c.Status = "ok"
			}
		}
		if c.Status == "" {
			c.Status = statusFor(c.Found)
		}
	case "CNAME":
		cn, err := r.LookupCNAME(ctx, rec.Name)
		if err != nil {
			return fail(err)
		}
		cn = trimDot(cn)
		c.Found = append(c.Found, cn)
		switch {
		case cn == rec.Value:
			c.Status = "ok"
		case cn == trimDot(rec.Name):
			c.Status, c.Found = "missing", []string{}
		default:
			c.Status = "wrong"
		}
	case "SRV":
		_, srvs, err := r.LookupSRV(ctx, "", "", rec.Name)
		if err != nil {
			return fail(err)
		}
		f := strings.Fields(rec.Value) // weight port target
		for _, s := range srvs {
			got := fmt.Sprintf("%d %d %s", s.Weight, s.Port, trimDot(s.Target))
			if trimDot(s.Target) == "" {
				got = fmt.Sprintf("%d %d .", s.Weight, s.Port)
			}
			c.Found = append(c.Found, got)
			if len(f) == 3 && fmt.Sprint(s.Port) == f[1] && (trimDot(s.Target) == f[2] || (f[2] == "." && trimDot(s.Target) == "")) {
				c.Status = "ok"
			}
		}
		if c.Status == "" {
			c.Status = statusFor(c.Found)
		}
	case "TXT":
		txts, err := r.LookupTXT(ctx, rec.Name)
		if err != nil {
			return fail(err)
		}
		c.Found = txts
		c.Status, c.Detail = matchTXT(rec, txts)
	default:
		c.Status, c.Detail = "error", "unknown record type"
	}
	return c
}

func statusFor(found []string) string {
	if len(found) == 0 {
		return "missing"
	}
	return "wrong"
}

// spfTerms are an SPF record's mechanisms.
func spfTerms(v string) []string { return strings.Fields(strings.ToLower(v)) }

func matchTXT(rec Record, txts []string) (string, string) {
	switch rec.Match {
	case "spf":
		var spf []string
		for _, t := range txts {
			if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
				spf = append(spf, t)
			}
		}
		if len(spf) == 0 {
			return "missing", ""
		}
		if len(spf) > 1 {
			return "wrong", "there are several SPF records; receivers treat that as an error. Merge them into one."
		}
		have := spfTerms(spf[0])
		for _, want := range spfTerms(rec.Value) {
			if want == "-all" || want == "v=spf1" {
				continue
			}
			if !slices.Contains(have, want) {
				return "wrong", "the SPF record lacks " + want
			}
		}
		if !slices.ContainsFunc(have, func(t string) bool { return t == "-all" || t == "~all" }) {
			return "wrong", "the SPF record should end with -all (or ~all)"
		}
		return "ok", ""
	case "dkim":
		want := keyOf(rec.Value)
		for _, t := range txts {
			if keyOf(t) == want && want != "" {
				return "ok", ""
			}
		}
		return statusFor(txts), ""
	case "dmarc":
		for _, t := range txts {
			if strings.HasPrefix(strings.ToUpper(strings.ReplaceAll(t, " ", "")), "V=DMARC1") {
				if strings.Contains(strings.ReplaceAll(t, " ", ""), "p=none") {
					return "ok", "the policy is p=none: failing mail is still delivered"
				}
				return "ok", ""
			}
		}
		return statusFor(txts), ""
	case "prefix":
		for _, t := range txts {
			if strings.HasPrefix(t, strings.SplitN(rec.Value, ";", 2)[0]) {
				return "ok", ""
			}
		}
		return statusFor(txts), ""
	case "sts":
		for _, t := range txts {
			if t == rec.Value {
				return "ok", ""
			}
			if strings.HasPrefix(t, "v=STSv1") {
				return "wrong", "the policy id differs: publish the new one"
			}
		}
		return statusFor(txts), ""
	}
	for _, t := range txts {
		if t == rec.Value {
			return "ok", ""
		}
	}
	return statusFor(txts), ""
}

// keyOf is a DKIM record's p= value without spaces.
func keyOf(v string) string {
	for _, part := range strings.Split(strings.ReplaceAll(v, " ", ""), ";") {
		if k, val, ok := strings.Cut(part, "="); ok && k == "p" {
			return val
		}
	}
	return ""
}

// Summary counts a domain's check results.
type Summary struct {
	OK       int  `json:"ok"`
	Problems int  `json:"problems"` // required records missing or wrong
	Optional int  `json:"optional"` // optional records missing or wrong
	Ready    bool `json:"ready"`    // every required record is right
}

// Summarize counts problems.
func Summarize(cs []Check) Summary {
	var s Summary
	for _, c := range cs {
		switch {
		case c.Status == "ok":
			s.OK++
		case c.Required:
			s.Problems++
		default:
			s.Optional++
		}
	}
	s.Ready = s.Problems == 0
	return s
}

// SortRecords puts required records first, then by purpose and name.
func SortRecords(rs []Record) {
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].Required != rs[j].Required {
			return rs[i].Required
		}
		return false
	})
}
