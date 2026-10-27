// Package mail is HardyOS's family mail server (docs/mail.md): Postfix
// (SMTP), Dovecot (IMAP, LMTP, sign-in), Rspamd (spam, DKIM signing,
// optional ClamAV) and Radicale (CalDAV/CardDAV) from Debian, configured by
// HardyOS.
//
// The split follows the rest of HardyOS: hardyd keeps the settings, the
// domains and the mailboxes in its database and decides what the server
// should look like (RootConfig); hardyd-priv validates that again,
// renders every configuration file itself (render.go) and runs the
// services. Root never accepts file contents from hardyd. Passwords are
// never checked by the mail programs themselves: Dovecot asks hardyd
// (auth.go: an OAuth2 password grant and an auth policy server on
// 127.0.0.1), which checks domain passwords with this server's own domain
// controller like a desktop sign-in.
package mail

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// ValidationError is a problem with what was asked for.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(f string, a ...any) error { return &ValidationError{Msg: fmt.Sprintf(f, a...)} }

// Ports HardyOS's mail server listens on. The 10xxx ports take connections
// forwarded by the VPS with the PROXY protocol (the client's real address);
// only the VPS's NetBird address may reach them (nftables) and Dovecot
// trusts PROXY headers from it alone (haproxy_trusted_networks).
const (
	PortRelay        = 2525  // inbound mail relayed by the VPS's Postfix
	PortSubmission   = 587   // STARTTLS submission (LAN, NetBird)
	PortSubmissions  = 465   // implicit TLS submission (LAN, NetBird)
	PortIMAPS        = 993   // IMAP over TLS (LAN, NetBird)
	PortProxySubm    = 10587 // 587 forwarded by the VPS (PROXY v2)
	PortProxySubms   = 10465 // 465 forwarded by the VPS (PROXY v2)
	PortProxyIMAPS   = 10993 // 993 forwarded by the VPS (PROXY v2)
	PortRadicale     = 5232  // Radicale on 127.0.0.1 (hardyd proxies /dav-mail/)
	PortRspamdMilter = 11332 // Rspamd's milter (127.0.0.1)
	PortRspamdCtl    = 11334 // Rspamd's controller (127.0.0.1)
	// DefaultAuthPort is hardyd's mail sign-in listener on 127.0.0.1.
	DefaultAuthPort = 44250
)

// VMailUser owns every mailbox on disk; Dovecot's mail processes run as it.
const VMailUser = "hardyos-vmail"

// NotifyLogin is the sign-in HardyOS's own notifications send with
// (Control Panel › Notifications, the "HardyOS Mail" channel). Its password
// is random, sealed in hardyd's database and checked by hardyd.
const NotifyLogin = "hardyos-notify"

// Limits.
const (
	MaxDomains       = 50
	MaxMailboxes     = 500
	MaxAliases       = 50 // per mailbox
	MaxGroupAliases  = 200
	MaxGroupTargets  = 100
	MaxQuotaMB       = 4 << 20 // 4 TiB
	MaxMessageMB     = 150
	DefaultMessageMB = 50
	DefaultQuotaMB   = 10 * 1024
	DefaultSendHour  = 200
	MaxSendHour      = 10000
)

var (
	labelRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	localRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9._+-]{0,62}[a-z0-9])?$`)
	selectorRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
	sesHostRE  = regexp.MustCompile(`^email-smtp(-fips)?\.[a-z]{2}(-gov)?-[a-z]+-[0-9]\.amazonaws\.com$`)
	sesUserRE  = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)
	secretRE   = regexp.MustCompile(`^[A-Za-z0-9_+/=.-]{16,256}$`)
	poolRE     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]{0,63}$`)
)

// ValidDomain reports whether d is a lower-case DNS name with at least two
// labels (no IDN in A-label form other than plain ASCII, no trailing dot).
func ValidDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 || d != strings.ToLower(d) {
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
	// The last label is a TLD: never all digits.
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

// ValidLocalPart reports whether s is an acceptable local part (lower case
// letters, digits, ".", "_", "+", "-"; no leading, trailing or doubled dot).
func ValidLocalPart(s string) bool {
	return localRE.MatchString(s) && !strings.Contains(s, "..")
}

// SplitAddress splits a lower-case address into local part and domain and
// validates both.
func SplitAddress(a string) (local, domain string, err error) {
	at := strings.LastIndexByte(a, '@')
	if at <= 0 {
		return "", "", invalid("%q isn't an email address", a)
	}
	local, domain = a[:at], a[at+1:]
	if a != strings.ToLower(a) {
		return "", "", invalid("%q must be lower case", a)
	}
	if !ValidLocalPart(local) {
		return "", "", invalid("%q: the part before @ may only use a-z, 0-9, \".\", \"_\", \"+\" and \"-\"", a)
	}
	if !ValidDomain(domain) {
		return "", "", invalid("%q: %q isn't a valid domain", a, domain)
	}
	return local, domain, nil
}

// NormalizeAddress lower-cases and trims an address and validates it.
func NormalizeAddress(a string) (string, error) {
	a = strings.ToLower(strings.TrimSpace(a))
	_, _, err := SplitAddress(a)
	return a, err
}

// RootDomain is a mail domain as root needs it.
type RootDomain struct {
	Name string `json:"name"`
	// Selector names the domain's DKIM key (<selector>._domainkey.<name>);
	// the private key is root's (GenerateDKIM).
	Selector string `json:"selector"`
}

// RootMailbox is one mailbox as root needs it.
type RootMailbox struct {
	// Address is the mailbox's own address; it is also what people sign in
	// with in mail apps.
	Address string `json:"address"`
	// Aliases deliver here and may be sent from.
	Aliases []string `json:"aliases"`
	// QuotaMB is the mailbox's size limit (0: none).
	QuotaMB int `json:"quotaMb"`
}

// RootGroupAlias delivers to several mailboxes (family@).
type RootGroupAlias struct {
	Address string   `json:"address"`
	Targets []string `json:"targets"`
}

// RootSES is Amazon SES's SMTP interface, the only way out.
type RootSES struct {
	Host     string `json:"host"`     // email-smtp.<region>.amazonaws.com
	Port     int    `json:"port"`     // 587 (STARTTLS) or 2587
	Username string `json:"username"` // the SMTP user name (an access key ID)
}

// RootConfig is everything hardyd-priv needs to render and run the mail
// server. hardyd sends it; root validates it again (Normalize).
type RootConfig struct {
	// Pool holds the dataset <pool>/mail (mailboxes, calendars, DKIM keys,
	// the TLS key).
	Pool string `json:"pool"`
	// Hostname is the server's mail name: the MX target, what mail apps
	// connect to and the certificate's name.
	Hostname string `json:"hostname"`
	// VPSPeer is the VPS's NetBird address: the only source for relayed
	// mail (2525) and PROXY-protocol connections (10xxx).
	VPSPeer string `json:"vpsPeer"`
	// Domains this server receives mail for (at least one).
	Domains []RootDomain `json:"domains"`
	// Mailboxes are delivered to; signing in is decided by hardyd.
	Mailboxes []RootMailbox `json:"mailboxes"`
	// GroupAliases deliver to several mailboxes.
	GroupAliases []RootGroupAlias `json:"groupAliases"`
	// Postmaster receives postmaster@, abuse@ and DMARC/TLS reports for
	// every domain (one of Mailboxes; "" for none).
	Postmaster string `json:"postmaster"`
	// SES relays all outgoing mail; nil: mail to other servers waits in
	// the queue ("Sending isn't set up").
	SES *RootSES `json:"ses,omitempty"`
	// ClamAV scans mail for viruses (clamd and freshclam run).
	ClamAV bool `json:"clamav"`
	// JunkScore is Rspamd's score from which mail goes to Junk.
	JunkScore float64 `json:"junkScore"`
	// MaxMessageMB is the largest message accepted.
	MaxMessageMB int `json:"maxMessageMb"`
	// SendPerHour is how many messages one person may send per hour.
	SendPerHour int `json:"sendPerHour"`
	// AuthPort is hardyd's mail sign-in listener on 127.0.0.1.
	AuthPort int `json:"authPort"`
	// NotifyFrom is the one address HardyOS's notifications may send from
	// (NotifyLogin); "" turns that sign-in off.
	NotifyFrom string `json:"notifyFrom"`
	// SharedCalendar makes the family calendar and address book (Radicale
	// collections everyone signed in may change).
	SharedCalendar bool `json:"sharedCalendar"`
}

// RootSecrets are passed along with RootConfig and never stored by hardyd
// in clear.
type RootSecrets struct {
	// SESPassword is the SES SMTP password.
	SESPassword string `json:"sesPassword,omitempty"`
	// AuthSecret proves to hardyd that a sign-in question comes from
	// Dovecot (the policy server's bearer token and the OAuth2 client
	// secret). hardyd makes it; it's only in Dovecot's root-owned config.
	AuthSecret string `json:"authSecret"`
	// DAV maps each mailbox address to the password hardyd uses with
	// Radicale on its behalf (hardyd checks the person's own password,
	// then talks to Radicale on 127.0.0.1 with this).
	DAV map[string]string `json:"dav,omitempty"`
}

// ApplyArgs is hardyd-priv's mail.apply.
type ApplyArgs struct {
	Config  RootConfig  `json:"config"`
	Secrets RootSecrets `json:"secrets"`
}

// Normalize validates a RootConfig with its secrets and fills defaults. It
// is what root relies on: everything that reaches a configuration file has
// passed through here.
func (c RootConfig) Normalize(s RootSecrets) (RootConfig, error) {
	out := c
	if !poolRE.MatchString(c.Pool) {
		return out, invalid("choose the pool mail is kept on")
	}
	if !ValidDomain(c.Hostname) {
		return out, invalid("the mail server's name %q isn't a valid host name (like mail.example.net)", c.Hostname)
	}
	vps, err := netip.ParseAddr(c.VPSPeer)
	if err != nil || vps.IsUnspecified() || vps.IsLoopback() || vps.IsMulticast() {
		return out, invalid("the VPS's NetBird address %q isn't valid", c.VPSPeer)
	}
	out.VPSPeer = vps.Unmap().String()
	if len(c.Domains) == 0 {
		return out, invalid("add a mail domain first")
	}
	if len(c.Domains) > MaxDomains {
		return out, invalid("at most %d mail domains", MaxDomains)
	}
	domains := map[string]bool{}
	out.Domains = nil
	for _, d := range c.Domains {
		if !ValidDomain(d.Name) {
			return out, invalid("%q isn't a valid domain", d.Name)
		}
		if domains[d.Name] {
			return out, invalid("the domain %s is listed twice", d.Name)
		}
		if !selectorRE.MatchString(d.Selector) {
			return out, invalid("the DKIM selector %q isn't valid", d.Selector)
		}
		domains[d.Name] = true
		out.Domains = append(out.Domains, d)
	}
	sort.Slice(out.Domains, func(i, j int) bool { return out.Domains[i].Name < out.Domains[j].Name })

	if len(c.Mailboxes) > MaxMailboxes {
		return out, invalid("at most %d mailboxes", MaxMailboxes)
	}
	taken := map[string]string{} // address -> what has it
	claim := func(addr, by string) error {
		_, dom, err := SplitAddress(addr)
		if err != nil {
			return err
		}
		if !domains[dom] {
			return invalid("%s isn't at one of the server's mail domains", addr)
		}
		if prev, ok := taken[addr]; ok {
			return invalid("%s is used twice (%s and %s)", addr, prev, by)
		}
		taken[addr] = by
		return nil
	}
	reserved := func(addr string) bool {
		local, _, _ := SplitAddress(addr)
		return local == "postmaster" || local == "abuse"
	}
	out.Mailboxes = nil
	for _, m := range c.Mailboxes {
		if err := claim(m.Address, m.Address); err != nil {
			return out, err
		}
		if m.QuotaMB < 0 || m.QuotaMB > MaxQuotaMB {
			return out, invalid("%s: the quota must be between 0 (none) and %d MB", m.Address, MaxQuotaMB)
		}
		if len(m.Aliases) > MaxAliases {
			return out, invalid("%s: at most %d aliases", m.Address, MaxAliases)
		}
		nm := RootMailbox{Address: m.Address, QuotaMB: m.QuotaMB, Aliases: []string{}}
		for _, a := range m.Aliases {
			if reserved(a) {
				return out, invalid("%s is kept for the postmaster", a)
			}
			if err := claim(a, m.Address); err != nil {
				return out, err
			}
			nm.Aliases = append(nm.Aliases, a)
		}
		sort.Strings(nm.Aliases)
		out.Mailboxes = append(out.Mailboxes, nm)
	}
	sort.Slice(out.Mailboxes, func(i, j int) bool { return out.Mailboxes[i].Address < out.Mailboxes[j].Address })
	isMailbox := func(a string) bool {
		return slices.ContainsFunc(out.Mailboxes, func(m RootMailbox) bool { return m.Address == a })
	}
	if len(c.GroupAliases) > MaxGroupAliases {
		return out, invalid("at most %d group addresses", MaxGroupAliases)
	}
	out.GroupAliases = nil
	for _, g := range c.GroupAliases {
		if reserved(g.Address) {
			return out, invalid("%s is kept for the postmaster", g.Address)
		}
		if err := claim(g.Address, "group "+g.Address); err != nil {
			return out, err
		}
		if len(g.Targets) == 0 || len(g.Targets) > MaxGroupTargets {
			return out, invalid("%s needs 1 to %d mailboxes", g.Address, MaxGroupTargets)
		}
		ng := RootGroupAlias{Address: g.Address}
		seen := map[string]bool{}
		for _, t := range g.Targets {
			if !isMailbox(t) {
				return out, invalid("%s: %s isn't a mailbox on this server", g.Address, t)
			}
			if !seen[t] {
				seen[t] = true
				ng.Targets = append(ng.Targets, t)
			}
		}
		sort.Strings(ng.Targets)
		out.GroupAliases = append(out.GroupAliases, ng)
	}
	sort.Slice(out.GroupAliases, func(i, j int) bool { return out.GroupAliases[i].Address < out.GroupAliases[j].Address })
	if c.Postmaster != "" && !isMailbox(c.Postmaster) {
		return out, invalid("the postmaster %s isn't a mailbox on this server", c.Postmaster)
	}
	if c.SES != nil {
		ses := *c.SES
		if !sesHostRE.MatchString(ses.Host) {
			return out, invalid("the SES SMTP host %q isn't an Amazon SES endpoint (email-smtp.<region>.amazonaws.com)", ses.Host)
		}
		if ses.Port == 0 {
			ses.Port = 587
		}
		if ses.Port != 587 && ses.Port != 2587 {
			return out, invalid("SES's STARTTLS port is 587 or 2587")
		}
		if !sesUserRE.MatchString(ses.Username) {
			return out, invalid("the SES SMTP user name isn't valid")
		}
		if !secretRE.MatchString(s.SESPassword) {
			return out, invalid("the SES SMTP password is missing or isn't valid")
		}
		out.SES = &ses
	}
	if out.JunkScore == 0 {
		out.JunkScore = 6
	}
	if out.JunkScore < 1 || out.JunkScore > 50 {
		return out, invalid("the junk score must be between 1 and 50")
	}
	if out.MaxMessageMB == 0 {
		out.MaxMessageMB = DefaultMessageMB
	}
	if out.MaxMessageMB < 1 || out.MaxMessageMB > MaxMessageMB {
		return out, invalid("the largest message must be 1 to %d MB", MaxMessageMB)
	}
	if out.SendPerHour == 0 {
		out.SendPerHour = DefaultSendHour
	}
	if out.SendPerHour < 1 || out.SendPerHour > MaxSendHour {
		return out, invalid("messages per hour must be 1 to %d", MaxSendHour)
	}
	if out.AuthPort == 0 {
		out.AuthPort = DefaultAuthPort
	}
	if out.AuthPort < 1024 || out.AuthPort > 65535 {
		return out, invalid("the sign-in port must be 1024-65535")
	}
	if out.NotifyFrom != "" {
		if _, dom, err := SplitAddress(out.NotifyFrom); err != nil || !domains[dom] {
			return out, invalid("the notification sender %q must be at one of the mail domains", out.NotifyFrom)
		}
	}
	if !secretRE.MatchString(s.AuthSecret) || len(s.AuthSecret) < 32 {
		return out, invalid("the sign-in secret is missing")
	}
	for addr, sec := range s.DAV {
		if !isMailbox(addr) {
			return out, invalid("calendar password for %s, which isn't a mailbox", addr)
		}
		if !secretRE.MatchString(sec) || len(sec) < 32 {
			return out, invalid("the calendar password for %s isn't valid", addr)
		}
	}
	return out, nil
}

// DomainNames lists the configured domains' names.
func (c RootConfig) DomainNames() []string {
	var out []string
	for _, d := range c.Domains {
		out = append(out, d.Name)
	}
	return out
}
