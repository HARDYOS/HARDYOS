// Package ports is the one list of the network ports HardyOS and the
// services it runs listen on (decision 300). Every package takes its port
// from here instead of writing the number itself; the tests in this package
// fail when two entries share a port or when a Go constant anywhere in the
// daemon names a port with a bare number. A new listener therefore starts
// with a line in this file, where a clash with another part of HardyOS shows
// up at once.
package ports

import "net/netip"

// Fixed TCP ports.
const (
	HTTP  = 80  // hardyd: redirect to HTTPS, ACME
	HTTPS = 443 // hardyd: the desktop and the API

	// The mail server (docs/mail.md). The 10xxx ports take connections the
	// VPS forwards with the PROXY protocol; only the VPS's NetBird address
	// may reach them.
	MailSubmissions      = 465   // Postfix, implicit TLS submission
	MailSubmission       = 587   // Postfix, STARTTLS submission
	MailIMAPS            = 993   // Dovecot, IMAP over TLS
	MailRelay            = 2525  // Postfix, mail relayed by the VPS
	MailRadicale         = 5232  // Radicale on 127.0.0.1 (hardyd proxies /dav-mail/)
	MailProxySubmissions = 10465 // 465 forwarded by the VPS
	MailProxySubmission  = 10587 // 587 forwarded by the VPS
	MailProxyIMAPS       = 10993 // 993 forwarded by the VPS

	NUT = 3493 // the UPS server (upsd)

	AppGateway = 44200 // the app gateway NetBird's reverse proxy reaches

	// The office suite (phase 7, office): the editor's own origin and the
	// listener its document server calls back on. Kept here so mail and
	// office can't both take them; the office integration replaces its own
	// constants with these.
	OfficeOrigin   = 44250
	OfficeInternal = 44251

	Replication = 44400 // a receiving server for other HardyOS servers
)

// AppProxyFirst and AppProxyCount are the app window proxies' range (one
// HTTPS port per app with a web page). The allocator skips every fixed
// port (Reserved), so Replication inside the range is never handed out.
const (
	AppProxyFirst = 44300
	AppProxyCount = 1000
)

// Entry names one fixed port.
type Entry struct {
	Name string
	Port int
}

// Fixed is every fixed port above, plus the ones services HardyOS runs
// take that no Go code listens on itself (kept from apps' own list).
var Fixed = []Entry{
	{"HTTP", HTTP},
	{"HTTPS", HTTPS},
	{"MailSubmissions", MailSubmissions},
	{"MailSubmission", MailSubmission},
	{"MailIMAPS", MailIMAPS},
	{"MailRelay", MailRelay},
	{"MailRadicale", MailRadicale},
	{"MailProxySubmissions", MailProxySubmissions},
	{"MailProxySubmission", MailProxySubmission},
	{"MailProxyIMAPS", MailProxyIMAPS},
	{"NUT", NUT},
	{"AppGateway", AppGateway},
	{"OfficeOrigin", OfficeOrigin},
	{"OfficeInternal", OfficeInternal},
	{"Replication", Replication},
	{"SOCKS (NetBird)", 1080},
	{"NFS", 2049},
	{"iSCSI", 3260},
	{"Global catalog", 3268},
	{"Global catalog (TLS)", 3269},
	{"mDNS", 5353},
	{"HTTPS (alternative)", 8443},
}

// Range is a block of ports handed out one by one.
type Range struct {
	Name         string
	First, Count int
	// SkipsFixed: the allocator never hands out a Fixed port.
	SkipsFixed bool
}

// Ranges are the blocks of ports.
var Ranges = []Range{
	{Name: "app window proxies", First: AppProxyFirst, Count: AppProxyCount, SkipsFixed: true},
}

var fixedSet = func() map[int]bool {
	m := map[int]bool{}
	for _, e := range Fixed {
		m[e.Port] = true
	}
	return m
}()

// Reserved reports whether p is one of the fixed ports.
func Reserved(p int) bool { return fixedSet[p] }

// WebmailSubnet is the Docker network of the webmail app (Roundcube): its
// compose file asks for exactly this subnet, and hardyd's mail sign-in
// accepts webmail tokens from it alone and never a password from it
// (decision 302). Outside Docker's default pools (172.17-31.0.0/16).
var WebmailSubnet = netip.MustParsePrefix("172.16.253.0/28")
