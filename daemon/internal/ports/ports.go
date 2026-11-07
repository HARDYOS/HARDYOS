// Package ports is the one list of the fixed ports HardyOS's own listeners
// and the services it runs use, so a clash between features is caught by a
// test (ports_test.go) rather than on a server. Add every new fixed port
// here and refer to it from its package: the tests also fail when a Go
// constant anywhere in the daemon names a port with a bare number
// (decision 303).
package ports

import "net/netip"

const (
	// HTTP and HTTPS are hardyd's own (the desktop, the API, ACME).
	HTTP  = 80
	HTTPS = 443

	// The mail server (docs/mail.md). The 10xxx ports take connections the
	// VPS forwards with the PROXY protocol; only the VPS's NetBird address
	// may reach them. hardyd's mail sign-in is a Unix socket, not a port
	// (decision 304).
	MailSubmissions      = 465   // Postfix, implicit TLS submission
	MailSubmission       = 587   // Postfix, STARTTLS submission
	MailIMAPS            = 993   // Dovecot, IMAP over TLS
	MailRelay            = 2525  // Postfix, mail relayed by the VPS
	MailRadicale         = 5232  // Radicale on 127.0.0.1 (hardyd proxies /dav-mail/)
	MailProxySubmissions = 10465 // 465 forwarded by the VPS
	MailProxySubmission  = 10587 // 587 forwarded by the VPS
	MailProxyIMAPS       = 10993 // 993 forwarded by the VPS

	// NUT is the UPS server (upsd).
	NUT = 3493

	// AppGateway is the app gateway NetBird's reverse proxy reaches
	// (decision 112).
	AppGateway = 44200
	// Office is the office suite's own origin (editor page and Document
	// Server proxy; decision 254).
	Office = 44250
	// OfficeInternal is hardyd's listener for the Document Server container,
	// on the docker0 address (decisions 253, 266).
	OfficeInternal = 44251
	// AppProxyBase is the first app window proxy port; app n gets
	// AppProxyBase + n, up to AppProxyBase + AppProxyCount - 1 (decision 66).
	AppProxyBase  = 44300
	AppProxyCount = 100
	// Replication is the receiving side of replication (decision 190).
	Replication = 44400
)

// Fixed lists every single fixed port with its owner (the app proxy range
// is checked separately), including ports services HardyOS runs take that
// no Go code listens on itself.
var Fixed = map[string]int{
	"http":                      HTTP,
	"https":                     HTTPS,
	"mail submissions":          MailSubmissions,
	"mail submission":           MailSubmission,
	"mail imaps":                MailIMAPS,
	"mail relay":                MailRelay,
	"mail radicale":             MailRadicale,
	"mail proxied submissions":  MailProxySubmissions,
	"mail proxied submission":   MailProxySubmission,
	"mail proxied imaps":        MailProxyIMAPS,
	"ups (nut)":                 NUT,
	"app gateway":               AppGateway,
	"office origin":             Office,
	"office internal":           OfficeInternal,
	"replication":               Replication,
	"socks (netbird)":           1080,
	"nfs":                       2049,
	"iscsi":                     3260,
	"global catalog":            3268,
	"global catalog (tls)":      3269,
	"mdns":                      5353,
	"https (alternative, apps)": 8443,
}

// Reserved reports whether p is one of the fixed ports: allocators (app
// window proxies, apps' host ports) never hand it out.
func Reserved(p int) bool {
	for _, v := range Fixed {
		if v == p {
			return true
		}
	}
	return false
}

// WebmailSubnet is the Docker network of the webmail app (Roundcube): its
// compose file asks for exactly this subnet, and hardyd's mail sign-in
// accepts webmail tokens from it alone and never a password from it
// (decision 305). Outside Docker's default pools (172.17-31.0.0/16).
var WebmailSubnet = netip.MustParsePrefix("172.16.253.0/28")

// WebmailAddr is the webmail container's own address in WebmailSubnet
// (its compose file pins it; decision 317).
var WebmailAddr = netip.MustParseAddr("172.16.253.2")
