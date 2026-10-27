package mail

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strings"
)

// Mail app settings (Thunderbird autoconfig, Outlook autodiscover, Apple
// configuration profiles). They only name servers and ports: no secrets,
// so they're served without a sign-in, like every mail provider does.

// ClientSettings is what a mail app needs.
type ClientSettings struct {
	Domain   string // the address's domain
	Hostname string // IMAP, SMTP and DAV server
	Address  string // the person's address ("" for templates)
	Name     string // display name (profiles)
	// DAV adds calendars and contacts to Apple profiles.
	DAV bool
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// AutoconfigXML is Thunderbird's config-v1.1 document.
func AutoconfigXML(c ClientSettings) string {
	h, d := xmlEscape(c.Hostname), xmlEscape(c.Domain)
	return `<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="` + d + `">
    <domain>` + d + `</domain>
    <displayName>` + d + ` (HardyOS)</displayName>
    <displayShortName>` + d + `</displayShortName>
    <incomingServer type="imap">
      <hostname>` + h + `</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>` + h + `</hostname>
      <port>465</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
    <outgoingServer type="smtp">
      <hostname>` + h + `</hostname>
      <port>587</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
  </emailProvider>
</clientConfig>
`
}

// AutodiscoverRequest is Outlook's POX request (only the address matters).
type AutodiscoverRequest struct {
	XMLName xml.Name `xml:"Autodiscover"`
	Request struct {
		EMailAddress             string `xml:"EMailAddress"`
		AcceptableResponseSchema string `xml:"AcceptableResponseSchema"`
	} `xml:"Request"`
}

// AutodiscoverXML is Outlook's POX response for IMAP and SMTP.
func AutodiscoverXML(c ClientSettings) string {
	h, a := xmlEscape(c.Hostname), xmlEscape(c.Address)
	return `<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
      <Protocol>
        <Type>IMAP</Type>
        <Server>` + h + `</Server>
        <Port>993</Port>
        <LoginName>` + a + `</LoginName>
        <DomainRequired>off</DomainRequired>
        <SPA>off</SPA>
        <SSL>on</SSL>
        <AuthRequired>on</AuthRequired>
      </Protocol>
      <Protocol>
        <Type>SMTP</Type>
        <Server>` + h + `</Server>
        <Port>465</Port>
        <LoginName>` + a + `</LoginName>
        <DomainRequired>off</DomainRequired>
        <SPA>off</SPA>
        <SSL>on</SSL>
        <Encryption>SSL</Encryption>
        <AuthRequired>on</AuthRequired>
        <UsePOPAuth>off</UsePOPAuth>
        <SMTPLast>off</SMTPLast>
      </Protocol>
    </Account>
  </Response>
</Autodiscover>
`
}

// uuidFrom makes a stable UUID-shaped identifier (profiles replace an
// installed profile with the same identifiers instead of adding another).
func uuidFrom(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	x := hex.EncodeToString(h[:16])
	return strings.ToUpper(x[0:8] + "-" + x[8:12] + "-4" + x[13:16] + "-8" + x[17:20] + "-" + x[20:32])
}

func plistString(key, val string) string {
	return "\t\t\t<key>" + xmlEscape(key) + "</key>\n\t\t\t<string>" + xmlEscape(val) + "</string>\n"
}

func plistInt(key string, v int) string {
	return fmt.Sprintf("\t\t\t<key>%s</key>\n\t\t\t<integer>%d</integer>\n", xmlEscape(key), v)
}

func plistBool(key string, v bool) string {
	b := "false"
	if v {
		b = "true"
	}
	return "\t\t\t<key>" + xmlEscape(key) + "</key>\n\t\t\t<" + b + "/>\n"
}

// MobileConfig is an Apple configuration profile (iPhone, iPad, Mac) for
// one person's mail, and with DAV their calendars and contacts. It holds
// no password: the device asks for it while installing.
func MobileConfig(c ClientSettings) []byte {
	id := "net.hardyos.mail." + strings.ReplaceAll(c.Address, "@", ".")
	var p strings.Builder
	p.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
`)
	p.WriteString(plistString("PayloadType", "com.apple.mail.managed"))
	p.WriteString(plistInt("PayloadVersion", 1))
	p.WriteString(plistString("PayloadIdentifier", id+".imap"))
	p.WriteString(plistString("PayloadUUID", uuidFrom(c.Address, "imap")))
	p.WriteString(plistString("PayloadDisplayName", c.Address))
	p.WriteString(plistString("EmailAccountDescription", c.Address))
	p.WriteString(plistString("EmailAccountName", c.Name))
	p.WriteString(plistString("EmailAccountType", "EmailTypeIMAP"))
	p.WriteString(plistString("EmailAddress", c.Address))
	p.WriteString(plistString("IncomingMailServerAuthentication", "EmailAuthPassword"))
	p.WriteString(plistString("IncomingMailServerHostName", c.Hostname))
	p.WriteString(plistInt("IncomingMailServerPortNumber", 993))
	p.WriteString(plistBool("IncomingMailServerUseSSL", true))
	p.WriteString(plistString("IncomingMailServerUsername", c.Address))
	p.WriteString(plistString("OutgoingMailServerAuthentication", "EmailAuthPassword"))
	p.WriteString(plistString("OutgoingMailServerHostName", c.Hostname))
	p.WriteString(plistInt("OutgoingMailServerPortNumber", 465))
	p.WriteString(plistBool("OutgoingMailServerUseSSL", true))
	p.WriteString(plistString("OutgoingMailServerUsername", c.Address))
	p.WriteString(plistBool("OutgoingPasswordSameAsIncomingPassword", true))
	p.WriteString(plistBool("PreventMove", false))
	p.WriteString(plistBool("SMIMEEnabled", false))
	p.WriteString("\t\t</dict>\n")
	if c.DAV {
		for _, kind := range []string{"caldav", "carddav"} {
			pre := map[string]string{"caldav": "CalDAV", "carddav": "CardDAV"}[kind]
			p.WriteString("\t\t<dict>\n")
			p.WriteString(plistString("PayloadType", "com.apple."+kind+".account"))
			p.WriteString(plistInt("PayloadVersion", 1))
			p.WriteString(plistString("PayloadIdentifier", id+"."+kind))
			p.WriteString(plistString("PayloadUUID", uuidFrom(c.Address, kind)))
			p.WriteString(plistString("PayloadDisplayName", map[string]string{"caldav": "Calendars", "carddav": "Contacts"}[kind]))
			p.WriteString(plistString(pre+"AccountDescription", map[string]string{"caldav": "Family calendars", "carddav": "Family contacts"}[kind]))
			p.WriteString(plistString(pre+"HostName", c.Hostname))
			p.WriteString(plistInt(pre+"Port", 443))
			p.WriteString(plistBool(pre+"UseSSL", true))
			p.WriteString(plistString(pre+"Username", c.Address))
			p.WriteString(plistString(pre+"PrincipalURL", "https://"+c.Hostname+DAVPath+c.Address+"/"))
			p.WriteString("\t\t</dict>\n")
		}
	}
	p.WriteString("\t</array>\n")
	p.WriteString("\t<key>PayloadDisplayName</key>\n\t<string>" + xmlEscape("Mail for "+c.Address) + "</string>\n")
	p.WriteString("\t<key>PayloadDescription</key>\n\t<string>" + xmlEscape("Sets up "+c.Address+" from your HardyOS server. Your device asks for your password while installing.") + "</string>\n")
	p.WriteString("\t<key>PayloadIdentifier</key>\n\t<string>" + xmlEscape(id) + "</string>\n")
	p.WriteString("\t<key>PayloadOrganization</key>\n\t<string>HardyOS</string>\n")
	p.WriteString("\t<key>PayloadRemovalDisallowed</key>\n\t<false/>\n")
	p.WriteString("\t<key>PayloadType</key>\n\t<string>Configuration</string>\n")
	p.WriteString("\t<key>PayloadUUID</key>\n\t<string>" + uuidFrom(c.Address, "profile") + "</string>\n")
	p.WriteString("\t<key>PayloadVersion</key>\n\t<integer>1</integer>\n")
	p.WriteString("</dict>\n</plist>\n")
	return []byte(p.String())
}

// ManualSettings is what the "Set up my phone or computer" page lists.
type ManualSettings struct {
	Address  string `json:"address"`
	Username string `json:"username"`
	IMAPHost string `json:"imapHost"`
	IMAPPort int    `json:"imapPort"`
	IMAPTLS  string `json:"imapTls"`
	SMTPHost string `json:"smtpHost"`
	SMTPPort int    `json:"smtpPort"`
	SMTPTLS  string `json:"smtpTls"`
	AltSMTP  int    `json:"altSmtpPort"`
	DAVURL   string `json:"davUrl"`
	Family   string `json:"familyCalendarUrl"`
	Contacts string `json:"familyContactsUrl"`
}

// Manual returns the settings to type in by hand.
func Manual(hostname, address string, family bool) ManualSettings {
	m := ManualSettings{Address: address, Username: address, IMAPHost: hostname, IMAPPort: 993, IMAPTLS: "SSL/TLS",
		SMTPHost: hostname, SMTPPort: 465, SMTPTLS: "SSL/TLS", AltSMTP: 587,
		DAVURL: "https://" + hostname + DAVPath + address + "/"}
	if family {
		m.Family = "https://" + hostname + DAVPath + "family/calendar/"
		m.Contacts = "https://" + hostname + DAVPath + "family/contacts/"
	}
	return m
}
