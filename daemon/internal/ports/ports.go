// Package ports is the one list of the fixed ports HardyOS's own listeners
// and the services it runs use, so a clash between features is caught by a
// test (ports_test.go) rather than on a server. Add every new fixed port
// here and refer to it from its package: the tests also fail when a Go
// constant anywhere in the daemon names a port with a bare number
// (decision 303).
package ports

import (
	"fmt"
	"net/netip"
)

const (
	// HTTP and HTTPS are hardyd's own (the desktop, the API, ACME).
	HTTP  = 80
	HTTPS = 443

	// The mail server (docs/mail.md). The 10xxx ports take connections the
	// VPS forwards with the PROXY protocol; only the VPS's NetBird address
	// may reach them. hardyd's mail sign-in is a Unix socket, not a port
	// (decision 304), and Radicale a Unix socket too (decision 319).
	MailSubmissions      = 465   // Postfix, implicit TLS submission
	MailSubmission       = 587   // Postfix, STARTTLS submission
	MailIMAPS            = 993   // Dovecot, IMAP over TLS
	MailRelay            = 2525  // Postfix, mail relayed by the VPS
	MailProxySubmissions = 10465 // 465 forwarded by the VPS
	MailProxySubmission  = 10587 // 587 forwarded by the VPS
	MailProxyIMAPS       = 10993 // 993 forwarded by the VPS

	// NUT is the UPS server (upsd).
	NUT = 3493

	// NFS and ISCSI are the kernel's NFS server and LIO's iSCSI target
	// (shared folders over NFS, and cluster storage on the storage network).
	NFS   = 2049
	ISCSI = 3260
	// MigrateFirst up to MigrateFirst + MigrateCount - 1 is QEMU's live
	// migration range (libvirt's default 49152-49215); the cluster's
	// storage firewall opens it to members (decisions 351, 384).
	MigrateFirst = 49152
	MigrateCount = 64

	// AppGateway is the app gateway NetBird's reverse proxy reaches
	// (decision 112).
	AppGateway = 44200
	// Office is the office suite's own origin (editor page and Document
	// Server proxy; decision 254).
	Office = 44250
	// OfficeInternal is hardyd's listener for the Document Server container,
	// on the docker0 address (decisions 253, 266).
	OfficeInternal = 44251
	// AppProxyBase up to AppProxyBase + AppProxyCount - 1 is the app window
	// proxy range (decision 66): every window, local or relayed from another
	// member, listens on a port of it and never outside it (AppProxy,
	// decision 510).
	AppProxyBase  = 44300
	AppProxyCount = 100
	// Replication is the receiving side of replication (decision 190).
	Replication = 44400
	// Cluster is the cluster listener on members and the witness: Raft,
	// the peer API and live migration relays (decision 321).
	Cluster = 44500

	// The NetBird standby server (docs/netbird-standby.md, decisions
	// 420-429): the netbird-standby app's own host ports, which the router
	// forwards to (public TCP 80, TCP 443 and UDP 3478). Only that app may
	// publish them (OwnedBy) and nothing reaches them from outside unless
	// HardyOS has taken over (hardyd-priv's hardyos_nbstandby table).
	NetBirdStandbyHTTP  = 44620
	NetBirdStandbyHTTPS = 44621
	NetBirdStandbySTUN  = 44622 // UDP
	// NetBirdSTUN is the STUN port NetBird's server advertises and listens
	// on inside its container (the router's public side of
	// NetBirdStandbySTUN; not a host port of this server).
	NetBirdSTUN = 3478
	// Sunshine's ports (game streaming inside a VM, decision 404). On the
	// host they're only ever forwarded from the NetBird interface, to the
	// one VM whose streaming is published; nothing on the host listens
	// on them. SunshineWebUI is never forwarded (the VM's network only).
	SunshineHTTPS   = 47984 // TCP, pairing and app list over TLS
	SunshineHTTP    = 47989 // TCP, server info and pairing
	SunshineWebUI   = 47990 // TCP, Sunshine's web UI and API (not forwarded)
	SunshineRTSP    = 48010 // TCP and UDP, RTSP session setup
	SunshineVideo   = 47998 // UDP
	SunshineControl = 47999 // UDP
	SunshineAudio   = 48000 // UDP
	SunshineMic     = 48002 // UDP
)

// SunshineTCP and SunshineUDP are the ports forwarded to a streaming VM.
var (
	SunshineTCP = []int{SunshineHTTPS, SunshineHTTP, SunshineRTSP}
	SunshineUDP = []int{SunshineVideo, SunshineControl, SunshineAudio, SunshineMic, SunshineRTSP}
)

// Game streaming port sets (decision 506). Several VMs of one server may
// be published to NetBird devices at once: each published VM gets a slot,
// its Sunshine runs with the slot's base port (Sunshine's `port` setting:
// every port it uses is an offset of it, and it tells Moonlight its own
// numbers, so the server forwards each number to the same number in the
// VM) and Moonlight adds the server as <NetBird address>:<base>. Slot 0 is
// Sunshine's standard set (base SunshineHTTP). Slots are StreamingSlotStride
// apart, so their sets never overlap; each slot is a registered range
// (StreamingRanges, decision 510), so no app is given one as a host port.
const (
	StreamingSlots      = 8
	StreamingSlotStride = 100
)

// Sunshine's ports as offsets of its base port (SunshineHTTP in slot 0).
const (
	sunshineOffHTTPS   = SunshineHTTPS - SunshineHTTP
	sunshineOffWebUI   = SunshineWebUI - SunshineHTTP
	sunshineOffRTSP    = SunshineRTSP - SunshineHTTP
	sunshineOffVideo   = SunshineVideo - SunshineHTTP
	sunshineOffControl = SunshineControl - SunshineHTTP
	sunshineOffAudio   = SunshineAudio - SunshineHTTP
	sunshineOffMic     = SunshineMic - SunshineHTTP
)

// StreamingSet is one slot's ports.
type StreamingSet struct {
	Slot int
	// Base is Sunshine's `port` (HTTP; what Moonlight is given).
	Base int
	// WebUI is Sunshine's web page and API (never forwarded).
	WebUI int
	TCP   []int
	UDP   []int
}

// ValidStreamingSlot reports whether slot is one of the slots.
func ValidStreamingSlot(slot int) bool { return slot >= 0 && slot < StreamingSlots }

// StreamingSlot is slot's port set (slot 0 for an invalid one).
func StreamingSlot(slot int) StreamingSet {
	if !ValidStreamingSlot(slot) {
		slot = 0
	}
	b := SunshineHTTP + slot*StreamingSlotStride
	return StreamingSet{Slot: slot, Base: b, WebUI: b + sunshineOffWebUI,
		TCP: []int{b + sunshineOffHTTPS, b, b + sunshineOffRTSP},
		UDP: []int{b + sunshineOffVideo, b + sunshineOffControl, b + sunshineOffAudio, b + sunshineOffMic, b + sunshineOffRTSP}}
}

// StreamingSlotOfBase is the slot whose base port is base (false: none).
func StreamingSlotOfBase(base int) (int, bool) {
	d := base - SunshineHTTP
	if d < 0 || d%StreamingSlotStride != 0 || !ValidStreamingSlot(d/StreamingSlotStride) {
		return 0, false
	}
	return d / StreamingSlotStride, true
}

// StreamingWebUIPorts are every slot's web UI port (the VM's firewall
// keeps them to the HardyOS server, decision 401).
func StreamingWebUIPorts() []int {
	out := make([]int, 0, StreamingSlots)
	for s := 0; s < StreamingSlots; s++ {
		out = append(out, StreamingSlot(s).WebUI)
	}
	return out
}

// NetBirdStandbyApp is the app id that owns the NetBird standby ports.
const NetBirdStandbyApp = "netbird-standby"

// Range is a registered block of ports, First to Last inclusive: no fixed
// port, no other range and no app's host port may use a port in it
// (decision 510).
type Range struct {
	Name        string
	First, Last int
}

// Contains reports whether p is in r.
func (r Range) Contains(p int) bool { return p >= r.First && p <= r.Last }

// Size is the number of ports in r.
func (r Range) Size() int { return r.Last - r.First + 1 }

// Overlaps reports whether r and o share a port.
func (r Range) Overlaps(o Range) bool { return r.First <= o.Last && o.First <= r.Last }

// The registered ranges.
var (
	// AppProxy is the app window proxy range.
	AppProxy = Range{Name: "app window proxies", First: AppProxyBase, Last: AppProxyBase + AppProxyCount - 1}
	// Migrate is QEMU's live migration range.
	Migrate = Range{Name: "live migration", First: MigrateFirst, Last: MigrateFirst + MigrateCount - 1}
)

// StreamingRanges are the game streaming port sets, one range per slot
// (its lowest port, Sunshine's HTTPS, to its highest, RTSP): Sunshine's
// ports are fixed ports of slot 0's range, and every slot's set is
// registered like any range so nothing else takes a port of it.
var StreamingRanges = streamingRanges()

func streamingRanges() []Range {
	out := make([]Range, 0, StreamingSlots)
	for s := 0; s < StreamingSlots; s++ {
		b := SunshineHTTP + s*StreamingSlotStride
		out = append(out, Range{Name: fmt.Sprintf("game streaming set %d", s), First: b + sunshineOffHTTPS, Last: b + sunshineOffRTSP})
	}
	return out
}

// InStreamingRange reports whether p is in a game streaming port set's
// range (any slot).
func InStreamingRange(p int) bool {
	for _, r := range StreamingRanges {
		if r.Contains(p) {
			return true
		}
	}
	return false
}

// Ranges lists every registered range; a test checks that they and Fixed
// are pairwise disjoint.
var Ranges = append([]Range{AppProxy, Migrate}, StreamingRanges...)

// InRange returns the registered range p is in, if any.
func InRange(p int) (Range, bool) {
	for _, r := range Ranges {
		if r.Contains(p) {
			return r, true
		}
	}
	return Range{}, false
}

// TakenOutside reports whether p is a fixed port or in a registered range
// other than r: an allocator handing out the ports of r skips it. For a
// registered r nothing is ever skipped this way (the ranges are disjoint);
// it matters for ranges tests make up.
func TakenOutside(p int, r Range) bool {
	if Reserved(p) {
		return true
	}
	for _, o := range Ranges {
		if o != r && o.Contains(p) {
			return true
		}
	}
	return false
}

// Fixed lists every single fixed port with its owner (the ranges are in
// Ranges), including ports services HardyOS runs take that no Go code
// listens on itself.
var Fixed = map[string]int{
	"http":                      HTTP,
	"https":                     HTTPS,
	"mail submissions":          MailSubmissions,
	"mail submission":           MailSubmission,
	"mail imaps":                MailIMAPS,
	"mail relay":                MailRelay,
	"mail proxied submissions":  MailProxySubmissions,
	"mail proxied submission":   MailProxySubmission,
	"mail proxied imaps":        MailProxyIMAPS,
	"ups (nut)":                 NUT,
	"app gateway":               AppGateway,
	"office origin":             Office,
	"office internal":           OfficeInternal,
	"replication":               Replication,
	"cluster":                   Cluster,
	"netbird standby http":      NetBirdStandbyHTTP,
	"netbird standby https":     NetBirdStandbyHTTPS,
	"netbird standby stun":      NetBirdStandbySTUN,
	"socks (netbird)":           1080,
	"nfs":                       NFS,
	"iscsi":                     ISCSI,
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
	return InStreamingRange(p)
}

// owned are fixed ports one app may publish (and no other).
var owned = map[int]string{
	NetBirdStandbyHTTP:  NetBirdStandbyApp,
	NetBirdStandbyHTTPS: NetBirdStandbyApp,
	NetBirdStandbySTUN:  NetBirdStandbyApp,
}

// OwnedBy names the app allowed to publish the fixed port p ("" for none):
// the apps engine lets that app, and only that app, use it.
func OwnedBy(p int) string { return owned[p] }

// WebmailSubnet is the Docker network of the webmail app (Roundcube): its
// compose file asks for exactly this subnet, and hardyd's mail sign-in
// accepts webmail tokens from it alone and never a password from it
// (decision 305). Outside Docker's default pools (172.17-31.0.0/16).
var WebmailSubnet = netip.MustParsePrefix("172.16.253.0/28")

// NetBirdStandbySubnet is the netbird-standby app's Docker network (its
// compose file asks for exactly this subnet; no other app may use it), so
// hardyd-priv's table can also drop traffic to its containers outside a
// take-over (decision 426).
var NetBirdStandbySubnet = netip.MustParsePrefix("172.16.253.16/28")

// WebmailAddr is the webmail container's own address in WebmailSubnet
// (its compose file pins it; decision 317).
var WebmailAddr = netip.MustParseAddr("172.16.253.2")
