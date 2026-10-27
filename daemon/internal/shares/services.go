package shares

// How a shared folder is offered on the network, and its snapshots. Stored
// as JSON in org.hardyos:services. See docs/plans/file-sharing.md: each
// protocol's code owns its own part of this struct.

import (
	"fmt"
	"net/netip"
	"strings"
)

// Services is a shared folder's network and snapshot settings.
type Services struct {
	SMB       SMB       `json:"smb"`
	NFS       NFS       `json:"nfs"`
	Snapshots Snapshots `json:"snapshots"`
	// SFTP and WebDAV offer the folder to domain accounts over SFTP and at
	// https://<server>/dav/ (when File Services has them on too). Off for
	// new folders.
	SFTP   bool `json:"sftp"`
	WebDAV bool `json:"webdav"`
}

// SMB: Windows/macOS file sharing.
type SMB struct {
	Enabled bool `json:"enabled"`
	// TimeMachine offers the folder to Macs as a Time Machine destination.
	TimeMachine bool `json:"timeMachine"`
	// TimeMachineMaxBytes caps each Mac's backups (0 = the folder's quota).
	TimeMachineMaxBytes uint64 `json:"timeMachineMaxBytes"`
	// PreviousVersions shows snapshots in Windows' Previous Versions tab.
	PreviousVersions bool `json:"previousVersions"`
}

// NFS: Linux/Unix clients, allowed by address.
type NFS struct {
	Enabled bool      `json:"enabled"`
	Clients []NFSRule `json:"clients"`
}

// NFSRule lets one address or network mount the folder.
type NFSRule struct {
	Client string `json:"client"` // 192.168.1.50 or 192.168.1.0/24
	Access string `json:"access"` // read or write
}

// Snapshots: how many automatic snapshots of each kind to keep (0 = none).
type Snapshots struct {
	Hourly  int `json:"hourly"`
	Daily   int `json:"daily"`
	Weekly  int `json:"weekly"`
	Monthly int `json:"monthly"`
}

// DefaultServices is what a new shared folder gets: SMB with Previous
// Versions, a day of hourly, two weeks of daily, two months of weekly and
// six monthly snapshots.
func DefaultServices() Services {
	return Services{
		SMB:       SMB{Enabled: true, PreviousVersions: true},
		NFS:       NFS{Clients: []NFSRule{}},
		Snapshots: Snapshots{Hourly: 24, Daily: 14, Weekly: 8, Monthly: 6},
	}
}

func (s *Services) normalize() {
	if s.NFS.Clients == nil {
		s.NFS.Clients = []NFSRule{}
	}
}

// Limits.
const (
	MaxNFSRules    = 32
	maxKeepHourly  = 168
	maxKeepDaily   = 90
	maxKeepWeekly  = 104
	maxKeepMonthly = 120
)

// CheckServices validates and cleans sharing settings.
func CheckServices(s Services) (Services, error) {
	s.normalize()
	if s.SMB.TimeMachine && !s.SMB.Enabled {
		return s, invalid("Time Machine needs SMB sharing turned on")
	}
	if len(s.NFS.Clients) > MaxNFSRules {
		return s, invalid("too many NFS clients: at most %d (use a network like 192.168.1.0/24)", MaxNFSRules)
	}
	seen := map[string]bool{}
	for i, r := range s.NFS.Clients {
		c, err := cleanNFSClient(r.Client)
		if err != nil {
			return s, err
		}
		if seen[c] {
			return s, invalid("the NFS client %s is listed twice", c)
		}
		seen[c] = true
		if r.Access != LevelRead && r.Access != LevelWrite {
			return s, invalid("NFS access for %s must be read or write", c)
		}
		s.NFS.Clients[i].Client = c
	}
	if s.NFS.Enabled && len(s.NFS.Clients) == 0 {
		return s, invalid("add at least one computer or network that may use NFS")
	}
	for _, k := range []struct {
		n, max int
		what   string
	}{{s.Snapshots.Hourly, maxKeepHourly, "hourly"}, {s.Snapshots.Daily, maxKeepDaily, "daily"},
		{s.Snapshots.Weekly, maxKeepWeekly, "weekly"}, {s.Snapshots.Monthly, maxKeepMonthly, "monthly"}} {
		if k.n < 0 || k.n > k.max {
			return s, invalid("keep 0 to %d %s snapshots", k.max, k.what)
		}
	}
	return s, nil
}

// cleanNFSClient accepts an IPv4/IPv6 address or network, never "everyone".
func cleanNFSClient(c string) (string, error) {
	c = strings.TrimSpace(c)
	if strings.Contains(c, "/") {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return "", invalid("%q isn't an address or network like 192.168.1.0/24", c)
		}
		p = p.Masked()
		if p.Bits() == 0 {
			return "", invalid("NFS can't be opened to every address; name a network like 192.168.1.0/24")
		}
		return p.String(), nil
	}
	a, err := netip.ParseAddr(c)
	if err != nil {
		return "", invalid("%q isn't an address or network like 192.168.1.0/24", c)
	}
	if a.IsUnspecified() {
		return "", invalid("%s isn't a computer's address", c)
	}
	return fmt.Sprint(a.Unmap()), nil
}
