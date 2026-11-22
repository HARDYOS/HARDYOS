package domain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Hostnames on the LAN (decision 459): with HardyOS's own domain controller,
// devices that use it for DNS find <name>.<base> at this server's address.
// The records go in the AD zone when the base is the domain or inside it,
// else in a zone for the base made on the DC (which then answers for the
// whole base on the LAN: the base is HardyOS's, as Remote Access's wildcard
// already says). HardyOS remembers what it added in the DC's own data
// folder and only ever removes those; a name another record holds is
// skipped.

const hostRecordsFile = "hardyos-hostnames.json"

// MaxHostRecords bounds the names in one call.
const MaxHostRecords = 200

// HostRecordsArgs are the names to keep, all at one address.
type HostRecordsArgs struct {
	Base    string   `json:"base"`
	Address string   `json:"address"`
	Labels  []string `json:"labels"` // empty: remove every record HardyOS added
	// Desktop is the desktop's label (Remote Access's desktop name).
	Desktop string `json:"desktop,omitempty"`
	// Allowed and PublicApex are set by root (never decoded from hardyd):
	// the labels root itself knows HardyOS serves, and whether the base is
	// the apex of its Cloudflare zone.
	Allowed    []string `json:"-"`
	PublicApex bool     `json:"-"`
}

// HostRecordsResult says what changed.
type HostRecordsResult struct {
	Zone    string   `json:"zone"`
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	Kept    []string `json:"kept"`
	Skipped []string `json:"skipped"` // names other records hold
}

type hostRecord struct {
	Zone    string `json:"zone"`
	Name    string `json:"name"` // relative to the zone
	Address string `json:"address"`
}

type hostRecordsState struct {
	Records []hostRecord `json:"records"`
	// Zones HardyOS created on the DC.
	Zones []string `json:"zones,omitempty"`
}

var hostLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func validBase(d string) bool {
	if len(d) == 0 || len(d) > 200 {
		return false
	}
	parts := strings.Split(d, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if !hostLabelRE.MatchString(p) {
			return false
		}
	}
	return true
}

func (m *Manager) loadHostRecords() (*hostRecordsState, error) {
	b, err := os.ReadFile(m.dataPath(hostRecordsFile))
	if errors.Is(err, os.ErrNotExist) {
		return &hostRecordsState{}, nil
	}
	if err != nil {
		return nil, err
	}
	var st hostRecordsState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (m *Manager) saveHostRecords(st *hostRecordsState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	p := m.dataPath(hostRecordsFile)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (m *Manager) samba(ctx context.Context, args ...string) ([]byte, error) {
	full := append([]string{"netns", "exec", m.ns(), "samba-tool"}, args...)
	full = append(full, "-P", "-s", m.SmbConf())
	return sysexec.Output(ctx, m.Runner, "ip", full...)
}

// zoneFor is where names under base go on this domain.
func zoneFor(c *Config, base string) (zone, suffix string) {
	dom := strings.ToLower(c.Domain)
	if base == dom {
		return dom, ""
	}
	if s, ok := strings.CutSuffix(base, "."+dom); ok {
		return dom, "." + s
	}
	return base, ""
}

// deniedHostLabels are never published, whatever asks: clients look them
// up by themselves for proxy and tunnel configuration.
var deniedHostLabels = map[string]bool{"wpad": true, "isatap": true}

// SetHostRecords makes the DC's DNS hold <label>.<base> A address for every
// label, and drops the records HardyOS added earlier that aren't wanted.
// Only labels in a.Allowed (root's own list) are published; wpad, isatap
// and names a computer or service in the directory uses are skipped.
func (m *Manager) SetHostRecords(ctx context.Context, a HostRecordsArgs) (*HostRecordsResult, error) {
	if len(a.Labels) == 0 {
		return m.RemoveHostRecords(ctx)
	}
	base := strings.ToLower(strings.TrimSuffix(a.Base, "."))
	if !validBase(base) {
		return nil, invalid("%q isn't a domain", a.Base)
	}
	addr, err := netip.ParseAddr(a.Address)
	if err != nil || !addr.Is4() || addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() {
		return nil, invalid("%q isn't an IPv4 address of this server", a.Address)
	}
	if len(a.Labels) > MaxHostRecords {
		return nil, invalid("at most %d names", MaxHostRecords)
	}
	allowed := map[string]bool{}
	for _, l := range a.Allowed {
		allowed[l] = true
	}
	want := map[string]bool{}
	res0 := []string{}
	for _, l := range a.Labels {
		if !hostLabelRE.MatchString(l) {
			return nil, invalid("%q isn't a name", l)
		}
		if !allowed[l] || deniedHostLabels[l] {
			res0 = append(res0, l)
			continue
		}
		want[l] = true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.Load()
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, ErrNotProvisioned
	}
	if !c.Enabled || !m.serviceActive(ctx) {
		return nil, errors.New("the domain controller isn't running")
	}
	if addr.String() == c.IP() {
		return nil, invalid("%s is the domain controller's own address, not this server's", addr)
	}
	zone, suffix := zoneFor(c, base)
	if zone != strings.ToLower(c.Domain) && a.PublicApex {
		return nil, invalid("%s is the apex of its Cloudflare zone: a zone for it on the domain controller would hide every other public record of %s on the home network. Use a base domain under it (home.%s) or your router", base, base, base)
	}
	// Names a computer or service in the directory already uses (fail
	// closed: no list, no records).
	var taken struct {
		Taken []string `json:"taken"`
	}
	ls := make([]string, 0, len(want))
	for l := range want {
		ls = append(ls, l)
	}
	if err := m.admin(ctx, "names.taken", map[string]any{"names": ls}, &taken); err != nil {
		return nil, fmt.Errorf("checking the directory's computer names: %w", err)
	}
	for _, t := range taken.Taken {
		if want[t] {
			delete(want, t)
			res0 = append(res0, t)
		}
	}
	st, err := m.loadHostRecords()
	if err != nil {
		return nil, err
	}
	res := &HostRecordsResult{Zone: zone, Added: []string{}, Removed: []string{}, Kept: []string{}, Skipped: []string{}}
	for _, l := range res0 {
		res.Skipped = append(res.Skipped, l+suffix+"."+zone)
	}
	// Records of another zone or base HardyOS added before: no longer wanted.
	var keep []hostRecord
	have := map[string]hostRecord{}
	for _, r := range st.Records {
		if r.Zone == zone && strings.HasSuffix(r.Name, suffix) {
			label := strings.TrimSuffix(r.Name, suffix)
			if want[label] && !strings.Contains(label, ".") {
				have[label] = r
				continue
			}
		}
		if m.deleteHostRecord(ctx, r) {
			res.Removed = append(res.Removed, r.Name+"."+r.Zone)
		} else {
			keep = append(keep, r) // try again next time
		}
	}
	if len(want) > 0 && zone != strings.ToLower(c.Domain) {
		if _, err := m.samba(ctx, "dns", "zoneinfo", "127.0.0.1", zone); err != nil {
			if _, err := m.samba(ctx, "dns", "zonecreate", "127.0.0.1", zone); err != nil {
				return nil, err
			}
			if !slices.Contains(st.Zones, zone) {
				st.Zones = append(st.Zones, zone)
			}
		}
	}
	labels := make([]string, 0, len(want))
	for l := range want {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	for _, l := range labels {
		name := l + suffix
		if r, ok := have[l]; ok {
			if r.Address == addr.String() {
				keep = append(keep, r)
				res.Kept = append(res.Kept, name+"."+zone)
				continue
			}
			if _, err := m.samba(ctx, "dns", "update", "127.0.0.1", zone, name, "A", r.Address, addr.String()); err != nil {
				keep = append(keep, r)
				res.Skipped = append(res.Skipped, name+"."+zone)
				continue
			}
			keep = append(keep, hostRecord{Zone: zone, Name: name, Address: addr.String()})
			res.Added = append(res.Added, name+"."+zone)
			continue
		}
		// Someone else's record for the name: left alone.
		if out, err := m.samba(ctx, "dns", "query", "127.0.0.1", zone, name, "ALL"); err == nil && strings.Contains(string(out), "Records=") && !strings.Contains(string(out), "Records=0") {
			res.Skipped = append(res.Skipped, name+"."+zone)
			continue
		}
		if _, err := m.samba(ctx, "dns", "add", "127.0.0.1", zone, name, "A", addr.String()); err != nil {
			res.Skipped = append(res.Skipped, name+"."+zone)
			continue
		}
		keep = append(keep, hostRecord{Zone: zone, Name: name, Address: addr.String()})
		res.Added = append(res.Added, name+"."+zone)
	}
	st.Records = keep
	m.dropEmptyZones(ctx, st, zone)
	if err := m.saveHostRecords(st); err != nil {
		return nil, err
	}
	return res, nil
}

func (m *Manager) deleteHostRecord(ctx context.Context, r hostRecord) bool {
	_, err := m.samba(ctx, "dns", "delete", "127.0.0.1", r.Zone, r.Name, "A", r.Address)
	return err == nil || strings.Contains(err.Error(), "NOT_EXIST") || strings.Contains(err.Error(), "not exist")
}

// dropEmptyZones deletes the zones HardyOS made on the DC that hold none
// of its records any more (keep: a zone just being used).
func (m *Manager) dropEmptyZones(ctx context.Context, st *hostRecordsState, keep string) {
	used := map[string]bool{keep: true}
	for _, r := range st.Records {
		used[r.Zone] = true
	}
	var zones []string
	for _, z := range st.Zones {
		if used[z] {
			zones = append(zones, z)
			continue
		}
		if _, err := m.samba(ctx, "dns", "zonedelete", "127.0.0.1", z); err != nil && !strings.Contains(err.Error(), "NOT_EXIST") {
			zones = append(zones, z) // try again next time
		}
	}
	st.Zones = zones
}

// RemoveHostRecords removes every record HardyOS added and the zones it
// made, from its own list (no base, address or token needed).
func (m *Manager) RemoveHostRecords(ctx context.Context) (*HostRecordsResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.Load()
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, ErrNotProvisioned
	}
	if !c.Enabled || !m.serviceActive(ctx) {
		return nil, errors.New("the domain controller isn't running")
	}
	st, err := m.loadHostRecords()
	if err != nil {
		return nil, err
	}
	res := &HostRecordsResult{Added: []string{}, Removed: []string{}, Kept: []string{}, Skipped: []string{}}
	var keep []hostRecord
	for _, r := range st.Records {
		if m.deleteHostRecord(ctx, r) {
			res.Removed = append(res.Removed, r.Name+"."+r.Zone)
		} else {
			keep = append(keep, r)
		}
	}
	st.Records = keep
	m.dropEmptyZones(ctx, st, "")
	if err := m.saveHostRecords(st); err != nil {
		return nil, err
	}
	return res, nil
}
