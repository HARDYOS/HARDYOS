package network

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// DomainHookPath makes dhclient put the domain's DNS servers first when the
// NAS gets its DNS from DHCP.
const DomainHookPath = "etc/dhcp/dhclient-enter-hooks.d/hardyos-domain"

// maxNameservers is how many nameserver lines the C library reads.
const maxNameservers = 3

// domainDNSState remembers what SyncDomainDNS last added, so it can take
// exactly that out again.
type domainDNSState struct {
	Servers []string `json:"servers"`
	Domain  string   `json:"domain"`
}

func (m *Manager) domainStateFile() string { return filepath.Join(m.stateDir(), "domain-dns.json") }

// domainDNS asks the domain controller manager what to use.
func (m *Manager) domainDNS() ([]string, string) {
	if m.DomainDNS == nil {
		return nil, ""
	}
	return m.DomainDNS()
}

// dhcpHeader marks a resolv.conf whose servers came from DHCP with the
// domain's put first. It must not say "HardyOS": Import reads files that do
// as DNS servers chosen in Control Panel > Network.
const dhcpHeader = "# DNS servers from DHCP, with the domain's controllers first (Control Panel > Domain).\n"

// RenderResolvDomain writes resolv.conf with the domain's DCs first. Short
// timeouts keep lookups quick while a DC is restarting.
func RenderResolvDomain(dcs []string, domain string, dns, search []string) string {
	return renderResolvDomain(header, dcs, domain, dns, search)
}

func renderResolvDomain(head string, dcs []string, domain string, dns, search []string) string {
	if len(dcs) == 0 {
		return RenderResolv(dns, search)
	}
	var all []string
	for _, s := range append(append([]string{}, dcs...), dns...) {
		if s != "" && !slices.Contains(all, s) {
			all = append(all, s)
		}
	}
	// Keep one non-DC server when there's room, so the NAS still resolves
	// names if every DC is down.
	if len(all) > maxNameservers {
		keep := all[:maxNameservers]
		if len(dcs) >= maxNameservers && len(dns) > 0 {
			keep = append(append([]string{}, all[:maxNameservers-1]...), dns[0])
		}
		all = keep
	}
	srch := []string{domain}
	for _, s := range search {
		if s != domain && !slices.Contains(srch, s) {
			srch = append(srch, s)
		}
	}
	var b strings.Builder
	b.WriteString(head)
	if head == header {
		b.WriteString("# The domain's controllers come first (Control Panel > Domain).\n")
	}
	b.WriteString("options timeout:2 attempts:2\n")
	for _, d := range all {
		fmt.Fprintf(&b, "nameserver %s\n", d)
	}
	fmt.Fprintf(&b, "search %s\n", strings.Join(srch, " "))
	return b.String()
}

// RenderDomainHook is the dhclient hook for DHCP-provided DNS.
func RenderDomainHook(dcs []string, domain string) string {
	return fmt.Sprintf(`# Written by HardyOS: the domain's DNS servers come first (Control Panel > Domain).
new_domain_name_servers="%s ${new_domain_name_servers}"
new_domain_search="%s${new_domain_search:+ $new_domain_search}"
`, strings.Join(dcs, " "), domain)
}

// withDomain adds the domain's DNS to rendered network files.
func (m *Manager) withDomain(c Config, f Files) Files {
	dcs, domain := m.domainDNS()
	f[DomainHookPath] = nil
	if len(dcs) == 0 {
		return f
	}
	if len(c.DNS) > 0 {
		f[ResolvPath] = str(RenderResolvDomain(dcs, domain, c.DNS, c.Search))
	} else {
		f[DomainHookPath] = str(RenderDomainHook(dcs, domain))
	}
	return f
}

// parseResolv reads nameserver and search lines.
func parseResolv(s string) (ns, search []string) {
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "nameserver":
			ns = append(ns, f[1])
		case "search", "domain":
			search = append(search, f[1:]...)
		}
	}
	return ns, search
}

func without(list, drop []string) []string {
	var out []string
	for _, v := range list {
		if !slices.Contains(drop, v) {
			out = append(out, v)
		}
	}
	return out
}

// SyncDomainDNS makes the NAS's own resolver use the domain's DCs first, or
// stop using them once the domain is gone. It changes nothing while a
// network change waits for confirmation (the change itself brings the
// domain's DNS along) and is safe to call any time.
func (m *Manager) SyncDomainDNS(ctx context.Context) error {
	dcs, domain := m.domainDNS()
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, err := m.loadPending(); err != nil || p != nil {
		return err
	}
	var prev domainDNSState
	if b, err := os.ReadFile(m.domainStateFile()); err == nil {
		_ = json.Unmarshal(b, &prev)
	}
	if len(dcs) == 0 && len(prev.Servers) == 0 {
		return nil // no domain now or before: nothing of ours to change
	}
	c := m.Current()
	// Without saved settings, Current reads DNS servers back from resolv.conf,
	// where the domain's DCs are ours, not the person's choice.
	added := append(append([]string{}, prev.Servers...), dcs...)
	c.DNS = without(c.DNS, added)
	c.Search = without(c.Search, []string{prev.Domain, domain})
	current := m.readFile(ResolvPath)
	var want string
	if len(c.DNS) > 0 {
		want = RenderResolvDomain(dcs, domain, c.DNS, c.Search)
	} else {
		// DNS from DHCP: keep what dhclient wrote, minus anything we added.
		ns, search := parseResolv(current)
		ns = without(ns, append(append([]string{}, prev.Servers...), dcs...))
		search = without(search, []string{prev.Domain, domain})
		if len(dcs) > 0 {
			want = renderResolvDomain(dhcpHeader, dcs, domain, ns, search)
		} else if len(prev.Servers) > 0 {
			want = renderPlainResolv(ns, search)
		} else {
			want = current // never ours: leave dhclient's file alone
		}
		var hook *string
		if len(dcs) > 0 {
			hook = str(RenderDomainHook(dcs, domain))
		}
		if err := writeOrRemove(m.path(DomainHookPath), hook); err != nil {
			return err
		}
	}
	if want != current {
		if err := writeOrRemove(m.path(ResolvPath), str(want)); err != nil {
			return err
		}
		m.log().Info("DNS servers updated for the domain", "domain", domain, "controllers", dcs)
	}
	return writeJSON(m.domainStateFile(), domainDNSState{Servers: dcs, Domain: domain})
}

// renderPlainResolv is resolv.conf as dhclient would write it.
func renderPlainResolv(dns, search []string) string {
	var b strings.Builder
	if len(search) > 0 {
		fmt.Fprintf(&b, "search %s\n", strings.Join(search, " "))
	}
	for _, d := range dns {
		fmt.Fprintf(&b, "nameserver %s\n", d)
	}
	return b.String()
}
