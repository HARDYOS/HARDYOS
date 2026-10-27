package domain

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// ReplLink is one inbound replication link: what this DC pulls from a
// partner DC for one naming context.
type ReplLink struct {
	Partner     string `json:"partner"` // Site\DC or the partner's GUID
	NC          string `json:"nc"`
	Failures    int    `json:"failures"`
	LastAttempt string `json:"lastAttempt"`
	LastSuccess string `json:"lastSuccess"`
	LastMessage string `json:"lastMessage"`
}

// Replication is how replication with the other DCs is going.
type Replication struct {
	// Checked is false when there's nothing to check (no domain, the DC is
	// off, or this DC is the only one).
	Checked bool       `json:"checked"`
	Links   []ReplLink `json:"links"`
	// Failing are the links with failures, in words.
	Failing []string `json:"failing"`
	Reason  string   `json:"reason,omitempty"`
}

type showrepl struct {
	RepsFrom []struct {
		NC          string `json:"NC dn"`
		GUID        string `json:"DSA objectGUID"`
		DSA         string `json:"DSA"`
		LastAttempt string `json:"last attempt time"`
		LastMessage string `json:"last attempt message"`
		Failures    int    `json:"consecutive failures"`
		LastSuccess string `json:"last success"`
		Deleted     bool   `json:"is deleted"`
	} `json:"repsFrom"`
}

// ParseShowrepl reads `samba-tool drs showrepl --json`.
func ParseShowrepl(out []byte) (*Replication, error) {
	var s showrepl
	if err := json.Unmarshal(out, &s); err != nil {
		return nil, fmt.Errorf("reading samba-tool drs showrepl: %w", err)
	}
	r := &Replication{Checked: true, Links: []ReplLink{}, Failing: []string{}}
	for _, l := range s.RepsFrom {
		if l.Deleted {
			continue
		}
		partner := l.DSA
		if partner == "" {
			partner = l.GUID
		}
		r.Links = append(r.Links, ReplLink{Partner: partner, NC: l.NC, Failures: l.Failures, LastAttempt: l.LastAttempt, LastSuccess: l.LastSuccess, LastMessage: l.LastMessage})
		if l.Failures > 0 {
			r.Failing = append(r.Failing, fmt.Sprintf("%s (%s): %d failed attempts, last success %s: %s", partner, l.NC, l.Failures, orNever(l.LastSuccess), l.LastMessage))
		}
	}
	sort.Strings(r.Failing)
	if len(r.Links) == 0 {
		r.Checked = false
		r.Reason = "this is the domain's only domain controller"
	}
	return r, nil
}

func orNever(s string) string {
	if s == "" || strings.HasPrefix(s, "NTTIME(0)") {
		return "never"
	}
	return s
}

// ReplicationTimeout bounds samba-tool drs showrepl.
var ReplicationTimeout = 45 * time.Second

// Replication asks this DC how replication from its partners is going.
//
// Only reading the configuration holds the manager's lock; samba-tool runs
// outside it with its own timeout, so a slow or stuck DC never blocks
// domain changes.
func (m *Manager) Replication(ctx context.Context) (*Replication, error) {
	m.mu.Lock()
	c, err := m.Load()
	m.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if c == nil {
		return &Replication{Reason: "no domain", Links: []ReplLink{}, Failing: []string{}}, nil
	}
	if !c.Enabled || !m.serviceActive(ctx) {
		return &Replication{Reason: "the domain controller isn't running", Links: []ReplLink{}, Failing: []string{}}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, ReplicationTimeout)
	defer cancel()
	out, err := sysexec.Output(ctx, m.Runner, "ip", "netns", "exec", m.ns(), "samba-tool", "drs", "showrepl", "--json", "-s", m.SmbConf(), "-P")
	if err != nil {
		return nil, err
	}
	return ParseShowrepl(out)
}
