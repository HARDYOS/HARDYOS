package api

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// Containment for the cluster desktop (decisions 368, 371). Whether
// cluster members fully trust one another (an administrator of one is an
// administrator of all, as in Proxmox) or must be kept apart from a
// compromised member is the owner's open decision. Until then:
//
//   - an administrator of another member (a synthetic "alice (via c1)") may
//     only use the parts of this member's API the cluster desktop needs to
//     manage workloads and data (clusterAdminMay), never accounts, the
//     terminal, sign-in, network, updates, remote access, custom code or
//     the cluster's membership;
//   - each member chooses which other members' administrators it accepts
//     at all ("accept administrators from these members"; all of them
//     unless an administrator turned one off here);
//   - the entry node caps relayed requests per person and in all.
//
// Full isolation would need the target to authenticate the person itself
// (pending the owner's decision; docs/cluster.md).

// clusterAdminAreas are the API areas open to administrators of other
// members.
var clusterAdminAreas = []string{
	"apps", "vms", "storage", "shares", "files", "sharelinks", "jobs", "events", "notifications", "monitor",
	"hardware", "alerts", "audit", "version", "devices", "backup", "replication", "office", "photos", "ups", "mail",
	"system", "cluster",
}

// clusterAdminDenied are refused within those areas: method ("" any) and
// path (a trailing "/" refuses the subtree too).
var clusterAdminDenied = []struct{ method, path string }{
	// Custom code: compose apps, packages, catalogs.
	{"POST", "/api/v1/apps/custom"},
	{"POST", "/api/v1/apps/packages"},
	{"POST", "/api/v1/apps/catalogs"},
	{"DELETE", "/api/v1/apps/catalogs"},
	{"", "/api/v1/devices/vgpu-driver/"},
	// Network changes and remote access.
	{"POST", "/api/v1/vms/bridge"},
	{"PUT", "/api/v1/apps/*/publish"},
	// Updates and boot environments, configuration backups (a restore
	// brings back accounts and settings).
	{"", "/api/v1/system/updates"},
	{"", "/api/v1/system/updates/"},
	{"", "/api/v1/system/versions/"},
	{"", "/api/v1/system/backups"},
	{"", "/api/v1/system/backups/"},
	// The cluster's membership and its trust.
	{"POST", "/api/v1/cluster"},
	{"", "/api/v1/cluster/join"},
	{"", "/api/v1/cluster/leave"},
	{"", "/api/v1/cluster/dissolve"},
	{"", "/api/v1/cluster/join-codes"},
	{"", "/api/v1/cluster/join-codes/"},
	{"", "/api/v1/cluster/witness/"},
	{"DELETE", "/api/v1/cluster/nodes/"},
	{"", "/api/v1/cluster/admin-trust"},
}

// clusterAdminMay reports whether an administrator of another member may
// call method path here (path is /api/v1/...).
func clusterAdminMay(method, path string) bool {
	rest, ok := strings.CutPrefix(path, "/api/v1/")
	if !ok {
		return false
	}
	area, _, _ := strings.Cut(rest, "/")
	if !slices.Contains(clusterAdminAreas, area) {
		return false
	}
	for _, d := range clusterAdminDenied {
		if d.method != "" && d.method != method {
			continue
		}
		if matchPath(d.path, path) {
			return false
		}
	}
	return true
}

// matchPath matches a path against a pattern whose "*" is one segment and
// whose trailing "/" matches the subtree.
func matchPath(pattern, path string) bool {
	sub := strings.HasSuffix(pattern, "/")
	ps := strings.Split(strings.TrimSuffix(pattern, "/"), "/")
	xs := strings.Split(strings.TrimSuffix(path, "/"), "/")
	if len(xs) < len(ps) || (!sub && len(xs) != len(ps)) || (sub && len(xs) == len(ps)) {
		return false
	}
	for i, p := range ps {
		if p != "*" && p != xs[i] {
			return false
		}
	}
	return true
}

// ---- which members' administrators this member accepts ---------------------------

// keyClusterAdminsRefused holds the members whose administrators this
// member doesn't accept (JSON list of node ids); every other member's are.
const keyClusterAdminsRefused = "cluster.admins.refused"

func (c *clusterAPI) refusedAdmins(ctx context.Context) []cluster.NodeID {
	if c.s.cfg.DB == nil {
		return nil
	}
	v, err := c.s.cfg.DB.GetSetting(ctx, keyClusterAdminsRefused)
	if err != nil || v == "" {
		return nil
	}
	var l []cluster.NodeID
	_ = json.Unmarshal([]byte(v), &l)
	return l
}

// acceptsAdminsFrom reports whether administrators of member id act as
// administrators here.
func (c *clusterAPI) acceptsAdminsFrom(ctx context.Context, id cluster.NodeID) bool {
	return !slices.Contains(c.refusedAdmins(ctx), id)
}

// ClusterAdminTrust is GET/PUT /cluster/admin-trust.
type ClusterAdminTrust struct {
	Members []ClusterAdminTrustMember `json:"members"`
}

// ClusterAdminTrustMember is one other member and whether its
// administrators are accepted here.
type ClusterAdminTrustMember struct {
	ID     cluster.NodeID `json:"id"`
	Name   string         `json:"name"`
	Accept bool           `json:"accept"`
}

func (c *clusterAPI) adminTrust(ctx context.Context) ClusterAdminTrust {
	out := ClusterAdminTrust{Members: []ClusterAdminTrustMember{}}
	core := c.core()
	if core.Info() == nil {
		return out
	}
	refused := c.refusedAdmins(ctx)
	self := core.ID()
	for _, m := range core.Machine().Snapshot().Nodes {
		if m.ID == self || m.Role == cluster.RoleWitness {
			continue
		}
		out.Members = append(out.Members, ClusterAdminTrustMember{ID: m.ID, Name: m.Name, Accept: !slices.Contains(refused, m.ID)})
	}
	sort.Slice(out.Members, func(i, j int) bool { return out.Members[i].ID < out.Members[j].ID })
	return out
}

func (c *clusterAPI) handleAdminTrust(w http.ResponseWriter, r *http.Request, u *auth.User) {
	writeJSON(w, http.StatusOK, c.adminTrust(r.Context()))
}

func (c *clusterAPI) handleAdminTrustSet(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if u.Source == SourceCluster {
		writeError(w, http.StatusForbidden, "forbidden", "only this server's own administrators can change this")
		return
	}
	var req ClusterAdminTrust
	if !decodeJSON(w, r, &req) {
		return
	}
	refused := []cluster.NodeID{}
	var changes []string
	cur := c.refusedAdmins(r.Context())
	for _, m := range req.Members {
		if !m.Accept {
			refused = append(refused, m.ID)
		}
		if was := !slices.Contains(cur, m.ID); was != m.Accept {
			verb := "accept"
			if !m.Accept {
				verb = "refuse"
			}
			changes = append(changes, verb+" "+string(m.ID))
		}
	}
	// Members not named keep their setting.
	for _, id := range cur {
		if !slices.ContainsFunc(req.Members, func(m ClusterAdminTrustMember) bool { return m.ID == id }) {
			refused = append(refused, id)
		}
	}
	slices.Sort(refused)
	refused = slices.Compact(refused)
	b, _ := json.Marshal(refused)
	if err := c.s.cfg.DB.SetSetting(r.Context(), keyClusterAdminsRefused, string(b)); err != nil {
		internalError(c.s, w, err)
		return
	}
	c.s.record(r, u, "cluster.admintrust", "administrators of other servers", audit.Success, strings.Join(changes, ", "))
	writeJSON(w, http.StatusOK, c.adminTrust(r.Context()))
}

// ---- relay caps on the entry node ----------------------------------------------------

// Relayed requests at once (decision 371): per person and in all, plain
// requests and WebSockets (consoles) counted apart.
const (
	maxRelayPerUser   = 16
	maxRelayTotal     = 128
	maxUpgradePerUser = 8
	maxUpgradeTotal   = 64
)

type relayLimits struct {
	mu               sync.Mutex
	perUser, upgrade map[string]int
	total, upTotal   int
}

// take reserves a slot for a person's relayed request (release frees it).
func (l *relayLimits) take(user string, upgrade bool) (func(), bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.perUser == nil {
		l.perUser, l.upgrade = map[string]int{}, map[string]int{}
	}
	m, total, perMax, totalMax := l.perUser, &l.total, maxRelayPerUser, maxRelayTotal
	if upgrade {
		m, total, perMax, totalMax = l.upgrade, &l.upTotal, maxUpgradePerUser, maxUpgradeTotal
	}
	if m[user] >= perMax || *total >= totalMax {
		return nil, false
	}
	m[user]++
	*total++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			m[user]--
			if m[user] <= 0 {
				delete(m, user)
			}
			*total--
		})
	}, true
}
