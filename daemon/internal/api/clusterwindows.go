package api

// App windows from any server (Phase 10, decisions 493-495,
// docs/plans/cluster-gaps.md). Where an app's window is:
//
//  1. a cluster app (a placement app:<id>): its owner, whatever server the
//     desktop named;
//  2. else the server the desktop named (/nodes/{node}/apps/{id}/open);
//  3. else this server.
//
// A window on another member is a remote window on this (the entry)
// server, relayed to the owner over the cluster relay (clusterproxy.go).
// App hostnames (<app>.<base>) follow the same routing, and when the app
// isn't a cluster app and isn't here, the one other member that has it
// (a directory of app windows each member answers on its peer API).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// windowRouter finds and reaches app windows on other members (the cluster
// desktop's clusterAPI; a fake in tests).
type windowRouter interface {
	// self is this server's node id ("" outside a cluster).
	self() cluster.NodeID
	// placed is a cluster app's owner when it isn't this server.
	placed(appID string) (cluster.NodeID, bool)
	// route is where an app that isn't this server's own runs: its owner
	// (a cluster app) or the one other member that has it; many lists the
	// members when several do.
	route(ctx context.Context, appID string) (node cluster.NodeID, many []cluster.NodeID)
	// check asks the owner whether the person may open the app's window
	// there, and where it opens (its web path).
	check(ctx context.Context, r *http.Request, u *auth.User, desktopToken string, node cluster.NodeID, appID string) (string, error)
	// transport relays one window request to the owner as the window
	// session's person (windowUserKey, windowDeskKey in the context).
	transport(node cluster.NodeID, appID string) http.RoundTripper
}

// errWindowForbidden: the owner says the person may not use the app.
var errWindowForbidden = errors.New("you haven't been given that app there")

// errWindowNone: the owner has no window for the app.
var errWindowNone = errors.New("that app has no window there")

// windowsPeerPath is the peer API path listing this member's app windows.
const windowsPeerPath = "windows"

// WindowEntry is an app with a window on a member.
type WindowEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ---- the clusterAPI's routing --------------------------------------------------

func (c *clusterAPI) self() cluster.NodeID {
	core := c.core()
	if core == nil || core.Info() == nil {
		return ""
	}
	return core.ID()
}

func (c *clusterAPI) placed(appID string) (cluster.NodeID, bool) {
	self := c.self()
	if self == "" {
		return "", false
	}
	p, ok := c.core().State().Placement(cluster.WorkloadRef{Kind: cluster.KindApp, ID: appID})
	if !ok || p == nil || p.Owner == "" || p.Owner == self {
		return "", false
	}
	if n, ok := c.core().Member(p.Owner); !ok || n.Role == cluster.RoleWitness {
		return "", false
	}
	return p.Owner, true
}

func (c *clusterAPI) route(ctx context.Context, appID string) (cluster.NodeID, []cluster.NodeID) {
	if node, ok := c.placed(appID); ok {
		return node, nil
	}
	self := c.self()
	if self == "" {
		return "", nil
	}
	if p, ok := c.core().State().Placement(cluster.WorkloadRef{Kind: cluster.KindApp, ID: appID}); ok && p != nil && p.Owner == self {
		return "", nil // a cluster app placed here: this server's own
	}
	var have []cluster.NodeID
	for node, list := range c.windowDir(ctx) {
		if node != self && slices.ContainsFunc(list, func(e WindowEntry) bool { return e.ID == appID }) {
			have = append(have, node)
		}
	}
	slices.Sort(have)
	switch len(have) {
	case 0:
		return "", nil
	case 1:
		return have[0], nil
	}
	return "", have
}

func (c *clusterAPI) check(ctx context.Context, r *http.Request, u *auth.User, desktopToken string, node cluster.NodeID, appID string) (string, error) {
	p, err := c.principal(ctx, u)
	if err != nil {
		return "", err
	}
	if p.Kind == "local" && !p.Admin {
		return "", fmt.Errorf("local accounts are per server: sign in on %s", node)
	}
	creq, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+string(node)+cluster.PeerPathPrefix+"windowcheck/"+appID, nil)
	if err != nil {
		return "", errWindowNone
	}
	creq.Host = r.Host
	cresp, err := relayRT{core: c.core(), node: node, p: p, sess: sessionHash(desktopToken)}.RoundTrip(creq)
	if err != nil {
		return "", fmt.Errorf("%s isn't answering: %w", node, err)
	}
	defer cresp.Body.Close()
	switch cresp.StatusCode {
	case http.StatusForbidden:
		return "", errWindowForbidden
	case http.StatusNoContent:
		// The app's web path (an older owner sends none: "/").
		return safeNext(cresp.Header.Get(windowPathHeader)), nil
	}
	return "", errWindowNone
}

// windowPathHeader carries an app's web path in the owner's window check.
const windowPathHeader = "X-Hardyos-Window-Path"

func (c *clusterAPI) transport(node cluster.NodeID, appID string) http.RoundTripper {
	rw := &remoteWindow{c: c, node: node, app: appID}
	rw.used.Store(time.Now().Unix())
	return rw
}

// ---- the directory of app windows (peer API) -------------------------------------

type windowDirectory struct {
	mu    sync.Mutex
	at    time.Time
	nodes map[cluster.NodeID][]WindowEntry
}

// windowDirRefresh is how long the directory is good for.
var windowDirRefresh = 30 * time.Second

// windowDir is every other member's app windows (asked again when older
// than windowDirRefresh; a member that doesn't answer keeps its last list).
func (c *clusterAPI) windowDir(ctx context.Context) map[cluster.NodeID][]WindowEntry {
	d := &c.dir
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.nodes != nil && time.Since(d.at) < windowDirRefresh {
		return d.nodes
	}
	core := c.core()
	if core == nil || core.Info() == nil {
		return nil
	}
	self := core.ID()
	next := map[cluster.NodeID][]WindowEntry{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for id, n := range core.State().Snapshot().Nodes {
		if id == self || n.Role == cluster.RoleWitness || n.State == cluster.NodeRemoved || n.State == cluster.NodeDead || n.State == cluster.NodeFenced {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			var l []WindowEntry
			err := core.Peers().Call(cctx, id, http.MethodGet, "/"+windowsPeerPath, nil, &l)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				next[id] = l
			} else if old, ok := d.nodes[id]; ok {
				next[id] = old
			}
		}()
	}
	wg.Wait()
	d.nodes, d.at = next, time.Now()
	return next
}

// handlePeerWindows answers another member: this server's apps with a web
// page (ids and names only).
func (c *clusterAPI) handlePeerWindows(w http.ResponseWriter, r *http.Request) {
	o, err := c.s.appsStatus(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	out := []WindowEntry{}
	for _, a := range o.Apps {
		if a.Web != nil {
			out = append(out, WindowEntry{ID: a.ID, Name: a.Name})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// ---- the desktop: apps on other servers --------------------------------------------

// ClusterWindow is an app on another member the person may open.
type ClusterWindow struct {
	Node     cluster.NodeID `json:"node"`
	NodeName string         `json:"nodeName"`
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	State    string         `json:"state"`
	// Cluster: a cluster app (it opens wherever it runs).
	Cluster bool `json:"cluster"`
}

// handleWindows is GET /cluster/windows: the apps with a window on other
// members that the person may open, each asked as the person (its access
// list is the owner's).
func (c *clusterAPI) handleWindows(w http.ResponseWriter, r *http.Request, u *auth.User) {
	out := []ClusterWindow{}
	core := c.core()
	if relayedFrom(r) != nil || core == nil || core.Info() == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	p, err := c.principal(r.Context(), u)
	if err != nil || (p.Kind == "local" && !p.Admin) {
		writeJSON(w, http.StatusOK, out) // local accounts are per server
		return
	}
	// One of the person's relayed requests while the members are asked
	// (decision 371's caps).
	release, ok := c.limits.take(u.Username, false)
	if !ok {
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, "too_many", "too many requests to other servers at once; try again shortly")
		return
	}
	defer release()
	token, _ := c.s.sessionToken(r)
	self := core.ID()
	snap := core.State().Snapshot()
	var mu sync.Mutex
	var wg sync.WaitGroup
	for id, n := range snap.Nodes {
		if id == self || n.Role == cluster.RoleWitness || n.State == cluster.NodeRemoved || n.State == cluster.NodeDead || n.State == cluster.NodeFenced {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+string(id)+cluster.PeerPathPrefix+"windowlist", nil)
			if err != nil {
				return
			}
			req.Host = r.Host
			resp, err := relayRT{core: core, node: id, p: p, sess: sessionHash(token)}.RoundTrip(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return
			}
			var l []ClusterWindow
			if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&l) != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, e := range l {
				if apps.ValidID(e.ID) != nil {
					continue
				}
				e.Node, e.NodeName = id, n.Name
				if pl := snap.Placements[cluster.WorkloadRef{Kind: cluster.KindApp, ID: e.ID}]; pl != nil && pl.Owner == id {
					e.Cluster = true
				}
				out = append(out, e)
			}
		}()
	}
	wg.Wait()
	slices.SortFunc(out, func(a, b ClusterWindow) int {
		if a.Name != b.Name {
			return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
		}
		return strings.Compare(string(a.Node), string(b.Node))
	})
	writeJSON(w, http.StatusOK, out)
}

// windowList is the owner's answer to the desktop's list: its apps with a
// window that the person may use.
func (c *clusterAPI) windowList(w http.ResponseWriter, r *http.Request, u *auth.User) {
	o, err := c.s.appsStatus(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "unavailable", "the apps aren't available")
		return
	}
	out := []ClusterWindow{}
	for _, a := range o.Apps {
		if a.Web == nil {
			continue
		}
		if may, err := c.s.mayUse(r.Context(), "", u, a.ID); err != nil || !may {
			continue
		}
		out = append(out, ClusterWindow{ID: a.ID, Name: a.Name, State: a.State})
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- opening a window on another member -------------------------------------------

// openOn opens an app's window that runs on another member, for the
// entry's POST /apps/{id}/open (a cluster app placed elsewhere) and
// /nodes/{node}/apps/{id}/open.
func (c *clusterAPI) openOn(w http.ResponseWriter, r *http.Request, u *auth.User, node cluster.NodeID, app string) {
	m, ok := c.core().Member(node)
	if !ok || m.Role == cluster.RoleWitness {
		writeError(w, http.StatusNotFound, "not_found", "no server called "+string(node)+" in the cluster")
		return
	}
	p, err := c.principal(r.Context(), u)
	if err != nil {
		writeError(w, http.StatusForbidden, "forbidden", err.Error())
		return
	}
	if p.Kind == "local" && !p.Admin {
		writeError(w, http.StatusForbidden, "forbidden", "local accounts are per server: sign in on "+m.Name)
		return
	}
	release, ok := c.limits.take(u.Username, false)
	if !ok {
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, "too_many", "too many requests to other servers at once; try again shortly")
		return
	}
	defer release()
	c.openRemoteWindow(w, r, u, p, node, app)
}
