package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/clustertest"
	"github.com/hardyos/hardyos/daemon/internal/cluster/member"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

type clusterNode struct {
	env *testEnv
	svc *member.Service
	api *ClusterAPI
}

func newClusterNode(t *testing.T, net *clustertest.Net, host string, addrs cluster.Addresses) *clusterNode {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	broker := events.NewBroker()
	m := &jobs.Manager{DB: db, Events: broker}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	s := New(Config{DB: db, Jobs: m, Events: broker, Insecure: true})
	timings := cluster.Timings{Heartbeat: 50 * time.Millisecond, Suspect: 500 * time.Millisecond, QuorumLease: 800 * time.Millisecond,
		SelfStop: 100 * time.Millisecond, Watchdog: 200 * time.Millisecond, Dead: 2 * time.Second, StorageIsolated: time.Second,
		LANIsolated: 2 * time.Second, FenceAck: time.Second}
	svc := &member.Service{DB: db, Version: "1.8.0", Dir: t.TempDir(), Net: net.Host(addrs.LAN, addrs.NetBird),
		Addrs: func(netip.Prefix) cluster.Addresses { return addrs }, Hostname: func() string { return host }, Timings: &timings,
		Raft:  cluster.RaftTimings{Heartbeat: 150 * time.Millisecond, Election: 150 * time.Millisecond, LeaderLease: 75 * time.Millisecond, Commit: 5 * time.Millisecond},
		Paths: cluster.PathTimings{Interval: 30 * time.Millisecond}}
	ca := s.AttachCluster(svc)
	if err := svc.Init(ctx); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s)
	t.Cleanup(func() {
		srv.Close()
		svc.Core().Stop()
		cancel()
		m.Wait()
		db.Close()
	})
	return &clusterNode{env: &testEnv{srv: srv, db: db, broker: broker}, svc: svc, api: ca}
}

func twoNodeCluster(t *testing.T) (*clusterNode, *clusterNode) {
	net := clustertest.NewNet()
	nas := newClusterNode(t, net, "nas", cluster.Addresses{LAN: netip.MustParseAddr("192.168.1.105")})
	c1 := newClusterNode(t, net, "c1", cluster.Addresses{LAN: netip.MustParseAddr("192.168.1.21")})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := nas.svc.Create(ctx, member.CreateParams{Name: "home", Role: cluster.RoleStorage, Actor: cluster.Actor{Kind: "local", Name: "cade"}}); err != nil {
		t.Fatal(err)
	}
	off, err := nas.svc.Core().OpenJoinCode(ctx, cluster.RoleCompute, "cade")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c1.svc.Join(ctx, "192.168.1.105", off.Code, cluster.RoleCompute); err != nil {
		t.Fatal(err)
	}
	return nas, c1
}

func TestClusterProxyAssertionsAndAuthorization(t *testing.T) {
	nas, c1 := twoNodeCluster(t)
	cade := nas.env.client(t)
	if code := cade.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil); code != 201 {
		t.Fatalf("setup nas = %d", code)
	}
	other := c1.env.client(t)
	if code := other.do("POST", "/api/v1/setup/admin", map[string]string{"username": "dora", "password": "supersecret1"}, nil); code != 201 {
		t.Fatalf("setup c1 = %d", code)
	}

	// The switcher's list.
	var nodes ClusterNodes
	if code := cade.do("GET", "/api/v1/cluster/nodes", nil, &nodes); code != 200 || !nodes.Member || len(nodes.Nodes) != 2 {
		t.Fatalf("nodes %d %+v", code, nodes)
	}

	// nas's administrator reads c1's users through the proxy: served by c1.
	var users []map[string]any
	if code := cade.do("GET", "/api/v1/nodes/c1/users", nil, &users); code != 200 || len(users) != 1 || users[0]["username"] != "dora" {
		t.Fatalf("proxied users = %d %v", code, users)
	}
	// The node scope works for this server too.
	if code := cade.do("GET", "/api/v1/nodes/nas/users", nil, &users); code != 200 || users[0]["username"] != "cade" {
		t.Fatalf("local scope = %d %v", code, users)
	}
	// A change on c1, audited there as cade (via nas).
	if code := cade.do("POST", "/api/v1/nodes/c1/users", map[string]string{"username": "kid", "password": "kidpassword1"}, nil); code != 201 {
		t.Fatalf("proxied create = %d", code)
	}
	l := &audit.Log{DB: c1.env.db}
	entries, err := l.List(context.Background(), audit.Query{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Actor == "cade (via nas)" && strings.HasPrefix(e.Action, "user.") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no audit entry by cade (via nas) on c1: %+v", entries)
	}
	// Signing in and the proxy itself are never forwarded; the witness and
	// unknown nodes aren't targets.
	if code := cade.do("POST", "/api/v1/nodes/c1/auth/logout", nil, nil); code != 404 {
		t.Fatalf("auth forwarded: %d", code)
	}
	if code := cade.do("GET", "/api/v1/nodes/c1/nodes/nas/users", nil, nil); code != 404 {
		t.Fatalf("chained: %d", code)
	}
	if code := cade.do("GET", "/api/v1/nodes/zz/users", nil, nil); code != 404 {
		t.Fatalf("unknown node: %d", code)
	}
	// A local non-admin of nas gets nothing on c1.
	if code := cade.do("POST", "/api/v1/users", map[string]string{"username": "kid2", "password": "kidpassword1"}, nil); code != 201 {
		t.Fatalf("create kid2 = %d", code)
	}
	kid := nas.env.client(t)
	if code := kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid2", "password": "kidpassword1"}, nil); code != 200 {
		t.Fatalf("kid login = %d", code)
	}
	var e ErrorResponse
	if code := kid.do("GET", "/api/v1/nodes/c1/jobs", nil, &e); code != 403 || !strings.Contains(e.Message, "sign in on c1") {
		t.Fatalf("local user on c1 = %d %+v", code, e)
	}
	// Without a session nothing is forwarded.
	anon := nas.env.client(t)
	if code := anon.do("GET", "/api/v1/nodes/c1/users", nil, nil); code != 401 {
		t.Fatalf("anonymous = %d", code)
	}
}

func TestRelayRefusesReplayTamperAndStrangers(t *testing.T) {
	nas, c1 := twoNodeCluster(t)
	core := nas.svc.Core()
	ctx := context.Background()
	send := func(f *cluster.Forward, tamper bool) int {
		t.Helper()
		req, sb, err := core.RelayRequest(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		defer sb.Close()
		if tamper {
			req.Body = io.NopCloser(strings.NewReader(`{"username":"kidy","password":"kidpassword1"}`))
		}
		resp, err := core.RoundTripRelay(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	admin := cluster.Principal{Kind: "local", Name: "cade", Admin: true}
	body := `{"username":"kidx","password":"kidpassword1"}`
	f := &cluster.Forward{Node: "c1", Principal: admin, Method: "POST", Path: "/api/v1/users", Header: http.Header{"Content-Type": {"application/json"}},
		Body: strings.NewReader(body)}
	// The body is bound to the assertion: a different body is refused.
	if code := send(&cluster.Forward{Node: f.Node, Principal: admin, Method: "POST", Path: f.Path, Header: f.Header, Body: strings.NewReader(body)}, true); code != 403 {
		t.Fatalf("tampered body = %d", code)
	}
	// A replayed request (same assertion, resent) is refused.
	req, sb, err := core.RelayRequest(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	jws := req.Header.Get(cluster.AssertionHeader)
	resp, err := core.RoundTripRelay(req)
	if err != nil || resp.StatusCode != 201 {
		t.Fatalf("first = %v %v", resp.StatusCode, err)
	}
	resp.Body.Close()
	sb.Close()
	req2, sb2, _ := core.RelayRequest(ctx, &cluster.Forward{Node: "c1", Principal: admin, Method: "POST", Path: "/api/v1/users",
		Header: f.Header, Body: strings.NewReader(body)})
	req2.Header.Set(cluster.AssertionHeader, jws)
	req2.Body = io.NopCloser(bytes.NewReader([]byte(body)))
	resp2, err := core.RoundTripRelay(req2)
	sb2.Close()
	if err != nil || resp2.StatusCode != 403 {
		t.Fatalf("replay = %v %v", resp2.StatusCode, err)
	}
	resp2.Body.Close()
	// A request without an assertion over the relay is refused.
	req3, sb3, _ := core.RelayRequest(ctx, &cluster.Forward{Node: "c1", Principal: admin, Method: "GET", Path: "/api/v1/users"})
	req3.Header.Del(cluster.AssertionHeader)
	resp3, err := core.RoundTripRelay(req3)
	sb3.Close()
	if err != nil || resp3.StatusCode != 403 {
		t.Fatalf("no assertion = %v %v", resp3.StatusCode, err)
	}
	resp3.Body.Close()
	_ = c1
}
