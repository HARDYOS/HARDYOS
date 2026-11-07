package member

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/clustertest"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

func openDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestDBStoreSealsCodesAndIdentity(t *testing.T) {
	ctx := context.Background()
	s := &DBStore{DB: openDB(t)}
	if i, err := s.Info(ctx); err != nil || i != nil {
		t.Fatalf("empty info: %v %v", i, err)
	}
	code := []byte("0123456789abcdef")
	if err := s.AddJoinCode(ctx, cluster.JoinCode{ID: "a1", Code: code, Role: cluster.RoleCompute, Expires: time.Now().Add(time.Hour), CreatedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddJoinCode(ctx, cluster.JoinCode{ID: "old", Code: code, Role: cluster.RoleCompute, Expires: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	// The code isn't readable in the table.
	var raw []byte
	_ = s.DB.QueryRowContext(ctx, `SELECT code_sealed FROM cluster_join_codes WHERE id = 'a1'`).Scan(&raw)
	if bytes.Contains(raw, code) {
		t.Fatal("join code stored in the clear")
	}
	l, err := s.JoinCodes(ctx, time.Now())
	if err != nil || len(l) != 1 || !bytes.Equal(l[0].Code, code) || l[0].CreatedBy != "admin" {
		t.Fatalf("codes %+v %v", l, err)
	}
	if n, _ := s.JoinCodeFailed(ctx, "a1"); n != 1 {
		t.Fatalf("failures %d", n)
	}
	var left int
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM cluster_join_codes`).Scan(&left)
	if left != 1 {
		t.Fatalf("expired code kept: %d", left)
	}
	id, err := s.NewIdentity(ctx, "nas")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := s.Identity(ctx)
	if err != nil || id2.Pin != id.Pin {
		t.Fatalf("identity: %v", err)
	}
	// Another key source can't open it (a database restored elsewhere).
	other := &DBStore{DB: s.DB}
	if _, err := other.Identity(ctx); err == nil {
		t.Fatal("identity opened with another key")
	}
}

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNodeIDFor(t *testing.T) {
	for in, want := range map[string]string{"NAS": "nas", "c1.local": "c1-local", "9box": "n-9box", "a_b": "a-b",
		strings.Repeat("x", 40): strings.Repeat("x", 32)} {
		if got := string(NodeIDFor(in)); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

func TestServiceCreateAndWitnessScript(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	net := clustertest.NewNet()
	addrs := cluster.Addresses{LAN: netip.MustParseAddr("192.168.1.105"), NetBird: netip.MustParseAddr("100.64.0.105")}
	bin := filepath.Join(t.TempDir(), "hardyos-witness")
	writeFile(t, bin, "binary")
	timings := cluster.Timings{Heartbeat: 50 * time.Millisecond, Suspect: 500 * time.Millisecond, QuorumLease: 800 * time.Millisecond,
		SelfStop: 100 * time.Millisecond, Watchdog: 200 * time.Millisecond, Dead: 2 * time.Second, StorageIsolated: time.Second,
		LANIsolated: 2 * time.Second, FenceAck: time.Second}
	s := &Service{DB: openDB(t), Version: "1.8.0", Dir: t.TempDir(), Net: net.Host(addrs.LAN, addrs.NetBird),
		Addrs: func(netip.Prefix) cluster.Addresses { return addrs }, Hostname: func() string { return "nas" },
		WitnessBinary: bin, Timings: &timings,
		Raft:  cluster.RaftTimings{Heartbeat: 300 * time.Millisecond, Election: 300 * time.Millisecond, LeaderLease: 150 * time.Millisecond, Commit: 5 * time.Millisecond},
		Paths: cluster.PathTimings{Interval: 30 * time.Millisecond}}
	if err := s.Init(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Core().Stop()
	if _, err := s.Create(ctx, CreateParams{Name: "home", Role: cluster.RoleStorage, StorageSubnet: "10.77.0.0/24",
		Actor: cluster.Actor{Kind: "local", Name: "admin"}}); err != nil {
		t.Fatal(err)
	}
	st := s.Status(ctx)
	if !st.Member || st.Self != "nas" || len(st.Nodes) != 1 || st.Nodes[0].PublicKey != nil {
		t.Fatalf("status %+v", st)
	}
	script, off, err := s.WitnessScript(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(script, []byte(off.Code)) || !bytes.Contains(script, []byte("100.64.0.105:44500")) {
		t.Fatal("script lacks the code or the member")
	}
	// Membership survives a restart of hardyd (a new Service on the same DB).
	info, _ := s.Store().Info(ctx)
	if info == nil || info.Node != "nas" || len(info.Peers) != 1 {
		t.Fatalf("stored info %+v", info)
	}
}
