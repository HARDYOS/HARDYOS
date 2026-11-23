package witness

import (
	"context"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/clustertest"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
)

var update = flag.Bool("update", false, "rewrite golden files")

func TestScriptGolden(t *testing.T) {
	b, err := Script(ScriptParams{Cluster: "abcdefghijklmnopqrstuvwxyz", Node: "witness", Code: "ABCDE-FGHIJ-KLMNO-PQRST-UVWXYZ",
		Members: []ScriptMember{
			{NetBird: netip.MustParseAddr("100.64.0.105"), Pin: strings.Repeat("ab", 32)},
			{NetBird: netip.MustParseAddr("100.64.0.21"), Pin: strings.Repeat("cd", 32)},
		},
		BinarySHA: strings.Repeat("0f", 32), Version: "1.8.0"})
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "install.golden.sh")
	if *update {
		_ = os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(golden, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if string(want) != string(b) {
		t.Fatal("the script changed: check it and run go test ./internal/cluster/witness -update")
	}
	for _, must := range []string{"DynamicUser=yes", "ProtectSystem=strict", "NoNewPrivileges=yes", "MemoryMax=128M",
		"RestrictAddressFamilies=AF_INET AF_INET6\n", "IPAddressDeny=any", "IPAddressAllow=$NBNET", "UMask=0077",
		"ProtectProc=invisible", "ProcSubset=pid", "PrivateUsers=yes", "LoadCredential=join:", "--pinnedpubkey 'sha256//q6ur",
		"sha256sum -c"} {
		if !strings.Contains(string(b), must) {
			t.Errorf("script lacks %q", must)
		}
	}
	if strings.Contains(string(b), "hardyos-witness run --code") {
		t.Error("the code is on a command line")
	}
	// The service is restarted once the drop-in with the code is gone, so
	// the running witness no longer has the credential (decision 374).
	if i, j := strings.Index(string(b), `rm -f "$DROPIN/join.conf"`), strings.LastIndex(string(b), "systemctl restart hardyos-witness.service"); i < 0 || j < i {
		t.Error("the witness isn't restarted after its join code is removed")
	}

}

func TestScriptRejectsInjection(t *testing.T) {
	base := ScriptParams{Cluster: "abcdefghijklmnopqrstuvwxyz", Node: "witness", Code: "ABCDE-FGHIJ-KLMNO-PQRST-UVWXYZ",
		Members:   []ScriptMember{{NetBird: netip.MustParseAddr("100.64.0.105"), Pin: strings.Repeat("ab", 32)}},
		BinarySHA: strings.Repeat("0f", 32), Version: "1.8.0"}
	for _, mod := range []func(p *ScriptParams){
		func(p *ScriptParams) { p.Code = "ABC'; rm -rf / #" },
		func(p *ScriptParams) { p.Version = "1.0$(id)" },
		func(p *ScriptParams) { p.BinarySHA = "zz" },
		func(p *ScriptParams) { p.Members[0].Pin = "x" },
		func(p *ScriptParams) { p.Members = nil },
	} {
		p := base
		p.Members = append([]ScriptMember(nil), base.Members...)
		mod(&p)
		if _, err := Script(p); err == nil {
			t.Errorf("accepted %+v", p)
		}
	}
}

func TestWitnessJoinsAndSaysHello(t *testing.T) {
	net := clustertest.NewNet()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	timings := cluster.Timings{Heartbeat: 50 * time.Millisecond, Suspect: 500 * time.Millisecond, QuorumLease: 800 * time.Millisecond,
		SelfStop: 100 * time.Millisecond, Watchdog: 200 * time.Millisecond, Dead: 2 * time.Second, StorageIsolated: time.Second,
		LANIsolated: 2 * time.Second, FenceAck: time.Second}
	raftT := cluster.RaftTimings{Heartbeat: 300 * time.Millisecond, Election: 300 * time.Millisecond, LeaderLease: 150 * time.Millisecond, Commit: 5 * time.Millisecond}
	paths := cluster.PathTimings{Interval: 30 * time.Millisecond, Timeout: 60 * time.Millisecond}
	nasAddrs := cluster.Addresses{LAN: netip.MustParseAddr("192.168.1.105"), NetBird: netip.MustParseAddr("100.64.0.105")}
	id, _ := cluster.NewIdentity("nas")
	nas, err := cluster.New(ctx, cluster.Config{Identity: id, Store: &clustertest.MemStore{}, Machine: state.New(),
		Net: net.Host(nasAddrs.LAN, nasAddrs.NetBird), Port: 44500, Version: "1.0.0", Features: state.Features(),
		Addresses: func() cluster.Addresses { return nasAddrs }, Raft: raftT, Paths: paths, Timings: &timings})
	if err != nil {
		t.Fatal(err)
	}
	defer nas.Stop()
	if _, err := nas.Create(ctx, cluster.CreateParams{Name: "home", Node: "nas", NodeName: "nas", Role: cluster.RoleStorage},
		cluster.Actor{Kind: "local", Name: "admin"}); err != nil {
		t.Fatal(err)
	}
	off, err := nas.OpenJoinCode(ctx, cluster.RoleWitness, "admin")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := &Config{Cluster: nas.Info().Cluster, Node: "witness", Name: "vpn", Listen: netip.MustParseAddr("100.64.0.9"),
		Members: []Member{{Address: netip.MustParseAddrPort("100.64.0.105:44500"), Pin: id.Pin}}}
	// A wrong pin: the witness refuses to join through that member.
	bad := *cfg
	bad.Members = []Member{{Address: cfg.Members[0].Address, Pin: strings.Repeat("00", 32)}}
	wb, _ := New(ctx, Options{Config: &bad, Dir: t.TempDir(), Version: "1.0.0", Net: net.Host(cfg.Listen), Port: 44500,
		JoinCode: func() (string, error) { return off.Code, nil }, Raft: raftT, Paths: paths, Timings: &timings})
	if err := wb.Join(ctx); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("join with a wrong pin: %v", err)
	}
	w, err := New(ctx, Options{Config: cfg, Dir: dir, Version: "1.0.0", BootID: "b1", Net: net.Host(cfg.Listen), Port: 44500,
		JoinCode: func() (string, error) { return off.Code, nil }, Raft: raftT, Paths: paths, Timings: &timings})
	if err != nil {
		t.Fatal(err)
	}
	rctx, rcancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- w.Run(rctx) }()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if n, ok := nas.Machine().Node("witness"); ok && n.State == cluster.NodeActive && n.BootID == "b1" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the witness never became active")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// With one HardyOS voter the witness stays a non-voter; its key file is
	// private; its status file says it joined.
	if fi, err := os.Stat(filepath.Join(dir, "identity.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("identity file: %v %v", fi, err)
	}
	deadline = time.Now().Add(15 * time.Second)
	for {
		b, _ := os.ReadFile(filepath.Join(dir, "status.json"))
		if strings.Contains(string(b), `"joined": true`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status: %s", b)
		}
		time.Sleep(50 * time.Millisecond)
	}
	rcancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
