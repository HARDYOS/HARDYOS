package domain

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// When the first VM creates the bridge (decision 121), the NAS's address
// moves from the port to br0. The DC's macvlan can't stay on a port that
// joins a bridge, so it lets go first and comes back on the bridge.
func TestDCMovesOntoTheBridge(t *testing.T) {
	f := &sysexec.Fake{}
	m := testManager(t, f)
	m.lastParent = "enp1s0"
	_ = os.MkdirAll(filepath.Join(m.Root, "run/netns"), 0o755)
	_ = os.WriteFile(filepath.Join(m.Root, "run/netns", DefaultNamespace), nil, 0o644)
	f.OnPrefix("ip ", sysexec.Result{})
	f.OnPrefix("sysctl ", sysexec.Result{})

	m.HoldNetwork(context.Background())
	got := strings.Join(f.Lines(), "\n")
	for _, want := range []string{"ip -n hardyos-dc link del hdc0", "ip link del hdc-shim"} {
		if !strings.Contains(got, want) {
			t.Errorf("hold didn't run %q:\n%s", want, got)
		}
	}
	// While held, nothing puts the DC back on the old port.
	n := len(f.Lines())
	c := &Config{Address: "192.168.1.20/24", Gateway: "192.168.1.1", Parent: "enp1s0", MAC: "02:11:22:33:44:55"}
	if err := m.SetupNetwork(context.Background(), c); err == nil {
		t.Fatal("the DC's network was set up while the network was changing")
	}
	if len(f.Lines()) != n {
		t.Fatalf("commands ran while held: %v", f.Lines()[n:])
	}

	// Now the NAS's address is on br0 and the port has none: the DC
	// attaches to the bridge.
	f2 := &sysexec.Fake{}
	m.Runner = f2
	f2.On("ip -j -4 addr show", `[{"ifname":"enp1s0","addr_info":[]},{"ifname":"br0","addr_info":[{"family":"inet","local":"192.168.1.10","prefixlen":24,"scope":"global"}]}]`)
	f2.On("ip -j -4 route show default", `[{"gateway":"192.168.1.1","dev":"br0"}]`)
	f2.OnPrefix("ip -j -n hardyos-dc addr show dev hdc0", sysexec.Result{ExitCode: 1, Stderr: []byte("does not exist")})
	f2.OnPrefix("ip -j -d addr show dev hdc-shim", sysexec.Result{ExitCode: 1, Stderr: []byte("does not exist")})
	f2.OnPrefix("ip ", sysexec.Result{})
	f2.OnPrefix("sysctl ", sysexec.Result{})
	m.netMu.Lock()
	m.held = false
	m.netMu.Unlock()
	if err := m.SetupNetwork(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	got = strings.Join(f2.Lines(), "\n")
	for _, want := range []string{
		"ip link add hdc-new link br0 address 02:11:22:33:44:55 type macvlan mode bridge",
		"ip link add hdc-shim link br0 type macvlan mode bridge",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "link enp1s0") {
		t.Errorf("the DC went back to the port under the bridge:\n%s", got)
	}
}
