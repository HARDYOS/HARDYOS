package dsnet

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func TestParseNetworks(t *testing.T) {
	ip, gw, err := ParseNetworks([]byte(`{"hardyos-onlyoffice_default":{"IPAddress":"172.19.0.2","Gateway":"172.19.0.1"}}`))
	if err != nil || ip.String() != "172.19.0.2" || gw.String() != "172.19.0.1" {
		t.Fatalf("%v %v %v", ip, gw, err)
	}
	for _, bad := range []string{
		`{}`,
		`{"a":{"IPAddress":"172.19.0.2","Gateway":"172.19.0.1"},"b":{"IPAddress":"172.20.0.2","Gateway":"172.20.0.1"}}`,
		`{"host":{"IPAddress":"","Gateway":""}}`,
		`{"a":{"IPAddress":"8.8.8.8","Gateway":"8.8.8.1"}}`,
		`{"a":{"IPAddress":"fd00::2","Gateway":"fd00::1"}}`,
		`not json`,
	} {
		if _, _, err := ParseNetworks([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestRules(t *testing.T) {
	ip, gw := netip.MustParseAddr("172.19.0.2"), netip.MustParseAddr("172.17.0.1")
	r := Rules(ip, gw, 998)
	join := func(c string) string {
		var l []string
		for _, x := range r[c] {
			l = append(l, strings.Join(x, " "))
		}
		return strings.Join(l, "\n")
	}
	in := join(ChainIn)
	if !strings.Contains(in, "-d 172.17.0.1/32 -p tcp --dport 44251 -j ACCEPT") || !strings.HasSuffix(in, "-j DROP") {
		t.Fatalf("in:\n%s", in)
	}
	out := join(ChainOut)
	if !strings.Contains(out, "--uid-owner 998 -j ACCEPT") || !strings.HasSuffix(out, "-j REJECT") {
		t.Fatalf("out:\n%s", out)
	}
	fwd := join(ChainFwd)
	for _, b := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "127.0.0.0/8"} {
		if !strings.Contains(fwd, "-s 172.19.0.2/32 -d "+b+" -j DROP") {
			t.Errorf("forwarding to %s not dropped", b)
		}
	}
	if !strings.Contains(fwd, "-d 172.19.0.2/32 -j DROP") || !strings.HasSuffix(fwd, "-j RETURN") {
		t.Fatalf("fwd:\n%s", fwd)
	}
}

func TestApplyReplacesOldJumps(t *testing.T) {
	f := &sysexec.Fake{}
	f.On("docker ps -q --no-trunc --filter label=com.docker.compose.project=hardyos-onlyoffice --filter label=com.docker.compose.service=documentserver --filter status=running", "abcdef0123456789\n")
	f.On("docker inspect --format {{json .NetworkSettings.Networks}} abcdef0123456789", `{"n":{"IPAddress":"172.19.0.3","Gateway":"172.19.0.1"}}`)
	f.On("iptables -w -S INPUT", "-P INPUT ACCEPT\n-A INPUT -s 172.19.0.2/32 -j HARDYOS-OFFICE-IN\n-A INPUT -i virbr0 -j HARDYOS-VMNAT\n")
	f.On("iptables -w -S OUTPUT", "-P OUTPUT ACCEPT\n")
	f.On("iptables -w -S DOCKER-USER", "-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n")
	f.OnPrefix("iptables -w -C", sysexec.Result{ExitCode: 1})
	f.OnPrefix("iptables", sysexec.Result{})
	m := &Manager{Runner: f, HardydUID: func() (int, error) { return 998, nil },
		HostGateway: func() (netip.Addr, error) { return netip.MustParseAddr("172.17.0.1"), nil }}
	a, err := m.Apply(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a.IP != "172.19.0.3" || a.HostGW != "172.17.0.1" {
		t.Fatalf("%+v", a)
	}
	lines := f.Lines()
	for _, want := range []string{
		"iptables -w -D INPUT -s 172.19.0.2/32 -j HARDYOS-OFFICE-IN",
		"iptables -w -I INPUT 1 -s 172.19.0.3/32 -j HARDYOS-OFFICE-IN",
		"iptables -w -I OUTPUT 1 -d 172.19.0.3/32 -j HARDYOS-OFFICE-OUT",
		"iptables -w -I DOCKER-USER 1 -s 172.19.0.3/32 -j HARDYOS-OFFICE-FWD",
		"iptables -w -I DOCKER-USER 1 -d 172.19.0.3/32 -j HARDYOS-OFFICE-FWD",
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, l := range lines {
		if strings.Contains(l, "HARDYOS-VMNAT") && strings.Contains(l, "-D") {
			t.Errorf("touched another chain's jump: %s", l)
		}
	}
	// Not running: a clear error, no rules touched.
	g := &sysexec.Fake{}
	g.OnPrefix("docker ps", sysexec.Result{})
	m.Runner = g
	if _, err := m.Apply(context.Background()); err != ErrNotRunning {
		t.Fatalf("not running: %v", err)
	}
	for _, l := range g.Lines() {
		if strings.HasPrefix(l, "iptables") {
			t.Fatalf("touched iptables: %s", l)
		}
	}
}
