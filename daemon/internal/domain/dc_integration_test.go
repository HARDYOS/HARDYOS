package domain

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// TestDCIntegration provisions a real Samba AD domain controller with the
// real Manager, in its own network namespace on the machine's LAN port, then
// manages users and groups and signs in over SMB. It changes the machine
// (/var/lib/hardyos-dc, a namespace, two macvlans), so it only runs as root
// on a throwaway machine with samba-ad-dc, iputils-arping, dnsutils and
// smbclient installed and hardyos-dc-admin at /usr/lib/hardyos:
//
//	sudo HARDYOS_DC_INTEGRATION=1 go test ./internal/domain -run TestDCIntegration -v
//
// HARDYOS_DC_TEST_ADDRESS and HARDYOS_DC_TEST_GATEWAY put the DC on a
// network of the test's choosing (CI uses a dummy interface, because cloud
// networks answer ARP for every address and nothing looks free).
//
// With systemd, packaging/systemd/hardyos-dc.service must be installed.
// Without it (containers), the test runs Samba the same way the unit does.
func TestDCIntegration(t *testing.T) {
	if os.Getenv("HARDYOS_DC_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_DC_INTEGRATION=1 on a throwaway machine")
	}
	ctx := context.Background()
	var runner sysexec.Runner = sysexec.Exec{}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		u := &unitless{}
		runner = u
		t.Cleanup(u.stop)
	}
	m := &Manager{Runner: runner, Root: "/"}
	if !m.Available() {
		t.Fatal("samba or hardyos-dc-admin isn't installed")
	}
	if c, _ := m.Load(); c != nil {
		t.Fatalf("a domain already exists here (%s)", c.Domain)
	}
	t.Cleanup(func() {
		if c, _ := m.Load(); c != nil {
			_ = m.Destroy(ctx, c.Domain)
		}
	})

	addr, gw := os.Getenv("HARDYOS_DC_TEST_ADDRESS"), os.Getenv("HARDYOS_DC_TEST_GATEWAY")
	if addr == "" {
		sug, err := m.Suggest(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("suggestion: %+v", sug)
		if sug.Address == "" {
			t.Fatal("no free address found for the DC")
		}
		addr = sug.Address
	}

	const pw = "Ci-Admin-Passw0rd!"
	start := time.Now()
	c, err := m.Provision(ctx, ProvisionArgs{Domain: "home.hardyos-ci.net", AdminPassword: pw, Address: addr, Gateway: gw, Forwarders: []string{"9.9.9.9"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("provisioned %s at %s in %s", c.Domain, c.Address, time.Since(start).Round(time.Second))

	waitResponding(t, m)
	// Still answering once the DC has forgotten the NAS's hardware address
	// (an expired ARP entry): replies must find their way back.
	_ = exec.Command("ip", "-n", Namespace, "neigh", "flush", "all").Run()
	_ = exec.Command("ip", "neigh", "flush", "dev", ShimLink).Run()
	if st, _ := m.Status(ctx); !st.Responding {
		t.Fatalf("the DC stopped answering after its ARP cache was cleared: %+v", st)
	}

	// The admin password set through stdin works.
	smbOK(t, c.IP(), "HOME", "Administrator", pw)

	if _, err := m.CreateUser(ctx, NewUser{Username: "alice", GivenName: "Alice", Surname: "Hardy", Password: "Al1ce-Passw0rd!"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateUser(ctx, NewUser{Username: "alice", Password: "Al1ce-Passw0rd!"}); err == nil {
		t.Error("a second alice was created")
	}
	if _, err := m.CreateGroup(ctx, NewGroup{Name: "Family", Members: []string{"alice"}}); err != nil {
		t.Fatal(err)
	}
	users, err := m.Users(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var alice *User
	for i := range users {
		if users[i].Username == "alice" {
			alice = &users[i]
		}
	}
	if alice == nil || alice.DisplayName != "Alice Hardy" || strings.Join(alice.Groups, ",") != "Domain Users,Family" && strings.Join(alice.Groups, ",") != "Family" {
		t.Fatalf("alice = %+v", alice)
	}
	smbOK(t, c.IP(), "HOME", "alice", "Al1ce-Passw0rd!")

	if _, err := m.SetUserEnabled(ctx, "alice", false); err != nil {
		t.Fatal(err)
	}
	if smbErr(c.IP(), "HOME", "alice", "Al1ce-Passw0rd!") == nil {
		t.Error("a turned-off account could still sign in")
	}
	if _, err := m.SetUserEnabled(ctx, "alice", true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ResetPassword(ctx, PasswordReset{Username: "alice", Password: "N3w-Passw0rd!"}); err != nil {
		t.Fatal(err)
	}
	smbOK(t, c.IP(), "HOME", "alice", "N3w-Passw0rd!")

	if err := m.DeleteUser(ctx, "Administrator"); err == nil {
		t.Error("the domain Administrator was deleted")
	}
	if err := m.DeleteGroup(ctx, "Domain Admins"); err == nil {
		t.Error("Domain Admins was deleted")
	}

	// Stop and start keep everything.
	if st, err := m.SetEnabled(ctx, false); err != nil || st.Running {
		t.Fatalf("stop: %+v %v", st, err)
	}
	if _, err := m.SetEnabled(ctx, true); err != nil {
		t.Fatal(err)
	}
	waitResponding(t, m)
	smbOK(t, c.IP(), "HOME", "alice", "N3w-Passw0rd!")

	// Pulling the DC off the network is repaired by Ensure (what Watch runs).
	_ = exec.Command("ip", "-n", Namespace, "link", "del", DCLink).Run()
	_ = exec.Command("ip", "link", "del", ShimLink).Run()
	if err := m.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	waitResponding(t, m)

	if err := m.Destroy(ctx, c.Domain); err != nil {
		t.Fatal(err)
	}
	if st, _ := m.Status(ctx); st.Provisioned {
		t.Error("still provisioned after Destroy")
	}
	if _, err := os.Stat("/run/netns/" + Namespace); err == nil {
		t.Error("namespace left behind")
	}
}

func waitResponding(t *testing.T, m *Manager) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var st *Status
	for time.Now().Before(deadline) {
		st, _ = m.Status(context.Background())
		if st != nil && st.Running && st.Responding {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("the DC never answered: %+v", st)
}

func smbErr(ip, dom, user, pw string) error {
	out, err := exec.Command("smbclient", "-L", "//"+ip, "-U", dom+`\`+user+"%"+pw).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "sysvol") {
		return fmt.Errorf("smbclient as %s: %v: %s", user, err, out)
	}
	return nil
}

func smbOK(t *testing.T, ip, dom, user, pw string) {
	t.Helper()
	var err error
	for i := 0; i < 10; i++ {
		if err = smbErr(ip, dom, user, pw); err == nil {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatal(err)
}

// unitless stands in for systemd where there is none: it runs Samba the way
// hardyos-dc.service does (the DC's namespace, /run/samba bound to its run
// folder) and answers systemctl for that one unit.
type unitless struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func (u *unitless) running() bool {
	if u.cmd == nil {
		return false
	}
	select {
	case <-u.done:
		return false
	default:
		return true
	}
}

func (u *unitless) stop() {
	if u.running() {
		_ = u.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-u.done:
		case <-time.After(15 * time.Second):
			_ = u.cmd.Process.Kill()
			<-u.done
		}
	}
	u.cmd = nil
}

func (u *unitless) Run(ctx context.Context, stdin []byte, name string, args ...string) (sysexec.Result, error) {
	if name == "systemctl" && len(args) > 0 && args[len(args)-1] == Service {
		switch args[0] {
		case "is-active":
			if u.running() {
				return sysexec.Result{}, nil
			}
			return sysexec.Result{ExitCode: 3}, nil
		case "stop":
			u.stop()
			return sysexec.Result{}, nil
		case "start":
			if u.running() {
				return sysexec.Result{}, nil
			}
			dir := DataDir
			_ = os.MkdirAll("/run/samba", 0o755)
			script := fmt.Sprintf("mount --bind %s /run/samba && exec samba --foreground --no-process-group -s %s",
				filepath.Join(dir, "run"), filepath.Join(dir, "etc", "smb.conf"))
			u.cmd = exec.Command("ip", "netns", "exec", Namespace, "unshare", "-m", "--propagation", "private", "sh", "-c", script)
			log, _ := os.Create(filepath.Join(dir, "log", "foreground.log"))
			u.cmd.Stdout, u.cmd.Stderr = log, log
			if err := u.cmd.Start(); err != nil {
				return sysexec.Result{ExitCode: 1, Stderr: []byte(err.Error())}, nil
			}
			u.done = make(chan struct{})
			go func(c *exec.Cmd, done chan struct{}) { _ = c.Wait(); close(done) }(u.cmd, u.done)
			time.Sleep(3 * time.Second)
			return sysexec.Result{}, nil
		}
	}
	return sysexec.Exec{}.Run(ctx, stdin, name, args...)
}
