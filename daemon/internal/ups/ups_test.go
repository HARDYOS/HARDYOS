package ups

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func TestNormalizeAndFiles(t *testing.T) {
	cfg := Config{Mode: ModeLocal, VendorID: "0764", ProductID: "0501", Serial: "CXXKV2000536", Description: "Rack UPS",
		ShutdownCharge: 25, ShutdownRuntime: 300, ServeNetwork: true}
	files, err := Files(cfg, Secrets{ClientPassword: "s3cret-pass"}, "MonitorPassw0rd")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]string{
		"nut.conf":    {"MODE=netserver"},
		"ups.conf":    {"[ups]", "driver = usbhid-ups", "port = auto", "vendorid = 0764", `serial = "CXXKV2000536"`, "ignorelb", "override.battery.charge.low = 25", "override.battery.runtime.low = 300"},
		"upsd.conf":   {"LISTEN 127.0.0.1 3493", "LISTEN 0.0.0.0 3493"},
		"upsd.users":  {"[hardyos-monitor]", "password = MonitorPassw0rd", "upsmon primary", "[hardyos-client]", "password = s3cret-pass", "upsmon secondary"},
		"upsmon.conf": {"MONITOR ups@localhost 1 hardyos-monitor MonitorPassw0rd primary", `SHUTDOWNCMD "/sbin/shutdown -h +0"`, "RUN_AS_USER nut"},
	} {
		for _, w := range want {
			if !strings.Contains(files[name], w) {
				t.Errorf("%s lacks %q:\n%s", name, w, files[name])
			}
		}
	}
	// Without network serving: localhost only, no client account.
	files, _ = Files(Config{Mode: ModeLocal}, Secrets{}, "MonitorPassw0rd")
	if strings.Contains(files["upsd.conf"], "0.0.0.0") || strings.Contains(files["upsd.users"], "secondary") || !strings.Contains(files["nut.conf"], "MODE=standalone") || strings.Contains(files["ups.conf"], "ignorelb") {
		t.Errorf("standalone files:\n%v", files)
	}
	files, err = Files(Config{Mode: ModeNetClient, RemoteHost: "nas1.home.arpa", RemoteUser: "hardyos-client"}, Secrets{RemotePassword: "s3cret-pass"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(files["upsmon.conf"], "MONITOR ups@nas1.home.arpa:3493 1 hardyos-client s3cret-pass secondary") || !strings.Contains(files["nut.conf"], "MODE=netclient") {
		t.Errorf("netclient files:\n%v", files)
	}
	files, _ = Files(Config{Mode: ModeOff}, Secrets{}, "")
	if !strings.Contains(files["nut.conf"], "MODE=none") || strings.Contains(files["upsmon.conf"], "MONITOR") {
		t.Errorf("off files %v", files)
	}
}

func TestNormalizeRejects(t *testing.T) {
	bad := []struct {
		c Config
		s Secrets
	}{
		{Config{Mode: "ups"}, Secrets{}},
		{Config{Mode: ModeLocal, Name: "UPS 1"}, Secrets{}},
		{Config{Mode: ModeLocal, Driver: "genericups"}, Secrets{}},
		{Config{Mode: ModeLocal, Port: "/dev/sda"}, Secrets{}},
		{Config{Mode: ModeLocal, Driver: "blazer_ser", Port: "/etc/shadow"}, Secrets{}},
		{Config{Mode: ModeLocal, Driver: "dummy-ups", Port: "../../etc/shadow"}, Secrets{}},
		{Config{Mode: ModeLocal, Description: "a\"\n[evil]"}, Secrets{}},
		{Config{Mode: ModeLocal, Serial: "x\ndriver = y"}, Secrets{}},
		{Config{Mode: ModeLocal, ShutdownCharge: 95}, Secrets{}},
		{Config{Mode: ModeLocal, ServeNetwork: true}, Secrets{ClientPassword: "short"}},
		{Config{Mode: ModeLocal, ServeNetwork: true}, Secrets{ClientPassword: "has space in it"}},
		{Config{Mode: ModeLocal, ServeNetwork: true, ClientUser: MonitorUser}, Secrets{ClientPassword: "longenough"}},
		{Config{Mode: ModeNetClient, RemoteHost: "nas;rm", RemoteUser: "u"}, Secrets{RemotePassword: "longenough"}},
		{Config{Mode: ModeNetClient, RemoteHost: "nas", RemoteUser: "u"}, Secrets{RemotePassword: `quote"d-pass`}},
		{Config{Mode: ModeNetClient, RemoteHost: "nas", RemoteUser: ""}, Secrets{RemotePassword: "longenough"}},
	}
	for i, b := range bad {
		if _, err := b.c.Normalize(b.s); err == nil {
			t.Errorf("case %d accepted: %+v", i, b.c)
		}
	}
}

func TestParseScannerAndSysfs(t *testing.T) {
	out := `[nutdev1]
	driver = "usbhid-ups"
	port = "auto"
	vendorid = "0764"
	productid = "0501"
	product = "CP1500PFCLCD"
	serial = "CXXKV2000536"
	vendor = "CPS"
	bus = "001"
[nutdev2]
	driver = "genericups"
	port = "auto"
`
	d := parseScanner([]byte(out))
	if len(d) != 1 || d[0].Product != "CP1500PFCLCD" || d[0].VendorID != "0764" {
		t.Errorf("scanner %+v", d)
	}
	root := fstest.MapFS{
		"sys/bus/usb/devices/1-2/idVendor":                {Data: []byte("051d\n")},
		"sys/bus/usb/devices/1-2/idProduct":               {Data: []byte("0002\n")},
		"sys/bus/usb/devices/1-2/product":                 {Data: []byte("Back-UPS ES 700\n")},
		"sys/bus/usb/devices/1-2/serial":                  {Data: []byte("4B1234P00000\n")},
		"sys/bus/usb/devices/1-2/1-2:1.0/bInterfaceClass": {Data: []byte("03\n")},
		"sys/bus/usb/devices/1-3/idVendor":                {Data: []byte("046d\n")}, // a mouse maker
		"sys/bus/usb/devices/1-3/1-3:1.0/bInterfaceClass": {Data: []byte("03\n")},
	}
	f := &sysexec.Fake{}
	f.OnResult("nut-scanner -U -q", sysexec.Result{ExitCode: 127})
	got := Detect(context.Background(), f, root)
	if len(got) != 1 || got[0].Vendor != "APC" || got[0].Product != "Back-UPS ES 700" || got[0].Driver != "usbhid-ups" {
		t.Errorf("sysfs detection %+v", got)
	}
}

func TestApplyWritesAndStarts(t *testing.T) {
	dir := t.TempDir()
	f := &sysexec.Fake{}
	f.OnPrefix("systemctl", sysexec.Result{})
	f.OnPrefix("upsdrvsvcctl", sysexec.Result{})
	r := &Root{Runner: f, Dir: dir, Write: func(p string, b []byte, m os.FileMode) error { return os.WriteFile(p, b, m) }, Chown: func(string) error { return nil }}
	res, err := r.Apply(context.Background(), ApplyArgs{Config: Config{Mode: ModeLocal}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != ModeLocal || len(res.Services) != 3 {
		t.Errorf("result %+v", res)
	}
	users, _ := os.ReadFile(filepath.Join(dir, "upsd.users"))
	mon, _ := os.ReadFile(filepath.Join(dir, "upsmon.conf"))
	pw := ""
	for _, l := range strings.Split(string(users), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "password = ") {
			pw = strings.TrimPrefix(strings.TrimSpace(l), "password = ")
		}
	}
	if len(pw) != 32 || !strings.Contains(string(mon), pw) {
		t.Errorf("monitor password %q not shared between upsd.users and upsmon.conf", pw)
	}
	st, _ := os.Stat(filepath.Join(dir, "upsd.users"))
	if st.Mode().Perm() != 0o640 {
		t.Errorf("upsd.users mode %v", st.Mode())
	}
	lines := strings.Join(f.Lines(), "\n")
	for _, want := range []string{"upsdrvsvcctl resync", "systemctl enable nut-driver-enumerator.path nut-driver.target nut-server.service nut-monitor.service", "systemctl restart nut-server.service nut-monitor.service"} {
		if !strings.Contains(lines, want) {
			t.Errorf("missing %q in\n%s", want, lines)
		}
	}
	if _, err := r.Apply(context.Background(), ApplyArgs{Config: Config{Mode: ModeLocal, Port: "/dev/sda"}}); err == nil {
		t.Error("invalid setup applied")
	}
}

// fakeUPSD answers LIST VAR from a mutable variable set.
type fakeUPSD struct {
	ln   net.Listener
	mu   sync.Mutex
	vars map[string]string
	down bool
}

func newFakeUPSD(t *testing.T) *fakeUPSD {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeUPSD{ln: ln, vars: map[string]string{"ups.status": "OL CHRG", "battery.charge": "100", "battery.runtime": "2400", "ups.load": "31", "ups.mfr": "CPS", "ups.model": "CP1500"}}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				line, _ := r.ReadString('\n')
				f.mu.Lock()
				defer f.mu.Unlock()
				if f.down {
					fmt.Fprint(c, "ERR DATA-STALE\n")
					return
				}
				name := strings.TrimSpace(strings.TrimPrefix(line, "LIST VAR "))
				if name != "ups" {
					fmt.Fprint(c, "ERR UNKNOWN-UPS\n")
					return
				}
				fmt.Fprintf(c, "BEGIN LIST VAR ups\n")
				for k, v := range f.vars {
					fmt.Fprintf(c, "VAR ups %s \"%s\"\n", k, strings.ReplaceAll(v, `"`, `\"`))
				}
				fmt.Fprintf(c, "END LIST VAR ups\n")
			}()
		}
	}()
	return f
}

func (f *fakeUPSD) set(kv ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := 0; i+1 < len(kv); i += 2 {
		f.vars[kv[i]] = kv[i+1]
	}
}

func TestQuery(t *testing.T) {
	f := newFakeUPSD(t)
	f.set("ups.model", `Smart "1500"`)
	st, err := Query(context.Background(), f.ln.Addr().String(), "ups")
	if err != nil {
		t.Fatal(err)
	}
	if !st.OnLine || !st.Charging || *st.ChargePct != 100 || *st.RuntimeSecs != 2400 || st.Model != `Smart "1500"` {
		t.Errorf("status %+v", st)
	}
	if _, err := Query(context.Background(), f.ln.Addr().String(), "other"); !errors.Is(err, ErrUnknownUPS) {
		t.Errorf("unknown UPS: %v", err)
	}
	if _, err := Query(context.Background(), f.ln.Addr().String(), "ups\nLOGOUT"); err == nil {
		t.Error("accepted a name with a newline")
	}
}

// TestDummyUPS runs NUT's own dummy-ups driver and upsd (set
// HARDYOS_NUT_TEST=1; needs nut-server installed): HardyOS reads the UPS
// and sees it go on battery and low.
func TestDummyUPS(t *testing.T) {
	if os.Getenv("HARDYOS_NUT_TEST") != "1" {
		t.Skip("set HARDYOS_NUT_TEST=1 to run NUT's dummy-ups driver")
	}
	driver := firstExisting("/lib/nut/dummy-ups", "/usr/lib/nut/dummy-ups")
	upsd := firstExisting("/lib/nut/upsd", "/usr/lib/nut/upsd", "/usr/sbin/upsd") // Debian wraps /usr/sbin/upsd in a script that reads /etc/nut
	if driver == "" || upsd == "" {
		t.Skip("NUT isn't installed")
	}
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	_ = os.Mkdir(state, 0o770)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	// HardyOS's own renderer for ups.conf (with the dummy driver).
	files, err := Files(Config{Mode: ModeLocal, Name: "dummy", Driver: "dummy-ups", Port: "dummy.dev", Description: "test"}, Secrets{}, "MonitorPassw0rd")
	if err != nil {
		t.Fatal(err)
	}
	write("nut.conf", files["nut.conf"])
	write("ups.conf", files["ups.conf"])
	write("upsd.users", files["upsd.users"])
	write("upsd.conf", fmt.Sprintf("LISTEN 127.0.0.1 %d\n", port))
	write("dummy.dev", "ups.status: OL\nbattery.charge: 100\nbattery.runtime: 3600\nups.load: 20\nups.mfr: Dummy\nups.model: Test 1500\n")
	// NUT's daemons drop to this user; run them as whoever runs the test.
	me := "root"
	if u, err := user.LookupId(fmt.Sprint(os.Geteuid())); err == nil {
		me = u.Username
	}
	env := []string{"NUT_CONFPATH=" + dir, "NUT_STATEPATH=" + state, "NUT_ALTPIDPATH=" + state, "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	var logs []*strings.Builder
	start := func(name string, args ...string) {
		cmd := exec.Command(name, args...)
		cmd.Env = env
		var out strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &out
		logs = append(logs, &out)
		if err := cmd.Start(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	}
	start(driver, "-a", "dummy", "-u", me, "-F")
	time.Sleep(time.Second)
	start(upsd, "-u", me, "-F")
	t.Cleanup(func() {
		if t.Failed() {
			for _, l := range logs {
				t.Log(l.String())
			}
		}
	})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	var st *Status
	deadline := time.Now().Add(15 * time.Second)
	for {
		st, err = Query(context.Background(), addr, "dummy")
		if err == nil && st.Raw != "" && st.Raw != "WAIT" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("upsd never answered: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !st.OnLine || *st.ChargePct != 100 || st.Model != "Test 1500" || st.Driver != "dummy-ups" {
		t.Fatalf("status %+v", st)
	}
	write("dummy.dev", "ups.status: OB LB\nbattery.charge: 9\nbattery.runtime: 120\nups.load: 20\n")
	deadline = time.Now().Add(20 * time.Second)
	for {
		st, err = Query(context.Background(), addr, "dummy")
		if err == nil && st.LowBattery {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("never saw low battery: %+v %v", st, err)
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !st.OnBattery || *st.RuntimeSecs != 120 {
		t.Errorf("status %+v", st)
	}
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
