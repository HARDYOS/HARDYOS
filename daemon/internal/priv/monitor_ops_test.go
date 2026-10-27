package priv

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/ups"
)

func call(t *testing.T, s *Server, op string, args any) (any, error) {
	t.Helper()
	raw, _ := json.Marshal(args)
	fn := s.ops[op]
	if fn == nil {
		t.Fatalf("op %s not registered", op)
	}
	return fn(context.Background(), raw)
}

func TestSMARTOpsOnlyKnownDisks(t *testing.T) {
	st, f := storageEnv(t)
	smart, _ := os.ReadFile("../hw/testdata/smart-sata-hdd.json")
	f.OnResult("smartctl --json=c -a -n standby,0 "+id("sda"), sysexec.Result{Stdout: smart})
	f.OnResult("smartctl --json=c -t long "+id("sdb"), sysexec.Result{Stdout: []byte(`{}`)})
	s := &Server{}
	RegisterStorage(s, st.env)
	RegisterMonitor(s, MonitorEnv{Storage: st.env})

	res, err := call(t, s, OpHWSmart, DeviceArgs{Device: id("sda"), NoWake: true})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	if !strings.Contains(string(b), `"model":"WDC WD120EFBX-68B0EN0"`) {
		t.Errorf("smart result %s", b)
	}
	if _, err := call(t, s, OpHWSmartTest, SmartTestArgs{Device: id("sdb"), Test: "long"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []any{
		DeviceArgs{Device: "/dev/sda"},                          // a known disk, but not by its stable path
		DeviceArgs{Device: "/dev/disk/by-id/ata-SOMEONE_ELSES"}, // not one of ours
		DeviceArgs{Device: "/dev/sda1"},                         // a partition
	} {
		before := len(f.Lines())
		if _, err := call(t, s, OpHWSmart, bad); err == nil {
			t.Errorf("hw.smart accepted %+v", bad)
		}
		for _, l := range f.Lines()[before:] {
			if strings.HasPrefix(l, "smartctl") {
				t.Errorf("ran %q for %+v", l, bad)
			}
		}
	}
	for _, bad := range []SmartTestArgs{{Device: id("sdc"), Test: "conveyance"}, {Device: "/dev/disk/by-id/../../sda", Test: "short"}, {Device: id("zzz"), Test: "short"}} {
		if _, err := call(t, s, OpHWSmartTest, bad); err == nil {
			t.Errorf("hw.smart.test accepted %+v", bad)
		}
	}
}

func TestUPSOps(t *testing.T) {
	dir := t.TempDir()
	f := &sysexec.Fake{}
	f.OnPrefix("systemctl", sysexec.Result{})
	f.OnResult("nut-scanner -U -q", sysexec.Result{Stdout: []byte("[nutdev1]\n\tdriver = \"usbhid-ups\"\n\tport = \"auto\"\n\tvendorid = \"0764\"\n\tproductid = \"0501\"\n")})
	s := &Server{}
	RegisterMonitor(s, MonitorEnv{UPS: &ups.Root{Runner: f, Dir: dir, Write: func(p string, b []byte, m os.FileMode) error { return os.WriteFile(p, b, m) }, Chown: func(string) error { return nil }}})
	res, err := call(t, s, OpUPSDetect, nil)
	if err != nil || len(res.([]ups.Device)) != 1 {
		t.Fatalf("detect %v %v", res, err)
	}
	if _, err := call(t, s, OpUPSApply, ups.ApplyArgs{Config: ups.Config{Mode: ups.ModeNetClient, RemoteHost: "10.0.0.2", RemoteUser: "monuser"}, Secrets: ups.Secrets{RemotePassword: "s3cret-pass"}}); err != nil {
		t.Fatal(err)
	}
	mon, _ := os.ReadFile(dir + "/upsmon.conf")
	if !strings.Contains(string(mon), "MONITOR ups@10.0.0.2:3493 1 monuser s3cret-pass secondary") {
		t.Errorf("upsmon.conf %s", mon)
	}
	_, err = call(t, s, OpUPSApply, ups.ApplyArgs{Config: ups.Config{Mode: ups.ModeLocal, Driver: "dummy-ups", Port: "/etc/shadow"}})
	var pe *Error
	if err == nil || !errorsAs(err, &pe) || pe.Code != CodeBadArgs {
		t.Errorf("bad setup: %v", err)
	}
}

func errorsAs(err error, pe **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*pe = e
	}
	return ok
}

func TestQuietOps(t *testing.T) {
	s := &Server{}
	QuietMonitoringOps(s)
	if !s.QuietOps[OpPing] || !s.QuietOps[OpHWSmart] || s.QuietOps[OpHWSmartTest] || s.QuietOps[OpUPSApply] {
		t.Errorf("quiet ops %v", s.QuietOps)
	}
}
