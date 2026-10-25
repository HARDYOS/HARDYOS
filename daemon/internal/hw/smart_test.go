package hw

import (
	"context"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

const ataGood = `{"smartctl":{"exit_status":0},"model_name":"WDC WD120EFBX","serial_number":"5QG0AAAA",
"user_capacity":{"bytes":12000138625024},"rotation_rate":7200,"smart_status":{"passed":true},
"temperature":{"current":34},"power_on_time":{"hours":12000},
"ata_smart_attributes":{"table":[{"id":5,"raw":{"value":0}},{"id":197,"raw":{"value":0}},{"id":198,"raw":{"value":0}},{"id":199,"raw":{"value":0}}]}}`

const ataWarn = `{"model_name":"ST4000","serial_number":"Z1","rotation_rate":5900,"smart_status":{"passed":true},
"temperature":{"current":57},"ata_smart_attributes":{"table":[{"id":5,"raw":{"value":8}},{"id":197,"raw":{"value":2}}]}}`

const nvmeFailing = `{"model_name":"Cheap NVMe","serial_number":"N1","smart_status":{"passed":false},
"temperature":{"current":45},"nvme_smart_health_information_log":{"critical_warning":4,"percentage_used":104,"media_errors":3}}`

func TestParseSMART(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		health  Health
		reasons int
	}{
		{"good", ataGood, HealthGood, 0},
		{"warn", ataWarn, HealthWarning, 3},
		{"failing", nvmeFailing, HealthFailing, 4},
		{"unknown", `{"model_name":"VMware Virtual"}`, HealthUnknown, 1},
	}
	for _, c := range cases {
		s, err := ParseSMART([]byte(c.in))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if s.Health != c.health || len(s.Reasons) != c.reasons {
			t.Errorf("%s: health %s reasons %v; want %s with %d reasons", c.name, s.Health, s.Reasons, c.health, c.reasons)
		}
	}
}

func TestReadSMARTValidatesAndUsesExitBits(t *testing.T) {
	f := &sysexec.Fake{}
	if _, err := ReadSMART(context.Background(), f, "/dev/sda; rm -rf /"); err == nil {
		t.Fatal("accepted an invalid device path")
	}
	if len(f.Calls) != 0 {
		t.Fatal("ran a command for an invalid path")
	}

	// Exit bit 3 = "disk failing" while still returning data.
	f.OnResult("smartctl --json=c -a /dev/sdb", sysexec.Result{Stdout: []byte(ataGood), ExitCode: 8})
	s, err := ReadSMART(context.Background(), f, "/dev/sdb")
	if err != nil || s.Health != HealthFailing {
		t.Fatalf("got %+v %v, want failing", s, err)
	}
	// Exit bit 1 = couldn't open the device.
	f.OnResult("smartctl --json=c -a /dev/sdc", sysexec.Result{ExitCode: 2, Stderr: []byte("open failed")})
	if _, err := ReadSMART(context.Background(), f, "/dev/sdc"); err == nil {
		t.Fatal("expected an error when the device can't be opened")
	}
}

func TestValidDevicePath(t *testing.T) {
	for _, ok := range []string{"/dev/sda", "/dev/nvme0n1", "/dev/vdb", "/dev/disk/by-id/wwn-0x5000cca2aaaaaaaa", "/dev/disk/by-id/nvme-WD_Red_SN700_1000GB_22AAA"} {
		if !ValidDevicePath(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"/dev/sda1", "/etc/passwd", "/dev/disk/by-id/../../sda", "sda", "/dev/sda ", "/dev/nvme0n1p1"} {
		if ValidDevicePath(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
