package hw

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func sample(t *testing.T, name string) *SMART {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseSMART(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSMARTSamples(t *testing.T) {
	sata := sample(t, "smart-sata-hdd.json")
	if sata.Health != HealthGood || sata.Protocol != "ATA" || sata.RotationRPM != 7200 || *sata.TemperatureC != 34 || *sata.PowerOnHours != 12004 {
		t.Errorf("SATA %+v", sata)
	}
	if len(sata.Attributes) != 10 || sata.Attributes[3].Name != "Reallocated_Sector_Ct" || sata.Attributes[3].Thresh != 5 {
		t.Errorf("SATA attributes %+v", sata.Attributes)
	}
	if sata.SelfTest.ShortMinutes != 2 || sata.SelfTest.LongMinutes != 1271 || sata.SelfTest.Running || len(sata.SelfTests) != 2 || !*sata.SelfTests[0].Passed {
		t.Errorf("SATA self-tests %+v %+v", sata.SelfTest, sata.SelfTests)
	}

	bad := sample(t, "smart-sata-failing.json")
	if bad.Health != HealthFailing {
		t.Fatalf("failing SATA verdict %s %v", bad.Health, bad.Reasons)
	}
	joined := strings.Join(bad.Reasons, "; ")
	for _, want := range []string{"last self-test failed: Completed: read failure", "1688 reallocated", "64 sectors pending", "64 uncorrectable", "312 reported uncorrectable"} {
		if !strings.Contains(joined, want) {
			t.Errorf("failing reasons lack %q: %s", want, joined)
		}
	}

	nv := sample(t, "smart-nvme.json")
	if nv.Health != HealthGood || nv.Protocol != "NVMe" || *nv.PercentUsed != 3 || *nv.AvailableSpare != 100 || *nv.UnsafeShutdowns != 12 || nv.CapacityBytes != 1000204886016 {
		t.Errorf("NVMe %+v", nv)
	}
	if len(nv.SelfTests) != 2 || nv.SelfTests[1].Type != "Extended" {
		t.Errorf("NVMe self-tests %+v", nv.SelfTests)
	}

	nvBad := sample(t, "smart-nvme-failing.json")
	if nvBad.Health != HealthFailing || !nvBad.SelfTest.Running || *nvBad.SelfTest.RemainingPct != 70 {
		t.Errorf("failing NVMe %+v", nvBad)
	}
	joined = strings.Join(nvBad.Reasons, "; ")
	for _, want := range []string{"self-assessment failed", "critical warning 0x05", "only 4% spare", "37 NVMe media errors", "104% of rated endurance", "running hot at 79"} {
		if !strings.Contains(joined, want) {
			t.Errorf("NVMe reasons lack %q: %s", want, joined)
		}
	}
	if strings.Contains(joined, "last self-test failed") {
		t.Error("a self-test in progress counted the previous result as current")
	}

	sas := sample(t, "smart-sas.json")
	if sas.Health != HealthWarning || sas.Model != "HGST HUH721010AL5200" || *sas.GrownDefects != 3 || *sas.UncorrectedErrs != 0 || sas.Protocol != "SCSI" {
		t.Errorf("SAS %+v", sas)
	}
	if len(sas.SelfTests) != 1 || !*sas.SelfTests[0].Passed {
		t.Errorf("SAS self-test %+v", sas.SelfTests)
	}

	sb := sample(t, "smart-standby.json")
	if !sb.Standby || sb.Health != HealthUnknown {
		t.Errorf("standby %+v", sb)
	}
}

func TestReadSMARTNoWakeAndSelfTest(t *testing.T) {
	f := &sysexec.Fake{}
	b, _ := os.ReadFile("testdata/smart-standby.json")
	f.OnResult("smartctl --json=c -a -n standby,0 /dev/sdb", sysexec.Result{Stdout: b})
	s, err := ReadSMARTOpts(context.Background(), f, "/dev/sdb", true)
	if err != nil || !s.Standby {
		t.Fatalf("%+v %v", s, err)
	}
	f.OnResult("smartctl --json=c -t long /dev/disk/by-id/ata-X_1", sysexec.Result{Stdout: []byte(`{}`)})
	if err := StartSelfTest(context.Background(), f, "/dev/disk/by-id/ata-X_1", TestLong); err != nil {
		t.Fatal(err)
	}
	f.OnResult("smartctl --json=c -t short /dev/sdb", sysexec.Result{ExitCode: 4, Stdout: []byte(`{"smartctl":{"messages":[{"string":"Can't start self-test without aborting current test"}]}}`)})
	if err := StartSelfTest(context.Background(), f, "/dev/sdb", TestShort); err == nil || !strings.Contains(err.Error(), "aborting current test") {
		t.Fatalf("want the drive's refusal, got %v", err)
	}
	if err := StartSelfTest(context.Background(), f, "/dev/sdb", "conveyance; reboot"); err == nil {
		t.Fatal("accepted an unknown test")
	}
	if err := StartSelfTest(context.Background(), f, "/dev/disk/by-id/../sda", TestShort); err == nil {
		t.Fatal("accepted a path with ..")
	}
}
