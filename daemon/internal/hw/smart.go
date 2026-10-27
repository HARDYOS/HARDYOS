package hw

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Health is an overall verdict for a disk.
type Health string

const (
	HealthGood    Health = "good"
	HealthWarning Health = "warning"
	HealthFailing Health = "failing"
	HealthUnknown Health = "unknown"
)

// SMARTAttribute is one row of an ATA drive's attribute table.
type SMARTAttribute struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Value  int    `json:"value"`  // normalized, higher is better
	Worst  int    `json:"worst"`  // lowest normalized value seen
	Thresh int    `json:"thresh"` // the drive fails the attribute at or below this
	Raw    int64  `json:"raw"`
	RawStr string `json:"rawString"`
	// WhenFailed: "" (never), "past" or "now".
	WhenFailed string `json:"whenFailed"`
}

// SelfTest is one entry of a drive's self-test log, newest first.
type SelfTest struct {
	Type   string `json:"type"`   // "Short offline", "Extended offline", "Short", ...
	Status string `json:"status"` // the drive's words
	Passed *bool  `json:"passed"` // nil while running or unknown
	Hours  *int64 `json:"hours"`  // power-on hours when it ran
}

// SelfTestState is what the drive is doing now.
type SelfTestState struct {
	Running      bool   `json:"running"`
	RemainingPct *int   `json:"remainingPct"` // of the running test
	Status       string `json:"status"`       // the drive's words about the current or last test
	// Minutes the drive says each test takes (0 when unknown).
	ShortMinutes int `json:"shortMinutes"`
	LongMinutes  int `json:"longMinutes"`
}

// SMART is a disk's health report, normalized across ATA (SATA), SCSI
// (SAS) and NVMe.
type SMART struct {
	Device          string   `json:"device"`
	Protocol        string   `json:"protocol"` // ATA, SCSI, NVMe or ""
	Model           string   `json:"model"`
	Serial          string   `json:"serial"`
	Firmware        string   `json:"firmware"`
	CapacityBytes   uint64   `json:"capacityBytes"`
	RotationRPM     int      `json:"rotationRpm"` // 0 for SSD/NVMe
	Standby         bool     `json:"standby"`     // asleep; not woken to read it (nothing else filled in)
	Passed          *bool    `json:"passed"`      // the drive's own overall self-assessment
	TemperatureC    *int     `json:"temperatureC"`
	PowerOnHours    *int64   `json:"powerOnHours"`
	PowerCycles     *int64   `json:"powerCycles"`
	Reallocated     *int64   `json:"reallocated"`       // ATA 5
	ReportedUncorr  *int64   `json:"reportedUncorrect"` // ATA 187
	Pending         *int64   `json:"pending"`           // ATA 197
	Uncorrectable   *int64   `json:"uncorrectable"`     // ATA 198
	CRCErrors       *int64   `json:"crcErrors"`         // ATA 199 (usually cabling)
	GrownDefects    *int64   `json:"grownDefects"`      // SCSI grown defect list
	UncorrectedErrs *int64   `json:"uncorrectedErrors"` // SCSI read+write+verify total uncorrected
	PercentUsed     *int     `json:"percentUsed"`       // NVMe endurance used
	AvailableSpare  *int     `json:"availableSpare"`    // NVMe, percent
	SpareThreshold  *int     `json:"spareThreshold"`    // NVMe, percent
	MediaErrors     *int64   `json:"mediaErrors"`       // NVMe
	UnsafeShutdowns *int64   `json:"unsafeShutdowns"`   // NVMe
	CriticalWarning *int     `json:"criticalWarning"`   // NVMe bitfield
	Health          Health   `json:"health"`
	Reasons         []string `json:"reasons"` // why the verdict isn't "good"

	Attributes []SMARTAttribute `json:"attributes"`
	SelfTest   SelfTestState    `json:"selfTest"`
	SelfTests  []SelfTest       `json:"selfTests"`
}

// devicePathRE limits SMART reads to whole disk device nodes.
var devicePathRE = regexp.MustCompile(`^/dev/(sd[a-z]{1,3}|nvme[0-9]{1,3}n[0-9]{1,3}|vd[a-z]{1,3}|disk/by-id/[A-Za-z0-9._:+@-]{1,200})$`)

// ValidDevicePath reports whether p names a whole disk we may query.
func ValidDevicePath(p string) bool { return devicePathRE.MatchString(p) && !strings.Contains(p, "..") }

// ReadSMART runs smartctl for one device. It needs root.
func ReadSMART(ctx context.Context, r sysexec.Runner, device string) (*SMART, error) {
	return ReadSMARTOpts(ctx, r, device, false)
}

// ReadSMARTOpts is ReadSMART; with noWake a drive in standby isn't spun up
// (the result then only says Standby).
func ReadSMARTOpts(ctx context.Context, r sysexec.Runner, device string, noWake bool) (*SMART, error) {
	if !ValidDevicePath(device) {
		return nil, fmt.Errorf("invalid device path %q", device)
	}
	args := []string{"--json=c", "-a"}
	if noWake {
		args = append(args, "-n", "standby,0")
	}
	res, err := r.Run(ctx, nil, "smartctl", append(args, device)...)
	if err != nil {
		return nil, err
	}
	// smartctl's exit status is a bitmask: bits 0-1 mean it couldn't read the
	// device at all; higher bits describe disk problems and still return data.
	if res.ExitCode&0b11 != 0 {
		return nil, &sysexec.CommandError{Name: "smartctl", Args: []string{device}, Result: res}
	}
	s, err := ParseSMART(res.Stdout)
	if err != nil {
		return nil, err
	}
	s.Device = device
	if res.ExitCode&(1<<3) != 0 && s.Health != HealthFailing {
		s.Health = HealthFailing
		s.Reasons = append(s.Reasons, "smartctl reports the disk is failing")
	}
	return s, nil
}

// Self-test kinds.
const (
	TestShort = "short"
	TestLong  = "long"
	TestAbort = "abort"
)

// StartSelfTest starts (or aborts) a drive self-test; the drive runs it in
// the background. It needs root.
func StartSelfTest(ctx context.Context, r sysexec.Runner, device, kind string) error {
	if !ValidDevicePath(device) {
		return fmt.Errorf("invalid device path %q", device)
	}
	var arg []string
	switch kind {
	case TestShort:
		arg = []string{"-t", "short"}
	case TestLong:
		arg = []string{"-t", "long"}
	case TestAbort:
		arg = []string{"-X"}
	default:
		return fmt.Errorf("invalid self-test %q", kind)
	}
	res, err := r.Run(ctx, nil, "smartctl", append(append([]string{"--json=c"}, arg...), device)...)
	if err != nil {
		return err
	}
	if res.ExitCode&0b111 != 0 {
		var j struct {
			Smartctl struct {
				Messages []struct {
					String string `json:"string"`
				} `json:"messages"`
			} `json:"smartctl"`
		}
		msg := "the drive refused the self-test"
		if json.Unmarshal(res.Stdout, &j) == nil && len(j.Smartctl.Messages) > 0 {
			msg += ": " + j.Smartctl.Messages[0].String
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

type smartStatus struct {
	Value           int    `json:"value"`
	String          string `json:"string"`
	Passed          *bool  `json:"passed"`
	RemainingPct    *int   `json:"remaining_percent"`
	CompletionPctNV *int   `json:"-"`
}

type smartJSON struct {
	Smartctl struct {
		Messages []struct {
			String string `json:"string"`
		} `json:"messages"`
	} `json:"smartctl"`
	Device struct {
		Protocol string `json:"protocol"`
	} `json:"device"`
	ModelName       string `json:"model_name"`
	ScsiModelName   string `json:"scsi_model_name"`
	SerialNumber    string `json:"serial_number"`
	FirmwareVersion string `json:"firmware_version"`
	UserCapacity    struct {
		Bytes uint64 `json:"bytes"`
	} `json:"user_capacity"`
	NVMeCapacity *uint64 `json:"nvme_total_capacity"`
	RotationRate *int    `json:"rotation_rate"`
	SmartStatus  *struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature *struct {
		Current int `json:"current"`
	} `json:"temperature"`
	PowerOnTime *struct {
		Hours int64 `json:"hours"`
	} `json:"power_on_time"`
	PowerCycleCount *int64 `json:"power_cycle_count"`
	ATA             *struct {
		Table []struct {
			ID         int    `json:"id"`
			Name       string `json:"name"`
			Value      int    `json:"value"`
			Worst      int    `json:"worst"`
			Thresh     int    `json:"thresh"`
			WhenFailed string `json:"when_failed"`
			Raw        struct {
				Value  int64  `json:"value"`
				String string `json:"string"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	ATAData *struct {
		SelfTest *struct {
			Status         smartStatus `json:"status"`
			PollingMinutes struct {
				Short    int `json:"short"`
				Extended int `json:"extended"`
			} `json:"polling_minutes"`
		} `json:"self_test"`
	} `json:"ata_smart_data"`
	ATALog *struct {
		Standard struct {
			Table []struct {
				Type struct {
					String string `json:"string"`
				} `json:"type"`
				Status        smartStatus `json:"status"`
				LifetimeHours *int64      `json:"lifetime_hours"`
			} `json:"table"`
		} `json:"standard"`
	} `json:"ata_smart_self_test_log"`
	NVMe *struct {
		CriticalWarning     int    `json:"critical_warning"`
		PercentageUsed      int    `json:"percentage_used"`
		AvailableSpare      *int   `json:"available_spare"`
		AvailableSpareThres *int   `json:"available_spare_threshold"`
		MediaErrors         int64  `json:"media_errors"`
		UnsafeShutdowns     *int64 `json:"unsafe_shutdowns"`
		PowerCycles         *int64 `json:"power_cycles"`
	} `json:"nvme_smart_health_information_log"`
	NVMeLog *struct {
		Current struct {
			Value  int    `json:"value"`
			String string `json:"string"`
		} `json:"current_self_test_operation"`
		CompletionPct *int `json:"current_self_test_completion_percent"`
		Table         []struct {
			Code struct {
				String string `json:"string"`
			} `json:"self_test_code"`
			Result struct {
				Value  int    `json:"value"`
				String string `json:"string"`
			} `json:"self_test_result"`
			PowerOnHours *int64 `json:"power_on_hours"`
		} `json:"table"`
	} `json:"nvme_self_test_log"`
	SCSIGrownDefects *int64 `json:"scsi_grown_defect_list"`
	SCSIErrors       *map[string]struct {
		TotalUncorrected int64 `json:"total_uncorrected_errors"`
	} `json:"scsi_error_counter_log"`
	SCSISelfTest0 *struct {
		Code struct {
			String string `json:"string"`
		} `json:"code"`
		Result struct {
			Value  int    `json:"value"`
			String string `json:"string"`
		} `json:"result"`
		PowerOnTime *struct {
			Hours int64 `json:"hours"`
		} `json:"power_on_time"`
	} `json:"scsi_self_test_0"`
}

// ParseSMART converts smartctl JSON into a SMART report with a verdict.
func ParseSMART(data []byte) (*SMART, error) {
	var j smartJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, fmt.Errorf("parse smartctl: %w", err)
	}
	s := &SMART{Model: j.ModelName, Serial: j.SerialNumber, Firmware: j.FirmwareVersion, CapacityBytes: j.UserCapacity.Bytes,
		Protocol: j.Device.Protocol, Reasons: []string{}, Attributes: []SMARTAttribute{}, SelfTests: []SelfTest{}}
	if s.Model == "" {
		s.Model = j.ScsiModelName
	}
	if s.CapacityBytes == 0 && j.NVMeCapacity != nil {
		s.CapacityBytes = *j.NVMeCapacity
	}
	for _, m := range j.Smartctl.Messages {
		up := strings.ToUpper(m.String)
		if strings.Contains(up, "STANDBY MODE") || strings.Contains(up, "SLEEP MODE") {
			s.Standby = true
		}
	}
	if s.Standby && j.SmartStatus == nil && j.ATA == nil && j.NVMe == nil {
		s.Health, s.Reasons = HealthUnknown, []string{"the disk is asleep (not woken up to read it)"}
		return s, nil
	}
	if j.RotationRate != nil {
		s.RotationRPM = *j.RotationRate
	}
	if j.SmartStatus != nil {
		p := j.SmartStatus.Passed
		s.Passed = &p
	}
	if j.Temperature != nil {
		t := j.Temperature.Current
		s.TemperatureC = &t
	}
	if j.PowerOnTime != nil {
		h := j.PowerOnTime.Hours
		s.PowerOnHours = &h
	}
	s.PowerCycles = j.PowerCycleCount
	if j.ATA != nil {
		for _, a := range j.ATA.Table {
			v := a.Raw.Value
			s.Attributes = append(s.Attributes, SMARTAttribute{ID: a.ID, Name: a.Name, Value: a.Value, Worst: a.Worst, Thresh: a.Thresh,
				Raw: v, RawStr: a.Raw.String, WhenFailed: a.WhenFailed})
			switch a.ID {
			case 5:
				s.Reallocated = &v
			case 187:
				s.ReportedUncorr = &v
			case 197:
				s.Pending = &v
			case 198:
				s.Uncorrectable = &v
			case 199:
				s.CRCErrors = &v
			}
		}
	}
	if j.ATAData != nil && j.ATAData.SelfTest != nil {
		st := j.ATAData.SelfTest
		s.SelfTest.Status = st.Status.String
		s.SelfTest.ShortMinutes, s.SelfTest.LongMinutes = st.PollingMinutes.Short, st.PollingMinutes.Extended
		// Status values 0xF0-0xFF mean a test is running.
		if st.Status.Value>>4 == 0xF {
			s.SelfTest.Running = true
			s.SelfTest.RemainingPct = st.Status.RemainingPct
		}
	}
	if j.ATALog != nil {
		for _, e := range j.ATALog.Standard.Table {
			s.SelfTests = append(s.SelfTests, SelfTest{Type: e.Type.String, Status: e.Status.String, Passed: e.Status.Passed, Hours: e.LifetimeHours})
		}
	}
	if j.NVMe != nil {
		cw, pu, me := j.NVMe.CriticalWarning, j.NVMe.PercentageUsed, j.NVMe.MediaErrors
		s.CriticalWarning, s.PercentUsed, s.MediaErrors = &cw, &pu, &me
		s.AvailableSpare, s.SpareThreshold, s.UnsafeShutdowns = j.NVMe.AvailableSpare, j.NVMe.AvailableSpareThres, j.NVMe.UnsafeShutdowns
		if s.PowerCycles == nil {
			s.PowerCycles = j.NVMe.PowerCycles
		}
		if s.Protocol == "" {
			s.Protocol = "NVMe"
		}
	}
	if j.NVMeLog != nil {
		if j.NVMeLog.Current.Value != 0 {
			s.SelfTest.Running = true
			if j.NVMeLog.CompletionPct != nil {
				r := 100 - *j.NVMeLog.CompletionPct
				s.SelfTest.RemainingPct = &r
			}
		}
		s.SelfTest.Status = j.NVMeLog.Current.String
		for _, e := range j.NVMeLog.Table {
			// Result 0 is success; 15 is an unused entry.
			if e.Result.Value == 15 {
				continue
			}
			p := e.Result.Value == 0
			s.SelfTests = append(s.SelfTests, SelfTest{Type: e.Code.String, Status: e.Result.String, Passed: &p, Hours: e.PowerOnHours})
		}
	}
	s.GrownDefects = j.SCSIGrownDefects
	if j.SCSIErrors != nil {
		var total int64
		for _, c := range *j.SCSIErrors {
			total += c.TotalUncorrected
		}
		s.UncorrectedErrs = &total
	}
	if j.SCSISelfTest0 != nil {
		e := j.SCSISelfTest0
		p := e.Result.Value == 0
		var h *int64
		if e.PowerOnTime != nil {
			h = &e.PowerOnTime.Hours
		}
		s.SelfTests = append(s.SelfTests, SelfTest{Type: e.Code.String, Status: e.Result.String, Passed: &p, Hours: h})
	}
	s.Health, s.Reasons = verdict(s)
	return s, nil
}

func verdict(s *SMART) (Health, []string) {
	var failing, warning []string
	if s.Passed != nil && !*s.Passed {
		failing = append(failing, "the drive's self-assessment failed")
	}
	for _, a := range s.Attributes {
		if a.WhenFailed == "now" {
			failing = append(failing, fmt.Sprintf("attribute %d %s is below its failure threshold", a.ID, a.Name))
		}
	}
	if s.CriticalWarning != nil && *s.CriticalWarning != 0 {
		failing = append(failing, fmt.Sprintf("NVMe critical warning 0x%02x", *s.CriticalWarning))
	}
	if s.AvailableSpare != nil && s.SpareThreshold != nil && *s.SpareThreshold > 0 && *s.AvailableSpare < *s.SpareThreshold {
		failing = append(failing, fmt.Sprintf("only %d%% spare blocks left (threshold %d%%)", *s.AvailableSpare, *s.SpareThreshold))
	}
	if len(s.SelfTests) > 0 && s.SelfTests[0].Passed != nil && !*s.SelfTests[0].Passed && !s.SelfTest.Running &&
		!strings.Contains(strings.ToLower(s.SelfTests[0].Status), "aborted") && !strings.Contains(strings.ToLower(s.SelfTests[0].Status), "interrupted") {
		failing = append(failing, "the last self-test failed: "+s.SelfTests[0].Status)
	}
	if s.MediaErrors != nil && *s.MediaErrors > 0 {
		warning = append(warning, fmt.Sprintf("%d NVMe media errors", *s.MediaErrors))
	}
	if s.Reallocated != nil && *s.Reallocated > 0 {
		warning = append(warning, fmt.Sprintf("%d reallocated sectors", *s.Reallocated))
	}
	if s.ReportedUncorr != nil && *s.ReportedUncorr > 0 {
		warning = append(warning, fmt.Sprintf("%d reported uncorrectable errors", *s.ReportedUncorr))
	}
	if s.Pending != nil && *s.Pending > 0 {
		warning = append(warning, fmt.Sprintf("%d sectors pending reallocation", *s.Pending))
	}
	if s.Uncorrectable != nil && *s.Uncorrectable > 0 {
		warning = append(warning, fmt.Sprintf("%d uncorrectable sectors", *s.Uncorrectable))
	}
	if s.GrownDefects != nil && *s.GrownDefects > 0 {
		warning = append(warning, fmt.Sprintf("%d grown defects", *s.GrownDefects))
	}
	if s.UncorrectedErrs != nil && *s.UncorrectedErrs > 0 {
		warning = append(warning, fmt.Sprintf("%d uncorrected read/write errors", *s.UncorrectedErrs))
	}
	if s.PercentUsed != nil && *s.PercentUsed >= 90 {
		warning = append(warning, fmt.Sprintf("%d%% of rated endurance used", *s.PercentUsed))
	}
	if s.TemperatureC != nil {
		limit := 55 // HDDs
		if s.RotationRPM == 0 {
			limit = 70 // SSD / NVMe
		}
		if *s.TemperatureC >= limit {
			warning = append(warning, fmt.Sprintf("running hot at %d °C", *s.TemperatureC))
		}
	}
	switch {
	case len(failing) > 0:
		return HealthFailing, append(failing, warning...)
	case len(warning) > 0:
		return HealthWarning, warning
	case s.Passed == nil && s.CriticalWarning == nil:
		return HealthUnknown, []string{"the drive doesn't report SMART health"}
	default:
		return HealthGood, []string{}
	}
}
