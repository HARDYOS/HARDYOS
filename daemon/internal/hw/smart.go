package hw

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

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

// SMART is a disk's health report, normalized across ATA and NVMe.
type SMART struct {
	Device          string   `json:"device"`
	Model           string   `json:"model"`
	Serial          string   `json:"serial"`
	CapacityBytes   uint64   `json:"capacityBytes"`
	RotationRPM     int      `json:"rotationRpm"` // 0 for SSD/NVMe
	Passed          *bool    `json:"passed"`      // the drive's own overall self-assessment
	TemperatureC    *int     `json:"temperatureC"`
	PowerOnHours    *int64   `json:"powerOnHours"`
	Reallocated     *int64   `json:"reallocated"`     // ATA 5
	Pending         *int64   `json:"pending"`         // ATA 197
	Uncorrectable   *int64   `json:"uncorrectable"`   // ATA 198
	CRCErrors       *int64   `json:"crcErrors"`       // ATA 199 (usually cabling)
	PercentUsed     *int     `json:"percentUsed"`     // NVMe endurance used
	MediaErrors     *int64   `json:"mediaErrors"`     // NVMe
	CriticalWarning *int     `json:"criticalWarning"` // NVMe bitfield
	Health          Health   `json:"health"`
	Reasons         []string `json:"reasons"` // why the verdict isn't "good"
}

// devicePathRE limits SMART reads to whole disk device nodes.
var devicePathRE = regexp.MustCompile(`^/dev/(sd[a-z]{1,3}|nvme[0-9]{1,3}n[0-9]{1,3}|vd[a-z]{1,3}|disk/by-id/[A-Za-z0-9._:+@-]{1,200})$`)

// ValidDevicePath reports whether p names a whole disk we may query.
func ValidDevicePath(p string) bool { return devicePathRE.MatchString(p) }

// ReadSMART runs smartctl for one device. It needs root.
func ReadSMART(ctx context.Context, r sysexec.Runner, device string) (*SMART, error) {
	if !ValidDevicePath(device) {
		return nil, fmt.Errorf("invalid device path %q", device)
	}
	res, err := r.Run(ctx, nil, "smartctl", "--json=c", "-a", device)
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

type smartJSON struct {
	ModelName    string `json:"model_name"`
	SerialNumber string `json:"serial_number"`
	UserCapacity struct {
		Bytes uint64 `json:"bytes"`
	} `json:"user_capacity"`
	RotationRate *int `json:"rotation_rate"`
	SmartStatus  *struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature *struct {
		Current int `json:"current"`
	} `json:"temperature"`
	PowerOnTime *struct {
		Hours int64 `json:"hours"`
	} `json:"power_on_time"`
	ATA *struct {
		Table []struct {
			ID  int `json:"id"`
			Raw struct {
				Value int64 `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	NVMe *struct {
		CriticalWarning int   `json:"critical_warning"`
		PercentageUsed  int   `json:"percentage_used"`
		MediaErrors     int64 `json:"media_errors"`
	} `json:"nvme_smart_health_information_log"`
}

// ParseSMART converts smartctl JSON into a SMART report with a verdict.
func ParseSMART(data []byte) (*SMART, error) {
	var j smartJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, fmt.Errorf("parse smartctl: %w", err)
	}
	s := &SMART{Model: j.ModelName, Serial: j.SerialNumber, CapacityBytes: j.UserCapacity.Bytes, Reasons: []string{}}
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
	if j.ATA != nil {
		for _, a := range j.ATA.Table {
			v := a.Raw.Value
			switch a.ID {
			case 5:
				s.Reallocated = &v
			case 197:
				s.Pending = &v
			case 198:
				s.Uncorrectable = &v
			case 199:
				s.CRCErrors = &v
			}
		}
	}
	if j.NVMe != nil {
		cw, pu, me := j.NVMe.CriticalWarning, j.NVMe.PercentageUsed, j.NVMe.MediaErrors
		s.CriticalWarning, s.PercentUsed, s.MediaErrors = &cw, &pu, &me
	}
	s.Health, s.Reasons = verdict(s)
	return s, nil
}

func verdict(s *SMART) (Health, []string) {
	var failing, warning []string
	if s.Passed != nil && !*s.Passed {
		failing = append(failing, "the drive's self-assessment failed")
	}
	if s.CriticalWarning != nil && *s.CriticalWarning != 0 {
		failing = append(failing, fmt.Sprintf("NVMe critical warning 0x%02x", *s.CriticalWarning))
	}
	if s.MediaErrors != nil && *s.MediaErrors > 0 {
		warning = append(warning, fmt.Sprintf("%d NVMe media errors", *s.MediaErrors))
	}
	if s.Reallocated != nil && *s.Reallocated > 0 {
		warning = append(warning, fmt.Sprintf("%d reallocated sectors", *s.Reallocated))
	}
	if s.Pending != nil && *s.Pending > 0 {
		warning = append(warning, fmt.Sprintf("%d sectors pending reallocation", *s.Pending))
	}
	if s.Uncorrectable != nil && *s.Uncorrectable > 0 {
		warning = append(warning, fmt.Sprintf("%d uncorrectable sectors", *s.Uncorrectable))
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
