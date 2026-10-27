package ups

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Status is a UPS's state as NUT reports it.
type Status struct {
	UPS          string   `json:"ups"`
	Manufacturer string   `json:"manufacturer"`
	Model        string   `json:"model"`
	Serial       string   `json:"serial"`
	Driver       string   `json:"driver"`
	Raw          string   `json:"raw"`   // ups.status, e.g. "OL CHRG"
	Flags        []string `json:"flags"` // its words
	// What the flags mean.
	OnLine         bool `json:"onLine"`
	OnBattery      bool `json:"onBattery"`
	LowBattery     bool `json:"lowBattery"`
	ReplaceBattery bool `json:"replaceBattery"`
	Charging       bool `json:"charging"`
	Overload       bool `json:"overload"`
	ForcedShutdown bool `json:"forcedShutdown"`
	// Numbers, when the UPS reports them.
	ChargePct     *float64 `json:"chargePct"`
	RuntimeSecs   *float64 `json:"runtimeSecs"`
	LoadPct       *float64 `json:"loadPct"`
	InputVolts    *float64 `json:"inputVolts"`
	OutputVolts   *float64 `json:"outputVolts"`
	BatteryVolts  *float64 `json:"batteryVolts"`
	NominalWatts  *float64 `json:"nominalWatts"`
	LowChargePct  *float64 `json:"lowChargePct"`  // battery.charge.low (where shutdown starts)
	LowRuntimeSec *float64 `json:"lowRuntimeSec"` // battery.runtime.low
	// Vars is every variable, for the details view.
	Vars map[string]string `json:"vars"`
}

// ErrUnknownUPS: the server has no UPS by that name.
var ErrUnknownUPS = errors.New("the NUT server has no UPS by that name")

// ErrStale: the driver lost contact with the UPS (cable, USB, power).
var ErrStale = errors.New("the UPS isn't answering its driver (data stale)")

// unquote reads NUT's quoted values ("a \"b\" c").
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return s
	}
	var b strings.Builder
	esc := false
	for _, r := range s[1 : len(s)-1] {
		if esc {
			b.WriteRune(r)
			esc = false
			continue
		}
		if r == '\\' {
			esc = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func nutErr(line string) error {
	code := strings.TrimSpace(strings.TrimPrefix(line, "ERR"))
	switch strings.Fields(code + " x")[0] {
	case "UNKNOWN-UPS":
		return ErrUnknownUPS
	case "DATA-STALE", "DRIVER-NOT-CONNECTED":
		return ErrStale
	case "ACCESS-DENIED":
		return errors.New("the NUT server refused this server (access denied)")
	}
	return fmt.Errorf("the NUT server answered %s", code)
}

// Query reads every variable of one UPS from a NUT server (upsd) over its
// network protocol; no sign-in is needed for reading.
func Query(ctx context.Context, addr, ups string) (*Status, error) {
	if !nameRE.MatchString(ups) {
		return nil, fmt.Errorf("invalid UPS name %q", ups)
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "LIST VAR %s\n", ups); err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 4096), 1<<20)
	vars := map[string]string{}
	begun := false
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "ERR"):
			return nil, nutErr(line)
		case strings.HasPrefix(line, "BEGIN LIST VAR"):
			begun = true
		case strings.HasPrefix(line, "END LIST VAR"):
			_, _ = fmt.Fprint(conn, "LOGOUT\n")
			return parseVars(ups, vars), nil
		case begun && strings.HasPrefix(line, "VAR "):
			rest := strings.TrimPrefix(line, "VAR ")
			f := strings.SplitN(rest, " ", 3)
			if len(f) == 3 && f[0] == ups {
				vars[f[1]] = unquote(f[2])
			}
		}
		if len(vars) > 2000 {
			return nil, errors.New("the NUT server sent too many variables")
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("the NUT server closed the connection")
}

func num(vars map[string]string, key string) *float64 {
	v, ok := vars[key]
	if !ok {
		return nil
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return nil
	}
	return &f
}

func parseVars(ups string, vars map[string]string) *Status {
	s := &Status{UPS: ups, Vars: vars, Raw: vars["ups.status"], Flags: strings.Fields(vars["ups.status"])}
	s.Manufacturer = firstOf(vars, "ups.mfr", "device.mfr")
	s.Model = firstOf(vars, "ups.model", "device.model")
	s.Serial = firstOf(vars, "ups.serial", "device.serial")
	s.Driver = vars["driver.name"]
	for _, f := range s.Flags {
		switch f {
		case "OL":
			s.OnLine = true
		case "OB":
			s.OnBattery = true
		case "LB":
			s.LowBattery = true
		case "RB":
			s.ReplaceBattery = true
		case "CHRG":
			s.Charging = true
		case "OVER":
			s.Overload = true
		case "FSD":
			s.ForcedShutdown = true
		}
	}
	s.ChargePct = num(vars, "battery.charge")
	s.RuntimeSecs = num(vars, "battery.runtime")
	s.LoadPct = num(vars, "ups.load")
	s.InputVolts = num(vars, "input.voltage")
	s.OutputVolts = num(vars, "output.voltage")
	s.BatteryVolts = num(vars, "battery.voltage")
	s.NominalWatts = num(vars, "ups.realpower.nominal")
	s.LowChargePct = num(vars, "battery.charge.low")
	s.LowRuntimeSec = num(vars, "battery.runtime.low")
	if s.Flags == nil {
		s.Flags = []string{}
	}
	return s
}

func firstOf(vars map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := vars[k]; v != "" {
			return v
		}
	}
	return ""
}

// SortedVars returns the variable names in order (for display).
func (s *Status) SortedVars() []string {
	out := make([]string, 0, len(s.Vars))
	for k := range s.Vars {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
