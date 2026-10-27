// Package ups watches an uninterruptible power supply through NUT
// (Network UPS Tools): a UPS on USB (usbhid-ups and friends) monitored by
// this server, optionally shared with other HardyOS servers over the
// network (this server is then their NUT server), or a UPS on another
// server watched over the network (netclient). NUT's own upsmon does the
// shutting down, so a clean shutdown never depends on hardyd being up;
// hardyd renders NUT's configuration (written by hardyd-priv), reads the
// UPS's state over NUT's network protocol, raises alerts and keeps history.
package ups

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Modes.
const (
	ModeOff       = "off"       // no UPS
	ModeLocal     = "local"     // a UPS connected to this server
	ModeNetClient = "netclient" // a UPS on another server (its NUT server)
)

// Drivers HardyOS lets an administrator choose. dummy-ups replays a file
// of values (for testing without a UPS).
var Drivers = map[string]bool{
	"usbhid-ups": true, "nutdrv_qx": true, "blazer_usb": true, "blazer_ser": true, "apcsmart": true,
	"bcmxcp_usb": true, "tripplite_usb": true, "riello_usb": true, "dummy-ups": true,
}

// serialDrivers talk to a serial port instead of USB.
var serialDrivers = map[string]bool{"blazer_ser": true, "apcsmart": true}

// Config is the UPS setup an administrator chooses (passwords apart).
type Config struct {
	Mode string `json:"mode"`

	// Local UPS.
	Name        string `json:"name"`        // NUT's name for it ("ups")
	Driver      string `json:"driver"`      // usbhid-ups
	Port        string `json:"port"`        // "auto" for USB, /dev/ttyS0 for serial, <file>.dev for dummy-ups
	VendorID    string `json:"vendorId"`    // pins the USB device when several are attached
	ProductID   string `json:"productId"`   //
	Serial      string `json:"serial"`      //
	Description string `json:"description"` // shown to NUT clients

	// Shut down when the battery is down to this charge (percent) or this
	// many seconds of runtime, whichever comes first; 0 leaves that one to
	// the UPS's own low-battery signal.
	ShutdownCharge  int `json:"shutdownCharge"`
	ShutdownRuntime int `json:"shutdownRuntime"`

	// ServeNetwork makes this server a NUT server: other servers (other
	// HardyOS servers in netclient mode) watch the UPS and shut down when
	// it runs low, before this one does. They sign in as ClientUser.
	ServeNetwork bool   `json:"serveNetwork"`
	ClientUser   string `json:"clientUser"`

	// Network client: the NUT server the UPS is on.
	RemoteHost string `json:"remoteHost"`
	RemotePort int    `json:"remotePort"`
	RemoteUPS  string `json:"remoteUps"`
	RemoteUser string `json:"remoteUser"`
}

// Secrets are a UPS setup's passwords.
type Secrets struct {
	ClientPassword string `json:"clientPassword,omitempty"` // for other servers (ServeNetwork)
	RemotePassword string `json:"remotePassword,omitempty"` // for the remote NUT server (netclient)
}

// DefaultPort is NUT's network port.
const DefaultPort = 3493

// MonitorUser is the NUT account upsmon uses on this server; its password
// is made by hardyd-priv on every apply and never leaves root.
const MonitorUser = "hardyos-monitor"

// ValidationError is a problem with a setup.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(f string, a ...any) error { return &ValidationError{Msg: fmt.Sprintf(f, a...)} }

var (
	nameRE     = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,30}$`)
	hexIDRE    = regexp.MustCompile(`^[0-9a-fA-F]{4}$`)
	serialRE   = regexp.MustCompile(`^[A-Za-z0-9._ -]{1,64}$`)
	descRE     = regexp.MustCompile(`^[A-Za-z0-9 ._,()/+-]{0,60}$`)
	ttyRE      = regexp.MustCompile(`^/dev/(ttyS|ttyUSB|ttyACM)[0-9]{1,3}$`)
	dummyRE    = regexp.MustCompile(`^[a-z0-9_-]{1,40}\.(dev|seq)$`)
	userRE     = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	passwordRE = regexp.MustCompile(`^[A-Za-z0-9!$%&()*+,./:;<=>?@\[\]^_{|}~-]{8,64}$`)
	hostRE     = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
)

// ValidPassword reports whether a NUT password is acceptable: 8-64
// printable characters without spaces, quotes, backslashes or "#" (NUT's
// configuration syntax).
func ValidPassword(p string) bool { return passwordRE.MatchString(p) }

// Normalize fills defaults and validates a setup with its passwords.
func (c Config) Normalize(s Secrets) (Config, error) {
	switch c.Mode {
	case "", ModeOff:
		return Config{Mode: ModeOff}, nil
	case ModeLocal:
		out := Config{Mode: ModeLocal, Name: c.Name, Driver: c.Driver, Port: c.Port, VendorID: strings.ToLower(c.VendorID),
			ProductID: strings.ToLower(c.ProductID), Serial: strings.TrimSpace(c.Serial), Description: strings.TrimSpace(c.Description),
			ShutdownCharge: c.ShutdownCharge, ShutdownRuntime: c.ShutdownRuntime, ServeNetwork: c.ServeNetwork, ClientUser: c.ClientUser}
		if out.Name == "" {
			out.Name = "ups"
		}
		if out.Driver == "" {
			out.Driver = "usbhid-ups"
		}
		if !nameRE.MatchString(out.Name) {
			return c, invalid("the UPS name must be lower-case letters, digits, - or _")
		}
		if !Drivers[out.Driver] {
			return c, invalid("driver %q isn't one HardyOS offers", c.Driver)
		}
		switch {
		case out.Driver == "dummy-ups":
			if !dummyRE.MatchString(out.Port) {
				return c, invalid("dummy-ups reads a file in /etc/nut named like ups.dev")
			}
		case serialDrivers[out.Driver]:
			if !ttyRE.MatchString(out.Port) {
				return c, invalid("a serial UPS needs a port like /dev/ttyS0 or /dev/ttyUSB0")
			}
		default:
			if out.Port == "" {
				out.Port = "auto"
			}
			if out.Port != "auto" {
				return c, invalid("a USB UPS uses port auto")
			}
		}
		if (out.VendorID != "" && !hexIDRE.MatchString(out.VendorID)) || (out.ProductID != "" && !hexIDRE.MatchString(out.ProductID)) {
			return c, invalid("USB vendor and product IDs are four hex digits")
		}
		if out.Serial != "" && !serialRE.MatchString(out.Serial) {
			return c, invalid("the serial number has characters NUT can't take")
		}
		if !descRE.MatchString(out.Description) {
			return c, invalid("the description may use letters, digits, spaces and . , ( ) / + -")
		}
		if out.ShutdownCharge < 0 || out.ShutdownCharge > 90 {
			return c, invalid("shut down at a charge between 0 and 90%%")
		}
		if out.ShutdownRuntime < 0 || out.ShutdownRuntime > 3600 {
			return c, invalid("shut down at a runtime between 0 and 3600 seconds")
		}
		if out.ServeNetwork {
			if out.ClientUser == "" {
				out.ClientUser = "hardyos-client"
			}
			if !userRE.MatchString(out.ClientUser) || out.ClientUser == MonitorUser {
				return c, invalid("the user name for other servers must be lower-case letters, digits, - or _")
			}
			if !ValidPassword(s.ClientPassword) {
				return c, invalid("the password for other servers must be 8-64 characters without spaces, quotes, \\ or #")
			}
		} else {
			out.ClientUser = ""
		}
		return out, nil
	case ModeNetClient:
		out := Config{Mode: ModeNetClient, RemoteHost: strings.ToLower(strings.TrimSpace(c.RemoteHost)), RemotePort: c.RemotePort,
			RemoteUPS: c.RemoteUPS, RemoteUser: c.RemoteUser}
		if out.RemotePort == 0 {
			out.RemotePort = DefaultPort
		}
		if out.RemoteUPS == "" {
			out.RemoteUPS = "ups"
		}
		if net.ParseIP(out.RemoteHost) == nil && !hostRE.MatchString(out.RemoteHost) {
			return c, invalid("the UPS server %q isn't a host name or address", c.RemoteHost)
		}
		if out.RemotePort < 1 || out.RemotePort > 65535 {
			return c, invalid("the port must be between 1 and 65535")
		}
		if !nameRE.MatchString(out.RemoteUPS) {
			return c, invalid("the UPS name must be lower-case letters, digits, - or _")
		}
		if !userRE.MatchString(out.RemoteUser) {
			return c, invalid("enter the user name the UPS server gave you")
		}
		if !ValidPassword(s.RemotePassword) {
			return c, invalid("the password must be 8-64 characters without spaces, quotes, \\ or #")
		}
		return out, nil
	}
	return c, invalid("mode must be off, local or netclient")
}

// Target is the host:port and UPS name hardyd reads the state from.
func (c Config) Target() (addr, name string) {
	switch c.Mode {
	case ModeLocal:
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(DefaultPort)), c.Name
	case ModeNetClient:
		return net.JoinHostPort(c.RemoteHost, strconv.Itoa(c.RemotePort)), c.RemoteUPS
	}
	return "", ""
}

// Files renders NUT's configuration for a setup: file name (in /etc/nut)
// to contents. monitorPassword is upsmon's own password on this server.
func Files(c Config, s Secrets, monitorPassword string) (map[string]string, error) {
	c, err := c.Normalize(s)
	if err != nil {
		return nil, err
	}
	if c.Mode == ModeLocal && !ValidPassword(monitorPassword) {
		return nil, invalid("invalid monitor password")
	}
	head := "# Written by HardyOS (Control Panel > UPS). Changes here are replaced.\n"
	files := map[string]string{}
	mode := map[string]string{ModeOff: "none", ModeLocal: "standalone", ModeNetClient: "netclient"}[c.Mode]
	if c.Mode == ModeLocal && c.ServeNetwork {
		mode = "netserver"
	}
	files["nut.conf"] = head + "MODE=" + mode + "\n"

	var ups, upsd, users strings.Builder
	ups.WriteString(head)
	upsd.WriteString(head)
	users.WriteString(head)
	if c.Mode == ModeLocal {
		ups.WriteString("maxretry = 3\n\n[" + c.Name + "]\n")
		fmt.Fprintf(&ups, "\tdriver = %s\n\tport = %s\n", c.Driver, c.Port)
		if c.Description != "" {
			fmt.Fprintf(&ups, "\tdesc = \"%s\"\n", c.Description)
		}
		if c.Driver != "dummy-ups" {
			if c.VendorID != "" {
				fmt.Fprintf(&ups, "\tvendorid = %s\n", c.VendorID)
			}
			if c.ProductID != "" {
				fmt.Fprintf(&ups, "\tproductid = %s\n", c.ProductID)
			}
			if c.Serial != "" {
				fmt.Fprintf(&ups, "\tserial = \"%s\"\n", c.Serial)
			}
			ups.WriteString("\tpollinterval = 5\n")
			// The driver raises "low battery" at HardyOS's thresholds
			// instead of the UPS's own; upsmon shuts down on it.
			if c.ShutdownCharge > 0 || c.ShutdownRuntime > 0 {
				ups.WriteString("\tignorelb\n")
				if c.ShutdownCharge > 0 {
					fmt.Fprintf(&ups, "\toverride.battery.charge.low = %d\n", c.ShutdownCharge)
				}
				if c.ShutdownRuntime > 0 {
					fmt.Fprintf(&ups, "\toverride.battery.runtime.low = %d\n", c.ShutdownRuntime)
				}
			}
		}
		upsd.WriteString("LISTEN 127.0.0.1 3493\nLISTEN ::1 3493\n")
		if c.ServeNetwork {
			upsd.WriteString("LISTEN 0.0.0.0 3493\nLISTEN :: 3493\n")
		}
		fmt.Fprintf(&users, "[%s]\n\tpassword = %s\n\tupsmon primary\n", MonitorUser, monitorPassword)
		if c.ServeNetwork {
			fmt.Fprintf(&users, "\n[%s]\n\tpassword = %s\n\tupsmon secondary\n", c.ClientUser, s.ClientPassword)
		}
	}
	files["ups.conf"] = ups.String()
	files["upsd.conf"] = upsd.String()
	files["upsd.users"] = users.String()

	var mon strings.Builder
	mon.WriteString(head + "RUN_AS_USER nut\n")
	switch c.Mode {
	case ModeLocal:
		fmt.Fprintf(&mon, "MONITOR %s@localhost 1 %s %s primary\n", c.Name, MonitorUser, monitorPassword)
	case ModeNetClient:
		host := c.RemoteHost
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		fmt.Fprintf(&mon, "MONITOR %s@%s:%d 1 %s %s secondary\n", c.RemoteUPS, host, c.RemotePort, c.RemoteUser, s.RemotePassword)
	}
	mon.WriteString(`MINSUPPLIES 1
SHUTDOWNCMD "/sbin/shutdown -h +0"
POLLFREQ 5
POLLFREQALERT 5
HOSTSYNC 15
DEADTIME 15
POWERDOWNFLAG "/etc/killpower"
FINALDELAY 5
`)
	files["upsmon.conf"] = mon.String()
	return files, nil
}

// FileNames are the files Files writes, in a fixed order.
func FileNames() []string {
	n := []string{"nut.conf", "ups.conf", "upsd.conf", "upsd.users", "upsmon.conf"}
	sort.Strings(n)
	return n
}
