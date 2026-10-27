package ups

import (
	"context"
	"crypto/rand"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/hardyos/hardyos/daemon/internal/rootfile"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// ApplyArgs is hardyd-priv's ups.apply: a setup and its passwords.
type ApplyArgs struct {
	Config  Config  `json:"config"`
	Secrets Secrets `json:"secrets"`
}

// ApplyResult says what's running afterwards.
type ApplyResult struct {
	Mode     string   `json:"mode"`
	Services []string `json:"services"` // started
	Warnings []string `json:"warnings"`
}

// Root writes NUT's configuration and starts or stops its services. It
// runs in hardyd-priv.
type Root struct {
	Runner sysexec.Runner
	Root   fs.FS  // "/" (for detection)
	Dir    string // /etc/nut
	// Write and Chown are the file operations (tests replace them); the
	// defaults write atomically without following links and give the files
	// to root:nut, mode 0640 (upsd and upsmon read them as nut).
	Write func(path string, data []byte, mode os.FileMode) error
	Chown func(path string) error
}

func (r *Root) dir() string {
	if r.Dir != "" {
		return r.Dir
	}
	return "/etc/nut"
}

func defaultChown(path string) error {
	g, err := user.LookupGroup("nut")
	if err != nil {
		return nil // NUT isn't installed: nothing reads the files anyway
	}
	gid, _ := strconv.Atoi(g.Gid)
	return os.Chown(path, 0, gid)
}

func monitorPassword() string {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// Services by mode: what runs. nut-driver.target holds the drivers
// (nut-driver@<ups>, made from ups.conf by the enumerator), nut-server is
// upsd, nut-monitor is upsmon.
var (
	allUnits   = []string{"nut-monitor.service", "nut-server.service", "nut-driver.target", "nut-driver-enumerator.path", "nut-driver-enumerator.service"}
	localUnits = []string{"nut-driver-enumerator.path", "nut-driver.target", "nut-server.service", "nut-monitor.service"}
)

// Apply writes the configuration for a setup and (re)starts what it needs.
func (r *Root) Apply(ctx context.Context, a ApplyArgs) (*ApplyResult, error) {
	cfg, err := a.Config.Normalize(a.Secrets)
	if err != nil {
		return nil, err
	}
	files, err := Files(cfg, a.Secrets, monitorPassword())
	if err != nil {
		return nil, err
	}
	write, chown := r.Write, r.Chown
	if write == nil {
		write = rootfile.WriteAtomic
	}
	if chown == nil {
		chown = defaultChown
	}
	for _, name := range FileNames() {
		p := filepath.Join(r.dir(), name)
		if err := write(p, []byte(files[name]), 0o640); err != nil {
			return nil, fmt.Errorf("writing %s: %w", p, err)
		}
		if err := chown(p); err != nil {
			return nil, fmt.Errorf("owner of %s: %w", p, err)
		}
	}
	res := &ApplyResult{Mode: cfg.Mode, Services: []string{}, Warnings: []string{}}
	systemctl := func(args ...string) error {
		out, err := sysexec.Output(ctx, r.Runner, "systemctl", args...)
		if err != nil {
			return fmt.Errorf("systemctl %v: %w %s", args, err, out)
		}
		return nil
	}
	switch cfg.Mode {
	case ModeOff:
		_ = systemctl(append([]string{"disable", "--now"}, allUnits...)...)
	case ModeNetClient:
		_ = systemctl(append([]string{"disable", "--now"}, allUnits[1:]...)...)
		if err := systemctl("enable", "nut-monitor.service"); err != nil {
			return nil, err
		}
		if err := systemctl("restart", "nut-monitor.service"); err != nil {
			return nil, err
		}
		res.Services = []string{"nut-monitor.service"}
	case ModeLocal:
		// Make nut-driver@<name> from ups.conf, then start everything.
		if out, err := sysexec.Output(ctx, r.Runner, "upsdrvsvcctl", "resync"); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("upsdrvsvcctl resync: %v %s", err, out))
		}
		if err := systemctl(append([]string{"enable"}, localUnits...)...); err != nil {
			return nil, err
		}
		if err := systemctl("restart", "nut-driver.target"); err != nil {
			// The UPS may be unplugged; upsd and upsmon still start and
			// report it.
			res.Warnings = append(res.Warnings, "the UPS driver didn't start: is the UPS plugged in? "+err.Error())
		}
		if err := systemctl("restart", "nut-server.service", "nut-monitor.service"); err != nil {
			return nil, err
		}
		res.Services = []string{"nut-driver@" + cfg.Name + ".service", "nut-server.service", "nut-monitor.service"}
	}
	return res, nil
}

// Detect finds UPSes on USB.
func (r *Root) Detect(ctx context.Context) []Device {
	root := r.Root
	if root == nil {
		root = os.DirFS("/")
	}
	return Detect(ctx, r.Runner, root)
}
