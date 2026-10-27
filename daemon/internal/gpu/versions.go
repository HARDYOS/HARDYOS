package gpu

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// The admin agrees to NVIDIA's licence of one driver version. HardyOS
// installs exactly the packages that were downloaded and shown (pkg=version,
// from the download, apt --no-download) and an update that would bring
// another driver version stops and asks for the agreement again.

// instRE reads apt-get -s's "Inst nvidia-driver [old] (550.163.01-2 Debian:13/stable [amd64])".
var instRE = regexp.MustCompile(`^Inst (\S+) (?:\[[^\]]*\] )?\((\S+) `)

// parseSimulation maps each package apt would install to its version.
func parseSimulation(out string) map[string]string {
	v := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if m := instRE.FindStringSubmatch(strings.TrimSpace(line)); m != nil && debVersionRE.MatchString(m[2]) {
			name, _, _ := strings.Cut(m[1], ":") // pkg:arch
			v[name] = m[2]
		}
	}
	return v
}

// pinned turns packages into apt arguments "pkg=version" where the version
// is known.
func pinned(pkgs []string, versions map[string]string) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		if v := versions[p]; v != "" && debVersionRE.MatchString(v) {
			out = append(out, p+"="+v)
		} else {
			out = append(out, p)
		}
	}
	return out
}

// licenceVersion is the version of the first licence package listed.
func licenceVersion(versions map[string]string) (string, string) {
	for _, p := range licencePackages {
		if v := versions[p]; v != "" {
			return p, v
		}
	}
	return "", ""
}

// compareVersions asks dpkg (never a string sort: 550.90 < 550.163, and
// epochs and ~ count) whether "a op b" holds; op is lt, le, eq, ne, ge, gt.
func compareVersions(ctx context.Context, r sysexec.Runner, a, op, b string) (bool, error) {
	switch op {
	case "lt", "le", "eq", "ne", "ge", "gt":
	default:
		return false, fmt.Errorf("unknown version comparison %q", op)
	}
	if !debVersionRE.MatchString(a) || !debVersionRE.MatchString(b) {
		return false, fmt.Errorf("invalid package version %q or %q", a, b)
	}
	if a == b {
		return op == "eq" || op == "le" || op == "ge", nil
	}
	res, err := r.Run(ctx, nil, "dpkg", "--compare-versions", a, op, b)
	if err != nil {
		return false, err
	}
	switch res.ExitCode {
	case 0:
		return true, nil
	case 1:
		return false, nil
	}
	return false, fmt.Errorf("dpkg --compare-versions %s %s %s exited %d", a, op, b, res.ExitCode)
}

// debFile finds the downloaded package file of pkg at version (the
// epoch's ":" is "%3a" in the name).
func debFile(sysRoot, pkg, version string) string {
	matches, _ := filepath.Glob(filepath.Join(sysRoot, "var/cache/apt/archives", pkg+"_*.deb"))
	for _, m := range matches {
		if debVersion(filepath.Base(m)) == version {
			return m
		}
	}
	return ""
}

// newestDeb picks the newest downloaded version of pkg, by dpkg's rules.
func newestDeb(ctx context.Context, r sysexec.Runner, sysRoot, pkg string) (string, string, error) {
	matches, _ := filepath.Glob(filepath.Join(sysRoot, "var/cache/apt/archives", pkg+"_*.deb"))
	best, bestV := "", ""
	for _, m := range matches {
		v := debVersion(filepath.Base(m))
		if v == "" {
			continue
		}
		if bestV != "" {
			newer, err := compareVersions(ctx, r, v, "gt", bestV)
			if err != nil {
				return "", "", err
			}
			if !newer {
				continue
			}
		}
		best, bestV = m, v
	}
	return best, bestV, nil
}

// ConsentError means an update would install a different NVIDIA driver
// version than the one whose licence the admin agreed to.
type ConsentError struct {
	Agreed, Offered string
}

func (e *ConsentError) Error() string {
	return fmt.Sprintf("the new version would install NVIDIA driver %s, but the licence you agreed to is for %s. "+
		"In Devices & GPUs, get the NVIDIA driver again and agree to its licence (that installs %s here too), then install the update; "+
		"or choose to install the update without the NVIDIA driver this time", e.Offered, e.Agreed, e.Offered)
}

// ErrConsent matches a ConsentError.
var ErrConsent = errors.New("NVIDIA licence agreement needed")

func (e *ConsentError) Is(target error) bool { return target == ErrConsent }
