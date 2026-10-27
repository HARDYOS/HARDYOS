package boot

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/rootfile"
)

// KernelArgsPath holds the extra kernel arguments every menu entry gets
// (for example the IOMMU flags for PCI passthrough). It sits on the shared
// state dataset, so every boot environment, and every update, uses the same
// list. It lives in root's own directory there (rootfile.RootStateDir,
// 0755 root): only hardyd-priv writes it, and a copy root didn't write is
// ignored.
const KernelArgsPath = rootfile.RootStateDir + "/kernel-args.json"

// LegacyKernelArgsPath is where the first Phase 5 builds kept the file, in
// hardyd's directory. MigrateRootState moves a trusted copy into
// KernelArgsPath; until then LoadKernelArgs still reads it.
const LegacyKernelArgsPath = "/var/lib/hardyos/kernel-args.json"

// KernelArgs is the file's content.
type KernelArgs struct {
	Args []string `json:"args"`
}

// kernelArgRE allows "key" or "key=value" with nothing GRUB or the kernel
// would read as syntax: no spaces, quotes, $, ; or braces.
var kernelArgRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}(=[A-Za-z0-9_.,:+-]{1,128})?$`)

// baseArgs are the arguments HardyOS always sets itself; the extra list
// can't change them.
var baseArgs = map[string]bool{"root": true, "boot": true, "console": true, "quiet": true, "init": true, "ro": true, "rw": true, "rootfstype": true}

// MaxKernelArgs bounds the extra list.
const MaxKernelArgs = 32

// ArgKey is the part of an argument before "=".
func ArgKey(a string) string {
	k, _, _ := strings.Cut(a, "=")
	return k
}

// ValidateKernelArg checks one extra argument.
func ValidateKernelArg(a string) error {
	if !kernelArgRE.MatchString(a) {
		return fmt.Errorf("kernel argument %q isn't allowed (letters, digits and _.-, optionally =value)", a)
	}
	if baseArgs[ArgKey(a)] {
		return fmt.Errorf("kernel argument %q is set by HardyOS itself", ArgKey(a))
	}
	return nil
}

// MergeKernelArgs adds args to have: an argument with the same key replaces
// the old one in place, new keys go at the end.
func MergeKernelArgs(have, add []string) []string {
	out := append([]string(nil), have...)
	for _, a := range add {
		replaced := false
		for i, h := range out {
			if ArgKey(h) == ArgKey(a) {
				out[i], replaced = a, true
				break
			}
		}
		if !replaced {
			out = append(out, a)
		}
	}
	return out
}

// RemoveKernelArgs drops every argument whose key is in keys.
func RemoveKernelArgs(have []string, keys ...string) []string {
	drop := map[string]bool{}
	for _, k := range keys {
		drop[ArgKey(k)] = true
	}
	var out []string
	for _, h := range have {
		if !drop[ArgKey(h)] {
			out = append(out, h)
		}
	}
	return out
}

// LoadKernelArgs reads the extra arguments. A missing file is an empty list.
// A file root didn't write, or one with an argument that isn't allowed, is
// reported as an error (and Sync then boots without the extras, because
// the server must always be able to boot).
func LoadKernelArgs(env Env) ([]string, error) {
	b, err := rootfile.ReadFileInRootDir(env.path(KernelArgsPath))
	if errors.Is(err, os.ErrNotExist) {
		b, err = rootfile.ReadFile(env.path(LegacyKernelArgsPath))
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ka KernelArgs
	if err := json.Unmarshal(b, &ka); err != nil {
		return nil, fmt.Errorf("parse %s: %w", KernelArgsPath, err)
	}
	if len(ka.Args) > MaxKernelArgs {
		return nil, fmt.Errorf("%s lists more than %d arguments", KernelArgsPath, MaxKernelArgs)
	}
	for _, a := range ka.Args {
		if err := ValidateKernelArg(a); err != nil {
			return nil, err
		}
	}
	return ka.Args, nil
}

// SaveKernelArgs validates and writes the extra arguments (keys must be
// unique). It doesn't touch the boot disks: run Sync afterwards.
func SaveKernelArgs(env Env, args []string) error {
	if len(args) > MaxKernelArgs {
		return fmt.Errorf("at most %d extra kernel arguments", MaxKernelArgs)
	}
	seen := map[string]bool{}
	for _, a := range args {
		if err := ValidateKernelArg(a); err != nil {
			return err
		}
		if seen[ArgKey(a)] {
			return fmt.Errorf("kernel argument %q is listed twice", ArgKey(a))
		}
		seen[ArgKey(a)] = true
	}
	if args == nil {
		args = []string{}
	}
	b, err := json.MarshalIndent(KernelArgs{Args: args}, "", "  ")
	if err != nil {
		return err
	}
	if err := rootfile.WriteInRootDir(env.path(KernelArgsPath), append(b, '\n'), 0o644, 0o755); err != nil {
		return err
	}
	// The new file is the one in use; an old copy must not come back.
	_ = os.Remove(env.path(LegacyKernelArgsPath))
	return nil
}

// MigrateRootState moves root's state files that early builds wrote into
// hardyd's directory into root's own one (hardyd-priv runs it at start).
// Only a copy root wrote is moved; anything else is removed.
func MigrateRootState(env Env) error {
	if err := rootfile.EnsureRootDir(env.path(rootfile.RootStateDir), 0o755); err != nil {
		return err
	}
	b, err := rootfile.ReadFile(env.path(LegacyKernelArgsPath))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err == nil {
		if _, serr := os.Lstat(env.path(KernelArgsPath)); errors.Is(serr, os.ErrNotExist) {
			if err := rootfile.WriteInRootDir(env.path(KernelArgsPath), b, 0o644, 0o755); err != nil {
				return err
			}
		}
	}
	return os.Remove(env.path(LegacyKernelArgsPath))
}
