package apps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

// Who an app is and what it may reach: its source and grants, its own user
// ID and the shared folders it was given. See docs/apps.md.

// unsharedDir holds an empty stand-in folder for every share the app
// wasn't given, so ${HARDY_SHARE_<NAME>} always names a folder.
const unsharedDir = ".unshared"

// DefaultCatalogDir is where HardyOS ships its catalog packages (under
// Root; packaging/nfpm.yaml installs dist/apps/*.hardyapp there).
const DefaultCatalogDir = "/usr/share/hardyos/apps"

func (m *Manager) catalogDir() string {
	if m.CatalogDir != "" {
		return m.CatalogDir
	}
	return m.sys(DefaultCatalogDir)
}

// inCatalog reports whether raw is, byte for byte, one of the packages
// shipped in the catalog folder (root-owned, read-only to hardyd).
func (m *Manager) inCatalog(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	want := sha256.Sum256(raw)
	dir := m.catalogDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".hardyapp") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() || fi.Size() != int64(len(raw)) {
			continue
		}
		b, err := os.ReadFile(p)
		if err == nil && sha256.Sum256(b) == want {
			return true
		}
	}
	return false
}

// packageSum is a package's SHA-256 (hex).
func packageSum(raw []byte) string {
	s := sha256.Sum256(raw)
	return hex.EncodeToString(s[:])
}

// deriveSource decides the app's source from the package bytes, never from
// what hardyd says: a package is catalog only if it is one HardyOS ships,
// or the very package root found in the catalog when it installed it
// (prev.CatalogSHA256, so a catalog app stays one after an OS update ships
// a newer version). Anything else is untrusted: the source hardyd asked
// for (upload, imported, custom) is kept as a label, and "catalog" or
// nothing becomes upload (or the label the app already had). It returns
// the source, its name and, for catalog packages, the package's hash.
func (m *Manager) deriveSource(raw []byte, asked Source, askedName string, prev *appState) (Source, string, string, error) {
	name := strings.TrimSpace(askedName)
	switch asked {
	case "", SourceCatalog, SourceUpload, SourceCustom:
	case SourceImported:
		if name == "" {
			return "", "", "", Problems{"an app from an imported catalog needs the catalog's name"}
		}
	default:
		return "", "", "", Problems{fmt.Sprintf("source %q: use catalog, upload, imported or custom", asked)}
	}
	if len(name) > 80 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", "", "", Problems{"the source name must be at most 80 characters on one line"}
	}
	if len(raw) > 0 {
		sum := packageSum(raw)
		if m.inCatalog(raw) || (prev != nil && prev.CatalogSHA256 != "" && prev.CatalogSHA256 == sum) {
			return SourceCatalog, "", sum, nil
		}
	}
	src := asked
	if src == "" || src == SourceCatalog {
		src = SourceUpload
		if prev != nil && (prev.Source == SourceUpload || prev.Source == SourceImported || prev.Source == SourceCustom) {
			src = prev.Source
			if name == "" {
				name = prev.SourceName
			}
		}
	}
	if src == SourceImported && name == "" {
		return "", "", "", Problems{"an app from an imported catalog needs the catalog's name"}
	}
	return src, name, "", nil
}

// neededGrants lists the grants an untrusted app needs for what its
// manifest declares.
func neededGrants(mf Manifest) []string {
	var out []string
	if mf.Permissions.HostNetwork {
		out = append(out, GrantHostNetwork)
	}
	if mf.Permissions.GPU {
		out = append(out, GrantGPU)
	}
	for _, d := range mf.Permissions.Devices {
		out = append(out, GrantDevice+d)
	}
	for _, c := range mf.Permissions.Capabilities {
		if !basicCapabilities[c] {
			out = append(out, GrantCapability+c)
		}
	}
	return out
}

// grantWords says what a grant allows, for messages.
func grantWords(mf Manifest, g string) string {
	switch {
	case g == GrantCapability+"NET_ADMIN" && mf.Permissions.HostNetwork:
		return "the capability NET_ADMIN, which together with the host network lets it change the server's own network settings (addresses, routes, firewall)"
	case g == GrantHostNetwork:
		return "the server's own network (host network)"
	case g == GrantGPU:
		return "the graphics card (GPU)"
	case strings.HasPrefix(g, GrantDevice):
		return "the device " + strings.TrimPrefix(g, GrantDevice)
	default:
		return "the capability " + strings.TrimPrefix(g, GrantCapability)
	}
}

func validGrant(g string) bool {
	switch {
	case g == GrantHostNetwork || g == GrantGPU:
		return true
	case strings.HasPrefix(g, GrantDevice):
		_, ok := deviceAllowed(strings.TrimPrefix(g, GrantDevice))
		return ok
	case strings.HasPrefix(g, GrantCapability):
		_, ok := AllowedCapabilities[strings.TrimPrefix(g, GrantCapability)]
		return ok
	}
	return false
}

// checkGrants refuses an untrusted app whose manifest declares permissions
// an admin didn't grant, and returns the grants it uses (none for catalog
// apps: they don't need any).
func checkGrants(mf Manifest, src Source, asked []string) ([]string, error) {
	var p Problems
	have := map[string]bool{}
	for _, g := range asked {
		if !validGrant(g) {
			p.addf("grant %q: use hostNetwork, gpu, device:<path> or cap:<NAME> for something apps may have", g)
			continue
		}
		have[g] = true
	}
	if err := p.err(); err != nil {
		return nil, err
	}
	out := []string{}
	if src.Trusted() {
		return out, nil
	}
	for _, g := range neededGrants(mf) {
		if !have[g] {
			p.addf("%s wants %s; an administrator must allow that for this app", mf.Name, grantWords(mf, g))
			continue
		}
		out = append(out, g)
	}
	sort.Strings(out)
	return out, p.err()
}

// allocUID returns the app's user ID: the one it has, or the lowest one no
// other app on the pool has (removed apps whose data is kept keep theirs).
func (m *Manager) allocUID(ctx context.Context, c *EngineConfig, prev *installedApp) (int, error) {
	if prev != nil && prev.state.UID >= FirstAppUID && prev.state.UID <= LastAppUID {
		return prev.state.UID, nil
	}
	apps, err := m.installed(ctx, c)
	if err != nil {
		return 0, err
	}
	used := map[int]bool{}
	for _, ia := range apps {
		used[ia.state.UID] = true
	}
	for uid := FirstAppUID; uid <= LastAppUID; uid++ {
		if !used[uid] {
			return uid, nil
		}
	}
	return 0, fmt.Errorf("every app user ID (%d-%d) is taken; delete the data of apps you removed", FirstAppUID, LastAppUID)
}

// chooseShares settles the shared folder for each of the manifest's
// shares (as asked, else as before), resolves each to its host folder and
// returns the choices, the folders for the policy and the variables.
func (m *Manager) chooseShares(ctx context.Context, mf Manifest, asked, prev map[string]ShareChoice, dataDir string,
	res *PrepareResult) (map[string]ShareChoice, []shareBind, map[string]string, error) {
	var p Problems
	for name := range asked {
		found := false
		for _, s := range mf.Shares {
			found = found || s.Name == name
		}
		if !found {
			p.addf("%s has no shared folder called %s", mf.Name, name)
		}
	}
	choices := map[string]ShareChoice{}
	var binds []shareBind
	env := map[string]string{}
	for _, s := range mf.Shares {
		ch, ok := asked[s.Name]
		if !ok {
			ch = prev[s.Name]
		}
		ch.Share = strings.TrimSpace(ch.Share)
		if strings.Trim(strings.TrimSpace(ch.Path), "/") != "" {
			// A subfolder could be swapped for a link by anything that can
			// write in the share (another app), and Docker mounts by path
			// whenever it restarts a container itself.
			p.addf("%s: apps get a whole shared folder, not a subfolder (%q); choose the shared folder itself", s.Label, ch.Path)
			continue
		}
		ch.Path = ""
		unshared := filepath.Join(dataDir, unsharedDir, s.Name)
		if ch.Share == "" {
			if s.Required {
				p.addf("%s: choose a shared folder", s.Label)
			}
			env[ShareEnv(s.Name)] = unshared
			continue
		}
		if ch.Access == "" {
			ch.Access = s.Access
		}
		switch {
		case !shareIDRE.MatchString(ch.Share):
			p.addf("%s: %q isn't a shared folder id", s.Label, ch.Share)
			continue
		case ch.Access != AccessRead && ch.Access != AccessWrite:
			p.addf("%s: access must be read or write", s.Label)
			continue
		case ch.Access == AccessWrite && s.Access == AccessRead:
			p.addf("%s: %s may only read this shared folder", s.Label, mf.Name)
			continue
		}
		if m.Shares == nil {
			if s.Required {
				p.addf("%s: shared folders aren't available on this server yet", s.Label)
			} else {
				res.Warnings = append(res.Warnings, fmt.Sprintf("Shared folders aren't available on this server yet; %s gets an empty folder for %s", mf.Name, s.Label))
				env[ShareEnv(s.Name)] = unshared
			}
			continue
		}
		host, err := m.Shares.Resolve(ctx, ch.Share, "")
		if err != nil {
			p.addf("%s: %v", s.Label, err)
			continue
		}
		if !filepath.IsAbs(host) || strings.ContainsAny(host, "'\n\r\x00") {
			p.addf("%s: the shared folder's path can't be used", s.Label)
			continue
		}
		host = filepath.Clean(host)
		choices[s.Name] = ch
		binds = append(binds, shareBind{Name: s.Name, Path: host, Write: ch.Access == AccessWrite})
		env[ShareEnv(s.Name)] = host
	}
	if err := p.err(); err != nil {
		return nil, nil, nil, err
	}
	return choices, binds, env, nil
}

// currentShareBinds resolves the app's shares again (before every start):
// a share that moved or went away no longer covers the folders the
// resolved compose file mounts, so the start is refused.
func (m *Manager) currentShareBinds(ctx context.Context, ia *installedApp) ([]shareBind, error) {
	var out []shareBind
	names := make([]string, 0, len(ia.state.Shares))
	for name := range ia.state.Shares {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ch := ia.state.Shares[name]
		if ch.Share == "" {
			continue
		}
		if ch.Path != "" {
			return nil, fmt.Errorf("%s has a subfolder of shared folder %s for %s; apps get whole shared folders now: choose the shared folder again in the app's settings", ia.manifest.Name, ch.Share, name)
		}
		if m.Shares == nil {
			return nil, fmt.Errorf("%s uses shared folders, which aren't available; refusing to start", ia.manifest.Name)
		}
		host, err := m.Shares.Resolve(ctx, ch.Share, "")
		if err != nil {
			return nil, fmt.Errorf("shared folder %s for %s: %w", ch.Share, name, err)
		}
		if real, err := filepath.EvalSymlinks(host); err == nil {
			host = real
		}
		out = append(out, shareBind{Name: name, Path: filepath.Clean(host), Write: ch.Access == AccessWrite})
	}
	return out, nil
}

// shareLevels maps each chosen share to whether the app may write in it.
func shareLevels(ch map[string]ShareChoice) map[string]bool {
	out := map[string]bool{}
	for _, c := range ch {
		if c.Share != "" {
			out[c.Share] = out[c.Share] || c.Access == AccessWrite
		}
	}
	return out
}

// applyShareGrants gives the app's user access to the shares it was given.
// When the choices changed, every old grant goes first.
func (m *Manager) applyShareGrants(ctx context.Context, id string, uid int, prev, cur map[string]ShareChoice) error {
	if m.Shares == nil {
		return nil
	}
	had, want := shareLevels(prev), shareLevels(cur)
	same := len(had) == len(want)
	for s, w := range want {
		if hw, ok := had[s]; !ok || hw != w {
			same = false
		}
	}
	if same {
		return nil
	}
	if len(had) > 0 {
		if err := m.Shares.RevokeApp(ctx, id); err != nil {
			return fmt.Errorf("removing the app's old shared folder access: %w", err)
		}
	}
	ids := make([]string, 0, len(want))
	for s := range want {
		ids = append(ids, s)
	}
	sort.Strings(ids)
	for _, s := range ids {
		if err := m.Shares.GrantApp(ctx, s, id, uid, want[s]); err != nil {
			return fmt.Errorf("giving the app access to shared folder %s: %w", s, err)
		}
	}
	return nil
}
