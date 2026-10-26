// Package appstore is hardyd's side of Docker apps: the catalog of packages
// that ship with HardyOS, packages people upload, and what the App Store
// shows about them. Installing and running apps happens in hardyd-priv
// (internal/apps), which checks every package again.
package appstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Default locations.
const (
	DefaultCatalogDir = "/usr/share/hardyos/apps"
	DefaultUploadDir  = "/var/lib/hardyos/app-packages"
	DefaultImportDir  = "/var/lib/hardyos/app-imports"
)

// Sources of a package (the same words as apps.Source).
const (
	SourceCatalog  = string(apps.SourceCatalog)
	SourceUpload   = string(apps.SourceUpload)
	SourceImported = string(apps.SourceImported)
	SourceCustom   = string(apps.SourceCustom)
)

// Store finds packages and keeps the App Store's own records (who may use
// each app, imported catalogs, window proxy ports) in hardyd's database.
type Store struct {
	CatalogDir string // packages that ship with HardyOS (*.hardyapp)
	UploadDir  string // packages people uploaded or built, named <sha256>.hardyapp
	// ImportDir caches packages from imported catalogs, named <sha256>.hardyapp.
	ImportDir string
	// DB holds app access, imported catalogs and proxy ports; nil disables them.
	DB *store.DB
	// Client fetches imported catalogs; nil uses a client with timeouts.
	Client *http.Client
}

func (s *Store) importDir() string {
	if s.ImportDir != "" {
		return s.ImportDir
	}
	return DefaultImportDir
}

// ErrNoDB means the store was built without a database.
var ErrNoDB = errors.New("the App Store database isn't available")

func (s *Store) db() (*store.DB, error) {
	if s.DB == nil {
		return nil, ErrNoDB
	}
	return s.DB, nil
}

// Entry is a package as the App Store shows it.
type Entry struct {
	Source string `json:"source"`
	// Ref is the app id (catalog) or the package's SHA-256 (upload, imported, custom).
	Ref string `json:"ref"`
	// SourceName is the imported catalog's name ("" otherwise).
	SourceName  string         `json:"sourceName"`
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Version     string         `json:"version"`
	Summary     string         `json:"summary"`
	Description string         `json:"description"`
	Publisher   string         `json:"publisher"`
	Website     string         `json:"website"`
	Icon        string         `json:"icon"`
	MinMemoryMB int            `json:"minMemoryMB"`
	Ports       []EntryPort    `json:"ports"`
	Settings    []EntrySetting `json:"settings"`
	// Permissions in plain words; empty for a plain container app.
	Permissions []string `json:"permissions"`
	// Grants are the extra permissions the package asks for, one per grant
	// string. Catalog apps get them by declaring them; for any other source
	// an administrator must tick each one (apps.PrepareArgs.Grants).
	Grants []EntryGrant `json:"grants"`
	// Shares are the shared folders the app can be given.
	Shares []apps.ShareMount `json:"shares"`
	// FixedPorts: the app uses the host network, so its ports are what the
	// manifest says and can't be changed.
	FixedPorts bool     `json:"fixedPorts"`
	Images     []string `json:"images"`
}

// EntryGrant is one extra permission, as a grant string and in plain words.
type EntryGrant struct {
	Grant string `json:"grant"`
	Label string `json:"label"`
}

// EntryPort is a port the app wants.
type EntryPort struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Default  int    `json:"default"`
	Protocol string `json:"protocol"`
	Web      bool   `json:"web"`
}

// EntrySetting is a setting the install form asks for (generated secrets
// aren't listed: nobody types them).
type EntrySetting struct {
	Env      string   `json:"env"`
	Label    string   `json:"label"`
	Help     string   `json:"help"`
	Type     string   `json:"type"`
	Default  string   `json:"default"`
	Options  []string `json:"options"`
	Required bool     `json:"required"`
}

// ErrNotFound means there's no such package.
var ErrNotFound = errors.New("no such app package")

var (
	shaRE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	imageRE = regexp.MustCompile(`(?m)^\s*image:\s*["']?([^"'\s#]+)`)
	varRE   = regexp.MustCompile(`\$\{([A-Z][A-Z0-9_]*)(?::?-[^}]*)?\}`)
)

// EntryOf describes a package.
func EntryOf(source, ref string, p *apps.Package) Entry {
	m := p.Manifest
	e := Entry{
		Source: source, Ref: ref, ID: m.ID, Name: m.Name, Version: m.Version, Summary: m.Summary,
		Description: m.Description, Publisher: m.Publisher, Website: m.Website,
		Icon: apps.IconDataURL(m.Icon, p.Icon), MinMemoryMB: m.MinMemoryMB,
		Ports: []EntryPort{}, Settings: []EntrySetting{}, Permissions: apps.DescribePermissions(m), Images: []string{},
		Grants: GrantsOf(m), Shares: m.Shares, FixedPorts: m.Permissions.HostNetwork,
	}
	if e.Shares == nil {
		e.Shares = []apps.ShareMount{}
	}
	for _, pt := range m.Ports {
		proto := pt.Protocol
		if proto == "" {
			proto = "tcp"
		}
		e.Ports = append(e.Ports, EntryPort{Name: pt.Name, Label: pt.Label, Default: pt.Default, Protocol: proto, Web: m.Web != nil && m.Web.Port == pt.Name})
	}
	for _, s := range m.Settings {
		if s.Hidden() {
			continue
		}
		typ := s.Type
		if typ == "" {
			typ = "text"
		}
		opts := s.Options
		if opts == nil {
			opts = []string{}
		}
		e.Settings = append(e.Settings, EntrySetting{Env: s.Env, Label: s.Label, Help: s.Help, Type: typ, Default: s.Default, Options: opts, Required: s.Required})
	}
	// The images as written in the compose file (variables unresolved), so
	// people can see where the software comes from.
	// Variables show as their defaults, e.g. ${KINCAST_TAG} as "latest".
	defaults := map[string]string{}
	for _, s := range m.Settings {
		if s.Default != "" {
			defaults[s.Env] = s.Default
		}
	}
	seen := map[string]bool{}
	for _, match := range imageRE.FindAllStringSubmatch(string(p.Compose), -1) {
		img := varRE.ReplaceAllStringFunc(match[1], func(v string) string {
			name := varRE.FindStringSubmatch(v)[1]
			if d, ok := defaults[name]; ok {
				return d
			}
			return v
		})
		if !seen[img] {
			seen[img] = true
			e.Images = append(e.Images, img)
		}
	}
	return e
}

// Catalog lists the packages that ship with HardyOS.
func (s *Store) Catalog() ([]Entry, error) {
	out := []Entry{}
	files, err := filepath.Glob(filepath.Join(s.CatalogDir, "*.hardyapp"))
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		p, err := readFile(f)
		if err != nil {
			continue // a broken catalog file shouldn't hide the rest
		}
		out = append(out, EntryOf(SourceCatalog, p.Manifest.ID, p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Save checks an uploaded package and keeps it for installing.
func (s *Store) Save(raw []byte) (*Entry, error) {
	return s.save(raw, SourceUpload)
}

func (s *Store) save(raw []byte, source string) (*Entry, error) {
	p, err := apps.ReadPackage(raw)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.UploadDir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(s.UploadDir, p.SHA256+".hardyapp")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return nil, err
	}
	s.pruneDir(s.UploadDir, path, 10)
	e := EntryOf(source, p.SHA256, p)
	return &e, nil
}

// pruneDir keeps the newest n packages in dir (and always keep).
func (s *Store) pruneDir(dir, keep string, n int) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.hardyapp"))
	if len(files) <= n {
		return
	}
	sort.Slice(files, func(i, j int) bool {
		a, _ := os.Stat(files[i])
		b, _ := os.Stat(files[j])
		return a != nil && b != nil && a.ModTime().After(b.ModTime())
	})
	for _, f := range files[n:] {
		if f != keep {
			_ = os.Remove(f)
		}
	}
}

// Load finds a package by source and ref.
func (s *Store) Load(source, ref string) (*apps.Package, error) {
	return s.LoadContext(context.Background(), source, ref)
}

// LoadContext finds a package by source and ref. A package from an imported
// catalog is downloaded (and checked against the catalog's SHA-256) the
// first time.
func (s *Store) LoadContext(ctx context.Context, source, ref string) (*apps.Package, error) {
	switch source {
	case SourceCatalog:
		if apps.ValidID(ref) != nil {
			return nil, ErrNotFound
		}
		files, _ := filepath.Glob(filepath.Join(s.CatalogDir, "*.hardyapp"))
		for _, f := range files {
			if p, err := readFile(f); err == nil && p.Manifest.ID == ref {
				return p, nil
			}
		}
		return nil, ErrNotFound
	case SourceUpload, SourceCustom:
		if !shaRE.MatchString(ref) {
			return nil, ErrNotFound
		}
		p, err := readFile(filepath.Join(s.UploadDir, ref+".hardyapp"))
		if errors.Is(err, os.ErrNotExist) {
			if source == SourceCustom {
				return nil, fmt.Errorf("%w: create the app again", ErrNotFound)
			}
			return nil, fmt.Errorf("%w: upload the package again", ErrNotFound)
		}
		if err == nil && p.SHA256 != ref {
			return nil, ErrNotFound
		}
		return p, err
	case SourceImported:
		if !shaRE.MatchString(ref) {
			return nil, ErrNotFound
		}
		return s.loadImported(ctx, ref)
	}
	return nil, ErrNotFound
}

// SourceNameOf is the imported catalog's name for an imported package ref.
func (s *Store) SourceNameOf(ctx context.Context, source, ref string) string {
	if source != SourceImported {
		return ""
	}
	if c, _, ok := s.findImported(ctx, ref); ok {
		return c.Name
	}
	return ""
}

// basicCapabilities are in Docker's default set, so the engine needs no
// grant for them (the same list as the engine's policy).
var basicCapabilities = map[string]bool{
	"CHOWN": true, "DAC_OVERRIDE": true, "FSETID": true, "FOWNER": true, "MKNOD": true, "NET_RAW": true,
	"SETGID": true, "SETUID": true, "SETPCAP": true, "NET_BIND_SERVICE": true, "SYS_CHROOT": true,
	"KILL": true, "AUDIT_WRITE": true,
}

// MissingGrants lists the grants a manifest needs that have doesn't hold.
func MissingGrants(m apps.Manifest, have []string) []EntryGrant {
	held := map[string]bool{}
	for _, g := range have {
		held[g] = true
	}
	out := []EntryGrant{}
	for _, g := range GrantsOf(m) {
		if !held[g.Grant] {
			out = append(out, g)
		}
	}
	return out
}

// GrantsOf lists the extra permissions a manifest asks for, as grant strings
// with plain words (the grants the engine requires from non-catalog apps).
func GrantsOf(m apps.Manifest) []EntryGrant {
	out := []EntryGrant{}
	if m.Permissions.HostNetwork {
		out = append(out, EntryGrant{Grant: apps.GrantHostNetwork, Label: "Use the server's network directly (host networking): it can reach and listen on every network the server is on"})
	}
	if m.Permissions.GPU {
		out = append(out, EntryGrant{Grant: apps.GrantGPU, Label: "Use the server's graphics card (GPU), for example to convert videos"})
	}
	for _, c := range m.Permissions.Capabilities {
		if basicCapabilities[c] {
			continue // in Docker's default set: nothing to grant
		}
		label := apps.AllowedCapabilities[c]
		if label == "" {
			label = c
		}
		out = append(out, EntryGrant{Grant: apps.GrantCapability + c, Label: fmt.Sprintf("%s (%s)", label, c)})
	}
	for _, d := range m.Permissions.Devices {
		label := d
		for _, w := range apps.DescribePermissions(apps.Manifest{Permissions: apps.Permissions{Devices: []string{d}}}) {
			if strings.Contains(w, d) {
				label = w
			}
		}
		out = append(out, EntryGrant{Grant: apps.GrantDevice + d, Label: label})
	}
	return out
}

// CatalogVersion is the catalog's version of an app, or "".
func (s *Store) CatalogVersion(id string) string {
	p, err := s.Load(SourceCatalog, id)
	if err != nil {
		return ""
	}
	return p.Manifest.Version
}

func readFile(path string) (*apps.Package, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > apps.MaxPackageBytes {
		return nil, fmt.Errorf("%s is too big", filepath.Base(path))
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return apps.ReadPackage(b)
}
