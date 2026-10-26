// Package appstore is hardyd's side of Docker apps: the catalog of packages
// that ship with HardyOS, packages people upload, and what the App Store
// shows about them. Installing and running apps happens in hardyd-priv
// (internal/apps), which checks every package again.
package appstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/hardyos/hardyos/daemon/internal/apps"
)

// Default locations.
const (
	DefaultCatalogDir = "/usr/share/hardyos/apps"
	DefaultUploadDir  = "/var/lib/hardyos/app-packages"
)

// Sources of a package.
const (
	SourceCatalog = "catalog"
	SourceUpload  = "upload"
)

// Store finds packages.
type Store struct {
	CatalogDir string // packages that ship with HardyOS (*.hardyapp)
	UploadDir  string // packages people uploaded, named <sha256>.hardyapp
}

// Entry is a package as the App Store shows it.
type Entry struct {
	Source      string         `json:"source"`
	Ref         string         `json:"ref"` // the app id (catalog) or the package's hash (upload)
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
	Images      []string `json:"images"`
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
	s.prune(path)
	e := EntryOf(SourceUpload, p.SHA256, p)
	return &e, nil
}

// prune keeps the newest few uploads.
func (s *Store) prune(keep string) {
	files, _ := filepath.Glob(filepath.Join(s.UploadDir, "*.hardyapp"))
	if len(files) <= 10 {
		return
	}
	sort.Slice(files, func(i, j int) bool {
		a, _ := os.Stat(files[i])
		b, _ := os.Stat(files[j])
		return a != nil && b != nil && a.ModTime().After(b.ModTime())
	})
	for _, f := range files[10:] {
		if f != keep {
			_ = os.Remove(f)
		}
	}
}

// Load finds a package by source and ref.
func (s *Store) Load(source, ref string) (*apps.Package, error) {
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
	case SourceUpload:
		if !shaRE.MatchString(ref) {
			return nil, ErrNotFound
		}
		p, err := readFile(filepath.Join(s.UploadDir, ref+".hardyapp"))
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: upload the package again", ErrNotFound)
		}
		return p, err
	}
	return nil, ErrNotFound
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
