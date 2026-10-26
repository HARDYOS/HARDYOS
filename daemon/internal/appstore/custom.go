package appstore

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/hardyos/hardyos/daemon/internal/apps"
)

// CustomApp is what App Store > Create an app sends: a pasted Compose file
// with the ports and folders it uses. It becomes a .hardyapp with source
// "custom", which is sandboxed like an upload.
type CustomApp struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"` // default 1.0.0
	Summary string `json:"summary,omitempty"`
	// Compose uses ${HARDY_PORT_<NAME>} for each port, ${HARDY_APP_DATA} for
	// its folders and may use the other HARDY_ variables.
	Compose string      `json:"compose"`
	Ports   []apps.Port `json:"ports"`
	// WebPort names the port with the app's web page ("" = none).
	WebPort string `json:"webPort,omitempty"`
	WebPath string `json:"webPath,omitempty"`
	// Folders are created under ${HARDY_APP_DATA} before the first start.
	Folders []apps.Folder `json:"folders,omitempty"`
}

// maxCustomCompose matches the package's own compose limit.
const maxCustomCompose = 256 << 10

// Manifest builds the manifest for a custom app.
func (c CustomApp) Manifest() apps.Manifest {
	version := strings.TrimSpace(c.Version)
	if version == "" {
		version = "1.0.0"
	}
	summary := strings.TrimSpace(c.Summary)
	if summary == "" {
		summary = "A custom app made from a Compose file."
	}
	m := apps.Manifest{
		Format: apps.FormatVersion, ID: strings.TrimSpace(c.ID), Name: strings.TrimSpace(c.Name),
		Version: version, Summary: summary, Publisher: "Custom (made on this server)",
		Icon: "icon.svg", Ports: c.Ports, Folders: c.Folders,
	}
	if c.WebPort != "" {
		m.Web = &apps.Web{Port: c.WebPort, Path: c.WebPath, Scheme: "http"}
	}
	return m
}

// BuildCustom checks a custom app and saves it as a package for installing.
// hardyd-priv checks the Compose file against the sandbox policy when it
// prepares the app.
func (s *Store) BuildCustom(c CustomApp) (*Entry, error) {
	var p apps.Problems
	compose := strings.ReplaceAll(c.Compose, "\r\n", "\n")
	switch {
	case strings.TrimSpace(compose) == "":
		p = append(p, "paste the app's Compose file")
	case len(compose) > maxCustomCompose:
		p = append(p, fmt.Sprintf("the Compose file can be at most %d KB", maxCustomCompose>>10))
	case !strings.Contains(compose, "services:"):
		p = append(p, "that doesn't look like a Compose file (it has no services:)")
	}
	for _, pt := range c.Ports {
		if pt.Name != "" && !strings.Contains(compose, "${"+apps.PortEnv(pt.Name)+"}") {
			p = append(p, fmt.Sprintf("the Compose file should publish %s as ${%s}", pt.Label, apps.PortEnv(pt.Name)))
		}
	}
	m := c.Manifest()
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		var mp apps.Problems
		if errors.As(err, &mp) {
			p = append(p, mp...)
		} else {
			p = append(p, err.Error())
		}
	}
	if len(p) > 0 {
		return nil, p
	}
	raw, err := packFiles(map[string][]byte{
		apps.ManifestFile: mb,
		apps.ComposeFile:  []byte(compose),
		"icon.svg":        customIcon(m.Name),
	})
	if err != nil {
		return nil, err
	}
	return s.save(raw, SourceCustom)
}

// packFiles builds a .hardyapp the way apps.Pack does (sorted names, fixed
// times), from memory.
func packFiles(files map[string][]byte) ([]byte, error) {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	zw.ModTime = time.Unix(0, 0)
	tw := tar.NewWriter(zw)
	for _, n := range names {
		b := files[n]
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(b)), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(b); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// customIcon is a rounded square in the HardyOS gradient with the app's
// first letter.
func customIcon(name string) []byte {
	letter := "?"
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			letter = strings.ToUpper(string(r))
			break
		}
	}
	return []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">` +
		`<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#00F0FF"/><stop offset="1" stop-color="#8B5CFF"/></linearGradient></defs>` +
		`<rect width="64" height="64" rx="14" fill="url(#g)"/>` +
		`<text x="32" y="43" font-family="Plus Jakarta Sans, sans-serif" font-size="30" font-weight="700" text-anchor="middle" fill="#0B0F19">` +
		html.EscapeString(letter) + `</text></svg>`)
}
