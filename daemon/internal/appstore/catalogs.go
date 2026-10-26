package appstore

// Imported (third-party) catalogs: an https URL to an index.json listing
// packages by URL and SHA-256. hardyd fetches the index and the packages
// itself (hardyd-priv never touches the network for them), with timeouts and
// size limits, and a package is only used if its hash matches the index.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Limits for imported catalogs.
const (
	MaxIndexBytes   = 1 << 20 // index.json
	MaxCatalogApps  = 500
	MaxCatalogs     = 20
	maxIndexIconLen = 180 << 10 // a data: URL
	fetchTimeout    = 30 * time.Second
)

// CatalogApp is one app in an imported catalog's index.json.
type CatalogApp struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Summary string `json:"summary"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	// Icon is a data: URL (svg or png) or "": the desktop never loads
	// pictures from other servers.
	Icon string `json:"icon"`
}

// CatalogIndex is an imported catalog's index.json.
type CatalogIndex struct {
	Name string       `json:"name"`
	Apps []CatalogApp `json:"apps"`
}

// Catalog is an imported catalog as the App Store shows it.
type Catalog struct {
	ID        int64      `json:"id"`
	URL       string     `json:"url"`
	Name      string     `json:"name"`
	AddedAt   time.Time  `json:"addedAt"`
	AddedBy   string     `json:"addedBy"`
	FetchedAt *time.Time `json:"fetchedAt"`
	// LastError is why the last refresh failed, or which apps were skipped.
	LastError string `json:"lastError"`
	// LocalNetwork lets hardyd fetch this catalog and its packages from this
	// server or its own networks (an administrator ticked "On my network").
	LocalNetwork bool         `json:"localNetwork"`
	Apps         []CatalogApp `json:"apps"`
}

var (
	versionRE = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+~_-]{0,63}$`)
	iconRE    = regexp.MustCompile(`^data:image/(svg\+xml|png);base64,[A-Za-z0-9+/=]+$`)
)

// client fetches catalogs and packages. Every connection it makes is
// checked by the network guard (netguard.go); allowLocal is the catalog's
// "On my network" flag. s.Client (tests) supplies TLS settings only: its
// transport is cloned and guarded the same way.
func (s *Store) client(allowLocal bool) *http.Client {
	var base *http.Transport
	if s.Client != nil {
		switch t := s.Client.Transport.(type) {
		case *http.Transport:
			base = t
		case nil:
		default:
			// A custom round tripper (tests) never dials; used as given.
			return &http.Client{Timeout: fetchTimeout, CheckRedirect: httpsRedirectsOnly, Transport: t}
		}
	}
	return &http.Client{Timeout: fetchTimeout, CheckRedirect: httpsRedirectsOnly, Transport: guardedTransport(base, allowLocal)}
}

func httpsRedirectsOnly(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != "https" {
		return errors.New("a catalog may only redirect to https:// addresses")
	}
	return nil
}

// CheckCatalogURL checks an imported catalog's address.
func CheckCatalogURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || len(raw) > 2000 {
		return nil, apps.Problems{"a catalog's address must be an https:// address, like https://example.com/hardyos/index.json"}
	}
	return u, nil
}

// fetch downloads at most limit bytes from an https URL.
func (s *Store) fetch(ctx context.Context, u *url.URL, limit int64, allowLocal bool) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, application/octet-stream")
	req.Header.Set("User-Agent", "HardyOS-AppStore/1")
	resp, err := s.client(allowLocal).Do(req)
	if err != nil {
		var le *LocalAddressError
		if errors.As(err, &le) {
			return nil, fmt.Errorf("couldn't fetch from %s: %w", u.Host, le)
		}
		return nil, fmt.Errorf("couldn't reach %s: %w", u.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", u.Host, resp.Status)
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("%s is bigger than %d KB", u.Path, limit>>10)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", u.Path, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is bigger than %d KB", u.Path, limit>>10)
	}
	return b, nil
}

// ParseIndex reads and checks an index.json. Apps with problems are left
// out and described in skipped; a broken index is an error.
func ParseIndex(b []byte, base *url.URL) (idx *CatalogIndex, skipped []string, err error) {
	var raw CatalogIndex
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, nil, apps.Problems{"the catalog isn't a HardyOS index.json: " + err.Error()}
	}
	name := strings.TrimSpace(raw.Name)
	if name == "" || len(name) > 60 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return nil, nil, apps.Problems{"the catalog needs a name of 1-60 characters"}
	}
	if strings.EqualFold(name, "HardyOS") {
		return nil, nil, apps.Problems{`a third-party catalog can't be called "HardyOS"`}
	}
	if len(raw.Apps) > MaxCatalogApps {
		return nil, nil, apps.Problems{fmt.Sprintf("the catalog lists %d apps; at most %d are allowed", len(raw.Apps), MaxCatalogApps)}
	}
	out := &CatalogIndex{Name: name, Apps: []CatalogApp{}}
	seen := map[string]bool{}
	for _, a := range raw.Apps {
		bad := func(why string) { skipped = append(skipped, fmt.Sprintf("%s: %s", a.ID, why)) }
		a.Name, a.Summary, a.SHA256 = strings.TrimSpace(a.Name), strings.TrimSpace(a.Summary), strings.ToLower(strings.TrimSpace(a.SHA256))
		switch {
		case apps.ValidID(a.ID) != nil:
			bad("not a valid app id")
			continue
		case seen[a.ID]:
			bad("listed twice")
			continue
		case a.Name == "" || len(a.Name) > 60:
			bad("name must be 1-60 characters")
			continue
		case !versionRE.MatchString(a.Version):
			bad("not a valid version")
			continue
		case len(a.Summary) > 200:
			bad("summary is longer than 200 characters")
			continue
		case !shaRE.MatchString(a.SHA256):
			bad("sha256 must be 64 hex digits")
			continue
		}
		ref, err := url.Parse(a.URL)
		if err != nil || a.URL == "" {
			bad("no package address")
			continue
		}
		abs := base.ResolveReference(ref)
		if abs.Scheme != "https" || abs.Hostname() == "" || abs.User != nil {
			bad("the package must be at an https:// address")
			continue
		}
		a.URL = abs.String()
		if a.Icon != "" && (len(a.Icon) > maxIndexIconLen || !iconRE.MatchString(a.Icon)) {
			a.Icon = "" // a remote or odd icon is dropped, not fetched
		}
		seen[a.ID] = true
		out.Apps = append(out.Apps, a)
	}
	return out, skipped, nil
}

func skippedNote(skipped []string) string {
	if len(skipped) == 0 {
		return ""
	}
	const show = 5
	note := fmt.Sprintf("%d apps were left out: %s", len(skipped), strings.Join(skipped[:min(len(skipped), show)], "; "))
	if len(skipped) > show {
		note += "; …"
	}
	return note
}

const catalogCols = `id, url, name, added_at, added_by, fetched_at, last_error, local_network, index_json`

func scanCatalog(row interface{ Scan(...any) error }) (*Catalog, error) {
	var (
		c                   Catalog
		added, fetched, idx string
	)
	if err := row.Scan(&c.ID, &c.URL, &c.Name, &added, &c.AddedBy, &fetched, &c.LastError, &c.LocalNetwork, &idx); err != nil {
		return nil, err
	}
	c.AddedAt = store.ParseTime(added)
	if fetched != "" {
		t := store.ParseTime(fetched)
		c.FetchedAt = &t
	}
	var ix CatalogIndex
	_ = json.Unmarshal([]byte(idx), &ix)
	c.Apps = ix.Apps
	if c.Apps == nil {
		c.Apps = []CatalogApp{}
	}
	return &c, nil
}

// Catalogs lists the imported catalogs.
func (s *Store) Catalogs(ctx context.Context) ([]Catalog, error) {
	db, err := s.db()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT `+catalogCols+` FROM app_catalogs ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Catalog{}
	for rows.Next() {
		c, err := scanCatalog(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// ImportedCatalog returns one imported catalog.
func (s *Store) ImportedCatalog(ctx context.Context, id int64) (*Catalog, error) {
	db, err := s.db()
	if err != nil {
		return nil, err
	}
	c, err := scanCatalog(db.QueryRowContext(ctx, `SELECT `+catalogCols+` FROM app_catalogs WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: no such catalog", ErrNotFound)
	}
	return c, err
}

// AddCatalog fetches an index.json and adds the catalog. localNetwork is the
// administrator's "On my network" tick: without it the catalog can't be on
// this server or its own networks.
func (s *Store) AddCatalog(ctx context.Context, rawURL, by string, localNetwork bool) (*Catalog, error) {
	db, err := s.db()
	if err != nil {
		return nil, err
	}
	u, err := CheckCatalogURL(rawURL)
	if err != nil {
		return nil, err
	}
	existing, err := s.Catalogs(ctx)
	if err != nil {
		return nil, err
	}
	if len(existing) >= MaxCatalogs {
		return nil, apps.Problems{fmt.Sprintf("at most %d catalogs can be imported", MaxCatalogs)}
	}
	for _, c := range existing {
		if c.URL == u.String() {
			return nil, apps.Problems{"that catalog is already imported as " + c.Name}
		}
	}
	b, err := s.fetch(ctx, u, MaxIndexBytes, localNetwork)
	if err != nil {
		return nil, apps.Problems{err.Error()}
	}
	idx, skipped, err := ParseIndex(b, u)
	if err != nil {
		return nil, err
	}
	for _, c := range existing {
		if strings.EqualFold(c.Name, idx.Name) {
			return nil, apps.Problems{fmt.Sprintf("a catalog called %q is already imported", idx.Name)}
		}
	}
	ib, _ := json.Marshal(idx)
	now := store.Now()
	res, err := db.ExecContext(ctx, `INSERT INTO app_catalogs (url, name, added_at, added_by, fetched_at, last_error, local_network, index_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, u.String(), idx.Name, now, by, now, skippedNote(skipped), localNetwork, string(ib))
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.ImportedCatalog(ctx, id)
}

// RefreshCatalog fetches a catalog's index again. If that fails the last
// good index is kept and the error noted.
func (s *Store) RefreshCatalog(ctx context.Context, id int64) (*Catalog, error) {
	db, err := s.db()
	if err != nil {
		return nil, err
	}
	c, err := s.ImportedCatalog(ctx, id)
	if err != nil {
		return nil, err
	}
	u, err := CheckCatalogURL(c.URL)
	if err != nil {
		return nil, err
	}
	b, err := s.fetch(ctx, u, MaxIndexBytes, c.LocalNetwork)
	var idx *CatalogIndex
	var skipped []string
	if err == nil {
		idx, skipped, err = ParseIndex(b, u)
	}
	if err != nil {
		_, _ = db.ExecContext(ctx, `UPDATE app_catalogs SET last_error = ? WHERE id = ?`, err.Error(), id)
		return nil, err
	}
	// The name stays what it was: installed apps record it as their source.
	ib, _ := json.Marshal(CatalogIndex{Name: c.Name, Apps: idx.Apps})
	if _, err := db.ExecContext(ctx, `UPDATE app_catalogs SET fetched_at = ?, last_error = ?, index_json = ? WHERE id = ?`,
		store.Now(), skippedNote(skipped), string(ib), id); err != nil {
		return nil, err
	}
	return s.ImportedCatalog(ctx, id)
}

// SetCatalogLocal changes a catalog's "On my network" flag.
func (s *Store) SetCatalogLocal(ctx context.Context, id int64, on bool) error {
	db, err := s.db()
	if err != nil {
		return err
	}
	res, err := db.ExecContext(ctx, `UPDATE app_catalogs SET local_network = ? WHERE id = ?`, on, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: no such catalog", ErrNotFound)
	}
	return nil
}

// RemoveCatalog forgets an imported catalog. Apps installed from it keep
// running; they just get no more updates from it.
func (s *Store) RemoveCatalog(ctx context.Context, id int64) (*Catalog, error) {
	db, err := s.db()
	if err != nil {
		return nil, err
	}
	c, err := s.ImportedCatalog(ctx, id)
	if err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM app_catalogs WHERE id = ?`, id); err != nil {
		return nil, err
	}
	return c, nil
}

// findImported finds a package hash in the imported catalog with that id.
// The hash must be listed by that catalog: another catalog listing the same
// hash doesn't count, so an install is always labelled with (and updated
// from) the catalog the administrator chose.
func (s *Store) findImported(ctx context.Context, catalogID int64, sha string) (*Catalog, *CatalogApp, bool) {
	if catalogID <= 0 {
		return nil, nil, false
	}
	c, err := s.ImportedCatalog(ctx, catalogID)
	if err != nil {
		return nil, nil, false
	}
	for j := range c.Apps {
		if c.Apps[j].SHA256 == sha {
			return c, &c.Apps[j], true
		}
	}
	return nil, nil, false
}

// ImportedLatest is the newest version of an app in the catalog called name,
// its package hash and the catalog's id. Only for apps installed before
// hardyd recorded the catalog's id; use ImportedLatestIn otherwise.
func (s *Store) ImportedLatest(ctx context.Context, catalog, id string) (version, sha string, catalogID int64) {
	cs, err := s.Catalogs(ctx)
	if err != nil {
		return "", "", 0
	}
	for _, c := range cs {
		if c.Name != catalog {
			continue
		}
		for _, a := range c.Apps {
			if a.ID == id {
				return a.Version, a.SHA256, c.ID
			}
		}
	}
	return "", "", 0
}

// ImportedLatestIn is the newest version of an app in the imported catalog
// with that id, and its package hash.
func (s *Store) ImportedLatestIn(ctx context.Context, catalogID int64, id string) (version, sha string) {
	c, err := s.ImportedCatalog(ctx, catalogID)
	if err != nil {
		return "", ""
	}
	for _, a := range c.Apps {
		if a.ID == id {
			return a.Version, a.SHA256
		}
	}
	return "", ""
}

// loadImported returns a package from an imported catalog, downloading it
// the first time. It must hash to what the index says and be the app and
// version the index names.
func (s *Store) loadImported(ctx context.Context, catalogID int64, sha string) (*apps.Package, error) {
	if catalogID <= 0 {
		return nil, fmt.Errorf("%w: say which imported catalog the package is from (catalogId)", ErrNotFound)
	}
	c, a, ok := s.findImported(ctx, catalogID, sha)
	if !ok {
		return nil, fmt.Errorf("%w: that catalog doesn't list this package (any more)", ErrNotFound)
	}
	cached := filepath.Join(s.importDir(), sha+".hardyapp")
	if p, err := readFile(cached); err == nil && p.SHA256 == sha {
		return p, nil
	}
	u, err := url.Parse(a.URL)
	if err != nil {
		return nil, err
	}
	raw, err := s.fetch(ctx, u, apps.MaxPackageBytes, c.LocalNetwork)
	if err != nil {
		return nil, apps.Problems{fmt.Sprintf("downloading %s from %s: %v", a.Name, c.Name, err)}
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != sha {
		return nil, apps.Problems{fmt.Sprintf("%s's package from %s doesn't match the catalog's checksum (got %s…); it was not used", a.Name, c.Name, got[:12])}
	}
	p, err := apps.ReadPackage(raw)
	if err != nil {
		return nil, err
	}
	if p.Manifest.ID != a.ID || p.Manifest.Version != a.Version {
		return nil, apps.Problems{fmt.Sprintf("the catalog says this is %s %s but the package is %s %s", a.ID, a.Version, p.Manifest.ID, p.Manifest.Version)}
	}
	if err := os.MkdirAll(s.importDir(), 0o700); err == nil {
		_ = os.WriteFile(cached, raw, 0o600)
		s.pruneDir(s.importDir(), cached, 30)
	}
	return p, nil
}
