package appstore

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Principal kinds for app access.
const (
	KindUser     = "user"
	KindGroup    = "group"
	KindEveryone = "everyone"
)

// Principal may use an app: a HardyOS user ("alice"), a domain user
// ("HOME\alice"), a domain group ("HOME\Family") or everyone signed in.
type Principal struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// Domain reports whether the principal is written NETBIOS\name.
func (p Principal) Domain() bool { return strings.Contains(p.Name, `\`) }

var (
	localUserRE = regexp.MustCompile(`^[a-z][a-z0-9._-]{1,31}$`)
	// NETBIOS domain (1-15) \ account or group name (no characters Windows refuses).
	domainNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,14}\\[^\\/:*?"<>|\[\]=;+,@\x00-\x1f]{1,64}$`)
)

// MaxPrincipals is the most principals one app's access lists.
const MaxPrincipals = 200

// NormalizePrincipals checks an access list and returns it sorted, without
// duplicates. A list holding "everyone" collapses to just that; an empty
// list also means everyone.
func NormalizePrincipals(in []Principal) ([]Principal, error) {
	if len(in) > MaxPrincipals {
		return nil, fmt.Errorf("at most %d people and groups per app", MaxPrincipals)
	}
	seen := map[string]bool{}
	out := []Principal{}
	for _, p := range in {
		p.Kind, p.Name = strings.TrimSpace(p.Kind), strings.TrimSpace(p.Name)
		switch p.Kind {
		case KindEveryone:
			return []Principal{{Kind: KindEveryone}}, nil
		case KindUser:
			if domainNameRE.MatchString(p.Name) {
				break
			}
			n := strings.ToLower(p.Name)
			if !localUserRE.MatchString(n) {
				return nil, fmt.Errorf("%q isn't a HardyOS user name or a domain user written DOMAIN\\name", p.Name)
			}
			p.Name = n
		case KindGroup:
			if !domainNameRE.MatchString(p.Name) {
				return nil, fmt.Errorf("group %q: write domain groups as DOMAIN\\group", p.Name)
			}
		default:
			return nil, fmt.Errorf("kind must be user, group or everyone, not %q", p.Kind)
		}
		key := p.Kind + "\x00" + strings.ToLower(p.Name)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind > out[j].Kind // users first, then groups
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

// Who is a signed-in person, for access checks.
type Who struct {
	// Username: "alice" for a HardyOS account, "HOME\alice" for a domain one.
	Username string
	// Groups the person is in, as "HOME\Family" (domain accounts only).
	Groups []string
	Admin  bool
}

// MayUse reports whether who may use an app with these access rules.
// Administrators may use every app; no rules means everyone.
func MayUse(rules []Principal, who Who) bool {
	if who.Admin || len(rules) == 0 {
		return true
	}
	for _, r := range rules {
		switch r.Kind {
		case KindEveryone:
			return true
		case KindUser:
			if strings.EqualFold(r.Name, who.Username) {
				return true
			}
		case KindGroup:
			for _, g := range who.Groups {
				if strings.EqualFold(r.Name, g) {
					return true
				}
			}
		}
	}
	return false
}

// Access returns who may use an app (empty = everyone).
func (s *Store) Access(ctx context.Context, appID string) ([]Principal, error) {
	all, err := s.queryAccess(ctx, `WHERE app_id = ?`, appID)
	if err != nil {
		return nil, err
	}
	if l := all[appID]; l != nil {
		return l, nil
	}
	return []Principal{}, nil
}

// AllAccess returns every app's access list, by app id.
func (s *Store) AllAccess(ctx context.Context) (map[string][]Principal, error) {
	return s.queryAccess(ctx, "")
}

func (s *Store) queryAccess(ctx context.Context, where string, args ...any) (map[string][]Principal, error) {
	db, err := s.db()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT app_id, kind, name FROM app_access `+where+` ORDER BY app_id, kind DESC, name COLLATE NOCASE`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]Principal{}
	for rows.Next() {
		var id string
		var p Principal
		if err := rows.Scan(&id, &p.Kind, &p.Name); err != nil {
			return nil, err
		}
		out[id] = append(out[id], p)
	}
	return out, rows.Err()
}

// SetAccess replaces who may use an app. The list must be normalized.
func (s *Store) SetAccess(ctx context.Context, appID string, list []Principal) error {
	db, err := s.db()
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM app_access WHERE app_id = ?`, appID); err != nil {
		return err
	}
	for _, p := range list {
		// "Everyone" is stored as no rows.
		if p.Kind == KindEveryone {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO app_access (app_id, kind, name) VALUES (?, ?, ?)`, appID, p.Kind, p.Name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ForgetApp removes an app's access list and proxy port (its data is gone).
func (s *Store) ForgetApp(ctx context.Context, appID string) error {
	db, err := s.db()
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM app_access WHERE app_id = ?`, appID); err != nil {
		return err
	}
	if _, err = db.ExecContext(ctx, `DELETE FROM app_origins WHERE app_id = ?`, appID); err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `DELETE FROM app_proxy_ports WHERE app_id = ?`, appID)
	return err
}

// Origin is where hardyd installed an app from.
type Origin struct {
	AppID  string
	Source string
	// CatalogID and CatalogName name the imported catalog (imported apps).
	CatalogID   int64
	CatalogName string
	// Ref is the package installed last (app id or SHA-256).
	Ref string
}

// SetOrigin records where an app was installed from.
func (s *Store) SetOrigin(ctx context.Context, o Origin) error {
	db, err := s.db()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO app_origins (app_id, source, catalog_id, catalog_name, ref) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(app_id) DO UPDATE SET source = excluded.source, catalog_id = excluded.catalog_id,
		catalog_name = excluded.catalog_name, ref = excluded.ref`, o.AppID, o.Source, o.CatalogID, o.CatalogName, o.Ref)
	return err
}

// OriginOf returns where an app was installed from, or nil when hardyd has
// no record (installed before records were kept, or no database).
func (s *Store) OriginOf(ctx context.Context, appID string) *Origin {
	db, err := s.db()
	if err != nil {
		return nil
	}
	o := Origin{AppID: appID}
	if err := db.QueryRowContext(ctx, `SELECT source, catalog_id, catalog_name, ref FROM app_origins WHERE app_id = ?`, appID).
		Scan(&o.Source, &o.CatalogID, &o.CatalogName, &o.Ref); err != nil {
		return nil
	}
	return &o
}

// ProxyPorts returns every app's window proxy port.
func (s *Store) ProxyPorts(ctx context.Context) (map[string]int, error) {
	db, err := s.db()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT app_id, port FROM app_proxy_ports`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var port int
		if err := rows.Scan(&id, &port); err != nil {
			return nil, err
		}
		out[id] = port
	}
	return out, rows.Err()
}

// AllocateProxyPort gives an app the lowest free port from base up (skipping
// avoid, ports that turned out to be taken) and records it.
func (s *Store) AllocateProxyPort(ctx context.Context, appID string, base int, avoid map[int]bool) (int, error) {
	db, err := s.db()
	if err != nil {
		return 0, err
	}
	used, err := s.ProxyPorts(ctx)
	if err != nil {
		return 0, err
	}
	taken := map[int]bool{}
	for id, p := range used {
		if id != appID {
			taken[p] = true
		}
	}
	for port := base; port < base+1000 && port <= 65535; port++ {
		if taken[port] || avoid[port] {
			continue
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO app_proxy_ports (app_id, port) VALUES (?, ?)
			ON CONFLICT(app_id) DO UPDATE SET port = excluded.port`, appID, port); err != nil {
			return 0, err
		}
		return port, nil
	}
	return 0, fmt.Errorf("no free port for %s's window from %d", appID, base)
}
