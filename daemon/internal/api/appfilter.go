package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// Per-app request filters: requests HardyOS's proxies (the window proxy
// and the app gateway, the only ways to an app whose port is bound to the
// server itself) keep away from an app, because HardyOS manages what they
// would change (decision 285).

// appFilter returns why a request is refused ("" lets it through). It may
// read the body; it must put it back.
type appFilter func(r *http.Request) string

var appFilters = map[string]appFilter{
	"immich": immichFilter,
}

// filterAppRequest answers a refused request and reports whether it did.
func filterAppRequest(w http.ResponseWriter, r *http.Request, appID string) bool {
	f := appFilters[appID]
	if f == nil {
		return false
	}
	why := f(r)
	if why == "" {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{"message": why, "error": "Forbidden", "statusCode": http.StatusForbidden})
	return true
}

// normalPaths are the ways a server could read a request's path: as sent
// and decoded, lower-cased (Express matches routes case-insensitively),
// with repeated and trailing slashes and dot segments taken out.
func normalPaths(u *url.URL) []string {
	var out []string
	for _, p := range []string{u.Path, u.EscapedPath()} {
		for i := 0; i < 3; i++ { // %2565 and the like
			d, err := url.PathUnescape(p)
			if err != nil || d == p {
				break
			}
			p = d
		}
		p = strings.ToLower(p)
		if i := strings.IndexByte(p, ';'); i >= 0 {
			p = p[:i]
		}
		for strings.Contains(p, "//") {
			p = strings.ReplaceAll(p, "//", "/")
		}
		p = path.Clean("/" + p)
		out = append(out, p)
	}
	return out
}

func requestMethods(r *http.Request) []string {
	m := []string{strings.ToUpper(r.Method)}
	for _, h := range []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"} {
		if v := r.Header.Get(h); v != "" {
			m = append(m, strings.ToUpper(strings.TrimSpace(v)))
		}
	}
	return m
}

const immichManaged = "HardyOS manages this for Immich (Control Panel > Photos)"

// immichFilter keeps people from changing what lets HardyOS tell their
// Immich accounts apart: their own e-mail address and password (PUT
// /api/users/me), unlinking their HardyOS sign-in (POST /api/oauth/unlink),
// and Immich's first sign-up (HardyOS makes Immich's first administrator
// itself, on the server).
func immichFilter(r *http.Request) string {
	writes := false
	for _, m := range requestMethods(r) {
		if m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions {
			writes = true
		}
	}
	if !writes {
		return ""
	}
	for _, p := range normalPaths(r.URL) {
		switch p {
		case "/api/oauth/unlink":
			return "Your Immich account stays linked to your HardyOS account. " + immichManaged
		case "/api/auth/admin-sign-up":
			return immichManaged
		case "/api/users/me":
			if why := immichUserUpdate(r); why != "" {
				return why
			}
		}
	}
	return ""
}

// immichUserUpdate refuses an update of one's own account that sets an
// e-mail address or password, or that HardyOS can't read to tell.
func immichUserUpdate(r *http.Request) string {
	if ce := strings.TrimSpace(r.Header.Get("Content-Encoding")); ce != "" && !strings.EqualFold(ce, "identity") {
		return immichManaged
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
	r.Body.Close()
	if err != nil || len(body) > 64<<10 {
		return immichManaged
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return immichManaged
	}
	for k := range m {
		switch strings.ToLower(k) {
		case "email":
			return "Your e-mail address in Immich is your HardyOS one. " + immichManaged
		case "password":
			return "Sign in with your HardyOS account; Immich's own password isn't used. " + immichManaged
		}
	}
	return ""
}
