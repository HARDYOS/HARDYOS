package office

import (
	"mime"
	"path"
	"regexp"

	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DSPrefix is where the Document Server is reached through hardyd, on the
// office origin and on files.<base> (decision 254). It's under /s/ so the
// files host, which serves nothing outside /s/, can carry it.
const DSPrefix = "/s/-/ds"

// GateCookie lets a browser use the Document Server proxy: set by an
// editor page hardyd served (to a signed-in person or a share link
// visitor), 12 hours.
const (
	GateCookie       = "__Host-hardyos_office"
	gateCookiePlain  = "hardyos_office" // plain HTTP (development)
	GateLifetime     = 12 * time.Hour
	gateCookieMaxLen = 200
)

// Gate signs and checks the proxy cookie with a per-process key.
type Gate struct {
	once sync.Once
	key  []byte
	Now  func() time.Time
}

func (g *Gate) init() {
	g.once.Do(func() {
		if g.key == nil {
			g.key = make([]byte, 32)
			_, _ = rand.Read(g.key)
		}
	})
}

func (g *Gate) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *Gate) sign(host string, exp int64) string {
	m := hmac.New(sha256.New, g.key)
	m.Write([]byte("hardyos-office-gate\x00" + strings.ToLower(host) + "\x00" + strconv.FormatInt(exp, 10)))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Set gives the browser the cookie for this host.
func (g *Gate) Set(w http.ResponseWriter, r *http.Request) {
	g.init()
	exp := g.now().Add(GateLifetime).Unix()
	name := GateCookie
	if r.TLS == nil {
		name = gateCookiePlain
	}
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: strconv.FormatInt(exp, 10) + "." + g.sign(r.Host, exp), Path: "/",
		MaxAge: int(GateLifetime / time.Second), HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
}

// Valid reports whether the request carries a live cookie for its host.
func (g *Gate) Valid(r *http.Request) bool {
	g.init()
	name := GateCookie
	if r.TLS == nil {
		name = gateCookiePlain
	}
	c, err := r.Cookie(name)
	if err != nil || len(c.Value) > gateCookieMaxLen {
		return false
	}
	ts, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	exp, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || g.now().Unix() > exp {
		return false
	}
	return hmac.Equal([]byte(sig), []byte(g.sign(r.Host, exp)))
}

// allowedDS are the Document Server paths browsers use (decision 264): the
// editors' code and fonts, the co-editing socket, the file cache, uploads
// (inserted images), downloads, printing and spelling dictionaries, plus
// "download as" and its large-file path. Everything else (the command and
// conversion services, the admin panel, the example, plugins, WOPI, info)
// isn't proxied at all.
var allowedDS = []string{
	"/web-apps/", "/sdkjs/", "/fonts/", "/doc/", "/cache/files/", "/upload/",
	"/downloadfile/", "/printfile/", "/dictionaries/", "/downloadas/", "/savefile/",
}

// versionRE is the version segment the Document Server puts in front of
// its static paths ("/9.4.0-129/").
var versionRE = regexp.MustCompile(`^/[0-9]{1,4}(\.[0-9]{1,4}){0,3}-[0-9A-Za-z]{1,32}/`)

// dsPath checks a request's escaped path below DSPrefix and returns the
// path the Document Server sees with the version segment taken off (for
// matching only), or false. Encoded slashes, backslashes and dots, double
// slashes and anything path.Clean would change are refused, so what was
// checked is exactly what's forwarded.
func dsPath(escaped string) (rest, unversioned string, ok bool) {
	rest, found := strings.CutPrefix(escaped, DSPrefix)
	if !found || !strings.HasPrefix(rest, "/") || len(rest) > 4096 {
		return "", "", false
	}
	low := strings.ToLower(rest)
	if strings.Contains(low, "%2f") || strings.Contains(low, "%5c") || strings.Contains(low, "%2e") || strings.Contains(low, "%00") ||
		strings.ContainsAny(rest, "\\\x00") || strings.Contains(rest, "//") {
		return "", "", false
	}
	if c := path.Clean(rest); c != rest && c+"/" != rest {
		return "", "", false
	}
	dec, err := url.PathUnescape(rest)
	if err != nil || dec != path.Clean(dec) && path.Clean(dec)+"/" != dec {
		return "", "", false
	}
	unversioned = rest
	if m := versionRE.FindString(rest); m != "" {
		unversioned = rest[len(m)-1:]
	}
	for _, a := range allowedDS {
		if strings.HasPrefix(unversioned, a) {
			return rest, unversioned, true
		}
	}
	return "", "", false
}

// dsPathAllowed reports whether an escaped path below the prefix may be
// proxied (tests).
func dsPathAllowed(rest string) bool {
	_, _, ok := dsPath(DSPrefix + rest)
	return ok
}

// fileLike: responses that are someone's file, not the editor's own code.
func fileLike(unversioned string) bool {
	return strings.HasPrefix(unversioned, "/cache/files/") || strings.HasPrefix(unversioned, "/upload/")
}

// Proxy is the Document Server behind hardyd at DSPrefix.
type Proxy struct {
	Service *Service
	Gate    *Gate

	once sync.Once
	rp   *httputil.ReverseProxy
}

func (p *Proxy) init() {
	p.once.Do(func() {
		p.rp = &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				in, err := p.Service.Internal()
				if err != nil {
					return
				}
				rest, _, ok := dsPath(pr.In.URL.EscapedPath())
				if !ok {
					return
				}
				pr.SetURL(in)
				// Exactly the path that was checked, as it was written.
				dec, _ := url.PathUnescape(rest)
				pr.Out.URL.Path, pr.Out.URL.RawPath = dec, rest
				pr.Out.Host = in.Host
				scheme := "http"
				if pr.In.TLS != nil {
					scheme = "https"
				}
				// OnlyOffice's documented way to run under a virtual path:
				// the prefix rides in X-Forwarded-Host, so every URL the
				// Document Server builds points back through this proxy.
				pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host+DSPrefix)
				pr.Out.Header.Set("X-Forwarded-Proto", scheme)
				pr.Out.Header.Del("X-Forwarded-For")
				pr.Out.Header.Del("Forwarded")
				// HardyOS's cookies (the desktop session, link passwords, the
				// gate) never reach the Document Server.
				pr.Out.Header.Del("Cookie")
				pr.Out.Header.Del("Authorization")
			},
			ModifyResponse: func(resp *http.Response) error {
				h := resp.Header
				h.Del("Set-Cookie")
				h.Del("X-Frame-Options")
				h.Del("Content-Security-Policy")
				h.Del("Strict-Transport-Security")
				// Only the editor page on this origin may frame it.
				h.Set("Content-Security-Policy", "frame-ancestors 'self'")
				h.Set("X-Content-Type-Options", "nosniff")
				h.Set("Referrer-Policy", "no-referrer")
				// Files from the cache and uploads (documents, inserted images)
				// never run as a page on this origin: opened directly they
				// download, framed they're sandboxed (PDFs excepted, which
				// browsers won't show sandboxed; print uses them). The editor's
				// own fetches of them aren't pages and are unaffected.
				if _, unv, ok := dsPath(DSPrefix + resp.Request.URL.EscapedPath()); ok && fileLike(unv) {
					switch resp.Request.Header.Get("Sec-Fetch-Dest") {
					case "", "document", "embed", "object":
						h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
						name := path.Base(resp.Request.URL.Path)
						h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
					case "iframe", "frame":
						if !strings.HasPrefix(strings.ToLower(h.Get("Content-Type")), "application/pdf") {
							h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
						}
					}
				}
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				http.Error(w, "The Document Server isn't answering.", http.StatusBadGateway)
			},
		}
	})
}

// ServeHTTP proxies one request under DSPrefix.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.init()
	if _, _, ok := dsPath(r.URL.EscapedPath()); !ok {
		http.NotFound(w, r)
		return
	}
	if !p.Gate.Valid(r) {
		http.Error(w, "Open the document again.", http.StatusForbidden)
		return
	}
	if _, err := p.Service.Internal(); err != nil {
		http.Error(w, "The office suite isn't running.", http.StatusServiceUnavailable)
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	p.Service.NoteBase((&url.URL{Scheme: scheme, Host: r.Host, Path: DSPrefix}).String())
	p.rp.ServeHTTP(w, r)
}
