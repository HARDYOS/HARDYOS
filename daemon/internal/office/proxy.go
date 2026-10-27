package office

import (
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

// blockedDS are Document Server paths browsers never need: its
// server-to-server APIs (they enforce the JWT anyway), the example app,
// the admin panel, plugins (turned off) and WOPI.
var blockedDS = []string{
	"/coauthoring/", "/converter", "/convertservice.ashx", "/command", "/docbuilder",
	"/info", "/internal/", "/example", "/admin", "/wopi", "/hosting/", "/healthcheck",
	"/sdkjs-plugins/", "/plugins.json", "/metrics",
}

// dsPathAllowed reports whether a path (after the prefix) may be proxied.
// The Document Server puts a version segment ("/9.4.0-129/") in front of
// its static paths; it's skipped for the check.
func dsPathAllowed(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") || strings.Contains(p, "\\") {
		return false
	}
	lp := strings.ToLower(p)
	check := []string{lp}
	if i := strings.IndexByte(lp[1:], '/'); i > 0 {
		seg := lp[1 : i+1]
		if seg != "" && seg[0] >= '0' && seg[0] <= '9' {
			check = append(check, lp[i+1:])
		}
	}
	for _, c := range check {
		for _, b := range blockedDS {
			if strings.HasPrefix(c, b) || c+"/" == b || (strings.HasSuffix(b, "/") && c == strings.TrimSuffix(b, "/")) {
				return false
			}
		}
	}
	return true
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
				pr.SetURL(in)
				pr.Out.URL.Path = strings.TrimPrefix(pr.In.URL.Path, DSPrefix)
				pr.Out.URL.RawPath = ""
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
	rest := strings.TrimPrefix(r.URL.Path, DSPrefix)
	if rest == r.URL.Path || !dsPathAllowed(rest) {
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
