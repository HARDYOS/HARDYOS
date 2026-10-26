package sharelinks

import (
	"archive/zip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/clientip"
	"github.com/hardyos/hardyos/daemon/internal/files"
)

//go:embed page/*
var pageFS embed.FS

var pageTmpl = template.Must(template.ParseFS(pageFS, "page/page.html"))

// Limits for one link's folder download (zip) and uploads.
const (
	zipMaxEntries  = 20000
	zipMaxDepth    = 32
	unlockLifetime = 12 * time.Hour
	// DefaultMaxFileBytes caps one uploaded file (5 GB); never more than
	// what's left of the link's upload budget.
	DefaultMaxFileBytes = 5_000_000_000
	// A download ticket lets a resumed download (or a video player asking
	// for the next part) go on without counting again, for this long.
	ticketLifetime = 6 * time.Hour
	// Upload budget is reserved in steps this big as the bytes arrive.
	reserveStep = 8 << 20
)

// Public serves the link pages at /s/<token> outside the desktop session:
// no React, no scripts, a strict CSP. Every request looks the link up again,
// checks it is still usable, asks Owner who made it now (an error stops the
// link) and reads files as that person through Files.
type Public struct {
	Links *Store
	Files files.Access
	// Owner returns who the link's creator is right now; any error (account
	// deleted or disabled, gone from the domain) stops the link.
	Owner func(ctx context.Context, userID int64) (files.Who, error)
	// Audit records downloads, uploads and wrong passwords.
	Audit func(r *http.Request, l *Link, action, target string, outcome audit.Outcome, detail string)
	Log   *slog.Logger
	// Insecure allows the unlock cookie over plain HTTP.
	Insecure bool
	// ClientIP says which address a request is from; nil uses the
	// connection's peer. hardyd passes a clientip.Resolver, which believes
	// X-Forwarded-For only from configured trusted proxies.
	ClientIP func(*http.Request) string
	// PerIP and PerToken cap requests.
	PerIP, PerToken *RateLimiter
	// Passwords throttles wrong passwords per link and address (5 in 15
	// minutes by default); LinkPasswords is the much higher ceiling for a
	// link from everyone together (200 in 15 minutes), so one visitor with
	// the link can't lock everybody else out.
	Passwords, LinkPasswords *auth.LoginLimiter
	// MaxFileBytes caps one uploaded file (default DefaultMaxFileBytes).
	MaxFileBytes int64
	// ZipsPerLink and ZipsPerIP cap folder zips being made at once
	// (defaults 1 and 2); more get 429.
	ZipsPerLink, ZipsPerIP int
	Now                    func() time.Time

	key  []byte
	mu   sync.Mutex
	zips map[string]int // "link:<id>" and "ip:<address>" -> zips running
}

func (p *Public) init() {
	if p.PerIP == nil {
		p.PerIP = NewRateLimiter(240, time.Minute)
	}
	if p.PerToken == nil {
		p.PerToken = NewRateLimiter(600, time.Minute)
	}
	if p.Passwords == nil {
		p.Passwords = auth.NewLoginLimiter()
	}
	if p.LinkPasswords == nil {
		p.LinkPasswords = &auth.LoginLimiter{MaxFailures: 200, Window: 15 * time.Minute, Lockout: 15 * time.Minute}
	}
	if p.MaxFileBytes == 0 {
		p.MaxFileBytes = DefaultMaxFileBytes
	}
	if p.ZipsPerLink == 0 {
		p.ZipsPerLink = 1
	}
	if p.ZipsPerIP == 0 {
		p.ZipsPerIP = 2
	}
	if p.Log == nil {
		p.Log = slog.Default()
	}
	if p.key == nil {
		p.key = make([]byte, 32)
		_, _ = rand.Read(p.key)
	}
}

func (p *Public) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Register adds the link routes to mux.
func (p *Public) Register(mux *http.ServeMux) {
	p.init()
	mux.HandleFunc("GET /s/-/static/{asset}", p.static)
	mux.HandleFunc("GET /s/{token}", p.page)
	mux.HandleFunc("POST /s/{token}/unlock", p.unlock)
	mux.HandleFunc("GET /s/{token}/download", p.download)
	mux.HandleFunc("POST /s/{token}/upload", p.upload)
}

func (p *Public) static(w http.ResponseWriter, r *http.Request) {
	var ct string
	switch r.PathValue("asset") {
	case "style.css":
		ct = "text/css; charset=utf-8"
	case "mark.svg":
		ct = "image/svg+xml"
	default:
		http.NotFound(w, r)
		return
	}
	b, err := pageFS.ReadFile("page/" + r.PathValue("asset"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(b)
}

// visit is one checked request on a link.
type visit struct {
	link  *Link
	who   files.Who
	token string
	root  *files.Entry
	// usedUp: the download limit is reached; only a resumed download
	// (with its ticket) may go on.
	usedUp bool
}

func pageHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("Cache-Control", "no-store")
}

// ip is the address the request is from (see ClientIP).
func (p *Public) ip(r *http.Request) string {
	if p.ClientIP != nil {
		return p.ClientIP(r)
	}
	return clientip.Peer(r)
}

// open checks the link behind the request. It writes the error page and
// returns nil when the link can't be used (passwordForm: show the form
// rather than refusing; download: a used-up link is left to download to
// refuse, which lets a resumed download finish).
func (p *Public) open(w http.ResponseWriter, r *http.Request, passwordForm, download bool) *visit {
	p.init()
	pageHeaders(w)
	token := r.PathValue("token")
	if !p.PerIP.Allow("ip:"+p.ip(r)) || !p.PerToken.Allow("t:"+HashToken(token)) {
		w.Header().Set("Retry-After", "60")
		p.errorPage(w, http.StatusTooManyRequests, "Slow down", "Too many requests. Wait a minute and try again.", nil)
		return nil
	}
	l, err := p.Links.ByToken(r.Context(), token)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			p.Log.Error("share link lookup", "err", err)
		}
		p.errorPage(w, http.StatusNotFound, "Link not found", ErrNotFound.Error(), nil)
		return nil
	}
	usedUp := false
	if err := l.Usable(p.now()); err != nil {
		if !download || !errors.Is(err, ErrUsedUp) {
			p.errorPage(w, http.StatusGone, "This link doesn't work any more", sentence(err), l)
			return nil
		}
		usedUp = true
	}
	who, err := p.Owner(r.Context(), l.CreatedByID)
	if err != nil {
		p.errorPage(w, http.StatusGone, "This link doesn't work any more", sentence(ErrOwnerGone), l)
		return nil
	}
	v := &visit{link: l, who: who, token: token, usedUp: usedUp}
	if l.HasPassword && !p.unlocked(r, l) {
		if passwordForm {
			p.render(w, http.StatusOK, view{Kind: "password", Title: "Enter the password", UnlockURL: "/s/" + token + "/unlock"}, l)
		} else {
			p.errorPage(w, http.StatusForbidden, "Enter the password first", "Open the link again and enter its password.", l)
		}
		return nil
	}
	e, err := p.Files.Stat(r.Context(), who, l.Share, l.Path)
	if err != nil || e.Dir != l.Dir {
		// Moved, deleted, or the person who shared it can't read it any more.
		p.errorPage(w, http.StatusGone, "This link doesn't work any more", "What it pointed at was moved or deleted, or isn't shared any more.", l)
		return nil
	}
	v.root = e
	return v
}

func sentence(err error) string {
	s := err.Error()
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:] + "."
}

// subPath reads ?path= for folder links.
func (p *Public) subPath(w http.ResponseWriter, r *http.Request, v *visit) (string, bool) {
	sub, err := CleanPath(r.URL.Query().Get("path"))
	if err != nil || (sub != "" && !v.link.Dir) {
		p.errorPage(w, http.StatusBadRequest, "Not found", "There's nothing at that address in this link.", v.link)
		return "", false
	}
	return sub, true
}

// view is the data the page template gets.
type view struct {
	Kind, Title, Message string
	SharedBy, Expires    string
	UnlockURL            string
	DownloadURL          string
	UploadURL            string
	UploadNote           string
	Size, Modified       string
	Crumbs               []crumb
	Entries              []row
}

type crumb struct{ Name, URL string }
type row struct {
	Name, URL, Size, Modified string
	Dir                       bool
}

func (p *Public) render(w http.ResponseWriter, status int, v view, l *Link) {
	if l != nil {
		v.SharedBy = displayPrincipal(l.CreatedBy)
		if l.Status == StatusActive {
			v.Expires = l.ExpiresAt.Local().Format("Jan 2, 2006")
		}
	} else {
		v.SharedBy = "a HardyOS server"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pageTmpl.ExecuteTemplate(w, "page", v); err != nil {
		p.Log.Warn("render share link page", "err", err)
	}
}

func (p *Public) errorPage(w http.ResponseWriter, status int, title, msg string, l *Link) {
	p.render(w, status, view{Kind: "error", Title: title, Message: msg}, l)
}

// displayPrincipal shows "HOME\alice" as "alice".
func displayPrincipal(s string) string {
	if i := strings.LastIndex(s, `\`); i >= 0 {
		return s[i+1:]
	}
	return s
}

func linkURL(token, action, sub string) string {
	u := "/s/" + token
	if action != "" {
		u += "/" + action
	}
	if sub != "" {
		u += "?path=" + url.QueryEscape(sub)
	}
	return u
}

func (p *Public) page(w http.ResponseWriter, r *http.Request) {
	v := p.open(w, r, true, false)
	if v == nil {
		return
	}
	sub, ok := p.subPath(w, r, v)
	if !ok {
		return
	}
	l := v.link
	title := l.Name
	if title == "" {
		title = p.shareName(r.Context(), v)
	}
	if !l.Dir {
		p.render(w, http.StatusOK, view{
			Kind: "file", Title: title, DownloadURL: linkURL(v.token, "download", ""),
			Size: humanBytes(v.root.Size), Modified: v.root.Modified.Local().Format("Jan 2, 2006 15:04"),
		}, l)
		return
	}
	target := Join(l.Path, sub)
	list, err := p.Files.List(r.Context(), v.who, l.Share, target)
	if err != nil {
		p.errorPage(w, http.StatusNotFound, "Not found", "That folder isn't there any more.", l)
		return
	}
	entries := make([]row, 0, len(list))
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Dir != list[j].Dir {
			return list[i].Dir
		}
		return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name)
	})
	for _, e := range list {
		if Hidden(e.Name) || e.Name == "" || strings.Contains(e.Name, "/") {
			continue
		}
		child := Join(sub, e.Name)
		rw := row{Name: e.Name, Dir: e.Dir, Modified: e.Modified.Local().Format("Jan 2, 2006")}
		if e.Dir {
			rw.URL = linkURL(v.token, "", child)
		} else {
			rw.URL = linkURL(v.token, "download", child)
			rw.Size = humanBytes(e.Size)
		}
		entries = append(entries, rw)
	}
	crumbs := []crumb{{Name: title, URL: linkURL(v.token, "", "")}}
	if sub != "" {
		parts := strings.Split(sub, "/")
		for i, part := range parts {
			crumbs = append(crumbs, crumb{Name: part, URL: linkURL(v.token, "", strings.Join(parts[:i+1], "/"))})
		}
	}
	crumbs[len(crumbs)-1].URL = ""
	pv := view{Kind: "folder", Title: title, Crumbs: crumbs, Entries: entries, DownloadURL: linkURL(v.token, "download", sub)}
	if l.AllowUpload {
		pv.UploadURL = linkURL(v.token, "upload", sub)
		left := l.MaxUploadBytes - l.UploadedBytes
		if left < 0 {
			left = 0
		}
		pv.UploadNote = fmt.Sprintf("Up to %s per file; %s more in all.", humanBytes(min(p.MaxFileBytes, left)), humanBytes(left))
	}
	if n := r.URL.Query().Get("uploaded"); n != "" {
		if c, err := strconv.Atoi(n); err == nil && c > 0 {
			pv.Message = fmt.Sprintf("Uploaded %d file%s.", c, plural(c))
		}
	}
	p.render(w, http.StatusOK, pv, l)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func (p *Public) shareName(ctx context.Context, v *visit) string {
	if list, err := p.Files.Shares(ctx, v.who); err == nil {
		for _, s := range list {
			if s.ID == v.link.Share {
				return s.Name
			}
		}
	}
	return "Shared folder"
}

func (p *Public) download(w http.ResponseWriter, r *http.Request) {
	v := p.open(w, r, false, true)
	if v == nil {
		return
	}
	sub, ok := p.subPath(w, r, v)
	if !ok {
		return
	}
	l := v.link
	target := Join(l.Path, sub)
	e := v.root
	if sub != "" {
		var err error
		if e, err = p.Files.Stat(r.Context(), v.who, l.Share, target); err != nil {
			p.errorPage(w, http.StatusNotFound, "Not found", "That file isn't there any more.", l)
			return
		}
	}
	if e.Dir {
		p.downloadZip(w, r, v, e, target)
		return
	}
	f, fe, err := p.Files.Open(r.Context(), v.who, l.Share, target)
	if err != nil {
		p.errorPage(w, http.StatusNotFound, "Not found", "That file can't be opened right now.", l)
		return
	}
	defer f.Close()
	// HEAD tells what GET would (size, type, date) and is never counted.
	if r.Method == http.MethodHead && v.usedUp {
		p.errorPage(w, http.StatusGone, "This link doesn't work any more", sentence(ErrUsedUp), l)
		return
	}
	if r.Method != http.MethodHead {
		ranges, err := parseRange(r.Header.Get("Range"))
		if err != nil {
			// What net/http would answer too, without a byte of the file.
			w.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(fe.Size, 10))
			http.Error(w, "The range asked for isn't valid.", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		// A download is counted once per file, not for each part a video
		// player or a resumed download asks for: a request for one part
		// that doesn't start at the beginning goes on uncounted only with
		// the ticket the counted download set. Anything else is a new
		// download, and refused when the limit is reached.
		resume := isResume(r, ranges, fe) && p.hasTicket(r, l, target)
		if !resume {
			if v.usedUp {
				p.errorPage(w, http.StatusGone, "This link doesn't work any more", sentence(ErrUsedUp), l)
				return
			}
			if err := p.Links.CountDownload(r.Context(), l.ID); err != nil {
				p.errorPage(w, http.StatusGone, "This link doesn't work any more", sentence(ErrUsedUp), l)
				return
			}
			p.audit(r, l, "sharelink.download", target, audit.Success, "")
			p.setTicket(w, r, v, target)
		}
	}
	downloadHeaders(w)
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": fe.Name}))
	http.ServeContent(w, r, fe.Name, fe.Modified, f)
}

func downloadHeaders(w http.ResponseWriter) {
	h := w.Header()
	// Never shown inline: someone's HTML or SVG must not run on this server's origin.
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
}

// byteRange is one part of a Range header: start (-1 for "the last
// suffix bytes") and end (-1 for "to the end").
type byteRange struct{ start, end, suffix int64 }

// parseRange reads a Range header as net/http's ServeContent does
// ("bytes=" then comma separated parts, spaces around parts ignored,
// empty parts skipped). "" is no range. An error is a header ServeContent
// would refuse too (416) or one this reads differently, which is refused.
func parseRange(s string) ([]byteRange, error) {
	if s == "" {
		return nil, nil
	}
	const b = "bytes="
	if !strings.HasPrefix(s, b) {
		return nil, errors.New("invalid range")
	}
	var out []byteRange
	for _, ra := range strings.Split(s[len(b):], ",") {
		ra = strings.Trim(ra, " \t")
		if ra == "" {
			continue
		}
		start, end, ok := strings.Cut(ra, "-")
		if !ok {
			return nil, errors.New("invalid range")
		}
		start, end = strings.Trim(start, " \t"), strings.Trim(end, " \t")
		if start == "" {
			// "-N": the last N bytes.
			n, err := strconv.ParseInt(end, 10, 64)
			if err != nil || n < 0 || end == "" || end[0] == '-' || end[0] == '+' {
				return nil, errors.New("invalid range")
			}
			out = append(out, byteRange{start: -1, end: -1, suffix: n})
			continue
		}
		i, err := strconv.ParseInt(start, 10, 64)
		if err != nil || i < 0 || start[0] == '+' {
			return nil, errors.New("invalid range")
		}
		r := byteRange{start: i, end: -1}
		if end != "" {
			j, err := strconv.ParseInt(end, 10, 64)
			if err != nil || j < i || end[0] == '+' {
				return nil, errors.New("invalid range")
			}
			r.end = j
		}
		out = append(out, r)
	}
	return out, nil
}

// isResume reports whether the request can only be answered with one part
// of the file that doesn't include its first byte: exactly one range, not
// from byte 0, and no If-Range that would make ServeContent send it all.
func isResume(r *http.Request, ranges []byteRange, fe *files.Entry) bool {
	if len(ranges) != 1 || len(r.Header.Values("Range")) != 1 {
		return false
	}
	rg := ranges[0]
	if rg.start == -1 {
		if rg.suffix >= fe.Size {
			return false // the whole file
		}
	} else if rg.start == 0 {
		return false
	}
	if ir := r.Header.Get("If-Range"); ir != "" {
		// No ETag is sent, so an ETag never matches (the whole file);
		// a date matches as ServeContent checks it.
		t, err := http.ParseTime(ir)
		if err != nil || fe.Modified.IsZero() || fe.Modified.Truncate(time.Second).After(t) {
			return false
		}
	}
	return true
}

// Download tickets: a cookie scoped to the link, one per file, holding an
// expiry and an HMAC of link id, file path and expiry.
func ticketName(l *Link, target string) string {
	sum := sha256.Sum256([]byte(target))
	return "hardyos_dl_" + strconv.FormatInt(l.ID, 10) + "_" + base64.RawURLEncoding.EncodeToString(sum[:9])
}

func (p *Public) ticketMAC(l *Link, target string, exp int64) string {
	m := hmac.New(sha256.New, p.key)
	fmt.Fprintf(m, "download|%d|%s|%d", l.ID, target, exp)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (p *Public) setTicket(w http.ResponseWriter, r *http.Request, v *visit, target string) {
	exp := p.now().Add(ticketLifetime)
	http.SetCookie(w, &http.Cookie{
		Name:  ticketName(v.link, target),
		Value: strconv.FormatInt(exp.Unix(), 10) + "." + p.ticketMAC(v.link, target, exp.Unix()),
		Path:  "/s/" + v.token, Expires: exp, MaxAge: int(ticketLifetime.Seconds()),
		HttpOnly: true, Secure: r.TLS != nil || !p.Insecure, SameSite: http.SameSiteLaxMode,
	})
}

func (p *Public) hasTicket(r *http.Request, l *Link, target string) bool {
	c, err := r.Cookie(ticketName(l, target))
	if err != nil {
		return false
	}
	es, mac, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	e, err := strconv.ParseInt(es, 10, 64)
	if err != nil || p.now().Unix() >= e || e > p.now().Add(ticketLifetime).Unix()+60 {
		return false
	}
	return hmac.Equal([]byte(mac), []byte(p.ticketMAC(l, target, e)))
}

// acquireZip takes one of the link's and the address's zip slots, or
// reports false when they're all in use.
func (p *Public) acquireZip(l *Link, addr string) (release func(), ok bool) {
	lk, ik := "link:"+strconv.FormatInt(l.ID, 10), "ip:"+addr
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.zips == nil {
		p.zips = map[string]int{}
	}
	if p.zips[lk] >= p.ZipsPerLink || p.zips[ik] >= p.ZipsPerIP {
		return nil, false
	}
	p.zips[lk]++
	p.zips[ik]++
	return func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, k := range []string{lk, ik} {
			if p.zips[k]--; p.zips[k] <= 0 {
				delete(p.zips, k)
			}
		}
	}, true
}

// downloadZip sends a folder as a zip, streamed as it's made. Every zip is
// a counted download whatever Range says (a zip has no parts to resume).
func (p *Public) downloadZip(w http.ResponseWriter, r *http.Request, v *visit, e *files.Entry, target string) {
	l := v.link
	name := e.Name
	if name == "" {
		name = p.shareName(r.Context(), v)
	}
	disp := mime.FormatMediaType("attachment", map[string]string{"filename": name + ".zip"})
	if v.usedUp {
		p.errorPage(w, http.StatusGone, "This link doesn't work any more", sentence(ErrUsedUp), l)
		return
	}
	if r.Method == http.MethodHead {
		downloadHeaders(w)
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", disp)
		w.WriteHeader(http.StatusOK)
		return
	}
	release, ok := p.acquireZip(l, p.ip(r))
	if !ok {
		w.Header().Set("Retry-After", "60")
		p.errorPage(w, http.StatusTooManyRequests, "One download at a time",
			"This folder is already being downloaded as a zip. Wait for that download to finish, then try again.", l)
		return
	}
	defer release()
	if err := p.Links.CountDownload(r.Context(), l.ID); err != nil {
		p.errorPage(w, http.StatusGone, "This link doesn't work any more", sentence(ErrUsedUp), l)
		return
	}
	p.audit(r, l, "sharelink.download", target, audit.Success, "folder as zip")
	downloadHeaders(w)
	h := w.Header()
	h.Set("Content-Type", "application/zip")
	h.Set("Content-Disposition", disp)
	z := &linkZip{zw: zip.NewWriter(w), max: l.MaxZipBytes}
	if z.max <= 0 {
		z.max = DefaultZipBytes
	}
	err := p.zipDir(r.Context(), z, v, target, "", 0)
	var stop *zipStop
	switch {
	case errors.As(err, &stop):
		// A bound was reached: the zip ends here, and says so.
		if fw, err := z.zw.Create("Not included.txt"); err == nil {
			fmt.Fprintf(fw, "This download stopped early: %s.\r\nDownload the rest of the folder's files one by one from the link.\r\n", stop.why)
		}
	case err != nil:
		p.Log.Warn("share link zip stopped", "link", l.ID, "err", err)
		panic(http.ErrAbortHandler) // the browser sees a failed download, not a short zip
	}
	if err := z.zw.Close(); err != nil {
		panic(http.ErrAbortHandler)
	}
}

// linkZip is one folder zip being made.
type linkZip struct {
	zw         *zip.Writer
	n          int
	bytes, max int64
}

// zipStop: the zip reached one of its bounds (entries, depth, bytes).
type zipStop struct{ why string }

func (e *zipStop) Error() string { return e.why }

func (p *Public) zipDir(ctx context.Context, z *linkZip, v *visit, dir, prefix string, depth int) error {
	if depth > zipMaxDepth {
		return &zipStop{fmt.Sprintf("folders are nested more than %d deep", zipMaxDepth)}
	}
	list, err := p.Files.List(ctx, v.who, v.link.Share, dir)
	if err != nil {
		return err
	}
	for _, e := range list {
		if err := ctx.Err(); err != nil {
			return err
		}
		if Hidden(e.Name) || e.Name == "" || e.Name == "." || e.Name == ".." || strings.Contains(e.Name, "/") {
			continue
		}
		z.n++
		if z.n > zipMaxEntries {
			return &zipStop{fmt.Sprintf("one zip holds at most %d files and folders", zipMaxEntries)}
		}
		child, name := Join(dir, e.Name), prefix+ZipName(e.Name)
		if e.Dir {
			if _, err := z.zw.CreateHeader(&zip.FileHeader{Name: name + "/", Modified: e.Modified}); err != nil {
				return err
			}
			if err := p.zipDir(ctx, z, v, child, name+"/", depth+1); err != nil {
				return err
			}
			continue
		}
		if z.bytes+e.Size > z.max {
			return &zipStop{fmt.Sprintf("one zip of this link holds at most %s", humanBytes(z.max))}
		}
		f, _, err := p.Files.Open(ctx, v.who, v.link.Share, child)
		if err != nil {
			continue // unreadable files are left out
		}
		fw, err := z.zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: e.Modified})
		var n int64
		if err == nil {
			// A file that grew since it was listed can't take the zip over its bound.
			n, err = io.Copy(fw, io.LimitReader(f, z.max-z.bytes+1))
			z.bytes += n
			if err == nil && z.bytes > z.max {
				err = errors.New("a file grew past the zip's size limit")
			}
		}
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// ZipName makes one file or folder name safe as part of a zip entry name:
// "\" and ":" (folder and drive separators to Windows extractors) and
// control characters become "_"; everything else is kept.
func ZipName(name string) string {
	return strings.Map(func(r rune) rune {
		if r == '\\' || r == ':' || unicode.IsControl(r) {
			return '_'
		}
		return r
	}, name)
}

// sameOrigin rejects cross-site form posts.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" || o == "null" {
		return o == ""
	}
	u, err := url.Parse(o)
	return err == nil && u.Host == r.Host
}

func (p *Public) unlock(w http.ResponseWriter, r *http.Request) {
	p.init()
	pageHeaders(w)
	token := r.PathValue("token")
	if !sameOrigin(r) {
		p.errorPage(w, http.StatusForbidden, "Not allowed", "Open the link again and enter its password there.", nil)
		return
	}
	if !p.PerIP.Allow("ip:"+p.ip(r)) || !p.PerToken.Allow("t:"+HashToken(token)) {
		w.Header().Set("Retry-After", "60")
		p.errorPage(w, http.StatusTooManyRequests, "Slow down", "Too many requests. Wait a minute and try again.", nil)
		return
	}
	l, err := p.Links.ByToken(r.Context(), token)
	if err != nil {
		p.errorPage(w, http.StatusNotFound, "Link not found", ErrNotFound.Error(), nil)
		return
	}
	if err := l.Usable(p.now()); err != nil {
		p.errorPage(w, http.StatusGone, "This link doesn't work any more", sentence(err), l)
		return
	}
	// Wrong passwords lock out one address for one link (5 in 15 minutes);
	// the link as a whole only after many more from everyone together, so
	// one visitor can't lock the others out.
	id := strconv.FormatInt(l.ID, 10)
	ipKey, linkKey := "link:"+id+"|ip:"+p.ip(r), "link:"+id
	for _, c := range []struct {
		lim *auth.LoginLimiter
		key string
	}{{p.Passwords, ipKey}, {p.LinkPasswords, linkKey}} {
		if ok, wait := c.lim.Allowed(c.key); !ok {
			p.render(w, http.StatusTooManyRequests, view{Kind: "password", Title: "Enter the password", UnlockURL: "/s/" + token + "/unlock",
				Message: fmt.Sprintf("Too many wrong passwords. Try again in %d minutes.", int(wait.Minutes())+1)}, l)
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	pw := r.PostFormValue("password")
	if !l.CheckPassword(pw) {
		p.Passwords.Fail(ipKey)
		p.LinkPasswords.Fail(linkKey)
		p.audit(r, l, "sharelink.password", l.Share+"/"+l.Path, audit.Denied, "wrong password")
		p.render(w, http.StatusUnauthorized, view{Kind: "password", Title: "Enter the password", UnlockURL: "/s/" + token + "/unlock",
			Message: "That password isn't right."}, l)
		return
	}
	p.Passwords.Succeed(ipKey)
	exp := p.now().Add(unlockLifetime)
	if exp.After(l.ExpiresAt) {
		exp = l.ExpiresAt
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName(l), Value: p.unlockValue(l, exp), Path: "/s/" + token, Expires: exp,
		HttpOnly: true, Secure: r.TLS != nil || !p.Insecure, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/s/"+token, http.StatusSeeOther)
}

func cookieName(l *Link) string { return "hardyos_link_" + strconv.FormatInt(l.ID, 10) }

func (p *Public) unlockMAC(l *Link, exp int64) string {
	m := hmac.New(sha256.New, p.key)
	fmt.Fprintf(m, "%d|%s|%d", l.ID, l.passwordStamp(), exp)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (p *Public) unlockValue(l *Link, exp time.Time) string {
	e := exp.Unix()
	return strconv.FormatInt(e, 10) + "." + p.unlockMAC(l, e)
}

func (p *Public) unlocked(r *http.Request, l *Link) bool {
	c, err := r.Cookie(cookieName(l))
	if err != nil {
		return false
	}
	es, mac, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	e, err := strconv.ParseInt(es, 10, 64)
	if err != nil || p.now().Unix() >= e {
		return false
	}
	return hmac.Equal([]byte(mac), []byte(p.unlockMAC(l, e)))
}

// uploadName makes a browser's file name safe to create: its last part,
// nothing starting with "." (hidden files, and HardyOS's own), no control
// characters.
func uploadName(raw string) (string, bool) {
	n := strings.ReplaceAll(raw, `\`, "/")
	n = strings.TrimSpace(path.Base(n))
	if n == "" || n == "/" || strings.HasPrefix(n, ".") || Hidden(n) || len(n) > 255 {
		return "", false
	}
	for _, r := range n {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return "", false
		}
	}
	return n, true
}

// numbered gives "photo (2).jpg" for "photo.jpg".
func numbered(name string, n int) string {
	ext := path.Ext(name)
	if ext == name {
		ext = ""
	}
	return fmt.Sprintf("%s (%d)%s", strings.TrimSuffix(name, ext), n, ext)
}

// errFileTooBig: one uploaded file is over the per-file cap.
var errFileTooBig = errors.New("file too big")

func (p *Public) upload(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		pageHeaders(w)
		p.errorPage(w, http.StatusForbidden, "Not allowed", "Upload from the link's own page.", nil)
		return
	}
	v := p.open(w, r, false, false)
	if v == nil {
		return
	}
	l := v.link
	if !l.Dir || !l.AllowUpload {
		p.errorPage(w, http.StatusForbidden, "Uploads are off", "This link doesn't take uploads.", l)
		return
	}
	sub, ok := p.subPath(w, r, v)
	if !ok {
		return
	}
	dir := Join(l.Path, sub)
	left := l.MaxUploadBytes - l.UploadedBytes
	if left <= 0 {
		p.uploadFailed(w, r, l, dir, nil, http.StatusRequestEntityTooLarge, sentence(ErrUploadBudget))
		return
	}
	// The budget is enforced byte by byte below; this only stops a body
	// that can't fit anyway (plus room for the form's own lines).
	r.Body = http.MaxBytesReader(w, r.Body, left+16<<20)
	mr, err := r.MultipartReader()
	if err != nil {
		p.errorPage(w, http.StatusBadRequest, "Upload failed", "Choose the files to upload, then press Upload.", l)
		return
	}
	var names []string
	var total int64
	skipped := 0
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			p.uploadFailed(w, r, l, dir, names, http.StatusBadRequest, "The upload was cut off. Try again.")
			return
		}
		if part.FormName() != "file" || part.FileName() == "" {
			part.Close()
			continue
		}
		name, ok := uploadName(part.FileName())
		if !ok {
			skipped++
			part.Close()
			continue
		}
		n, written, err := p.saveUpload(r.Context(), v, dir, name, part)
		part.Close()
		total += n
		if err != nil {
			status, msg := http.StatusBadRequest, "The upload was cut off. Try again."
			switch {
			case errors.Is(err, files.ErrNoAccess) || errors.Is(err, files.ErrNotAllowed):
				msg = "This folder doesn't take uploads any more."
			case errors.Is(err, errFileTooBig):
				status, msg = http.StatusRequestEntityTooLarge, fmt.Sprintf("%s is too big: this link takes files of up to %s.", name, humanBytes(p.MaxFileBytes))
			case errors.Is(err, ErrUploadBudget):
				status, msg = http.StatusRequestEntityTooLarge, fmt.Sprintf("%s didn't fit: this link takes %s in all, and that's used up.", name, humanBytes(l.MaxUploadBytes))
			}
			p.uploadFailed(w, r, l, dir, names, status, msg)
			return
		}
		names = append(names, written)
	}
	if len(names) == 0 {
		msg := "Choose the files to upload, then press Upload."
		if skipped > 0 {
			msg = "Files whose names start with a dot or have control characters can't be uploaded here. Rename them and try again."
		}
		p.errorPage(w, http.StatusBadRequest, "Nothing uploaded", msg, l)
		return
	}
	p.Links.Touch(r.Context(), l.ID)
	p.audit(r, l, "sharelink.upload", Join(l.Share, dir), audit.Success, fmt.Sprintf("%s (%s)", strings.Join(names, ", "), humanBytes(total)))
	u := linkURL(v.token, "", sub)
	if strings.Contains(u, "?") {
		u += "&"
	} else {
		u += "?"
	}
	http.Redirect(w, r, u+"uploaded="+strconv.Itoa(len(names)), http.StatusSeeOther)
}

func (p *Public) uploadFailed(w http.ResponseWriter, r *http.Request, l *Link, dir string, done []string, status int, msg string) {
	p.audit(r, l, "sharelink.upload", Join(l.Share, dir), audit.Failure, msg)
	if len(done) > 0 {
		msg += fmt.Sprintf(" (%d file%s uploaded before it stopped.)", len(done), plural(len(done)))
	}
	p.errorPage(w, status, "Upload failed", msg, l)
}

// budgetWriter writes one uploaded file, taking its bytes out of the
// link's upload budget as they arrive (reserved in steps, atomically, so
// parallel uploads can't go over the budget together) and refusing more
// than the per-file cap.
type budgetWriter struct {
	ctx            context.Context
	links          *Store
	id             int64
	w              io.Writer
	max            int64 // the per-file cap
	used, reserved int64
}

func (b *budgetWriter) Write(d []byte) (int, error) {
	end := b.used + int64(len(d))
	if end > b.max {
		return 0, errFileTooBig
	}
	if need := end - b.reserved; need > 0 {
		ask := min(max(need, reserveStep), b.max-b.reserved)
		err := b.links.ReserveUpload(b.ctx, b.id, ask)
		if errors.Is(err, ErrUploadBudget) && ask > need {
			ask = need // near the end of the budget: just what this write needs
			err = b.links.ReserveUpload(b.ctx, b.id, ask)
		}
		if err != nil {
			return 0, err
		}
		b.reserved += ask
	}
	n, err := b.w.Write(d)
	b.used += int64(n)
	return n, err
}

// permanentDeleter is files.Extended's delete, which can skip the recycle bin.
type permanentDeleter interface {
	DeleteItem(ctx context.Context, who files.Who, share, path string, permanent bool) (bool, error)
}

// purge deletes a half-written upload for good: it never goes to the
// recycle bin, where it would keep taking space and be nobody's to clean up.
func (p *Public) purge(ctx context.Context, v *visit, target string) {
	d, ok := p.Files.(permanentDeleter)
	if !ok {
		p.Log.Error("share link upload: can't delete a partial upload permanently", "link", v.link.ID)
		return
	}
	if _, err := d.DeleteItem(ctx, v.who, v.link.Share, target, true); err != nil {
		p.Log.Warn("share link upload: deleting a partial upload", "link", v.link.ID, "err", err)
	}
}

// saveUpload writes one file as the link's creator, never replacing
// anything: a taken name gets " (2)", " (3)"...
func (p *Public) saveUpload(ctx context.Context, v *visit, dir, name string, src io.Reader) (int64, string, error) {
	bg := context.WithoutCancel(ctx)
	for i := 1; i <= 100; i++ {
		try := name
		if i > 1 {
			try = numbered(name, i)
		}
		target := Join(dir, try)
		f, err := p.Files.Create(ctx, v.who, v.link.Share, target, false)
		if errors.Is(err, files.ErrExists) {
			continue
		}
		if err != nil {
			return 0, "", err
		}
		bw := &budgetWriter{ctx: bg, links: p.Links, id: v.link.ID, w: f, max: p.MaxFileBytes}
		n, err := io.Copy(bw, src)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			// Don't leave half a file behind, nor its share of the budget.
			p.purge(bg, v, target)
			p.Links.ReleaseUpload(bg, v.link.ID, bw.reserved)
			return n, "", err
		}
		p.Links.ReleaseUpload(bg, v.link.ID, bw.reserved-bw.used)
		return n, try, nil
	}
	return 0, "", files.ErrExists
}

func (p *Public) audit(r *http.Request, l *Link, action, target string, outcome audit.Outcome, detail string) {
	if p.Audit != nil {
		p.Audit(r, l, action, target, outcome, detail)
	}
}

func humanBytes(n int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	v := float64(n)
	i := 0
	for v >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	s := strconv.FormatFloat(v, 'f', 1, 64)
	s = strings.TrimSuffix(s, ".0")
	return s + " " + units[i]
}
