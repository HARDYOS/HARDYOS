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
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/files"
)

//go:embed page/*
var pageFS embed.FS

var pageTmpl = template.Must(template.ParseFS(pageFS, "page/page.html"))

// Limits for one link's folder download (zip) and uploads.
const (
	zipMaxEntries         = 20000
	zipMaxDepth           = 32
	DefaultMaxUploadBytes = 10 << 30
	unlockLifetime        = 12 * time.Hour
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
	// PerIP and PerToken cap requests; Passwords throttles wrong passwords.
	PerIP, PerToken *RateLimiter
	Passwords       *auth.LoginLimiter
	MaxUploadBytes  int64
	Now             func() time.Time

	key []byte
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
	if p.MaxUploadBytes == 0 {
		p.MaxUploadBytes = DefaultMaxUploadBytes
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
}

func pageHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("Cache-Control", "no-store")
}

func ip(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// open checks the link behind the request. It writes the error page and
// returns nil when the link can't be used (needPassword: show the form
// rather than refusing).
func (p *Public) open(w http.ResponseWriter, r *http.Request, passwordForm bool) *visit {
	p.init()
	pageHeaders(w)
	token := r.PathValue("token")
	if !p.PerIP.Allow("ip:"+ip(r)) || !p.PerToken.Allow("t:"+HashToken(token)) {
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
	if err := l.Usable(p.now()); err != nil {
		p.errorPage(w, http.StatusGone, "This link doesn't work any more", sentence(err), l)
		return nil
	}
	who, err := p.Owner(r.Context(), l.CreatedByID)
	if err != nil {
		p.errorPage(w, http.StatusGone, "This link doesn't work any more", sentence(ErrOwnerGone), l)
		return nil
	}
	v := &visit{link: l, who: who, token: token}
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
	v := p.open(w, r, true)
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
	v := p.open(w, r, false)
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
	// A download is counted once per file, not for each part a video
	// player or a resumed download asks for.
	if rg := r.Header.Get("Range"); rg == "" || strings.HasPrefix(rg, "bytes=0-") {
		if err := p.Links.CountDownload(r.Context(), l.ID); err != nil {
			p.errorPage(w, http.StatusGone, "This link doesn't work any more", sentence(ErrUsedUp), l)
			return
		}
		p.audit(r, l, "sharelink.download", target, audit.Success, "")
	}
	h := w.Header()
	// Never shown inline: someone's HTML or SVG must not run on this server's origin.
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	if e.Dir {
		name := e.Name
		if name == "" {
			name = p.shareName(r.Context(), v)
		}
		h.Set("Content-Type", "application/zip")
		h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name + ".zip"}))
		zw := zip.NewWriter(w)
		count := 0
		if err := p.zipDir(r.Context(), zw, v, target, "", 0, &count); err != nil {
			p.Log.Warn("share link zip", "link", l.ID, "err", err)
		}
		_ = zw.Close()
		return
	}
	f, fe, err := p.Files.Open(r.Context(), v.who, l.Share, target)
	if err != nil {
		p.errorPage(w, http.StatusNotFound, "Not found", "That file can't be opened right now.", l)
		return
	}
	defer f.Close()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": fe.Name}))
	http.ServeContent(w, r, fe.Name, fe.Modified, f)
}

func (p *Public) zipDir(ctx context.Context, zw *zip.Writer, v *visit, dir, prefix string, depth int, count *int) error {
	if depth > zipMaxDepth {
		return errors.New("folders nested too deep")
	}
	list, err := p.Files.List(ctx, v.who, v.link.Share, dir)
	if err != nil {
		return err
	}
	for _, e := range list {
		if Hidden(e.Name) || e.Name == "" || e.Name == "." || e.Name == ".." || strings.Contains(e.Name, "/") {
			continue
		}
		*count++
		if *count > zipMaxEntries {
			return errors.New("too many files for one download")
		}
		child, name := Join(dir, e.Name), prefix+e.Name
		if e.Dir {
			if _, err := zw.CreateHeader(&zip.FileHeader{Name: name + "/", Modified: e.Modified}); err != nil {
				return err
			}
			if err := p.zipDir(ctx, zw, v, child, name+"/", depth+1, count); err != nil {
				return err
			}
			continue
		}
		f, _, err := p.Files.Open(ctx, v.who, v.link.Share, child)
		if err != nil {
			continue // unreadable files are left out
		}
		fw, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: e.Modified})
		if err == nil {
			_, err = io.Copy(fw, f)
		}
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
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
	if !p.PerIP.Allow("ip:"+ip(r)) || !p.PerToken.Allow("t:"+HashToken(token)) {
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
	linkKey, ipKey := "link:"+strconv.FormatInt(l.ID, 10), "linkip:"+ip(r)
	for _, k := range []string{linkKey, ipKey} {
		if ok, wait := p.Passwords.Allowed(k); !ok {
			p.render(w, http.StatusTooManyRequests, view{Kind: "password", Title: "Enter the password", UnlockURL: "/s/" + token + "/unlock",
				Message: fmt.Sprintf("Too many wrong passwords. Try again in %d minutes.", int(wait.Minutes())+1)}, l)
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	pw := r.PostFormValue("password")
	if !l.CheckPassword(pw) {
		p.Passwords.Fail(linkKey)
		p.Passwords.Fail(ipKey)
		p.audit(r, l, "sharelink.password", l.Share+"/"+l.Path, audit.Denied, "wrong password")
		p.render(w, http.StatusUnauthorized, view{Kind: "password", Title: "Enter the password", UnlockURL: "/s/" + token + "/unlock",
			Message: "That password isn't right."}, l)
		return
	}
	p.Passwords.Succeed(linkKey)
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
// no hidden or reserved names.
func uploadName(raw string) (string, bool) {
	n := strings.ReplaceAll(raw, `\`, "/")
	n = strings.TrimSpace(path.Base(n))
	if n == "" || n == "." || n == ".." || n == "/" || Hidden(n) || len(n) > 255 || strings.ContainsRune(n, 0) {
		return "", false
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

func (p *Public) upload(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		pageHeaders(w)
		p.errorPage(w, http.StatusForbidden, "Not allowed", "Upload from the link's own page.", nil)
		return
	}
	v := p.open(w, r, false)
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
	r.Body = http.MaxBytesReader(w, r.Body, p.MaxUploadBytes)
	mr, err := r.MultipartReader()
	if err != nil {
		p.errorPage(w, http.StatusBadRequest, "Upload failed", "Choose the files to upload, then press Upload.", l)
		return
	}
	var names []string
	var total int64
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			p.uploadFailed(w, r, l, dir, names, "The upload was cut off. Try again.")
			return
		}
		if part.FormName() != "file" || part.FileName() == "" {
			part.Close()
			continue
		}
		name, ok := uploadName(part.FileName())
		if !ok {
			part.Close()
			continue
		}
		n, written, err := p.saveUpload(r.Context(), v, dir, name, part)
		part.Close()
		total += n
		if err != nil {
			msg := "The upload was cut off. Try again."
			if errors.Is(err, files.ErrNoAccess) || errors.Is(err, files.ErrNotAllowed) {
				msg = "This folder doesn't take uploads any more."
			}
			p.uploadFailed(w, r, l, dir, names, msg)
			return
		}
		names = append(names, written)
	}
	if len(names) == 0 {
		p.errorPage(w, http.StatusBadRequest, "Nothing uploaded", "Choose the files to upload, then press Upload.", l)
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

func (p *Public) uploadFailed(w http.ResponseWriter, r *http.Request, l *Link, dir string, done []string, msg string) {
	p.audit(r, l, "sharelink.upload", Join(l.Share, dir), audit.Failure, msg)
	if len(done) > 0 {
		msg += fmt.Sprintf(" (%d file%s uploaded before it stopped.)", len(done), plural(len(done)))
	}
	p.errorPage(w, http.StatusBadRequest, "Upload failed", msg, l)
}

// saveUpload writes one file as the link's creator, never replacing
// anything: a taken name gets " (2)", " (3)"...
func (p *Public) saveUpload(ctx context.Context, v *visit, dir, name string, src io.Reader) (int64, string, error) {
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
		n, err := io.Copy(f, src)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			// Don't leave half a file behind.
			_ = p.Files.Delete(context.WithoutCancel(ctx), v.who, v.link.Share, target)
			return n, "", err
		}
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
