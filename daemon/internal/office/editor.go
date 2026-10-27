package office

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
)

//go:embed page/*
var pageFS embed.FS

var pageTmpl = template.Must(template.ParseFS(pageFS, "page/editor.html"))

// pageCSP is the editor page's policy: its own two scripts (api.js comes
// through the proxy on this origin), the Document Server's frames from this
// origin, nothing from anywhere else.
func pageCSP(ancestors string) string {
	if ancestors == "" {
		ancestors = "'none'"
	}
	return "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; " +
		"font-src 'self' data:; connect-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors " + ancestors
}

func pageHeaders(w http.ResponseWriter, ancestors string) {
	h := w.Header()
	h.Set("Content-Security-Policy", pageCSP(ancestors))
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("Cache-Control", "no-store")
	h.Del("X-Frame-Options")
}

// ServeEditor writes the editor page for ed. ancestors is the CSP
// frame-ancestors source list (the desktop's origin for a desktop window;
// "" for a top-level page).
func ServeEditor(w http.ResponseWriter, ed *Editor, title, notice, ancestors string) {
	b, err := json.Marshal(ed.Config)
	if err != nil {
		http.Error(w, "couldn't prepare the editor", http.StatusInternalServerError)
		return
	}
	pageHeaders(w, ancestors)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pageTmpl.ExecuteTemplate(w, "editor", map[string]string{
		"Title": title, "Notice": notice, "Config": base64.StdEncoding.EncodeToString(b),
	})
}

// ServeMessage writes a plain page with a title and a sentence.
func ServeMessage(w http.ResponseWriter, status int, title, msg, ancestors string) {
	pageHeaders(w, ancestors)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = pageTmpl.ExecuteTemplate(w, "message", map[string]string{"Title": title, "Message": msg})
}

// ServeStatic serves /s/-/office/static/{editor.js,editor.css}.
func ServeStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/s/-/office/static/")
	var ct string
	switch name {
	case "editor.js":
		ct = "text/javascript; charset=utf-8"
	case "editor.css":
		ct = "text/css; charset=utf-8"
	default:
		http.NotFound(w, r)
		return
	}
	b, err := pageFS.ReadFile("page/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(b)
}
