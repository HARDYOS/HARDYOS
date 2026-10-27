// Package office connects HardyOS to an OnlyOffice Document Server
// (phase 7 part B, docs/office.md, decisions 250-262): it opens files from
// shared folders and homes in the editor, hands the Document Server each
// file through a one-time URL bound to that file and person, and writes
// every save back as the person who made the last change, through the file
// worker (so the kernel checks their permissions), never as hardyd.
//
// The Document Server is a HardyOS-managed Docker app that listens on
// 127.0.0.1 only. Browsers reach it through hardyd's proxy (Proxy) on an
// origin of its own; it reaches hardyd on an internal listener
// (InternalHandler) for downloads and save callbacks. Everything between
// the two is signed with a shared JWT secret.
package office

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/files"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Limits.
const (
	// EditorLimit is the Community Edition's limit on simultaneous editors
	// (connections editing at once, across every document).
	EditorLimit = 20
	// DefaultMaxFileBytes is the largest file opened (the Document
	// Server's own default upload limit is the same).
	DefaultMaxFileBytes = 100 << 20
	// ConfigLifetime is how long a signed editor config can be used to
	// open the editor; DownloadLifetime how long its document URL works.
	ConfigLifetime   = 15 * time.Minute
	DownloadLifetime = 15 * time.Minute
	// idleSession: an open session nobody is in that hasn't heard from
	// the Document Server for this long is treated as over.
	idleSession = 24 * time.Hour
)

// Files is what office needs from the file worker client (files.Service).
type Files interface {
	Stat(ctx context.Context, who files.Who, share, path string) (*files.Entry, error)
	Open(ctx context.Context, who files.Who, share, path string) (*os.File, *files.Entry, error)
	Create(ctx context.Context, who files.Who, share, path string, overwrite bool) (*os.File, error)
	OpenWrite(ctx context.Context, who files.Who, share, path string) (*os.File, *files.Entry, error)
	Replace(ctx context.Context, who files.Who, share, from, to string) error
	Rename(ctx context.Context, who files.Who, share, from, toShare, to string) error
	DeleteItem(ctx context.Context, who files.Who, share, path string, permanent bool) (bool, error)
}

// AuditEvent is something office records in the audit log.
type AuditEvent struct {
	Action, Target, Detail string
	Outcome                audit.Outcome
	// Participant is who it was done for (nil: HardyOS itself).
	Participant *Participant
}

// Service is the office integration's core: sessions, editor configs,
// document downloads and save callbacks.
type Service struct {
	DB    *store.DB
	Files Files
	// Identity says who a participant reads and writes files as right now.
	// write asks whether they may still change the session's file (an edit
	// share link that was turned off, expired or turned into a view link
	// fails; an account that was disabled fails). Any error refuses.
	Identity func(ctx context.Context, p Participant, s *Session, write bool) (files.Who, error)
	// Secret is the JWT secret shared with the Document Server.
	Secret func(ctx context.Context) ([]byte, error)
	// Internal is the Document Server's own address (http://127.0.0.1:<port>),
	// the only place hardyd ever fetches a saved document from.
	Internal func() (*url.URL, error)
	// CallbackBase is how the Document Server reaches hardyd's internal
	// listener (http://host.docker.internal:44251).
	CallbackBase func() string
	// PublicBase reports whether scheme://host is one of this server's
	// public Document Server origins (the office port, files.<base>), for
	// save URLs the proxy hasn't noted since hardyd started.
	PublicBase func(scheme, host string) bool
	// MaxFileBytes is the largest file opened or saved (0: default).
	MaxFileBytes func() int64
	// Audit records opens and saves.
	Audit func(ctx context.Context, e AuditEvent)
	// HTTP fetches saved documents from the Document Server (default: no
	// proxy, no redirects, dialling only the internal address).
	HTTP *http.Client
	Log  *slog.Logger
	Now  func() time.Time

	mu        sync.Mutex
	openMu    sync.Mutex
	downloads map[string]*download // sha256(token) -> download
	keyLocks  map[string]*sync.Mutex
	bases     map[string]time.Time // public Document Server bases the proxy served
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) db() dbStore { return dbStore{db: s.DB} }

func (s *Service) maxBytes() int64 {
	if s.MaxFileBytes != nil {
		if n := s.MaxFileBytes(); n > 0 {
			return n
		}
	}
	return DefaultMaxFileBytes
}

func (s *Service) audit(ctx context.Context, e AuditEvent) {
	if s.Audit != nil {
		s.Audit(ctx, e)
	}
}

// keyKey is the HMAC key for document keys, derived from the JWT secret.
func keyKey(secret []byte) []byte {
	h := sha256.Sum256(append([]byte("hardyos-office-dockey\x00"), secret...))
	return h[:]
}

// Errors Open returns (shown to people as they are).
var (
	ErrNotDocument = errors.New("the editor doesn't open this kind of file")
	ErrTooBig      = errors.New("this file is too big for the editor")
	ErrIsFolder    = errors.New("folders can't be opened in the editor")
)

// OpenRequest asks for an editor on one file.
type OpenRequest struct {
	// Who reads the file now (the person, or a link's creator).
	Who   files.Who
	Share string
	Path  string
	// Kind, UserID, LinkID and Name describe the participant.
	Kind   string
	UserID int64
	LinkID int64
	Name   string
	// WantEdit asks for editing; MayEdit is the caller's own rule (a view
	// link may not). Editing also needs a format the editor saves and
	// write access to the file.
	WantEdit bool
	MayEdit  bool
	// Lang is the editor's language (default "en").
	Lang string
}

// Editor is what the editor page needs.
type Editor struct {
	Config      map[string]any `json:"config"`
	Mode        Mode           `json:"mode"`
	Session     *Session       `json:"session"`
	Participant *Participant   `json:"participant"`
	// ViewReason says why the file opened read only, when editing was
	// asked for.
	ViewReason string `json:"viewReason,omitempty"`
}

// CleanName makes a participant's name safe to show to others: printable,
// one line, at most 64 characters; "" becomes fallback.
func CleanName(name, fallback string) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.TrimSpace(name) {
		if n >= 64 {
			break
		}
		switch {
		case unicode.IsSpace(r):
			r = ' '
		case unicode.Is(unicode.Cf, r), unicode.IsControl(r), unicode.Is(unicode.Co, r), r == utf8.RuneError:
			continue
		}
		b.WriteRune(r)
		n++
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if out == "" {
		return fallback
	}
	return out
}

// Open finds or starts the session for a file, adds the participant and
// returns a signed editor config for them.
func (s *Service) Open(ctx context.Context, req OpenRequest) (*Editor, error) {
	f, ok := FormatOf(req.Path)
	if !ok {
		return nil, ErrNotDocument
	}
	if req.Kind != KindUser && req.Kind != KindLink {
		return nil, errors.New("unknown kind of participant")
	}
	e, err := s.Files.Stat(ctx, req.Who, req.Share, req.Path)
	if err != nil {
		return nil, err
	}
	if e.Dir {
		return nil, ErrIsFolder
	}
	if e.Size > s.maxBytes() {
		return nil, ErrTooBig
	}
	secret, err := s.Secret(ctx)
	if err != nil {
		return nil, fmt.Errorf("the office secret isn't available: %w", err)
	}
	mode, why := ModeView, ""
	if req.WantEdit {
		switch {
		case !req.MayEdit:
			why = "This link lets people view the file, not change it."
		case !f.Editable:
			why = "The editor can't save this kind of file; it opens read only. Save a copy as ." + map[string]string{"word": "docx", "cell": "xlsx", "slide": "pptx"}[f.DocumentType] + " to edit it."
		case !e.Writable:
			why = "You can read this file but not change it."
		default:
			mode = ModeEdit
		}
	}

	s.openMu.Lock()
	defer s.openMu.Unlock()
	now := s.now()
	sess, err := s.db().openSession(ctx, req.Share, req.Path)
	if err != nil && !errors.Is(err, ErrNoSession) {
		return nil, err
	}
	if sess != nil {
		changed := !sameVersion(e, sess.BaseModified, sess.BaseSize)
		idle := len(sess.Active) == 0 && now.Sub(sess.UpdatedAt) > time.Minute
		stale := len(sess.Active) == 0 && now.Sub(sess.UpdatedAt) > idleSession
		if (changed && idle) || stale {
			// The file changed since, and nobody is editing the old
			// version: start over from the file as it is now.
			_ = s.db().setState(ctx, sess.Key, StateClosed, "the file changed outside the editor", now)
			sess = nil
		}
	}
	if mode == ModeEdit && s.activeEditors(ctx, sess) >= EditorLimit {
		mode, why = ModeView, fmt.Sprintf("%d people are editing documents on this server, the most the free Document Server allows at once. The file opened read only; try again when someone closes theirs.", EditorLimit)
	}
	if sess == nil {
		sess = &Session{
			Key:   DeriveKey(keyKey(secret), req.Share, req.Path, e.Size, e.Modified, newID("")),
			Share: req.Share, Path: req.Path, FileType: f.Ext,
			BaseModified: e.Modified, BaseSize: e.Size, State: StateOpen, Active: []string{},
			CreatedAt: now, UpdatedAt: now,
		}
		if err := s.db().insertSession(ctx, sess); err != nil {
			return nil, err
		}
	}
	p := &Participant{ID: newID("p"), Key: sess.Key, Kind: req.Kind, UserID: req.UserID, LinkID: req.LinkID,
		Name: CleanName(req.Name, "Guest"), Mode: mode, Created: now}
	if err := s.db().addParticipant(ctx, p); err != nil {
		return nil, err
	}
	token := s.newDownload(sess.Key, p.ID, now)
	cfg := s.config(f, e.Name, sess, p, token, req.Lang)
	claims := map[string]any{}
	for k, v := range cfg {
		claims[k] = v
	}
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(ConfigLifetime).Unix()
	signed, err := SignJWT(secret, claims)
	if err != nil {
		return nil, err
	}
	cfg["token"] = signed
	detail := string(mode)
	if why != "" {
		detail += " (asked to edit: " + why + ")"
	}
	s.audit(ctx, AuditEvent{Action: "office.open", Target: req.Share + ":/" + req.Path, Outcome: audit.Success,
		Detail: detail + ", session " + sess.Key[:8], Participant: p})
	return &Editor{Config: cfg, Mode: mode, Session: sess, Participant: p, ViewReason: why}, nil
}

// sameVersion: e is the version the session expects.
func sameVersion(e *files.Entry, mod time.Time, size int64) bool {
	// The database keeps times to the millisecond.
	return e.Size == size && e.Modified.Truncate(time.Millisecond).Equal(mod.Truncate(time.Millisecond))
}

// activeEditors counts the people the Document Server says are in
// documents, across every open session (cur counts one more if it's new).
func (s *Service) activeEditors(ctx context.Context, cur *Session) int {
	list, err := s.db().openSessions(ctx)
	if err != nil {
		return 0
	}
	n := 0
	now := s.now()
	for _, x := range list {
		if now.Sub(x.UpdatedAt) > idleSession {
			continue
		}
		n += len(x.Active)
	}
	return n
}

func (s *Service) config(f Format, title string, sess *Session, p *Participant, token, lang string) map[string]any {
	if lang == "" {
		lang = "en"
	}
	edit := p.Mode == ModeEdit
	base := strings.TrimRight(s.CallbackBase(), "/")
	perms := map[string]any{
		"edit": edit, "review": edit && f.DocumentType == "word", "comment": edit,
		"download": true, "print": true, "copy": true, "chat": edit,
		"fillForms": edit, "modifyFilter": edit, "modifyContentControl": edit,
	}
	return map[string]any{
		"type":         "desktop",
		"width":        "100%",
		"height":       "100%",
		"documentType": f.DocumentType,
		"document": map[string]any{
			"fileType":    f.Ext,
			"key":         sess.Key,
			"title":       title,
			"url":         base + "/office/file/" + token,
			"permissions": perms,
		},
		"editorConfig": map[string]any{
			"callbackUrl": base + "/office/callback/" + sess.Key,
			"mode":        string(p.Mode),
			"lang":        lang,
			"user":        map[string]any{"id": p.ID, "name": p.Name},
			"coEditing":   map[string]any{"mode": "fast", "change": true},
			"customization": map[string]any{
				// Nothing that loads or runs code from elsewhere.
				"plugins":         false,
				"macros":          false,
				"macrosMode":      "disable",
				"help":            false,
				"feedback":        false,
				"goback":          false,
				"forcesave":       true,
				"autosave":        true,
				"compactHeader":   true,
				"hideRightMenu":   false,
				"uiTheme":         "theme-dark",
				"integrationMode": "embed",
			},
		},
	}
}

// ---- downloads ----------------------------------------------------------------

// download is one document URL: one session, one participant, one use.
type download struct {
	key, participant string
	expires          time.Time
	busy, used       bool
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func (s *Service) newDownload(key, participant string, now time.Time) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.downloads == nil {
		s.downloads = map[string]*download{}
	}
	for k, d := range s.downloads {
		if now.After(d.expires) || d.used {
			delete(s.downloads, k)
		}
	}
	s.downloads[hashToken(token)] = &download{key: key, participant: participant, expires: now.Add(DownloadLifetime)}
	return token
}

// Errors from a document download.
var (
	ErrDownloadGone = errors.New("this document link doesn't work (used, expired or never made)")
	ErrDownloadBusy = errors.New("this document is already being downloaded")
)

// claimDownload takes a token for one transfer.
func (s *Service) claimDownload(token string) (*download, error) {
	if len(token) != 64 {
		return nil, ErrDownloadGone
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.downloads[hashToken(token)]
	if d == nil || d.used || s.now().After(d.expires) {
		return nil, ErrDownloadGone
	}
	if d.busy {
		return nil, ErrDownloadBusy
	}
	d.busy = true
	return d, nil
}

func (s *Service) finishDownload(d *download, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d.busy = false
	if ok {
		d.used = true
	}
}

// ServeDownload sends a session's file to the Document Server, read as the
// participant the URL was made for.
func (s *Service) ServeDownload(w http.ResponseWriter, r *http.Request, token string) {
	d, err := s.claimDownload(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	ok := false
	defer func() { s.finishDownload(d, ok) }()
	ctx := r.Context()
	sess, err := s.db().session(ctx, d.key)
	if err != nil || sess.State != StateOpen {
		http.Error(w, "the editing session is over", http.StatusGone)
		return
	}
	p, err := s.db().participant(ctx, d.key, d.participant)
	if err != nil {
		http.Error(w, "unknown participant", http.StatusNotFound)
		return
	}
	who, err := s.Identity(ctx, *p, sess, false)
	if err != nil {
		s.audit(ctx, AuditEvent{Action: "office.download", Target: sess.Share + ":/" + sess.Path, Outcome: audit.Denied, Detail: err.Error(), Participant: p})
		http.Error(w, "no access", http.StatusForbidden)
		return
	}
	f, e, err := s.Files.Open(ctx, who, sess.Share, sess.Path)
	if err != nil {
		http.Error(w, "the file can't be read", http.StatusNotFound)
		return
	}
	defer f.Close()
	if e.Size > s.maxBytes() {
		http.Error(w, ErrTooBig.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", fmt.Sprint(e.Size))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	n, err := ioCopyN(w, f, e.Size)
	ok = err == nil && n == e.Size
}

// ---- known Document Server addresses --------------------------------------------

// NoteBase records a public base URL the proxy serves the Document Server
// at ("https://files.example.com/s/-/ds"); save callbacks name documents by
// such URLs. At most 64 are kept, oldest dropped.
func (s *Service) NoteBase(base string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bases == nil {
		s.bases = map[string]time.Time{}
	}
	s.bases[base] = s.now()
	if len(s.bases) > 64 {
		var oldest string
		var at time.Time
		for b, t := range s.bases {
			if oldest == "" || t.Before(at) {
				oldest, at = b, t
			}
		}
		delete(s.bases, oldest)
	}
}

// ErrForeignURL: a callback named a document somewhere other than the
// Document Server's file cache.
var ErrForeignURL = errors.New("the download URL doesn't point at the Document Server's file cache")

// InternalURL turns a document URL from a callback into the address hardyd
// fetches it from: the same path and query on the Document Server's own
// 127.0.0.1 port. It must start with the Document Server's internal address
// or a base the proxy has served, and name a file in /cache/files/; anything
// else is refused, so a callback can't make hardyd fetch other URLs.
func (s *Service) InternalURL(raw string) (*url.URL, error) {
	in, err := s.Internal()
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, ErrForeignURL
	}
	rest := ""
	if strings.EqualFold(u.Scheme, in.Scheme) && strings.EqualFold(u.Host, in.Host) {
		rest = u.EscapedPath()
	} else {
		s.mu.Lock()
		for b := range s.bases {
			bu, err := url.Parse(b)
			if err != nil || !strings.EqualFold(bu.Scheme, u.Scheme) || !strings.EqualFold(bu.Host, u.Host) {
				continue
			}
			prefix := strings.TrimRight(bu.EscapedPath(), "/") + "/"
			if strings.HasPrefix(u.EscapedPath(), prefix) {
				rest = "/" + strings.TrimPrefix(u.EscapedPath(), prefix)
				break
			}
		}
		s.mu.Unlock()
		// After a restart the proxy hasn't seen the editors' addresses yet:
		// the office origin's port or files.<base> still name this server's
		// Document Server (hardyd never connects to them; only the path is
		// used, on the internal address).
		if rest == "" && s.PublicBase != nil && s.PublicBase(u.Scheme, u.Host) && strings.HasPrefix(u.EscapedPath(), DSPrefix+"/") {
			rest = strings.TrimPrefix(u.EscapedPath(), DSPrefix)
		}
	}
	if rest == "" {
		return nil, ErrForeignURL
	}
	// Checked as written and decoded: "%2e%2e" is ".." to the server.
	dec, err := url.PathUnescape(rest)
	if err != nil || strings.ContainsAny(dec, "\\\x00") {
		return nil, ErrForeignURL
	}
	for _, p := range []string{rest, dec} {
		if clean := path.Clean(p); clean != p && clean+"/" != p {
			return nil, ErrForeignURL
		}
	}
	lower := strings.ToLower(rest)
	if !strings.HasPrefix(dec, "/cache/files/") || !strings.HasPrefix(rest, "/cache/files/") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return nil, ErrForeignURL
	}
	out := *in
	out.Path, out.RawPath = "", ""
	ref, err := url.Parse(rest)
	if err != nil {
		return nil, ErrForeignURL
	}
	res := out.ResolveReference(ref)
	res.RawQuery = u.RawQuery
	if res.Host != in.Host || res.Scheme != in.Scheme {
		return nil, ErrForeignURL
	}
	return res, nil
}
