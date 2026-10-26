package api

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/files"
	"github.com/hardyos/hardyos/daemon/internal/fileworker"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// File Manager API (docs/plans/file-sharing.md section 3): files are read
// and written as the signed-in person through files.Service; hardyd only
// streams the file descriptors it's handed.

// File job kinds.
const (
	JobKindFilesCopy    = "files.copy"
	JobKindFilesDelete  = "files.delete"
	JobKindFilesRestore = "files.restore"
	JobKindFilesMove    = "files.move"
)

// syncItems: copies, moves and deletes of at most this many items (and no
// folder copies) are done at once; more run as a job with progress.
const syncItems = 5

// maxItems bounds one bulk request.
const maxItems = 1000

func (s *Server) fileRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/files/shares", s.authed(s.handleFilesShares))
	m.Handle("GET /api/v1/files/list", s.authed(s.handleFilesList))
	m.Handle("GET /api/v1/files/stat", s.authed(s.handleFilesStat))
	m.Handle("GET /api/v1/files/download", s.authed(s.handleFilesDownload))
	m.Handle("PUT /api/v1/files/upload", s.authed(s.handleFilesUpload))
	m.Handle("GET /api/v1/files/upload", s.authed(s.handleFilesUploadStatus))
	m.Handle("DELETE /api/v1/files/upload", s.authed(s.handleFilesUploadCancel))
	m.Handle("POST /api/v1/files/mkdir", s.authed(s.handleFilesMkdir))
	m.Handle("POST /api/v1/files/rename", s.authed(s.handleFilesRename))
	m.Handle("POST /api/v1/files/copy", s.authed(s.handleFilesCopy))
	m.Handle("POST /api/v1/files/delete", s.authed(s.handleFilesDelete))
	m.Handle("GET /api/v1/files/versions", s.authed(s.handleFilesVersions))
	m.Handle("POST /api/v1/files/restore", s.authed(s.handleFilesRestore))
}

// filesWho is who files are read and written as; false (answered) for
// HardyOS accounts that aren't administrators.
func (s *Server) filesWho(w http.ResponseWriter, u *auth.User) (files.Who, bool) {
	who := files.WhoFor(u)
	if who.Local && !who.Admin {
		writeError(w, http.StatusForbidden, "no_access", "files can be used by administrators and domain accounts; ask an administrator for a domain account")
		return who, false
	}
	return who, true
}

// writeFilesError maps file errors to 404 / 403 / 409 (507 when full).
func (s *Server) writeFilesError(w http.ResponseWriter, err error) {
	var fe *files.Error
	msg := err.Error()
	if errors.As(err, &fe) {
		msg = fe.Msg
	}
	switch {
	case errors.Is(err, files.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", msg)
	case errors.Is(err, files.ErrNoAccess):
		writeError(w, http.StatusForbidden, "no_access", msg)
	case errors.Is(err, files.ErrExists):
		writeError(w, http.StatusConflict, "exists", msg)
	case errors.Is(err, files.ErrNotAllowed):
		writeError(w, http.StatusConflict, "not_allowed", msg)
	case errors.Is(err, files.ErrFull):
		writeError(w, http.StatusInsufficientStorage, "full", msg)
	case errors.Is(err, context.Canceled):
		writeError(w, http.StatusRequestTimeout, "cancelled", "the request was cancelled")
	default:
		s.writePrivError(w, err)
	}
}

// ---- reading ---------------------------------------------------------------

// FilesSharesResponse lists the folders the person can open.
type FilesSharesResponse struct {
	Shares []files.ShareInfo `json:"shares"`
}

func (s *Server) handleFilesShares(w http.ResponseWriter, r *http.Request, u *auth.User) {
	who, ok := s.filesWho(w, u)
	if !ok {
		return
	}
	l, err := s.cfg.Files.Shares(r.Context(), who)
	if err != nil {
		s.writeFilesError(w, err)
		return
	}
	if l == nil {
		l = []files.ShareInfo{}
	}
	writeJSON(w, http.StatusOK, FilesSharesResponse{Shares: l})
}

func (s *Server) handleFilesList(w http.ResponseWriter, r *http.Request, u *auth.User) {
	who, ok := s.filesWho(w, u)
	if !ok {
		return
	}
	q := r.URL.Query()
	l, err := s.cfg.Files.ListDir(r.Context(), who, q.Get("share"), q.Get("path"), q.Get("snapshot"))
	if err != nil {
		s.writeFilesError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, l)
}

func (s *Server) handleFilesStat(w http.ResponseWriter, r *http.Request, u *auth.User) {
	who, ok := s.filesWho(w, u)
	if !ok {
		return
	}
	q := r.URL.Query()
	e, err := s.cfg.Files.StatVersion(r.Context(), who, q.Get("share"), q.Get("path"), q.Get("snapshot"))
	if err != nil {
		s.writeFilesError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

// FilesVersionsResponse lists a path's older versions, newest first.
type FilesVersionsResponse struct {
	Versions []files.Version `json:"versions"`
}

func (s *Server) handleFilesVersions(w http.ResponseWriter, r *http.Request, u *auth.User) {
	who, ok := s.filesWho(w, u)
	if !ok {
		return
	}
	q := r.URL.Query()
	l, err := s.cfg.Files.Versions(r.Context(), who, q.Get("share"), q.Get("path"))
	if err != nil {
		s.writeFilesError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, FilesVersionsResponse{Versions: l})
}

// ---- downloads ----------------------------------------------------------------

// Types a browser may show in place (preview); anything else is always a
// download, so a file can never run as a page of the desktop.
var inlineTypes = map[string]bool{
	"image/png": true, "image/jpeg": true, "image/gif": true, "image/webp": true, "image/avif": true, "image/bmp": true,
	"video/mp4": true, "video/webm": true, "video/ogg": true, "video/quicktime": true,
	"audio/mpeg": true, "audio/ogg": true, "audio/wav": true, "audio/x-wav": true, "audio/flac": true, "audio/mp4": true, "audio/aac": true, "audio/webm": true,
	"application/pdf": true, "text/plain": true,
}

// Extensions previewed as plain text.
var textExts = map[string]bool{
	".txt": true, ".md": true, ".log": true, ".csv": true, ".json": true, ".xml": true, ".yaml": true, ".yml": true,
	".ini": true, ".conf": true, ".cfg": true, ".toml": true, ".sh": true, ".py": true, ".go": true, ".js": true,
	".ts": true, ".css": true, ".html": true, ".htm": true, ".svg": true, ".c": true, ".h": true, ".java": true, ".srt": true, ".vtt": true,
}

// contentType is what a file is served as: inline-safe types as they are,
// text as text/plain (an .html or .svg is shown as its source), anything
// else as a download.
func contentType(name string, inline bool) (string, bool) {
	ext := strings.ToLower(path.Ext(name))
	if inline && textExts[ext] {
		return "text/plain; charset=utf-8", true
	}
	ct := mime.TypeByExtension(ext)
	base, _, _ := mime.ParseMediaType(ct)
	if ct == "" {
		return "application/octet-stream", false
	}
	if inline && inlineTypes[base] {
		return ct, true
	}
	if base == "text/html" || base == "image/svg+xml" || base == "application/xhtml+xml" || strings.Contains(base, "javascript") {
		return "application/octet-stream", false
	}
	return ct, false
}

// disposition is a Content-Disposition with the name in both forms.
func disposition(kind, name string) string {
	ascii := strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, name)
	return fmt.Sprintf(`%s; filename="%s"; filename*=UTF-8''%s`, kind, ascii, url.PathEscape(name))
}

func (s *Server) handleFilesDownload(w http.ResponseWriter, r *http.Request, u *auth.User) {
	who, ok := s.filesWho(w, u)
	if !ok {
		return
	}
	q := r.URL.Query()
	share, snap, paths := q.Get("share"), q.Get("snapshot"), q["path"]
	if len(paths) == 0 {
		paths = []string{""}
	}
	if len(paths) > maxItems {
		writeError(w, http.StatusBadRequest, "invalid", fmt.Sprintf("at most %d items at once", maxItems))
		return
	}
	ctx := r.Context()
	fs := s.cfg.Files
	if len(paths) == 1 {
		e, err := fs.StatVersion(ctx, who, share, paths[0], snap)
		if err != nil {
			s.writeFilesError(w, err)
			return
		}
		if !e.Dir {
			f, fe, err := fs.OpenVersion(ctx, who, share, paths[0], snap)
			if err != nil {
				s.writeFilesError(w, err)
				return
			}
			defer f.Close()
			ct, inline := contentType(fe.Name, q.Get("inline") == "1")
			h := w.Header()
			h.Set("Content-Type", ct)
			kind := "attachment"
			if inline {
				kind = "inline"
			}
			h.Set("Content-Disposition", disposition(kind, fe.Name))
			h.Set("Cache-Control", "private, no-cache")
			h.Set("ETag", fmt.Sprintf(`"%x-%x"`, fe.Size, fe.Modified.UnixNano()))
			if !strings.HasPrefix(ct, "application/pdf") {
				// Shown in a sandbox: nothing in it can run as the desktop.
				h.Set("Content-Security-Policy", "default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; sandbox")
			}
			http.ServeContent(w, r, "", fe.Modified, f)
			return
		}
	}
	// Folders and several items: a zip, streamed as it's made.
	name := "Download"
	if len(paths) == 1 {
		if base := path.Base(strings.Trim(paths[0], "/")); paths[0] != "" && base != "." && base != "/" {
			name = base
		} else if l, err := fs.Shares(ctx, who); err == nil {
			for _, sh := range l {
				if sh.ID == share {
					name = sh.Name
				}
			}
		}
	}
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Type", "application/zip")
		w.WriteHeader(http.StatusOK)
		return
	}
	// Check every item before the first byte goes out, so a mistake is an
	// error and not a broken zip.
	tops := make([]*files.Entry, len(paths))
	for i, p := range paths {
		e, err := fs.StatVersion(ctx, who, share, p, snap)
		if err != nil {
			s.writeFilesError(w, err)
			return
		}
		tops[i] = e
	}
	h := w.Header()
	h.Set("Content-Type", "application/zip")
	h.Set("Content-Disposition", disposition("attachment", name+".zip"))
	h.Set("Cache-Control", "no-store")
	z := &zipper{fs: fs, who: who, share: share, snap: snap, zw: zip.NewWriter(w)}
	for i, e := range tops {
		// One folder: its contents at the top of the zip. Several items:
		// each under its own name.
		prefix := ""
		if len(paths) > 1 {
			prefix = e.Name
		}
		if err := z.add(ctx, paths[i], e, prefix, 0); err != nil {
			s.log.Warn("folder download stopped", "share", share, "err", err)
			panic(http.ErrAbortHandler) // the browser sees a failed download, not a short zip
		}
	}
	if len(z.skipped) > 0 {
		if fw, err := z.zw.Create("Files not included.txt"); err == nil {
			fmt.Fprintf(fw, "These couldn't be read, so they aren't in this zip:\r\n\r\n%s\r\n", strings.Join(z.skipped, "\r\n"))
		}
	}
	if err := z.zw.Close(); err != nil {
		panic(http.ErrAbortHandler)
	}
}

// zip limits.
const (
	maxZipEntries = 200000
	maxZipDepth   = 64
)

type zipper struct {
	fs      files.Service
	who     files.Who
	share   string
	snap    string
	zw      *zip.Writer
	n       int
	skipped []string
}

// add writes e (at share path p) into the zip under name.
func (z *zipper) add(ctx context.Context, p string, e *files.Entry, name string, depth int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	z.n++
	if z.n > maxZipEntries {
		return fmt.Errorf("more than %d items", maxZipEntries)
	}
	if !e.Dir {
		f, fe, err := z.fs.OpenVersion(ctx, z.who, z.share, p, z.snap)
		if errors.Is(err, files.ErrNoAccess) || errors.Is(err, files.ErrNotFound) || errors.Is(err, files.ErrNotAllowed) {
			z.skipped = append(z.skipped, name)
			return nil
		}
		if err != nil {
			return err
		}
		defer f.Close()
		hdr := &zip.FileHeader{Name: name, Method: zip.Store, Modified: fe.Modified}
		hdr.UncompressedSize64 = uint64(fe.Size)
		fw, err := z.zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		_, err = io.Copy(fw, f)
		return err
	}
	if depth >= maxZipDepth {
		z.skipped = append(z.skipped, name+"/ (too deep)")
		return nil
	}
	if name != "" {
		if _, err := z.zw.CreateHeader(&zip.FileHeader{Name: name + "/", Method: zip.Store, Modified: e.Modified}); err != nil {
			return err
		}
	}
	l, err := z.fs.ListDir(ctx, z.who, z.share, p, z.snap)
	if errors.Is(err, files.ErrNoAccess) {
		z.skipped = append(z.skipped, name+"/")
		return nil
	}
	if err != nil {
		return err
	}
	if l.Truncated {
		z.skipped = append(z.skipped, name+"/ (only the first entries)")
	}
	for i := range l.Entries {
		ce := l.Entries[i]
		cn := ce.Name
		if name != "" {
			cn = name + "/" + ce.Name
		}
		if err := z.add(ctx, ce.Path, &ce, cn, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// ---- uploads ----------------------------------------------------------------

// Uploads in progress: one temporary file each, next to where the file
// goes, named .hardyos-upload-<id> (hidden). A chunk (PUT with
// Content-Range) is written at its offset; the last one renames the
// temporary file into place.
type uploads struct {
	mu sync.Mutex
	m  map[string]*upload
}

type upload struct {
	ID        string
	Principal string
	Who       files.Who
	Share     string
	Path      string // where the file goes
	Tmp       string // its temporary path
	Total     int64
	Received  int64
	Overwrite bool
	Modified  time.Time
	touched   time.Time
	busy      bool
}

// Upload limits.
const (
	uploadIdle     = 24 * time.Hour
	maxUploadsEach = 50
)

// FilesUploadStatus is an upload in progress (or just finished: Entry set).
type FilesUploadStatus struct {
	UploadID string       `json:"uploadId"`
	Share    string       `json:"share"`
	Path     string       `json:"path"`
	Received int64        `json:"received"`
	Total    int64        `json:"total"`
	Done     bool         `json:"done"`
	Entry    *files.Entry `json:"entry,omitempty"`
}

func (up *upload) status() FilesUploadStatus {
	return FilesUploadStatus{UploadID: up.ID, Share: up.Share, Path: up.Path, Received: up.Received, Total: up.Total}
}

func newUploadID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// sweep drops uploads nobody has continued for a day (and their files).
func (s *Server) sweepUploads() {
	s.uploads.mu.Lock()
	var gone []*upload
	for id, up := range s.uploads.m {
		if !up.busy && time.Since(up.touched) > uploadIdle {
			gone = append(gone, up)
			delete(s.uploads.m, id)
		}
	}
	s.uploads.mu.Unlock()
	for _, up := range gone {
		go func(up *upload) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			_, _ = s.cfg.Files.DeleteItem(ctx, up.Who, up.Share, up.Tmp, true)
		}(up)
	}
}

// contentRange parses "bytes 0-1048575/52428800".
func contentRange(h string) (start, end, total int64, ok bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(h), "bytes ")
	if !found {
		return 0, 0, 0, false
	}
	rng, tot, found := strings.Cut(rest, "/")
	if !found {
		return 0, 0, 0, false
	}
	a, b, found := strings.Cut(rng, "-")
	if !found {
		return 0, 0, 0, false
	}
	var err1, err2, err3 error
	start, err1 = strconv.ParseInt(a, 10, 64)
	end, err2 = strconv.ParseInt(b, 10, 64)
	total, err3 = strconv.ParseInt(tot, 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || start < 0 || end < start || total <= end {
		return 0, 0, 0, false
	}
	return start, end, total, true
}

func parseModified(v string) (time.Time, bool) {
	if v == "" {
		return time.Time{}, true
	}
	if ms, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.UnixMilli(ms).UTC(), true
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	return t.UTC(), err == nil
}

func (s *Server) handleFilesUpload(w http.ResponseWriter, r *http.Request, u *auth.User) {
	who, ok := s.filesWho(w, u)
	if !ok {
		return
	}
	s.sweepUploads()
	q := r.URL.Query()
	ctx := r.Context()
	fs := s.cfg.Files
	share, p := q.Get("share"), strings.Trim(q.Get("path"), "/")
	overwrite := q.Get("overwrite") == "1" || q.Get("overwrite") == "true"
	modified, ok := parseModified(q.Get("modified"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid", "modified must be milliseconds since 1970 or an RFC 3339 time")
		return
	}
	dir, name := path.Split(p)
	if err := fileworker.CleanName(name); err != nil || name == "" {
		writeError(w, http.StatusBadRequest, "invalid", "give the file a valid name")
		return
	}
	var start, end, total int64
	chunked := r.Header.Get("Content-Range") != ""
	if chunked {
		var ok bool
		if start, end, total, ok = contentRange(r.Header.Get("Content-Range")); !ok {
			writeError(w, http.StatusBadRequest, "invalid", "Content-Range must look like bytes 0-1048575/52428800")
			return
		}
		if r.ContentLength >= 0 && r.ContentLength != end-start+1 {
			writeError(w, http.StatusBadRequest, "invalid", "the chunk's length doesn't match its Content-Range")
			return
		}
	}

	var up *upload
	if id := q.Get("uploadId"); id != "" {
		s.uploads.mu.Lock()
		up = s.uploads.m[id]
		switch {
		case up == nil || !strings.EqualFold(up.Principal, who.Principal):
			s.uploads.mu.Unlock()
			writeError(w, http.StatusNotFound, "not_found", "that upload isn't in progress any more; start it again")
			return
		case up.Share != share || up.Path != p:
			s.uploads.mu.Unlock()
			writeError(w, http.StatusBadRequest, "invalid", "that upload is for another file")
			return
		case up.busy:
			s.uploads.mu.Unlock()
			writeError(w, http.StatusConflict, "busy", "another part of this upload is still being written")
			return
		case !chunked || total != up.Total:
			s.uploads.mu.Unlock()
			writeError(w, http.StatusBadRequest, "invalid", "continue an upload with Content-Range chunks of the same total size")
			return
		case start != up.Received:
			st := up.status()
			s.uploads.mu.Unlock()
			writeJSON(w, http.StatusConflict, map[string]any{"code": "wrong_offset", "message": fmt.Sprintf("the next part starts at byte %d", st.Received), "upload": st})
			return
		}
		up.busy, up.touched = true, time.Now()
		s.uploads.mu.Unlock()
	} else {
		if chunked && start != 0 {
			writeError(w, http.StatusBadRequest, "invalid", "a new upload starts at byte 0; pass uploadId to continue one")
			return
		}
		// Fail early if the name is taken (the final rename checks again).
		if e, err := fs.Stat(ctx, who, share, p); err == nil {
			if e.Dir || !overwrite {
				writeError(w, http.StatusConflict, "exists", name+" is already there")
				return
			}
		} else if !errors.Is(err, files.ErrNotFound) {
			s.writeFilesError(w, err)
			return
		}
		up = &upload{ID: newUploadID(), Principal: who.Principal, Who: who, Share: share, Path: p,
			Total: total, Overwrite: overwrite, Modified: modified, touched: time.Now(), busy: true}
		up.Tmp = dir + fileworker.UploadPrefix + up.ID
		if chunked {
			s.uploads.mu.Lock()
			n := 0
			for _, o := range s.uploads.m {
				if strings.EqualFold(o.Principal, who.Principal) {
					n++
				}
			}
			if n >= maxUploadsEach {
				s.uploads.mu.Unlock()
				writeError(w, http.StatusTooManyRequests, "too_many", "too many uploads at once; finish or cancel some")
				return
			}
			if s.uploads.m == nil {
				s.uploads.m = map[string]*upload{}
			}
			s.uploads.m[up.ID] = up
			s.uploads.mu.Unlock()
		}
		f, err := fs.Create(ctx, who, share, up.Tmp, false)
		if err != nil {
			s.dropUpload(up, false)
			s.writeFilesError(w, err)
			return
		}
		f.Close()
	}
	release := func() {
		s.uploads.mu.Lock()
		up.busy, up.touched = false, time.Now()
		s.uploads.mu.Unlock()
	}

	f, _, err := fs.OpenWrite(ctx, who, share, up.Tmp)
	if err != nil {
		release()
		s.writeFilesError(w, err)
		return
	}
	var n int64
	if chunked {
		if _, err = f.Seek(start, io.SeekStart); err == nil {
			n, err = io.CopyN(f, r.Body, end-start+1)
		}
	} else {
		n, err = io.Copy(f, r.Body)
	}
	if err == nil {
		if !chunked || start+n == up.Total {
			err = f.Sync()
		}
	}
	cerr := f.Close()
	if err == nil {
		err = cerr
	}
	if err != nil {
		if !chunked {
			s.dropUpload(up, true)
		} else {
			// Keep what was written: the client asks where to go on from.
			s.uploads.mu.Lock()
			up.Received = start + n
			s.uploads.mu.Unlock()
			release()
		}
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "incomplete", "the upload was cut off; continue it from where it stopped")
			return
		}
		s.writeFilesError(w, err)
		return
	}
	if chunked {
		s.uploads.mu.Lock()
		up.Received = end + 1
		s.uploads.mu.Unlock()
		if up.Received < up.Total {
			release()
			writeJSON(w, http.StatusOK, up.status())
			return
		}
	} else {
		up.Total, up.Received = n, n
	}

	// Complete: put it in place.
	if up.Overwrite {
		err = fs.Replace(ctx, who, share, up.Tmp, up.Path)
	} else {
		err = fs.Rename(ctx, who, share, up.Tmp, share, up.Path)
	}
	if err != nil {
		s.dropUpload(up, true)
		s.writeFilesError(w, err)
		return
	}
	s.dropUpload(up, false)
	if !up.Modified.IsZero() {
		if err := fs.SetModified(ctx, who, share, up.Path, up.Modified); err != nil {
			s.log.Warn("upload: setting the modified time", "err", err)
		}
	}
	s.record(r, u, "files.upload", share+":/"+up.Path, audit.Success, fmt.Sprintf("%d bytes", up.Total))
	st := up.status()
	st.Done = true
	if e, err := fs.Stat(ctx, who, share, up.Path); err == nil {
		st.Entry = e
	}
	writeJSON(w, http.StatusCreated, st)
}

// dropUpload forgets an upload and, if removeFile, deletes its temporary file.
func (s *Server) dropUpload(up *upload, removeFile bool) {
	s.uploads.mu.Lock()
	delete(s.uploads.m, up.ID)
	s.uploads.mu.Unlock()
	if removeFile {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = s.cfg.Files.DeleteItem(ctx, up.Who, up.Share, up.Tmp, true)
	}
}

func (s *Server) findUpload(w http.ResponseWriter, r *http.Request, who files.Who) *upload {
	s.uploads.mu.Lock()
	defer s.uploads.mu.Unlock()
	up := s.uploads.m[r.URL.Query().Get("uploadId")]
	if up == nil || !strings.EqualFold(up.Principal, who.Principal) {
		writeError(w, http.StatusNotFound, "not_found", "that upload isn't in progress any more; start it again")
		return nil
	}
	return up
}

func (s *Server) handleFilesUploadStatus(w http.ResponseWriter, r *http.Request, u *auth.User) {
	who, ok := s.filesWho(w, u)
	if !ok {
		return
	}
	if up := s.findUpload(w, r, who); up != nil {
		s.uploads.mu.Lock()
		st := up.status()
		s.uploads.mu.Unlock()
		writeJSON(w, http.StatusOK, st)
	}
}

func (s *Server) handleFilesUploadCancel(w http.ResponseWriter, r *http.Request, u *auth.User) {
	who, ok := s.filesWho(w, u)
	if !ok {
		return
	}
	up := s.findUpload(w, r, who)
	if up == nil {
		return
	}
	s.uploads.mu.Lock()
	busy := up.busy
	s.uploads.mu.Unlock()
	if busy {
		writeError(w, http.StatusConflict, "busy", "a part of this upload is still being written")
		return
	}
	s.dropUpload(up, true)
	w.WriteHeader(http.StatusNoContent)
}

// ---- changing -----------------------------------------------------------------

// FilesPathRequest names one file or folder.
type FilesPathRequest struct {
	Share string `json:"share"`
	Path  string `json:"path"`
}

func (s *Server) handleFilesMkdir(w http.ResponseWriter, r *http.Request, u *auth.User) {
	who, ok := s.filesWho(w, u)
	if !ok {
		return
	}
	var req FilesPathRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.cfg.Files.Mkdir(r.Context(), who, req.Share, req.Path); err != nil {
		s.writeFilesError(w, err)
		return
	}
	e, err := s.cfg.Files.Stat(r.Context(), who, req.Share, req.Path)
	if err != nil {
		s.writeFilesError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, e)
}

// FilesRenameRequest renames or moves one item: To is its new path, in
// ToShare (default: the same share).
type FilesRenameRequest struct {
	Share   string `json:"share"`
	Path    string `json:"path"`
	ToShare string `json:"toShare,omitempty"`
	To      string `json:"to"`
}

// FilesPathResponse says where something ended up.
type FilesPathResponse struct {
	Share string `json:"share"`
	Path  string `json:"path"`
}

func (s *Server) handleFilesRename(w http.ResponseWriter, r *http.Request, u *auth.User) {
	who, ok := s.filesWho(w, u)
	if !ok {
		return
	}
	var req FilesRenameRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.ToShare == "" {
		req.ToShare = req.Share
	}
	if req.ToShare != req.Share {
		// Between shared folders it's a copy: a job.
		e, err := s.cfg.Files.Stat(r.Context(), who, req.Share, req.Path)
		if err != nil {
			s.writeFilesError(w, err)
			return
		}
		folder, name := path.Split(strings.Trim(req.To, "/"))
		p := filesBulk{Who: who, Share: req.Share, Paths: []string{req.Path}, ToShare: req.ToShare, ToFolder: strings.Trim(folder, "/"),
			Names: []string{name}, Move: true, Conflict: files.ConflictFail}
		s.submit(w, r, u, JobKindFilesMove, "Move "+e.Name, p, "files.move", req.Share+":/"+strings.Trim(req.Path, "/"), nil)
		return
	}
	if err := s.cfg.Files.Rename(r.Context(), who, req.Share, req.Path, req.ToShare, req.To); err != nil {
		s.writeFilesError(w, err)
		return
	}
	s.record(r, u, "files.rename", req.Share+":/"+strings.Trim(req.Path, "/"), audit.Success, "to /"+strings.Trim(req.To, "/"))
	writeJSON(w, http.StatusOK, FilesPathResponse{Share: req.ToShare, Path: strings.Trim(req.To, "/")})
}

// FilesCopyRequest copies (or moves) items into a folder.
type FilesCopyRequest struct {
	Share    string   `json:"share"`
	Paths    []string `json:"paths"`
	ToShare  string   `json:"toShare,omitempty"`
	ToFolder string `json:"toFolder"`
	Move     bool   `json:"move,omitempty"`
	// Conflict: rename (default), skip, replace or fail.
	Conflict files.Conflict `json:"conflict,omitempty"`
}

// filesBulk is a copy, move or delete job's parameters.
type filesBulk struct {
	Who      files.Who      `json:"who"`
	Share    string         `json:"share"`
	Paths    []string       `json:"paths"`
	ToShare  string         `json:"toShare,omitempty"`
	ToFolder string         `json:"toFolder,omitempty"`
	Names    []string       `json:"names,omitempty"` // new names (a move with a rename)
	Move     bool           `json:"move,omitempty"`
	Conflict files.Conflict `json:"conflict,omitempty"`
	// Delete:
	Permanent bool `json:"permanent,omitempty"`
	// Restore:
	Snapshot string `json:"snapshot,omitempty"`
}

// FilesItemResult is what happened to one item.
type FilesItemResult struct {
	Path     string `json:"path"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Code     string `json:"code,omitempty"`
	To       string `json:"to,omitempty"`       // copies and moves: where it went
	Skipped  bool   `json:"skipped,omitempty"`  // copies: the name was taken (conflict skip)
	Recycled bool   `json:"recycled,omitempty"` // deletes: to the recycle bin
}

// FilesBulkResult is a copy's, move's or delete's outcome (inline, or a
// job's result).
type FilesBulkResult struct {
	Done    bool              `json:"done"`
	Results []FilesItemResult `json:"results"`
}

func errCode(err error) string {
	switch {
	case errors.Is(err, files.ErrNotFound):
		return "not_found"
	case errors.Is(err, files.ErrNoAccess):
		return "no_access"
	case errors.Is(err, files.ErrExists):
		return "exists"
	case errors.Is(err, files.ErrNotAllowed):
		return "not_allowed"
	case errors.Is(err, files.ErrFull):
		return "full"
	}
	return "failed"
}

func itemErr(p string, err error) FilesItemResult {
	msg := err.Error()
	var fe *files.Error
	if errors.As(err, &fe) {
		msg = fe.Msg
	}
	var pe *priv.Error
	if errors.As(err, &pe) {
		msg = pe.Message
	}
	return FilesItemResult{Path: p, Error: msg, Code: errCode(err)}
}

func checkConflict(c files.Conflict) (files.Conflict, bool) {
	switch c {
	case "":
		return files.ConflictRename, true
	case files.ConflictRename, files.ConflictSkip, files.ConflictReplace, files.ConflictFail:
		return c, true
	}
	return c, false
}

// runCopy copies or moves the items one by one.
func runCopy(ctx context.Context, fs files.Service, p filesBulk, progress func(pct float64, msg string)) FilesBulkResult {
	res := FilesBulkResult{Done: true, Results: []FilesItemResult{}}
	toShare := p.ToShare
	if toShare == "" {
		toShare = p.Share
	}
	for i, item := range p.Paths {
		if ctx.Err() != nil {
			res.Results = append(res.Results, itemErr(item, ctx.Err()))
			continue
		}
		name := path.Base(strings.Trim(item, "/"))
		if i < len(p.Names) && p.Names[i] != "" {
			name = p.Names[i]
		}
		to := strings.Trim(path.Join(p.ToFolder, name), "/")
		base := float64(i) / float64(len(p.Paths)) * 100
		each := 100 / float64(len(p.Paths))
		report := func(pr files.Progress) {
			if progress == nil {
				return
			}
			frac := 0.0
			if pr.TotalBytes > 0 {
				frac = float64(pr.Bytes) / float64(pr.TotalBytes)
			} else if pr.TotalFiles > 0 {
				frac = float64(pr.Files) / float64(pr.TotalFiles)
			}
			verb := "Copying"
			if p.Move {
				verb = "Moving"
			}
			progress(base+frac*each, fmt.Sprintf("%s %s (%d of %d files)", verb, pr.Current, pr.Files, pr.TotalFiles))
		}
		var dest string
		var err error
		sameShare := toShare == p.Share
		switch {
		case p.Move && sameShare:
			dest = to
			if p.Conflict == files.ConflictRename || p.Conflict == files.ConflictSkip {
				if _, serr := fs.Stat(ctx, p.Who, toShare, to); serr == nil {
					if p.Conflict == files.ConflictSkip {
						res.Results = append(res.Results, FilesItemResult{Path: item, OK: true, Skipped: true})
						continue
					}
					dest, err = freeName(ctx, fs, p.Who, toShare, to)
				}
			}
			if err == nil {
				err = fs.Rename(ctx, p.Who, p.Share, item, toShare, dest)
			}
		case p.Move:
			// Another share: copy, then delete the original for good.
			dest, err = fs.CopyTree(ctx, p.Who, files.Location{Share: p.Share, Path: item}, files.Location{Share: toShare, Path: to},
				files.CopyOptions{Conflict: p.Conflict, Progress: report})
			if err == nil && dest != "" {
				if _, derr := fs.DeleteItem(ctx, p.Who, p.Share, item, true); derr != nil {
					err = fmt.Errorf("copied to %s, but the original couldn't be removed: %w", dest, derr)
				}
			}
		default:
			dest, err = fs.CopyTree(ctx, p.Who, files.Location{Share: p.Share, Path: item}, files.Location{Share: toShare, Path: to},
				files.CopyOptions{Conflict: p.Conflict, Progress: report})
		}
		if err != nil {
			res.Results = append(res.Results, itemErr(item, err))
			continue
		}
		res.Results = append(res.Results, FilesItemResult{Path: item, OK: true, To: dest, Skipped: dest == ""})
	}
	return res
}

// freeName finds "name (2).ext" style names for a move onto a taken name.
func freeName(ctx context.Context, fs files.Service, who files.Who, share, p string) (string, error) {
	dir, name := path.Split(p)
	stem, ext := name, ""
	if i := strings.LastIndexByte(name, '.'); i > 0 {
		stem, ext = name[:i], name[i:]
	}
	for i := 2; i <= 100; i++ {
		cand := fmt.Sprintf("%s%s (%d)%s", dir, stem, i, ext)
		if _, err := fs.Stat(ctx, who, share, cand); errors.Is(err, files.ErrNotFound) {
			return cand, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", &files.Error{Kind: files.ErrExists, Msg: name + " is already there many times over"}
}

func runDelete(ctx context.Context, fs files.Service, p filesBulk, progress func(pct float64, msg string)) FilesBulkResult {
	res := FilesBulkResult{Done: true, Results: []FilesItemResult{}}
	for i, item := range p.Paths {
		if progress != nil {
			progress(float64(i)/float64(len(p.Paths))*100, "Deleting "+path.Base(strings.Trim(item, "/")))
		}
		if ctx.Err() != nil {
			res.Results = append(res.Results, itemErr(item, ctx.Err()))
			continue
		}
		recycled, err := fs.DeleteItem(ctx, p.Who, p.Share, item, p.Permanent)
		if err != nil {
			res.Results = append(res.Results, itemErr(item, err))
			continue
		}
		res.Results = append(res.Results, FilesItemResult{Path: item, OK: true, Recycled: recycled})
	}
	return res
}

func cleanItems(w http.ResponseWriter, paths []string) ([]string, bool) {
	if len(paths) == 0 {
		writeError(w, http.StatusBadRequest, "invalid", "choose at least one file or folder")
		return nil, false
	}
	if len(paths) > maxItems {
		writeError(w, http.StatusBadRequest, "invalid", fmt.Sprintf("at most %d items at once", maxItems))
		return nil, false
	}
	out := make([]string, 0, len(paths))
	seen := map[string]bool{}
	for _, p := range paths {
		p = strings.Trim(p, "/")
		if p == "" {
			writeError(w, http.StatusConflict, "not_allowed", "the top of a shared folder can't be copied, moved or deleted")
			return nil, false
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, true
}

// auditNames lists items for an audit entry, shortened.
func auditNames(paths []string) string {
	s := strings.Join(paths, ", ")
	if len(s) > 900 {
		s = s[:900] + fmt.Sprintf("... (%d items)", len(paths))
	}
	return s
}

// singleError answers a one-item request that failed with the item's error.
func (s *Server) singleError(w http.ResponseWriter, res FilesBulkResult) bool {
	if len(res.Results) != 1 || res.Results[0].OK {
		return false
	}
	r := res.Results[0]
	status := map[string]int{"not_found": 404, "no_access": 403, "exists": 409, "not_allowed": 409, "full": 507}[r.Code]
	if status == 0 {
		status = http.StatusUnprocessableEntity
	}
	writeError(w, status, r.Code, r.Error)
	return true
}

func (s *Server) handleFilesCopy(w http.ResponseWriter, r *http.Request, u *auth.User) {
	who, ok := s.filesWho(w, u)
	if !ok {
		return
	}
	var req FilesCopyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	paths, ok := cleanItems(w, req.Paths)
	if !ok {
		return
	}
	conflict, ok := checkConflict(req.Conflict)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid", "conflict must be rename, skip, replace or fail")
		return
	}
	if req.ToShare == "" {
		req.ToShare = req.Share
	}
	p := filesBulk{Who: who, Share: req.Share, Paths: paths, ToShare: req.ToShare, ToFolder: strings.Trim(req.ToFolder, "/"), Move: req.Move, Conflict: conflict}
	ctx := r.Context()
	// Quick ones at once: a few files, or moves within a folder's share.
	quick := len(paths) <= syncItems
	if quick && !(req.Move && req.ToShare == req.Share) {
		for _, it := range paths {
			e, err := s.cfg.Files.Stat(ctx, who, req.Share, it)
			if err != nil {
				if len(paths) == 1 {
					s.writeFilesError(w, err)
					return
				}
				continue
			}
			if e.Dir || e.Size > 256<<20 {
				quick = false
			}
		}
	}
	action, verb := "files.copy", "Copy"
	kind := JobKindFilesCopy
	if req.Move {
		action, verb, kind = "files.move", "Move", JobKindFilesMove
	}
	target := req.Share + ":/" + strings.Join(paths, ", /")
	if len(paths) > 3 {
		target = fmt.Sprintf("%s: %d items", req.Share, len(paths))
	}
	if !quick {
		title := fmt.Sprintf("%s %d items", verb, len(paths))
		if len(paths) == 1 {
			title = verb + " " + path.Base(paths[0])
		}
		s.submit(w, r, u, kind, title, p, action, target, nil)
		return
	}
	res := runCopy(ctx, s.cfg.Files, p, nil)
	if req.Move {
		s.record(r, u, action, target, audit.Success, "to "+req.ToShare+":/"+p.ToFolder)
	}
	if s.singleError(w, res) {
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// FilesDeleteRequest deletes items (to the recycle bin unless Permanent).
type FilesDeleteRequest struct {
	Share     string   `json:"share"`
	Paths     []string `json:"paths"`
	Permanent bool     `json:"permanent,omitempty"`
}

func (s *Server) handleFilesDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	who, ok := s.filesWho(w, u)
	if !ok {
		return
	}
	var req FilesDeleteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	paths, ok := cleanItems(w, req.Paths)
	if !ok {
		return
	}
	p := filesBulk{Who: who, Share: req.Share, Paths: paths, Permanent: req.Permanent}
	how := "to the recycle bin if the folder has one"
	if req.Permanent {
		how = "permanently"
	}
	if len(paths) > syncItems {
		s.submit(w, r, u, JobKindFilesDelete, fmt.Sprintf("Delete %d items", len(paths)), p, "files.delete",
			fmt.Sprintf("%s: %d items", req.Share, len(paths)), nil)
		return
	}
	res := runDelete(r.Context(), s.cfg.Files, p, nil)
	var done []string
	for _, it := range res.Results {
		if it.OK {
			done = append(done, "/"+it.Path)
		}
	}
	if len(done) > 0 {
		s.record(r, u, "files.delete", req.Share+":"+auditNames(done), audit.Success, how)
	}
	if s.singleError(w, res) {
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// FilesRestoreRequest restores an older version of a file or folder.
type FilesRestoreRequest struct {
	Share    string `json:"share"`
	Path     string `json:"path"`
	Snapshot string `json:"snapshot"`
}

func (s *Server) handleFilesRestore(w http.ResponseWriter, r *http.Request, u *auth.User) {
	who, ok := s.filesWho(w, u)
	if !ok {
		return
	}
	var req FilesRestoreRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Path = strings.Trim(req.Path, "/")
	e, err := s.cfg.Files.StatVersion(r.Context(), who, req.Share, req.Path, req.Snapshot)
	if err != nil {
		s.writeFilesError(w, err)
		return
	}
	target := req.Share + ":/" + req.Path
	if e.Dir || e.Size > 256<<20 {
		p := filesBulk{Who: who, Share: req.Share, Paths: []string{req.Path}, Snapshot: req.Snapshot}
		s.submit(w, r, u, JobKindFilesRestore, "Restore "+e.Name, p, "files.restore", target, nil)
		return
	}
	to, err := s.cfg.Files.Restore(r.Context(), who, req.Share, req.Path, req.Snapshot)
	if err != nil {
		s.writeFilesError(w, err)
		return
	}
	s.record(r, u, "files.restore", target, audit.Success, "from "+req.Snapshot+" to /"+to)
	writeJSON(w, http.StatusOK, FilesPathResponse{Share: req.Share, Path: to})
}

// RegisterFileJobs adds the bulk file jobs (copy, move, delete, restore),
// run as the person who asked through fs.
func RegisterFileJobs(m *jobs.Manager, fs files.Service) {
	params := func(jc *jobs.Context) (filesBulk, error) {
		var p filesBulk
		err := jc.Params(&p)
		return p, err
	}
	finish := func(res FilesBulkResult) (any, error) {
		failed := 0
		for _, r := range res.Results {
			if !r.OK {
				failed++
			}
		}
		if failed > 0 && failed == len(res.Results) {
			return nil, &jobs.FailedWith{Err: errors.New(res.Results[0].Error), Result: res}
		}
		return res, nil
	}
	copyRun := func(jc *jobs.Context) (any, error) {
		p, err := params(jc)
		if err != nil {
			return nil, err
		}
		res := runCopy(jc, fs, p, jc.Progress)
		jc.Progress(100, "Done")
		return finish(res)
	}
	m.Register(jobs.Kind{Name: JobKindFilesCopy, Run: copyRun})
	m.Register(jobs.Kind{Name: JobKindFilesMove, Run: copyRun})
	m.Register(jobs.Kind{Name: JobKindFilesDelete, Run: func(jc *jobs.Context) (any, error) {
		p, err := params(jc)
		if err != nil {
			return nil, err
		}
		res := runDelete(jc, fs, p, jc.Progress)
		jc.Progress(100, "Done")
		return finish(res)
	}})
	m.Register(jobs.Kind{Name: JobKindFilesRestore, Run: func(jc *jobs.Context) (any, error) {
		p, err := params(jc)
		if err != nil {
			return nil, err
		}
		if len(p.Paths) != 1 {
			return nil, errors.New("restore one item at a time")
		}
		to, err := fs.RestoreWith(jc, p.Who, p.Share, p.Paths[0], p.Snapshot, func(pr files.Progress) {
			pct := 0.0
			if pr.TotalBytes > 0 {
				pct = float64(pr.Bytes) / float64(pr.TotalBytes) * 100
			}
			jc.Progress(pct, fmt.Sprintf("Restoring %s (%d of %d files)", pr.Current, pr.Files, pr.TotalFiles))
		})
		if err != nil {
			return nil, err
		}
		jc.Progress(100, "Restored")
		return FilesPathResponse{Share: p.Share, Path: to}, nil
	}})
}
