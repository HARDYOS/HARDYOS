package office

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/files"
	"github.com/hardyos/hardyos/daemon/internal/fileworker"
)

// Callback statuses (OnlyOffice's callback handler API).
const (
	StatusEditing     = 1 // someone joined or left
	StatusReady       = 2 // everyone closed it; save
	StatusSaveError   = 3
	StatusClosed      = 4 // closed without changes
	StatusForceSave   = 6 // saved while still open
	StatusForceSaveEr = 7
)

// Callback is what the Document Server posts to the callback URL.
type Callback struct {
	Key      string   `json:"key"`
	Status   int      `json:"status"`
	URL      string   `json:"url,omitempty"`
	FileType string   `json:"filetype,omitempty"`
	Users    []string `json:"users,omitempty"`
	Actions  []struct {
		Type   int    `json:"type"`
		UserID string `json:"userid"`
	} `json:"actions,omitempty"`
	ForceSaveType *int   `json:"forcesavetype,omitempty"`
	Token         string `json:"token,omitempty"`
}

// Callback refusals (also what tests look for).
var (
	ErrCallbackToken   = errors.New("the callback isn't signed with the office secret")
	ErrCallbackKey     = errors.New("the callback is for another document")
	ErrCallbackSession = errors.New("there's no open editing session for this document")
	ErrCallbackUser    = errors.New("the callback names nobody who opened the document for editing")
	ErrReplay          = errors.New("this save was already handled")
)

// MaxCallbackBytes bounds a callback body.
const MaxCallbackBytes = 1 << 20

// CallbackResult is how a callback ended.
type CallbackResult struct {
	// Saved is the path written (empty when nothing was).
	Saved string
	// Conflict: the file changed outside the editor, so the save went next
	// to it under another name.
	Conflict bool
	// Duplicate: a resent callback that was already handled.
	Duplicate bool
}

// ParseCallback verifies a callback's token and returns its payload. The
// token is in the Authorization header ("Bearer <jwt>", its claims carry the
// payload under "payload") or in the body's "token" (its claims are the
// payload). The signed payload is what counts; unsigned body fields are
// ignored.
func ParseCallback(secret []byte, header string, body []byte, now time.Time) (*Callback, error) {
	var raw Callback
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("the callback isn't JSON: %w", err)
	}
	token, nested := raw.Token, false
	if h := strings.TrimSpace(header); h != "" {
		t, ok := strings.CutPrefix(h, "Bearer ")
		if !ok {
			return nil, ErrCallbackToken
		}
		token, nested = strings.TrimSpace(t), true
	}
	if token == "" {
		return nil, ErrCallbackToken
	}
	claims, err := VerifyJWT(secret, token, VerifyOptions{Now: now, RequireExp: true, MaxAge: time.Hour})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCallbackToken, err)
	}
	var cb Callback
	if nested {
		var wrap struct {
			Payload *Callback `json:"payload"`
		}
		if err := json.Unmarshal(claims, &wrap); err != nil {
			return nil, ErrCallbackToken
		}
		if wrap.Payload != nil {
			cb = *wrap.Payload
		} else if err := json.Unmarshal(claims, &cb); err != nil {
			return nil, ErrCallbackToken
		}
	} else if err := json.Unmarshal(claims, &cb); err != nil {
		return nil, ErrCallbackToken
	}
	if !ValidKey(cb.Key) {
		return nil, ErrCallbackKey
	}
	return &cb, nil
}

func fingerprint(cb *Callback) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00%s\x00%s\x00%s", cb.Status, cb.URL, cb.FileType, strings.Join(cb.Users, ","))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Service) keyLock(key string) func() {
	s.mu.Lock()
	if s.keyLocks == nil {
		s.keyLocks = map[string]*sync.Mutex{}
	}
	l := s.keyLocks[key]
	if l == nil {
		l = &sync.Mutex{}
		s.keyLocks[key] = l
	}
	s.mu.Unlock()
	l.Lock()
	return l.Unlock
}

// HandleCallback acts on a verified callback for the document key in its
// URL (pathKey): records who is in the document, or saves it.
func (s *Service) HandleCallback(ctx context.Context, pathKey string, cb *Callback) (*CallbackResult, error) {
	if cb.Key != pathKey {
		return nil, ErrCallbackKey
	}
	unlock := s.keyLock(cb.Key)
	defer unlock()
	sess, err := s.db().session(ctx, cb.Key)
	if err != nil {
		return nil, ErrCallbackSession
	}
	now := s.now()
	target := sess.Share + ":/" + sess.Path
	switch cb.Status {
	case StatusEditing:
		if sess.State != StateOpen {
			return &CallbackResult{}, nil
		}
		return &CallbackResult{}, s.db().setActive(ctx, sess.Key, s.knownUsers(ctx, sess.Key, cb.Users), now)
	case StatusClosed:
		if sess.State == StateOpen {
			_ = s.db().setState(ctx, sess.Key, StateClosed, "", now)
		}
		return &CallbackResult{}, nil
	case StatusSaveError, StatusForceSaveEr:
		s.audit(ctx, AuditEvent{Action: "office.save", Target: target, Outcome: audit.Failure,
			Detail: "the Document Server couldn't assemble the document (status " + strconv.Itoa(cb.Status) + ")"})
		if cb.Status == StatusSaveError {
			_ = s.db().setState(ctx, sess.Key, StateError, "the Document Server couldn't save the document", now)
		}
		return &CallbackResult{}, nil
	case StatusReady, StatusForceSave:
	default:
		return &CallbackResult{}, nil
	}

	fp := fingerprint(cb)
	if s.db().seenCallback(ctx, sess.Key, fp) {
		// The Document Server sends a callback again when the answer to the
		// first got lost; it was handled, so it's acknowledged, never
		// written twice. A forged copy of an old callback ends here too.
		return &CallbackResult{Duplicate: true}, nil
	}
	if sess.State != StateOpen {
		s.audit(ctx, AuditEvent{Action: "office.save", Target: target, Outcome: audit.Denied, Detail: "the session was already over"})
		return nil, ErrCallbackSession
	}
	res, p, err := s.save(ctx, sess, cb)
	if err != nil {
		s.audit(ctx, AuditEvent{Action: "office.save", Target: target, Outcome: audit.Denied, Detail: err.Error(), Participant: p})
		if cb.Status == StatusReady {
			_ = s.db().setState(ctx, sess.Key, StateError, err.Error(), now)
		}
		return nil, err
	}
	if _, err := s.db().markCallback(ctx, sess.Key, fp, cb.Status, now); err != nil {
		s.log().Warn("office: recording a callback", "err", err)
	}
	detail := fmt.Sprintf("saved by the editor (%s)", map[int]string{StatusReady: "everyone closed it", StatusForceSave: "saved while open"}[cb.Status])
	if res.Conflict {
		detail += "; the file had changed outside the editor, so this was saved as " + res.Saved
	}
	s.audit(ctx, AuditEvent{Action: "files.write", Target: sess.Share + ":/" + res.Saved, Outcome: audit.Success, Detail: detail, Participant: p})
	if cb.Status == StatusReady {
		_ = s.db().setState(ctx, sess.Key, StateClosed, "", now)
	}
	return res, nil
}

// knownUsers keeps the ids that are this session's participants.
func (s *Service) knownUsers(ctx context.Context, key string, ids []string) []string {
	list, err := s.db().participants(ctx, key)
	if err != nil {
		return []string{}
	}
	known := map[string]bool{}
	for _, p := range list {
		known[p.ID] = true
	}
	out := []string{}
	seen := map[string]bool{}
	for _, id := range ids {
		if known[id] && !seen[id] {
			out = append(out, id)
			seen[id] = true
		}
	}
	return out
}

// save writes the document the Document Server assembled back to the
// session's file, as the participant who made the last change, if they
// still may; or next to it, when the file changed outside the editor.
func (s *Service) save(ctx context.Context, sess *Session, cb *Callback) (*CallbackResult, *Participant, error) {
	if len(cb.Users) == 0 {
		return nil, nil, ErrCallbackUser
	}
	// "users" names the last person who changed the document first.
	p, err := s.db().participant(ctx, sess.Key, cb.Users[0])
	if err != nil {
		return nil, nil, ErrCallbackUser
	}
	if p.Mode != ModeEdit {
		return nil, p, fmt.Errorf("%w (%s had it open read only)", ErrCallbackUser, p.Name)
	}
	src, err := s.InternalURL(cb.URL)
	if err != nil {
		return nil, p, err
	}
	who, err := s.Identity(ctx, *p, sess, true)
	if err != nil {
		return nil, p, fmt.Errorf("%s can't change this file any more: %w", p.Name, err)
	}
	e, err := s.Files.Stat(ctx, who, sess.Share, sess.Path)
	conflict := false
	target := sess.Path
	switch {
	case errors.Is(err, files.ErrNotFound):
		// Moved or deleted while open: the edits are kept as a new file
		// where it was, if the folder is still there.
		conflict = true
	case err != nil:
		return nil, p, err
	case e.Dir:
		return nil, p, ErrIsFolder
	case !e.Writable:
		return nil, p, fmt.Errorf("%s can't change this file any more", p.Name)
	case !sameVersion(e, sess.BaseModified, sess.BaseSize):
		conflict = true
	}
	if ft := strings.ToLower(cb.FileType); ft != "" && ft != sess.FileType {
		// Saved in another format (an old binary file): never over the original.
		target = strings.TrimSuffix(target, path.Ext(target)) + "." + ft
		conflict = true
	}
	if !conflict {
		// Replacing needs write access to the file itself, not only its
		// folder (a rename into place only asks the folder): open it for
		// writing as the person first, as WebDAV does.
		wf, _, err := s.Files.OpenWrite(ctx, who, sess.Share, sess.Path)
		if err != nil {
			return nil, p, fmt.Errorf("%s can't change this file any more: %w", p.Name, err)
		}
		_ = wf.Close()
	}

	body, err := s.fetch(ctx, src)
	if err != nil {
		return nil, p, err
	}
	defer body.Close()

	dir := path.Dir(target)
	if dir == "." {
		dir = ""
	}
	tmp := path.Join(dir, fileworker.UploadPrefix+newID(""))
	f, err := s.Files.Create(ctx, who, sess.Share, tmp, false)
	if err != nil {
		return nil, p, err
	}
	max := s.maxBytes()
	n, err := io.Copy(f, io.LimitReader(body, max+1))
	if err == nil && n > max {
		err = ErrTooBig
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	drop := func() { _, _ = s.Files.DeleteItem(context.WithoutCancel(ctx), who, sess.Share, tmp, true) }
	if err != nil {
		drop()
		return nil, p, fmt.Errorf("receiving the saved document: %w", err)
	}
	if conflict {
		target, err = s.freeName(ctx, who, sess.Share, target, p.Name)
		if err == nil {
			err = s.Files.Rename(ctx, who, sess.Share, tmp, sess.Share, target)
		}
	} else {
		err = s.Files.Replace(ctx, who, sess.Share, tmp, target)
	}
	if err != nil {
		drop()
		return nil, p, err
	}
	if !conflict {
		if ne, err := s.Files.Stat(ctx, who, sess.Share, target); err == nil {
			_ = s.db().saved(ctx, sess.Key, ne.Modified, ne.Size, s.now())
		}
	}
	return &CallbackResult{Saved: target, Conflict: conflict}, p, nil
}

// freeName is "name (edited by Alice 2026-10-27 1504).docx", numbered if taken.
func (s *Service) freeName(ctx context.Context, who files.Who, share, p, by string) (string, error) {
	dir, name := path.Split(p)
	ext := path.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	tag := "edited by " + strings.NewReplacer("/", "-", `\`, "-").Replace(by) + " " + s.now().Format("2006-01-02 1504")
	for i := 1; i <= 50; i++ {
		cand := fmt.Sprintf("%s (%s)%s", stem, tag, ext)
		if i > 1 {
			cand = fmt.Sprintf("%s (%s %d)%s", stem, tag, i, ext)
		}
		if fileworker.CleanName(cand) != nil {
			cand = fmt.Sprintf("%s (edited %d)%s", stem, i, ext)
		}
		full := dir + cand
		if _, err := s.Files.Stat(ctx, who, share, full); errors.Is(err, files.ErrNotFound) {
			return full, nil
		}
	}
	return "", errors.New("no free name for the edited copy")
}

// fetch gets a document from the Document Server's own port.
func (s *Service) fetch(ctx context.Context, u fmtURL) (io.ReadCloser, error) {
	c := s.HTTP
	if c == nil {
		c = s.defaultClient()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		cancel()
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("fetching the saved document from the Document Server: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("the Document Server answered %d for the saved document", resp.StatusCode)
	}
	return &cancelBody{ReadCloser: resp.Body, cancel: cancel}, nil
}

type fmtURL interface{ String() string }

type cancelBody struct {
	io.ReadCloser
	cancel func()
}

func (c *cancelBody) Close() error { err := c.ReadCloser.Close(); c.cancel(); return err }

// defaultClient dials only the Document Server's internal address, uses no
// proxy and follows no redirects.
func (s *Service) defaultClient() *http.Client {
	dial := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				in, err := s.Internal()
				if err != nil {
					return nil, err
				}
				if addr != in.Host {
					return nil, fmt.Errorf("refusing to connect to %s", addr)
				}
				return dial.DialContext(ctx, network, addr)
			},
			ResponseHeaderTimeout: time.Minute,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func ioCopyN(w io.Writer, r io.Reader, n int64) (int64, error) { return io.CopyN(w, r, n) }
