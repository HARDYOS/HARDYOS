package office

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/files"
)

// ---- what a save may be ----------------------------------------------------------

var fileTypeRE = regexp.MustCompile(`^[a-z0-9]{1,8}$`)

// saveFormats are the formats the Document Server may hand back for a
// document type when saving.
var saveFormats = map[string]map[string]bool{
	"word":  {"docx": true, "odt": true, "rtf": true, "txt": true},
	"cell":  {"xlsx": true, "ods": true, "csv": true},
	"slide": {"pptx": true, "odp": true},
}

// SaveFormat reports whether a save of a file of type orig may come back as
// ft: a short lowercase extension the editor writes for that kind of
// document (decision 274).
func SaveFormat(orig, ft string) bool {
	if !fileTypeRE.MatchString(ft) {
		return false
	}
	f, ok := FormatOf("x." + orig)
	if !ok {
		return false
	}
	return saveFormats[f.DocumentType][ft]
}

// ---- dropping people ------------------------------------------------------------

// CommandPath is the Document Server's command service.
const CommandPath = "/coauthoring/CommandService.ashx"

// Command sends a JWT-signed command to the Document Server's command
// service on its internal address and returns its error code (0 = done).
func (s *Service) Command(ctx context.Context, cmd map[string]any) (int, json.RawMessage, error) {
	in, err := s.Internal()
	if err != nil {
		return 0, nil, err
	}
	secret, err := s.Secret(ctx)
	if err != nil {
		return 0, nil, err
	}
	now := s.now()
	tok, err := SignJWT(secret, map[string]any{"payload": cmd, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()})
	if err != nil {
		return 0, nil, err
	}
	body, _ := json.Marshal(cmd)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, in.String()+CommandPath, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	c := s.HTTP
	if c == nil {
		c = s.defaultClient()
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var out struct {
		Error *int `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Error == nil {
		return 0, raw, fmt.Errorf("the Document Server answered %d: %.200q", resp.StatusCode, raw)
	}
	return *out.Error, raw, nil
}

// Drop asks the Document Server to put participants out of a document.
// Error code 1 (the document isn't open there any more) counts as done.
func (s *Service) Drop(ctx context.Context, key string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	code, raw, err := s.Command(ctx, map[string]any{"c": "drop", "key": key, "users": ids})
	if err != nil {
		return err
	}
	if code != 0 && code != 1 {
		return fmt.Errorf("the Document Server didn't drop them (error %d: %.200s)", code, raw)
	}
	return nil
}

func (s *Service) dropAsync(key string, ids []string, why string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s.dropAndRecord(ctx, key, ids, why)
}

func (s *Service) dropAndRecord(ctx context.Context, key string, ids []string, why string) {
	err := s.Drop(ctx, key, ids)
	sess, serr := s.db().session(ctx, key)
	target := "document " + key[:8]
	if serr == nil {
		target = sess.Share + ":/" + sess.Path
	}
	for _, id := range ids {
		p, perr := s.db().participant(ctx, key, id)
		if perr != nil {
			continue
		}
		out, detail := audit.Success, "put out of the document: "+why
		if err != nil {
			out, detail = audit.Failure, "couldn't put out of the document ("+why+"): "+err.Error()
		}
		s.audit(ctx, AuditEvent{Action: "office.drop", Target: target, Outcome: out, Detail: detail, Participant: p})
	}
}

// invalid lists the participants among ids who may no longer be in the
// session (their link or account, or their access to the file, is gone).
func (s *Service) invalid(ctx context.Context, sess *Session, ids []string) []string {
	var bad []string
	for _, id := range ids {
		p, err := s.db().participant(ctx, sess.Key, id)
		if err != nil {
			continue
		}
		who, err := s.Identity(ctx, *p, sess, p.Mode == ModeEdit)
		if err != nil || LocationOf(sess.Share, who) != sess.Location {
			bad = append(bad, id)
			continue
		}
		if _, err := s.Files.Stat(ctx, who, sess.Share, sess.Path); errors.Is(err, files.ErrNoAccess) {
			bad = append(bad, id)
		}
	}
	return bad
}

// DropLink puts everyone who came in through a share link out of their
// documents (the link was turned off).
func (s *Service) DropLink(ctx context.Context, linkID int64, why string) {
	if s.DB == nil {
		return
	}
	list, err := s.db().linkParticipants(ctx, linkID)
	if err != nil {
		return
	}
	s.dropList(ctx, list, why)
}

// DropUser puts an account out of every document (it was turned off,
// deleted or is gone from the domain).
func (s *Service) DropUser(ctx context.Context, userID int64, why string) {
	if s.DB == nil {
		return
	}
	list, err := s.db().userParticipants(ctx, userID)
	if err != nil {
		return
	}
	s.dropList(ctx, list, why)
}

func (s *Service) dropList(ctx context.Context, list []Participant, why string) {
	byKey := map[string][]string{}
	for _, p := range list {
		if !p.SeenAt.IsZero() && p.LeftAt.IsZero() {
			byKey[p.Key] = append(byKey[p.Key], p.ID)
		}
	}
	for key, ids := range byKey {
		s.dropAndRecord(ctx, key, ids, why)
	}
}

// Sweep keeps open sessions honest (every minute, and right after a link is
// turned off or an account disabled): a session nobody is in is closed
// after EmptySessionQuiet; one the Document Server hasn't reported on for
// MaxSessionQuiet is closed and its people dropped; anyone in a document
// who may no longer be is dropped (decisions 265, 267).
func (s *Service) Sweep(ctx context.Context) {
	if s.DB == nil {
		return
	}
	list, err := s.db().openSessions(ctx)
	if err != nil {
		return
	}
	now := s.now()
	for _, sess := range list {
		quiet := now.Sub(sess.lastActivity())
		switch {
		case len(sess.Active) == 0 && quiet > EmptySessionQuiet:
			_ = s.db().setState(ctx, sess.Key, StateClosed, "nobody was in it", now)
		case quiet > MaxSessionQuiet:
			s.dropAndRecord(ctx, sess.Key, sess.Active, "the editing session went quiet for a day")
			_ = s.db().setState(ctx, sess.Key, StateClosed, "the Document Server stopped reporting on it", now)
		default:
			if bad := s.invalid(ctx, sess, sess.Active); len(bad) > 0 {
				s.dropAndRecord(ctx, sess.Key, bad, "no longer allowed")
			}
		}
	}
	s.db().prune(ctx, now)
}
