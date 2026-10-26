// Package updates is hardyd's side of system updates: it receives update
// files (upload or download), runs installs as jobs through hardyd-priv,
// confirms a new version once hardyd is healthy on it, and reports results
// in the notification center.
package updates

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/update"
)

// Job kinds.
const (
	JobInstall  = "system.update"
	JobDownload = "system.update.download"
	JobActivate = "system.version.activate"
	JobDelete   = "system.version.delete"
)

// MaxBundleBytes bounds an uploaded or downloaded update file.
const MaxBundleBytes = 4 << 30

// stageTimeout bounds unpacking a new version.
const stageTimeout = 45 * time.Minute

// Service runs updates for hardyd.
type Service struct {
	Priv   *priv.Client
	Jobs   *jobs.Manager
	Notify *notify.Center
	DB     *store.DB
	Log    *slog.Logger
	// Dir is where update files are saved (update.Updater.UploadDir()).
	Dir string
	// HTTP downloads updates (default: http.DefaultClient with a timeout).
	HTTP *http.Client
}

func (s *Service) dir() string {
	if s.Dir == "" {
		return "/var/lib/hardyos/updates"
	}
	return s.Dir
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Status asks hardyd-priv for installed versions and update state.
func (s *Service) Status(ctx context.Context) (*update.Status, error) {
	var st update.Status
	if err := s.Priv.Call(ctx, priv.OpUpdateStatus, nil, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// ErrTooLarge means an update file exceeded MaxBundleBytes.
var ErrTooLarge = errors.New("the update file is too large")

// Save writes an update file from r into the updates directory and returns
// its path. Partial files are removed on error.
func (s *Service) Save(r io.Reader) (string, error) {
	if err := os.MkdirAll(s.dir(), 0o750); err != nil {
		return "", err
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	path := filepath.Join(s.dir(), "upload-"+hex.EncodeToString(b)+".hupd")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return "", err
	}
	n, err := io.Copy(f, io.LimitReader(r, MaxBundleBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > MaxBundleBytes {
		err = ErrTooLarge
	}
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

type installParams struct {
	Path string `json:"path"`
}

type downloadParams struct {
	URL string `json:"url"`
}

// VersionParams names an installed version for activate/delete jobs.
type VersionParams struct {
	Name            string `json:"name"`
	RestoreSettings bool   `json:"restoreSettings,omitempty"`
	ConfirmName     string `json:"confirmName,omitempty"`
}

// ValidateURL accepts only https URLs (http for localhost testing).
func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("enter the full address of the update file")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")) {
		return errors.New("update addresses must start with https://")
	}
	return nil
}

// RegisterJobs adds the update job kinds.
func (s *Service) RegisterJobs(m *jobs.Manager) {
	// One update or version change at a time.
	lock := func(json.RawMessage) string { return "system-update" }
	m.Register(jobs.Kind{Name: JobInstall, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		var p installParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		return s.stage(jc, p.Path)
	}})
	m.Register(jobs.Kind{Name: JobDownload, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		var p downloadParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		path, err := s.download(jc, p.URL)
		if err != nil {
			return nil, err
		}
		return s.stage(jc, path)
	}})
	m.Register(jobs.Kind{Name: JobActivate, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		var p VersionParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		jc.Progress(30, "Updating the boot menu")
		var out map[string]bool
		err := s.Priv.Call(jc, priv.OpUpdateActivate, priv.VersionArgs{Name: p.Name, RestoreSettings: p.RestoreSettings}, &out)
		return out, err
	}})
	m.Register(jobs.Kind{Name: JobDelete, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		var p VersionParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		jc.Progress(30, "Removing the version")
		var out map[string]string
		err := s.Priv.Call(jc, priv.OpUpdateDelete, priv.VersionArgs{Name: p.Name, ConfirmName: p.ConfirmName}, &out)
		return out, err
	}})
}

func (s *Service) stage(jc *jobs.Context, path string) (any, error) {
	jc.Progress(50, "Checking the signature and installing the new version")
	ctx, cancel := context.WithTimeout(jc, stageTimeout)
	defer cancel()
	var res update.StageResult
	if err := s.Priv.Call(ctx, priv.OpUpdateStage, priv.UpdateStageArgs{Path: path}, &res); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	jc.Progress(100, fmt.Sprintf("HardyOS %s is ready. Restart to start using it.", res.Version))
	return res, nil
}

// progressReader reports download progress.
type progressReader struct {
	r        io.Reader
	n, total int64
	report   func(n, total int64)
	last     time.Time
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.n += int64(n)
	if time.Since(p.last) > 500*time.Millisecond {
		p.last = time.Now()
		p.report(p.n, p.total)
	}
	return n, err
}

func (s *Service) download(jc *jobs.Context, rawURL string) (string, error) {
	if err := ValidateURL(rawURL); err != nil {
		return "", err
	}
	client := s.HTTP
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Hour}
	}
	req, err := http.NewRequestWithContext(jc, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	jc.Progress(1, "Downloading the update")
	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed: the server answered %s", res.Status)
	}
	if res.ContentLength > MaxBundleBytes {
		return "", ErrTooLarge
	}
	pr := &progressReader{r: res.Body, total: res.ContentLength, report: func(n, total int64) {
		if total > 0 {
			jc.Progress(45*float64(n)/float64(total), fmt.Sprintf("Downloading the update (%d of %d MB)", n>>20, total>>20))
		}
	}}
	return s.Save(pr)
}

// ConfirmWhenHealthy runs after hardyd starts serving. If this boot is a new
// version's first, it confirms the update once hardyd has stayed up for a
// short while and the root helper answers; then it reports the last update
// result in the notification center.
func (s *Service) ConfirmWhenHealthy(ctx context.Context, settle time.Duration) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(settle):
	}
	st, err := s.Status(ctx)
	if err != nil {
		s.log().Warn("update status", "err", err)
		return
	}
	if st.Pending != nil && st.Running == st.Pending.BE {
		var ping priv.PingResult
		if err := s.Priv.Call(ctx, priv.OpPing, nil, &ping); err != nil {
			s.log().Error("not confirming the update: root helper unhealthy", "err", err)
			return
		}
		if err := s.DB.PingContext(ctx); err != nil {
			s.log().Error("not confirming the update: database unhealthy", "err", err)
			return
		}
		var res update.ConfirmResult
		if err := s.Priv.Call(ctx, priv.OpUpdateConfirm, nil, &res); err != nil {
			s.log().Error("confirm update", "err", err)
			return
		}
		s.log().Info("update confirmed", "version", res.Version, "confirmed", res.Confirmed)
		if st, err = s.Status(ctx); err != nil {
			return
		}
	}
	s.reportResult(ctx, st)
}

// reportResult sends a notification for an update result not reported yet.
func (s *Service) reportResult(ctx context.Context, st *update.Status) {
	if st.Last == nil || s.Notify == nil {
		return
	}
	stamp := st.Last.At.UTC().Format(time.RFC3339Nano)
	if seen, _ := s.DB.GetSetting(ctx, "update.reported"); seen == stamp {
		return
	}
	n := notify.Notification{Level: notify.Success, Title: "Update finished", Body: st.Last.Message, Source: "updates", AdminOnly: true}
	if !st.Last.OK {
		n.Level, n.Title = notify.Error, "Update rolled back"
	}
	if err := s.Notify.Send(ctx, n); err == nil {
		_ = s.DB.SetSetting(ctx, "update.reported", stamp)
	}
}
