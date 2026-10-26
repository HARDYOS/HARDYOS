// Package backups is hardyd's side of settings backups: it makes backups
// (nightly onto a data pool, or a password-protected download), checks
// backups before a restore and stages them through hardyd-priv, which
// applies them at the next start.
package backups

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/backup"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// JobCreate makes a backup onto a pool. Downloads and restores aren't jobs:
// they carry a password, and job parameters are kept in the job history.
const JobCreate = "system.backup.create"

// Settings keys.
const (
	keyNightly   = "backups.nightly"
	keyPool      = "backups.pool"
	keyKeep      = "backups.keep"
	keyTime      = "backups.time"
	keyLastRun   = "backups.last_run"
	keyLastError = "backups.last_error"
	keyReported  = "backups.restore_reported"
)

// DownloadTTL is how long a prepared download stays.
const DownloadTTL = time.Hour

// MinPasswordLen is the shortest password for a protected backup.
const MinPasswordLen = 8

// Service makes and restores settings backups.
type Service struct {
	DB      *store.DB
	Priv    *priv.Client
	Jobs    *jobs.Manager
	Notify  *notify.Center
	Log     *slog.Logger
	Current string // running HardyOS version
	// Dir is hardyd's work directory (default /var/lib/hardyos/backups);
	// it must match backup.WorkDir on a real system.
	Dir string
	// Hostname defaults to os.Hostname.
	Hostname func() string
	Now      func() time.Time
}

func (s *Service) dir() string {
	if s.Dir != "" {
		return s.Dir
	}
	return "/" + backup.WorkDir
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) hostname() string {
	if s.Hostname != nil {
		return s.Hostname()
	}
	h, _ := os.Hostname()
	if h == "" {
		h = "hardyos"
	}
	return h
}

func randHex() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Settings is the nightly backup setup.
type Settings struct {
	Nightly bool   `json:"nightly"`
	Pool    string `json:"pool"` // empty: the first data pool
	Keep    int    `json:"keep"`
	Time    string `json:"time"` // HH:MM, server time
}

// LoadSettings returns the nightly backup setup (defaults: on, 14 kept, 03:15).
func (s *Service) LoadSettings(ctx context.Context) Settings {
	st := Settings{Nightly: true, Keep: 14, Time: "03:15"}
	if v, err := s.DB.GetSetting(ctx, keyNightly); err == nil {
		st.Nightly = v != "false"
	}
	st.Pool, _ = s.DB.GetSetting(ctx, keyPool)
	if v, err := s.DB.GetSetting(ctx, keyKeep); err == nil {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			st.Keep = n
		}
	}
	if v, err := s.DB.GetSetting(ctx, keyTime); err == nil && validTime(v) {
		st.Time = v
	}
	return st
}

func validTime(v string) bool {
	t, err := time.Parse("15:04", v)
	return err == nil && t.Format("15:04") == v
}

// SaveSettings validates and stores the nightly backup setup.
func (s *Service) SaveSettings(ctx context.Context, st Settings) error {
	if st.Keep < 1 || st.Keep > 365 {
		return errors.New("keep between 1 and 365 backups")
	}
	if !validTime(st.Time) {
		return errors.New("the time must look like 03:15")
	}
	if st.Pool != "" && (backup.BootPools[st.Pool] || strings.ContainsAny(st.Pool, "/ ")) {
		return fmt.Errorf("%q can't hold backups", st.Pool)
	}
	for k, v := range map[string]string{keyNightly: fmt.Sprint(st.Nightly), keyPool: st.Pool, keyKeep: strconv.Itoa(st.Keep), keyTime: st.Time} {
		if err := s.DB.SetSetting(ctx, k, v); err != nil {
			return err
		}
	}
	return nil
}

// Status is the Backup page.
type Status struct {
	Settings   Settings            `json:"settings"`
	Pools      []string            `json:"pools"`
	Backups    []backup.PoolBackup `json:"backups"`
	LastRun    *time.Time          `json:"lastRun"`
	LastError  string              `json:"lastError"`
	Pending    *backup.Staged      `json:"pending"`
	LastResult *backup.Result      `json:"lastResult"`
}

// Status collects settings, backups on pools and restore state.
func (s *Service) Status(ctx context.Context) (*Status, error) {
	st := &Status{Settings: s.LoadSettings(ctx), Pools: []string{}, Backups: []backup.PoolBackup{}}
	var list priv.BackupListResult
	if err := s.Priv.Call(ctx, priv.OpBackupList, nil, &list); err != nil {
		return nil, err
	}
	st.Pools, st.Backups = list.Pools, list.Backups
	var rs priv.BackupStatus
	if err := s.Priv.Call(ctx, priv.OpBackupStatus, nil, &rs); err != nil {
		return nil, err
	}
	st.Pending, st.LastResult = rs.Pending, rs.LastResult
	if v, err := s.DB.GetSetting(ctx, keyLastRun); err == nil {
		if t := store.ParseTime(v); !t.IsZero() {
			st.LastRun = &t
		}
	}
	st.LastError, _ = s.DB.GetSetting(ctx, keyLastError)
	return st, nil
}

// make builds a backup file in the work directory and returns its path.
func (s *Service) make(ctx context.Context, password string, secrets bool, note string) (string, *backup.Manifest, error) {
	if err := os.MkdirAll(s.dir(), 0o750); err != nil {
		return "", nil, err
	}
	tmp := filepath.Join(s.dir(), "snapshot-"+randHex()+".db")
	defer os.Remove(tmp)
	if err := s.DB.Snapshot(ctx, tmp); err != nil {
		return "", nil, fmt.Errorf("copying the database: %w", err)
	}
	db, err := os.ReadFile(tmp)
	if err != nil {
		return "", nil, err
	}
	info, err := store.Inspect(ctx, tmp)
	if err != nil {
		return "", nil, err
	}
	var files priv.BackupCollectResult
	if err := s.Priv.Call(ctx, priv.OpBackupCollect, priv.BackupCollectArgs{Secrets: secrets}, &files); err != nil {
		return "", nil, err
	}
	m := backup.Manifest{
		CreatedAt: s.now().UTC().Truncate(time.Second),
		Version:   s.Current,
		Hostname:  s.hostname(),
		Schema:    info.Schema,
		Users:     info.Users,
		Note:      note,
	}
	b, err := backup.Pack(backup.Contents{Manifest: m, DB: db, Files: files.Files}, password)
	if err != nil {
		return "", nil, err
	}
	path := filepath.Join(s.dir(), "made-"+randHex()+"-"+backup.FileName(m.Hostname, m.CreatedAt))
	if err := os.WriteFile(path, b, 0o640); err != nil {
		return "", nil, err
	}
	return path, &m, nil
}

// choosePool picks the pool for nightly backups.
func (s *Service) choosePool(ctx context.Context, want string) (string, error) {
	var list priv.BackupListResult
	if err := s.Priv.Call(ctx, priv.OpBackupList, nil, &list); err != nil {
		return "", err
	}
	if len(list.Pools) == 0 {
		return "", errors.New("there's no storage pool to keep backups on yet")
	}
	if want == "" {
		return list.Pools[0], nil
	}
	for _, p := range list.Pools {
		if p == want {
			return p, nil
		}
	}
	return "", fmt.Errorf("pool %s isn't imported", want)
}

// CreateOnPool makes a backup and keeps it on a pool (empty: the configured
// or first one).
func (s *Service) CreateOnPool(ctx context.Context, pool, note string) (*backup.PoolBackup, error) {
	set := s.LoadSettings(ctx)
	if pool == "" {
		pool = set.Pool
	}
	pool, err := s.choosePool(ctx, pool)
	if err != nil {
		return nil, s.recordRun(ctx, err)
	}
	path, _, err := s.make(ctx, "", false, note)
	if err != nil {
		return nil, s.recordRun(ctx, err)
	}
	defer os.Remove(path)
	var pb backup.PoolBackup
	if err := s.Priv.Call(ctx, priv.OpBackupStore, priv.BackupStoreArgs{Pool: pool, Path: path, Keep: set.Keep}, &pb); err != nil {
		return nil, s.recordRun(ctx, err)
	}
	return &pb, s.recordRun(ctx, nil)
}

func (s *Service) recordRun(ctx context.Context, err error) error {
	_ = s.DB.SetSetting(ctx, keyLastRun, store.Now())
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	_ = s.DB.SetSetting(ctx, keyLastError, msg)
	return err
}

// Download is a prepared backup file for the browser.
type Download struct {
	Name string `json:"name"` // what to fetch from /system/backups/files/{name}
	File string `json:"file"` // the name to save it as
	Size int64  `json:"size"`
}

// PrepareDownload makes a password-protected backup to download.
func (s *Service) PrepareDownload(ctx context.Context, password string, secrets bool) (*Download, error) {
	if len(password) < MinPasswordLen {
		return nil, fmt.Errorf("use a password of at least %d characters", MinPasswordLen)
	}
	path, m, err := s.make(ctx, password, secrets, "manual")
	if err != nil {
		return nil, err
	}
	name := "download-" + randHex() + ".hbak"
	final := filepath.Join(s.dir(), name)
	if err := os.Rename(path, final); err != nil {
		return nil, err
	}
	fi, _ := os.Stat(final)
	d := &Download{Name: name, File: backup.FileName(m.Hostname, m.CreatedAt)}
	if fi != nil {
		d.Size = fi.Size()
	}
	return d, nil
}

// OpenDownload opens a prepared download.
func (s *Service) OpenDownload(name string) (*os.File, error) {
	if !strings.HasPrefix(name, "download-") || !strings.HasSuffix(name, ".hbak") || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return nil, os.ErrNotExist
	}
	return os.Open(filepath.Join(s.dir(), name))
}

// SaveUpload stores an uploaded backup for a restore.
func (s *Service) SaveUpload(r io.Reader) (string, error) {
	if err := os.MkdirAll(s.dir(), 0o750); err != nil {
		return "", err
	}
	name := "upload-" + randHex() + ".hbak"
	path := filepath.Join(s.dir(), name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return "", err
	}
	n, err := io.Copy(f, io.LimitReader(r, backup.MaxBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > backup.MaxBytes {
		err = errors.New("the file is too large to be a settings backup")
	}
	if err == nil {
		b, _ := os.ReadFile(path)
		_, err = backup.Encrypted(b)
	}
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return name, nil
}

// RestoreSource is where a restore comes from: an upload or a pool backup.
type RestoreSource struct {
	Upload   string `json:"upload,omitempty"`
	Pool     string `json:"pool,omitempty"`
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}

// Stage checks a backup and stages it for the next start.
func (s *Service) Stage(ctx context.Context, src RestoreSource) (*backup.Staged, error) {
	var path string
	switch {
	case src.Upload != "":
		if !strings.HasPrefix(src.Upload, "upload-") || strings.ContainsAny(src.Upload, "/\\") || strings.Contains(src.Upload, "..") {
			return nil, errors.New("invalid upload")
		}
		path = filepath.Join(s.dir(), src.Upload)
	case src.Pool != "" && src.Name != "":
		var fr priv.BackupFetchResult
		if err := s.Priv.Call(ctx, priv.OpBackupFetch, priv.BackupRef{Pool: src.Pool, Name: src.Name}, &fr); err != nil {
			return nil, err
		}
		path = fr.Path
	default:
		return nil, errors.New("choose a backup to restore")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := backup.Unpack(b, src.Password)
	if errors.Is(err, backup.ErrNeedPassword) || errors.Is(err, backup.ErrWrongPassword) {
		// Keep the file so the person can try another password.
		return nil, err
	}
	defer os.Remove(path)
	if err != nil {
		return nil, err
	}
	// The database must be one this version can use.
	tmp := filepath.Join(s.dir(), "check-"+randHex()+".db")
	defer os.Remove(tmp)
	if err := os.WriteFile(tmp, c.DB, 0o600); err != nil {
		return nil, err
	}
	info, err := store.Inspect(ctx, tmp)
	if err != nil {
		return nil, errors.New("the backup's database can't be read")
	}
	if info.Schema > store.SchemaVersion() {
		return nil, fmt.Errorf("this backup was made by a newer HardyOS (%s); update this server first", c.Manifest.Version)
	}
	if info.Users == 0 {
		return nil, errors.New("the backup has no user accounts, so nobody could sign in after restoring it")
	}
	var st backup.Staged
	if err := s.Priv.Call(ctx, priv.OpBackupStage, priv.BackupStageArgs{Path: path, Password: src.Password}, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Unstage cancels a waiting restore.
func (s *Service) Unstage(ctx context.Context) error {
	return s.Priv.Call(ctx, priv.OpBackupUnstage, nil, nil)
}

// RegisterJobs adds the backup job kinds.
func (s *Service) RegisterJobs(m *jobs.Manager) {
	lock := func(json.RawMessage) string { return "settings-backup" }
	m.Register(jobs.Kind{Name: JobCreate, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		var p struct {
			Pool string `json:"pool"`
			Note string `json:"note"`
		}
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		jc.Progress(20, "Saving the settings")
		return s.CreateOnPool(jc, p.Pool, p.Note)
	}})
}

// Run makes the nightly backup, removes old downloads and reports the
// result of a restore after it was applied.
func (s *Service) Run(ctx context.Context) {
	s.reportRestore(ctx)
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.Tick(ctx, now)
		}
	}
}

// Tick runs what's due at now.
func (s *Service) Tick(ctx context.Context, now time.Time) {
	s.cleanDownloads(now)
	set := s.LoadSettings(ctx)
	if !set.Nightly || now.Format("15:04") != set.Time {
		return
	}
	if v, err := s.DB.GetSetting(ctx, keyLastRun); err == nil && now.Sub(store.ParseTime(v)) < 12*time.Hour {
		return
	}
	if s.Jobs == nil {
		return
	}
	if _, err := s.Jobs.Submit(ctx, JobCreate, "Nightly settings backup", map[string]string{"note": "nightly"}, nil); err != nil {
		s.log().Warn("nightly backup", "err", err)
	}
}

func (s *Service) cleanDownloads(now time.Time) {
	entries, err := os.ReadDir(s.dir())
	if err != nil {
		return
	}
	for _, e := range entries {
		n := e.Name()
		if !(strings.HasPrefix(n, "download-") || strings.HasPrefix(n, "upload-") || strings.HasPrefix(n, "fetched-") || strings.HasPrefix(n, "made-")) {
			continue
		}
		if fi, err := e.Info(); err == nil && now.Sub(fi.ModTime()) > DownloadTTL {
			_ = os.Remove(filepath.Join(s.dir(), n))
		}
	}
}

// reportRestore notifies administrators once about an applied restore.
func (s *Service) reportRestore(ctx context.Context) {
	if s.Notify == nil {
		return
	}
	var rs priv.BackupStatus
	if err := s.Priv.Call(ctx, priv.OpBackupStatus, nil, &rs); err != nil || rs.LastResult == nil {
		return
	}
	stamp := rs.LastResult.At.UTC().Format(time.RFC3339Nano)
	if seen, _ := s.DB.GetSetting(ctx, keyReported); seen == stamp {
		return
	}
	n := notify.Notification{Level: notify.Success, Title: "Settings restored", Body: rs.LastResult.Message, Source: "backups", AdminOnly: true}
	if !rs.LastResult.OK {
		n.Level, n.Title = notify.Error, "Settings restore failed"
	} else if len(rs.LastResult.Notes) > 0 {
		n.Level = notify.Warning
		n.Body += " " + strings.Join(rs.LastResult.Notes, " ")
	}
	if err := s.Notify.Send(ctx, n); err == nil {
		_ = s.DB.SetSetting(ctx, keyReported, stamp)
	}
}
