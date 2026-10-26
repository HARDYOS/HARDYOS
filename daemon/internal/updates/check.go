package updates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/notify"
)

// DefaultReleasesURL is the latest stable HardyOS release on GitHub. Drafts
// and pre-releases never show up here.
const DefaultReleasesURL = "https://api.github.com/repos/HARDYOS/HARDYOS/releases/latest"

// CheckInterval is how often the server looks for a new version.
const CheckInterval = 24 * time.Hour

// Settings keys.
const (
	keyAutoCheck = "updates.auto_check"
	keyLastCheck = "updates.last_check"
	keyLastError = "updates.last_check_error"
	keyAvailable = "updates.available"
	keyNotified  = "updates.notified_version"
)

// Available is a newer version found on GitHub.
type Available struct {
	Version     string    `json:"version"`
	Name        string    `json:"name"`
	Notes       string    `json:"notes"`
	URL         string    `json:"url"`     // the signed .hupd file
	PageURL     string    `json:"pageUrl"` // the release page
	Size        int64     `json:"size"`
	PublishedAt time.Time `json:"publishedAt"`
}

// CheckState is what Control Panel > Updates shows about checking.
type CheckState struct {
	AutoCheck bool       `json:"autoCheck"`
	Current   string     `json:"current"`
	LastCheck *time.Time `json:"lastCheck"`
	LastError string     `json:"lastError"`
	Available *Available `json:"available"`
}

func (s *Service) releasesURL() string {
	if s.ReleasesURL != "" {
		return s.ReleasesURL
	}
	return DefaultReleasesURL
}

func (s *Service) arch() string {
	if s.Arch != "" {
		return s.Arch
	}
	return runtime.GOARCH
}

// CheckState reads the saved check results.
func (s *Service) CheckState(ctx context.Context) CheckState {
	st := CheckState{AutoCheck: true, Current: s.Current}
	if v, err := s.DB.GetSetting(ctx, keyAutoCheck); err == nil {
		st.AutoCheck = v != "false"
	}
	if v, err := s.DB.GetSetting(ctx, keyLastCheck); err == nil {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			st.LastCheck = &t
		}
	}
	st.LastError, _ = s.DB.GetSetting(ctx, keyLastError)
	if v, err := s.DB.GetSetting(ctx, keyAvailable); err == nil && v != "" {
		var a Available
		if json.Unmarshal([]byte(v), &a) == nil && CompareVersions(a.Version, s.Current) > 0 {
			st.Available = &a
		}
	}
	return st
}

// SetAutoCheck turns the daily check on or off.
func (s *Service) SetAutoCheck(ctx context.Context, on bool) error {
	return s.DB.SetSetting(ctx, keyAutoCheck, fmt.Sprint(on))
}

// ghRelease is the part of GitHub's release JSON we use.
type ghRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	HTMLURL     string    `json:"html_url"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

// ErrNoRelease means GitHub has no published release yet.
var ErrNoRelease = errors.New("no HardyOS release has been published yet")

// CheckNow asks GitHub for the latest release and saves the result.
func (s *Service) CheckNow(ctx context.Context) (CheckState, error) {
	a, err := s.fetchLatest(ctx)
	now := time.Now().UTC()
	_ = s.DB.SetSetting(ctx, keyLastCheck, now.Format(time.RFC3339))
	if err != nil && !errors.Is(err, ErrNoRelease) {
		_ = s.DB.SetSetting(ctx, keyLastError, err.Error())
		return s.CheckState(ctx), err
	}
	_ = s.DB.SetSetting(ctx, keyLastError, "")
	value := ""
	if a != nil && CompareVersions(a.Version, s.Current) > 0 {
		b, _ := json.Marshal(a)
		value = string(b)
	}
	if err := s.DB.SetSetting(ctx, keyAvailable, value); err != nil {
		return s.CheckState(ctx), err
	}
	st := s.CheckState(ctx)
	if st.Available != nil {
		s.notifyAvailable(ctx, st.Available)
	}
	return st, nil
}

func (s *Service) fetchLatest(ctx context.Context) (*Available, error) {
	client := s.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.releasesURL(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "HardyOS/"+s.Current)
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("couldn't reach GitHub to check for updates: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return nil, ErrNoRelease
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub answered %s while checking for updates", res.Status)
	}
	var r ghRelease
	if err := json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(&r); err != nil {
		return nil, fmt.Errorf("couldn't read GitHub's answer: %w", err)
	}
	if r.Draft || r.Prerelease {
		return nil, ErrNoRelease
	}
	ver := strings.TrimPrefix(r.TagName, "v")
	want := fmt.Sprintf("hardyos-%s-%s.hupd", ver, s.arch())
	a := &Available{Version: ver, Name: r.Name, Notes: r.Body, PageURL: r.HTMLURL, PublishedAt: r.PublishedAt}
	for _, as := range r.Assets {
		if as.Name == want {
			a.URL, a.Size = as.URL, as.Size
		}
	}
	if a.URL == "" {
		return nil, fmt.Errorf("HardyOS %s has no update file for %s", ver, s.arch())
	}
	if err := ValidateURL(a.URL); err != nil {
		return nil, fmt.Errorf("HardyOS %s: %w", ver, err)
	}
	if a.Name == "" {
		a.Name = "HardyOS " + ver
	}
	return a, nil
}

// notifyAvailable tells administrators once per version.
func (s *Service) notifyAvailable(ctx context.Context, a *Available) {
	if s.Notify == nil {
		return
	}
	if seen, _ := s.DB.GetSetting(ctx, keyNotified); seen == a.Version {
		return
	}
	n := notify.Notification{
		Level:     notify.Info,
		Title:     fmt.Sprintf("HardyOS %s is available", a.Version),
		Body:      "Install it from Control Panel > Updates.",
		Source:    "updates",
		AdminOnly: true,
	}
	if err := s.Notify.Send(ctx, n); err == nil {
		_ = s.DB.SetSetting(ctx, keyNotified, a.Version)
	}
}

// RunChecks checks a few minutes after start and then daily, while
// automatic checks are on. A failed check is retried in an hour.
func (s *Service) RunChecks(ctx context.Context) {
	wait := 3 * time.Minute
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = CheckInterval + time.Duration(rand.Int64N(int64(time.Hour))) // spread checks out
		st := s.CheckState(ctx)
		if !st.AutoCheck {
			continue
		}
		if st.LastCheck != nil && time.Since(*st.LastCheck) < CheckInterval-time.Hour {
			wait = time.Until(st.LastCheck.Add(CheckInterval))
			continue
		}
		if _, err := s.CheckNow(ctx); err != nil {
			s.log().Info("update check failed", "err", err)
			wait = time.Hour
		}
	}
}

// AvailableURL returns the update file of the newer version found by the
// last check, for the "Install" button.
func (s *Service) AvailableURL(ctx context.Context) (string, string, error) {
	st := s.CheckState(ctx)
	if st.Available == nil {
		return "", "", errors.New("no newer version is known; check for updates first")
	}
	return st.Available.URL, st.Available.Version, nil
}

// CompareVersions compares two HardyOS versions the way Debian does for the
// upstream part (so 0.1.0~dev < 0.1.0 < 0.1.0+3.g1a2b < 0.1.1). It returns
// -1, 0 or 1.
func CompareVersions(a, b string) int {
	a, b = strings.TrimPrefix(a, "v"), strings.TrimPrefix(b, "v")
	for a != "" || b != "" {
		// Non-digit part, compared with ~ before everything and letters
		// before other characters.
		na, nb := nonDigits(a), nonDigits(b)
		for i := 0; i < len(na) || i < len(nb); i++ {
			ca, cb := order(na, i), order(nb, i)
			if ca != cb {
				return sign(ca - cb)
			}
		}
		a, b = a[len(na):], b[len(nb):]
		// Digit part, compared as numbers.
		da, db := digits(a), digits(b)
		a, b = a[len(da):], b[len(db):]
		da, db = strings.TrimLeft(da, "0"), strings.TrimLeft(db, "0")
		if len(da) != len(db) {
			return sign(len(da) - len(db))
		}
		if da != db {
			if da < db {
				return -1
			}
			return 1
		}
	}
	return 0
}

func nonDigits(s string) string {
	i := 0
	for i < len(s) && (s[i] < '0' || s[i] > '9') {
		i++
	}
	return s[:i]
}

func digits(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}

// order is dpkg's character weight: end of string 0, ~ below it, letters
// by value, everything else after letters.
func order(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	c := s[i]
	switch {
	case c == '~':
		return -1
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return int(c)
	default:
		return int(c) + 256
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
