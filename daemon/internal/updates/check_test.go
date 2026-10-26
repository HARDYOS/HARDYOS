package updates

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

func TestCompareVersions(t *testing.T) {
	ordered := []string{
		"0.0.0-dev",
		"0.1.0~ci1",
		"0.1.0~ci2",
		"0.1.0~ci10",
		"0.1.0~dev.20261024.g1a2b3c4",
		"0.1.0",
		"0.1.0+3.g1a2b3c4",
		"0.1.0+12.gffffff0",
		"0.1.1~ci1",
		"0.1.1",
		"v0.1.2",
		"0.2.0",
		"0.10.0",
		"1.0.0",
	}
	for i := range ordered {
		for j := range ordered {
			want := sign(i - j)
			if got := CompareVersions(ordered[i], ordered[j]); got != want {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
	if CompareVersions("v0.1.1", "0.1.1") != 0 {
		t.Error("leading v should be ignored")
	}
}

const releaseJSON = `{
  "tag_name": "v0.2.0",
  "name": "HardyOS 0.2.0",
  "body": "Network settings and automatic update checks.",
  "html_url": "https://github.com/HARDYOS/HARDYOS/releases/tag/v0.2.0",
  "draft": false,
  "prerelease": false,
  "published_at": "2026-10-26T12:00:00Z",
  "assets": [
    {"name": "hardyos-0.2.0-amd64.iso", "browser_download_url": "https://github.com/HARDYOS/HARDYOS/releases/download/v0.2.0/hardyos-0.2.0-amd64.iso", "size": 760000000},
    {"name": "hardyos-0.2.0-amd64.hupd", "browser_download_url": "https://github.com/HARDYOS/HARDYOS/releases/download/v0.2.0/hardyos-0.2.0-amd64.hupd", "size": 617000000},
    {"name": "hardyos-0.2.0-amd64.hupd.sha256", "browser_download_url": "https://github.com/x", "size": 90}
  ]
}`

func newCheckService(t *testing.T, current string, handler http.HandlerFunc) (*Service, *notify.Center) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	n := &notify.Center{DB: db, Events: events.NewBroker()}
	return &Service{DB: db, Notify: n, Current: current, ReleasesURL: srv.URL, Arch: "amd64", HTTP: srv.Client()}, n
}

func TestCheckFindsNewerVersion(t *testing.T) {
	var hits atomic.Int32
	svc, n := newCheckService(t, "0.1.1", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("User-Agent") != "HardyOS/0.1.1" {
			t.Errorf("user agent = %q", r.Header.Get("User-Agent"))
		}
		_, _ = w.Write([]byte(releaseJSON))
	})
	ctx := context.Background()
	if st := svc.CheckState(ctx); !st.AutoCheck || st.Available != nil || st.LastCheck != nil {
		t.Fatalf("initial state = %+v", st)
	}
	st, err := svc.CheckNow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a := st.Available
	if a == nil || a.Version != "0.2.0" || !strings.HasSuffix(a.URL, "/hardyos-0.2.0-amd64.hupd") || a.Size != 617000000 || a.Notes == "" {
		t.Fatalf("available = %+v", a)
	}
	if st.LastCheck == nil || st.LastError != "" {
		t.Fatalf("state = %+v", st)
	}
	url, ver, err := svc.AvailableURL(ctx)
	if err != nil || ver != "0.2.0" || url != a.URL {
		t.Fatalf("AvailableURL = %q %q %v", url, ver, err)
	}

	// One notification per version, however often it's checked.
	if _, err := svc.CheckNow(ctx); err != nil {
		t.Fatal(err)
	}
	list, _ := n.List(ctx, true, 10)
	if len(list) != 1 || !strings.Contains(list[0].Title, "0.2.0 is available") || !list[0].AdminOnly {
		t.Fatalf("notifications = %+v", list)
	}

	// After installing it, the same release is no longer offered.
	svc.Current = "0.2.0"
	if st := svc.CheckState(ctx); st.Available != nil {
		t.Fatalf("still offered on 0.2.0: %+v", st.Available)
	}
	if _, _, err := svc.AvailableURL(ctx); err == nil {
		t.Fatal("AvailableURL should fail with nothing newer")
	}

	if err := svc.SetAutoCheck(ctx, false); err != nil {
		t.Fatal(err)
	}
	if svc.CheckState(ctx).AutoCheck {
		t.Fatal("auto check still on")
	}
}

func TestCheckOlderOrSameIsNotOffered(t *testing.T) {
	svc, _ := newCheckService(t, "0.2.0+4.gabcdef0", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(releaseJSON))
	})
	st, err := svc.CheckNow(context.Background())
	if err != nil || st.Available != nil {
		t.Fatalf("a build after 0.2.0 was offered 0.2.0: %+v %v", st.Available, err)
	}
}

func TestCheckFailures(t *testing.T) {
	ctx := context.Background()
	// No release published yet: not an error, nothing offered.
	svc, _ := newCheckService(t, "0.1.0", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	if st, err := svc.CheckNow(ctx); err != nil || st.Available != nil || st.LastError != "" {
		t.Fatalf("404: %+v %v", st, err)
	}
	// GitHub rate limits or is down: the reason is kept for the page.
	svc, _ = newCheckService(t, "0.1.0", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "rate limited", http.StatusForbidden) })
	st, err := svc.CheckNow(ctx)
	if err == nil || !strings.Contains(st.LastError, "403") {
		t.Fatalf("403: %+v %v", st, err)
	}
	// A release without an update file for this architecture.
	svc, _ = newCheckService(t, "0.1.0", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.ReplaceAll(releaseJSON, "amd64.hupd", "arm64.hupd")))
	})
	if _, err := svc.CheckNow(ctx); err == nil || !strings.Contains(err.Error(), "no update file for amd64") {
		t.Fatalf("missing asset err = %v", err)
	}
	// Pre-releases aren't offered.
	svc, _ = newCheckService(t, "0.1.0", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Replace(releaseJSON, `"prerelease": false`, `"prerelease": true`, 1)))
	})
	if st, err := svc.CheckNow(ctx); err != nil || st.Available != nil {
		t.Fatalf("prerelease offered: %+v %v", st, err)
	}
	// A later successful check clears the old error.
	svc2, _ := newCheckService(t, "0.1.0", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(releaseJSON)) })
	_ = svc2.DB.SetSetting(ctx, keyLastError, "old")
	if st, _ := svc2.CheckNow(ctx); st.LastError != "" || st.Available == nil {
		t.Fatalf("after success: %+v", st)
	}
}
