package apps

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitImageRef(t *testing.T) {
	for ref, want := range map[string][2]string{
		"jellyfin/jellyfin:12.3":                 {"jellyfin/jellyfin", "12.3"},
		"postgres":                               {"postgres", "latest"},
		"localhost:5000/team/app":                {"localhost:5000/team/app", "latest"},
		"localhost:5000/team/app:2":              {"localhost:5000/team/app", "2"},
		"ghcr.io/immich-app/postgres@sha256:abc": {"ghcr.io/immich-app/postgres", "sha256:abc"},
	} {
		if n, tag := splitImageRef(ref); n != want[0] || tag != want[1] {
			t.Errorf("splitImageRef(%q) = %q, %q", ref, n, tag)
		}
	}
}

// fakeEngine serves Docker's /images/create on a unix socket under root.
func fakeEngine(t *testing.T, root string, h http.HandlerFunc) {
	t.Helper()
	sock := filepath.Join(root, DockerSocket)
	if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets: %v", err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
}

func TestAPIPullReportsProgress(t *testing.T) {
	root := t.TempDir()
	m := &Manager{Root: root}
	gotQuery := ""
	step := make(chan struct{})
	seen := make(chan PullProgress, 1)
	fakeEngine(t, root, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		f := w.(http.Flusher)
		line := func(s string) { fmt.Fprintln(w, s); f.Flush() }
		line(`{"status":"Pulling from jellyfin/jellyfin","id":"12.3"}`)
		line(`{"status":"Pulling fs layer","id":"a"}`)
		line(`{"status":"Already exists","id":"b"}`)
		line(`{"status":"Downloading","progressDetail":{"current":50,"total":200},"id":"a"}`)
		line(`{"status":"Downloading","progressDetail":{"current":10,"total":100},"id":"c"}`)
		<-step // let the test read progress mid-download
		line(`{"status":"Download complete","id":"a"}`)
		line(`{"status":"Pull complete","id":"c"}`)
		line(`{"status":"Status: Downloaded newer image for jellyfin/jellyfin:12.3"}`)
	})
	st := m.pullState("jellyfin", "app")
	errc := make(chan error, 1)
	go func() { errc <- m.apiPull(context.Background(), "jellyfin/jellyfin:12.3", st) }()
	go func() {
		for {
			if p := m.PullStatus("jellyfin", "app"); p.Active && p.Current == 60 {
				seen <- p
				close(step)
				return
			}
		}
	}()
	p := <-seen
	// a: 50/200, b: done but size unknown (0), c: 10/100.
	if p.Total != 300 || p.Current != 60 || p.Layers != 3 {
		t.Errorf("mid-download = %+v", p)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if p := m.PullStatus("jellyfin", "app"); p.Active || p.Current != p.Total || p.Total != 300 {
		t.Errorf("after = %+v", p)
	}
	if !strings.Contains(gotQuery, "fromImage=jellyfin%2Fjellyfin") || !strings.Contains(gotQuery, "tag=12.3") {
		t.Errorf("query = %s", gotQuery)
	}
}

func TestAPIPullErrors(t *testing.T) {
	root := t.TempDir()
	m := &Manager{Root: root}
	// No socket: the caller falls back to Compose.
	if err := m.apiPull(context.Background(), "x:1", m.pullState("x", "s")); err != errNoEngineAPI {
		t.Errorf("no socket: %v", err)
	}
	fakeEngine(t, root, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "missing") {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintln(w, `{"message":"pull access denied for missing"}`)
			return
		}
		fmt.Fprintln(w, `{"status":"Pulling fs layer","id":"a"}`)
		fmt.Fprintln(w, `{"errorDetail":{"message":"unexpected EOF"},"error":"unexpected EOF"}`)
	})
	if err := m.apiPull(context.Background(), "missing:1", m.pullState("x", "s")); err == nil || !strings.Contains(err.Error(), "pull access denied") {
		t.Errorf("404: %v", err)
	}
	if err := m.apiPull(context.Background(), "broken:1", m.pullState("x", "s")); err == nil || !strings.Contains(err.Error(), "unexpected EOF") {
		t.Errorf("stream error: %v", err)
	}
	if p := m.PullStatus("../x", "s"); p != (PullProgress{}) {
		t.Errorf("bad id answered: %+v", p)
	}
}
