package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHealth(t *testing.T) {
	srv := httptest.NewServer(New(Config{}))
	defer srv.Close()

	res, err := http.Get(srv.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	var body HealthResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "ok" {
		t.Fatalf("status field = %q, want ok", body.Status)
	}
	for _, h := range []string{"X-Content-Type-Options", "Content-Security-Policy", "X-Frame-Options"} {
		if res.Header.Get(h) == "" {
			t.Errorf("missing security header %s", h)
		}
	}
}

func TestVersion(t *testing.T) {
	srv := httptest.NewServer(New(Config{}))
	defer srv.Close()

	res, err := http.Get(srv.URL + "/api/v1/version")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"version", "commit", "goVersion", "os", "arch"} {
		if _, ok := body[k]; !ok {
			t.Errorf("version response missing %q", k)
		}
	}
}

func TestUnknownAPIRouteIsJSON404(t *testing.T) {
	srv := httptest.NewServer(New(Config{}))
	defer srv.Close()

	res, err := http.Get(srv.URL + "/api/v1/nope")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content type = %q, want JSON", ct)
	}
}

func TestSPAFallback(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>shell</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Config{WebRoot: dir}))
	defer srv.Close()

	for _, p := range []string{"/", "/apps/storage"} {
		res, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusOK || !strings.Contains(string(body), "shell") {
			t.Errorf("GET %s: status %d body %q, want index.html", p, res.StatusCode, body)
		}
	}
}
