package office

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/files"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// TestDocumentServerIntegration runs against a real OnlyOffice Document
// Server container (CI job "Office"; gated like the Docker apps job):
//
//	HARDYOS_OFFICE_INTEGRATION=1
//	OFFICE_DS_URL=http://127.0.0.1:18080          the container's published port
//	OFFICE_JWT_SECRET=...                         the secret it was started with
//	OFFICE_LISTEN=172.17.0.1:44251                where this test listens for it
//	OFFICE_CALLBACK_BASE=http://host.docker.internal:44251
//
// For each new-document template it opens the file through Service.Open
// (a signed config with a one-time download URL), has the Document Server
// fetch it from this process (the way the editor does: through the URL in
// the signed config, as the participant), converts it, then saves the
// result back through a signed status-2 callback whose URL is the Document
// Server's own file cache, exactly as a save arrives. It also checks the
// download URL works once, the Document Server refuses unsigned requests,
// and the proxy serves the editor's api.js.
//
// A real browser co-editing session isn't driven here; docs/office.md says
// how to check that by hand.
func TestDocumentServerIntegration(t *testing.T) {
	if os.Getenv("HARDYOS_OFFICE_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_OFFICE_INTEGRATION=1 with a Document Server running (see the comment)")
	}
	dsURL, _ := url.Parse(os.Getenv("OFFICE_DS_URL"))
	secret := []byte(os.Getenv("OFFICE_JWT_SECRET"))
	listen := os.Getenv("OFFICE_LISTEN")
	base := os.Getenv("OFFICE_CALLBACK_BASE")
	if dsURL == nil || dsURL.Host == "" || len(secret) < 16 || listen == "" || base == "" {
		t.Fatal("OFFICE_DS_URL, OFFICE_JWT_SECRET, OFFICE_LISTEN and OFFICE_CALLBACK_BASE are needed")
	}
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	dir := t.TempDir()
	fs := &fakeFiles{dirs: map[string]string{"docs": dir}, readOnly: map[string]bool{}}
	var audits []AuditEvent
	svc := &Service{
		DB: db, Files: fs,
		Secret:       func(context.Context) ([]byte, error) { return secret, nil },
		Internal:     func() (*url.URL, error) { return dsURL, nil },
		CallbackBase: func() string { return base },
		Identity: func(_ context.Context, p Participant, _ *Session, _ bool) (files.Who, error) {
			return files.Who{Principal: p.Name}, nil
		},
		Audit: func(_ context.Context, a AuditEvent) { audits = append(audits, a) },
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	peers := DockerPeers()
	var refused int
	srv := &http.Server{Handler: svc.InternalHandler(func(a netip.Addr) bool {
		ok := peers(a) || localAddr(a)
		if !ok {
			refused++
		}
		return ok
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	waitHealthy(t, dsURL)

	for kind, ext := range NewKinds {
		t.Run(kind, func(t *testing.T) {
			name := "new-" + kind + "." + ext
			b, _ := Blank(kind)
			if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
				t.Fatal(err)
			}
			ed, err := svc.Open(ctx, OpenRequest{Who: files.Who{Principal: "alice"}, Share: "docs", Path: name,
				Kind: KindUser, UserID: 1, Name: "alice", WantEdit: true, MayEdit: true})
			if err != nil {
				t.Fatal(err)
			}
			doc := ed.Config["document"].(map[string]any)
			key := doc["key"].(string)
			// The Document Server fetches the file from us with the URL in
			// the signed config, and converts it (to the same format: the
			// result lands in its file cache like a saved document).
			out, err := convert(dsURL, secret, doc["url"].(string), ext, ext, key)
			if err != nil {
				t.Fatalf("convert: %v (refused peers: %d)", err, refused)
			}
			if fs.reads[len(fs.reads)-1] != "alice" {
				t.Fatalf("read as %v", fs.reads)
			}
			// The download URL was used up.
			if _, err := convert(dsURL, secret, doc["url"].(string), ext, ext, key+"x"); err == nil {
				t.Fatal("the one-time document URL worked twice")
			}
			// Save it back as a status-2 callback, posted the way the
			// Document Server posts them.
			cb := map[string]any{"key": key, "status": StatusReady, "url": out, "users": []string{ed.Participant.ID}, "filetype": ext}
			hdr, body := signed(t, secret, cb)
			resp := postCallback(t, "http://"+listen+"/office/callback/"+key, hdr, body)
			if !strings.Contains(resp, `"error":0`) {
				t.Fatalf("callback answer %s (audits %+v)", resp, audits)
			}
			saved, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(saved, b) {
				t.Fatal("the file wasn't replaced by the Document Server's version")
			}
			if _, err := zip.NewReader(bytes.NewReader(saved), int64(len(saved))); err != nil {
				t.Fatalf("saved file isn't an Office document: %v", err)
			}
		})
	}

	t.Run("refusals", func(t *testing.T) {
		// The Document Server enforces the JWT: an unsigned conversion is refused.
		body, _ := json.Marshal(map[string]any{"async": false, "filetype": "docx", "key": "unsigned1", "outputtype": "pdf", "url": base + "/office/file/x"})
		req, _ := http.NewRequest(http.MethodPost, dsURL.String()+"/converter", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		resp, err := direct.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && !strings.Contains(string(b), `"error"`) {
			t.Fatalf("unsigned conversion accepted: %s", b)
		}
	})

	t.Run("proxy", func(t *testing.T) {
		gate := &Gate{}
		p := &Proxy{Service: svc, Gate: gate}
		req := httptest.NewRequest(http.MethodGet, "https://nas.test:44250"+DSPrefix+"/web-apps/apps/api/documents/api.js", nil)
		set := httptest.NewRecorder()
		gate.Set(set, req)
		req.AddCookie(set.Result().Cookies()[0])
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "DocsAPI") {
			t.Fatalf("api.js through the proxy: %d", w.Code)
		}
	})
}

func waitHealthy(t *testing.T, ds *url.URL) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Minute)
	for {
		resp, err := direct.Get(ds.String() + "/healthcheck")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if strings.TrimSpace(string(b)) == "true" {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the Document Server didn't become healthy")
		}
		time.Sleep(3 * time.Second)
	}
}

// convert asks the Document Server's ConvertService (JWT-signed) to fetch
// src and convert it; it returns the result's URL in its file cache.
func convert(ds *url.URL, secret []byte, src, from, to, key string) (string, error) {
	payload := map[string]any{"async": false, "filetype": from, "key": key, "outputtype": to, "title": "x." + from, "url": src}
	claims := map[string]any{"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()}
	for k, v := range payload {
		claims[k] = v
	}
	tok, err := SignJWT(secret, claims)
	if err != nil {
		return "", err
	}
	payload["token"] = tok
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, ds.String()+"/converter", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	c := direct
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		FileURL     string `json:"fileUrl"`
		EndConvert  bool   `json:"endConvert"`
		Error       int    `json:"error"`
		ErrorString string `json:"-"`
	}
	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, &out); err != nil {
		return "", fmt.Errorf("answer %d %s", resp.StatusCode, b)
	}
	if out.Error != 0 || !out.EndConvert || out.FileURL == "" {
		return "", errors.New("conversion failed: " + string(b))
	}
	return out.FileURL, nil
}

func postCallback(t *testing.T, u, hdr string, body []byte) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	req.Header.Set("Authorization", hdr)
	req.Header.Set("Content-Type", "application/json")
	resp, err := direct.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// localAddr: the test itself posts callbacks from one of this machine's
// own addresses (which one depends on the host's routing).
func localAddr(a netip.Addr) bool {
	addrs, _ := net.InterfaceAddrs()
	for _, x := range addrs {
		if n, ok := x.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap() == a {
				return true
			}
		}
	}
	return false
}

// direct ignores HTTP(S)_PROXY: everything here is on this machine.
var direct = &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{Proxy: nil}}
