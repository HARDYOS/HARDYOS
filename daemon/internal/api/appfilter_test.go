package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestImmichFilter(t *testing.T) {
	req := func(method, target, body string, hdr ...string) *http.Request {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		return r
	}
	blocked := map[string]*http.Request{
		"unlink":            req("POST", "/api/oauth/unlink", ""),
		"unlink case":       req("POST", "/API/OAuth/Unlink/", ""),
		"unlink slashes":    req("POST", "//api//oauth/unlink", ""),
		"unlink encoded":    req("POST", "/api/oauth/unl%69nk", ""),
		"unlink dots":       req("POST", "/api/x/../oauth/unlink", ""),
		"admin sign-up":     req("POST", "/api/auth/admin-sign-up", `{"email":"a@b","password":"x","name":"x"}`),
		"email":             req("PUT", "/api/users/me", `{"email":"dave@home.example.net"}`),
		"email escaped key": req("PUT", "/api/users/me", `{"email":"x"}`),
		"email upper key":   req("PUT", "/api/users/me", `{"Email":"x"}`),
		"password":          req("PUT", "/api/users/me", `{"name":"B","password":"x"}`),
		"not json":          req("PUT", "/api/users/me", `email=x`),
		"gzip":              req("PUT", "/api/users/me", "\x1f\x8b", "Content-Encoding", "gzip"),
		"override":          req("POST", "/api/users/me?_method=PUT", `{"email":"x"}`, "X-HTTP-Method-Override", "PUT"),
		"semicolon":         req("PUT", "/api/users/me;x", `{"email":"x"}`),
	}
	for name, r := range blocked {
		if why := immichFilter(r); why == "" {
			t.Errorf("%s: let through", name)
		}
	}
	allowed := map[string]*http.Request{
		"name":        req("PUT", "/api/users/me", `{"name":"Bob","avatarColor":"red"}`),
		"read me":     req("GET", "/api/users/me", ""),
		"oauth start": req("POST", "/api/oauth/authorize", `{"redirectUri":"x"}`),
		"upload":      req("POST", "/api/assets", "data"),
		"preferences": req("PUT", "/api/users/me/preferences", `{"email":{"enabled":true}}`),
	}
	for name, r := range allowed {
		if why := immichFilter(r); why != "" {
			t.Errorf("%s: refused (%s)", name, why)
		}
	}
	// The body is still there for Immich.
	r := req("PUT", "/api/users/me", `{"name":"Bob"}`)
	_ = immichFilter(r)
	if b, _ := io.ReadAll(r.Body); string(b) != `{"name":"Bob"}` {
		t.Fatalf("body after the filter: %q", b)
	}
	// Answered as Immich would answer a refusal; other apps untouched.
	w := httptest.NewRecorder()
	if !filterAppRequest(w, req("POST", "/api/oauth/unlink", ""), "immich") || w.Code != 403 || !strings.Contains(w.Body.String(), "HardyOS") {
		t.Fatalf("answer %d %s", w.Code, w.Body)
	}
	if filterAppRequest(httptest.NewRecorder(), req("POST", "/api/oauth/unlink", ""), "notes") {
		t.Fatal("filtered another app")
	}
}
