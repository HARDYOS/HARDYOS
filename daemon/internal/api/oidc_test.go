package api

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func adminClient(t *testing.T, env *testEnv) *client {
	t.Helper()
	admin := env.client(t)
	if code := admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil); code != 201 {
		t.Fatalf("setup admin = %d", code)
	}
	return admin
}

func TestOIDCClientsAPI(t *testing.T) {
	env := newEnv(t)
	admin := adminClient(t, env)

	var st map[string]any
	if code := admin.do("GET", "/api/v1/oidc", nil, &st); code != 200 || st["localAccounts"] != false || !strings.HasSuffix(st["issuer"].(string), "/oidc") {
		t.Fatalf("status %d %v", code, st)
	}
	// Presets for Cade's NetBird.
	var presets struct {
		Presets []struct {
			ID     string         `json:"id"`
			Client map[string]any `json:"client"`
		} `json:"presets"`
	}
	if code := admin.do("GET", "/api/v1/oidc/presets?netbirdUrl="+url.QueryEscape("https://vpn.hardynetworks.net"), nil, &presets); code != 200 || len(presets.Presets) != 2 {
		t.Fatalf("presets %d %v", code, presets)
	}
	// Create from the NetBird preset: the secret comes back once.
	var created struct {
		Client map[string]any `json:"client"`
		Secret string         `json:"secret"`
	}
	if code := admin.do("POST", "/api/v1/oidc/clients", presets.Presets[0].Client, &created); code != 201 || created.Secret == "" {
		t.Fatalf("create %d %v", code, created)
	}
	id := created.Client["id"].(string)
	var got map[string]any
	if code := admin.do("GET", "/api/v1/oidc/clients/"+id, nil, &got); code != 200 || got["hasSecret"] != true || got["secret"] != nil {
		t.Fatalf("get %d %v", code, got)
	}
	// Paste NetBird's redirect URL in.
	spec := presets.Presets[0].Client
	spec["redirectUris"] = []string{"https://vpn.hardynetworks.net/oauth2/callback/hardyos-abc"}
	var updated struct {
		Client map[string]any `json:"client"`
		Secret string         `json:"secret"`
	}
	if code := admin.do("PATCH", "/api/v1/oidc/clients/"+id, spec, &updated); code != 200 || updated.Secret != "" {
		t.Fatalf("update %d %v", code, updated)
	}
	var ns map[string]string
	if code := admin.do("POST", "/api/v1/oidc/clients/"+id+"/secret", nil, &ns); code != 200 || ns["secret"] == "" || ns["secret"] == created.Secret {
		t.Fatalf("new secret %d %v", code, ns)
	}
	var bad map[string]any
	if code := admin.do("POST", "/api/v1/oidc/clients", map[string]any{"name": "x", "redirectUris": []string{"http://evil.example"}}, &bad); code != 400 || bad["code"] != "invalid" {
		t.Fatalf("invalid client %d %v", code, bad)
	}
	if code := admin.do("PATCH", "/api/v1/oidc", map[string]any{"localAccounts": true}, &st); code != 200 || st["localAccounts"] != true {
		t.Fatalf("settings %d %v", code, st)
	}
	if code := admin.do("POST", "/api/v1/oidc/keys/rotate", nil, &st); code != 200 || len(st["keys"].([]any)) < 2 {
		t.Fatalf("rotate %d %v", code, st)
	}
	if code := admin.do("DELETE", "/api/v1/oidc/clients/"+id, nil, nil); code != 204 {
		t.Fatalf("delete %d", code)
	}
	// Audited.
	var entries []map[string]any
	admin.do("GET", "/api/v1/audit?limit=100", nil, &entries)
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e["action"].(string)] = true
	}
	for _, a := range []string{"oidc.client.create", "oidc.client.update", "oidc.client.secret", "oidc.client.delete", "oidc.settings", "oidc.keys.rotate"} {
		if !seen[a] {
			t.Errorf("%s not audited (%v)", a, seen)
		}
	}
	// Users can't.
	if code := admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"}, nil); code != 201 {
		t.Fatal(code)
	}
	kid := env.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	if code := kid.do("GET", "/api/v1/oidc/clients", nil, nil); code != 403 {
		t.Fatalf("user listing clients: %d", code)
	}
}

// The provider is served by the desktop's handler on the issuer's host and
// reuses a desktop session there (local accounts only when allowed).
func TestOIDCOnTheDesktopHost(t *testing.T) {
	env := newEnv(t)
	admin := adminClient(t, env)
	issuer := env.srv.URL + "/oidc"
	if code := admin.do("PATCH", "/api/v1/oidc", map[string]any{"issuer": issuer}, nil); code != 200 {
		t.Fatalf("set issuer %d", code)
	}
	resp, err := http.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("discovery %d", resp.StatusCode)
	}
	var created struct {
		Client map[string]any `json:"client"`
	}
	admin.do("POST", "/api/v1/oidc/clients", map[string]any{"name": "CLI", "kind": "public", "firstParty": true,
		"redirectUris": []string{"http://localhost:53000"}}, &created)
	id := created.Client["id"].(string)
	verifier := "v-0123456789-0123456789-0123456789-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {id}, "redirect_uri": {"http://localhost:53000"}, "response_type": {"code"}, "scope": {"openid"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "state": {"s"}}
	hc := *admin.http
	hc.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if req.URL.Host == "localhost:53000" {
			return http.ErrUseLastResponse
		}
		return nil
	}
	// A local administrator signed in to the desktop: asked for a password
	// while HardyOS accounts are off for apps.
	resp, err = hc.Get(issuer + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected the sign-in page, got %d", resp.StatusCode)
	}
	admin.do("PATCH", "/api/v1/oidc", map[string]any{"localAccounts": true}, nil)
	resp, err = hc.Get(issuer + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || loc.Host != "localhost:53000" || loc.Query().Get("code") == "" {
		t.Fatalf("desktop session not reused: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// The provider's pages carry their own strict headers, not the desktop's.
	resp, err = http.Get(issuer + "/logged-out")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Fatalf("CSP %q", csp)
	}
}
