package photos

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/oidc"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// TestImmichIntegration starts the catalog's Immich with real Docker
// (server, Postgres with vectors, Valkey; machine learning isn't needed)
// and runs a Photos sync against it: HardyOS's administrator account and
// key, sign-in with an OIDC provider (a small one in this test, reached
// from the container), libraries of existing photos and the family
// library. Immich's own /api/oauth/authorize then shows it read the
// provider's discovery document and uses HardyOS's redirects.
//
// Gated: HARDYOS_IMMICH_INTEGRATION=1, as root (the containers run as
// 30001 and their folders must be theirs). CI's "Photos (Immich)" job.
func TestImmichIntegration(t *testing.T) {
	if os.Getenv("HARDYOS_IMMICH_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_IMMICH_INTEGRATION=1 (needs Docker, root, and downloads Immich)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	// Cleanups run after the test's defers: the context ends with them.
	t.Cleanup(cancel)
	const uid = 30001
	project := "hardyos-immich-it"
	tmp := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	mkdir := func(p string, mode os.FileMode) string {
		must(os.MkdirAll(p, mode))
		must(os.Chmod(p, mode))
		must(os.Chown(p, uid, uid))
		return p
	}
	must(os.Chmod(tmp, 0o755))
	data := mkdir(filepath.Join(tmp, "data"), 0o755)
	for _, d := range []string{"postgres", "redis"} {
		mkdir(filepath.Join(data, d), 0o700)
	}
	for _, d := range []string{"model-cache", "model-cache-cuda", "model-cache-openvino", "model-cache-rocm"} {
		mkdir(filepath.Join(data, d), 0o750)
	}
	shares := map[string]string{}
	for _, s := range []string{"PHOTOS", "EXISTING", "EXISTING_2", "EXISTING_3", "FAMILY"} {
		shares[s] = mkdir(filepath.Join(tmp, "share-"+strings.ToLower(s)), 0o755)
	}
	writeJPEG(t, filepath.Join(mkdir(filepath.Join(shares["EXISTING"], "Bob"), 0o755), "beach.jpg"), color.RGBA{0, 120, 200, 255})
	writeJPEG(t, filepath.Join(shares["FAMILY"], "picnic.jpg"), color.RGBA{30, 160, 60, 255})

	port := freePort(t)
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + tmp, "HARDY_APP_ID=immich", "HARDY_APP_DATA=" + data,
		"HARDY_HOST=127.0.0.1", "HARDY_TZ=UTC", fmt.Sprintf("HARDY_UID=%d", uid), fmt.Sprintf("HARDY_GID=%d", uid),
		fmt.Sprintf("HARDY_PORT_WEB=%d", port), "DB_PASSWORD=" + RandomPassword()[:24],
		"ML_CUDA_REPLICAS=0", "ML_OPENVINO_REPLICAS=0", "ML_ROCM_REPLICAS=0"}
	for s, p := range shares {
		env = append(env, "HARDY_SHARE_"+s+"="+p)
	}
	compose := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "docker", append([]string{"compose", "-p", project}, args...)...)
		cmd.Env = env
		cmd.Dir = tmp
		var errb bytes.Buffer
		cmd.Stderr = &errb
		out, err := cmd.Output()
		if err != nil {
			return out, fmt.Errorf("docker compose %s: %v: %s", strings.Join(args, " "), err, errb.String())
		}
		return out, nil
	}
	// Resolved as HardyOS resolves it, minus the GPU devices a CI machine
	// doesn't have (HardyOS's engine drops them the same way).
	cwd, err := os.Getwd()
	must(err)
	raw, err := compose("-f", filepath.Join(cwd, "..", "..", "..", "apps", "catalog", "immich", "compose.yaml"), "config", "--format", "json")
	must(err)
	var resolved map[string]any
	must(json.Unmarshal(raw, &resolved))
	for _, svc := range resolved["services"].(map[string]any) {
		m := svc.(map[string]any)
		delete(m, "devices")
		if dp, ok := m["deploy"].(map[string]any); ok {
			delete(dp, "resources")
		}
	}
	file := filepath.Join(tmp, "compose.json")
	b, _ := json.Marshal(resolved)
	must(os.WriteFile(file, b, 0o600))
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := compose("-f", file, "logs", "--tail", "120")
			t.Logf("logs:\n%s", out)
		}
		_, _ = compose("-f", file, "down", "-v", "--remove-orphans")
	})
	if _, err := compose("-f", file, "up", "-d", "--wait", "--wait-timeout", "600", "database", "redis"); err != nil {
		t.Fatal(err)
	}
	if _, err := compose("-f", file, "up", "-d", "immich-server"); err != nil {
		t.Fatal(err)
	}

	// HardyOS's own sign-in provider (plain HTTP here, which only tests
	// allow), reached by the container through its network's gateway.
	db, err := store.Open(ctx, filepath.Join(tmp, "hardyd.db"))
	must(err)
	t.Cleanup(func() { db.Close() })
	gw := networkGateway(t, ctx, project+"_default")
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	must(err)
	issuer := fmt.Sprintf("http://%s:%d/oidc", gw, ln.Addr().(*net.TCPAddr).Port)
	users := &auth.Users{DB: db}
	provider, err := oidc.New(oidc.Config{DB: db, Users: users, SignIn: &auth.SignIn{Users: users}, Secrets: secretbox.NewStaticSource(),
		Insecure: true, LoadUser: func(ctx context.Context, id int64) (*auth.User, error) { return users.Get(ctx, id) }})
	must(err)
	must(provider.SetIssuer(ctx, issuer))
	var discovery atomic.Int32
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			discovery.Add(1)
		}
		if !provider.Owns(r) {
			http.NotFound(w, r)
			return
		}
		provider.ServeHTTP(w, r)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	published := "https://immich.home.example.net"
	clientID, clientSecret, err := provider.Clients.Ensure(ctx, ClientKey, "Photos (Immich)", RedirectURIs(published, nil), nil)
	must(err)

	st := &Store{DB: db}
	rec := &Reconciler{Immich: &Immich{Base: fmt.Sprintf("http://127.0.0.1:%d", port)}, Store: st, Dir: newFakeDir(), Ready: 8 * time.Minute}

	set := Defaults()
	set.Libraries = []Library{{OwnerID: 2, Share: "EXISTING", Path: "Bob", Name: "Bob's old photos"}}
	set.Family = Family{Enabled: true, Name: "Family Photos", Members: []appstore.Principal{}}
	set, err = set.Normalize()
	must(err)
	plan := Plan{
		Settings: set,
		Wanted: Wanted{OAuth: &OAuth{Issuer: issuer, ClientID: clientID, ClientSecret: clientSecret,
			MobileRedirect: MobileRedirect(published), AllowInsecure: true},
			MLURLs: MLURLs(MLCPU), ScanCron: set.ScanCron(), ExternalDomain: published},
		Access: []appstore.Principal{},
		Shares: map[string]bool{"PHOTOS": true, "EXISTING": true, "FAMILY": true},
		// Immich reads the provider's discovery document to answer.
		CheckOAuthFrom: published + "/auth/login",
	}
	status := &Status{Notes: []string{}}
	if err := rec.Run(ctx, plan, status); err != nil {
		t.Fatalf("sync: %v (%+v)", err, status)
	}
	if !status.SSO.Active || discovery.Load() == 0 {
		t.Fatalf("Immich didn't use the provider (discovery %d): %+v", discovery.Load(), status.SSO)
	}
	acct, err := st.Account(ctx)
	must(err)
	admin := rec.Immich.WithAPIKey(acct.AdminKey)
	feat, err := rec.Immich.Features(ctx)
	must(err)
	if !feat.OAuth || feat.PasswordLogin {
		t.Fatalf("sign-in features %+v", feat)
	}
	// The phone app's redirect becomes Immich's mobile redirect on HardyOS's
	// published address (HardyOS's provider takes https redirects only).
	u, err := admin.OAuthAuthorize(ctx, "app.immich:///oauth-callback")
	must(err)
	pu, err := url.Parse(u)
	must(err)
	if !strings.HasPrefix(u, issuer+"/authorize?") || pu.Query().Get("client_id") != clientID ||
		pu.Query().Get("redirect_uri") != MobileRedirect(published) || pu.Query().Get("code_challenge_method") != "S256" ||
		pu.Query().Get("scope") != Scope {
		t.Fatalf("authorize URL %s", u)
	}
	// HardyOS's provider takes that sign-in request: client, redirect,
	// PKCE and the Photos scope all accepted, so it asks the person to sign
	// in (an unknown client or redirect gets an error page, never this).
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := hc.Get(u)
	must(err)
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusFound || !strings.Contains(loc, "/login?id=") {
		t.Fatalf("provider answered Immich's sign-in request with %d %q", resp.StatusCode, loc)
	}
	// The web sign-in from the published address works the same way.
	u, err = admin.OAuthAuthorize(ctx, published+"/auth/login")
	must(err)
	resp, err = hc.Get(u)
	must(err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("web sign-in request: %d", resp.StatusCode)
	}
	// Libraries: Bob's (owned by the account HardyOS made for him) and the
	// family one; their scans find the photos.
	libs, err := admin.Libraries(ctx)
	must(err)
	if len(libs) != 2 {
		t.Fatalf("libraries %+v", libs)
	}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		libs, err = admin.Libraries(ctx)
		must(err)
		found := 0
		for _, l := range libs {
			var stats struct {
				Total  int `json:"total"`
				Photos int `json:"photos"`
			}
			if err := admin.do(ctx, http.MethodGet, "/libraries/"+l.ID+"/statistics", nil, &stats); err == nil && stats.Total+stats.Photos > 0 {
				found++
			}
		}
		if found == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("library scans found photos in %d of 2 libraries: %+v", found, libs)
		}
		time.Sleep(5 * time.Second)
	}
	// A second sync changes nothing.
	again := &Status{Notes: []string{}}
	if err := rec.Run(ctx, plan, again); err != nil || len(again.Notes) != 0 {
		t.Fatalf("second sync: %v %v", err, again.Notes)
	}
}

func writeJPEG(t *testing.T, path string, c color.Color) {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 64, 48))
	for y := 0; y < 48; y++ {
		for x := 0; x < 64; x++ {
			img.Set(x, y, c)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := jpeg.Encode(f, img, nil); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(path, 0o644)
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func networkGateway(t *testing.T, ctx context.Context, network string) string {
	t.Helper()
	out, err := exec.CommandContext(ctx, "docker", "network", "inspect", "--format", "{{range .IPAM.Config}}{{.Gateway}} {{end}}", network).Output()
	if err != nil {
		t.Fatalf("docker network inspect %s: %v", network, err)
	}
	for _, f := range strings.Fields(string(out)) {
		if ip := net.ParseIP(f); ip != nil && ip.To4() != nil {
			return f
		}
	}
	t.Fatalf("no IPv4 gateway for %s: %q", network, out)
	return ""
}
