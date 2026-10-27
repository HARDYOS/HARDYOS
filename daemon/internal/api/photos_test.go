package api

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/photos"
	"github.com/hardyos/hardyos/daemon/internal/photos/immichfake"
	"github.com/hardyos/hardyos/daemon/internal/publish"
)

// Photos end to end against a fake Immich: the sign-in client HardyOS
// keeps for it (exact redirect URIs, secret sealed), Immich's
// configuration, who may sign in, the machine learning setting, and SSO
// going off again.
func TestPhotosSync(t *testing.T) {
	e := newRemoteEnv(t)
	ctx := context.Background()
	imm := immichfake.New()
	t.Cleanup(imm.Close)
	port := imm.Srv.Listener.Addr().(*net.TCPAddr).Port

	var info PhotosInfo
	if code := e.kid.do("GET", "/api/v1/photos", nil, &info); code != 200 || info.Installed {
		t.Fatalf("photos before install = %d %+v", code, info)
	}
	if code := e.kid.do("GET", "/api/v1/photos/settings", nil, nil); code != 403 {
		t.Fatalf("a non-administrator read Photos settings: %d", code)
	}

	// Immich installed from the catalog, with photos and family folders.
	e.stub.mu.Lock()
	e.stub.apps["immich"] = apps.App{ID: "immich", Name: "Immich", Version: "3.3.5.1", Source: apps.SourceCatalog, State: "running",
		Web: &apps.AppWeb{Port: port, Path: "/", Scheme: "http"}, Containers: []apps.Container{{Service: "immich-server", State: "running"}},
		Shares: []apps.AppShare{{Name: "PHOTOS", Share: "photos", Access: "write"}, {Name: "EXISTING", Share: "media", Access: "read"},
			{Name: "FAMILY", Share: "family", Access: "read"}}}
	e.stub.mu.Unlock()

	// Without Remote Access there's no sign-in with HardyOS: Immich keeps
	// its passwords, and the status says why.
	j, _ := e.submit(t, "POST", "/api/v1/photos/sync", nil)
	if j["state"] != "succeeded" {
		t.Fatalf("sync = %v", j)
	}
	var view PhotosView
	e.admin.do("GET", "/api/v1/photos/settings", nil, &view)
	if view.Status == nil || !view.Status.Installed || !view.Status.Linked || view.Status.SSO.Active || !strings.Contains(view.Status.SSO.Why, "sso.<base>") {
		t.Fatalf("status without remote access: %+v", view.Status)
	}
	if imm.Lookup("oauth.enabled") != false || imm.Lookup("passwordLogin.enabled") != true {
		t.Fatal("OAuth on without a provider Immich can check")
	}
	// Machine learning on the processor, as installed: nothing to change.
	e.stub.mu.Lock()
	rc := slices.Clone(e.stub.reconfigs)
	e.stub.mu.Unlock()
	if len(rc) != 0 || view.Status.ML.Mode != photos.MLCPU {
		t.Fatalf("ML settings %+v %+v", rc, view.Status.ML)
	}
	// NVIDIA chosen: its image is downloaded first, then the service is
	// turned on (and the others off) through the apps engine.
	cuda := photos.Defaults()
	cuda.SSO, cuda.MLAcceleration = false, photos.MLCUDA
	if j, _ := e.submit(t, "PUT", "/api/v1/photos/settings", cuda); j["state"] != "succeeded" {
		t.Fatalf("settings = %v", j)
	}
	e.stub.mu.Lock()
	rc = slices.Clone(e.stub.reconfigs)
	e.stub.mu.Unlock()
	if len(rc) != 1 || rc[0].ID != "immich" || rc[0].Settings["ML_CUDA_REPLICAS"] != "1" || rc[0].Settings["ML_OPENVINO_REPLICAS"] != "0" || rc[0].Settings["ML_ROCM_REPLICAS"] != "0" {
		t.Fatalf("ML settings %+v", rc)
	}
	if p := e.stub.called("pull"); len(p) != 1 || !strings.Contains(p[0], `"service":"immich-machine-learning-cuda"`) {
		t.Fatalf("pulls %v", p)
	}
	if got := imm.Lookup("machineLearning.urls"); len(got.([]any)) != 2 || got.([]any)[0] != "http://immich-machine-learning-cuda:3003" {
		t.Fatalf("ML urls %v", got)
	}
	if _, err := e.server.photos.SaveSettings(ctx, photos.Defaults()); err != nil {
		t.Fatal(err)
	}

	// Remote Access with a base domain: sign-in with HardyOS at sso.<base>.
	e.submit(t, "POST", "/api/v1/remote/join", RemoteJoinRequest{ManagementURL: "https://vpn.hardynetworks.net", SetupKey: "A1B2C3D4-0000-1111-2222-333344445555"})
	tok := testToken
	if j, _ := e.submit(t, "PUT", "/api/v1/remote/publishing", RemotePublishingRequest{Enabled: true, BaseDomain: "home.example.net",
		APIURL: e.api.URL, DefaultMode: publish.ModePublic, Token: &tok}); j["state"] != "succeeded" {
		t.Fatalf("publishing = %v", j)
	}
	// Published for the phone app: public, its own sign-in only.
	if j, _ := e.submit(t, "PUT", "/api/v1/apps/immich/publish", PublishRequest{Mode: publish.ModePublic, Auth: publish.AuthNone, ConfirmOpen: true}); j["state"] != "succeeded" {
		t.Fatalf("publish immich = %v", j)
	}
	if j, _ := e.submit(t, "POST", "/api/v1/photos/sync", nil); j["state"] != "succeeded" {
		t.Fatalf("sync = %v", j)
	}
	e.admin.do("GET", "/api/v1/photos/settings", nil, &view)
	st := view.Status
	wantURIs := []string{"https://immich.home.example.net/auth/login", "https://immich.home.example.net/user-settings",
		"https://immich.home.example.net/api/oauth/mobile-redirect"}
	if !st.SSO.Active || st.SSO.Issuer != "https://sso.home.example.net" || !slices.Equal(st.SSO.RedirectURIs, wantURIs) ||
		st.PublishedURL != "https://immich.home.example.net" || !st.PhoneReady {
		t.Fatalf("status with remote access: %+v", st)
	}
	cl, err := e.server.OIDC().Clients.Managed(ctx, photos.ClientKey)
	if err != nil || !slices.Equal(cl.RedirectURIs, wantURIs) || cl.Kind != "confidential" || cl.ID != st.SSO.ClientID {
		t.Fatalf("sign-in client %+v %v", cl, err)
	}
	for path, want := range map[string]any{
		"oauth.enabled": true, "oauth.issuerUrl": "https://sso.home.example.net", "oauth.clientId": cl.ID,
		"oauth.mobileRedirectUri": "https://immich.home.example.net/api/oauth/mobile-redirect", "passwordLogin.enabled": false,
		"server.externalDomain": "https://immich.home.example.net", "oauth.scope": "openid email profile hardyos_photos",
	} {
		if got := imm.Lookup(path); got != want {
			t.Errorf("Immich %s = %v, want %v", path, got, want)
		}
	}
	// The client secret Immich has is sealed in hardyd's database.
	secret, _ := imm.Lookup("oauth.clientSecret").(string)
	var raw string
	_ = e.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'photos.oidc_client'`).Scan(&raw)
	if secret == "" || raw == "" || strings.Contains(raw, secret) {
		t.Fatal("the client secret isn't sealed")
	}
	if a := auditActions(e.admin, "oidc.client.create"); len(a) == 0 {
		t.Fatal("client creation not audited")
	}

	// Only people who may use Immich sign in to it with HardyOS.
	kid, err := e.server.users.GetByName(ctx, "kid")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.server.photosAccess(ctx, photos.ClientKey, kid); err != nil {
		t.Fatalf("everyone may use Immich: %v", err)
	}
	if err := e.store.SetAccess(ctx, "immich", []appstore.Principal{{Kind: "user", Name: "cade"}}); err != nil {
		t.Fatal(err)
	}
	if err := e.server.photosAccess(ctx, photos.ClientKey, kid); !errors.Is(err, errPhotosAccess) {
		t.Fatalf("kid without access: %v", err)
	}
	if err := e.server.photosAccess(ctx, "remote-gateway", kid); err != nil {
		t.Fatalf("other clients aren't Photos': %v", err)
	}

	// Bad settings are refused before a job; good ones run one.
	if code := e.admin.do("PUT", "/api/v1/photos/settings", photos.Settings{ScanHours: 999}, nil); code != 400 {
		t.Fatalf("bad settings = %d", code)
	}
	off := photos.Defaults()
	off.SSO = false
	if j, _ := e.submit(t, "PUT", "/api/v1/photos/settings", off); j["state"] != "succeeded" {
		t.Fatalf("settings = %v", j)
	}
	if _, err := e.server.OIDC().Clients.Managed(ctx, photos.ClientKey); err == nil {
		t.Fatal("the sign-in client stayed with SSO off")
	}
	if imm.Lookup("oauth.enabled") != false || imm.Lookup("passwordLogin.enabled") != true || imm.Lookup("oauth.clientSecret") != "" {
		t.Fatal("Immich still signs in with HardyOS")
	}

	// An API key to link an Immich set up earlier never shows up in a job.
	const key = "immich-api-key-0123456789abcdef"
	_, id := e.submit(t, "POST", "/api/v1/photos/link", PhotosLinkRequest{APIKey: key})
	if strings.Contains(jobText(t, e.admin, id), key) {
		t.Fatal("the API key is in the job")
	}
}
