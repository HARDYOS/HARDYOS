package photos

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

func TestNormalize(t *testing.T) {
	ok := Defaults()
	ok.Libraries = []Library{{OwnerID: 1, Share: "EXISTING", Path: " Pictures//2019/ ", Name: " Old "}}
	got, err := ok.Normalize()
	if err != nil || got.Libraries[0].Path != "Pictures/2019" || got.Libraries[0].Name != "Old" || got.Libraries[0].ImportPath() != "/mnt/existing/Pictures/2019" {
		t.Fatalf("%+v %v", got.Libraries, err)
	}
	whole := Library{OwnerID: 1, Share: "EXISTING_3", Path: "."}
	whole.Path, _ = cleanFolder(whole.Path)
	if whole.ImportPath() != "/mnt/existing-3" {
		t.Fatal(whole.ImportPath())
	}
	for name, l := range map[string]Library{
		"up":        {OwnerID: 1, Share: "EXISTING", Path: "a/../../etc", Name: "x"},
		"absolute":  {OwnerID: 1, Share: "EXISTING", Path: "/etc", Name: "x"},
		"backslash": {OwnerID: 1, Share: "EXISTING", Path: `a\b`, Name: "x"},
		"control":   {OwnerID: 1, Share: "EXISTING", Path: "a\nb", Name: "x"},
		"share":     {OwnerID: 1, Share: "PHOTOS", Name: "x"},
		"family":    {OwnerID: 1, Share: "FAMILY", Name: "x"},
		"owner":     {Share: "EXISTING", Name: "x"},
		"name":      {OwnerID: 1, Share: "EXISTING"},
	} {
		s := Defaults()
		s.Libraries = []Library{l}
		if _, err := s.Normalize(); err == nil {
			t.Errorf("%s: accepted %+v", name, l)
		}
	}
	dup := Defaults()
	dup.Libraries = []Library{{OwnerID: 1, Share: "EXISTING", Path: "a", Name: "x"}, {OwnerID: 1, Share: "EXISTING", Path: "a/", Name: "y"}}
	if _, err := dup.Normalize(); err == nil {
		t.Error("the same folder twice for one person")
	}
	bad := Defaults()
	bad.MLAcceleration, bad.ScanHours = "tpu", 500
	bad.Family.Members = []appstore.Principal{{Kind: "group", Name: "nodomain"}}
	if _, err := bad.Normalize(); err == nil || !strings.Contains(err.Error(), "machine learning") || !strings.Contains(err.Error(), "rescan") || !strings.Contains(err.Error(), "family members") {
		t.Fatalf("bad settings: %v", err)
	}
}

func TestScanCron(t *testing.T) {
	for h, want := range map[int]string{1: "0 * * * *", 6: "0 */6 * * *", 24: "0 1 * * *", 47: "0 1 * * *", 72: "0 1 */3 * *", 168: "0 1 */7 * *"} {
		if got := (Settings{ScanHours: h}).ScanCron(); got != want {
			t.Errorf("%d hours: %q, want %q", h, got, want)
		}
	}
}

func TestChooseML(t *testing.T) {
	nv := GPU{Vendor: "nvidia", Model: "RTX 3060", Driver: "nvidia", Owner: "apps"}
	nvVM := GPU{Vendor: "nvidia", Model: "RTX 3060", Driver: "vfio-pci", Owner: "vm", VM: "gaming"}
	nvNoDriver := GPU{Vendor: "nvidia", Driver: "nouveau", Owner: "apps"}
	igpu := GPU{Vendor: "intel", Model: "UHD 770", Driver: "i915", Owner: "apps"}
	amd := GPU{Vendor: "amd", Model: "RX 6600", Driver: "amdgpu", Owner: "apps"}
	for _, c := range []struct {
		name    string
		setting string
		gpus    []GPU
		arch    string
		mode    string
		lent    bool
	}{
		{"none", MLAuto, nil, "amd64", MLCPU, false},
		{"nvidia", MLAuto, []GPU{igpu, nv}, "amd64", MLCUDA, false},
		{"intel", MLAuto, []GPU{igpu}, "amd64", MLOpenVINO, false},
		{"amd", MLAuto, []GPU{amd}, "amd64", MLROCm, false},
		{"nvidia without its driver", MLAuto, []GPU{nvNoDriver, igpu}, "amd64", MLOpenVINO, false},
		{"lent nvidia still chosen, falls back while lent", MLAuto, []GPU{nvVM}, "amd64", MLCUDA, true},
		{"a free intel beats an nvidia a VM has", MLAuto, []GPU{nvVM, igpu}, "amd64", MLOpenVINO, false},
		{"a free intel beats an nvidia a VM is set up to take", MLAuto, []GPU{{Vendor: "nvidia", Driver: "nvidia", Owner: "apps", Assigned: true}, igpu}, "amd64", MLOpenVINO, false},
		{"arm64", MLAuto, []GPU{nv}, "arm64", MLCPU, false},
		{"arm64 forced", MLCUDA, []GPU{nv}, "arm64", MLCPU, false},
		{"cpu", MLCPU, []GPU{nv}, "amd64", MLCPU, false},
		{"forced intel", MLOpenVINO, []GPU{nv, igpu}, "amd64", MLOpenVINO, false},
		{"forced without hardware", MLROCm, nil, "amd64", MLROCm, false},
	} {
		got := ChooseML(c.setting, c.gpus, c.arch)
		if got.Mode != c.mode || got.Lent != c.lent || got.Reason == "" {
			t.Errorf("%s: %+v, want %s lent=%v", c.name, got, c.mode, c.lent)
		}
	}
}

func TestMLSettingsAndURLs(t *testing.T) {
	s := MLSettings(MLOpenVINO)
	if len(s) != 3 || s["ML_OPENVINO_REPLICAS"] != "1" || s["ML_CUDA_REPLICAS"] != "0" || s["ML_ROCM_REPLICAS"] != "0" {
		t.Fatal(s)
	}
	if s := MLSettings(MLCPU); s["ML_CUDA_REPLICAS"]+s["ML_OPENVINO_REPLICAS"]+s["ML_ROCM_REPLICAS"] != "000" {
		t.Fatal(s)
	}
	if u := MLURLs(MLCUDA); !slices.Equal(u, []string{"http://immich-machine-learning-cuda:3003", "http://immich-machine-learning:3003"}) {
		t.Fatal(u)
	}
	if u := MLURLs(MLCPU); !slices.Equal(u, []string{"http://immich-machine-learning:3003"}) {
		t.Fatal(u)
	}
}

func TestRedirectURIs(t *testing.T) {
	got := RedirectURIs("https://immich.home.example.net", []string{"https://nas:44301"})
	want := []string{
		"https://immich.home.example.net/auth/login", "https://immich.home.example.net/user-settings",
		"https://nas:44301/auth/login", "https://nas:44301/user-settings",
		"https://immich.home.example.net/api/oauth/mobile-redirect",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%v", got)
	}
	// Without a published address there's no phone redirect.
	if got := RedirectURIs("", []string{"https://nas:44301"}); len(got) != 2 {
		t.Fatalf("%v", got)
	}
}

func TestApplyKeepsTheRest(t *testing.T) {
	cur := map[string]any{
		"oauth":   map[string]any{"enabled": false, "clientId": "", "buttonText": "Login with OAuth"},
		"ffmpeg":  map[string]any{"accel": "qsv", "crf": float64(23)},
		"trash":   map[string]any{"days": float64(10)},
		"library": map[string]any{"scan": map[string]any{"enabled": false}},
	}
	w := Wanted{OAuth: &OAuth{Issuer: "https://sso.x", ClientID: "hos-1", ClientSecret: "sek"}, MLURLs: MLURLs(MLCPU), ScanCron: "0 */6 * * *", DefaultQuotaGiB: 50}
	next, changed := Apply(cur, w)
	if lookup(next, "ffmpeg.accel") != "qsv" || lookup(next, "trash.days") != float64(10) {
		t.Fatal("touched what isn't HardyOS's")
	}
	if lookup(cur, "oauth.enabled") != false {
		t.Fatal("changed the input")
	}
	if lookup(next, "oauth.defaultStorageQuota") != 50 || lookup(next, "passwordLogin.enabled") != false || lookup(next, "oauth.mobileOverrideEnabled") != false {
		t.Fatalf("%v", next["oauth"])
	}
	if !slices.Contains(changed, "oauth.clientSecret") || slices.ContainsFunc(changed, func(c string) bool { return strings.Contains(c, "sek") }) {
		t.Fatalf("changed %v", changed)
	}
	if _, again := Apply(next, w); len(again) != 0 {
		t.Fatalf("not idempotent: %v", again)
	}
	if lookup(next, "user.deleteDelay") != MinDeleteDelayDays {
		t.Fatalf("delete delay %v", lookup(next, "user.deleteDelay"))
	}
	longer := deepCopy(next)
	longer["user"] = map[string]any{"deleteDelay": float64(90)}
	if out, _ := Apply(longer, w); lookup(out, "user.deleteDelay") != float64(90) {
		t.Fatal("a longer delete delay was shortened")
	}
	// Off: the secret goes, passwords come back.
	off, _ := Apply(next, Wanted{})
	if lookup(off, "oauth.enabled") != false || lookup(off, "oauth.clientSecret") != "" || lookup(off, "passwordLogin.enabled") != true || lookup(off, "oauth.defaultStorageQuota") != nil {
		t.Fatalf("%v %v", off["oauth"], off["passwordLogin"])
	}
}

func TestStoreSeals(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	src := secretbox.NewStaticSource()
	s := &Store{DB: db, Secrets: src}
	if err := s.SaveAccount(ctx, Account{AdminEmail: AdminEmail, AdminPassword: "pw-very-secret", AdminKey: "key-very-secret"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveClient(ctx, ClientCreds{ID: "hos-1", Secret: "client-very-secret"}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{settingAccount, settingClient} {
		raw, _ := db.GetSetting(ctx, k)
		if !strings.HasPrefix(raw, "v1:") || strings.Contains(raw, "very-secret") {
			t.Fatalf("%s stored as %q", k, raw)
		}
	}
	a, err := s.Account(ctx)
	if err != nil || a.AdminKey != "key-very-secret" {
		t.Fatalf("%+v %v", a, err)
	}
	// A value moved to another setting doesn't open.
	raw, _ := db.GetSetting(ctx, settingAccount)
	_ = db.SetSetting(ctx, settingClient, raw)
	if c, err := s.Client(ctx); err != nil || c.Secret != "" {
		t.Fatalf("moved sealed value opened: %+v %v", c, err)
	}
	// Another server's key: forgotten, not an error.
	other := &Store{DB: db, Secrets: secretbox.NewStaticSource()}
	if a, err := other.Account(ctx); err != nil || a.AdminKey != "" {
		t.Fatalf("%+v %v", a, err)
	}
	// Settings round-trip and are checked.
	set := Defaults()
	set.SSO = false
	if _, err := s.SaveSettings(ctx, set); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Settings(ctx); got.SSO || got.ScanHours != 6 {
		t.Fatalf("%+v", got)
	}
	set.ScanHours = -1
	if _, err := s.SaveSettings(ctx, set); err == nil {
		t.Fatal("bad settings saved")
	}
}
