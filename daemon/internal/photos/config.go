package photos

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/oidc"
)

// OAuth is Immich's sign-in with HardyOS.
type OAuth struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// MobileRedirect is Immich's /api/oauth/mobile-redirect at its
	// published address ("" when it isn't published: the phone app then
	// can't sign in with HardyOS).
	MobileRedirect string
	AutoLaunch     bool
	// AllowInsecure lets Immich use an http:// issuer (tests only).
	AllowInsecure bool
}

// Scope is what Immich asks HardyOS's provider for.
const Scope = "openid email profile " + oidc.ScopePhotos

// ButtonText is the sign-in button on Immich's page.
const ButtonText = "Sign in with HardyOS"

// Wanted is the part of Immich's configuration HardyOS keeps. Everything
// else stays as Immich's administrators set it.
type Wanted struct {
	// OAuth nil turns sign-in with HardyOS off.
	OAuth *OAuth
	// PasswordLogin: Immich's own passwords (always on without OAuth, so no
	// one is locked out).
	PasswordLogin   bool
	DefaultQuotaGiB int
	MLURLs          []string
	ScanCron        string
	Watch           bool
	// ExternalDomain is Immich's published address, for the links it makes
	// (shared links, emails); "" leaves Immich's own setting.
	ExternalDomain string
}

// Apply returns cur with HardyOS's part set to w, and the names of the
// settings that changed (secrets by name only).
func Apply(cur map[string]any, w Wanted) (map[string]any, []string) {
	out := deepCopy(cur)
	var changed []string
	set := func(p string, v any) {
		keys := strings.Split(p, ".")
		m := out
		for _, k := range keys[:len(keys)-1] {
			next, ok := m[k].(map[string]any)
			if !ok {
				next = map[string]any{}
				m[k] = next
			}
			m = next
		}
		last := keys[len(keys)-1]
		if !sameJSON(m[last], v) {
			changed = append(changed, p)
		}
		m[last] = v
	}

	if o := w.OAuth; o != nil {
		set("oauth.enabled", true)
		set("oauth.issuerUrl", o.Issuer)
		set("oauth.clientId", o.ClientID)
		set("oauth.clientSecret", o.ClientSecret)
		set("oauth.scope", Scope)
		set("oauth.autoRegister", true)
		set("oauth.autoLaunch", o.AutoLaunch)
		set("oauth.buttonText", ButtonText)
		set("oauth.mobileOverrideEnabled", o.MobileRedirect != "")
		set("oauth.mobileRedirectUri", o.MobileRedirect)
		set("oauth.signingAlgorithm", "RS256")
		set("oauth.profileSigningAlgorithm", "none")
		set("oauth.tokenEndpointAuthMethod", "client_secret_post")
		set("oauth.roleClaim", oidc.ClaimPhotosRole)
		set("oauth.storageLabelClaim", oidc.ClaimStorageLabel)
		// HardyOS sends no quota claim: the default below applies.
		set("oauth.storageQuotaClaim", "hardyos_photos_quota")
		set("oauth.prompt", "")
		set("oauth.allowInsecureRequests", o.AllowInsecure)
	} else {
		set("oauth.enabled", false)
		set("oauth.autoLaunch", false)
		// No secret left behind for a client that may be gone.
		if v, _ := lookup(out, "oauth.clientId").(string); strings.HasPrefix(v, "hos-") {
			set("oauth.clientId", "")
			set("oauth.clientSecret", "")
		}
	}
	if w.DefaultQuotaGiB > 0 {
		set("oauth.defaultStorageQuota", w.DefaultQuotaGiB)
	} else {
		set("oauth.defaultStorageQuota", nil)
	}
	set("passwordLogin.enabled", w.PasswordLogin || w.OAuth == nil)

	// Each person's files in library/<their storage label>/.
	set("storageTemplate.enabled", true)
	if len(w.MLURLs) > 0 {
		urls := make([]any, len(w.MLURLs))
		for i, u := range w.MLURLs {
			urls[i] = u
		}
		set("machineLearning.urls", urls)
	}
	set("library.scan.enabled", true)
	if w.ScanCron != "" {
		set("library.scan.cronExpression", w.ScanCron)
	}
	set("library.watch.enabled", w.Watch)
	// Immich's nightly database dumps (into the photos folder's backups/)
	// are what a backup of the photos folder restores the database from.
	set("backup.database.enabled", true)
	if w.ExternalDomain != "" {
		set("server.externalDomain", w.ExternalDomain)
	}
	sort.Strings(changed)
	return out, changed
}

func lookup(m map[string]any, p string) any {
	var cur any = m
	for _, k := range strings.Split(p, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

func deepCopy(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]any{}
	}
	return out
}

func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
