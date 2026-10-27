package oidc

import (
	"net/url"
	"strings"
)

// Preset is a ready-made client for an app HardyOS knows, with what to
// paste where on the app's side. Values in Steps may hold {clientId},
// {clientSecret} and {issuer}, which Control Panel fills in once the
// client exists.
type Preset struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Client      ClientSpec `json:"client"`
	// RedirectFromApp: the app shows the exact redirect URL only after it
	// has the client ID (NetBird's identity provider connector); Control
	// Panel asks for it and adds it to the client.
	RedirectFromApp string       `json:"redirectFromApp,omitempty"`
	Steps           []PresetStep `json:"steps"`
	Notes           []string     `json:"notes"`
}

// PresetStep is one thing to do on the app's side.
type PresetStep struct {
	Where string `json:"where"`
	Field string `json:"field,omitempty"`
	Value string `json:"value,omitempty"`
}

// DefaultNetBirdURL is the NetBird management address HardyOS offers first
// (the contract's default; Remote Access's join form uses the same).
const DefaultNetBirdURL = "https://vpn.hardynetworks.net"

// Presets lists the presets for a NetBird server at netbirdURL (its
// dashboard and management address).
func Presets(netbirdURL string) []Preset {
	nb := strings.TrimRight(strings.TrimSpace(netbirdURL), "/")
	if u, err := url.Parse(nb); err != nil || u.Scheme != "https" || u.Host == "" {
		nb = DefaultNetBirdURL
	}
	return []Preset{
		{
			ID:   "netbird",
			Name: "NetBird",
			Description: "Sign in to NetBird (its dashboard, the NetBird app on each device, and the sign-in in front of public apps on its reverse proxy) " +
				"with your HardyOS account. HardyOS is added to NetBird's own identity provider as a Generic OIDC provider.",
			Client: ClientSpec{
				Name: "NetBird", Kind: KindConfidential, FirstParty: true, Preset: "netbird",
				RedirectURIs:           []string{nb + "/oauth2/callback"},
				PostLogoutRedirectURIs: []string{nb + "/oauth2/logout/callback"},
			},
			RedirectFromApp: nb + "/oauth2/callback/",
			Steps: []PresetStep{
				{Where: "NetBird dashboard (" + nb + "): Settings > Identity Providers > Add Identity Provider > Generic OIDC"},
				{Where: "Add Identity Provider", Field: "Type", Value: "Generic OIDC"},
				{Where: "Add Identity Provider", Field: "Name", Value: "HardyOS"},
				{Where: "Add Identity Provider", Field: "Client ID", Value: "{clientId}"},
				{Where: "Add Identity Provider", Field: "Client Secret", Value: "{clientSecret}"},
				{Where: "Add Identity Provider", Field: "Issuer", Value: "{issuer}"},
				{Where: "Click Save and keep the window open: NetBird shows a Redirect URL (" + nb + "/oauth2/callback/…). Paste it into HardyOS (below) so HardyOS accepts it."},
				{Where: "Optional, to use HardyOS groups in NetBird: Settings > Groups", Field: "JWT group sync", Value: "On"},
				{Where: "Settings > Groups", Field: "JWT claim", Value: "groups"},
				{Where: "Test: sign out of the dashboard and choose \"HardyOS\" on the sign-in page."},
			},
			Notes: []string{
				"Groups arrive as DOMAIN\\group (HOME\\Family). Distribution groups on public services can then limit an app to a HardyOS group.",
				"The sign-in in front of public apps on NetBird's reverse proxy uses NetBird's identity provider, so with this in place people choose HardyOS there too; nothing else is needed in HardyOS for it.",
				"Accounts without an email address in Domain > Users get name@domain as their address, marked unverified.",
			},
		},
		{
			ID:   "netbird-proxy",
			Name: "NetBird reverse proxy SSO (HardyOS as NetBird's only identity provider)",
			Description: "Only when NetBird runs without its built-in identity provider and uses HardyOS for everything: the dashboard, the NetBird app " +
				"(PKCE on http://localhost:53000) and the reverse proxy's SSO callback all use this one public client. With NetBird's built-in identity " +
				"provider use the NetBird preset instead: its reverse proxy SSO then works with no client of its own.",
			Client: ClientSpec{
				Name: "NetBird (dashboard and reverse proxy)", Kind: KindPublic, FirstParty: true, Preset: "netbird-proxy",
				RedirectURIs: []string{
					nb + "/auth", nb + "/silent-auth", nb + "/api/reverse-proxy/callback",
					"http://localhost:53000", "http://localhost:54000",
				},
				PostLogoutRedirectURIs: []string{nb + "/"},
			},
			Steps: []PresetStep{
				{Where: "NetBird setup.env (then regenerate the configuration and restart)", Field: "NETBIRD_AUTH_OIDC_CONFIGURATION_ENDPOINT", Value: "{issuer}/.well-known/openid-configuration"},
				{Where: "setup.env", Field: "NETBIRD_USE_AUTH0", Value: "false"},
				{Where: "setup.env", Field: "NETBIRD_AUTH_CLIENT_ID", Value: "{clientId}"},
				{Where: "setup.env", Field: "NETBIRD_AUTH_AUDIENCE", Value: "{clientId}"},
				{Where: "setup.env", Field: "NETBIRD_AUTH_SUPPORTED_SCOPES", Value: "openid profile email offline_access groups"},
				{Where: "setup.env", Field: "NETBIRD_AUTH_REDIRECT_URI", Value: "/auth"},
				{Where: "setup.env", Field: "NETBIRD_AUTH_SILENT_REDIRECT_URI", Value: "/silent-auth"},
				{Where: "management.json, HttpConfig (reverse proxy SSO)", Field: "AuthClientID", Value: "{clientId}"},
				{Where: "management.json, HttpConfig", Field: "AuthCallbackURL", Value: nb + "/api/reverse-proxy/callback"},
				{Where: "Restart management: docker compose restart management"},
			},
			Notes: []string{
				"HardyOS issues JWT access tokens with aud = the client ID and a groups claim, as NetBird's management expects.",
				"HardyOS has no device-code flow and no user-management API for NetBird: device sign-in uses PKCE in the browser, and NetBird can't list HardyOS accounts before they first sign in.",
				"Every service on the proxy with SSO turned on then sends people to HardyOS; distribution groups limit who gets in.",
			},
		},
	}
}

// PresetByID returns one preset.
func PresetByID(netbirdURL, id string) (Preset, bool) {
	for _, p := range Presets(netbirdURL) {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}
