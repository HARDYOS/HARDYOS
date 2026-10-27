package photos

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Immich is a client for the parts of Immich's API Photos uses. It talks
// to the app on 127.0.0.1 (its published port), never through the
// internet, and never follows redirects.
type Immich struct {
	// Base is http://127.0.0.1:<port> (no path).
	Base string
	// APIKey (x-api-key) or Token (a session from Login) authenticates.
	APIKey string
	Token  string
	HTTP   *http.Client
}

// maxImmichBody bounds what's read from one answer.
const maxImmichBody = 8 << 20

// APIError is an answer Immich refused.
type APIError struct {
	Status  int
	Message string
	Path    string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("Immich answered %s with %d", e.Path, e.Status)
	}
	return fmt.Sprintf("Immich answered %s with %d: %s", e.Path, e.Status, e.Message)
}

// IsStatus reports whether err is an APIError with that status.
func IsStatus(err error, status int) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == status
}

// WithAPIKey returns a copy that authenticates with key.
func (c *Immich) WithAPIKey(key string) *Immich {
	n := *c
	n.APIKey, n.Token = key, ""
	return &n
}

// WithToken returns a copy that authenticates with a session token.
func (c *Immich) WithToken(tok string) *Immich {
	n := *c
	n.APIKey, n.Token = "", tok
	return &n
}

func (c *Immich) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (c *Immich) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+"/api"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	switch {
	case c.APIKey != "":
		req.Header.Set("x-api-key", c.APIKey)
	case c.Token != "":
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("asking Immich (%s %s): %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxImmichBody+1))
	if err != nil {
		return fmt.Errorf("reading Immich's answer to %s: %w", path, err)
	}
	if len(raw) > maxImmichBody {
		return fmt.Errorf("Immich's answer to %s is too big", path)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Message any `json:"message"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := ""
		switch m := e.Message.(type) {
		case string:
			msg = m
		case []any:
			var parts []string
			for _, x := range m {
				parts = append(parts, fmt.Sprint(x))
			}
			msg = strings.Join(parts, "; ")
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return &APIError{Status: resp.StatusCode, Message: msg, Path: path}
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("reading Immich's answer to %s: %w", path, err)
	}
	return nil
}

// Ping is Immich's liveness check (/api/server/ping answers {"res":"pong"}).
func (c *Immich) Ping(ctx context.Context) error {
	var r struct {
		Res string `json:"res"`
	}
	if err := c.do(ctx, http.MethodGet, "/server/ping", nil, &r); err != nil {
		return err
	}
	if r.Res != "pong" {
		return fmt.Errorf("Immich answered the ping with %q", r.Res)
	}
	return nil
}

// WaitReady pings until Immich answers or ctx ends.
func (c *Immich) WaitReady(ctx context.Context, every time.Duration) error {
	for {
		err := c.Ping(ctx)
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("Immich isn't answering yet: %w", err)
		case <-time.After(every):
		}
	}
}

// ServerConfig is the public part of /api/server/config.
type ServerConfig struct {
	IsInitialized  bool   `json:"isInitialized"`
	ExternalDomain string `json:"externalDomain"`
}

// ServerConfig reads whether Immich has an administrator yet.
func (c *Immich) ServerConfig(ctx context.Context) (*ServerConfig, error) {
	var r ServerConfig
	return &r, c.do(ctx, http.MethodGet, "/server/config", nil, &r)
}

// Features is /api/server/features (what the sign-in page offers).
type Features struct {
	OAuth           bool `json:"oauth"`
	OAuthAutoLaunch bool `json:"oauthAutoLaunch"`
	PasswordLogin   bool `json:"passwordLogin"`
}

// Features reads which sign-ins Immich offers.
func (c *Immich) Features(ctx context.Context) (*Features, error) {
	var r Features
	return &r, c.do(ctx, http.MethodGet, "/server/features", nil, &r)
}

// AdminSignUp makes Immich's first administrator (only while it has none).
func (c *Immich) AdminSignUp(ctx context.Context, email, name, password string) error {
	return c.do(ctx, http.MethodPost, "/auth/admin-sign-up", map[string]string{"email": email, "name": name, "password": password}, nil)
}

// Login signs in with a password and returns the session token.
func (c *Immich) Login(ctx context.Context, email, password string) (string, error) {
	var r struct {
		AccessToken string `json:"accessToken"`
	}
	if err := c.do(ctx, http.MethodPost, "/auth/login", map[string]string{"email": email, "password": password}, &r); err != nil {
		return "", err
	}
	if r.AccessToken == "" {
		return "", errors.New("Immich's sign-in gave no token")
	}
	return r.AccessToken, nil
}

// Logout ends the session the client signs in with.
func (c *Immich) Logout(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/auth/logout", nil, nil)
}

// CreateAPIKey makes an API key for the signed-in account and returns its
// secret (Immich shows it only now).
func (c *Immich) CreateAPIKey(ctx context.Context, name string, permissions []string) (string, error) {
	var r struct {
		Secret string `json:"secret"`
	}
	if err := c.do(ctx, http.MethodPost, "/api-keys", map[string]any{"name": name, "permissions": permissions}, &r); err != nil {
		return "", err
	}
	if r.Secret == "" {
		return "", errors.New("Immich made an API key without a secret")
	}
	return r.Secret, nil
}

// Me is the account the client signs in as.
func (c *Immich) Me(ctx context.Context) (*User, error) {
	var u User
	return &u, c.do(ctx, http.MethodGet, "/users/me", nil, &u)
}

// SystemConfig reads Immich's whole configuration.
func (c *Immich) SystemConfig(ctx context.Context) (map[string]any, error) {
	var r map[string]any
	if err := c.do(ctx, http.MethodGet, "/system-config", nil, &r); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, errors.New("Immich returned no configuration")
	}
	return r, nil
}

// SetSystemConfig replaces Immich's configuration (it takes the whole of it).
func (c *Immich) SetSystemConfig(ctx context.Context, cfg map[string]any) error {
	return c.do(ctx, http.MethodPut, "/system-config", cfg, nil)
}

// User is an Immich account (the admin view).
type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	IsAdmin      bool   `json:"isAdmin"`
	OAuthID      string `json:"oauthId"`
	StorageLabel string `json:"storageLabel"`
	Status       string `json:"status"`
	DeletedAt    string `json:"deletedAt"`
}

// Users lists every account.
func (c *Immich) Users(ctx context.Context) ([]User, error) {
	var r []User
	return r, c.do(ctx, http.MethodGet, "/admin/users", nil, &r)
}

// NewUser is an account to create.
type NewUser struct {
	Email        string `json:"email"`
	Name         string `json:"name"`
	Password     string `json:"password"`
	StorageLabel string `json:"storageLabel,omitempty"`
	IsAdmin      bool   `json:"isAdmin"`
	Notify       bool   `json:"notify"`
	// QuotaSizeInBytes nil: no limit.
	QuotaSizeInBytes *int64 `json:"quotaSizeInBytes"`
}

// CreateUser makes an account.
func (c *Immich) CreateUser(ctx context.Context, u NewUser) (*User, error) {
	var r User
	return &r, c.do(ctx, http.MethodPost, "/admin/users", u, &r)
}

// UpdateUser changes fields of an account.
func (c *Immich) UpdateUser(ctx context.Context, id string, fields map[string]any) error {
	return c.do(ctx, http.MethodPut, "/admin/users/"+url.PathEscape(id), fields, nil)
}

// ImmichLibrary is an external library.
type ImmichLibrary struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	OwnerID           string   `json:"ownerId"`
	ImportPaths       []string `json:"importPaths"`
	ExclusionPatterns []string `json:"exclusionPatterns"`
	AssetCount        int      `json:"assetCount"`
}

// Libraries lists the external libraries.
func (c *Immich) Libraries(ctx context.Context) ([]ImmichLibrary, error) {
	var r []ImmichLibrary
	return r, c.do(ctx, http.MethodGet, "/libraries", nil, &r)
}

// CreateLibrary makes an external library owned by ownerID.
func (c *Immich) CreateLibrary(ctx context.Context, ownerID, name string, importPaths, exclusions []string) (*ImmichLibrary, error) {
	var r ImmichLibrary
	return &r, c.do(ctx, http.MethodPost, "/libraries", map[string]any{
		"ownerId": ownerID, "name": name, "importPaths": importPaths, "exclusionPatterns": exclusions,
	}, &r)
}

// UpdateLibrary changes a library's name and folders.
func (c *Immich) UpdateLibrary(ctx context.Context, id, name string, importPaths, exclusions []string) error {
	return c.do(ctx, http.MethodPut, "/libraries/"+url.PathEscape(id), map[string]any{
		"name": name, "importPaths": importPaths, "exclusionPatterns": exclusions,
	}, nil)
}

// DeleteLibrary removes a library (its photos leave Immich; the files
// stay where they are).
func (c *Immich) DeleteLibrary(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/libraries/"+url.PathEscape(id), nil, nil)
}

// ScanLibrary asks Immich to look for new and removed files now.
func (c *Immich) ScanLibrary(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/libraries/"+url.PathEscape(id)+"/scan", nil, nil)
}

// Partner is an account the signed-in one shares its photos with.
type Partner struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// SharedWith lists the accounts the signed-in account shares with.
func (c *Immich) SharedWith(ctx context.Context) ([]Partner, error) {
	var r []Partner
	return r, c.do(ctx, http.MethodGet, "/partners?direction=shared-by", nil, &r)
}

// AddPartner shares the signed-in account's photos with userID.
func (c *Immich) AddPartner(ctx context.Context, userID string) error {
	return c.do(ctx, http.MethodPost, "/partners", map[string]string{"sharedWithId": userID}, nil)
}

// RemovePartner stops sharing with userID.
func (c *Immich) RemovePartner(ctx context.Context, userID string) error {
	return c.do(ctx, http.MethodDelete, "/partners/"+url.PathEscape(userID), nil, nil)
}

// OAuthAuthorize asks Immich for the URL it would send a browser to for
// signing in from redirectURI (what the sign-in button does). Immich reads
// the provider's discovery document to answer, so this checks the whole
// OAuth configuration short of a person signing in.
func (c *Immich) OAuthAuthorize(ctx context.Context, redirectURI string) (string, error) {
	var r struct {
		URL string `json:"url"`
	}
	if err := c.do(ctx, http.MethodPost, "/oauth/authorize", map[string]string{"redirectUri": redirectURI}, &r); err != nil {
		return "", err
	}
	return r.URL, nil
}
