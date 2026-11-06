// Package immichfake is a stand-in for the part of Immich's API that
// HardyOS's Photos uses, for tests. It follows Immich's rules where they
// matter: the first sign-up only while there's no administrator, password
// sign-in refused while it's off, administrator-only endpoints, API key
// permissions, one owner per library, partners per signed-in account,
// OAuth linking by e-mail at the first sign-in.
package immichfake

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
)

// User is an Immich account.
type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	IsAdmin      bool   `json:"isAdmin"`
	OAuthID      string `json:"oauthId"`
	StorageLabel string `json:"storageLabel"`
	DeletedAt    string `json:"deletedAt,omitempty"`
}

// Library is an external library.
type Library struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	OwnerID           string   `json:"ownerId"`
	ImportPaths       []string `json:"importPaths"`
	ExclusionPatterns []string `json:"exclusionPatterns"`
	AssetCount        int      `json:"assetCount"`
}

// Key is an API key.
type Key struct {
	User  string
	Perms []string
}

// Fake is the fake server. Lock Mu to look at or change its state.
type Fake struct {
	Srv *httptest.Server
	URL string

	Mu       sync.Mutex
	Users    []User
	Password map[string]string // user id -> password
	Keys     map[string]Key
	Sessions map[string]string // token -> user id
	Config   map[string]any
	Libs     []Library
	Scans    []string
	Partners map[string][]string // sharer -> shared with
	Calls    []string
	// Updates are the accounts PUT /admin/users changed, in order.
	Updates []string
	n       int
}

// SetOwnEmail is a person changing their own address (PUT /api/users/me,
// which HardyOS's proxies refuse but Immich allows).
func (f *Fake) SetOwnEmail(id, email string) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	f.User(id).Email = email
}

// Unlink is a person unlinking OAuth (POST /api/oauth/unlink).
func (f *Fake) Unlink(id string) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	f.User(id).OAuthID = ""
}

// AddUser adds an account as if someone made it in Immich.
func (f *Fake) AddUser(u User, password string) string {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if u.ID == "" {
		u.ID = f.id()
	}
	f.Users = append(f.Users, u)
	f.Password[u.ID] = password
	return u.ID
}

// Get returns a copy of an account.
func (f *Fake) Get(id string) User {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if u := f.User(id); u != nil {
		return *u
	}
	return User{}
}

// New starts a fake Immich with Immich's default configuration (the parts
// HardyOS touches, and one it doesn't: trash.days). Close it with Close.
func New() *Fake {
	f := &Fake{Password: map[string]string{}, Keys: map[string]Key{}, Sessions: map[string]string{},
		Partners: map[string][]string{}}
	f.Config = map[string]any{
		"oauth": map[string]any{"enabled": false, "clientId": "", "clientSecret": "", "issuerUrl": "", "autoLaunch": false,
			"scope": "openid email profile", "defaultStorageQuota": nil, "roleClaim": "immich_role"},
		"passwordLogin":   map[string]any{"enabled": true},
		"storageTemplate": map[string]any{"enabled": false, "template": "{{y}}/{{filename}}"},
		"machineLearning": map[string]any{"enabled": true, "urls": []any{"http://immich-machine-learning:3003"}},
		"library":         map[string]any{"scan": map[string]any{"enabled": true, "cronExpression": "0 0 * * *"}, "watch": map[string]any{"enabled": false}},
		"backup":          map[string]any{"database": map[string]any{"enabled": true}},
		"server":          map[string]any{"externalDomain": ""},
		"trash":           map[string]any{"days": float64(30)},
	}
	f.Srv = httptest.NewServer(http.HandlerFunc(f.serve))
	f.URL = f.Srv.URL
	return f
}

// Close stops the server.
func (f *Fake) Close() { f.Srv.Close() }

func (f *Fake) id() string {
	f.n++
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", f.n)
}

// User finds an account (Mu held).
func (f *Fake) User(id string) *User {
	for i := range f.Users {
		if f.Users[i].ID == id {
			return &f.Users[i]
		}
	}
	return nil
}

// Lookup reads a dotted path of the configuration.
func (f *Fake) Lookup(p string) any {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	var cur any = f.Config
	for _, k := range strings.Split(p, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[k]
	}
	return cur
}

func (f *Fake) passwordOn() bool {
	pl, _ := f.Config["passwordLogin"].(map[string]any)
	on, _ := pl["enabled"].(bool)
	return on
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/api")
	f.Calls = append(f.Calls, r.Method+" "+path)
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if v != nil {
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	fail := func(status int, msg string) { reply(status, map[string]any{"message": msg}) }
	var body map[string]any
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	str := func(k string) string { s, _ := body[k].(string); return s }

	var me *User
	var perms []string
	if k := r.Header.Get("x-api-key"); k != "" {
		fk, ok := f.Keys[k]
		if !ok {
			fail(401, "Invalid API key")
			return
		}
		me, perms = f.User(fk.User), fk.Perms
	} else if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		uid, ok := f.Sessions[strings.TrimPrefix(a, "Bearer ")]
		if !ok {
			fail(401, "Invalid user token")
			return
		}
		me, perms = f.User(uid), []string{"all"}
	}
	if me != nil && me.DeletedAt != "" {
		// A soft-deleted account's keys and sessions stop working.
		fail(401, "Invalid user token")
		return
	}
	need := func(perm string, admin bool) bool {
		if me == nil {
			fail(401, "Authentication required")
			return false
		}
		if admin && !me.IsAdmin {
			fail(403, "Forbidden")
			return false
		}
		if !slices.Contains(perms, "all") && !slices.Contains(perms, perm) {
			fail(403, "Missing required permission: "+perm)
			return false
		}
		return true
	}
	hasAdmin := slices.ContainsFunc(f.Users, func(u User) bool { return u.IsAdmin })

	switch {
	case r.Method == "GET" && path == "/server/ping":
		reply(200, map[string]string{"res": "pong"})
	case r.Method == "GET" && path == "/server/config":
		reply(200, map[string]any{"isInitialized": hasAdmin, "externalDomain": ""})
	case r.Method == "GET" && path == "/server/features":
		oa, _ := f.Config["oauth"].(map[string]any)
		reply(200, map[string]any{"oauth": oa["enabled"], "passwordLogin": f.passwordOn()})
	case r.Method == "POST" && path == "/auth/admin-sign-up":
		if hasAdmin {
			fail(400, "The server already has an admin")
			return
		}
		u := User{ID: f.id(), Email: str("email"), Name: str("name"), IsAdmin: true, StorageLabel: "admin"}
		f.Users = append(f.Users, u)
		f.Password[u.ID] = str("password")
		reply(201, u)
	case r.Method == "POST" && path == "/auth/login":
		if !f.passwordOn() {
			fail(401, "Password login has been disabled")
			return
		}
		for _, u := range f.Users {
			if u.DeletedAt == "" && strings.EqualFold(u.Email, str("email")) && f.Password[u.ID] == str("password") {
				tok := "tok-" + f.id()
				f.Sessions[tok] = u.ID
				reply(201, map[string]any{"accessToken": tok, "userId": u.ID})
				return
			}
		}
		fail(401, "Incorrect email or password")
	case r.Method == "POST" && path == "/auth/logout":
		delete(f.Sessions, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		reply(200, map[string]any{"successful": true})
	case r.Method == "POST" && path == "/api-keys":
		if !need("apiKey.create", false) {
			return
		}
		var p []string
		for _, x := range anySlice(body["permissions"]) {
			p = append(p, fmt.Sprint(x))
		}
		secret := "key-" + f.id()
		f.Keys[secret] = Key{User: me.ID, Perms: p}
		reply(201, map[string]any{"secret": secret})
	case r.Method == "GET" && path == "/users/me":
		if me == nil {
			fail(401, "Authentication required")
			return
		}
		reply(200, me)
	case path == "/system-config":
		if r.Method == "GET" {
			if need("systemConfig.read", true) {
				reply(200, f.Config)
			}
			return
		}
		if need("systemConfig.update", true) {
			f.Config = body
			reply(200, f.Config)
		}
	case path == "/admin/users" && r.Method == "GET":
		if need("adminUser.read", true) {
			out := []User{}
			for _, u := range f.Users {
				if u.DeletedAt == "" || r.URL.Query().Get("withDeleted") == "true" {
					out = append(out, u)
				}
			}
			reply(200, out)
		}
	case path == "/admin/users" && r.Method == "POST":
		if !need("adminUser.create", true) {
			return
		}
		for _, u := range f.Users {
			if strings.EqualFold(u.Email, str("email")) {
				fail(400, "Email is not available")
				return
			}
		}
		u := User{ID: f.id(), Email: str("email"), Name: str("name"), StorageLabel: str("storageLabel")}
		u.IsAdmin, _ = body["isAdmin"].(bool)
		f.Users = append(f.Users, u)
		f.Password[u.ID] = str("password")
		reply(201, u)
	case strings.HasPrefix(path, "/admin/users/") && strings.HasSuffix(path, "/restore") && r.Method == "POST":
		if !need("adminUser.delete", true) {
			return
		}
		u := f.User(strings.TrimSuffix(strings.TrimPrefix(path, "/admin/users/"), "/restore"))
		if u == nil {
			fail(400, "User not found")
			return
		}
		u.DeletedAt = ""
		reply(200, u)
	case strings.HasPrefix(path, "/admin/users/") && r.Method == "DELETE":
		if !need("adminUser.delete", true) {
			return
		}
		u := f.User(strings.TrimPrefix(path, "/admin/users/"))
		switch {
		case u == nil:
			fail(400, "User not found")
		case u.ID == me.ID:
			fail(403, "Cannot delete your own account")
		case u.IsAdmin:
			fail(403, "Cannot delete admin user")
		default:
			u.DeletedAt = "2026-10-27T00:00:00.000Z"
			reply(200, u)
		}
	case strings.HasPrefix(path, "/admin/users/") && r.Method == "PUT":
		if !need("adminUser.update", true) {
			return
		}
		u := f.User(strings.TrimPrefix(path, "/admin/users/"))
		if u == nil {
			fail(400, "User not found")
			return
		}
		if e, ok := body["email"].(string); ok && !strings.EqualFold(e, u.Email) {
			for _, o := range f.Users {
				if strings.EqualFold(o.Email, e) {
					fail(400, "Email already in use by another account")
					return
				}
			}
			u.Email = e
		}
		if n, ok := body["name"].(string); ok {
			u.Name = n
		}
		if a, ok := body["isAdmin"].(bool); ok {
			u.IsAdmin = a
		}
		if p, ok := body["password"].(string); ok {
			f.Password[u.ID] = p
		}
		f.Updates = append(f.Updates, u.ID)
		reply(200, u)
	case path == "/libraries" && r.Method == "GET":
		if need("library.read", true) {
			reply(200, f.Libs)
		}
	case path == "/libraries" && r.Method == "POST":
		if !need("library.create", true) {
			return
		}
		if f.User(str("ownerId")) == nil {
			fail(400, "Owner not found")
			return
		}
		l := Library{ID: f.id(), OwnerID: str("ownerId"), Name: str("name"), ImportPaths: strs(body["importPaths"]), ExclusionPatterns: strs(body["exclusionPatterns"])}
		f.Libs = append(f.Libs, l)
		reply(201, l)
	case strings.HasPrefix(path, "/libraries/") && strings.HasSuffix(path, "/scan"):
		if need("library.update", true) {
			f.Scans = append(f.Scans, strings.TrimSuffix(strings.TrimPrefix(path, "/libraries/"), "/scan"))
			reply(204, nil)
		}
	case strings.HasPrefix(path, "/libraries/"):
		id := strings.TrimPrefix(path, "/libraries/")
		i := slices.IndexFunc(f.Libs, func(l Library) bool { return l.ID == id })
		if r.Method == "PUT" && need("library.update", true) {
			if i < 0 {
				fail(400, "Library not found")
				return
			}
			f.Libs[i].Name, f.Libs[i].ImportPaths, f.Libs[i].ExclusionPatterns = str("name"), strs(body["importPaths"]), strs(body["exclusionPatterns"])
			reply(200, f.Libs[i])
		}
		if r.Method == "DELETE" && need("library.delete", true) {
			if i >= 0 {
				f.Libs = slices.Delete(f.Libs, i, i+1)
			}
			reply(204, nil)
		}
	case path == "/partners" && r.Method == "GET":
		if !need("partner.read", false) {
			return
		}
		if r.URL.Query().Get("direction") != "shared-by" {
			fail(400, "direction")
			return
		}
		out := []map[string]string{}
		for _, id := range f.Partners[me.ID] {
			out = append(out, map[string]string{"id": id, "email": f.User(id).Email})
		}
		reply(200, out)
	case path == "/partners" && r.Method == "POST":
		if !need("partner.create", false) {
			return
		}
		id := str("sharedWithId")
		if f.User(id) == nil || slices.Contains(f.Partners[me.ID], id) {
			fail(400, "Partner already exists")
			return
		}
		f.Partners[me.ID] = append(f.Partners[me.ID], id)
		reply(201, map[string]string{"id": id})
	case strings.HasPrefix(path, "/partners/") && r.Method == "DELETE":
		if !need("partner.delete", false) {
			return
		}
		id := strings.TrimPrefix(path, "/partners/")
		f.Partners[me.ID] = slices.DeleteFunc(f.Partners[me.ID], func(x string) bool { return x == id })
		reply(204, nil)
	case path == "/oauth/authorize" && r.Method == "POST":
		oa, _ := f.Config["oauth"].(map[string]any)
		if on, _ := oa["enabled"].(bool); !on {
			fail(400, "OAuth is not enabled")
			return
		}
		issuer, _ := oa["issuerUrl"].(string)
		cid, _ := oa["clientId"].(string)
		reply(201, map[string]string{"url": issuer + "/authorize?client_id=" + url.QueryEscape(cid) + "&redirect_uri=" + url.QueryEscape(str("redirectUri"))})
	default:
		fail(404, "Not found: "+r.Method+" "+path)
	}
}

func strs(v any) []string {
	out := []string{}
	for _, x := range anySlice(v) {
		out = append(out, fmt.Sprint(x))
	}
	return out
}

func anySlice(v any) []any {
	s, _ := v.([]any)
	return s
}

// SignInWithOAuth is a person's sign-in with HardyOS as Immich does it:
// the account with that subject, else link the one with that e-mail
// address, else register a new one. It returns the account's id.
func (f *Fake) SignInWithOAuth(sub, email, name string) string {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	for i := range f.Users {
		if f.Users[i].OAuthID == sub && f.Users[i].DeletedAt == "" {
			return f.Users[i].ID
		}
	}
	for i := range f.Users {
		if strings.EqualFold(f.Users[i].Email, email) && f.Users[i].OAuthID == "" && f.Users[i].DeletedAt == "" {
			f.Users[i].OAuthID = sub
			return f.Users[i].ID
		}
	}
	u := User{ID: f.id(), Email: email, Name: name, OAuthID: sub}
	f.Users = append(f.Users, u)
	return u.ID
}
