package photos

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/oidc"
)

// Directory is what Photos needs from HardyOS's accounts and sign-in
// provider.
type Directory interface {
	// UserByID loads an account (nil, nil when it's gone).
	UserByID(ctx context.Context, id int64) (*auth.User, error)
	// Profile is what a sign-in would tell Immich about u.
	Profile(ctx context.Context, u *auth.User) (*oidc.AppProfile, error)
	// UserForSubject is the account behind a sign-in subject.
	UserForSubject(ctx context.Context, sub string) (*auth.User, error)
}

// Plan is everything a sync applies.
type Plan struct {
	Settings Settings
	Wanted   Wanted
	// Access is who may use the Immich app (its App Store list; empty =
	// everyone).
	Access []appstore.Principal
	// Shares are the package's shares the app was given a shared folder
	// for (EXISTING, FAMILY, ...).
	Shares map[string]bool
	// CheckOAuthFrom, when set, is a redirect URI to ask Immich to start a
	// sign-in from after configuring it: Immich then reads the provider's
	// discovery document, so a provider it can't reach shows up here.
	CheckOAuthFrom string
}

// Permissions of the API keys HardyOS makes: the administrator's for
// configuration, accounts and libraries; the family account's for
// partners only.
var (
	AdminKeyPermissions = []string{
		"systemConfig.read", "systemConfig.update",
		"adminUser.read", "adminUser.create", "adminUser.update",
		"library.read", "library.create", "library.update", "library.delete", "library.statistics",
	}
	FamilyKeyPermissions = []string{"partner.read", "partner.create", "partner.delete"}
)

// Account e-mail addresses HardyOS gives its own Immich accounts (never
// signed in to by people).
const (
	AdminEmail  = "hardyos-admin@hardyos.invalid"
	FamilyEmail = "hardyos-family@hardyos.invalid"
)

// Reconciler applies a Plan to Immich.
type Reconciler struct {
	// Immich is the unauthenticated client (its Base set).
	Immich *Immich
	Store  *Store
	Dir    Directory
	Log    *slog.Logger
	// Ready bounds the wait for Immich to answer (default 3 minutes).
	Ready time.Duration
}

// ErrNeedsLink: Immich already has an administrator HardyOS doesn't know.
var ErrNeedsLink = errors.New("Immich was set up before Photos: link it with an API key from one of its administrators (Control Panel > Photos)")

func (r *Reconciler) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

// Run brings Immich in line with p and fills st. An error stops the sync
// (st says how far it got); problems with one library or person are noted
// on them and the sync goes on.
func (r *Reconciler) Run(ctx context.Context, p Plan, st *Status) error {
	wait := r.Ready
	if wait == 0 {
		wait = 3 * time.Minute
	}
	wctx, cancel := context.WithTimeout(ctx, wait)
	err := r.Immich.WaitReady(wctx, 3*time.Second)
	cancel()
	if err != nil {
		return err
	}
	acct, err := r.Store.Account(ctx)
	if err != nil {
		return err
	}
	admin, err := r.ensureAdmin(ctx, &acct, st)
	if err != nil {
		return err
	}
	st.Linked = true

	family := p.Settings.Family.Enabled && p.Shares[FamilyShare]
	if family {
		if err := r.ensureFamilyAccount(ctx, admin, &acct, p.Settings.Family.Name); err != nil {
			st.Family.Problem = err.Error()
			family = false
		}
	}

	// Immich's configuration: HardyOS's part only.
	cur, err := admin.SystemConfig(ctx)
	if err != nil {
		return err
	}
	next, changed := Apply(cur, p.Wanted)
	if len(changed) > 0 {
		if err := admin.SetSystemConfig(ctx, next); err != nil {
			return fmt.Errorf("configuring Immich: %w", err)
		}
		st.Notes = append(st.Notes, "Immich settings changed: "+strings.Join(changed, ", "))
	}
	if p.Wanted.OAuth != nil && p.CheckOAuthFrom != "" {
		u, err := admin.OAuthAuthorize(ctx, p.CheckOAuthFrom)
		switch {
		case err != nil:
			st.SSO.Why = "Immich can't reach HardyOS's sign-in at " + p.Wanted.OAuth.Issuer + " (" + err.Error() + "): check in Control Panel > Remote Access that it is published, and that this server can look its name up"
		case !strings.HasPrefix(u, strings.TrimSuffix(p.Wanted.OAuth.Issuer, "/")+"/"):
			st.SSO.Why = "Immich sends people to " + host(u) + " to sign in, not to HardyOS"
		default:
			st.SSO.Active = true
		}
	}

	users, err := admin.Users(ctx)
	if err != nil {
		return err
	}
	if err := r.libraries(ctx, admin, p, &acct, family, &users, st); err != nil {
		return err
	}
	if err := r.partners(ctx, p, &acct, family, users, st); err != nil {
		st.Family.Problem = err.Error()
	}
	r.people(ctx, users, &acct, st)
	return nil
}

func host(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	h, _, _ := strings.Cut(u, "/")
	return h
}

// ensureAdmin returns a client authenticated as HardyOS's administrator
// account, making it (Immich's first sign-up) or a new API key for it
// when needed.
func (r *Reconciler) ensureAdmin(ctx context.Context, acct *Account, st *Status) (*Immich, error) {
	if acct.AdminKey != "" {
		c := r.Immich.WithAPIKey(acct.AdminKey)
		_, err := c.SystemConfig(ctx)
		if err == nil {
			return c, nil
		}
		if !IsStatus(err, http.StatusUnauthorized) && !IsStatus(err, http.StatusForbidden) {
			return nil, err
		}
		r.log().Warn("photos: Immich refused HardyOS's API key; making a new one", "err", err)
		acct.AdminKey = ""
		if acct.Linked {
			acct.Linked = false
			_ = r.Store.SaveAccount(ctx, *acct)
			st.NeedsLink = true
			return nil, ErrNeedsLink
		}
	}
	cfg, err := r.Immich.ServerConfig(ctx)
	if err != nil {
		return nil, err
	}
	if !cfg.IsInitialized {
		// A fresh Immich: HardyOS's account is its first administrator.
		// The password is saved before the sign-up, so a crash between the
		// two can't leave an administrator nobody knows.
		acct.AdminEmail, acct.AdminPassword, acct.Linked = AdminEmail, RandomPassword(), false
		acct.FamilyUserID, acct.FamilyKey = "", ""
		if err := r.Store.SaveAccount(ctx, *acct); err != nil {
			return nil, err
		}
		if err := r.Immich.AdminSignUp(ctx, acct.AdminEmail, "HardyOS", acct.AdminPassword); err != nil {
			return nil, fmt.Errorf("creating HardyOS's Immich account: %w", err)
		}
		st.Notes = append(st.Notes, "Made HardyOS's administrator account in Immich")
	} else if acct.AdminPassword == "" {
		st.NeedsLink = true
		return nil, ErrNeedsLink
	}
	key, err := r.keyWithPassword(ctx, acct.AdminEmail, acct.AdminPassword, "HardyOS", AdminKeyPermissions)
	if err != nil {
		return nil, fmt.Errorf("signing in to Immich as HardyOS: %w", err)
	}
	acct.AdminKey = key
	if err := r.Store.SaveAccount(ctx, *acct); err != nil {
		return nil, err
	}
	return r.Immich.WithAPIKey(key), nil
}

// keyWithPassword signs in with a password and makes an API key. Immich
// refuses password sign-ins while they're turned off, so they're turned
// on for the moment it takes (the configuration step after this sets
// them back).
func (r *Reconciler) keyWithPassword(ctx context.Context, email, password, name string, perms []string) (string, error) {
	tok, err := r.Immich.Login(ctx, email, password)
	if IsStatus(err, http.StatusUnauthorized) {
		if on, ferr := r.Immich.Features(ctx); ferr == nil && !on.PasswordLogin {
			if err := r.passwordLogin(ctx); err != nil {
				return "", err
			}
			tok, err = r.Immich.Login(ctx, email, password)
		}
	}
	if err != nil {
		return "", err
	}
	s := r.Immich.WithToken(tok)
	defer func() { _ = s.Logout(context.WithoutCancel(ctx)) }()
	return s.CreateAPIKey(ctx, name, perms)
}

// passwordLogin turns Immich's password sign-in on with the admin
// account's stored key (needed to make a key for the family account).
func (r *Reconciler) passwordLogin(ctx context.Context) error {
	acct, err := r.Store.Account(ctx)
	if err != nil || acct.AdminKey == "" {
		return errors.New("Immich's password sign-in is off and HardyOS has no key to turn it on")
	}
	admin := r.Immich.WithAPIKey(acct.AdminKey)
	cur, err := admin.SystemConfig(ctx)
	if err != nil {
		return err
	}
	pl, _ := cur["passwordLogin"].(map[string]any)
	if pl == nil {
		pl = map[string]any{}
		cur["passwordLogin"] = pl
	}
	pl["enabled"] = true
	return admin.SetSystemConfig(ctx, cur)
}

// ensureFamilyAccount makes the family account and its partner-only key.
func (r *Reconciler) ensureFamilyAccount(ctx context.Context, admin *Immich, acct *Account, name string) error {
	users, err := admin.Users(ctx)
	if err != nil {
		return err
	}
	var fam *User
	for i := range users {
		u := &users[i]
		if (acct.FamilyUserID != "" && u.ID == acct.FamilyUserID) || strings.EqualFold(u.Email, FamilyEmail) {
			fam = u
		}
	}
	if fam != nil && acct.FamilyPassword == "" {
		return errors.New("Immich has a family account HardyOS has no password for; remove " + FamilyEmail + " in Immich to start again")
	}
	if fam == nil {
		acct.FamilyEmail, acct.FamilyPassword, acct.FamilyKey = FamilyEmail, RandomPassword(), ""
		if err := r.Store.SaveAccount(ctx, *acct); err != nil {
			return err
		}
		u, err := admin.CreateUser(ctx, NewUser{Email: acct.FamilyEmail, Name: name, Password: acct.FamilyPassword, StorageLabel: "family"})
		if err != nil {
			return fmt.Errorf("creating the family account in Immich: %w", err)
		}
		fam = u
	} else if fam.Name != name {
		if err := admin.UpdateUser(ctx, fam.ID, map[string]any{"name": name}); err != nil {
			return err
		}
	}
	acct.FamilyUserID = fam.ID
	if acct.FamilyKey != "" {
		if _, err := r.Immich.WithAPIKey(acct.FamilyKey).SharedWith(ctx); err == nil {
			return r.Store.SaveAccount(ctx, *acct)
		}
	}
	key, err := r.keyWithPassword(ctx, acct.FamilyEmail, acct.FamilyPassword, "HardyOS family sharing", FamilyKeyPermissions)
	if err != nil {
		return fmt.Errorf("signing in to Immich's family account: %w", err)
	}
	acct.FamilyKey = key
	return r.Store.SaveAccount(ctx, *acct)
}

// person finds (or makes) the Immich account for a HardyOS account: the
// one signed in with its subject, else the one with its e-mail address
// (Immich links that one at the first sign-in), else a new one with a
// password nobody knows, ready for that first sign-in.
func (r *Reconciler) person(ctx context.Context, admin *Immich, prof *oidc.AppProfile, quotaGiB int, users *[]User) (*User, error) {
	for i := range *users {
		u := &(*users)[i]
		if u.DeletedAt == "" && u.OAuthID != "" && u.OAuthID == prof.Subject {
			return u, nil
		}
	}
	for i := range *users {
		u := &(*users)[i]
		if u.DeletedAt == "" && strings.EqualFold(u.Email, prof.Email) {
			if u.OAuthID != "" {
				return nil, fmt.Errorf("%s belongs to another sign-in in Immich", prof.Email)
			}
			return u, nil
		}
	}
	if prof.Email == "" {
		return nil, errors.New("the account has no e-mail address for Immich")
	}
	nu := NewUser{Email: prof.Email, Name: prof.Name, Password: RandomPassword(), StorageLabel: prof.StorageLabel, IsAdmin: prof.Admin}
	if quotaGiB > 0 {
		q := int64(quotaGiB) << 30
		nu.QuotaSizeInBytes = &q
	}
	u, err := admin.CreateUser(ctx, nu)
	if err != nil {
		return nil, fmt.Errorf("creating %s's Immich account: %w", prof.Name, err)
	}
	*users = append(*users, *u)
	return u, nil
}

// libraries keeps the personal libraries of existing photos and the
// family library, and removes the ones HardyOS made that are no longer
// asked for.
func (r *Reconciler) libraries(ctx context.Context, admin *Immich, p Plan, acct *Account, family bool, users *[]User, st *Status) error {
	recs, err := r.Store.Libraries(ctx)
	if err != nil {
		return err
	}
	have, err := admin.Libraries(ctx)
	if err != nil {
		return err
	}
	byID := map[string]ImmichLibrary{}
	for _, l := range have {
		byID[l.ID] = l
	}
	type want struct {
		key, name, owner, ownerName, path string
	}
	var wants []want
	st.Libraries = []LibraryState{}
	for _, l := range p.Settings.Libraries {
		ls := LibraryState{Key: l.Key(), Name: l.Name, ImportPath: l.ImportPath()}
		if !p.Shares[l.Share] {
			ls.Problem = "Immich wasn't given a shared folder for " + l.Share + " (App Store > Immich > Settings)"
			st.Libraries = append(st.Libraries, ls)
			continue
		}
		u, err := r.Dir.UserByID(ctx, l.OwnerID)
		if err != nil || u == nil {
			ls.Problem = "its owner's HardyOS account is gone"
			st.Libraries = append(st.Libraries, ls)
			continue
		}
		ls.Owner = u.IdentityPrincipal()
		prof, err := r.Dir.Profile(ctx, u)
		if err != nil {
			ls.Problem = err.Error()
			st.Libraries = append(st.Libraries, ls)
			continue
		}
		iu, err := r.person(ctx, admin, prof, p.Settings.DefaultQuotaGiB, users)
		if err != nil {
			ls.Problem = err.Error()
			st.Libraries = append(st.Libraries, ls)
			continue
		}
		st.Libraries = append(st.Libraries, ls)
		wants = append(wants, want{key: l.Key(), name: l.Name, owner: iu.ID, ownerName: ls.Owner, path: l.ImportPath()})
	}
	if family && acct.FamilyUserID != "" {
		wants = append(wants, want{key: FamilyKey, name: p.Settings.Family.Name, owner: acct.FamilyUserID, path: FamilyMount})
	}
	kept := map[string]bool{}
	for _, w := range wants {
		kept[w.key] = true
		rec, ok := recs[w.key]
		lib, exists := byID[rec.ImmichID]
		id := ""
		switch {
		case ok && exists && lib.OwnerID == w.owner:
			id = lib.ID
			if lib.Name != w.name || !slices.Equal(lib.ImportPaths, []string{w.path}) {
				if err := admin.UpdateLibrary(ctx, lib.ID, w.name, []string{w.path}, lib.ExclusionPatterns); err != nil {
					r.noteLibrary(st, w.key, err.Error())
					continue
				}
				_ = admin.ScanLibrary(ctx, lib.ID)
			}
		default:
			if ok && exists {
				// Its owner changed: the old one goes (Immich can't move a
				// library to another account).
				if err := admin.DeleteLibrary(ctx, lib.ID); err != nil {
					r.noteLibrary(st, w.key, err.Error())
					continue
				}
			}
			nl, err := admin.CreateLibrary(ctx, w.owner, w.name, []string{w.path}, []string{"**/@eaDir/**", "**/._*", "**/#recycle/**", "**/.snapshot/**", "**/.zfs/**"})
			if err != nil {
				r.noteLibrary(st, w.key, err.Error())
				continue
			}
			id = nl.ID
			if err := r.Store.SaveLibrary(ctx, LibRecord{Key: w.key, ImmichID: nl.ID, OwnerID: w.owner, ImportPath: w.path}); err != nil {
				return err
			}
			if err := admin.ScanLibrary(ctx, nl.ID); err != nil {
				r.log().Warn("photos: starting a library scan failed", "library", w.name, "err", err)
			}
			st.Notes = append(st.Notes, "Made the library "+w.name)
		}
		if w.key == FamilyKey {
			st.Family.ImmichID = id
			st.Family.Active = true
			continue
		}
		for i := range st.Libraries {
			if st.Libraries[i].Key == w.key {
				st.Libraries[i].ImmichID = id
				st.Libraries[i].Assets = byID[id].AssetCount
			}
		}
	}
	for key, rec := range recs {
		if kept[key] {
			continue
		}
		if _, exists := byID[rec.ImmichID]; exists {
			if err := admin.DeleteLibrary(ctx, rec.ImmichID); err != nil {
				st.Notes = append(st.Notes, "Couldn't remove a library HardyOS made ("+rec.ImportPath+"): "+err.Error())
				continue
			}
			st.Notes = append(st.Notes, "Removed the library for "+rec.ImportPath+" (its files stay where they are)")
		}
		if err := r.Store.ForgetLibrary(ctx, key); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reconciler) noteLibrary(st *Status, key, problem string) {
	if key == FamilyKey {
		st.Family.Problem = problem
		return
	}
	for i := range st.Libraries {
		if st.Libraries[i].Key == key {
			st.Libraries[i].Problem = problem
		}
	}
}

// partners shares the family account with each Immich account whose
// HardyOS account is a family member and may use Immich, and stops sharing
// with those HardyOS added that no longer are. Accounts that never signed
// in with HardyOS have no subject to check, so they wait for their first
// sign-in.
func (r *Reconciler) partners(ctx context.Context, p Plan, acct *Account, family bool, users []User, st *Status) error {
	mine, err := r.Store.Partners(ctx)
	if err != nil {
		return err
	}
	if acct.FamilyKey == "" {
		if len(mine) > 0 && !family {
			// No key to undo them with; Immich drops them with the account.
			for id := range mine {
				_ = r.Store.ForgetPartner(ctx, id)
			}
		}
		return nil
	}
	fc := r.Immich.WithAPIKey(acct.FamilyKey)
	cur, err := fc.SharedWith(ctx)
	if err != nil {
		return err
	}
	shared := map[string]bool{}
	for _, x := range cur {
		shared[x.ID] = true
	}
	want := map[string]bool{}
	if family {
		for _, u := range users {
			if u.DeletedAt != "" || u.OAuthID == "" || u.ID == acct.FamilyUserID {
				continue
			}
			hu, err := r.Dir.UserForSubject(ctx, u.OAuthID)
			if err != nil || hu == nil {
				continue
			}
			who := appstore.Who{Username: hu.IdentityPrincipal(), Groups: hu.IdentityGroups(), Admin: hu.IsAdmin()}
			if !appstore.MayUse(p.Access, who) {
				continue
			}
			if len(p.Settings.Family.Members) > 0 && !memberOf(p.Settings.Family.Members, hu) {
				continue
			}
			want[u.ID] = true
		}
	}
	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if shared[id] {
			continue
		}
		if err := fc.AddPartner(ctx, id); err != nil {
			return fmt.Errorf("sharing the family library: %w", err)
		}
		if err := r.Store.SavePartner(ctx, id); err != nil {
			return err
		}
	}
	for id := range mine {
		if want[id] {
			continue
		}
		if shared[id] {
			if err := fc.RemovePartner(ctx, id); err != nil && !IsStatus(err, http.StatusNotFound) && !IsStatus(err, http.StatusBadRequest) {
				return fmt.Errorf("stopping family sharing: %w", err)
			}
		}
		if err := r.Store.ForgetPartner(ctx, id); err != nil {
			return err
		}
	}
	st.Family.Members = len(want)
	return nil
}

// memberOf: the family list names u (as a user or through a group).
// Administrators aren't members just for being administrators.
func memberOf(list []appstore.Principal, u *auth.User) bool {
	for _, pr := range list {
		if u.Matches(pr.Kind, pr.Name) {
			return true
		}
	}
	return false
}

// people lists the Immich accounts that belong to HardyOS accounts.
func (r *Reconciler) people(ctx context.Context, users []User, acct *Account, st *Status) {
	st.People = []PersonState{}
	for _, u := range users {
		if u.DeletedAt != "" || strings.EqualFold(u.Email, AdminEmail) || u.ID == acct.FamilyUserID {
			continue
		}
		ps := PersonState{Email: u.Email, ImmichID: u.ID, Linked: u.OAuthID != ""}
		if u.OAuthID != "" {
			if hu, err := r.Dir.UserForSubject(ctx, u.OAuthID); err == nil && hu != nil {
				ps.Username = hu.IdentityPrincipal()
			}
		}
		st.People = append(st.People, ps)
	}
	sort.Slice(st.People, func(i, j int) bool { return st.People[i].Email < st.People[j].Email })
}

// Link saves an Immich administrator's API key for an Immich that was set
// up before Photos. The key must work and belong to an administrator.
func (r *Reconciler) Link(ctx context.Context, key string) error {
	key = strings.TrimSpace(key)
	if len(key) < 16 || len(key) > 512 || strings.ContainsAny(key, " \t\r\n") {
		return errors.New("that isn't an Immich API key")
	}
	c := r.Immich.WithAPIKey(key)
	me, err := c.Me(ctx)
	if err != nil {
		return fmt.Errorf("Immich didn't accept the key: %w", err)
	}
	if !me.IsAdmin {
		return errors.New("the key belongs to " + me.Email + ", who isn't an Immich administrator")
	}
	if _, err := c.SystemConfig(ctx); err != nil {
		return fmt.Errorf("the key can't read Immich's settings (give it all permissions): %w", err)
	}
	acct, err := r.Store.Account(ctx)
	if err != nil {
		return err
	}
	acct.AdminEmail, acct.AdminPassword, acct.AdminKey, acct.Linked = me.Email, "", key, true
	return r.Store.SaveAccount(ctx, acct)
}
