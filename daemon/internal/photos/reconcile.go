package photos

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/oidc"
	"github.com/hardyos/hardyos/daemon/internal/shares"
)

// Directory is what Photos needs from HardyOS's accounts and sign-in
// provider.
type Directory interface {
	// UserByID loads an account (nil, nil when it's gone).
	UserByID(ctx context.Context, id int64) (*auth.User, error)
	// Profile is what a sign-in would tell Immich about u (an error for an
	// account without an e-mail address).
	Profile(ctx context.Context, u *auth.User) (*oidc.AppProfile, error)
	// UserForSubject is the account behind a sign-in subject (an error
	// when it's gone or turned off).
	UserForSubject(ctx context.Context, sub string) (*auth.User, error)
	// People lists HardyOS's accounts, turned-off ones included.
	People(ctx context.Context) ([]*auth.User, error)
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
	// Links are each library share's scan for links leading out of it
	// (shares.links); a share with none here couldn't be checked, and
	// LinkErrors says why.
	Links      map[string]*shares.LinkScan
	LinkErrors map[string]string
	// CheckOAuthFrom, when set, is a redirect URI to ask Immich to start a
	// sign-in from after configuring it: Immich then reads the provider's
	// discovery document, so a provider it can't reach shows up here.
	CheckOAuthFrom string
	// FreshInstall: this Immich was installed with new data while Photos
	// was there, so HardyOS made (or is about to make) its first
	// administrator: another one is an incident, not a link to ask for.
	FreshInstall bool
}

// Permissions of the API keys HardyOS makes: the administrator's for
// configuration, accounts and libraries; the family account's for
// partners only.
var (
	AdminKeyPermissions = []string{
		"systemConfig.read", "systemConfig.update",
		"adminUser.read", "adminUser.create", "adminUser.update", "adminUser.delete",
		"library.read", "library.create", "library.update", "library.delete", "library.statistics",
	}
	FamilyKeyPermissions = []string{"partner.read", "partner.create", "partner.delete"}
)

// Account e-mail addresses HardyOS gives its own Immich accounts (never
// signed in to by people). No placeholder (local.hardyos.invalid) or moved
// account (unlinked-*@hardyos.invalid) can have them.
const (
	AdminEmail  = "admin@service.hardyos.invalid"
	FamilyEmail = "family@service.hardyos.invalid"
)

// MaxEscapingLinks is how many links leading out of a share a library on
// it may have excluded; more, and the library isn't made.
const MaxEscapingLinks = 200

// Reconciler applies a Plan to Immich.
type Reconciler struct {
	// Immich is the unauthenticated client (its Base set).
	Immich *Immich
	Store  *Store
	Dir    Directory
	Log    *slog.Logger
	// Audit records what HardyOS changed in Immich's accounts.
	Audit func(ctx context.Context, action, target, detail string)
	// Ready bounds the wait for Immich to answer (default 3 minutes).
	Ready time.Duration
}

// ErrNeedsLink: Immich already has an administrator HardyOS doesn't know.
var ErrNeedsLink = errors.New("Immich was set up before Photos: link it with an API key from one of its administrators (Control Panel > Photos)")

// ErrUnexpectedAdmin: an Immich HardyOS installed got an administrator
// before HardyOS made its own (someone signed Immich up first).
var ErrUnexpectedAdmin = errors.New("Immich got an administrator HardyOS didn't make, before Photos set it up: someone signed up on Immich's page first. Photos won't use it. Remove Immich with its data and install it again, or link it with an API key if you made that administrator yourself")

func (r *Reconciler) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

func (r *Reconciler) audit(ctx context.Context, action, target, detail string) {
	if r.Audit != nil {
		r.Audit(ctx, action, target, detail)
	}
}

// EnsureAdmin makes HardyOS's administrator account in a fresh Immich (or
// a new key for it) as soon as Immich answers. The sync runs it first, and
// hardyd runs it on its own right after an install.
func (r *Reconciler) EnsureAdmin(ctx context.Context, fresh bool, st *Status) (*Immich, error) {
	wait := r.Ready
	if wait == 0 {
		wait = 3 * time.Minute
	}
	wctx, cancel := context.WithTimeout(ctx, wait)
	err := r.Immich.WaitReady(wctx, time.Second)
	cancel()
	if err != nil {
		return nil, err
	}
	acct, err := r.Store.Account(ctx)
	if err != nil {
		return nil, err
	}
	admin, err := r.ensureAdmin(ctx, &acct, st, fresh)
	if err == nil {
		st.Linked = true
	}
	return admin, err
}

// Run brings Immich in line with p and fills st. An error stops the sync
// (st says how far it got); problems with one library or person are noted
// on them and the sync goes on.
func (r *Reconciler) Run(ctx context.Context, p Plan, st *Status) error {
	admin, err := r.EnsureAdmin(ctx, p.FreshInstall, st)
	if err != nil {
		return err
	}
	acct, err := r.Store.Account(ctx)
	if err != nil {
		return err
	}

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
	recs, err := r.Store.Accounts(ctx)
	if err != nil {
		return err
	}
	rs := &runState{admin: admin, users: users, recs: recs, bySub: map[string]*hosPerson{}, byEmail: map[string]string{},
		accounts: map[string]string{}, holder: map[string]string{}, flags: map[string]string{}, service: map[string]bool{}}
	for _, id := range []string{acct.AdminUserID, acct.FamilyUserID} {
		if id != "" {
			rs.service[id] = true
		}
	}
	if err := r.loadPeople(ctx, p, rs, st); err != nil {
		return err
	}
	if err := r.guard(ctx, p, rs, st); err != nil {
		return err
	}
	r.forgetGone(ctx, rs)
	if err := r.libraries(ctx, p, rs, &acct, family, st); err != nil {
		return err
	}
	if st.Family.Problem != "" {
		// The family account isn't usable: its partners stay as they are.
	} else if err := r.partners(ctx, p, rs, &acct, family, st); err != nil {
		st.Family.Problem = err.Error()
	}
	r.people(rs, st)
	return nil
}

// forgetGone drops records of accounts Immich no longer has at all.
func (r *Reconciler) forgetGone(ctx context.Context, rs *runState) {
	have := map[string]bool{}
	for _, u := range rs.users {
		have[u.ID] = true
	}
	for id := range rs.recs {
		if !have[id] {
			_ = r.Store.ForgetAccountRec(ctx, id)
			delete(rs.recs, id)
		}
	}
}

func host(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	h, _, _ := strings.Cut(u, "/")
	return h
}

// ensureAdmin returns a client authenticated as HardyOS's administrator
// account, making it (Immich's first sign-up) or a new API key for it
// when needed.
func (r *Reconciler) ensureAdmin(ctx context.Context, acct *Account, st *Status, fresh bool) (*Immich, error) {
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
		acct.AdminEmail, acct.AdminPassword, acct.Linked, acct.AdminUserID = AdminEmail, RandomPassword(), false, ""
		acct.FamilyUserID, acct.FamilyKey = "", ""
		if err := r.Store.SaveAccount(ctx, *acct); err != nil {
			return nil, err
		}
		if err := r.Immich.AdminSignUp(ctx, acct.AdminEmail, "HardyOS", acct.AdminPassword); err != nil {
			return nil, fmt.Errorf("creating HardyOS's Immich account: %w", err)
		}
		r.audit(ctx, "photos.account.create", AdminEmail, "HardyOS's administrator account in Immich")
		st.Notes = append(st.Notes, "Made HardyOS's administrator account in Immich")
	} else if acct.AdminPassword == "" {
		if fresh {
			st.Incident = ErrUnexpectedAdmin.Error()
			return nil, ErrUnexpectedAdmin
		}
		st.NeedsLink = true
		return nil, ErrNeedsLink
	}
	key, uid, err := r.keyWithPassword(ctx, acct.AdminEmail, acct.AdminPassword, "HardyOS", AdminKeyPermissions)
	if err != nil {
		return nil, fmt.Errorf("signing in to Immich as HardyOS: %w", err)
	}
	acct.AdminKey, acct.AdminUserID = key, uid
	if err := r.Store.SaveAccount(ctx, *acct); err != nil {
		return nil, err
	}
	return r.Immich.WithAPIKey(key), nil
}

// keyWithPassword signs in with a password and makes an API key, returning
// it and the account's id. Immich refuses password sign-ins while they're
// turned off, so they're turned on for the moment it takes and put back as
// they were before it returns.
func (r *Reconciler) keyWithPassword(ctx context.Context, email, password, name string, perms []string) (string, string, error) {
	tok, uid, err := r.Immich.Login(ctx, email, password)
	if IsStatus(err, http.StatusUnauthorized) {
		if on, ferr := r.Immich.Features(ctx); ferr == nil && !on.PasswordLogin {
			restore, perr := r.passwordLogin(ctx)
			if perr != nil {
				return "", "", perr
			}
			defer restore()
			tok, uid, err = r.Immich.Login(ctx, email, password)
		}
	}
	if err != nil {
		return "", "", err
	}
	s := r.Immich.WithToken(tok)
	defer func() { _ = s.Logout(context.WithoutCancel(ctx)) }()
	key, err := s.CreateAPIKey(ctx, name, perms)
	return key, uid, err
}

// passwordLogin turns Immich's password sign-in on with the admin
// account's stored key (needed to make a key for the family account) and
// returns what turns it off again.
func (r *Reconciler) passwordLogin(ctx context.Context) (func(), error) {
	acct, err := r.Store.Account(ctx)
	if err != nil || acct.AdminKey == "" {
		return nil, errors.New("Immich's password sign-in is off and HardyOS has no key to turn it on")
	}
	admin := r.Immich.WithAPIKey(acct.AdminKey)
	set := func(on bool) error {
		cur, err := admin.SystemConfig(ctx)
		if err != nil {
			return err
		}
		pl, _ := cur["passwordLogin"].(map[string]any)
		if pl == nil {
			pl = map[string]any{}
			cur["passwordLogin"] = pl
		}
		pl["enabled"] = on
		return admin.SetSystemConfig(ctx, cur)
	}
	if err := set(true); err != nil {
		return nil, err
	}
	return func() {
		if err := set(false); err != nil {
			r.log().Warn("photos: turning Immich's password sign-in off again", "err", err)
		}
	}, nil
}

// ensureFamilyAccount makes the family account and its partner-only key.
// The account is the one whose id HardyOS recorded, never one found by its
// address.
func (r *Reconciler) ensureFamilyAccount(ctx context.Context, admin *Immich, acct *Account, name string) error {
	users, err := admin.Users(ctx)
	if err != nil {
		return err
	}
	var fam *User
	for i := range users {
		if acct.FamilyUserID != "" && users[i].ID == acct.FamilyUserID {
			fam = &users[i]
		}
	}
	if fam != nil && fam.DeletedAt != "" {
		if err := admin.RestoreUser(ctx, fam.ID); err != nil {
			return fmt.Errorf("restoring the family account in Immich: %w", err)
		}
	}
	if fam != nil && acct.FamilyPassword == "" {
		fam = nil
	}
	// Another account with the family address (someone made it in Immich)
	// is moved aside: HardyOS signs in to the family account by address.
	for _, u := range users {
		if strings.EqualFold(u.Email, FamilyEmail) && (fam == nil || u.ID != fam.ID) {
			if err := admin.UpdateUser(ctx, u.ID, map[string]any{"email": unlinkedEmail(u.ID)}); err != nil {
				return fmt.Errorf("moving an account with the family address aside: %w", err)
			}
			r.audit(ctx, "photos.account.unlink", FamilyEmail, "an account HardyOS didn't make had the family account's address; now "+unlinkedEmail(u.ID))
		}
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
		r.audit(ctx, "photos.account.create", FamilyEmail, "the family library's account")
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
	// A new password (and its address back) on the recorded account first,
	// so the sign-in can only reach that account.
	pw := RandomPassword()
	acct.FamilyEmail, acct.FamilyPassword = FamilyEmail, pw
	if err := r.Store.SaveAccount(ctx, *acct); err != nil {
		return err
	}
	if err := admin.UpdateUser(ctx, fam.ID, map[string]any{"email": FamilyEmail, "password": pw}); err != nil {
		return fmt.Errorf("resetting the family account's password: %w", err)
	}
	key, uid, err := r.keyWithPassword(ctx, acct.FamilyEmail, acct.FamilyPassword, "HardyOS family sharing", FamilyKeyPermissions)
	if err == nil && uid != "" && uid != fam.ID {
		return errors.New("signing in to Immich's family account reached another account")
	}
	if err != nil {
		return fmt.Errorf("signing in to Immich's family account: %w", err)
	}
	acct.FamilyKey = key
	return r.Store.SaveAccount(ctx, *acct)
}

// defaultExclusions keep NAS bookkeeping out of every library.
var defaultExclusions = []string{"**/@eaDir/**", "**/._*", "**/#recycle/**", "**/.snapshot/**", "**/.zfs/**"}

// globEscape escapes a path for Immich's exclusion patterns (glob syntax).
func globEscape(p string) string {
	var b strings.Builder
	for _, r := range p {
		if strings.ContainsRune(`\*?[]{}()!@+`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// linkExclusions are the patterns that keep a library's crawl away from
// the share's links that lead out of it, or a reason to refuse the
// library. mount is where the share is in Immich, importPath the
// library's folder in it.
func linkExclusions(p Plan, share, mount, importPath string) ([]string, string) {
	scan := p.Links[share]
	switch {
	case scan == nil:
		why := p.LinkErrors[share]
		if why == "" {
			why = "it wasn't checked"
		}
		return nil, "HardyOS couldn't check the shared folder for links that lead out of it (" + why + "), so the library isn't made"
	case scan.Truncated:
		return nil, "the shared folder is too big to check for links that lead out of it, so the library isn't made"
	case scan.Count > MaxEscapingLinks:
		return nil, fmt.Sprintf("the shared folder has %d links that lead out of it; remove them (or move the photos to a folder without them) and the library is made", scan.Count)
	}
	var out []string
	for _, rel := range scan.Escaping {
		abs := path.Join(mount, rel)
		if abs == importPath || strings.HasPrefix(abs, importPath+"/") {
			e := globEscape(abs)
			out = append(out, e, e+"/**")
		}
	}
	return out, ""
}

// libraries keeps the personal libraries of existing photos and the
// family library, and removes the ones HardyOS made that are no longer
// asked for (or whose owner's sign-in changed).
func (r *Reconciler) libraries(ctx context.Context, p Plan, rs *runState, acct *Account, family bool, st *Status) error {
	admin := rs.admin
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
		key, name, owner, subject, path string
		exclusions                      []string
	}
	var wants []want
	refused := map[string]bool{}
	st.Libraries = []LibraryState{}
	for _, l := range p.Settings.Libraries {
		ls := LibraryState{Key: l.Key(), Name: l.Name, ImportPath: l.ImportPath()}
		problem := func(s string) {
			ls.Problem = s
			st.Libraries = append(st.Libraries, ls)
		}
		if !p.Shares[l.Share] {
			problem("Immich wasn't given a shared folder for " + l.Share + " (App Store > Immich > Settings)")
			continue
		}
		u, err := r.Dir.UserByID(ctx, l.OwnerID)
		if err != nil || u == nil {
			problem("its owner's HardyOS account is gone")
			continue
		}
		ls.Owner = u.IdentityPrincipal()
		prof, err := r.Dir.Profile(ctx, u)
		if err != nil {
			problem(err.Error())
			continue
		}
		hp := rs.bySub[prof.Subject]
		if hp == nil || !hp.may {
			problem(ls.Owner + " may not use Photos (App Store > Immich > Who can use it)")
			continue
		}
		ex, why := linkExclusions(p, l.Share, libraryMounts[l.Share], l.ImportPath())
		if why != "" {
			refused[l.Key()] = true
			problem(why)
			continue
		}
		owner, err := r.person(ctx, p, rs, hp, st)
		if err != nil {
			problem(err.Error())
			continue
		}
		st.Libraries = append(st.Libraries, ls)
		wants = append(wants, want{key: l.Key(), name: l.Name, owner: owner, subject: prof.Subject, path: l.ImportPath(), exclusions: ex})
	}
	if family && acct.FamilyUserID != "" {
		if ex, why := linkExclusions(p, FamilyShare, FamilyMount, FamilyMount); why != "" {
			refused[FamilyKey] = true
			st.Family.Problem = why
		} else {
			wants = append(wants, want{key: FamilyKey, name: p.Settings.Family.Name, owner: acct.FamilyUserID, path: FamilyMount, exclusions: ex})
		}
	}
	kept := map[string]bool{}
	for _, w := range wants {
		kept[w.key] = true
		exclusions := append(slices.Clone(defaultExclusions), w.exclusions...)
		rec, ok := recs[w.key]
		lib, exists := byID[rec.ImmichID]
		id := ""
		switch {
		case ok && exists && lib.OwnerID == w.owner && rec.Subject == w.subject:
			id = lib.ID
			if lib.Name != w.name || !slices.Equal(lib.ImportPaths, []string{w.path}) || !sameSet(lib.ExclusionPatterns, exclusions) {
				if err := admin.UpdateLibrary(ctx, lib.ID, w.name, []string{w.path}, exclusions); err != nil {
					r.noteLibrary(st, w.key, err.Error())
					continue
				}
				_ = admin.ScanLibrary(ctx, lib.ID)
			}
		default:
			if ok && exists {
				// Its owner (or the person behind the owner's account)
				// changed: the old one goes (Immich can't move a library to
				// another account).
				if err := admin.DeleteLibrary(ctx, lib.ID); err != nil {
					r.noteLibrary(st, w.key, err.Error())
					continue
				}
				st.Notes = append(st.Notes, "Removed the library "+lib.Name+" from its previous owner")
			}
			nl, err := admin.CreateLibrary(ctx, w.owner, w.name, []string{w.path}, exclusions)
			if err != nil {
				r.noteLibrary(st, w.key, err.Error())
				continue
			}
			id = nl.ID
			if err := r.Store.SaveLibrary(ctx, LibRecord{Key: w.key, ImmichID: nl.ID, OwnerID: w.owner, ImportPath: w.path, Subject: w.subject}); err != nil {
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
			if refused[key] {
				st.Notes = append(st.Notes, "Removed the library for "+rec.ImportPath+" until its shared folder can be checked")
			} else {
				st.Notes = append(st.Notes, "Removed the library for "+rec.ImportPath+" (its files stay where they are)")
			}
		}
		if err := r.Store.ForgetLibrary(ctx, key); err != nil {
			return err
		}
	}
	return nil
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
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

// partners shares the family account with each Immich account (signed in
// with HardyOS, or made by HardyOS for someone) whose person may use Immich
// and is a family member, and stops sharing with those HardyOS added that
// no longer are.
func (r *Reconciler) partners(ctx context.Context, p Plan, rs *runState, acct *Account, family bool, st *Status) error {
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
		for sub, id := range rs.accounts {
			hp := rs.bySub[sub]
			if hp == nil || !hp.may {
				continue
			}
			if len(p.Settings.Family.Members) > 0 && !memberOf(p.Settings.Family.Members, hp.u) {
				continue
			}
			want[id] = true
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
		r.audit(ctx, "photos.family.share", emailOf(rs, id), "the family library is shared with them")
	}
	for id := range mine {
		if want[id] {
			continue
		}
		if shared[id] {
			if err := fc.RemovePartner(ctx, id); err != nil && !IsStatus(err, http.StatusNotFound) && !IsStatus(err, http.StatusBadRequest) {
				return fmt.Errorf("stopping family sharing: %w", err)
			}
			r.audit(ctx, "photos.family.unshare", emailOf(rs, id), "the family library is no longer shared with them")
		}
		if err := r.Store.ForgetPartner(ctx, id); err != nil {
			return err
		}
	}
	st.Family.Members = len(want)
	return nil
}

func emailOf(rs *runState, id string) string {
	for _, u := range rs.users {
		if u.ID == id {
			return u.Email
		}
	}
	return id
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

// people lists Immich's accounts other than HardyOS's own, with what
// HardyOS did about each.
func (r *Reconciler) people(rs *runState, st *Status) {
	st.People = []PersonState{}
	subOf := map[string]string{}
	for sub, id := range rs.accounts {
		subOf[id] = sub
	}
	for _, u := range rs.users {
		if rs.service[u.ID] || (u.DeletedAt != "" && rs.flags[u.ID] == "" && !rs.recs[u.ID].Suspended) {
			continue
		}
		ps := PersonState{Email: u.Email, ImmichID: u.ID, Linked: u.OAuthID != "", Flag: rs.flags[u.ID]}
		if rs.recs[u.ID].Suspended && ps.Flag == "" {
			ps.Flag = "suspended"
		}
		if hp := rs.bySub[subOf[u.ID]]; hp != nil {
			ps.Username = hp.u.IdentityPrincipal()
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
	acct.AdminEmail, acct.AdminPassword, acct.AdminKey, acct.Linked, acct.AdminUserID = me.Email, "", key, true, me.ID
	return r.Store.SaveAccount(ctx, acct)
}
