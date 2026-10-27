package photos

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/oidc"
)

// Immich links a first OAuth sign-in to the account that has the same
// e-mail address, and lets people change their own address and unlink
// OAuth (HardyOS's proxies refuse those two, decision 285). So that no
// address can lead a sign-in to someone else's account, every sync:
//
//   - gives every address a HardyOS account could sign in with to an
//     account HardyOS made for exactly that account (made ahead of the
//     first sign-in, recorded by subject), and renames any other unlinked
//     account holding one (or any *hardyos.invalid address) to
//     unlinked-<id>@hardyos.invalid, flagged in the status;
//   - puts the address of every linked account back to its HardyOS one;
//   - soft-deletes (restorable) the Immich account of anyone who may no
//     longer use Photos (account gone, turned off, off the access list),
//     restores it when they may again, keeps administrators in step with
//     HardyOS and, while Immich's passwords are off, gives linked accounts
//     new random passwords.

// UnlinkedDomain is where unlinked accounts that held a HardyOS address
// are moved.
const UnlinkedDomain = "hardyos.invalid"

func unlinkedEmail(id string) string { return "unlinked-" + id + "@" + UnlinkedDomain }

// suspendedEmail is a suspended account's address while it's suspended
// (Immich keeps a soft-deleted account's address taken): its person, or a
// new one with the same address, can have a new account meanwhile.
func suspendedEmail(id string) string { return "suspended-" + id + "@" + UnlinkedDomain }

// hardyosAddress: an address in one of HardyOS's .invalid domains.
func hardyosAddress(e string) bool {
	e = strings.ToLower(e)
	return strings.HasSuffix(e, "@hardyos.invalid") || strings.HasSuffix(e, ".hardyos.invalid")
}

// hosPerson is a HardyOS account as Photos sees it.
type hosPerson struct {
	u    *auth.User
	prof *oidc.AppProfile
	may  bool // may use Immich now
}

// runState is what one sync knows about accounts.
type runState struct {
	admin    *Immich
	users    []User
	recs     map[string]AccountRec
	bySub    map[string]*hosPerson
	byEmail  map[string]string // address -> subject ("" when two accounts share it)
	accounts map[string]string // subject -> its live Immich account
	holder   map[string]string // address -> live Immich account holding it
	flags    map[string]string // Immich id -> what HardyOS did about it
	service  map[string]bool   // HardyOS's own Immich accounts
}

func who(u *auth.User) appstore.Who {
	return appstore.Who{Username: u.IdentityPrincipal(), Groups: u.IdentityGroups(), Admin: u.IsAdmin()}
}

func (r *Reconciler) loadPeople(ctx context.Context, p Plan, rs *runState, st *Status) error {
	people, err := r.Dir.People(ctx)
	if err != nil {
		return err
	}
	noAddress := 0
	for _, u := range people {
		prof, err := r.Dir.Profile(ctx, u)
		if err != nil || prof == nil || prof.Email == "" {
			noAddress++
			continue
		}
		hp := &hosPerson{u: u, prof: prof, may: !u.Disabled && appstore.MayUse(p.Access, who(u))}
		rs.bySub[prof.Subject] = hp
		if s, dup := rs.byEmail[prof.Email]; dup && s != prof.Subject {
			rs.byEmail[prof.Email] = ""
			st.Notes = append(st.Notes, "Two HardyOS accounts have the address "+prof.Email+": neither gets an Immich account until one is changed (Users)")
		} else {
			rs.byEmail[prof.Email] = prof.Subject
		}
	}
	if noAddress > 0 {
		st.Notes = append(st.Notes, fmt.Sprintf("%d domain account(s) have no e-mail address, so they can't use Immich", noAddress))
	}
	return nil
}

// guard runs the account rules above. Then rs.accounts maps each subject
// that may use Immich to its account (pre-made ones included, when
// sign-in with HardyOS is on).
func (r *Reconciler) guard(ctx context.Context, p Plan, rs *runState, st *Status) error {
	rotate := p.Wanted.OAuth != nil && !p.Wanted.PasswordLogin
	live := func(u *User) bool { return u.DeletedAt == "" }
	for i := range rs.users {
		u := &rs.users[i]
		if live(u) && !rs.service[u.ID] {
			rs.holder[strings.ToLower(u.Email)] = u.ID
		}
	}

	// Accounts HardyOS suspended whose person may use Immich again.
	for i := range rs.users {
		u := &rs.users[i]
		rec, ok := rs.recs[u.ID]
		if live(u) || !ok || !rec.Suspended {
			continue
		}
		sub := rec.Subject
		if u.OAuthID != "" {
			sub = u.OAuthID
		}
		if hp := rs.bySub[sub]; hp != nil && hp.may && sub == rec.Subject {
			if err := rs.admin.RestoreUser(ctx, u.ID); err != nil {
				st.Notes = append(st.Notes, "Couldn't restore "+u.Email+"'s Immich account: "+err.Error())
				continue
			}
			rec.Suspended = false
			if err := r.Store.SaveAccountRec(ctx, rec); err != nil {
				return err
			}
			u.DeletedAt = ""
			rs.holder[strings.ToLower(u.Email)] = u.ID
			r.audit(ctx, "photos.account.restore", hp.prof.Email, "may use Photos again")
			rs.flags[u.ID] = "restored"
		}
	}

	// 1. Unlinked accounts HardyOS didn't make that hold a HardyOS address.
	for i := range rs.users {
		u := &rs.users[i]
		if !live(u) || rs.service[u.ID] || u.OAuthID != "" || rs.recs[u.ID].Made {
			continue
		}
		e := strings.ToLower(u.Email)
		_, claimed := rs.byEmail[e]
		if !claimed && !hardyosAddress(e) {
			continue
		}
		want := unlinkedEmail(u.ID)
		if e != want {
			if err := rs.admin.UpdateUser(ctx, u.ID, map[string]any{"email": want}); err != nil {
				return fmt.Errorf("moving %s's Immich account aside: %w", u.Email, err)
			}
			delete(rs.holder, e)
			rs.holder[want] = u.ID
			r.audit(ctx, "photos.account.unlink", u.Email, "an Immich account not linked to HardyOS held a HardyOS address; now "+want)
			st.Notes = append(st.Notes, "An Immich account HardyOS didn't make had the address "+u.Email+"; it's now "+want+" (Immich › Administration › Users)")
			u.Email = want
		}
		rs.flags[u.ID] = "held a HardyOS address: renamed"
	}

	suspend := func(u *User, sub, why string) error {
		if u.IsAdmin {
			if err := rs.admin.UpdateUser(ctx, u.ID, map[string]any{"isAdmin": false}); err != nil {
				return err
			}
		}
		if err := rs.admin.UpdateUser(ctx, u.ID, map[string]any{"password": RandomPassword(), "email": suspendedEmail(u.ID)}); err != nil {
			return err
		}
		delete(rs.holder, strings.ToLower(u.Email))
		if err := rs.admin.DeleteUser(ctx, u.ID); err != nil {
			return err
		}
		rec := rs.recs[u.ID]
		rec.ImmichID, rec.Suspended = u.ID, true
		if rec.Subject == "" {
			rec.Subject = sub
		}
		if err := r.Store.SaveAccountRec(ctx, rec); err != nil {
			return err
		}
		rs.recs[u.ID] = rec
		u.DeletedAt = "suspended"
		r.audit(ctx, "photos.account.suspend", u.Email, why)
		st.Notes = append(st.Notes, "Suspended "+u.Email+"'s Immich account: "+why)
		rs.flags[u.ID] = "suspended: " + why
		u.Email = suspendedEmail(u.ID)
		return nil
	}
	// keep puts a person's account in step with their HardyOS account.
	keep := func(u *User, hp *hosPerson) error {
		fields := map[string]any{}
		if want := hp.prof.Email; !strings.EqualFold(u.Email, want) {
			if h := rs.holder[want]; h != "" && h != u.ID {
				st.Notes = append(st.Notes, "Couldn't give "+u.Email+" back the address "+want+": another Immich account has it")
			} else {
				fields["email"] = want
			}
		}
		if u.IsAdmin != hp.prof.Admin {
			fields["isAdmin"] = hp.prof.Admin
		}
		if rotate {
			fields["password"] = RandomPassword()
		}
		if len(fields) == 0 {
			return nil
		}
		if err := rs.admin.UpdateUser(ctx, u.ID, fields); err != nil {
			return fmt.Errorf("updating %s's Immich account: %w", u.Email, err)
		}
		if e, ok := fields["email"].(string); ok {
			r.audit(ctx, "photos.account.email", u.Email, "address set back to "+e)
			delete(rs.holder, strings.ToLower(u.Email))
			rs.holder[e] = u.ID
			u.Email = e
		}
		if a, ok := fields["isAdmin"].(bool); ok {
			r.audit(ctx, "photos.account.role", u.Email, fmt.Sprintf("Immich administrator: %v", a))
			u.IsAdmin = a
		}
		return nil
	}

	// 2. Accounts signed in with HardyOS.
	for i := range rs.users {
		u := &rs.users[i]
		if !live(u) || rs.service[u.ID] || u.OAuthID == "" {
			continue
		}
		rec, ok := rs.recs[u.ID]
		hp := rs.bySub[u.OAuthID]
		var err error
		switch {
		case ok && rec.Made && rec.Subject != u.OAuthID:
			err = suspend(u, u.OAuthID, "made for one HardyOS account but signed in to by another")
		case hp == nil:
			if _, rerr := r.Dir.UserForSubject(ctx, u.OAuthID); rerr != nil {
				err = suspend(u, u.OAuthID, "its HardyOS account is gone or turned off")
			} else {
				err = suspend(u, u.OAuthID, "its HardyOS account has no e-mail address")
			}
		case !hp.may:
			err = suspend(u, u.OAuthID, "its HardyOS account may no longer use Photos")
		case rs.accounts[u.OAuthID] != "":
			err = suspend(u, u.OAuthID, "a second Immich account signed in as the same HardyOS account")
		default:
			rs.accounts[u.OAuthID] = u.ID
			err = keep(u, hp)
		}
		if err != nil {
			return err
		}
	}

	// 3. Accounts HardyOS made that nobody has signed in to yet.
	for i := range rs.users {
		u := &rs.users[i]
		rec, ok := rs.recs[u.ID]
		if !live(u) || !ok || !rec.Made || u.OAuthID != "" {
			continue
		}
		hp := rs.bySub[rec.Subject]
		var err error
		switch {
		case hp == nil || !hp.may:
			err = suspend(u, rec.Subject, "its HardyOS account may no longer use Photos")
		case rs.accounts[rec.Subject] != "":
			err = suspend(u, rec.Subject, "the person signed in to another Immich account")
		default:
			rs.accounts[rec.Subject] = u.ID
			err = keep(u, hp)
		}
		if err != nil {
			return err
		}
	}

	// 4. Everyone else who may use Immich gets an account now, holding
	// their address, ready for their first sign-in.
	if p.Wanted.OAuth == nil {
		return nil
	}
	subs := make([]string, 0, len(rs.bySub))
	for s := range rs.bySub {
		subs = append(subs, s)
	}
	sort.Strings(subs)
	for _, s := range subs {
		hp := rs.bySub[s]
		if !hp.may || rs.accounts[s] != "" || rs.byEmail[hp.prof.Email] != s {
			continue
		}
		if _, err := r.makePerson(ctx, p, rs, hp, st); err != nil {
			st.Notes = append(st.Notes, err.Error())
		}
	}
	return nil
}

// person is the Immich account for someone who may use Immich: theirs, or
// one HardyOS makes now. Accounts are only ever found by subject.
func (r *Reconciler) person(ctx context.Context, p Plan, rs *runState, hp *hosPerson, st *Status) (string, error) {
	if id := rs.accounts[hp.prof.Subject]; id != "" {
		return id, nil
	}
	if rs.byEmail[hp.prof.Email] != hp.prof.Subject {
		return "", fmt.Errorf("another HardyOS account has the address %s", hp.prof.Email)
	}
	return r.makePerson(ctx, p, rs, hp, st)
}

func (r *Reconciler) makePerson(ctx context.Context, p Plan, rs *runState, hp *hosPerson, st *Status) (string, error) {
	prof := hp.prof
	if h := rs.holder[prof.Email]; h != "" {
		return "", fmt.Errorf("can't make %s's Immich account: another Immich account has %s", prof.Name, prof.Email)
	}
	nu := NewUser{Email: prof.Email, Name: prof.Name, Password: RandomPassword(), StorageLabel: prof.StorageLabel, IsAdmin: prof.Admin}
	if q := p.Settings.DefaultQuotaGiB; q > 0 {
		b := int64(q) << 30
		nu.QuotaSizeInBytes = &b
	}
	u, err := rs.admin.CreateUser(ctx, nu)
	if err != nil {
		return "", fmt.Errorf("creating %s's Immich account: %w", prof.Name, err)
	}
	rec := AccountRec{ImmichID: u.ID, Subject: prof.Subject, Made: true}
	if err := r.Store.SaveAccountRec(ctx, rec); err != nil {
		return "", err
	}
	rs.recs[u.ID] = rec
	rs.accounts[prof.Subject] = u.ID
	rs.holder[prof.Email] = u.ID
	rs.users = append(rs.users, *u)
	r.audit(ctx, "photos.account.create", prof.Email, "for "+hp.u.IdentityPrincipal()+", ready for their first sign-in")
	return u.ID, nil
}
