package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/router"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Two-factor sign-in from the console (decisions 441, 443).

// settingFirstBootCode is when the first-boot setup code was shown (it's
// shown once).
const settingFirstBootCode = "auth.mfa.first_boot_code"

func openDB(ctx context.Context, dbPath string) (*store.DB, error) {
	db, err := store.Open(ctx, dbPath)
	if err != nil {
		return nil, fmt.Errorf("open %s (run as root?): %w", dbPath, err)
	}
	return db, nil
}

// setupCode makes a one-time setup code for an account: with it and the
// password, the account sets up an authenticator from outside (24 hours,
// once; it replaces an earlier one).
func setupCode(dbPath string, args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("expected exactly one username")
	}
	ctx := context.Background()
	db, err := openDB(ctx, dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	u, err := (&auth.Users{DB: db}).GetByName(ctx, args[0])
	if err != nil {
		return fmt.Errorf("user %q: %w", args[0], err)
	}
	m := &auth.MFA{DB: db}
	if on, err := m.Enabled(ctx, u.ID); err != nil {
		return err
	} else if on {
		return fmt.Errorf("%q already has an authenticator (reset-2fa removes it)", u.Username)
	}
	code, until, err := m.IssueSetupCode(ctx, u.ID)
	if err != nil {
		return err
	}
	_ = (&audit.Log{DB: db}).Record(ctx, audit.Entry{Actor: "hardyctl@" + hostname(), Action: "recovery.2fa_setup_code", Target: u.Username, Outcome: audit.Success,
		Detail: "one-time setup code issued on the console"})
	fmt.Fprintf(out, "Setup code for %q (once, until %s):\n\n    %s\n\nSign in with the password, then enter this code to set up an authenticator.\n",
		u.Username, until.Local().Format("2006-01-02 15:04"), code)
	return nil
}

// firstBootCode runs once at boot (hardyos-setup-code.service): on the
// first boot of a new server with exactly one administrator and no
// authenticator yet, it issues a setup code and writes it for the console
// login screen, so the owner can finish setting up from anywhere, NAT or
// not (re-review HIGH 1). Later boots only clear the screen of it.
func firstBootCode(dbPath, issue string, out io.Writer) error {
	ctx := context.Background()
	db, err := openDB(ctx, dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	clear := func() error {
		if issue == "" {
			return nil
		}
		if err := os.Remove(issue); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if _, err := db.GetSetting(ctx, settingFirstBootCode); err == nil {
		return clear() // shown once already
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	users, err := (&auth.Users{DB: db}).List(ctx)
	if err != nil {
		return err
	}
	var admins []*auth.User
	for _, u := range users {
		if u.Role == auth.RoleAdmin && !u.Disabled {
			admins = append(admins, u)
		}
	}
	if len(admins) != 1 {
		// None yet (set up in the browser later: then an administrator
		// issues codes) or several: nothing to show.
		return clear()
	}
	u := admins[0]
	m := &auth.MFA{DB: db}
	if on, err := m.Enabled(ctx, u.ID); err != nil || on {
		_ = db.SetSetting(ctx, settingFirstBootCode, store.Now())
		if err != nil {
			return err
		}
		return clear()
	}
	code, until, err := m.IssueSetupCode(ctx, u.ID)
	if err != nil {
		return err
	}
	if err := db.SetSetting(ctx, settingFirstBootCode, store.Now()); err != nil {
		return err
	}
	_ = (&audit.Log{DB: db}).Record(ctx, audit.Entry{Actor: "hardyctl@" + hostname(), Action: "recovery.2fa_setup_code", Target: u.Username, Outcome: audit.Success,
		Detail: "first boot: one-time setup code shown on the console"})
	text := fmt.Sprintf("  Two-factor setup code for %s (once, until %s):\n\n      %s\n\n"+
		"  Signing in from outside your network asks for it after the password.\n\n",
		u.Username, until.UTC().Format("2006-01-02 15:04 UTC"), code)
	if issue == "" {
		fmt.Fprint(out, text)
		return nil
	}
	// Only on the login screen, never in the journal.
	fmt.Fprintf(out, "A one-time two-factor setup code for %s is on the console login screen.\n", u.Username)

	if err := os.MkdirAll(filepath.Dir(issue), 0o700); err != nil {
		return err
	}
	return os.WriteFile(issue, []byte(text), 0o600)
}

// trustRouter turns "this server is behind NAT: trust the router's
// address" on (for the router as it is now) or off, or shows it.
func trustRouter(dbPath string, args []string, out io.Writer) error {
	if len(args) != 1 || (args[0] != "on" && args[0] != "off" && args[0] != "status") {
		return errors.New("expected on, off or status")
	}
	ctx := context.Background()
	db, err := openDB(ctx, dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	ip, mac := router.Default()
	t := router.Load(ctx, db)
	switch args[0] {
	case "status":
		switch {
		case t == nil:
			fmt.Fprintln(out, "Off: requests from the router's own address count as outside.")
		case t.Matches(ip, mac):
			fmt.Fprintf(out, "On for %s (%s) since %s.\n", t.IP, t.MAC, t.At.Local().Format(time.RFC3339))
		default:
			fmt.Fprintf(out, "Lapsed: turned on for %s (%s); the router is now %s (%s).\n", t.IP, t.MAC, ip, mac)
		}
		return nil
	case "off":
		if err := router.Untrust(ctx, db); err != nil {
			return err
		}
		_ = (&audit.Log{DB: db}).Record(ctx, audit.Entry{Actor: "hardyctl@" + hostname(), Action: "auth.2fa.trust_router", Outcome: audit.Success,
			Detail: "the router's address is no longer trusted"})
		fmt.Fprintln(out, "Off: requests from the router's own address count as outside.")
		return nil
	}
	nt, err := router.Trust(ctx, db, ip, mac, "hardyctl@"+hostname())
	if err != nil {
		return err
	}
	_ = (&audit.Log{DB: db}).Record(ctx, audit.Entry{Actor: "hardyctl@" + hostname(), Action: "auth.2fa.trust_router", Outcome: audit.Success,
		Detail: "this server is behind NAT: the router's address (" + nt.IP + ") is trusted"})
	fmt.Fprintf(out, "On for %s (%s): requests from it count as home for two-factor sign-in. Administrators see a banner while it's on.\n", nt.IP, nt.MAC)
	return nil
}
