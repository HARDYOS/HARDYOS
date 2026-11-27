package sftp

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// ---- PAM -------------------------------------------------------------------

const (
	pamBegin = "# BEGIN HardyOS SFTP"
	pamEnd   = "# END HardyOS SFTP"
)

// Failed-password lockout for domain accounts over SFTP (pam_faillock, per
// account name as typed): FaillockDeny wrong passwords lock the name for
// FaillockUnlock seconds, without asking the domain controller again.
const (
	FaillockDeny   = 10
	FaillockUnlock = 900
)

var (
	includeAuthRE    = regexp.MustCompile(`^\s*@include\s+common-auth\s*$`)
	includeAccountRE = regexp.MustCompile(`^\s*@include\s+common-account\s*$`)
	includeSessionRE = regexp.MustCompile(`^\s*@include\s+common-session\s*$`)
)

// pamCond selects domain accounts by user ID: anything else skips the
// whole block and goes on to the usual stack (pam_unix).
var pamCond = fmt.Sprintf("pam_succeed_if.so quiet uid >= %d uid <= %d", DomainUIDLow, DomainUIDHigh)

// pamMember: only accounts in hardyos-sftp (they have a view) go on to
// winbind. Everyone else fails here, before the domain controller is asked:
// sshd hands PAM a deliberately wrong password for accounts AllowGroups
// refuses, and that must not count towards their lockout in the domain.
var pamMember = "pam_succeed_if.so quiet user ingroup " + Group

var faillockArgs = fmt.Sprintf("deny=%d unlock_time=%d", FaillockDeny, FaillockUnlock)

// PAMHelper is what pam_exec runs: `hardyctl pam-sftp <op>` asks hardyd
// over its local SFTP sign-in socket (internal/sftpauth).
const PAMHelper = "/usr/bin/hardyctl"

// pamHelper is a pam_exec module line for op; withPassword hands it the
// typed password on stdin (only the app op).
func pamHelper(helper, op string, withPassword bool) string {
	args := "pam_exec.so quiet "
	if withPassword {
		args += "expose_authtok "
	}
	return args + helper + " pam-sftp " + op
}

// pamBlock is one of HardyOS's blocks. Jumps (default=N) count the lines
// after the condition, so each block is self-contained and never jumps
// over an @include (whose length PAM decides).
func pamBlock(kind string) []string { return pamBlockWith(kind, PAMHelper) }

// pamBlockWith is pamBlock with another helper (tests).
func pamBlockWith(kind, helper string) []string {
	head := pamBegin + ": domain accounts sign in to SFTP with their domain password (docs/file-sharing.md)"
	switch kind {
	case "auth":
		// hardyd decides with WebDAV's rule (decisions 445, 514): an app
		// password with the sftp scope always works (straight to
		// authsucc); the domain password only when hardyd says it may be
		// used from where the sign-in comes, asked before winbind sees it
		// and again after winbind said yes. Wrong ones are recorded.
		return []string{head,
			"auth\t[success=ignore default=10]\t" + pamCond,
			"auth\t[success=ignore default=die]\t" + pamMember,
			"auth\t[success=ignore default=die]\tpam_faillock.so preauth silent " + faillockArgs,
			"auth\t[success=6 default=ignore]\t" + pamHelper(helper, "app", true),
			"auth\t[success=ignore default=die]\t" + pamHelper(helper, "own", false),
			"auth\t[success=ignore default=2]\tpam_winbind.so try_first_pass",
			"auth\t[success=ignore default=die]\t" + pamHelper(helper, "after", false),
			"auth\t[success=2 default=die]\tpam_permit.so",
			"auth\t[default=ignore]\t" + pamHelper(helper, "fail", false),
			"auth\t[default=die]\tpam_faillock.so authfail " + faillockArgs,
			"auth\t[success=done default=die]\tpam_faillock.so authsucc " + faillockArgs,
			pamEnd}
	case "account":
		return []string{head,
			"account\t[success=ignore default=2]\t" + pamCond,
			"account\t[success=ignore default=die]\t" + pamMember,
			"account\t[success=done default=die]\tpam_winbind.so",
			pamEnd}
	default:
		// Domain accounts never run common-session: its pam_systemd would
		// start user@.service, a systemd --user outside the chroot that
		// runs the person's own ~/.config/systemd/user units.
		return []string{head,
			"session\t[success=ignore default=2]\t" + pamCond,
			"session\trequired\tpam_limits.so",
			"session\t[success=done default=die]\tpam_permit.so",
			pamEnd}
	}
}

// ErrPAMLayout: /etc/pam.d/sshd doesn't include common-auth,
// common-account and common-session the way Debian's does, so HardyOS
// can't place its lines.
var ErrPAMLayout = fmt.Errorf("the SSH server's PAM settings (%s) were changed by hand: they don't @include common-auth, common-account and common-session, so SFTP sign-in can't be added", PAMFile)

// EditPAM takes HardyOS's blocks out of an sshd PAM file and, with on, puts
// them back in front of the common-auth, common-account and common-session
// includes. A domain account in hardyos-sftp then signs in with an app
// password hardyd accepts, or with its domain password where hardyd allows
// it, checked by winbind (wrong = denied, too many wrong = locked for a
// while); its account state too (turned off,
// expired, a password that must be changed = denied); and its session
// skips common-session. Everyone else's path is unchanged.
func EditPAM(text string, on bool) (string, error) { return EditPAMWith(text, on, PAMHelper) }

// helperRE: an absolute path without spaces (a PAM line is split on them).
var helperRE = regexp.MustCompile(`^/[A-Za-z0-9._/+-]+$`)

// EditPAMWith is EditPAM with helper in place of PAMHelper (tests run a
// stand-in).
func EditPAMWith(text string, on bool, helper string) (string, error) {
	if !helperRE.MatchString(helper) || strings.Contains(helper, "..") {
		return "", fmt.Errorf("the PAM helper %q isn't an absolute path", helper)
	}
	lines := strings.Split(text, "\n")
	var kept []string
	skip := false
	for _, l := range lines {
		switch {
		case strings.HasPrefix(strings.TrimSpace(l), pamBegin):
			skip = true
			continue
		case skip && strings.TrimSpace(l) == pamEnd:
			skip = false
			continue
		case skip:
			continue
		}
		kept = append(kept, l)
	}
	if !on {
		return strings.Join(kept, "\n"), nil
	}
	var out []string
	auth, account, session := false, false, false
	for _, l := range kept {
		if !auth && includeAuthRE.MatchString(l) {
			out = append(out, pamBlockWith("auth", helper)...)
			auth = true
		}
		if !account && includeAccountRE.MatchString(l) {
			out = append(out, pamBlock("account")...)
			account = true
		}
		if !session && includeSessionRE.MatchString(l) {
			out = append(out, pamBlock("session")...)
			session = true
		}
		out = append(out, l)
	}
	if !auth || !account || !session {
		return "", ErrPAMLayout
	}
	return strings.Join(out, "\n"), nil
}

// pamModule returns the module a PAM line uses and its type ("auth",
// "session", ...), or "" for comments, blank lines and @include.
func pamModule(l string) (typ, module string) {
	l = strings.TrimSpace(l)
	if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "@") {
		return "", ""
	}
	i := strings.IndexAny(l, " \t")
	if i < 0 {
		return "", ""
	}
	typ = strings.TrimPrefix(l[:i], "-")
	rest := strings.TrimSpace(l[i:])
	// The control: a word or a [bracketed list].
	var f []string
	if strings.HasPrefix(rest, "[") {
		j := strings.IndexByte(rest, ']')
		if j < 0 {
			return typ, ""
		}
		f = strings.Fields(rest[j+1:])
	} else if f = strings.Fields(rest); len(f) > 0 {
		f = f[1:]
	}
	if len(f) == 0 {
		return typ, ""
	}
	return typ, filepath.Base(f[0])
}

// ErrPAMSession: something in sshd's session stack would run for a domain
// account before HardyOS's session block takes over.
type ErrPAMSession struct{ Msg string }

func (e *ErrPAMSession) Error() string { return e.Msg }

// CheckPAMSession checks an sshd PAM file that has HardyOS's blocks: no
// session line a domain account still reaches before the session block
// (directly or through an @include) may use pam_systemd, and the block
// must be there. read returns an included file's text (nil: not found).
func CheckPAMSession(text string, read func(name string) ([]byte, error)) error {
	begun := false
	var check func(text, where string, depth int) error
	check = func(text, where string, depth int) error {
		for _, l := range strings.Split(text, "\n") {
			t := strings.TrimSpace(l)
			// HardyOS's session block ends the part a domain account goes
			// through.
			if depth == 0 && t == "session\t[success=ignore default=2]\t"+pamCond {
				begun = true
				return nil
			}
			if strings.HasPrefix(t, "@include") {
				f := strings.Fields(t)
				if len(f) != 2 || depth > 3 {
					continue
				}
				b, err := read(f[1])
				if err != nil {
					continue
				}
				if err := check(string(b), f[1], depth+1); err != nil {
					return err
				}
				continue
			}
			typ, mod := pamModule(t)
			if typ == "session" && mod == "pam_systemd.so" {
				return &ErrPAMSession{Msg: fmt.Sprintf("pam_systemd is in the SSH server's session stack (%s) ahead of HardyOS's lines; it would start a systemd user manager for domain accounts outside their SFTP view", where)}
			}
		}
		return nil
	}
	if err := check(text, PAMFile, 0); err != nil {
		return err
	}
	if !begun {
		return &ErrPAMSession{Msg: "HardyOS's session lines are missing from " + PAMFile}
	}
	return nil
}

// WinbindEverywhere reports whether a system-wide PAM stack (common-auth)
// uses winbind: then domain accounts could sign in to the console too.
func WinbindEverywhere(commonAuth string) bool {
	for _, l := range strings.Split(commonAuth, "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "#") && strings.Contains(l, "pam_winbind") {
			return true
		}
	}
	return false
}

// validNSSName: what an account name from winbind may look like before it
// goes into /etc/group (HOME\alice; no commas, colons or spaces).
var validNSSName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,14}\\[A-Za-z0-9][A-Za-z0-9._$-]{0,63}$`)

// ValidNSSName reports whether n can be listed in the hardyos-sftp group.
func ValidNSSName(n string) bool { return validNSSName.MatchString(n) }
