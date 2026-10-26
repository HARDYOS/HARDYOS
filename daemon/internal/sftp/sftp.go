// Package sftp offers the shared folders over SFTP to domain accounts
// (docs/plans/file-sharing.md section 5). It runs in hardyd-priv.
//
// OpenSSH's own sshd does the work: a drop-in under /etc/ssh/sshd_config.d
// turns every domain account (an account whose groups are HOME\...) into an
// SFTP-only account (internal-sftp, no shell, no TTY, no forwarding of any
// kind) locked into its own view, /srv/hardyos/sftp/<uid>. A view is a
// root-owned folder holding bind mounts of the shared folders with SFTP on
// that the person's access rules let in (read-only binds for read access)
// and of their home folder; on disk, the folders' ACLs still decide as the
// person. Domain passwords are checked by pam_winbind, added to sshd's PAM
// stack only (/etc/pam.d/sshd) and only for user IDs in the domain's range;
// local accounts (root, the administrator's own) sign in to SSH as before.
//
// Layout:
//
//	/etc/ssh/sshd_config.d/hardyos-sftp.conf   written by HardyOS, checked with sshd -t
//	/etc/pam.d/sshd                            a marked block for pam_winbind
//	/srv/hardyos/sftp/                         root's, 0755, a private mount
//	  <uid>/                                   one view per domain account with something to see
//	    Media/  Photos/  Home/                 bind mounts
//	group hardyos-sftp                         the domain accounts that have a view (sshd AllowGroups)
package sftp

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/fileworker"
	"github.com/hardyos/hardyos/daemon/internal/shares"
)

// Defaults.
const (
	ViewsRoot = "/srv/hardyos/sftp"
	DropIn    = "/etc/ssh/sshd_config.d/hardyos-sftp.conf"
	PAMFile   = "/etc/pam.d/sshd"
	// CommonAuth is the system-wide PAM stack winbind must stay out of.
	CommonAuth = "/etc/pam.d/common-auth"
	SSHUnit    = "ssh.service"
	// Group lists the domain accounts allowed to sign in (they have a view).
	Group = "hardyos-sftp"
	// HomeName is the home folder's name in a view.
	HomeName = "Home"
)

// Domain user IDs (winbind's rid range, contract section 1). Only these get
// a view and a winbind password check.
const (
	DomainUIDLow  = 100000
	DomainUIDHigh = 999999
)

// User is a domain account that may get a view.
type User struct {
	// Principal: HOME\alice, as the folders' rules name people.
	Principal string
	// Name is the account's name as NSS (winbind) spells it, what sshd and
	// /etc/group see.
	Name   string
	UID    int
	GID    int
	Groups []int
	Admin  bool
	// Home is the home folder's path and HomeDataset its dataset ("" for none).
	Home, HomeDataset string
	// HomeDev is the device of the home folder's verified mount.
	HomeDev uint64
}

// Folder is a shared folder with SFTP on.
type Folder struct {
	ID, Name, Path, Dataset string
	Rules                   []shares.Rule
	// Dev is the device of the folder's verified mount (shares.Share.RootDev).
	Dev uint64
}

// Bind is one bind mount in a view.
type Bind struct {
	UID int
	// Name is the folder's name in the view.
	Name string
	// Share is the shared folder's id, or fileworker.HomeShare.
	Share   string
	Source  string
	Dataset string
	// Dev is the device of Source's verified mount; the bind is only made
	// from a descriptor opened with shares.OpenRoot on it.
	Dev uint64
	// ReadOnly: the person may only read the folder.
	ReadOnly bool
}

// Rel is the bind's path below the views' root.
func (b Bind) Rel() string { return strconv.Itoa(b.UID) + "/" + b.Name }

// viewName makes a folder name usable as one path component.
func viewName(n string) string {
	n = strings.TrimSpace(n)
	if n == "" || n == "." || n == ".." || strings.ContainsAny(n, "/\x00\n") || len(n) > 255 {
		return ""
	}
	return n
}

// Plan works out every view: for each user, the folders their rules let in
// (fileworker.Level, the File Manager's rule: "none" wins, otherwise the
// highest matching level, administrators everything) and their home. groupID
// maps a rule's group name (HOME\Family) to its Linux group ID; groups it
// doesn't know never match.
func Plan(users []User, folders []Folder, groupID func(name string) (int, bool)) []Bind {
	sorted := append([]Folder(nil), folders...)
	sort.Slice(sorted, func(i, j int) bool { return strings.ToLower(sorted[i].Name) < strings.ToLower(sorted[j].Name) })
	var out []Bind
	for _, u := range users {
		if u.UID < DomainUIDLow || u.UID > DomainUIDHigh {
			continue
		}
		member := map[int]bool{u.GID: true}
		for _, g := range u.Groups {
			member[g] = true
		}
		taken := map[string]bool{}
		if u.Home != "" {
			taken[strings.ToLower(HomeName)] = true
			out = append(out, Bind{UID: u.UID, Name: HomeName, Share: fileworker.HomeShare, Source: u.Home, Dataset: u.HomeDataset, Dev: u.HomeDev})
		}
		for _, f := range sorted {
			name := viewName(f.Name)
			if name == "" || f.Path == "" {
				continue
			}
			if taken[strings.ToLower(name)] {
				name = name + " (shared folder)"
				if taken[strings.ToLower(name)] {
					continue
				}
			}
			who := fileworker.Who{Principal: u.Principal, Admin: u.Admin}
			for _, r := range f.Rules {
				if r.Kind != shares.KindGroup {
					continue
				}
				if gid, ok := groupID(strings.TrimSpace(r.Name)); ok && member[gid] {
					who.Groups = append(who.Groups, strings.TrimSpace(r.Name))
				}
			}
			level := fileworker.Level(f.Rules, who)
			if level == shares.LevelNone {
				continue
			}
			taken[strings.ToLower(name)] = true
			out = append(out, Bind{UID: u.UID, Name: name, Share: f.ID, Source: f.Path, Dataset: f.Dataset, Dev: f.Dev, ReadOnly: level != shares.LevelWrite})
		}
	}
	return out
}

// ---- sshd ------------------------------------------------------------------

// sshdSettings are what every domain account gets. Each is allowed in a
// Match block (checked by sshd -t before the file is used).
func sshdSettings(root string) []string {
	return []string{
		"AllowGroups " + Group,
		"ChrootDirectory " + root + "/%U",
		"ForceCommand internal-sftp -d /",
		"DisableForwarding yes",
		"AllowTcpForwarding no",
		"AllowAgentForwarding no",
		"AllowStreamLocalForwarding no",
		"X11Forwarding no",
		"PermitTunnel no",
		"PermitListen none",
		"PermitOpen none",
		"GatewayPorts no",
		"PermitTTY no",
		"PermitUserRC no",
		// Only the domain password: no keys a person could leave in their
		// home folder, so turning an account off or changing its password
		// always locks it out.
		"PubkeyAuthentication no",
		"AuthorizedKeysFile none",
		"PasswordAuthentication yes",
		"KbdInteractiveAuthentication no",
		"AuthenticationMethods password",
	}
}

// RenderSSHD is the drop-in. Domain accounts are recognised two ways, so a
// name spelled differently can't slip past: by their groups (winbind names
// every domain group HOME\..., local groups never contain a backslash) and
// by the name typed (HOME\alice, alice@home.example.net). Patterns use no
// quoting or escapes, which sshd's Match parsers treat differently between
// versions. "Match all" ends the blocks, whatever follows the Include.
// With on false, domain accounts are refused outright.
func RenderSSHD(root string, on bool) string {
	var b strings.Builder
	b.WriteString("# Written by HardyOS (Control Panel > File Services > SFTP): changes here are replaced.\n")
	b.WriteString("# Domain accounts may only use SFTP, each inside its own view of the shared\n")
	b.WriteString("# folders. Local accounts (root and other Linux accounts) are not affected.\n")
	settings := []string{"DenyGroups *", "DisableForwarding yes", "PermitTTY no", "ForceCommand internal-sftp -d /", "ChrootDirectory /nonexistent"}
	if on {
		settings = sshdSettings(root)
	} else {
		b.WriteString("# SFTP is off: domain accounts can't sign in over SSH.\n")
	}
	for _, m := range []string{`Match Group *\*`, `Match User *\*,*@*`} {
		b.WriteString(m + "\n")
		for _, s := range settings {
			b.WriteString("\t" + s + "\n")
		}
	}
	b.WriteString("Match all\n")
	return b.String()
}

// ---- PAM -------------------------------------------------------------------

const (
	pamBegin = "# BEGIN HardyOS SFTP"
	pamEnd   = "# END HardyOS SFTP"
)

var (
	includeAuthRE    = regexp.MustCompile(`^\s*@include\s+common-auth\s*$`)
	includeAccountRE = regexp.MustCompile(`^\s*@include\s+common-account\s*$`)
)

// pamCond selects domain accounts by user ID: anything else skips the
// winbind line and goes on to the usual stack (pam_unix).
var pamCond = fmt.Sprintf("pam_succeed_if.so quiet uid >= %d uid <= %d", DomainUIDLow, DomainUIDHigh)

func pamBlock(kind string) []string {
	head := pamBegin + ": domain accounts sign in to SFTP with their domain password (docs/file-sharing.md)"
	switch kind {
	case "auth":
		return []string{head,
			"auth\t[success=ignore default=1]\t" + pamCond,
			"auth\t[success=done default=die]\tpam_winbind.so",
			pamEnd}
	default:
		return []string{head,
			"account\t[success=ignore default=1]\t" + pamCond,
			"account\t[success=done default=die]\tpam_winbind.so",
			pamEnd}
	}
}

// ErrPAMLayout: /etc/pam.d/sshd doesn't include common-auth and
// common-account the way Debian's does, so HardyOS can't place its lines.
var ErrPAMLayout = fmt.Errorf("the SSH server's PAM settings (%s) were changed by hand: they don't @include common-auth and common-account, so SFTP sign-in can't be added", PAMFile)

// EditPAM takes HardyOS's blocks out of an sshd PAM file and, with on, puts
// them back in front of the common-auth and common-account includes. A
// domain account's password is then checked by winbind and nothing else
// (wrong = denied), its account state too (turned off, expired, a password
// that must be changed = denied). Everyone else's path is unchanged.
func EditPAM(text string, on bool) (string, error) {
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
	auth, account := false, false
	for _, l := range kept {
		if !auth && includeAuthRE.MatchString(l) {
			out = append(out, pamBlock("auth")...)
			auth = true
		}
		if !account && includeAccountRE.MatchString(l) {
			out = append(out, pamBlock("account")...)
			account = true
		}
		out = append(out, l)
	}
	if !auth || !account {
		return "", ErrPAMLayout
	}
	return strings.Join(out, "\n"), nil
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
