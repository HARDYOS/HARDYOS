package shares

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// Limits.
const (
	MaxNameLen        = 40
	MaxIDLen          = 32
	MaxDescriptionLen = 200
	MaxRules          = 64
	MaxSubfolders     = 32
	MaxFolderLen      = 64
	// ZFS keeps user property values up to 8 KiB.
	maxPropLen = 8000
)

// App user IDs (apps.FirstAppUID..apps.LastAppUID; repeated here so this
// package doesn't depend on the apps engine).
const (
	firstAppUID = 30000
	lastAppUID  = 30999
)

var (
	idRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	nameRE  = regexp.MustCompile(`^[\p{L}\p{N} ._()'&-]+$`)
	appIDRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)
	// NETBIOS\name for domain principals, or a plain HardyOS account name.
	principalRE = regexp.MustCompile(`^(?:[A-Za-z0-9][A-Za-z0-9-]{0,14}\\)?[\p{L}\p{N}][\p{L}\p{N} ._'$-]{0,63}$`)
	folderRE    = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._()'&,+-]*$`)
)

// Names SMB reserves for its own sections; refused now so file sharing can
// use every shared folder as is.
var reservedNames = map[string]bool{"global": true, "homes": true, "printers": true, "print$": true, "ipc$": true}

func invalid(format string, a ...any) error { return &ValidationError{Msg: fmt.Sprintf(format, a...)} }

// ValidID reports whether id can be a shared folder's id.
func ValidID(id string) error {
	if !idRE.MatchString(id) || strings.HasSuffix(id, "-") {
		return invalid("the id %q isn't valid: use 1-32 lowercase letters, digits and dashes, starting with a letter or digit", id)
	}
	if reservedNames[id] {
		return invalid("%q is reserved for file sharing; choose another id", id)
	}
	return nil
}

// CleanName trims a shared folder's name and checks it.
func CleanName(name string) (string, error) {
	n := strings.Join(strings.Fields(name), " ")
	switch {
	case n == "":
		return "", invalid("give the shared folder a name")
	case utf8.RuneCountInString(n) > MaxNameLen:
		return "", invalid("the name is too long: at most %d characters", MaxNameLen)
	case !nameRE.MatchString(n):
		return "", invalid("the name %q can only have letters, digits, spaces and . - _ ( ) ' &", n)
	case !strings.ContainsFunc(n, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }):
		return "", invalid("the name needs at least one letter or digit")
	case reservedNames[strings.ToLower(n)]:
		return "", invalid("%q is reserved for file sharing; choose another name", n)
	}
	return n, nil
}

// DeriveID turns a name into an id: "TV & Movies" -> "tv-movies".
func DeriveID(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		default:
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
		if b.Len() >= MaxIDLen {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}

func cleanDescription(d string) (string, error) {
	d = strings.TrimSpace(d)
	if utf8.RuneCountInString(d) > MaxDescriptionLen {
		return "", invalid("the description is too long: at most %d characters", MaxDescriptionLen)
	}
	if strings.ContainsFunc(d, unicode.IsControl) {
		return "", invalid("the description can't have tabs or line breaks")
	}
	return d, nil
}

// CleanRules checks access rules and returns them tidied (names trimmed,
// "everyone" without a name). An empty list means administrators only.
func CleanRules(rules []Rule) ([]Rule, error) {
	if len(rules) > MaxRules {
		return nil, invalid("too many access rules: at most %d", MaxRules)
	}
	out := make([]Rule, 0, len(rules))
	seen := map[string]bool{}
	for _, r := range rules {
		r.Name = strings.TrimSpace(r.Name)
		switch r.Level {
		case LevelRead, LevelWrite, LevelNone:
		default:
			return nil, invalid("access level %q isn't valid: use read, write or none", r.Level)
		}
		switch r.Kind {
		case KindEveryone:
			r.Name = ""
		case KindUser, KindGroup:
			if r.Name == "" {
				return nil, invalid("an access rule for a %s needs its name", r.Kind)
			}
			if !principalRE.MatchString(r.Name) {
				return nil, invalid("%q isn't a valid %s name (domain accounts are written like HOME\\alice)", r.Name, r.Kind)
			}
		default:
			return nil, invalid("access rule kind %q isn't valid: use user, group or everyone", r.Kind)
		}
		key := r.Kind + "\x00" + strings.ToLower(r.Name)
		if seen[key] {
			if r.Kind == KindEveryone {
				return nil, invalid("there's more than one rule for everyone")
			}
			return nil, invalid("there's more than one rule for %s", r.Name)
		}
		seen[key] = true
		out = append(out, r)
	}
	return out, nil
}

// CleanFolder checks a relative folder path inside a share ("Movies/Kids")
// and returns it cleaned, without leading or trailing slashes; "" is the
// share itself. It never allows going up (..).
func CleanFolder(p string) (string, error) {
	if strings.ContainsRune(p, 0) {
		return "", invalid("the folder path isn't valid")
	}
	p = strings.Trim(p, "/")
	if p == "" {
		return "", nil
	}
	parts := strings.Split(p, "/")
	if len(parts) > 32 || len(p) > 1024 {
		return "", invalid("the folder path is too long")
	}
	for _, s := range parts {
		if s == "" || s == "." || s == ".." {
			return "", invalid("the folder path %q isn't valid: use folder names separated by /", p)
		}
	}
	return path.Clean(p), nil
}

func cleanSubfolder(name string) (string, error) {
	n := strings.TrimSpace(name)
	switch {
	case n == "":
		return "", invalid("a subfolder needs a name")
	case utf8.RuneCountInString(n) > MaxFolderLen:
		return "", invalid("the subfolder name %q is too long: at most %d characters", n, MaxFolderLen)
	case !folderRE.MatchString(n):
		return "", invalid("the subfolder name %q can only have letters, digits, spaces and . - _ ( ) ' & , +", n)
	}
	return n, nil
}

// CheckNew validates a new shared folder and returns it normalized (name
// trimmed, id derived). It doesn't look at the system, so hardyd uses it
// to catch mistakes before starting a job.
func CheckNew(a NewShare) (NewShare, error) {
	if a.Pool == "" {
		return a, invalid("choose a pool for the shared folder")
	}
	if err := zfs.ValidPoolName(a.Pool); err != nil {
		return a, invalid("%v", err)
	}
	name, err := CleanName(a.Name)
	if err != nil {
		return a, err
	}
	a.Name = name
	if a.ID == "" {
		a.ID = DeriveID(name)
		if a.ID == "" {
			return a, invalid("choose a short id for %q (lowercase letters, digits and dashes)", name)
		}
	}
	if err := ValidID(a.ID); err != nil {
		return a, err
	}
	if a.Description, err = cleanDescription(a.Description); err != nil {
		return a, err
	}
	if a.Access, err = CleanRules(a.Access); err != nil {
		return a, err
	}
	if err := checkPropSize(a.Access); err != nil {
		return a, err
	}
	if len(a.Subfolders) > MaxSubfolders {
		return a, invalid("too many subfolders: at most %d", MaxSubfolders)
	}
	seen := map[string]bool{}
	subs := make([]string, 0, len(a.Subfolders))
	for _, s := range a.Subfolders {
		c, err := cleanSubfolder(s)
		if err != nil {
			return a, err
		}
		if seen[strings.ToLower(c)] {
			return a, invalid("the subfolder %q is listed twice", c)
		}
		seen[strings.ToLower(c)] = true
		subs = append(subs, c)
	}
	a.Subfolders = subs
	if a.QuotaBytes != 0 && a.QuotaBytes < minQuota {
		return a, invalid("the quota is too small: at least 1 MB, or 0 for none")
	}
	return a, nil
}

// minQuota is the smallest quota accepted (ZFS refuses tiny ones).
const minQuota = 1 << 20

func checkPropSize(rules []Rule) error {
	if len(mustJSON(rules)) > maxPropLen {
		return invalid("the access rules are too long; use groups instead of many single accounts")
	}
	return nil
}

// ValidAppGrant checks the arguments of GrantApp/RevokeApp.
func ValidAppGrant(app string, uid int) error {
	if !appIDRE.MatchString(app) {
		return invalid("the app id %q isn't valid", app)
	}
	if uid < firstAppUID || uid > lastAppUID {
		return invalid("app user ID %d is outside %d-%d", uid, firstAppUID, lastAppUID)
	}
	return nil
}
