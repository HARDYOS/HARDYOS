package sftp

import (
	"fmt"
	"sort"
	"strings"
)

// EffectiveArgs is the sshd -T call that shows the settings a domain
// account really gets: user is a real account name NSS knows (so sshd
// sees its groups and "Match Group" applies as at sign-in).
func EffectiveArgs(user string) []string {
	return []string{"-T", "-C", "user=" + user + ",host=x,addr=127.0.0.1"}
}

// CheckEffective checks sshd -T output for a domain account against what
// the drop-in sets. Anything missing or different (another file or the
// main config overriding it, the drop-in not included at all) is an error,
// and SFTP sign-in stays off.
func CheckEffective(out, root string) error {
	got := map[string][]string{}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		k, v, _ := strings.Cut(l, " ")
		k, v = strings.ToLower(k), strings.TrimSpace(v)
		// A list (AllowGroups) is printed once per entry; both of the
		// drop-in's Match blocks apply to an account matched by group and by
		// name, so the same entry can come twice.
		dup := false
		for _, x := range got[k] {
			dup = dup || x == v
		}
		if !dup {
			got[k] = append(got[k], v)
		}
	}
	want := []struct{ key, value string }{
		{"forcecommand", "internal-sftp -d / -P symlink,hardlink"},
		{"chrootdirectory", root + "/%U"},
		{"disableforwarding", "yes"},
		{"allowgroups", Group},
		{"authenticationmethods", "password"},
		{"pubkeyauthentication", "no"},
		{"permittty", "no"},
		{"allowtcpforwarding", "no"},
		{"allowagentforwarding", "no"},
		{"x11forwarding", "no"},
		{"permittunnel", "no"},
	}
	var bad []string
	for _, w := range want {
		vals := got[w.key]
		if len(vals) != 1 || vals[0] != w.value {
			have := "nothing"
			if len(vals) > 0 {
				have = strings.Join(vals, ", ")
			}
			bad = append(bad, fmt.Sprintf("%s is %s, not %s", w.key, have, w.value))
		}
	}
	if len(bad) == 0 {
		return nil
	}
	sort.Strings(bad)
	hint := ""
	if v := got["forcecommand"]; len(v) == 0 || v[0] == "none" {
		hint = " (is " + DropIn + " included? /etc/ssh/sshd_config needs \"Include /etc/ssh/sshd_config.d/*.conf\" at its top)"
	}
	return fmt.Errorf("the SSH server doesn't apply HardyOS's SFTP settings to domain accounts%s: %s", hint, strings.Join(bad, "; "))
}
