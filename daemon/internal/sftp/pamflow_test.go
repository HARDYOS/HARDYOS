package sftp

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// runAuth walks HardyOS's auth block the way Linux-PAM does for a domain
// account in hardyos-sftp: results says what each module returns
// (true: success), keyed by a word of its line; it returns whether the
// stack succeeded and which modules ran.
func runAuth(t *testing.T, results map[string]bool) (bool, []string) {
	t.Helper()
	body := pamBlock("auth")
	body = body[1 : len(body)-1]
	ctl := regexp.MustCompile(`^auth\t\[([^\]]*)\]\t(.*)$`)
	state := "undef"
	var ran []string
	for i := 0; i < len(body); i++ {
		m := ctl.FindStringSubmatch(body[i])
		if m == nil {
			t.Fatalf("line %q", body[i])
		}
		actions := map[string]string{}
		for _, kv := range strings.Fields(m[1]) {
			k, v, _ := strings.Cut(kv, "=")
			actions[k] = v
		}
		mod := m[2]
		key := mod
		switch {
		case strings.Contains(mod, "pam-sftp "):
			key = "helper " + mod[strings.LastIndex(mod, " ")+1:]
		case strings.Contains(mod, "uid >="):
			key = "uid"
		case strings.Contains(mod, "ingroup"):
			key = "ingroup"
		case strings.Contains(mod, "preauth"):
			key = "preauth"
		case strings.Contains(mod, "authfail"):
			key = "authfail"
		case strings.Contains(mod, "authsucc"):
			key = "authsucc"
		case strings.Contains(mod, "pam_winbind"):
			key = "winbind"
		case strings.Contains(mod, "pam_permit"):
			key = "permit"
		}
		ran = append(ran, key)
		ok, known := results[key]
		if !known {
			ok = key != "authfail" // authfail always fails; the rest succeed unless told
		}
		ret := "fail"
		if ok {
			ret = "success"
		}
		act := actions[ret]
		if act == "" {
			act = actions["default"]
		}
		switch act {
		case "ignore":
		case "die":
			if !ok {
				return false, ran
			}
			state = "success"
		case "done":
			if ok && state != "fail" {
				return true, ran
			}
			return false, ran
		default:
			n, err := strconv.Atoi(act)
			if err != nil {
				t.Fatalf("action %q", act)
			}
			if state == "undef" || state == "success" {
				state = ret
			}
			i += n
		}
	}
	return state == "success", ran
}

func has(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// The SFTP auth block (decision 514): an app password never reaches
// winbind; an own password reaches winbind only when hardyd allows it from
// there, and only signs in if hardyd still allows it afterwards; wrong
// ones are recorded and count in faillock, refused ones don't.
func TestAuthBlockFlow(t *testing.T) {
	for name, c := range map[string]struct {
		results    map[string]bool
		ok         bool
		ran, never []string
	}{
		"app password":                  {map[string]bool{"helper app": true}, true, []string{"authsucc"}, []string{"winbind", "helper own", "authfail"}},
		"own password at home":          {map[string]bool{"helper app": false}, true, []string{"helper own", "winbind", "helper after", "authsucc"}, []string{"authfail", "helper fail"}},
		"own password from outside":     {map[string]bool{"helper app": false, "helper own": false}, false, nil, []string{"winbind", "authfail", "authsucc"}},
		"wrong password at home":        {map[string]bool{"helper app": false, "winbind": false}, false, []string{"helper fail", "authfail"}, []string{"helper after", "authsucc"}},
		"enrolled while winbind looked": {map[string]bool{"helper app": false, "helper after": false}, false, []string{"winbind"}, []string{"authsucc"}},
		"hardyd down":                   {map[string]bool{"helper app": false, "helper own": false, "helper after": false}, false, nil, []string{"winbind"}},
		"locked by faillock":            {map[string]bool{"preauth": false}, false, nil, []string{"helper app", "winbind"}},
		"not in hardyos-sftp":           {map[string]bool{"ingroup": false}, false, nil, []string{"preauth", "helper app", "winbind"}},
	} {
		ok, ran := runAuth(t, c.results)
		if ok != c.ok {
			t.Errorf("%s: signed in %v (ran %v)", name, ok, ran)
		}
		for _, m := range c.ran {
			if !has(ran, m) {
				t.Errorf("%s: %s didn't run (%v)", name, m, ran)
			}
		}
		for _, m := range c.never {
			if has(ran, m) {
				t.Errorf("%s: %s ran (%v)", name, m, ran)
			}
		}
	}
	// Only the app step sees the password.
	for _, l := range pamBlock("auth") {
		if strings.Contains(l, "expose_authtok") != strings.HasSuffix(l, "pam-sftp app") {
			t.Errorf("password handed to %q", l)
		}
	}
}
