package apps

import (
	"strings"
	"testing"
)

// Decision 302: only the webmail app may have the webmail network, where
// hardyd's mail sign-in accepts webmail tokens.
func TestPolicyKeepsWebmailSubnet(t *testing.T) {
	m := testMF(t, "")
	net := func(project, subnet string) string {
		return `,"networks":{"default":{"name":"` + project + `_default","ipam":{"config":[{"subnet":"` + subnet + `"}]}}}`
	}
	r := resolved(t, `"networks":{"default":null}`, net("hardyos-notes", "172.16.253.0/24"))
	if err := r.Check(m, "hardyos-notes", dataDir, ports); err == nil || !strings.Contains(err.Error(), "kept for the webmail app") {
		t.Fatalf("another app took the webmail network: %v", err)
	}
	r = resolved(t, `"networks":{"default":null}`, net("hardyos-notes", "172.30.9.0/24"))
	if err := r.Check(m, "hardyos-notes", dataDir, ports); err != nil {
		t.Fatalf("an ordinary subnet: %v", err)
	}
	r = resolved(t, `"networks":{"default":null}`, net("hardyos-roundcube", "172.16.253.0/28"))
	if err := r.check(m, ProjectName(WebmailAppID), dataDir, ports, nil, true); err != nil && strings.Contains(err.Error(), "kept for the webmail") {
		t.Fatalf("the catalog's webmail app can't have its network: %v", err)
	}
	// An uploaded app calling itself roundcube can't.
	r = resolved(t, `"networks":{"default":null}`, net("hardyos-roundcube", "172.16.253.0/28"))
	if err := r.check(m, ProjectName(WebmailAppID), dataDir, ports, nil, false); err == nil || !strings.Contains(err.Error(), "kept for the webmail") {
		t.Fatalf("an uploaded roundcube took the webmail network: %v", err)
	}
}
