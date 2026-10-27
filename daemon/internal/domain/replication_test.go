package domain

import (
	"strings"
	"testing"
)

const showreplTwoDCs = `{
 "repsFrom": [
  {"NC dn": "DC=hardy,DC=home", "DSA objectGUID": "8c3a...", "DSA": "Default-First-Site-Name\\DC2", "last attempt time": "Mon Oct 27 10:00:01 2026 CDT",
   "last attempt message": "WERR_OK", "consecutive failures": 0, "last success": "Mon Oct 27 10:00:01 2026 CDT", "NTDS DN": "CN=NTDS Settings,...", "is deleted": false},
  {"NC dn": "CN=Configuration,DC=hardy,DC=home", "DSA objectGUID": "8c3a...", "DSA": "Default-First-Site-Name\\DC2", "last attempt time": "Mon Oct 27 10:00:01 2026 CDT",
   "last attempt message": "WERR_BADFILE", "consecutive failures": 7, "last success": "Sun Oct 26 22:00:00 2026 CDT", "is deleted": false},
  {"NC dn": "DC=old", "DSA objectGUID": "x", "consecutive failures": 99, "is deleted": true}
 ],
 "repsTo": [], "NTDSConnections": [], "dsa": {"DSA Options": "0x00000001"}
}`

func TestParseShowrepl(t *testing.T) {
	r, err := ParseShowrepl([]byte(showreplTwoDCs))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Checked || len(r.Links) != 2 || len(r.Failing) != 1 {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.Failing[0], `Default-First-Site-Name\DC2 (CN=Configuration,DC=hardy,DC=home): 7 failed attempts`) || !strings.Contains(r.Failing[0], "WERR_BADFILE") {
		t.Errorf("failing %q", r.Failing[0])
	}
	alone, _ := ParseShowrepl([]byte(`{"repsFrom": [], "repsTo": []}`))
	if alone.Checked {
		t.Error("a single DC counted as replicating")
	}
	if _, err := ParseShowrepl([]byte("ERROR")); err == nil {
		t.Error("garbage parsed")
	}
}
