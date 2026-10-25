package install

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestNewCode(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c, err := NewCode()
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^[A-HJKMNP-Z2-9]{4}-[A-HJKMNP-Z2-9]{4}$`).MatchString(c) {
			t.Fatalf("code %q has an unexpected shape", c)
		}
		seen[c] = true
	}
	if len(seen) < 199 {
		t.Fatalf("codes repeat: %d unique of 200", len(seen))
	}
}

func TestCodesMatch(t *testing.T) {
	for typed, want := range map[string]bool{
		"K7QM-4TXP": true, "k7qm4txp": true, " k7qm 4txp ": true,
		"K7QM-4TXQ": false, "K7QM": false, "": false,
	} {
		if got := CodesMatch(typed, "K7QM-4TXP"); got != want {
			t.Errorf("CodesMatch(%q) = %v", typed, got)
		}
	}
	if CodesMatch("", "") {
		t.Error("empty codes must not match")
	}
}

func TestPublishCode(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "run/hardyos"), 0o755)
	if err := PublishCode(root, "K7QM-4TXP", -1); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(root, CodeFile))
	if strings.TrimSpace(string(b)) != "K7QM-4TXP" {
		t.Fatalf("code file = %q", b)
	}
	issue, _ := os.ReadFile(filepath.Join(root, "etc/issue.d/50-hardyos-installer.issue"))
	if !strings.Contains(string(issue), "K7QM-4TXP") || strings.Contains(string(issue), `\4`) {
		t.Fatalf("issue = %s", issue)
	}
	if IsLive(root) {
		t.Fatal("not live without the marker")
	}
	_ = os.MkdirAll(filepath.Join(root, "etc/hardyos"), 0o755)
	_ = os.WriteFile(filepath.Join(root, LiveMarker), nil, 0o644)
	if !IsLive(root) {
		t.Fatal("live marker not detected")
	}
}
