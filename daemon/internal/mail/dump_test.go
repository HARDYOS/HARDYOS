package mail

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDumpRender writes a sample configuration under
// $HARDYOS_MAIL_RENDER_DIR (for checking it with the real programs by
// hand); skipped otherwise.
func TestDumpRender(t *testing.T) {
	dir := os.Getenv("HARDYOS_MAIL_RENDER_DIR")
	if dir == "" {
		t.Skip("HARDYOS_MAIL_RENDER_DIR not set")
	}
	cfg, err := sampleConfig().Normalize(sampleSecrets())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range Render(cfg, sampleSecrets(), sampleEnv()) {
		p := filepath.Join(dir, f.Path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(f.Content), os.FileMode(f.Mode)); err != nil {
			t.Fatal(err)
		}
	}
}

func sampleConfig() RootConfig {
	return RootConfig{
		Pool: "tank", Hostname: "mail.example.net", VPSPeer: "100.90.1.2",
		Domains: []RootDomain{{Name: "example.net", Selector: "hardyos1"}, {Name: "family.example", Selector: "hardyos1"}},
		Mailboxes: []RootMailbox{
			{Address: "alice@example.net", Aliases: []string{"mom@example.net", "alice@family.example"}, QuotaMB: 2048},
			{Address: "bob@example.net", QuotaMB: 0},
		},
		GroupAliases: []RootGroupAlias{{Address: "family@example.net", Targets: []string{"alice@example.net", "bob@example.net"}}},
		Postmaster:   "alice@example.net",
		SES:          &RootSES{Host: "email-smtp.us-east-1.amazonaws.com", Port: 587, Username: "AKIAEXAMPLEEXAMPLE12"},
		ClamAV:       true, NotifyFrom: "hardyos@example.net", SharedCalendar: true,
	}
}

func sampleSecrets() RootSecrets {
	return RootSecrets{
		SESPassword: "BAbcdEFghIJklMNopQRstUVwxYZ0123456789abcdEFGH",
		AuthSecret:  "0123456789abcdef0123456789abcdef0123456789abcdef",
		DAV:         map[string]string{"alice@example.net": "dav0123456789abcdef0123456789abcdef"},
	}
}

func sampleEnv() Env { return Env{MailRoot: "/tank/mail", VMailUID: 29990, VMailGID: 29990} }
