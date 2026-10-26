package domain

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func TestUserGroups(t *testing.T) {
	f := &sysexec.Fake{}
	m := testManager(t, f)
	ctx := context.Background()
	if _, err := m.UserGroups(ctx, "alice"); !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("without a domain: %v", err)
	}
	_ = os.MkdirAll(m.dataPath(), 0o700)
	if err := m.save(&Config{Domain: "home.example.net", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	var ve *ValidationError
	if _, err := m.UserGroups(ctx, "bad name;"); !errors.As(err, &ve) {
		t.Fatalf("bad name: %v", err)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("ran the helper for a bad name: %+v", f.Calls)
	}

	tool := AdminTool + " " + m.SmbConf()
	f.On(tool+" user.groups", `{"exists":true,"username":"Alice","displayName":"Alice Hardy","email":"","enabled":true,"lockedOut":false,"expired":false,"mustChangePassword":false,"groups":["Domain Users","Family"]}`)
	g, err := m.UserGroups(ctx, " alice ")
	if err != nil {
		t.Fatal(err)
	}
	if !g.Exists || g.Username != "Alice" || len(g.Groups) != 2 || g.Groups[1] != "Family" {
		t.Errorf("UserGroups = %+v", g)
	}
	var args map[string]string
	_ = json.Unmarshal(f.Calls[len(f.Calls)-1].Stdin, &args)
	if args["username"] != "alice" {
		t.Errorf("helper got %v", args)
	}

	f.On(tool+" user.groups", `{"exists":false,"groups":null}`)
	g, err = m.UserGroups(ctx, "nobody")
	if err != nil || g.Exists || g.Groups == nil {
		t.Errorf("missing user = %+v, %v", g, err)
	}
}
