package domain

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/auth"
)

// signInIntegration checks desktop sign-in's view of a real DC (part of
// TestDCIntegration): passwords by Kerberos AS exchange from the NAS's side
// of the shim, and groups through the directory helper. alice (password
// Al1ce-Passw0rd!) is enabled and in Family; adminPW is Administrator's.
func signInIntegration(t *testing.T, m *Manager, c *Config, adminPW string) {
	t.Helper()
	ctx := context.Background()
	info := auth.DomainInfo{Realm: c.Realm, NetBIOS: c.NetBIOS, DNS: c.Domain, KDCs: c.DNSServers()}
	k := auth.KerberosChecker{}

	if err := k.CheckPassword(ctx, info, "alice", "Al1ce-Passw0rd!"); err != nil {
		t.Errorf("Kerberos sign-in as alice: %v", err)
	}
	if err := k.CheckPassword(ctx, info, "Administrator", adminPW); err != nil {
		t.Errorf("Kerberos sign-in as Administrator: %v", err)
	}
	if err := k.CheckPassword(ctx, info, "alice", "Wr0ng-Passw0rd!"); !errors.Is(err, auth.ErrBadCredentials) {
		t.Errorf("wrong password: %v", err)
	}
	if err := k.CheckPassword(ctx, info, "nobody-here", "Wr0ng-Passw0rd!"); !errors.Is(err, auth.ErrBadCredentials) {
		t.Errorf("unknown user: %v", err)
	}

	g, err := m.UserGroups(ctx, "alice")
	if err != nil {
		t.Fatalf("UserGroups(alice): %v", err)
	}
	if !g.Exists || !g.Enabled || g.Expired || !slices.Contains(g.Groups, "Family") || !slices.Contains(g.Groups, "Domain Users") {
		t.Errorf("alice = %+v", g)
	}
	if adm, err := m.UserGroups(ctx, "Administrator"); err != nil || !slices.Contains(adm.Groups, "Domain Admins") {
		t.Errorf("Administrator = %+v, %v", adm, err)
	}
	if none, err := m.UserGroups(ctx, "nobody-here"); err != nil || none.Exists {
		t.Errorf("unknown user = %+v, %v", none, err)
	}

	if _, err := m.SetUserEnabled(ctx, "alice", false); err != nil {
		t.Fatal(err)
	}
	if err := k.CheckPassword(ctx, info, "alice", "Al1ce-Passw0rd!"); !errors.Is(err, auth.ErrAccountRevoked) {
		t.Errorf("turned-off account: %v", err)
	}
	if g, err := m.UserGroups(ctx, "alice"); err != nil || g.Enabled {
		t.Errorf("turned-off alice = %+v, %v", g, err)
	}
	if _, err := m.SetUserEnabled(ctx, "alice", true); err != nil {
		t.Fatal(err)
	}
}
