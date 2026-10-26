package domain

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/auth"
)

// signInIntegration checks desktop sign-in's view of a real DC (part of
// TestDCIntegration): passwords by Kerberos AS exchange with this server's
// own DC from the NAS's side of the shim, groups through the directory
// helper, and the administrator role by SID (Domain Admins as
// <domain SID>-512, HardyOS Admins as the SID recorded when it's created).
// alice (password Al1ce-Passw0rd!) is enabled and in Family; adminPW is
// Administrator's.
func signInIntegration(t *testing.T, m *Manager, c *Config, adminPW string) {
	t.Helper()
	ctx := context.Background()
	info := auth.DomainInfo{Realm: c.Realm, NetBIOS: c.NetBIOS, DNS: c.Domain, LocalKDC: c.IP()}
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
	adm, err := m.UserGroups(ctx, "Administrator")
	if err != nil || !slices.Contains(adm.Groups, "Domain Admins") {
		t.Fatalf("Administrator = %+v, %v", adm, err)
	}
	if !strings.HasPrefix(adm.DomainSID, "S-1-5-21-") || !slices.Contains(adm.GroupSIDs, adm.DomainSID+"-512") {
		t.Errorf("Administrator's SIDs = %s %v", adm.DomainSID, adm.GroupSIDs)
	}
	if !auth.AdminBySID(adm.DomainSID, "", adm.GroupSIDs) {
		t.Error("Domain Admins by SID: not an administrator")
	}
	if auth.AdminBySID(g.DomainSID, "", g.GroupSIDs) {
		t.Errorf("alice is an administrator: %v", g.GroupSIDs)
	}

	// HardyOS Admins: created through the root op, known by its SID.
	ha, err := m.SetUpAdminsGroup(ctx, AdminsGroupArgs{})
	if err != nil || !ha.Created || !strings.HasPrefix(ha.SID, adm.DomainSID+"-") {
		t.Fatalf("SetUpAdminsGroup = %+v, %v", ha, err)
	}
	if cur, _ := m.Load(); cur == nil || cur.AdminsGroupSID != ha.SID {
		t.Errorf("recorded SID = %+v", cur)
	}
	if again, err := m.SetUpAdminsGroup(ctx, AdminsGroupArgs{}); err != nil || again.Created || again.SID != ha.SID {
		t.Errorf("second SetUpAdminsGroup = %+v, %v", again, err)
	}
	if _, err := m.UpdateGroup(ctx, GroupUpdate{Name: ha.Name, Add: []string{"alice"}}); err != nil {
		t.Fatal(err)
	}
	// A look-alike group made by someone else grants nothing.
	if _, err := m.CreateGroup(ctx, NewGroup{Name: "HardyOS Admins2", Members: []string{"alice"}}); err != nil {
		t.Fatal(err)
	}
	g, err = m.UserGroups(ctx, "alice")
	if err != nil || !slices.Contains(g.GroupSIDs, ha.SID) {
		t.Fatalf("alice in HardyOS Admins = %+v, %v", g, err)
	}
	if !auth.AdminBySID(g.DomainSID, ha.SID, g.GroupSIDs) {
		t.Error("HardyOS Admins by SID: not an administrator")
	}
	if auth.AdminBySID(g.DomainSID, "", g.GroupSIDs) {
		t.Error("an administrator without the recorded SID")
	}
	if _, err := m.UpdateGroup(ctx, GroupUpdate{Name: ha.Name, Remove: []string{"alice"}}); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteGroup(ctx, "HardyOS Admins2"); err != nil {
		t.Fatal(err)
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
