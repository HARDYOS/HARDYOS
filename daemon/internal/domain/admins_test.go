package domain

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func TestUserGroupsSIDs(t *testing.T) {
	f := &sysexec.Fake{}
	m := testManager(t, f)
	_ = os.MkdirAll(m.dataPath(), 0o700)
	if err := m.save(&Config{Domain: "home.example.net", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	tool := AdminTool + " " + m.SmbConf()
	f.On(tool+" user.groups", `{"exists":true,"username":"boss","enabled":true,"groups":["Domain Admins","Domain Users"],`+
		`"groupSids":["S-1-5-21-1-2-3-512","S-1-5-21-1-2-3-513"],"domainSid":"S-1-5-21-1-2-3"}`)
	g, err := m.UserGroups(context.Background(), "boss")
	if err != nil {
		t.Fatal(err)
	}
	if g.DomainSID != "S-1-5-21-1-2-3" || len(g.GroupSIDs) != 2 || g.GroupSIDs[0] != "S-1-5-21-1-2-3-512" {
		t.Errorf("UserGroups = %+v", g)
	}
	// An older helper without SIDs: empty, not nil.
	f.On(tool+" user.groups", `{"exists":true,"username":"boss","enabled":true,"groups":["Domain Admins"]}`)
	if g, _ := m.UserGroups(context.Background(), "boss"); g.GroupSIDs == nil || len(g.GroupSIDs) != 0 || g.DomainSID != "" {
		t.Errorf("without SIDs = %+v", g)
	}
}

func TestSetUpAdminsGroup(t *testing.T) {
	f := &sysexec.Fake{}
	m := testManager(t, f)
	ctx := context.Background()
	if _, err := m.SetUpAdminsGroup(ctx, AdminsGroupArgs{}); !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("without a domain: %v", err)
	}
	_ = os.MkdirAll(m.dataPath(), 0o700)
	if err := m.save(&Config{Domain: "home.example.net", Enabled: true, Others: []DC{{Name: "dc2", Address: "192.0.2.21"}}}); err != nil {
		t.Fatal(err)
	}
	tool := AdminTool + " " + m.SmbConf()
	const sid = "S-1-5-21-1-2-3-1105"
	setGroups := func(js string) { f.On(tool+" groups", js) }

	// Created by HardyOS: recorded.
	setGroups(`{"groups":[{"name":"Domain Admins","sid":"S-1-5-21-1-2-3-512","members":["Administrator"],"builtin":true}]}`)
	f.On(tool+" group.create", `{"name":"HardyOS Admins","sid":"`+sid+`","description":"","members":[],"builtin":false}`)
	g, err := m.SetUpAdminsGroup(ctx, AdminsGroupArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if !g.Created || g.SID != sid || g.Name != AdminsGroupName {
		t.Errorf("created = %+v", g)
	}
	c, _ := m.Load()
	if c.AdminsGroupSID != sid || len(c.Others) != 1 {
		t.Errorf("config = %+v", c)
	}
	var args NewGroup
	for _, call := range f.Calls {
		if strings.HasSuffix(call.Line, " group.create") {
			_ = json.Unmarshal(call.Stdin, &args)
		}
	}
	if args.Name != AdminsGroupName {
		t.Errorf("group.create got %+v", args)
	}
	// Renamed since: still the one, nothing created.
	setGroups(`{"groups":[{"name":"Desktop Bosses","sid":"` + sid + `","members":["alice"],"builtin":false}]}`)
	f.On(tool+" group.create", `{"name":"wrong","sid":"S-1-5-21-1-2-3-9999"}`)
	g, err = m.SetUpAdminsGroup(ctx, AdminsGroupArgs{})
	if err != nil || g.Created || g.Adopted || g.Name != "Desktop Bosses" || g.SID != sid {
		t.Errorf("already recorded = %+v %v", g, err)
	}

	// Deleted, and someone else made a group with the name: refused unless adopted.
	setGroups(`{"groups":[{"name":"HardyOS Admins","sid":"S-1-5-21-1-2-3-1300","members":["mallory"],"builtin":false}]}`)
	_, err = m.SetUpAdminsGroup(ctx, AdminsGroupArgs{})
	var exists *AdminsGroupExistsError
	if !errors.As(err, &exists) || len(exists.Members) != 1 || !strings.Contains(err.Error(), "mallory") {
		t.Fatalf("existing group without adopt: %v", err)
	}
	if c, _ := m.Load(); c.AdminsGroupSID != sid {
		t.Errorf("SID changed without adopt: %s", c.AdminsGroupSID)
	}
	g, err = m.SetUpAdminsGroup(ctx, AdminsGroupArgs{Adopt: true})
	if err != nil || !g.Adopted || g.SID != "S-1-5-21-1-2-3-1300" {
		t.Fatalf("adopt = %+v %v", g, err)
	}
	if c, _ := m.Load(); c.AdminsGroupSID != "S-1-5-21-1-2-3-1300" {
		t.Errorf("adopted SID not recorded: %s", c.AdminsGroupSID)
	}

	// A built-in group renamed to HardyOS Admins is never adopted.
	_ = m.save(&Config{Domain: "home.example.net", Enabled: true})
	setGroups(`{"groups":[{"name":"HardyOS Admins","sid":"S-1-5-21-1-2-3-513","members":[],"builtin":true}]}`)
	var ve *ValidationError
	if _, err := m.SetUpAdminsGroup(ctx, AdminsGroupArgs{Adopt: true}); !errors.As(err, &ve) {
		t.Errorf("built-in group adopted: %v", err)
	}
	// A helper that doesn't say SIDs records nothing.
	setGroups(`{"groups":[]}`)
	f.On(tool+" group.create", `{"name":"HardyOS Admins","members":[]}`)
	if _, err := m.SetUpAdminsGroup(ctx, AdminsGroupArgs{}); err == nil {
		t.Error("recorded a group without a SID")
	}
	if c, _ := m.Load(); c.AdminsGroupSID != "" {
		t.Errorf("SID = %q", c.AdminsGroupSID)
	}
}

func TestSetupNetworkPinsNeighbors(t *testing.T) {
	f := &sysexec.Fake{}
	m := testManager(t, f)
	m.lastParent = "enp1s0"
	c := &Config{Address: "192.168.1.20/24", Gateway: "192.168.1.1", Parent: "enp1s0", MAC: "02:11:22:33:44:55"}
	f.On("ip -j -n hardyos-dc addr show dev hdc0", `[{"ifname":"hdc0","flags":["UP"],"addr_info":[{"family":"inet","local":"192.168.1.20","prefixlen":24,"scope":"global"}]}]`)
	f.On("ip -j -d addr show dev hdc-shim", `[{"ifname":"hdc-shim","address":"02:aa:bb:cc:dd:ee","link":"enp1s0","flags":["UP"],"addr_info":[{"family":"inet","local":"169.254.250.1","prefixlen":32,"scope":"link"}]}]`)
	f.OnPrefix("ip ", sysexec.Result{})
	f.OnPrefix("sysctl ", sysexec.Result{})
	if err := m.SetupNetwork(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(f.Lines(), "\n")
	for _, want := range []string{
		"ip neigh replace 192.168.1.20 lladdr 02:11:22:33:44:55 dev hdc-shim nud permanent",
		"ip -n hardyos-dc neigh replace 169.254.250.1 lladdr 02:aa:bb:cc:dd:ee dev hdc0 nud permanent",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}
