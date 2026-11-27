package hacopy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/shares"
)

func shareRef(side Side) Ref { return Ref{Kind: KindShare, ID: "media", Pool: "tank", Side: side} }

// A shared folder moving with its app (decisions 500-501): its ids are
// shared folder ids, it is the server's own on either side, never cluster
// storage, and nothing may be below it.
func TestShareRefRules(t *testing.T) {
	for _, id := range []string{"Media", "a/b", "global", "x-", ""} {
		if err := (Ref{Kind: KindShare, ID: id, Pool: "tank", Side: SideLocal}).Validate(); err == nil {
			t.Errorf("share id %q accepted", id)
		}
	}
	if err := (Ref{Kind: KindShare, ID: "2025-photos", Pool: "tank", Side: SideCluster}).Validate(); err != nil {
		t.Fatal(err)
	}
	if got := shareRef(SideLocal).Dataset(); got != "tank/shares/media" {
		t.Fatal(got)
	}
	f := newFake()
	f.add("tank", "filesystem")
	f.add("tank/shares", "filesystem")
	f.add("tank/shares/media", "filesystem", shares.PropShare, "1")
	r := &Root{Runner: f}
	ctx := context.Background()
	for _, side := range []Side{SideLocal, SideCluster} {
		if _, err := r.checkSource(ctx, shareRef(side)); err != nil {
			t.Fatalf("%s: %v", side, err)
		}
	}
	f.ds["tank/shares/media"]["org.hardyos:role"] = "cluster"
	if _, err := r.checkSource(ctx, shareRef(SideCluster)); err == nil {
		t.Fatal("cluster storage taken for a shared folder")
	}
	delete(f.ds["tank/shares/media"], "org.hardyos:role")
	delete(f.ds["tank/shares/media"], shares.PropShare)
	if _, err := r.checkSource(ctx, shareRef(SideLocal)); err == nil {
		t.Fatal("a dataset that isn't a shared folder was taken for one")
	}
	f.ds["tank/shares/media"][shares.PropShare] = "1"
	f.add("tank/shares/media/sub", "filesystem")
	if _, err := r.checkSource(ctx, shareRef(SideLocal)); err == nil {
		t.Fatal("a dataset below a shared folder was sent along")
	}
}

// This server's shared folder is parked only while its own conversion
// holds it; the storage server's only when it carries a conversion's mark
// and no compute server mounts it any more. File sharing lets go first
// and takes the change up after.
func TestShareParkRules(t *testing.T) {
	f := newFake()
	f.add("tank", "filesystem")
	f.add("tank/shares", "filesystem")
	f.add("tank/shares/media", "filesystem", shares.PropShare, "1", "written", "0")
	var released, changed int
	busy := true
	r := &Root{Runner: f, ShareRelease: func(context.Context, string) func() { released++; return nil }, ShareChanged: func(context.Context) { changed++ },
		ShareBusy: func(context.Context, string, string) (bool, error) { return busy, nil }}
	ctx := context.Background()
	a := ParkArgs{Ref: shareRef(SideLocal), Confirm: "media", Conv: "abcdefgh12s0"}
	if _, err := r.Park(ctx, a); err == nil {
		t.Fatal("a shared folder nobody held was parked")
	}
	f.ds["tank/shares/media"][propHAHold] = "otherconv12"
	if _, err := r.Park(ctx, a); err == nil {
		t.Fatal("another conversion's hold was taken")
	}
	f.ds["tank/shares/media"][propHAHold] = "abcdefgh12s0"
	res, err := r.Park(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.Name, "share-media-") || released != 1 || changed != 1 {
		t.Fatalf("parked %+v released %d changed %d", res, released, changed)
	}
	if _, there := f.ds["tank/hardyos-ha-parked/"+res.Name]; !there {
		t.Fatal("not under the parked folder")
	}
	// The parked copy lists, and is put back as a shared folder, its hold
	// ended (read-only and the mark go).
	l, _ := r.ParkedList(ctx)
	if len(l) != 1 || l[0].Kind != KindShare || l[0].ID != "media" {
		t.Fatalf("parked list %+v", l)
	}
	if _, err := r.UnparkState(ctx, UnparkArgs{Ref: shareRef(SideLocal), Name: res.Name}); err != nil {
		t.Fatal(err)
	}
	p := f.ds["tank/shares/media"]
	if p == nil || p[propHAHold] != "" || p["readonly"] != "" || p[shares.PropShare] != "1" || p["acltype"] != "posixacl" {
		t.Fatalf("put back %v", p)
	}
	// The storage server's side: only with a conversion's mark expected,
	// and never while it is still exported to compute servers.
	c := ParkArgs{Ref: shareRef(SideCluster), Confirm: "media", Conv: "abcdefgh12s0x1"}
	if _, err := r.Park(ctx, c); err == nil {
		t.Fatal("the storage server's own shared folder was parked without a conversion's mark")
	}
	f.ds["tank/shares/media"][PropParkedConv] = "abcdefgh12s0"
	c.Expect = "abcdefgh12s0"
	if _, err := r.Park(ctx, c); !errors.Is(err, ErrBusy) {
		t.Fatalf("parked while exported: %v", err)
	}
	busy = false
	if _, err := r.Park(ctx, c); err != nil {
		t.Fatal(err)
	}
}

// A shared folder is adopted on the storage server only, with settings
// checked like a person's, never over one of that server's shared
// folders, and held (read-only, unmounted) until the conversion lets go.
func TestShareAdopt(t *testing.T) {
	f := newFake()
	f.add("nas", "filesystem")
	f.add("nas/hardyos-ha-incoming", "filesystem")
	f.add("nas/hardyos-ha-incoming/abcdefgh12s0", "filesystem", PropIncoming, "share:media")
	f.add("nas/hardyos-ha-incoming/abcdefgh12s0/share-media", "filesystem")
	taken := error(nil)
	var changed int
	r := &Root{Runner: f, ShareTaken: func(context.Context, string, string) error { return taken }, ShareChanged: func(context.Context) { changed++ }}
	ctx := context.Background()
	ref := Ref{Kind: KindShare, ID: "media", Pool: "nas", Side: SideCluster}
	set := &shares.Settings{Name: "Media", Access: []shares.Rule{{Kind: shares.KindEveryone, Level: shares.LevelRead}},
		Apps: []shares.AppGrant{{App: "jellyfin", UID: 30001, Level: shares.LevelRead}}, Services: shares.DefaultServices()}
	if _, err := r.Adopt(ctx, AdoptArgs{Ref: ref, Conv: "abcdefgh12s0"}); err == nil {
		t.Fatal("adopted without its settings")
	}
	if _, err := r.Adopt(ctx, AdoptArgs{Ref: Ref{Kind: KindShare, ID: "media", Pool: "nas", Side: SideLocal}, Conv: "abcdefgh12s0", Share: set}); err == nil {
		t.Fatal("adopted on this server's own side")
	}
	bad := *set
	bad.Name = "Media\tx"
	if _, err := r.Adopt(ctx, AdoptArgs{Ref: ref, Conv: "abcdefgh12s0", Share: &bad}); err == nil {
		t.Fatal("settings with a tab were written")
	}
	taken = errors.New("there's a Media here")
	if _, err := r.Adopt(ctx, AdoptArgs{Ref: ref, Conv: "abcdefgh12s0", Share: set}); err == nil {
		t.Fatal("adopted over the storage server's own shared folder")
	}
	taken = nil
	res, err := r.Adopt(ctx, AdoptArgs{Ref: ref, Conv: "abcdefgh12s0", Share: set})
	if err != nil {
		t.Fatal(err)
	}
	p := f.ds["nas/shares/media"]
	if res.Dataset != "nas/shares/media" || p == nil || p[shares.PropShare] != "1" || p[shares.PropName] != "Media" || p[PropParkedConv] != "abcdefgh12s0" {
		t.Fatalf("adopted %+v %v", res, p)
	}
	if p[propHAHold] != "abcdefgh12s0" || p["readonly"] != "on" || p["canmount"] != "noauto" || p["acltype"] != "posixacl" {
		t.Fatalf("not held as adopted: %v", p)
	}
	if !strings.Contains(p[shares.PropApps], "jellyfin") || f.ds["nas/shares"]["org.hardyos:role"] != "shares" {
		t.Fatalf("app access or parent %v %v", p[shares.PropApps], f.ds["nas/shares"])
	}
	// Asked again (its answer lost): the same, still held.
	if _, err := r.Adopt(ctx, AdoptArgs{Ref: ref, Conv: "abcdefgh12s0", Share: set}); err != nil || f.ds["nas/shares/media"]["canmount"] != "noauto" {
		t.Fatalf("again: %v %v", err, f.ds["nas/shares/media"])
	}
}
