package cloudbackup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Findings from the security review (decision 183).
func TestReviewSmallFixes(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tg := e.target("rv")
	share := filepath.Join(e.base, "media")
	write(t, filepath.Join(share, "a.txt"), "a")
	e.shares.add("media", "Media", share)
	if x, _ := e.backup(tg.ID, "t", "v1", Item{Kind: ItemShare, ID: "media"}, Item{Kind: ItemSystem}); x.Error != "" {
		t.Fatal(x.Error)
	}
	versions, _ := e.root.Versions(ctx, tg.ID)
	var sys, media string
	for _, it := range versions[0].Items {
		switch it.Item {
		case ItemSystem:
			sys = it.Snapshot
		case "share:media":
			media = it.Snapshot
		}
	}

	// L12: the settings are replaced only with "settings" typed.
	if _, err := e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: sys, Mode: ModeRollback, Confirm: "yes"}); err == nil || !strings.Contains(err.Error(), "type settings") {
		t.Fatalf("settings restore without typing settings: %v", err)
	}

	// L15: a snapshot whose path isn't the item's own folder isn't HardyOS's.
	repo, err := e.root.repo(tg.ID)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(e.base, "elsewhere")
	write(t, filepath.Join(other, "x"), "x")
	sum, err := e.root.Restic.Backup(ctx, repo, ResticBackup{Path: other, Tags: []string{"task=t", "run=forged", "item=share:media", "server=" + e.root.ServerID()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshotCache.drop(tg.ID)
	if _, _, err := e.root.findSnapshot(ctx, repo, sum.SnapshotID); err == nil {
		t.Fatal("a snapshot of another path was taken as the folder's")
	}
	if _, _, err := e.root.findSnapshot(ctx, repo, media); err != nil {
		t.Fatalf("the folder's own snapshot: %v", err)
	}

	// L14: the database copy must be hardyd's own regular file, one name.
	secret := filepath.Join(e.base, "root.key")
	write(t, secret, "ROOT KEY")
	link := filepath.Join(e.work, "cloud-00000000000000aa.db")
	if err := os.Link(secret, link); err != nil {
		t.Fatal(err)
	}
	if _, err := e.root.systemDB(link); err == nil || !strings.Contains(err.Error(), "hardyd's own") {
		t.Fatalf("a hard link was read as the database copy: %v", err)
	}
	plain := filepath.Join(e.work, "cloud-00000000000000bb.db")
	write(t, plain, "db")
	e.root.DBOwner = os.Getuid() + 1
	if _, err := e.root.systemDB(plain); err == nil {
		t.Fatal("a database copy someone else owns was read")
	}
	e.root.DBOwner = os.Getuid()
	if os.Getuid() > 0 {
		if _, err := e.root.systemDB(plain); err != nil {
			t.Fatal(err)
		}
	}
	e.root.DBOwner = 0

	// L13: the installer's probe says nothing the far end sent.
	bad, _ := NewRepoPassword()
	kit := EncodeKit(KitData{Target: tg, Repository: tg.Repository(), Key: bad})
	_, err = e.root.Probe(ctx, ProbeArgs{Kit: kit})
	if err == nil || !strings.Contains(err.Error(), "key doesn't open") || strings.Contains(err.Error(), "restic") || strings.Contains(err.Error(), "Fatal") {
		t.Fatalf("probe with a wrong key: %v", err)
	}
	missing := tg
	missing.Path = filepath.Join(e.base, "nothing-here")
	kit = EncodeKit(KitData{Target: missing, Repository: missing.Repository(), Key: bad})
	if _, err := e.root.Probe(ctx, ProbeArgs{Kit: kit}); err == nil || strings.Contains(err.Error(), missing.Path) {
		t.Fatalf("probe of nothing: %v", err)
	}
}

// L11: keys saved for one host never go to another.
func TestNewKeysForANewHost(t *testing.T) {
	a := Target{Kind: KindS3, Endpoint: "https://s3.eu-west-1.amazonaws.com"}
	b := Target{Kind: KindS3, Endpoint: "https://s3.eu-west-1.amazonaws.com:443/"}
	c := Target{Kind: KindS3, Endpoint: "https://evil.example.com"}
	if endpointHost(&a) != endpointHost(&b) || endpointHost(&a) == endpointHost(&c) {
		t.Fatalf("%s %s %s", endpointHost(&a), endpointHost(&b), endpointHost(&c))
	}
}
