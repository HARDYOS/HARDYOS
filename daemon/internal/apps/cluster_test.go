package apps

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A cluster app's files live on shared storage that other servers could
// write: the starting server checks them against the approved hash and
// runs the full policy check again (decision 386).
func TestClusterAppRecheckAndHash(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.install(PrepareArgs{Shares: map[string]ShareChoice{"MEDIA": {Share: "media"}}, Source: SourceUpload}); err != nil {
		t.Fatal(err)
	}
	load := func() *installedApp {
		ia, err := e.m.loadDir("tank/apps/notes", e.dir("notes"))
		if err != nil {
			t.Fatal(err)
		}
		return ia
	}
	ia := load()
	if err := e.m.clusterRecheck(ctx, ia); err != nil {
		t.Fatalf("the installed app fails its own check: %v", err)
	}
	approved, err := e.m.clusterHash(ia)
	if err != nil || !strings.HasPrefix(approved, "sha256:") || len(approved) != 71 {
		t.Fatalf("%q %v", approved, err)
	}
	if again, _ := e.m.clusterHash(load()); again != approved {
		t.Fatal("the hash isn't stable")
	}

	// Another server rewrites the resolved compose file: privileged.
	resolved := filepath.Join(e.dir("notes"), metaDir, resolvedFile)
	orig, err := os.ReadFile(resolved)
	if err != nil {
		t.Fatal(err)
	}
	evil := strings.Replace(string(orig), `"image":`, `"privileged":true,"image":`, 1)
	must(t, os.WriteFile(resolved, []byte(evil), 0o600))
	ia = load()
	if err := e.m.clusterRecheck(ctx, ia); err == nil {
		t.Fatal("a privileged container passed the re-check")
	}
	if h, _ := e.m.clusterHash(ia); h == approved {
		t.Fatal("the hash didn't change with the compose file")
	}
	// HardyOS's own cgroup slice passes, another one doesn't.
	must(t, os.WriteFile(resolved, orig, 0o600))
	r, err := ParseResolved(orig)
	if err != nil {
		t.Fatal(err)
	}
	svc := r["services"].(map[string]any)["app"].(map[string]any)
	if svc["cgroup_parent"] != SliceName("notes") {
		t.Fatalf("the stored compose file has no cgroup slice: %s", orig)
	}
	svc["cgroup_parent"] = "/"
	must(t, os.WriteFile(resolved, mustJSON(r), 0o600))
	if err := e.m.clusterRecheck(ctx, load()); err == nil {
		t.Fatal("a foreign cgroup passed")
	}
	must(t, os.WriteFile(resolved, orig, 0o600))

	// The manifest gains a permission: same compose, other hash.
	mfPath := filepath.Join(e.dir("notes"), metaDir, ManifestFile)
	mf, _ := os.ReadFile(mfPath)
	var mfv map[string]any
	must(t, json.Unmarshal(mf, &mfv))
	mfv["permissions"] = map[string]any{"capabilities": []string{"SYS_ADMIN"}}
	must(t, os.WriteFile(mfPath, mustJSON(mfv), 0o600))
	if h, _ := e.m.clusterHash(load()); h == approved {
		t.Fatal("the hash didn't change with the manifest's permissions")
	}
	must(t, os.WriteFile(mfPath, mf, 0o600))
	if h, _ := e.m.clusterHash(load()); h != approved {
		t.Fatal("restoring the files didn't restore the hash")
	}
}

func TestClusterStartNeedsTheApprovedHash(t *testing.T) {
	// remote() only accepts folders under /mnt/hc: a start without the
	// hash is refused before anything is read.
	m := &Manager{Backend: fakeBackend{}}
	err := m.ClusterStart(context.Background(), ClusterStartArgs{ID: "notes", Generation: 1})
	if err == nil {
		t.Fatal("started without storage")
	}
	if errors.Is(err, ErrSpecChanged) {
		return
	}
}

type fakeBackend struct{}

func (fakeBackend) Locate(context.Context, string) (*AppStorage, error) { return nil, ErrNotInstalled }
func (fakeBackend) List(context.Context) ([]string, error)              { return nil, nil }
func (fakeBackend) DockerRoot(context.Context) (string, string, error) {
	return "", "", errors.New("no")
}
