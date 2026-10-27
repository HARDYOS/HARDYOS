package shares

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestScanLinks(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "share")
	other := filepath.Join(root, "other")
	for _, d := range []string{base + "/a/b", base + "/s", other} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(base, "a", "photo.jpg"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(other, "secret.jpg"), []byte("x"), 0o644)
	links := map[string]string{
		"ok-rel":        "a/photo.jpg",
		"a/b/ok-up":     "../photo.jpg",
		"abs-inside":    filepath.Join(base, "a"), // absolute: means something else in a container
		"abs-outside":   "/etc/passwd",
		"rel-outside":   "../other/secret.jpg",
		"dangling":      "nope/nothing",
		"s/dot":         ".",
		"via-dot":       "s/dot/../../other", // escapes only through another link
		"a/b/dir-ok":    "..",
		"loop1":         "loop2",
		"loop2":         "loop1",
		"a/deep-escape": "b/dir-ok/../../..",
	}
	for l, target := range links {
		if err := os.Symlink(target, filepath.Join(base, l)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := scanLinks(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a/deep-escape", "abs-inside", "abs-outside", "dangling", "loop1", "loop2", "rel-outside", "via-dot"}
	slices.Sort(got.Escaping)
	if !slices.Equal(got.Escaping, want) || got.Count != len(want) || got.Truncated {
		t.Fatalf("escaping %v (count %d, truncated %v), want %v", got.Escaping, got.Count, got.Truncated, want)
	}
	// A cancelled scan says it didn't see everything.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 5000; i++ {
		_ = os.WriteFile(filepath.Join(base, "a", fmt.Sprintf("f%d", i)), nil, 0o644)
	}
	if got, _ := scanLinks(ctx, base); !got.Truncated {
		t.Fatal("a cancelled scan isn't marked truncated")
	}
}
