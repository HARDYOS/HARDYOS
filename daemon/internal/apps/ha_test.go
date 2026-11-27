package apps

import (
	"encoding/json"
	"testing"
)

// A moved app's resolved compose file names its folder where it is now:
// the folder itself and paths below it, nothing that merely starts with
// the same letters (decision 483).
func TestRewriteDir(t *testing.T) {
	in := `{"services":{"web":{"volumes":[{"type":"bind","source":"/mnt/tank/apps/notes/data/db","target":"/db"},
		{"type":"bind","source":"/mnt/tank/apps/notes-old/x","target":"/x"}],"working_dir":"/mnt/tank/apps/notes"}}}`
	out, n, err := rewriteDir([]byte(in), "/mnt/tank/apps/notes", "/mnt/hc/nas/apps/notes")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("rewrote %d paths", n)
	}
	var v struct {
		Services map[string]struct {
			Volumes []struct {
				Source string `json:"source"`
			} `json:"volumes"`
			WorkingDir string `json:"working_dir"`
		} `json:"services"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatal(err)
	}
	web := v.Services["web"]
	if web.Volumes[0].Source != "/mnt/hc/nas/apps/notes/data/db" || web.Volumes[1].Source != "/mnt/tank/apps/notes-old/x" || web.WorkingDir != "/mnt/hc/nas/apps/notes" {
		t.Fatalf("rewritten %+v", web)
	}
	for _, d := range []string{"relative/apps/notes", "/mnt/tank/apps/other", "/mnt/tank/apps/notes/../x", "/mnt/tank/notes"} {
		if validDir(d, "notes") == nil {
			t.Errorf("%q passed as the app's folder", d)
		}
	}
	if err := validDir("/mnt/tank/apps/notes", "notes"); err != nil {
		t.Fatal(err)
	}
}
