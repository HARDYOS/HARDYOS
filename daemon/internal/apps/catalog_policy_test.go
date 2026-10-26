package apps

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// TestCatalogPolicy resolves every catalog app with Docker Compose and
// checks it against the policy as a catalog app (skipped without Compose).
func TestCatalogPolicy(t *testing.T) {
	if exec.Command("docker", "compose", "version").Run() != nil {
		t.Skip("docker compose isn't installed")
	}
	root := filepath.Join("..", "..", "..", "apps", "catalog")
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		var mf Manifest
		b, _ := os.ReadFile(filepath.Join(dir, ManifestFile))
		if err := json.Unmarshal(b, &mf); err != nil {
			t.Errorf("%s: %v", e.Name(), err)
			continue
		}
		tmp := t.TempDir()
		data := filepath.Join(tmp, "data")
		os.MkdirAll(data, 0o755)
		env := []string{"PATH=" + os.Getenv("PATH"), "HARDY_APP_ID=" + mf.ID, "HARDY_APP_DATA=" + data, "HARDY_HOST=nas.local", "HARDY_TZ=UTC", "HARDY_UID=30000", "HARDY_GID=30000"}
		ports := map[string]int{}
		for _, p := range mf.Ports {
			ports[p.Name] = p.Default
			env = append(env, "HARDY_PORT_"+p.Name+"="+itoa(p.Default))
		}
		var binds []shareBind
		for _, s := range mf.Shares {
			sp := filepath.Join(tmp, "share-"+s.Name)
			os.MkdirAll(sp, 0o755)
			binds = append(binds, shareBind{Name: s.Name, Path: sp, Write: s.Access == "write"})
			env = append(env, ShareEnv(s.Name)+"="+sp)
		}
		for _, s := range mf.Settings {
			v := s.Default
			if v == "" {
				v = "x"
			}
			env = append(env, s.Env+"="+v)
		}
		cmd := exec.Command("docker", "compose", "-p", ProjectName(mf.ID), "-f", filepath.Join(dir, ComposeFile), "config", "--format", "json")
		cmd.Env = env
		out, err := cmd.Output()
		if err != nil {
			t.Errorf("%s: compose config: %v", mf.ID, err)
			continue
		}
		r, err := ParseResolved(out)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.check(mf, ProjectName(mf.ID), data, ports, binds); err != nil {
			t.Errorf("%s: %v", mf.ID, err)
		}
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
