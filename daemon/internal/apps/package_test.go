package apps

import (
	"archive/tar"
	"bytes"
	"compress/gzip"

	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testManifest = `{"format":1,"id":"notes","name":"Family Notes","version":"1.0.0","summary":"Shared notes.",
  "publisher":"Test","website":"https://example.com","icon":"icon.svg","arch":["amd64","arm64"],
  "web":{"port":"WEB","path":"/"},
  "ports":[{"name":"WEB","label":"Website","default":8100}],
  "settings":[{"env":"SECRET","generate":"secret"},{"env":"TITLE","label":"Title","default":"Notes"}],
  "folders":[{"path":"db","owner":"999:999","mode":"0700"}]}`

const testCompose = "services:\n  app:\n    image: ghcr.io/x/app:latest\n    ports: [\"${HARDY_PORT_WEB}:80\"]\n"

const testIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"/>`

func tarGz(t *testing.T, files map[string]string, extra func(*tar.Writer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	if extra != nil {
		extra(tw)
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func goodFiles() map[string]string {
	return map[string]string{"hardyapp.json": testManifest, "compose.yaml": testCompose, "icon.svg": testIcon, "README.md": "# hi"}
}

func TestReadPackage(t *testing.T) {
	p, err := ReadPackage(tarGz(t, goodFiles(), nil))
	if err != nil {
		t.Fatal(err)
	}
	if p.Manifest.ID != "notes" || string(p.Compose) != testCompose || len(p.SHA256) != 64 || string(p.Icon) != testIcon {
		t.Fatalf("package: %+v", p.Manifest)
	}
	if s := p.Manifest.Setting("SECRET"); s == nil || !s.Secret() || !s.Hidden() {
		t.Fatalf("SECRET setting: %+v", s)
	}
	if !strings.HasPrefix(IconDataURL(p.Manifest.Icon, p.Icon), "data:image/svg+xml;base64,") {
		t.Error("icon data URL")
	}

	bad := map[string]struct {
		files map[string]string
		extra func(*tar.Writer)
		want  string
	}{
		"no manifest": {files: map[string]string{"compose.yaml": testCompose}, want: "no hardyapp.json"},
		"no compose":  {files: map[string]string{"hardyapp.json": testManifest, "icon.svg": testIcon}, want: "no compose.yaml"},
		"subfolder":   {files: map[string]string{"x/hardyapp.json": testManifest}, want: "top of the package"},
		"extra file":  {files: merge(goodFiles(), "run.sh", "rm -rf /"), want: "unexpected file"},
		"no icon":     {files: map[string]string{"hardyapp.json": testManifest, "compose.yaml": testCompose}, want: "icon icon.svg"},
		"symlink": {files: goodFiles(), extra: func(tw *tar.Writer) {
			_ = tw.WriteHeader(&tar.Header{Name: "evil", Linkname: "/etc/shadow", Typeflag: tar.TypeSymlink})
		}, want: "only regular files"},
		"bad manifest": {files: merge(goodFiles(), "hardyapp.json", strings.Replace(testManifest, `"id":"notes"`, `"id":"Notes!"`, 1)), want: "id"},
		"reserved var": {files: merge(goodFiles(), "hardyapp.json", strings.Replace(testManifest, `"env":"TITLE"`, `"env":"HARDY_HOST"`, 1)), want: "belong to HardyOS"},
		"http website": {files: merge(goodFiles(), "hardyapp.json", strings.Replace(testManifest, "https://", "http://", 1)), want: "https://"},
		"low port":     {files: merge(goodFiles(), "hardyapp.json", strings.Replace(testManifest, `"default":8100`, `"default":80`, 1)), want: "1024-65535"},
		"bad folder":   {files: merge(goodFiles(), "hardyapp.json", strings.Replace(testManifest, `"path":"db"`, `"path":"../etc"`, 1)), want: "folder"},
		"bad cap": {files: merge(goodFiles(), "hardyapp.json", strings.Replace(testManifest, `"folders"`, `"permissions":{"capabilities":["SYS_ADMIN"]},"folders"`, 1)),
			want: "SYS_ADMIN isn't available"},
		"bad device": {files: merge(goodFiles(), "hardyapp.json", strings.Replace(testManifest, `"folders"`, `"permissions":{"devices":["/dev/sda"]},"folders"`, 1)),
			want: "/dev/sda isn't available"},
		"unknown field": {files: merge(goodFiles(), "hardyapp.json", strings.Replace(testManifest, `"format":1`, `"format":1,"root":true`, 1)), want: "root"},
	}
	for name, c := range bad {
		_, err := ReadPackage(tarGz(t, c.files, c.extra))
		var p Problems
		if err == nil || !errors.As(err, &p) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want a problem mentioning %q", name, err, c.want)
		}
	}
	if _, err := ReadPackage([]byte("plain text")); err == nil {
		t.Error("plain text accepted")
	}
	if _, err := ReadPackage(make([]byte, MaxPackageBytes+1)); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("huge package: %v", err)
	}
	// A small package that unpacks to a lot (a zip bomb) is refused.
	bomb := tarGz(t, merge(goodFiles(), "README.md", strings.Repeat("a", 3<<20)), nil)
	if len(bomb) > MaxPackageBytes {
		t.Fatalf("bomb is %d bytes", len(bomb))
	}
	if _, err := ReadPackage(bomb); err == nil || !strings.Contains(err.Error(), "2 MB") {
		t.Errorf("bomb: %v", err)
	}
}

func merge(m map[string]string, k, v string) map[string]string {
	out := map[string]string{}
	for a, b := range m {
		out[a] = b
	}
	out[k] = v
	return out
}

func TestPackIsDeterministicAndChecked(t *testing.T) {
	dir := t.TempDir()
	for name, body := range goodFiles() {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	a, err := Pack(dir)
	if err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Hour)
	_ = os.Chtimes(filepath.Join(dir, "compose.yaml"), later, later)
	b, _ := Pack(dir)
	if !bytes.Equal(a, b) {
		t.Error("packing twice gave different bytes")
	}
	if err := os.WriteFile(filepath.Join(dir, "hardyapp.json"), []byte(`{"format":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Pack(dir); err == nil {
		t.Error("packed an invalid manifest")
	}
}

func TestCatalogPackagesAreValid(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "..", "apps", "catalog"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := Pack(filepath.Join("..", "..", "..", "apps", "catalog", e.Name()))
		if err != nil {
			t.Errorf("%s: %v", e.Name(), err)
			continue
		}
		p, _ := ReadPackage(b)
		if p.Manifest.ID != e.Name() {
			t.Errorf("%s: the folder must be named after the app id (%s)", e.Name(), p.Manifest.ID)
		}
	}
}
