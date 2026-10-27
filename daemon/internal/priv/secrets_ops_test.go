package priv

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSecretsKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	s := &Server{}
	RegisterSecrets(s, dir)
	call := func(purpose string) ([]byte, error) {
		raw, _ := json.Marshal(SecretsKeyArgs{Purpose: purpose})
		res, err := s.ops[OpSecretsKey](context.Background(), raw)
		if err != nil {
			return nil, err
		}
		return res.(SecretsKeyResult).Key, nil
	}
	a, err := call("oidc-signing")
	if err != nil || len(a) != 32 {
		t.Fatalf("%x %v", a, err)
	}
	again, _ := call("oidc-signing")
	other, _ := call("netbird-token")
	if !bytes.Equal(a, again) || bytes.Equal(a, other) {
		t.Fatal("keys aren't stable per purpose")
	}
	fi, err := os.Stat(filepath.Join(dir, MasterKeyFile))
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Size() != 32 {
		t.Fatalf("master key file: %v %v", fi, err)
	}
	for _, bad := range []string{"", "Oidc", "../x", "a b", "x123456789012345678901234567890123"} {
		if _, err := call(bad); err == nil {
			t.Errorf("purpose %q accepted", bad)
		}
	}
	// A link where the key should be is refused, not followed.
	dir2 := filepath.Join(t.TempDir(), "keys")
	_ = os.MkdirAll(dir2, 0o700)
	target := filepath.Join(t.TempDir(), "elsewhere")
	_ = os.WriteFile(target, bytes.Repeat([]byte{1}, 32), 0o600)
	_ = os.Symlink(target, filepath.Join(dir2, MasterKeyFile))
	if _, err := loadMasterKey(dir2); err == nil {
		t.Fatal("followed a link")
	}
	// So is a link in place of the keys folder (hardyd owns its parent):
	// the key is never made in a folder someone else controls. As root
	// the link is moved aside and a folder of root's made; otherwise the
	// folder is refused.
	elsewhere := t.TempDir()
	dir3 := filepath.Join(t.TempDir(), "keys")
	_ = os.Symlink(elsewhere, dir3)
	_, err = loadMasterKey(dir3)
	if os.Geteuid() == 0 {
		if fi, lerr := os.Lstat(dir3); err != nil || lerr != nil || !fi.IsDir() {
			t.Fatalf("as root: %v, keys folder %v %v", err, fi, lerr)
		}
	} else if err == nil {
		t.Fatal("used a linked keys folder")
	}
	if _, err := os.Stat(filepath.Join(elsewhere, MasterKeyFile)); err == nil {
		t.Fatal("made the master key through a linked keys folder")
	}
}
