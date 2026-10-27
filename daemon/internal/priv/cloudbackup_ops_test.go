package priv

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/cloudbackup"
	"github.com/hardyos/hardyos/daemon/internal/rootauth"
)

// The recovery kit needs a password root checks itself (decision 180):
// hardyd asking isn't enough.
func TestCloudKitNeedsRootCheckedPassword(t *testing.T) {
	dir := t.TempDir()
	ra := &rootauth.Checker{Dir: dir}
	if err := ra.Set("admin", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	RegisterCloudBackup(s, &cloudbackup.Root{Dir: dir}, ra)
	kit := s.ops[OpCloudKit]
	call := func(a CloudKitArgs) error {
		raw, _ := json.Marshal(a)
		_, err := kit(context.Background(), raw)
		return err
	}
	for _, a := range []CloudKitArgs{
		{ID: "off"},
		{ID: "off", Username: "admin", Password: "wrong"},
		{ID: "off", Username: "someone", Password: "correct horse battery"},
	} {
		if err := call(a); err == nil || strings.Contains(err.Error(), "no such") {
			t.Errorf("%+v: %v", a, err)
		}
	}
	// The right password gets as far as the destination (none here).
	if err := call(CloudKitArgs{ID: "off", Username: "Admin", Password: "correct horse battery"}); err == nil ||
		strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "check") {
		t.Fatalf("right password: %v", err)
	}

	// An administrator's own password change reaches root's verifier only
	// with the old password.
	change := s.ops[OpAdminPasswordChange]
	raw, _ := json.Marshal(AdminPasswordChangeArgs{Username: "admin", Old: "nope", New: "new password here"})
	if _, err := change(context.Background(), raw); err == nil {
		t.Fatal("changed root's verifier without the old password")
	}
	raw, _ = json.Marshal(AdminPasswordChangeArgs{Username: "admin", Old: "correct horse battery", New: "new password here"})
	if _, err := change(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	if err := ra.Check(context.Background(), "admin", "new password here"); err != nil {
		t.Fatal(err)
	}
}
