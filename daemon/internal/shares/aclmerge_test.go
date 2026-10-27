package shares

import "testing"

func TestMergeRestoredACL(t *testing.T) {
	person := aclEntry{Tag: tagUser, Perm: permR, ID: 4242}
	oldApp := aclEntry{Tag: tagUser, Perm: permR | permW | permX, ID: 30005}
	nfsNow := aclEntry{Tag: tagUser, Perm: permR | permX, ID: 31002}
	backup := aclFromMode(0o640)
	backup = append(backup, person, oldApp).normalize()
	current := aclFromMode(0o640).withUser(FilesUID, permR|permW).withUser(31002, permR|permX)

	got, err := MergeRestoredACL(backup.encode(), current.encode(), 0o640, false)
	if err != nil {
		t.Fatal(err)
	}
	a, err := decodeACL(got)
	if err != nil {
		t.Fatal(err)
	}
	has := func(e aclEntry) bool {
		for _, x := range a {
			if x.Tag == e.Tag && x.ID == e.ID {
				return true
			}
		}
		return false
	}
	if !has(person) || has(oldApp) || !has(nfsNow) || !has(aclEntry{Tag: tagUser, ID: FilesUID}) {
		t.Fatalf("merged ACL: %+v", a)
	}
	if a.find(tagMask) < 0 {
		t.Fatal("no mask")
	}

	// No ACL in the backup and none now: nothing.
	if got, err := MergeRestoredACL(nil, nil, 0o644, false); err != nil || got != nil {
		t.Fatalf("plain file: %v %v", got, err)
	}
	// Only HardyOS's old entries in the backup: they go.
	onlyApp := aclFromMode(0o644).withUser(30001, permR)
	if got, _ := MergeRestoredACL(onlyApp.encode(), nil, 0o644, false); got != nil {
		t.Fatalf("an old app entry came back: %v", got)
	}
	// A default ACL: today's managed entries even when the backup had none.
	def, _ := MergeRestoredACL(nil, current.encode(), 0o755, true)
	if d, _ := decodeACL(def); d.find(tagUser) < 0 {
		t.Fatalf("default without today's entries: %+v", d)
	}
	// A narrower mask someone chose stays.
	narrow := append(aclFromMode(0o640), person, aclEntry{Tag: tagMask, Perm: 0, ID: undefinedID})
	got, _ = MergeRestoredACL(narrow.encode(), nil, 0o600, false)
	n, _ := decodeACL(got)
	if i := n.find(tagMask); i < 0 || n[i].Perm != 0 {
		t.Fatalf("mask widened: %+v", n)
	}
	if !ManagedUID(FilesUID) || !ManagedUID(30500) || !ManagedUID(31999) || ManagedUID(1000) || ManagedUID(2000000) {
		t.Fatal("ManagedUID")
	}
}
