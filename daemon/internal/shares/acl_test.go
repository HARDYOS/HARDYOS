package shares

import (
	"bytes"
	"testing"
)

func TestACLEditing(t *testing.T) {
	base := aclFromMode(0o750)
	if !base.equal(acl{{tagUserObj, 7, undefinedID}, {tagGroupObj, 5, undefinedID}, {tagOther, 0, undefinedID}}) {
		t.Fatalf("from mode = %+v", base)
	}
	a := base.withUser(30001, grantPerm(true, true, 0))
	want := acl{{tagUserObj, 7, undefinedID}, {tagUser, 7, 30001}, {tagGroupObj, 5, undefinedID}, {tagMask, 7, undefinedID}, {tagOther, 0, undefinedID}}
	if !a.equal(want) {
		t.Fatalf("with user = %+v", a)
	}
	// A second app sorts by id; the mask is the group class's union.
	b := a.withUser(30000, grantPerm(false, false, 0o644))
	if b[1] != (aclEntry{tagUser, permR, 30000}) || b[2].ID != 30001 || b[4] != (aclEntry{tagMask, 7, undefinedID}) {
		t.Fatalf("two users = %+v", b)
	}
	// Changing an entry replaces it.
	if c := b.withUser(30001, permR|permX); c[2].Perm != 5 || len(c) != len(b) || c[4].Perm != 5 {
		t.Fatalf("replace = %+v", c)
	}
	// Removing the last named entry drops the mask.
	c, changed := a.withoutUser(30001)
	if !changed || !c.equal(base) {
		t.Fatalf("without = %+v %v", c, changed)
	}
	if _, changed := base.withoutUser(1); changed {
		t.Fatal("removed a missing entry")
	}

	// The xattr encoding round-trips and matches what setfacl writes.
	enc := a.encode()
	if !bytes.Equal(enc[:4], []byte{2, 0, 0, 0}) || len(enc) != 4+8*len(a) {
		t.Fatalf("encoding = %x", enc)
	}
	dec, err := decodeACL(enc)
	if err != nil || !dec.equal(a) {
		t.Fatalf("decode = %+v %v", dec, err)
	}
	if _, err := decodeACL([]byte{1, 0, 0, 0}); err == nil {
		t.Fatal("decoded an unknown version")
	}

	// X: execute for folders and already-executable files only.
	if grantPerm(true, false, 0o644) != 6 || grantPerm(true, false, 0o700) != 7 || grantPerm(false, true, 0) != 5 {
		t.Fatal("grantPerm")
	}
}
