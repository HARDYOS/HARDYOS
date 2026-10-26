package shares

import (
	"encoding/binary"
	"errors"
	"sort"
)

// POSIX ACLs as Linux stores them in the system.posix_acl_access and
// system.posix_acl_default extended attributes (what setfacl writes).

const (
	xattrAccess  = "system.posix_acl_access"
	xattrDefault = "system.posix_acl_default"

	aclVersion = 2

	tagUserObj  = 0x01
	tagUser     = 0x02
	tagGroupObj = 0x04
	tagGroup    = 0x08
	tagMask     = 0x10
	tagOther    = 0x20

	permR = 4
	permW = 2
	permX = 1

	undefinedID = 0xffffffff
)

type aclEntry struct {
	Tag  uint16
	Perm uint16
	ID   uint32
}

type acl []aclEntry

func decodeACL(b []byte) (acl, error) {
	if len(b) < 4 || (len(b)-4)%8 != 0 || binary.LittleEndian.Uint32(b) != aclVersion {
		return nil, errors.New("unknown ACL format")
	}
	var a acl
	for i := 4; i < len(b); i += 8 {
		a = append(a, aclEntry{
			Tag:  binary.LittleEndian.Uint16(b[i:]),
			Perm: binary.LittleEndian.Uint16(b[i+2:]),
			ID:   binary.LittleEndian.Uint32(b[i+4:]),
		})
	}
	return a, nil
}

func (a acl) encode() []byte {
	b := make([]byte, 4, 4+8*len(a))
	binary.LittleEndian.PutUint32(b, aclVersion)
	for _, e := range a {
		b = binary.LittleEndian.AppendUint16(b, e.Tag)
		b = binary.LittleEndian.AppendUint16(b, e.Perm)
		b = binary.LittleEndian.AppendUint32(b, e.ID)
	}
	return b
}

// aclFromMode is the minimal ACL equal to a file mode.
func aclFromMode(mode uint32) acl {
	return acl{
		{Tag: tagUserObj, Perm: uint16(mode>>6) & 7, ID: undefinedID},
		{Tag: tagGroupObj, Perm: uint16(mode>>3) & 7, ID: undefinedID},
		{Tag: tagOther, Perm: uint16(mode) & 7, ID: undefinedID},
	}
}

func (a acl) find(tag uint16) int {
	for i, e := range a {
		if e.Tag == tag {
			return i
		}
	}
	return -1
}

func (a acl) hasNamed() bool {
	for _, e := range a {
		if e.Tag == tagUser || e.Tag == tagGroup {
			return true
		}
	}
	return false
}

// normalize sorts the entries the way the kernel requires and recomputes
// the mask (the union of the group class), as setfacl does. A mask is
// added when there are named entries; without any it is dropped.
func (a acl) normalize() acl {
	out := make(acl, 0, len(a)+1)
	var group uint16
	for _, e := range a {
		if e.Tag == tagMask {
			continue
		}
		if e.Tag == tagGroupObj || e.Tag == tagUser || e.Tag == tagGroup {
			group |= e.Perm
		}
		out = append(out, e)
	}
	if out.hasNamed() {
		out = append(out, aclEntry{Tag: tagMask, Perm: group, ID: undefinedID})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Tag != out[j].Tag {
			return out[i].Tag < out[j].Tag
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// withUser returns a copy with uid's entry set to perm (added if missing).
func (a acl) withUser(uid uint32, perm uint16) acl {
	out := append(acl{}, a...)
	for i, e := range out {
		if e.Tag == tagUser && e.ID == uid {
			out[i].Perm = perm
			return out.normalize()
		}
	}
	return append(out, aclEntry{Tag: tagUser, Perm: perm, ID: uid}).normalize()
}

// withoutUser returns a copy without uid's entry; changed is false when it
// had none.
func (a acl) withoutUser(uid uint32) (acl, bool) {
	out := make(acl, 0, len(a))
	changed := false
	for _, e := range a {
		if e.Tag == tagUser && e.ID == uid {
			changed = true
			continue
		}
		out = append(out, e)
	}
	return out.normalize(), changed
}

func (a acl) equal(b acl) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// grantPerm is rwX or r-X for a file or directory with this mode: X gives
// execute only to directories and to files someone may already execute.
func grantPerm(write, dir bool, mode uint32) uint16 {
	p := uint16(permR)
	if write {
		p |= permW
	}
	if dir || mode&0o111 != 0 {
		p |= permX
	}
	return p
}
