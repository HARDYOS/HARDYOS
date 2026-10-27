package shares

import (
	"fmt"
	"strings"
)

// Recycle bins. A shared folder with its recycle bin on has a .recycle
// folder at its top: root's, mode 1777 and without ACL entries (like
// /tmp), so everyone can make their own bin in it and nobody can touch
// anyone else's. Each person's bin is a folder in it named after a key
// that can only be theirs, owned by them, mode 0700; Samba (vfs_recycle)
// and the File Manager's workers use the same names:
//
//	<netbios>.<user>  a domain account (lower case, like its home folder)
//	hardyos-files     HardyOS administrators (local accounts)
//
// Every name of a domain account has a dot in it, so no domain account
// can ever be given the administrators' bin.

// RecycleDir is the recycle bin folder at the top of a shared folder.
const RecycleDir = ".recycle"

// FilesBin is the bin of HardyOS administrators, who act as hardyos-files.
const FilesBin = "hardyos-files"

// BinName is a domain account's bin: <netbios>.<user>, lower case. It
// returns "" for names that can't be one (empty parts, a slash, a dot
// only, ...).
func BinName(netbios, user string) string {
	nb, u := strings.ToLower(netbios), strings.ToLower(user)
	if nb == "" || u == "" || strings.ContainsAny(nb, "/\\\x00.") || strings.ContainsAny(u, "/\\\x00") {
		return ""
	}
	b := nb + "." + u
	if b == FilesBin || len(b) > 255 {
		return ""
	}
	return b
}

// BinError is a recycle bin that can't be used safely.
type BinError struct{ Msg string }

func (e *BinError) Error() string { return e.Msg }

func binErr(format string, a ...any) error { return &BinError{Msg: fmt.Sprintf(format, a...)} }
