package replica

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// A resume token (zfs get receive_resume_token) is
// <version>-<fletcher4 word 0 of the payload>-<unpacked length>-<payload>,
// the payload being the hex of a zlib-compressed nvlist packed in the
// native encoding (OpenZFS libzfs zfs_send_resume_token_to_nvlist,
// module/nvpair/nvpair.c). `zfs send -t` finds the snapshot to send by the
// token's toguid anywhere in the pool, so the token is decoded here and
// checked against this dataset's snapshots before zfs sees it.

// Token is what a resume token says.
type Token struct {
	ToName   string
	ToGUID   uint64
	FromGUID uint64 // 0 for a full stream
	HasFrom  bool
	// Keys lists every key in the token.
	Keys []string
}

// MaxTokenPacked bounds a token's unpacked size.
const MaxTokenPacked = 64 << 10

// tokenKeys are the keys HardyOS's own sends produce (-L -e -c, -i);
// anything else (rawok, savedok, redaction lists, unknown keys) is refused.
var tokenKeys = map[string]uint32{
	"fromguid": nvUint64, "object": nvUint64, "offset": nvUint64, "bytes": nvUint64, "toguid": nvUint64,
	"toname": nvString, "embedok": nvBoolean, "compressok": nvBoolean, "largeblockok": nvBoolean,
}

// nvlist data types used in tokens.
const (
	nvBoolean = 1
	nvUint64  = 8
	nvString  = 9
)

// fletcher4 is fletcher_4_native_varsize's first word over whole 32-bit
// little-endian words (trailing bytes ignored, as libzfs does).
func fletcher4(b []byte) uint64 {
	var a, bb, c, d uint64
	for i := 0; i+4 <= len(b); i += 4 {
		a += uint64(binary.LittleEndian.Uint32(b[i:]))
		bb += a
		c += bb
		d += c
	}
	return a
}

// DecodeToken decodes and checks a resume token (version 1 only).
func DecodeToken(tok string) (*Token, error) {
	if err := ValidToken(tok); err != nil {
		return nil, err
	}
	parts := strings.SplitN(tok, "-", 4)
	if parts[0] != "1" {
		return nil, invalid("resume token version %s", parts[0])
	}
	sum, err := strconv.ParseUint(parts[1], 16, 64)
	if err != nil {
		return nil, invalid("resume token checksum")
	}
	plen, err := strconv.ParseUint(parts[2], 16, 64)
	if err != nil || plen == 0 || plen > MaxTokenPacked {
		return nil, invalid("resume token length")
	}
	comp, err := hex.DecodeString(parts[3])
	if err != nil {
		return nil, invalid("resume token payload")
	}
	if fletcher4(comp) != sum {
		return nil, invalid("resume token checksum doesn't match")
	}
	zr, err := zlib.NewReader(bytes.NewReader(comp))
	if err != nil {
		return nil, invalid("resume token payload: %v", err)
	}
	packed, err := io.ReadAll(io.LimitReader(zr, int64(plen)+1))
	if err != nil || uint64(len(packed)) != plen {
		return nil, invalid("resume token payload doesn't unpack")
	}
	return decodeTokenNVList(packed)
}

// decodeTokenNVList reads a native-encoded nvlist: a 4-byte header
// (encoding 0 = native, endian 1 = little), nvl_version and nvl_nvflag
// (int32 each), then nvpairs {int32 size, int16 name size, int16, int32
// elements, int32 type, name (NUL-terminated), value at the next 8-byte
// boundary} until a size of 0.
func decodeTokenNVList(b []byte) (*Token, error) {
	bad := func(what string) error { return invalid("resume token: %s", what) }
	if len(b) < 12 {
		return nil, bad("too short")
	}
	if b[0] != 0 {
		return nil, bad("not native-encoded")
	}
	var bo binary.ByteOrder = binary.BigEndian
	if b[1] == 1 {
		bo = binary.LittleEndian
	}
	off := 12
	t := &Token{}
	seen := map[string]bool{}
	for {
		if off+4 > len(b) {
			return nil, bad("truncated")
		}
		size := int(int32(bo.Uint32(b[off:])))
		if size == 0 {
			if off+4 != len(b) {
				return nil, bad("data after the end")
			}
			break
		}
		if size < 16 || size%8 != 0 || off+size > len(b) {
			return nil, bad("bad pair size")
		}
		p := b[off : off+size]
		nameSz := int(int16(bo.Uint16(p[4:])))
		nelem := int32(bo.Uint32(p[8:]))
		typ := bo.Uint32(p[12:])
		if nameSz < 2 || 16+nameSz > size || p[16+nameSz-1] != 0 {
			return nil, bad("bad name")
		}
		name := string(p[16 : 16+nameSz-1])
		if strings.IndexByte(name, 0) >= 0 {
			return nil, bad("bad name")
		}
		want, ok := tokenKeys[name]
		if !ok {
			return nil, invalid("the resume token asks for %q, which HardyOS never sends", name)
		}
		if typ != want || seen[name] {
			return nil, bad("unexpected " + name)
		}
		seen[name] = true
		t.Keys = append(t.Keys, name)
		val := p[(16+nameSz+7)&^7:]
		switch typ {
		case nvBoolean:
			if nelem != 0 {
				return nil, bad(name)
			}
		case nvUint64:
			if nelem != 1 || len(val) < 8 {
				return nil, bad(name)
			}
			v := bo.Uint64(val)
			switch name {
			case "toguid":
				t.ToGUID = v
			case "fromguid":
				t.FromGUID, t.HasFrom = v, true
			}
		case nvString:
			i := bytes.IndexByte(val, 0)
			if nelem != 1 || i < 0 {
				return nil, bad(name)
			}
			t.ToName = string(val[:i])
		}
		off += size
	}
	for _, k := range []string{"toname", "toguid", "object", "offset", "bytes"} {
		if !seen[k] {
			return nil, bad("missing " + k)
		}
	}
	return t, nil
}

// checkToken accepts a token only for this task's snapshot of exactly ds,
// with the base (if any) one of the task's snapshots of ds, matched by
// GUID (which is how zfs send -t finds them). It returns the label sent.
func checkToken(t *Token, ds, task string, snaps []SnapInfo, want string) (string, error) {
	name, label, ok := strings.Cut(t.ToName, "@")
	if !ok || name != ds || ValidSnap(label, task) != nil || (want != "" && label != want) {
		return "", invalid("the resume token is for %q, not a snapshot of %s", t.ToName, ds)
	}
	guids := map[uint64]string{}
	for _, s := range snaps {
		if g, err := strconv.ParseUint(s.GUID, 10, 64); err == nil {
			guids[g] = s.Name
		}
	}
	if guids[t.ToGUID] != label {
		return "", invalid("the resume token's snapshot (guid %d) isn't %s@%s", t.ToGUID, ds, label)
	}
	if t.HasFrom {
		from, ok := guids[t.FromGUID]
		if !ok || from == label {
			return "", invalid("the resume token builds on a snapshot (guid %d) that isn't one of this task's snapshots of %s", t.FromGUID, ds)
		}
	}
	return label, nil
}

func (t *Token) String() string {
	return fmt.Sprintf("%s (to %d, from %d)", t.ToName, t.ToGUID, t.FromGUID)
}
