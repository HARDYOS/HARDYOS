package replica

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

type nvp struct {
	name string
	typ  uint32
	u64  uint64
	str  string
}

// packNV packs pairs the way nvlist_pack(NV_ENCODE_NATIVE) does on a
// little-endian machine.
func packNV(pairs []nvp) []byte {
	le := binary.LittleEndian
	var b bytes.Buffer
	b.Write([]byte{0, 1, 0, 0})
	b.Write(make([]byte, 8)) // nvl_version, nvl_nvflag
	align := func(n int) int { return (n + 7) &^ 7 }
	for _, p := range pairs {
		nameSz := len(p.name) + 1
		var val []byte
		nelem := int32(1)
		switch p.typ {
		case nvBoolean:
			nelem = 0
		case nvUint64:
			val = make([]byte, 8)
			le.PutUint64(val, p.u64)
		case nvString:
			val = append([]byte(p.str), 0)
		}
		size := align(16+nameSz) + align(len(val))
		rec := make([]byte, size)
		le.PutUint32(rec[0:], uint32(size))
		le.PutUint16(rec[4:], uint16(nameSz))
		le.PutUint32(rec[8:], uint32(nelem))
		le.PutUint32(rec[12:], p.typ)
		copy(rec[16:], p.name)
		copy(rec[align(16+nameSz):], val)
		b.Write(rec)
	}
	b.Write(make([]byte, 4))
	return b.Bytes()
}

func makeToken(pairs []nvp) string {
	packed := packNV(pairs)
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	w.Write(packed)
	w.Close()
	return fmt.Sprintf("1-%x-%x-%s", fletcher4(z.Bytes()), len(packed), hex.EncodeToString(z.Bytes()))
}

func tokenPairs(toname string, toguid, fromguid uint64, extra ...nvp) []nvp {
	l := []nvp{{name: "object", typ: nvUint64, u64: 12}, {name: "offset", typ: nvUint64, u64: 4096}, {name: "bytes", typ: nvUint64, u64: 1 << 20},
		{name: "toguid", typ: nvUint64, u64: toguid}, {name: "toname", typ: nvString, str: toname},
		{name: "embedok", typ: nvBoolean}, {name: "compressok", typ: nvBoolean}, {name: "largeblockok", typ: nvBoolean}}
	if fromguid != 0 {
		l = append(l, nvp{name: "fromguid", typ: nvUint64, u64: fromguid})
	}
	return append(l, extra...)
}

func TestDecodeToken(t *testing.T) {
	tok := makeToken(tokenPairs("tank/shares/media@"+label, 222, 111))
	got, err := DecodeToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.ToName != "tank/shares/media@"+label || got.ToGUID != 222 || got.FromGUID != 111 || !got.HasFrom {
		t.Fatalf("%+v", got)
	}
	for name, bad := range map[string]string{
		"rawok":             makeToken(tokenPairs("tank/shares/media@"+label, 222, 0, nvp{name: "rawok", typ: nvBoolean})),
		"savedok":           makeToken(tokenPairs("tank/shares/media@"+label, 222, 0, nvp{name: "savedok", typ: nvBoolean})),
		"book_redact_snaps": makeToken(tokenPairs("tank/shares/media@"+label, 222, 0, nvp{name: "book_redact_snaps", typ: nvUint64, u64: 1})),
		"redact_book":       makeToken(tokenPairs("tank/shares/media@"+label, 222, 0, nvp{name: "redact_book", typ: nvString, str: "x"})),
		"toguid as string":  makeToken([]nvp{{name: "toguid", typ: nvString, str: "1"}}),
		"missing toguid":    makeToken([]nvp{{name: "toname", typ: nvString, str: "a@b"}}),
		"twice":             makeToken(append(tokenPairs("tank/shares/media@"+label, 222, 0), nvp{name: "toguid", typ: nvUint64, u64: 9})),
		"version":           "2" + tok[1:],
		"checksum":          strings.Join(append([]string{"1", "1"}, strings.SplitN(tok, "-", 4)[2:]...), "-"),
	} {
		if _, err := DecodeToken(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCheckToken(t *testing.T) {
	ds := "tank/shares/media"
	older := "hardyos-repl-abc123-20261027T100000Z"
	snaps := []SnapInfo{{Name: older, GUID: "111"}, {Name: label, GUID: "222"}}
	ok := func(toname string, to, from uint64) error {
		tk, err := DecodeToken(makeToken(tokenPairs(toname, to, from)))
		if err != nil {
			return err
		}
		_, err = checkToken(tk, ds, "abc123", snaps, "")
		return err
	}
	if err := ok(ds+"@"+label, 222, 111); err != nil {
		t.Fatal(err)
	}
	if err := ok(ds+"@"+label, 222, 0); err != nil {
		t.Fatal(err)
	}
	// The name says this dataset but the GUID is another snapshot in the
	// pool (zfs would send that one): refused.
	if ok(ds+"@"+label, 999, 111) == nil {
		t.Error("foreign toguid accepted")
	}
	if ok(ds+"@"+label, 222, 999) == nil {
		t.Error("foreign fromguid accepted")
	}
	if ok("tank/shares/secret@"+label, 222, 0) == nil {
		t.Error("another dataset accepted")
	}
	if ok(ds+"@"+older, 222, 0) == nil {
		t.Error("name and guid of different snapshots accepted")
	}
}

func TestSendResumesOnlyItsOwnSnapshot(t *testing.T) {
	ds := "tank/shares/media"
	f := &sysexec.Fake{}
	f.On("zfs list -H -p -t snapshot -o name,guid,creation -d 1 "+ds, ds+"@"+label+"\t222\t1761560100\n"+ds+"@manual\t333\t1761560100\n")
	f.OnPrefix("zfs send -n -P -t ", sysexec.Result{Stdout: []byte("size\t99\n")})
	st := &fakeStarter{Output: []byte("s")}
	m := &Manager{Runner: f, Starter: st, Items: fakeItems{"share/media": ds}}
	good := makeToken(tokenPairs(ds+"@"+label, 222, 0))
	res, r, err := m.Send(context.Background(), SendArgs{Task: "abc123", Kind: KindShare, ID: "media", Token: good})
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	if res.Snapshot != label || res.Estimate != 99 || strings.Join(st.Calls()[0], " ") != "zfs send -t "+good {
		t.Fatalf("%+v %v", res, st.Calls())
	}
	// A user snapshot's GUID in a token naming this task's snapshot.
	if _, _, err := m.Send(context.Background(), SendArgs{Task: "abc123", Kind: KindShare, ID: "media", Token: makeToken(tokenPairs(ds+"@"+label, 333, 0))}); err == nil {
		t.Fatal("a token for another snapshot was sent")
	}
	if len(st.Calls()) != 1 {
		t.Fatal("zfs ran for a refused token")
	}
}
