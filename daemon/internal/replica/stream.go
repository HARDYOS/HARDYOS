package replica

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// A zfs send stream starts with a DRR_BEGIN record (OpenZFS
// include/sys/zfs_ioctl.h, struct dmu_replay_record): 312 bytes, in the
// sending machine's byte order.
//
//	0   uint32 drr_type (DRR_BEGIN = 0)
//	4   uint32 drr_payloadlen
//	8   uint64 drr_magic (0x2F5bacbac)
//	16  uint64 drr_versioninfo: bits 0-1 header type, 2-31 feature flags
//	24  uint64 drr_creation_time
//	32  uint32 drr_type (objset type: 2 file system, 3 volume)
//	36  uint32 drr_flags
//	40  uint64 drr_toguid
//	48  uint64 drr_fromguid
//	56  char   drr_toname[256]
const BeginRecordSize = 312

const backupMagic = 0x2F5bacbac

// Header types.
const (
	hdrSubstream = 1 // one dataset: what HardyOS sends
	hdrCompound  = 2 // a "package" (-R, -I, -p, -h, -b): properties and several datasets
)

// Objset types.
const (
	ObjsetFilesystem = 2
	ObjsetVolume     = 3
)

// Feature flags (DMU_BACKUP_FEATURE_*).
const (
	FeatureDedup           = 1 << 0
	FeatureDedupProps      = 1 << 1
	FeatureSASpill         = 1 << 2
	FeatureEmbedData       = 1 << 16
	FeatureLZ4             = 1 << 17
	FeatureLargeBlocks     = 1 << 19
	FeatureResuming        = 1 << 20
	FeatureRedacted        = 1 << 21
	FeatureCompressed      = 1 << 22
	FeatureLargeDnode      = 1 << 23
	FeatureRaw             = 1 << 24
	FeatureZstd            = 1 << 25
	FeatureHolds           = 1 << 26
	FeatureSwitchToLarge   = 1 << 27
	FeatureLongName        = 1 << 28
	FeatureLargeMicrozap   = 1 << 29
	drrFlagClone           = 1 << 0
	allowedFeatures        = FeatureSASpill | FeatureEmbedData | FeatureLZ4 | FeatureLargeBlocks | FeatureResuming | FeatureCompressed | FeatureLargeDnode | FeatureZstd | FeatureSwitchToLarge | FeatureLongName | FeatureLargeMicrozap
	featureNamesUnknownTag = "unknown"
)

// Begin is what HardyOS reads from a stream's first record.
type Begin struct {
	Header   int    // 1 substream, 2 compound
	Features uint32 // feature flags
	Objset   uint32 // 2 file system, 3 volume
	Flags    uint32
	ToGUID   uint64
	FromGUID uint64
	ToName   string // dataset@snapshot on the sender
	Payload  uint32
}

// Incremental reports whether the stream needs an earlier snapshot.
func (b *Begin) Incremental() bool { return b.FromGUID != 0 }

// Resuming reports whether the stream continues an interrupted one.
func (b *Begin) Resuming() bool { return b.Features&FeatureResuming != 0 }

// Label is the snapshot part of ToName.
func (b *Begin) Label() string {
	_, l, _ := strings.Cut(b.ToName, "@")
	return l
}

// ParseBegin reads the first record of a stream.
func ParseBegin(rec []byte) (*Begin, error) {
	if len(rec) < BeginRecordSize {
		return nil, invalid("the stream ended before its first record")
	}
	var bo binary.ByteOrder
	switch {
	case binary.LittleEndian.Uint64(rec[8:]) == backupMagic:
		bo = binary.LittleEndian
	case binary.BigEndian.Uint64(rec[8:]) == backupMagic:
		bo = binary.BigEndian
	default:
		return nil, invalid("not a ZFS stream")
	}
	if t := bo.Uint32(rec[0:]); t != 0 {
		return nil, invalid("the stream doesn't start with a BEGIN record")
	}
	vi := bo.Uint64(rec[16:])
	b := &Begin{
		Header:   int(vi & 3),
		Features: uint32((vi >> 2) & (1<<30 - 1)),
		Payload:  bo.Uint32(rec[4:]),
		Objset:   bo.Uint32(rec[32:]),
		Flags:    bo.Uint32(rec[36:]),
		ToGUID:   bo.Uint64(rec[40:]),
		FromGUID: bo.Uint64(rec[48:]),
	}
	name := rec[56:BeginRecordSize]
	if i := indexByte(name, 0); i >= 0 {
		name = name[:i]
	} else {
		return nil, invalid("the stream's snapshot name isn't terminated")
	}
	b.ToName = string(name)
	return b, nil
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// MaxBeginPayload bounds the payload after the first record (a resumed
// stream's small nvlist; never a package's property list).
const MaxBeginPayload = 1 << 20

// Policy says which streams a receive accepts.
type Policy struct {
	// AllowRaw accepts raw (still encrypted, `zfs send -w`) streams. Off
	// for now: nothing sends them yet.
	AllowRaw bool
	// Label is the snapshot the stream must carry (ToName's part after @).
	Label string
	// Objset, when not 0, is the type the target already has.
	Objset uint32
	// Incremental: the target exists, so the stream must build on it
	// (or resume); a full stream is only accepted for a new target.
	Incremental bool
}

// Check refuses streams HardyOS never sends: packages (-R/-I/-p/-h: they
// carry properties and other datasets), dedup and redacted streams,
// holds, clones, raw streams unless allowed, unknown features, and
// anything not for the snapshot asked for.
func (p Policy) Check(b *Begin) error {
	if b.Payload > MaxBeginPayload {
		return invalid("the stream's first record carries %d bytes; at most %d are accepted", b.Payload, MaxBeginPayload)
	}
	if b.Header != hdrSubstream {
		if b.Header == hdrCompound {
			return invalid("the stream is a package of several datasets or carries properties (zfs send -R/-I/-p); only single-dataset streams are accepted")
		}
		return invalid("unknown stream header type %d", b.Header)
	}
	allowed := uint32(allowedFeatures)
	if p.AllowRaw {
		allowed |= FeatureRaw
	}
	if bad := b.Features &^ allowed; bad != 0 {
		return invalid("the stream uses features that aren't accepted: %s", FeatureNames(bad))
	}
	if b.Flags&drrFlagClone != 0 {
		return invalid("clone streams aren't accepted")
	}
	if b.Objset != ObjsetFilesystem && b.Objset != ObjsetVolume {
		return invalid("the stream is of an unsupported dataset type (%d)", b.Objset)
	}
	if p.Objset != 0 && b.Objset != p.Objset {
		return invalid("the stream is a %s but the replica is a %s", objsetName(b.Objset), objsetName(p.Objset))
	}
	ds, label, ok := strings.Cut(b.ToName, "@")
	if !ok || ds == "" || label != p.Label {
		return invalid("the stream is for %q, not the snapshot %s", b.ToName, p.Label)
	}
	if p.Incremental && !b.Incremental() && !b.Resuming() {
		return invalid("the replica exists, so only an incremental stream can follow (no full stream over it)")
	}
	if !p.Incremental && b.Incremental() && !b.Resuming() {
		return invalid("an incremental stream needs an existing replica")
	}
	return nil
}

func objsetName(t uint32) string {
	switch t {
	case ObjsetFilesystem:
		return "file system"
	case ObjsetVolume:
		return "volume"
	}
	return fmt.Sprintf("type %d", t)
}

var featureNames = []struct {
	bit  uint32
	name string
}{
	{FeatureDedup, "dedup"}, {FeatureDedupProps, "dedupprops"}, {FeatureSASpill, "sa_spill"},
	{FeatureEmbedData, "embed_data"}, {FeatureLZ4, "lz4"}, {FeatureLargeBlocks, "large_blocks"},
	{FeatureResuming, "resuming"}, {FeatureRedacted, "redacted"}, {FeatureCompressed, "compressed"},
	{FeatureLargeDnode, "large_dnode"}, {FeatureRaw, "raw"}, {FeatureZstd, "zstd"}, {FeatureHolds, "holds"},
	{FeatureSwitchToLarge, "switch_to_large_blocks"}, {FeatureLongName, "longname"}, {FeatureLargeMicrozap, "large_microzap"},
}

// FeatureNames names feature bits.
func FeatureNames(bits uint32) string {
	var out []string
	for _, f := range featureNames {
		if bits&f.bit != 0 {
			out = append(out, f.name)
			bits &^= f.bit
		}
	}
	if bits != 0 {
		out = append(out, fmt.Sprintf("%s(0x%x)", featureNamesUnknownTag, bits))
	}
	return strings.Join(out, ", ")
}
