package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

// ShardManifest flag bits.
const (
	// ShardManifestFlagGroupsValid indicates the trailing payload encodes a
	// valid joined-groups list or bitmap (per BitmapBytes / GroupCount).
	ShardManifestFlagGroupsValid byte = 1 << 0

	// ShardManifestFlagAuthoritative marks the announcer as an operator-curated
	// authoritative source (see BRC-137 safety guidance).
	ShardManifestFlagAuthoritative byte = 1 << 1

	// ShardManifestFlagShutdown marks the final announcement before a graceful
	// shutdown; consumers MAY evict the corresponding registry entry immediately.
	ShardManifestFlagShutdown byte = 1 << 2
)

// RoleHint values for ShardManifest.RoleHint.
const (
	RoleHintGeneric       byte = 0
	RoleHintProxy         byte = 1
	RoleHintListener      byte = 2
	RoleHintRetryEndpoint byte = 3
	RoleHintProducer      byte = 4
	RoleHintManifestOnly  byte = 5
)

// MaxShardBits is the maximum permitted ShardBits value (per BRC-129).
const MaxShardBits = 12

// crc32cTable is the Castagnoli CRC32 table used for ShardManifest.ManifestCRC.
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// Sentinel errors returned by ShardManifest encode/decode helpers.
var (
	// ErrShardManifestTooShort is returned when the buffer is shorter than
	// [ShardManifestHeaderSize].
	ErrShardManifestTooShort = errors.New("shard_manifest: datagram shorter than header")

	// ErrShardManifestBadMsgType is returned when the MsgType byte is not
	// [MsgTypeShardManifest].
	ErrShardManifestBadMsgType = errors.New("shard_manifest: unexpected MsgType")

	// ErrShardManifestBadShardBits is returned when ShardBits exceeds
	// [MaxShardBits].
	ErrShardManifestBadShardBits = errors.New("shard_manifest: ShardBits exceeds maximum")

	// ErrShardManifestBadEncoding is returned when the payload encoding rules
	// are violated (both list and bitmap set, or GroupsValid without payload,
	// or list not sorted/unique).
	ErrShardManifestBadEncoding = errors.New("shard_manifest: invalid payload encoding")

	// ErrShardManifestTruncated is returned when the trailing payload is
	// shorter than declared by GroupCount or BitmapBytes.
	ErrShardManifestTruncated = errors.New("shard_manifest: trailing payload truncated")

	// ErrShardManifestBadCRC is returned when ManifestCRC verification fails.
	ErrShardManifestBadCRC = errors.New("shard_manifest: CRC mismatch")
)

// ShardManifest is the in-memory representation of a BRC-137 ShardManifest
// datagram. It advertises a participant's shard_bits configuration and
// optional joined-groups claim.
//
// Either Groups or Bitmap (not both) carries the joined-groups payload when
// Flags has [ShardManifestFlagGroupsValid] set:
//
//   - List form: Groups holds a sorted, unique slice of 16-bit group indices.
//     Bitmap MUST be nil/empty.
//   - Bitmap form: Bitmap holds a byte slice; bit position i (LSB-first within
//     each byte) indicates membership in group i. Groups MUST be nil/empty.
//
// When [ShardManifestFlagGroupsValid] is clear, both Groups and Bitmap MUST
// be empty (identity-only manifest).
type ShardManifest struct {
	Flags            byte
	SrcIPv6          [16]byte
	InstanceID       uint32
	Epoch            uint32
	TTL              uint16
	AnnounceInterval uint16
	ShardBits        uint8
	RoleHint         uint8
	GenerationID     [16]byte
	Groups           []uint16
	Bitmap           []byte
}

// ShardManifestSize returns the total wire size of m, including header and
// trailing payload.
func ShardManifestSize(m *ShardManifest) int {
	if m.Flags&ShardManifestFlagGroupsValid == 0 {
		return ShardManifestHeaderSize
	}
	if len(m.Bitmap) > 0 {
		return ShardManifestHeaderSize + len(m.Bitmap)
	}
	return ShardManifestHeaderSize + 2*len(m.Groups)
}

// EncodeShardManifest serialises m into buf. It returns the number of bytes
// written. buf must be at least [ShardManifestSize](m) bytes long.
//
// Encode validates ShardBits and the encoding-form rules (see [ShardManifest]).
// Groups, when non-empty, MUST be sorted ascending with no duplicates.
func EncodeShardManifest(m *ShardManifest, buf []byte) (int, error) {
	if m.ShardBits > MaxShardBits {
		return 0, fmt.Errorf("%w: got %d, max %d", ErrShardManifestBadShardBits, m.ShardBits, MaxShardBits)
	}

	groupsValid := m.Flags&ShardManifestFlagGroupsValid != 0
	hasList := len(m.Groups) > 0
	hasBitmap := len(m.Bitmap) > 0

	if !groupsValid && (hasList || hasBitmap) {
		return 0, fmt.Errorf("%w: payload present but GroupsValid=0", ErrShardManifestBadEncoding)
	}
	if groupsValid && hasList && hasBitmap {
		return 0, fmt.Errorf("%w: both list and bitmap present", ErrShardManifestBadEncoding)
	}
	if groupsValid && !hasList && !hasBitmap {
		return 0, fmt.Errorf("%w: GroupsValid=1 but no payload", ErrShardManifestBadEncoding)
	}
	if hasList {
		for i := 1; i < len(m.Groups); i++ {
			if m.Groups[i] <= m.Groups[i-1] {
				return 0, fmt.Errorf("%w: list not sorted/unique at index %d", ErrShardManifestBadEncoding, i)
			}
		}
		if len(m.Groups) > 0xFFFF {
			return 0, fmt.Errorf("%w: list exceeds 65535 entries", ErrShardManifestBadEncoding)
		}
	}
	if hasBitmap && len(m.Bitmap) > 0xFFFF {
		return 0, fmt.Errorf("%w: bitmap exceeds 65535 bytes", ErrShardManifestBadEncoding)
	}

	total := ShardManifestSize(m)
	if len(buf) < total {
		return 0, fmt.Errorf("shard_manifest: buffer too small (%d bytes, need %d)", len(buf), total)
	}

	binary.BigEndian.PutUint32(buf[0:4], MagicBSV)
	binary.BigEndian.PutUint16(buf[4:6], ProtoVer)
	buf[6] = MsgTypeShardManifest
	buf[7] = m.Flags
	copy(buf[8:24], m.SrcIPv6[:])
	binary.BigEndian.PutUint32(buf[24:28], m.InstanceID)
	binary.BigEndian.PutUint32(buf[28:32], m.Epoch)
	binary.BigEndian.PutUint16(buf[32:34], m.TTL)
	binary.BigEndian.PutUint16(buf[34:36], m.AnnounceInterval)
	buf[36] = m.ShardBits
	buf[37] = m.RoleHint

	var groupCount, bitmapBytes uint16
	switch {
	case hasBitmap:
		bitmapBytes = uint16(len(m.Bitmap))
	case hasList:
		groupCount = uint16(len(m.Groups))
	}
	binary.BigEndian.PutUint16(buf[38:40], groupCount)
	binary.BigEndian.PutUint16(buf[40:42], bitmapBytes)
	buf[42] = 0
	buf[43] = 0
	// CRC field at [44:48] zeroed for now; computed below.
	buf[44] = 0
	buf[45] = 0
	buf[46] = 0
	buf[47] = 0
	copy(buf[48:64], m.GenerationID[:])

	switch {
	case hasBitmap:
		copy(buf[ShardManifestHeaderSize:total], m.Bitmap)
	case hasList:
		off := ShardManifestHeaderSize
		for _, g := range m.Groups {
			binary.BigEndian.PutUint16(buf[off:off+2], g)
			off += 2
		}
	}

	crc := crc32.Checksum(buf[:total], crc32cTable)
	binary.BigEndian.PutUint32(buf[44:48], crc)
	return total, nil
}

// DecodeShardManifest parses a ShardManifest datagram from buf. The returned
// ShardManifest's Groups and Bitmap fields, when non-empty, are zero-copy
// slices over fresh allocations (Groups is parsed into a new []uint16; Bitmap
// is sliced from buf and the caller MUST NOT mutate buf while the returned
// value is in scope).
//
// Decode verifies magic, MsgType, ShardBits, encoding-form rules, payload
// length, and the ManifestCRC.
func DecodeShardManifest(buf []byte) (*ShardManifest, error) {
	if len(buf) < ShardManifestHeaderSize {
		return nil, ErrShardManifestTooShort
	}
	if magic := binary.BigEndian.Uint32(buf[0:4]); magic != MagicBSV {
		return nil, fmt.Errorf("%w: got 0x%08X", ErrBadMagic, magic)
	}
	if buf[6] != MsgTypeShardManifest {
		return nil, ErrShardManifestBadMsgType
	}

	m := &ShardManifest{
		Flags:            buf[7],
		InstanceID:       binary.BigEndian.Uint32(buf[24:28]),
		Epoch:            binary.BigEndian.Uint32(buf[28:32]),
		TTL:              binary.BigEndian.Uint16(buf[32:34]),
		AnnounceInterval: binary.BigEndian.Uint16(buf[34:36]),
		ShardBits:        buf[36],
		RoleHint:         buf[37],
	}
	copy(m.SrcIPv6[:], buf[8:24])
	copy(m.GenerationID[:], buf[48:64])

	if m.ShardBits > MaxShardBits {
		return nil, fmt.Errorf("%w: got %d, max %d", ErrShardManifestBadShardBits, m.ShardBits, MaxShardBits)
	}

	groupCount := binary.BigEndian.Uint16(buf[38:40])
	bitmapBytes := binary.BigEndian.Uint16(buf[40:42])
	groupsValid := m.Flags&ShardManifestFlagGroupsValid != 0

	switch {
	case !groupsValid:
		if groupCount != 0 || bitmapBytes != 0 {
			return nil, fmt.Errorf("%w: GroupsValid=0 but counts non-zero", ErrShardManifestBadEncoding)
		}
	case bitmapBytes > 0 && groupCount > 0:
		return nil, fmt.Errorf("%w: both bitmap and list non-zero", ErrShardManifestBadEncoding)
	case bitmapBytes == 0 && groupCount == 0:
		return nil, fmt.Errorf("%w: GroupsValid=1 but no payload", ErrShardManifestBadEncoding)
	}

	payloadLen := int(bitmapBytes)
	if payloadLen == 0 {
		payloadLen = 2 * int(groupCount)
	}
	total := ShardManifestHeaderSize + payloadLen
	if len(buf) < total {
		return nil, ErrShardManifestTruncated
	}

	// Verify CRC (zero the field locally).
	wantCRC := binary.BigEndian.Uint32(buf[44:48])
	tmp := make([]byte, total)
	copy(tmp, buf[:total])
	tmp[44] = 0
	tmp[45] = 0
	tmp[46] = 0
	tmp[47] = 0
	if got := crc32.Checksum(tmp, crc32cTable); got != wantCRC {
		return nil, fmt.Errorf("%w: got 0x%08X, want 0x%08X", ErrShardManifestBadCRC, got, wantCRC)
	}

	switch {
	case bitmapBytes > 0:
		m.Bitmap = buf[ShardManifestHeaderSize:total]
	case groupCount > 0:
		groups := make([]uint16, groupCount)
		off := ShardManifestHeaderSize
		var prev uint16
		for i := range groups {
			g := binary.BigEndian.Uint16(buf[off : off+2])
			if i > 0 && g <= prev {
				return nil, fmt.Errorf("%w: list not sorted/unique at index %d", ErrShardManifestBadEncoding, i)
			}
			groups[i] = g
			prev = g
			off += 2
		}
		m.Groups = groups
	}

	return m, nil
}

// IsShardManifest reports whether buf begins with a valid BRC-137 ShardManifest
// header (magic + MsgType == 0x40) without performing a full decode. It returns
// false for any buffer shorter than [ShardManifestHeaderSize].
func IsShardManifest(buf []byte) bool {
	if len(buf) < ShardManifestHeaderSize {
		return false
	}
	if binary.BigEndian.Uint32(buf[0:4]) != MagicBSV {
		return false
	}
	return buf[6] == MsgTypeShardManifest
}
