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
	// authoritative source (see BRC-139 safety guidance).
	ShardManifestFlagAuthoritative byte = 1 << 1

	// ShardManifestFlagShutdown marks the final announcement before a graceful
	// shutdown; consumers MAY evict the corresponding registry entry immediately.
	ShardManifestFlagShutdown byte = 1 << 2

	// ShardManifestFlagSourceModeSSM declares the data plane uses
	// Source-Specific Multicast (FF3x::/32 per RFC 4607). Auto-configuration
	// consumers MUST use the SSM prefix when computing data-plane group
	// addresses derived from this manifest.
	ShardManifestFlagSourceModeSSM byte = 1 << 3

	// ShardManifestFlagSourcesValid indicates the trailing payload includes
	// SourceCount × 16 bytes of publisher source IPv6 addresses after the
	// groups payload. Consumers union the source set across all
	// currently-valid manifests they hold.
	ShardManifestFlagSourcesValid byte = 1 << 4

	// ShardManifestFlagPilotOnly marks the manifest as exclusively a
	// pilot/assignment broadcast: the announcer is not itself joined to the
	// announced groups and the groups payload describes desired fleet state,
	// not its own joins. Implies Authoritative=1; per BRC-139 consumers MUST
	// reject PilotOnly=1 && Authoritative=0 as malformed (this decoder does
	// not enforce the rejection — it is the consumer's responsibility).
	ShardManifestFlagPilotOnly byte = 1 << 5

	// ShardManifestFlagSuccessorValid indicates the trailing payload includes
	// a 24-byte Successor block describing an in-flight generation transition
	// (BRC-139 §Successor block). The block lives immediately after the
	// sources payload. Requires Authoritative=1; consumers MUST reject
	// manifests with SuccessorValid=1 && Authoritative=0 as malformed.
	ShardManifestFlagSuccessorValid byte = 1 << 6
)

// SuccessorBlockSize is the fixed size of the BRC-139 Successor block.
const SuccessorBlockSize = 24

// SuccessorFlag bits for [SuccessorBlock.Flags].
const (
	// SuccessorFlagSourceModeSSM declares that the successor generation's
	// data plane uses Source-Specific Multicast. Mirrors
	// [ShardManifestFlagSourceModeSSM] but for the incoming generation.
	SuccessorFlagSourceModeSSM byte = 1 << 0
)

// SuccessorBlock describes the incoming generation in a BRC-139
// generation-transition signal. Encoded as 24 bytes immediately after the
// sources payload when [ShardManifestFlagSuccessorValid] is set.
type SuccessorBlock struct {
	// GenerationID is the incoming generation's 128-bit identifier.
	GenerationID [16]byte
	// ShardBits is the incoming generation's shard-bit width. The pilot
	// MUST keep |ShardBits - active ShardBits| ≤ 1.
	ShardBits uint8
	// Flags carry per-successor mode bits (currently only
	// [SuccessorFlagSourceModeSSM]).
	Flags uint8
	// TransitionEpoch is the Unix-seconds time at which the successor
	// becomes the sole active generation. Bridging consumers exit the
	// bridging window when local_clock >= TransitionEpoch.
	TransitionEpoch uint32
}

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

	// ErrShardManifestBadSources is returned when SourcesValid / SourceCount
	// coherence rules are violated (BRC-139 §Sources payload), e.g.
	// SourcesValid=1 with SourceCount=0, or SourcesValid=0 with SourceCount>0.
	ErrShardManifestBadSources = errors.New("shard_manifest: invalid sources encoding")

	// ErrShardManifestBadSuccessor is returned when the Successor block fails
	// BRC-139 validation: SuccessorValid set without an accompanying
	// SuccessorBlock, SuccessorBlock set without the flag, the announcer is
	// not Authoritative, or the successor's ShardBits differs from the
	// announcer's by more than ±1.
	ErrShardManifestBadSuccessor = errors.New("shard_manifest: invalid successor block")
)

// ShardManifest is the in-memory representation of a BRC-139 ShardManifest
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
//
// Sources, when non-empty, carries the publisher source IPv6 addresses
// contributed by this announcer (BRC-139 §Sources payload). It is encoded
// as the trailing K × 16 bytes of the datagram, appearing after the
// groups payload. [ShardManifestFlagSourcesValid] MUST be set when
// Sources is non-empty and MUST be clear when Sources is empty.
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
	Sources          [][16]byte

	// Successor describes an in-flight generation transition (BRC-139
	// §Successor block). Non-nil iff [ShardManifestFlagSuccessorValid] is
	// set in Flags. Decode rejects datagrams that violate the coherence or
	// ±1 ShardBits-shift rules.
	Successor *SuccessorBlock
}

// ShardManifestSize returns the total wire size of m, including header,
// groups payload, sources payload, and successor block (if present).
func ShardManifestSize(m *ShardManifest) int {
	size := ShardManifestHeaderSize
	if m.Flags&ShardManifestFlagGroupsValid != 0 {
		if len(m.Bitmap) > 0 {
			size += len(m.Bitmap)
		} else {
			size += 2 * len(m.Groups)
		}
	}
	size += 16 * len(m.Sources)
	if m.Flags&ShardManifestFlagSuccessorValid != 0 {
		size += SuccessorBlockSize
	}
	return size
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

	sourcesValid := m.Flags&ShardManifestFlagSourcesValid != 0
	hasSources := len(m.Sources) > 0
	if sourcesValid && !hasSources {
		return 0, fmt.Errorf("%w: SourcesValid=1 but no sources", ErrShardManifestBadSources)
	}
	if !sourcesValid && hasSources {
		return 0, fmt.Errorf("%w: sources present but SourcesValid=0", ErrShardManifestBadSources)
	}
	if hasSources && len(m.Sources) > 0xFFFF {
		return 0, fmt.Errorf("%w: sources list exceeds 65535 entries", ErrShardManifestBadSources)
	}

	successorValid := m.Flags&ShardManifestFlagSuccessorValid != 0
	hasSuccessor := m.Successor != nil
	if successorValid && !hasSuccessor {
		return 0, fmt.Errorf("%w: SuccessorValid=1 but no Successor block", ErrShardManifestBadSuccessor)
	}
	if !successorValid && hasSuccessor {
		return 0, fmt.Errorf("%w: Successor present but SuccessorValid=0", ErrShardManifestBadSuccessor)
	}
	if successorValid {
		if m.Flags&ShardManifestFlagAuthoritative == 0 {
			return 0, fmt.Errorf("%w: SuccessorValid=1 requires Authoritative=1", ErrShardManifestBadSuccessor)
		}
		if m.Successor.ShardBits > MaxShardBits {
			return 0, fmt.Errorf("%w: successor ShardBits %d exceeds maximum %d",
				ErrShardManifestBadSuccessor, m.Successor.ShardBits, MaxShardBits)
		}
		if !withinOneBit(m.ShardBits, m.Successor.ShardBits) {
			return 0, fmt.Errorf("%w: |successor.ShardBits-active.ShardBits|>1 (%d vs %d)",
				ErrShardManifestBadSuccessor, m.Successor.ShardBits, m.ShardBits)
		}
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
	binary.BigEndian.PutUint16(buf[42:44], uint16(len(m.Sources)))
	// CRC field at [44:48] zeroed for now; computed below.
	buf[44] = 0
	buf[45] = 0
	buf[46] = 0
	buf[47] = 0
	copy(buf[48:64], m.GenerationID[:])

	off := ShardManifestHeaderSize
	switch {
	case hasBitmap:
		copy(buf[off:off+len(m.Bitmap)], m.Bitmap)
		off += len(m.Bitmap)
	case hasList:
		for _, g := range m.Groups {
			binary.BigEndian.PutUint16(buf[off:off+2], g)
			off += 2
		}
	}
	for _, src := range m.Sources {
		copy(buf[off:off+16], src[:])
		off += 16
	}

	if successorValid {
		copy(buf[off:off+16], m.Successor.GenerationID[:])
		buf[off+16] = m.Successor.ShardBits
		buf[off+17] = m.Successor.Flags
		buf[off+18] = 0 // Reserved
		buf[off+19] = 0
		binary.BigEndian.PutUint32(buf[off+20:off+24], m.Successor.TransitionEpoch)
		// off is no longer used after this point but reserved for future
		// payload sections; leave the increment elided to satisfy ineffassign.
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
	sourceCount := binary.BigEndian.Uint16(buf[42:44])
	groupsValid := m.Flags&ShardManifestFlagGroupsValid != 0
	sourcesValid := m.Flags&ShardManifestFlagSourcesValid != 0

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

	switch {
	case sourcesValid && sourceCount == 0:
		return nil, fmt.Errorf("%w: SourcesValid=1 but SourceCount=0", ErrShardManifestBadSources)
	case !sourcesValid && sourceCount > 0:
		return nil, fmt.Errorf("%w: SourcesValid=0 but SourceCount>0", ErrShardManifestBadSources)
	}

	successorValid := m.Flags&ShardManifestFlagSuccessorValid != 0
	if successorValid && m.Flags&ShardManifestFlagAuthoritative == 0 {
		return nil, fmt.Errorf("%w: SuccessorValid=1 requires Authoritative=1", ErrShardManifestBadSuccessor)
	}

	groupsLen := int(bitmapBytes)
	if groupsLen == 0 {
		groupsLen = 2 * int(groupCount)
	}
	sourcesLen := 16 * int(sourceCount)
	successorLen := 0
	if successorValid {
		successorLen = SuccessorBlockSize
	}
	total := ShardManifestHeaderSize + groupsLen + sourcesLen + successorLen
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

	off := ShardManifestHeaderSize
	switch {
	case bitmapBytes > 0:
		m.Bitmap = buf[off : off+int(bitmapBytes)]
		off += int(bitmapBytes)
	case groupCount > 0:
		groups := make([]uint16, groupCount)
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

	if sourceCount > 0 {
		sources := make([][16]byte, sourceCount)
		for i := range sources {
			copy(sources[i][:], buf[off:off+16])
			off += 16
		}
		m.Sources = sources
	}

	if successorValid {
		s := &SuccessorBlock{
			ShardBits:       buf[off+16],
			Flags:           buf[off+17],
			TransitionEpoch: binary.BigEndian.Uint32(buf[off+20 : off+24]),
		}
		copy(s.GenerationID[:], buf[off:off+16])
		// Reserved bytes [18:20] are ignored on receive per BRC-139 forward-
		// compatibility; producers MUST set them to zero (enforced in encode).
		if s.ShardBits > MaxShardBits {
			return nil, fmt.Errorf("%w: successor ShardBits %d exceeds maximum %d",
				ErrShardManifestBadSuccessor, s.ShardBits, MaxShardBits)
		}
		if !withinOneBit(m.ShardBits, s.ShardBits) {
			return nil, fmt.Errorf("%w: |successor.ShardBits-active.ShardBits|>1 (%d vs %d)",
				ErrShardManifestBadSuccessor, s.ShardBits, m.ShardBits)
		}
		m.Successor = s
		// off is no longer used after the successor block — kept for
		// future payload-section extensions; do not increment to avoid
		// ineffassign.
	}

	return m, nil
}

// withinOneBit reports whether |a-b| ≤ 1. Used to enforce the BRC-139
// Successor-block constraint that the incoming generation's ShardBits
// differs from the active one by at most ±1.
func withinOneBit(a, b uint8) bool {
	if a > b {
		return a-b <= 1
	}
	return b-a <= 1
}

// IsShardManifest reports whether buf begins with a valid BRC-139 ShardManifest
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
