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

	// ShardManifestFlagDomainsValid indicates the datagram carries a BRC-148
	// Domains descriptor section appended after the groups, sources, and
	// top-level Successor payloads. This is the final unallocated BRC-139 flag
	// bit; all subsequent per-domain extensions ride the descriptor's own
	// Version field instead of new top-level flags.
	ShardManifestFlagDomainsValid byte = 1 << 7
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
	// RoleHintProducerBEEF hints the announcer publishes BEEF-plane objects
	// (BRC-148). Informational only — never a routing/filtering input.
	RoleHintProducerBEEF byte = 6
	// RoleHintListenerBEEF hints the announcer subscribes to BEEF-plane
	// groups (BRC-148). Informational only.
	RoleHintListenerBEEF byte = 7
)

// MaxShardBits is the maximum permitted ShardBits value (per BRC-129).
const MaxShardBits = 12

// BRC-148 Domains section constants.
const (
	// DomainDescriptorSize is a Domain Descriptor's fixed 24-byte core; a
	// descriptor with DomainFlagSuccessorValid is followed by a further
	// [SuccessorBlockSize] bytes.
	DomainDescriptorSize = 24

	// MaxDomainDescriptors bounds DomainCount (domains 0x00–0x0E).
	MaxDomainDescriptors = 15

	// MaxDomainID is the highest legal Domain Descriptor DomainID; 0x0F is
	// forbidden (its slot overlaps the BRC-129 control plane).
	MaxDomainID = 0x0E

	// MaxPlaneShardBits caps a non-zero domain's ShardBits (wide planes,
	// BRC-148); domain 0x00 retains the BRC-129 cap [MaxShardBits].
	MaxPlaneShardBits = 15

	// domainControlBase is the first control-plane index; every plane's
	// address range must satisfy planeBase + 2^ShardBits ≤ this bound.
	domainControlBase = 0xF800
)

// DomainDescriptor flag bits ([DomainDescriptor.Flags]).
const (
	// DomainFlagSourceModeSSM declares this plane's data plane uses SSM
	// (FF3x addressing).
	DomainFlagSourceModeSSM byte = 1 << 0
	// DomainFlagSuccessorValid indicates a 24-byte Successor block follows
	// this descriptor's core.
	DomainFlagSuccessorValid byte = 1 << 1
	// DomainFlagActive marks the announcer as publishing and/or serving this
	// plane (the authoritative per-domain participation signal).
	DomainFlagActive byte = 1 << 2
)

// DomainDescriptor is one BRC-148 per-plane entry in a manifest's Domains
// section: the plane's shard-bit width, slot reservation, mode flags, and
// generation — the per-domain analogue of the manifest's top-level
// ShardBits/GenerationID/Successor.
type DomainDescriptor struct {
	DomainID     uint8    // plane selector, 0x00–0x0E
	ShardBits    uint8    // this plane's width (domain 0: ≤ 12; others: ≤ 15)
	SlotSpan     uint8    // contiguous 0x1000 slots reserved; ≥ ceil(2^ShardBits/4096)
	Flags        byte     // DomainFlag* bits
	Version      uint8    // descriptor format version; 0x00 in this revision
	GenerationID [16]byte // this plane's 128-bit generation id
	// Successor is non-nil iff Flags has [DomainFlagSuccessorValid]: an
	// in-flight generation transition for this plane, layout per the BRC-139
	// Successor block.
	Successor *SuccessorBlock
}

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

	// ErrShardManifestBadDomains is returned when the BRC-148 Domains section
	// fails validation: DomainsValid/section coherence, DomainCount out of
	// range, duplicate or forbidden DomainIDs, a plane range reaching the
	// control plane, SlotSpan below the implied span or overlapping another
	// descriptor's reservation, a domain-0 descriptor disagreeing with the
	// top-level fields, or an invalid per-domain successor.
	ErrShardManifestBadDomains = errors.New("shard_manifest: invalid domains section")
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

	// Domains is the BRC-148 per-plane descriptor section, appended after
	// the groups, sources, and top-level Successor payloads. Non-empty iff
	// [ShardManifestFlagDomainsValid] is set in Flags. The top-level
	// ShardBits/GenerationID/Successor remain authoritative for domain 0x00;
	// a domain-0 descriptor MAY appear but MUST agree with them.
	Domains []DomainDescriptor
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
	if m.Flags&ShardManifestFlagDomainsValid != 0 {
		size += 1 // DomainCount
		for i := range m.Domains {
			size += DomainDescriptorSize
			if m.Domains[i].Flags&DomainFlagSuccessorValid != 0 {
				size += SuccessorBlockSize
			}
		}
	}
	return size
}

// validateDomains enforces the BRC-148 Domains-section rules shared by
// encode and decode. topShardBits/topGeneration/authoritative come from the
// enclosing manifest.
func validateDomains(domains []DomainDescriptor, topShardBits uint8, topGeneration [16]byte, authoritative bool) error {
	if len(domains) == 0 || len(domains) > MaxDomainDescriptors {
		return fmt.Errorf("%w: descriptor count %d outside [1, %d]", ErrShardManifestBadDomains, len(domains), MaxDomainDescriptors)
	}
	var seen [MaxDomainID + 1]bool
	var slots [MaxDomainID + 1]uint8 // slot index → owning descriptor count
	for i := range domains {
		d := &domains[i]
		if d.DomainID > MaxDomainID {
			return fmt.Errorf("%w: DomainID 0x%X (0x0F forbidden)", ErrShardManifestBadDomains, d.DomainID)
		}
		if seen[d.DomainID] {
			return fmt.Errorf("%w: duplicate DomainID 0x%X", ErrShardManifestBadDomains, d.DomainID)
		}
		seen[d.DomainID] = true

		maxBits := uint8(MaxPlaneShardBits)
		if d.DomainID == 0 {
			maxBits = MaxShardBits
		}
		if d.ShardBits > maxBits {
			return fmt.Errorf("%w: domain 0x%X ShardBits %d exceeds %d", ErrShardManifestBadDomains, d.DomainID, d.ShardBits, maxBits)
		}
		if end := uint32(d.DomainID)<<12 + uint32(1)<<d.ShardBits; end > domainControlBase {
			return fmt.Errorf("%w: domain 0x%X range reaches control plane", ErrShardManifestBadDomains, d.DomainID)
		}

		implied := uint8(1)
		if d.ShardBits > 12 {
			implied = 1 << (d.ShardBits - 12)
		}
		if d.SlotSpan < implied {
			return fmt.Errorf("%w: domain 0x%X SlotSpan %d below implied %d", ErrShardManifestBadDomains, d.DomainID, d.SlotSpan, implied)
		}
		if int(d.DomainID)+int(d.SlotSpan) > MaxDomainID+1 {
			return fmt.Errorf("%w: domain 0x%X SlotSpan %d intrudes on slot 0xF", ErrShardManifestBadDomains, d.DomainID, d.SlotSpan)
		}
		for s := int(d.DomainID); s < int(d.DomainID)+int(d.SlotSpan); s++ {
			slots[s]++
			if slots[s] > 1 {
				return fmt.Errorf("%w: slot 0x%X reserved by more than one descriptor", ErrShardManifestBadDomains, s)
			}
		}

		if d.DomainID == 0 {
			if d.ShardBits != topShardBits || d.GenerationID != topGeneration {
				return fmt.Errorf("%w: domain-0 descriptor disagrees with top-level fields", ErrShardManifestBadDomains)
			}
		}

		hasSucc := d.Successor != nil
		flagSucc := d.Flags&DomainFlagSuccessorValid != 0
		if hasSucc != flagSucc {
			return fmt.Errorf("%w: domain 0x%X successor/flag mismatch", ErrShardManifestBadDomains, d.DomainID)
		}
		if hasSucc {
			if !authoritative {
				return fmt.Errorf("%w: domain 0x%X successor requires Authoritative=1", ErrShardManifestBadDomains, d.DomainID)
			}
			if d.Successor.ShardBits > maxBits {
				return fmt.Errorf("%w: domain 0x%X successor ShardBits %d exceeds %d", ErrShardManifestBadDomains, d.DomainID, d.Successor.ShardBits, maxBits)
			}
			if !withinOneBit(d.ShardBits, d.Successor.ShardBits) {
				return fmt.Errorf("%w: domain 0x%X |successor-active| ShardBits > 1", ErrShardManifestBadDomains, d.DomainID)
			}
			if end := uint32(d.DomainID)<<12 + uint32(1)<<d.Successor.ShardBits; end > domainControlBase {
				return fmt.Errorf("%w: domain 0x%X successor range reaches control plane", ErrShardManifestBadDomains, d.DomainID)
			}
		}
	}
	return nil
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

	domainsValid := m.Flags&ShardManifestFlagDomainsValid != 0
	hasDomains := len(m.Domains) > 0
	if domainsValid && !hasDomains {
		return 0, fmt.Errorf("%w: DomainsValid=1 but no descriptors", ErrShardManifestBadDomains)
	}
	if !domainsValid && hasDomains {
		return 0, fmt.Errorf("%w: descriptors present but DomainsValid=0", ErrShardManifestBadDomains)
	}
	if domainsValid {
		if err := validateDomains(m.Domains, m.ShardBits, m.GenerationID,
			m.Flags&ShardManifestFlagAuthoritative != 0); err != nil {
			return 0, err
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
		off += SuccessorBlockSize
	}

	if domainsValid {
		buf[off] = byte(len(m.Domains))
		off++
		for i := range m.Domains {
			d := &m.Domains[i]
			buf[off] = d.DomainID
			buf[off+1] = d.ShardBits
			buf[off+2] = d.SlotSpan
			buf[off+3] = d.Flags
			buf[off+4] = d.Version
			buf[off+5] = 0 // Reserved: zero on send, ignored on receive
			buf[off+6] = 0
			buf[off+7] = 0
			copy(buf[off+8:off+24], d.GenerationID[:])
			off += DomainDescriptorSize
			if d.Successor != nil {
				copy(buf[off:off+16], d.Successor.GenerationID[:])
				buf[off+16] = d.Successor.ShardBits
				buf[off+17] = d.Successor.Flags
				buf[off+18] = 0
				buf[off+19] = 0
				binary.BigEndian.PutUint32(buf[off+20:off+24], d.Successor.TransitionEpoch)
				off += SuccessorBlockSize
			}
		}
	}
	_ = off // future payload sections append here

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

	// The Domains section's length is data-dependent (per-descriptor
	// successor flags), so pre-scan it to establish the datagram extent
	// before CRC verification.
	domainsValid := m.Flags&ShardManifestFlagDomainsValid != 0
	if domainsValid {
		if len(buf) < total+1 {
			return nil, ErrShardManifestTruncated
		}
		count := int(buf[total])
		if count < 1 || count > MaxDomainDescriptors {
			return nil, fmt.Errorf("%w: descriptor count %d outside [1, %d]",
				ErrShardManifestBadDomains, count, MaxDomainDescriptors)
		}
		scan := total + 1
		for i := 0; i < count; i++ {
			if len(buf) < scan+DomainDescriptorSize {
				return nil, ErrShardManifestTruncated
			}
			scan += DomainDescriptorSize
			if buf[scan-DomainDescriptorSize+3]&DomainFlagSuccessorValid != 0 {
				scan += SuccessorBlockSize
			}
		}
		if len(buf) < scan {
			return nil, ErrShardManifestTruncated
		}
		total = scan
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
		off += SuccessorBlockSize
	}

	if domainsValid {
		count := int(buf[off])
		off++
		domains := make([]DomainDescriptor, 0, count)
		for i := 0; i < count; i++ {
			d := DomainDescriptor{
				DomainID:  buf[off],
				ShardBits: buf[off+1],
				SlotSpan:  buf[off+2],
				Flags:     buf[off+3],
				Version:   buf[off+4],
				// Reserved bytes [5:8] ignored on receive.
			}
			copy(d.GenerationID[:], buf[off+8:off+24])
			off += DomainDescriptorSize
			if d.Flags&DomainFlagSuccessorValid != 0 {
				s := &SuccessorBlock{
					ShardBits:       buf[off+16],
					Flags:           buf[off+17],
					TransitionEpoch: binary.BigEndian.Uint32(buf[off+20 : off+24]),
				}
				copy(s.GenerationID[:], buf[off:off+16])
				d.Successor = s
				off += SuccessorBlockSize
			}
			domains = append(domains, d)
		}
		if err := validateDomains(domains, m.ShardBits, m.GenerationID,
			m.Flags&ShardManifestFlagAuthoritative != 0); err != nil {
			return nil, err
		}
		m.Domains = domains
	}
	_ = off // future payload sections parse from here

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
