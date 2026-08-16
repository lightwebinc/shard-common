// Package frame defines the BSV-over-UDP BRC-12 (legacy), BRC-124/BRC-128,
// BRC-130 (fragmentation), BRC-131 (block control), BRC-132 (subtree data),
// BRC-134 (chained anchor transactions), and BRC-135 (block header) wire
// formats used by the BSV transaction sharding pipeline.
//
// # Wire format — BRC-12 (legacy, 44 bytes)
//
// All multi-byte integers are big-endian.
//
//	Offset  Size  Field            Value / notes
//	------  ----  -----            -------------
//	     0     4  Network magic    0xE3E1F3E8
//	     4     2  Protocol ver     0x02BF
//	     6     1  Frame version    0x01
//	     7     1  Reserved         0x00
//	     8    32  Transaction ID   raw 256-bit txid
//	    40     4  Payload length   uint32
//	    44     *  BSV tx payload
//
// # Wire format — BRC-124/BRC-128 (92 bytes)
//
// All multi-byte integers are big-endian.
//
//	Offset  Size  Align  Field          Value / notes
//	------  ----  -----  -----          -------------
//	     0     4   —     Network magic  0xE3E1F3E8 (BSV mainnet P2P magic)
//	     4     2   —     Protocol ver   0x02BF = 703 (BSV node version baseline)
//	     6     1   —     Frame version  0x02 (BRC-124/BRC-128)
//	     7     1   —     Reserved       0x00
//	     8    32   8B    TxID           raw 256-bit txid (NOT display-reversed)
//	    40     8   8B    HashKey        XXH64(senderIPv6 ∥ groupIdx ∥ subtreeID); stable per flow; 0 = unset
//	    48     8   8B    SeqNum         Monotonic counter per flow; 0 = unset/unstamped
//	    56    32   8B    SubtreeID      32-byte batch identifier; zeros = unset
//	    88     4   8B    PayloadLen     uint32 BE (fragment data length)
//	    92     *   —     Payload        raw serialised BSV transaction
//
// # Wire format — BRC-130 (104 bytes, fragmentation)
//
// Extends BRC-124 with a 12-byte fragment extension at bytes 92–103.
// Bytes 0–91 are layout-compatible with BRC-124 (same field offsets).
//
//	Offset  Size  Field          Value / notes
//	------  ----  -----          -------------
//	     0    92  (BRC-124 hdr)  Identical layout; FrameVer = 0x03; PayloadLen = fragment data size
//	    92     4  OrigPayloadLen Total unfragmented payload size (uint32 BE)
//	    96     2  FragIndex      0-based fragment index (uint16 BE)
//	    98     2  FragTotal      Total number of fragments (uint16 BE)
//	   100     1  OrigFrameVer   Original FrameVer (0x00/0x02=V2, 0x04=V4 block, 0x05=V5 subtree, 0x09=V9 BEEF)
//	   101     3  Reserved2      Must be 0x000000
//	   104     *  Fragment data
//
// Each fragment carries an independent HashKey and SeqNum stamped by the
// proxy. Listeners reassemble fragments keyed by TxID — except V9 (BRC-149
// BEEF) fragments, which key on the (ContentID, TopicID) pair as
// SHA-256(ContentID ∥ TopicID) — and verify
// SHA256d(reassembled payload) == TxID after completion (for V2 fragments).
// For V5 subtree-data fragments, SHA256d is not applicable; optional
// Merkle-root verification is used instead.
//
// # Wire format — BRC-132 (92 bytes, subtree data)
//
// BRC-132 uses the same 92-byte header layout as BRC-124 but with
// FrameVer 0x05 and a MsgType byte at offset 7.
//
//	Offset  Size  Align  Field          Value / notes
//	------  ----  -----  -----          -------------
//	     0     4   —     Network magic  0xE3E1F3E8
//	     4     2   —     Protocol ver   0x02BF
//	     6     1   —     Frame version  0x05 (BRC-132 subtree data)
//	     7     1   —     MsgType        0x01=HashesOnly, 0x02=FullNodes
//	     8    32   8B    SubtreeID      SHA-256 Merkle root hash (content + reassembly key)
//	    40     8   8B    HashKey        XXH64(senderIPv6 ∥ 0xFFFB ∥ subtreeID); stamped by proxy
//	    48     8   8B    SeqNum         Monotonic per-flow counter; 0 = unset/unstamped
//	    56    32   8B    LayoutPad32    All zeros (no secondary subtree ID; field kept for uniform HeaderSize)
//	    88     4   8B    PayloadLen     uint32 BE
//	    92     *   —     Payload        Subtree data (see SubtreeDataPayload)
//
// # HashKey and SeqNum
//
// HashKey is a stable per-flow identifier stamped by the proxy
// (shard-proxy) as XXH64(senderIPv6 ∥ groupIdx ∥ subtreeID). It is
// the same value for every frame in a (sender, group, subtree) flow.
// SeqNum is a per-flow monotonic counter starting at 1. Senders set both to 0;
// the proxy stamps them in-place before multicast forwarding. Gap detection
// is performed by listeners as SeqNum ≠ lastSeqNum+1.
//
// # BRC-12 handling
//
// [Decode] accepts BRC-12, BRC-124/BRC-128, and BRC-130 frames.
// BRC-12 frames are decoded into a [Frame] with [Version] = [FrameVerV1]
// and zero-valued BRC-124-only fields.
// BRC-130 fragment frames are decoded into a [FragFrame].
// Unknown versions return [ErrBadVer].
//
// # BSV transaction format compatibility
//
// The payload field carries a raw BSV transaction in the same serialisation
// format as the BSV P2P "tx" message payload: version (4 bytes LE), input
// vector, output vector, locktime (4 bytes LE). No P2P message envelope
// wraps it — the frame header above serves that role.
package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Wire format constants.
const (
	// MagicBSV is the BSV mainnet P2P network magic, used as the frame
	// identifier. Matches the first four bytes of every BSV P2P message.
	MagicBSV uint32 = 0xE3E1F3E8

	// ProtoVer is the protocol version field. 703 (0x02BF) is the BSV node
	// version baseline that introduced the large-block policy.
	ProtoVer uint16 = 0x02BF

	// FrameVerV1 is the legacy BRC-12 frame version (44-byte header). [Decode]
	// accepts BRC-12 frames and returns them with zero-valued BRC-124-only fields.
	FrameVerV1 byte = 0x01

	// FrameVerV2 is the current BRC-124/BRC-128 frame version.
	FrameVerV2 byte = 0x02

	// FrameVerV3 is the BRC-130 fragment frame version (104-byte header).
	// Each BRC-130 datagram carries one fragment of a larger payload.
	FrameVerV3 byte = 0x03

	// FrameVerV4 is the BRC-131 block control frame version (92-byte header,
	// layout-identical to BRC-124). Carried on the GroupBlockBroadcast multicast
	// group (FF0E::B:FFFE).
	FrameVerV4 byte = 0x04

	// FrameVerV5 is the BRC-132 subtree data frame version (92-byte header,
	// layout-identical to BRC-124). Carried on the GroupSubtreeDataAnnounce
	// multicast group (FF0X::B:FFFB).
	FrameVerV5 byte = 0x05

	// FrameVerV6 is the BRC-134 chained anchor transaction frame version
	// (92-byte header, layout-identical to BRC-124). Anchor transactions are
	// the root of a chain of dependent transactions and must reach every
	// subscriber regardless of shard assignment. Carried on the
	// GroupBlockBroadcast multicast group (FF0E::B:FFFE).
	FrameVerV6 byte = 0x06

	// FrameVerV7 is the BRC-135 block header frame version (92-byte header,
	// layout-identical to BRC-124, with a fixed 80-byte payload carrying a
	// raw BSV block header). Produced by emitters that strip the header from
	// a BRC-131 BlockAnnounce and re-emit it to a downstream egress channel
	// (typically GroupBlockHeader = 0xFFFA). BRC-135 frames are NOT
	// retransmitted via BRC-126 on the primary fabric.
	FrameVerV7 byte = 0x07

	// FrameVerV8 is the BRC-142 coalescing bundle frame version. A bundle has a
	// 66-byte header followed by a length-prefixed member section packing many
	// small transactions of one (group, subtree) flow into a single datagram.
	// It is not layout-compatible with BRC-124; decode it with the `bundle`
	// package. [Decode] returns [ErrBadVer] for 0x08, like other extension
	// versions, so single-transaction callers can distinguish it.
	FrameVerV8 byte = 0x08

	// FrameVerV9 is the BRC-149 BEEF object frame version (92-byte header,
	// layout-identical to BRC-124). ContentID (SHA-256d of the payload)
	// occupies the TxID slot and TopicID (SHA-256 of the overlay topic name)
	// occupies the SubtreeID slot. Carried on the BEEF object plane's
	// domain-tagged shard groups (IDX 0x1000 + shardIndex(TopicID)). Decode it
	// with [DecodeBEEF].
	FrameVerV9 byte = 0x09

	// BlockMsgAnnounce identifies a BlockAnnounce payload in a FrameVerV4 frame.
	// The payload carries the 80-byte block header, coinbase TxID, and subtree hashes.
	BlockMsgAnnounce byte = 0x01

	// BlockMsgCoinbase identifies a CoinbaseTx payload in a FrameVerV4 frame.
	// The payload carries the raw serialised coinbase transaction.
	BlockMsgCoinbase byte = 0x02

	// SubtreeMsgHashesOnly identifies a hashes-only subtree data payload in a
	// FrameVerV5 frame. Each node is represented as a 32-byte TxHash.
	SubtreeMsgHashesOnly byte = 0x01

	// SubtreeMsgFullNodes identifies a full-node subtree data payload in a
	// FrameVerV5 frame. Each node carries TxHash (32B) + Fee (8B) + Size (8B).
	SubtreeMsgFullNodes byte = 0x02

	// HeaderSizeLegacy is the fixed size of the legacy BRC-12 frame header.
	HeaderSizeLegacy = 44

	// HeaderSize is the total size of the BRC-124/BRC-128 frame header in bytes.
	// Payload begins at offset HeaderSize.
	HeaderSize = 92

	// HeaderSizeV3 is the total size of the BRC-130 fragment frame header in
	// bytes. Fragment data begins at offset HeaderSizeV3.
	HeaderSizeV3 = 104

	// MsgTypeNACK identifies a gap-retransmission request (BRC-126).
	MsgTypeNACK byte = 0x10

	// MsgTypeMISS identifies a "frame not in cache" response from a retry
	// endpoint (BRC-126).
	MsgTypeMISS byte = 0x11

	// MsgTypeACK identifies a "frame found, retransmit dispatched" response
	// from a retry endpoint (BRC-126).
	MsgTypeACK byte = 0x12

	// MsgTypeADVERT identifies a periodic beacon advertisement from a retry
	// endpoint (BRC-126).
	MsgTypeADVERT byte = 0x20

	// MsgTypeSubtreeGroupAnnounce identifies a BRC-127 subtree group announcement
	// datagram. Sent periodically by block assemblers to the
	// GroupSubtreeGroupAnnounce multicast group (0xFFFC).
	MsgTypeSubtreeGroupAnnounce byte = 0x30

	// SubtreeGroupAnnounceSize is the fixed wire size of a SubtreeGroupAnnounce datagram
	// in bytes.
	SubtreeGroupAnnounceSize = 64

	// MsgTypeShardManifest identifies a BRC-139 shard manifest announcement
	// datagram. Sent periodically by every multicast participant to the
	// GroupBeacon multicast group to advertise its shard_bits configuration
	// and the set of shard groups it has joined.
	MsgTypeShardManifest byte = 0x40

	// ShardManifestHeaderSize is the fixed size of the BRC-139 ShardManifest
	// datagram header in bytes. The trailing payload (joined-groups list or
	// bitmap) follows the header.
	ShardManifestHeaderSize = 64
)

// Sentinel errors returned by [Decode].
var (
	// ErrBadMagic is returned when the first four bytes do not match MagicBSV.
	ErrBadMagic = errors.New("frame: invalid BSV magic bytes")

	// ErrBadVer is returned when the frame version byte is not a known version.
	ErrBadVer = errors.New("frame: unsupported frame version")

	// ErrTooShort is returned when the datagram is shorter than the minimum
	// header size ([HeaderSizeLegacy] for BRC-12, [HeaderSize] for BRC-124/BRC-128,
	// [HeaderSizeV3] for BRC-130).
	ErrTooShort = errors.New("frame: datagram shorter than header")

	// ErrBadFrag is returned when a BRC-130 fragment has an invalid
	// FragIndex (≥ FragTotal) or FragTotal of zero.
	ErrBadFrag = errors.New("frame: invalid fragment index or total")

	// ErrBadBlockMsg is returned when a FrameVerV4 frame has an invalid
	// BlockMsgType (not BlockMsgAnnounce or BlockMsgCoinbase).
	ErrBadBlockMsg = errors.New("frame: invalid block message type")

	// ErrBadSubtreeMsg is returned when a FrameVerV5 frame has an invalid
	// MsgType (not SubtreeMsgHashesOnly or SubtreeMsgFullNodes).
	ErrBadSubtreeMsg = errors.New("frame: invalid subtree data message type")
)

// Frame is the parsed in-memory representation of a BRC-12 or BRC-124/BRC-128 BSV datagram.
//
// Payload is a zero-copy slice pointing into the buffer passed to [Decode];
// the buffer must remain valid for the lifetime of the Frame.
type Frame struct {
	Version   byte     // FrameVerV1, FrameVerV2, or FrameVerV6 — set by Decode / DecodeAnchor
	TxID      [32]byte // Raw 256-bit transaction ID (internal byte order)
	HashKey   uint64   // Stable per-flow identifier: XXH64(senderIPv6 ∥ groupIdx ∥ subtreeID); 0 = unset
	SeqNum    uint64   // Monotonic per-flow counter starting at 1; 0 = unset/unstamped
	SubtreeID [32]byte // 32-byte batch identifier; zeros = unset (always zero for BRC-12)
	Payload   []byte   // Raw serialised BSV transaction
}

// Encode serialises f into buf and returns the number of bytes written.
// buf must be at least HeaderSize + len(f.Payload) bytes long.
//
// Returns an error if buf is too small.
func Encode(f *Frame, buf []byte) (int, error) {
	total := HeaderSize + len(f.Payload)
	if len(buf) < total {
		return 0, fmt.Errorf("frame: buffer too small (%d bytes, need %d)", len(buf), total)
	}

	binary.BigEndian.PutUint32(buf[0:4], MagicBSV)
	binary.BigEndian.PutUint16(buf[4:6], ProtoVer)
	buf[6] = FrameVerV2
	buf[7] = 0
	copy(buf[8:40], f.TxID[:])
	binary.BigEndian.PutUint64(buf[40:48], f.HashKey)
	binary.BigEndian.PutUint64(buf[48:56], f.SeqNum)
	copy(buf[56:88], f.SubtreeID[:])
	binary.BigEndian.PutUint32(buf[88:92], uint32(len(f.Payload)))
	copy(buf[92:], f.Payload)

	return total, nil
}

// Decode parses a raw BRC-12 or BRC-124/BRC-128 datagram into a Frame.
//
// The returned Frame.Payload is a zero-copy slice into buf. The caller must
// not modify or reuse buf while the Frame is in scope.
//
// BRC-12 frames (FrameVer 0x01) are decoded with [Version] = FrameVerV1 and
// zero-valued HashKey, SeqNum, and SubtreeID. The forwarder forwards BRC-12
// frames verbatim (no re-encoding).
//
// Unknown versions return [ErrBadVer].
//
// Possible errors: [ErrTooShort], [ErrBadMagic], [ErrBadVer],
// or [io.ErrUnexpectedEOF] if the datagram is truncated relative to the
// declared payload length.
func Decode(buf []byte) (*Frame, error) {
	if len(buf) < HeaderSizeLegacy {
		return nil, ErrTooShort
	}

	if magic := binary.BigEndian.Uint32(buf[0:4]); magic != MagicBSV {
		return nil, fmt.Errorf("%w: got 0x%08X", ErrBadMagic, magic)
	}

	fver := buf[6]
	switch fver {
	case FrameVerV1:
		return decodeV1(buf)
	case FrameVerV2:
		return decodeV2(buf)
	case FrameVerV3:
		// BRC-130 fragment frames are decoded separately; Decode returns an
		// error so callers that only handle Frame can distinguish fragments.
		// Use [DecodeFragment] to obtain a [FragFrame].
		return nil, fmt.Errorf("%w: FrameVer 0x03 is a BRC-130 fragment; use DecodeFragment", ErrBadVer)
	case FrameVerV4:
		// BRC-131 block control frames are decoded separately; Decode returns
		// an error so callers that only handle Frame can distinguish them.
		// Use [DecodeBlock] to obtain a [BlockFrame].
		return nil, fmt.Errorf("%w: FrameVer 0x04 is a BRC-131 block control frame; use DecodeBlock", ErrBadVer)
	case FrameVerV5:
		// BRC-132 subtree data frames are decoded separately; Decode returns
		// an error so callers that only handle Frame can distinguish them.
		// Use [DecodeSubtreeData] to obtain a [SubtreeDataFrame].
		return nil, fmt.Errorf("%w: FrameVer 0x05 is a BRC-132 subtree data frame; use DecodeSubtreeData", ErrBadVer)
	case FrameVerV6:
		// BRC-134 anchor transaction frames are decoded separately; Decode
		// returns an error so callers that only handle Frame can distinguish
		// them. Use [DecodeAnchor] to obtain a [Frame] with Version=FrameVerV6.
		return nil, fmt.Errorf("%w: FrameVer 0x06 is a BRC-134 anchor transaction frame; use DecodeAnchor", ErrBadVer)
	case FrameVerV7:
		// BRC-135 block header frames are decoded separately; Decode returns
		// an error so callers that only handle Frame can distinguish them.
		// Use [DecodeBlockHeader] to obtain a [Frame] with Version=FrameVerV7.
		return nil, fmt.Errorf("%w: FrameVer 0x07 is a BRC-135 block header frame; use DecodeBlockHeader", ErrBadVer)
	case FrameVerV8:
		// BRC-142 bundle frames pack many transactions into one datagram and
		// are decoded separately; Decode returns an error so callers that only
		// handle a single-tx Frame can distinguish them. Use the bundle package.
		return nil, fmt.Errorf("%w: FrameVer 0x08 is a BRC-142 bundle frame; use bundle.Decode", ErrBadVer)
	case FrameVerV9:
		// BRC-149 BEEF object frames are decoded separately; Decode returns an
		// error so callers that only handle Frame can distinguish them.
		// Use [DecodeBEEF] to obtain a [BEEFFrame].
		return nil, fmt.Errorf("%w: FrameVer 0x09 is a BRC-149 BEEF object frame; use DecodeBEEF", ErrBadVer)
	default:
		return nil, fmt.Errorf("%w: got 0x%02X", ErrBadVer, fver)
	}
}

// decodeV1 parses the 44-byte BRC-12 (legacy) header. BRC-124/BRC-128 fields default to zero.
func decodeV1(buf []byte) (*Frame, error) {
	if len(buf) < HeaderSizeLegacy {
		return nil, ErrTooShort
	}
	payLen := int(binary.BigEndian.Uint32(buf[40:44]))
	if len(buf)-HeaderSizeLegacy < payLen {
		return nil, io.ErrUnexpectedEOF
	}
	f := &Frame{Version: FrameVerV1}
	copy(f.TxID[:], buf[8:40])
	f.Payload = buf[HeaderSizeLegacy : HeaderSizeLegacy+payLen]
	return f, nil
}

// DecodeAnchor parses a raw BRC-134 chained anchor transaction datagram into a
// Frame. The header layout is identical to BRC-124 (same field offsets) but
// the version byte is 0x06 and the frame is routed to GroupBlockBroadcast instead
// of a shard group.
//
// The returned Frame.Payload is a zero-copy slice into buf. The caller must
// not modify or reuse buf while the Frame is in scope.
//
// Possible errors: [ErrTooShort], [ErrBadMagic], [ErrBadVer], or
// [io.ErrUnexpectedEOF] if the datagram is truncated relative to the declared
// payload length.
func DecodeAnchor(buf []byte) (*Frame, error) {
	if len(buf) < HeaderSizeLegacy {
		return nil, ErrTooShort
	}
	if magic := binary.BigEndian.Uint32(buf[0:4]); magic != MagicBSV {
		return nil, fmt.Errorf("%w: got 0x%08X", ErrBadMagic, magic)
	}
	if buf[6] != FrameVerV6 {
		return nil, fmt.Errorf("%w: got 0x%02X, want 0x06", ErrBadVer, buf[6])
	}
	if len(buf) < HeaderSize {
		return nil, ErrTooShort
	}
	payLen := int(binary.BigEndian.Uint32(buf[88:HeaderSize]))
	if len(buf)-HeaderSize < payLen {
		return nil, io.ErrUnexpectedEOF
	}
	f := &Frame{Version: FrameVerV6}
	copy(f.TxID[:], buf[8:40])
	f.HashKey = binary.BigEndian.Uint64(buf[40:48])
	f.SeqNum = binary.BigEndian.Uint64(buf[48:56])
	// SubtreeID at 56–87 is always zeros for anchor frames; copy anyway for
	// layout symmetry with decodeV2.
	copy(f.SubtreeID[:], buf[56:88])
	f.Payload = buf[HeaderSize : HeaderSize+payLen]
	return f, nil
}

// IsAnchorFrame reports whether buf begins with a valid BRC-134 anchor
// transaction header (magic + FrameVer == 0x06) without performing a full
// decode. It returns false for any buffer shorter than [HeaderSizeLegacy].
func IsAnchorFrame(buf []byte) bool {
	if len(buf) < HeaderSizeLegacy {
		return false
	}
	if binary.BigEndian.Uint32(buf[0:4]) != MagicBSV {
		return false
	}
	return buf[6] == FrameVerV6
}

// IsBundle reports whether buf begins with a valid BRC-142 bundle header
// (magic + FrameVer == 0x08) without performing a full decode. It returns false
// for any buffer shorter than [HeaderSizeLegacy].
func IsBundle(buf []byte) bool {
	if len(buf) < HeaderSizeLegacy {
		return false
	}
	if binary.BigEndian.Uint32(buf[0:4]) != MagicBSV {
		return false
	}
	return buf[6] == FrameVerV8
}

// decodeV2 parses the 92-byte BRC-124/BRC-128 header.
func decodeV2(buf []byte) (*Frame, error) {
	if len(buf) < HeaderSize {
		return nil, ErrTooShort
	}
	payLen := int(binary.BigEndian.Uint32(buf[88:HeaderSize]))
	if len(buf)-HeaderSize < payLen {
		return nil, io.ErrUnexpectedEOF
	}
	f := &Frame{Version: FrameVerV2}
	copy(f.TxID[:], buf[8:40])
	f.HashKey = binary.BigEndian.Uint64(buf[40:48])
	f.SeqNum = binary.BigEndian.Uint64(buf[48:56])
	copy(f.SubtreeID[:], buf[56:88])
	f.Payload = buf[HeaderSize : HeaderSize+payLen]
	return f, nil
}
