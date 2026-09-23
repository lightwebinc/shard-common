// BRC-149 BEEF object frame encode/decode.
//
// A FrameVer 0x09 frame uses the same 92-byte header layout as BRC-124 but
// carries a BEEF-family transaction object (BRC-62 / BRC-95 / BRC-96) on the
// BEEF object plane's domain-tagged shard groups
// (IDX 0x1000 + shardIndex(TopicID)). ContentID (SHA-256d of the payload)
// occupies the TxID slot; TopicID (SHA-256 of the overlay topic name)
// occupies the SubtreeID slot. The BEEF encoding version is not duplicated
// in the header — it is the object's first four bytes.
//
// The payload takes one of two forms, told apart by its leading bytes: the
// BRC-149 submission record verbatim (leads with the 0xBEEF tag; carries every
// topic name the publisher submitted, then the object) or a bare BEEF object
// (leads with 0x01). One record is one frame at any topic count. Byte 7,
// DeliverCount, says how many of the record's leading topics are
// deliverable; TopicID at offset 56 is always the first of them.

package frame

import (
	"encoding/binary"
	"fmt"
	"io"
)

// BEEFFrame is the parsed in-memory representation of a BRC-149 BEEF object
// datagram (FrameVer 0x09, 92-byte header).
//
// Payload is a zero-copy slice pointing into the buffer passed to
// [DecodeBEEF]; the buffer must remain valid for the lifetime of the
// BEEFFrame.
type BEEFFrame struct {
	ContentID [32]byte // SHA-256d(payload) — object identity; keys BRC-130 reassembly
	HashKey   uint64   // Stamped at ingress; XXH64(sender ∥ domain-tagged groupIdx ∥ zeros); 0 = unset
	SeqNum    uint64   // Stamped at ingress; monotonic per (sender, group) flow; 0 = unset
	TopicID   [32]byte // SHA-256(UTF-8 topic name) of the first deliverable topic — shard key
	// DeliverCount (byte 7) is how many of the payload record's leading topics
	// are deliverable: 1 on the open path, up to the operator's cap on the
	// authenticated path. 0 is the legacy encoding and means exactly 1
	// (TopicID alone); every further name in the record is a label the
	// subscriber receives but is never matched on.
	DeliverCount uint8
	Payload      []byte // submission record (0xBEEF-led) or bare BEEF object (0x01-led), verbatim
}

// BEEFDeliverCountLegacy is the DeliverCount of a frame emitted before the
// byte carried meaning; it is read as one deliverable topic.
const BEEFDeliverCountLegacy uint8 = 0

// DecodeBEEF parses a raw BRC-149 BEEF object datagram into a BEEFFrame.
//
// The returned BEEFFrame.Payload is a zero-copy slice into buf. The caller
// must not modify or reuse buf while the BEEFFrame is in scope.
//
// Byte 7 is DeliverCount; a zero (the legacy encoding) decodes as such and
// callers treat it as one deliverable topic via [BEEFFrame.Deliverable].
//
// Possible errors: [ErrTooShort], [ErrBadMagic], [ErrBadVer], or
// [io.ErrUnexpectedEOF] if the datagram is truncated relative to the
// declared payload length.
func DecodeBEEF(buf []byte) (*BEEFFrame, error) {
	if len(buf) < HeaderSizeLegacy {
		return nil, ErrTooShort
	}
	if magic := binary.BigEndian.Uint32(buf[0:4]); magic != MagicBSV {
		return nil, fmt.Errorf("%w: got 0x%08X", ErrBadMagic, magic)
	}
	if buf[6] != FrameVerV9 {
		return nil, fmt.Errorf("%w: got 0x%02X, want 0x09", ErrBadVer, buf[6])
	}
	if len(buf) < HeaderSize {
		return nil, ErrTooShort
	}

	payLen := int(binary.BigEndian.Uint32(buf[88:92]))
	if len(buf)-HeaderSize < payLen {
		return nil, io.ErrUnexpectedEOF
	}

	bf := &BEEFFrame{
		HashKey:      binary.BigEndian.Uint64(buf[40:48]),
		SeqNum:       binary.BigEndian.Uint64(buf[48:56]),
		DeliverCount: buf[7],
		Payload:      buf[HeaderSize : HeaderSize+payLen],
	}
	copy(bf.ContentID[:], buf[8:40])
	copy(bf.TopicID[:], buf[56:88])
	return bf, nil
}

// Deliverable returns the number of leading record topics a listener may
// match on: DeliverCount, with the legacy zero read as one.
func (f *BEEFFrame) Deliverable() int {
	if f.DeliverCount == BEEFDeliverCountLegacy {
		return 1
	}
	return int(f.DeliverCount)
}

// EncodeBEEF serialises a BRC-149 BEEF object frame into buf and returns the
// number of bytes written.
// buf must be at least HeaderSize + len(f.Payload) bytes long.
func EncodeBEEF(f *BEEFFrame, buf []byte) (int, error) {
	total := HeaderSize + len(f.Payload)
	if len(buf) < total {
		return 0, fmt.Errorf("frame: buffer too small (%d bytes, need %d)", len(buf), total)
	}

	binary.BigEndian.PutUint32(buf[0:4], MagicBSV)
	binary.BigEndian.PutUint16(buf[4:6], ProtoVer)
	buf[6] = FrameVerV9
	buf[7] = f.DeliverCount
	copy(buf[8:40], f.ContentID[:])
	binary.BigEndian.PutUint64(buf[40:48], f.HashKey)
	binary.BigEndian.PutUint64(buf[48:56], f.SeqNum)
	copy(buf[56:88], f.TopicID[:])
	binary.BigEndian.PutUint32(buf[88:92], uint32(len(f.Payload)))
	copy(buf[92:], f.Payload)

	return total, nil
}

// IsBEEFFrame reports whether buf begins with a valid BRC-149 BEEF object
// header (magic + FrameVer == 0x09) without performing a full decode.
// It returns false for any buffer shorter than [HeaderSizeLegacy].
func IsBEEFFrame(buf []byte) bool {
	if len(buf) < HeaderSizeLegacy {
		return false
	}
	if binary.BigEndian.Uint32(buf[0:4]) != MagicBSV {
		return false
	}
	return buf[6] == FrameVerV9
}
